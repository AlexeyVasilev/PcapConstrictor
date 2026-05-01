#include "pcap/PcapNgReader.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <sstream>
#include <utility>

#include "bytes/Endian.hpp"
#include "pcap/PcapNgFormat.hpp"

namespace pc::pcap {

namespace {

[[nodiscard]] bool read_exact_stream(std::ifstream& stream, std::span<std::uint8_t> out) {
    if (out.empty()) {
        return true;
    }

    stream.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    return stream.gcount() == static_cast<std::streamsize>(out.size());
}

[[nodiscard]] std::uint32_t read_u32_at(
    const std::vector<std::uint8_t>& bytes,
    const std::size_t offset,
    const pc::bytes::Endianness endianness
) {
    return pc::bytes::read_u32(std::span<const std::uint8_t, 4>(bytes.data() + offset, 4U), endianness);
}

[[nodiscard]] std::uint16_t read_u16_at(
    const std::vector<std::uint8_t>& bytes,
    const std::size_t offset,
    const pc::bytes::Endianness endianness
) {
    return pc::bytes::read_u16(std::span<const std::uint8_t, 2>(bytes.data() + offset, 2U), endianness);
}

}  // namespace

void PcapNgReader::clear() {
    if (stream_.is_open()) {
        stream_.close();
    }

    file_size_ = 0;
    next_input_offset_ = 0;
    next_packet_index_ = 0;
    has_error_ = false;
    error_message_.clear();
    has_section_endianness_ = false;
    section_endianness_ = pc::bytes::Endianness::little;
    interfaces_.clear();
}

void PcapNgReader::set_error(std::string message) {
    has_error_ = true;
    error_message_ = std::move(message);
}

void PcapNgReader::set_error_at(const std::uint64_t offset, std::string message) {
    std::ostringstream out {};
    out << "file offset " << offset << ": " << message;
    set_error(out.str());
}

bool PcapNgReader::read_exact(const std::uint64_t offset, std::vector<std::uint8_t>& out) {
    if (!stream_.is_open()) {
        return false;
    }

    stream_.clear();
    stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!stream_.good()) {
        return false;
    }

    return read_exact_stream(stream_, std::span<std::uint8_t>(out.data(), out.size()));
}

bool PcapNgReader::open(const std::filesystem::path& path) {
    clear();

    std::error_code size_error {};
    const auto size = std::filesystem::file_size(path, size_error);
    if (size_error) {
        set_error("failed to read input file size");
        return false;
    }

    if (size > static_cast<std::uintmax_t>(std::numeric_limits<std::uint64_t>::max())) {
        set_error("input file is too large");
        return false;
    }
    file_size_ = static_cast<std::uint64_t>(size);

    stream_ = std::ifstream(path, std::ios::binary);
    if (!stream_.is_open()) {
        set_error("failed to open input file");
        return false;
    }

    return true;
}

std::optional<PcapNgBlock> PcapNgReader::parse_section_header_block(
    const std::uint64_t block_offset,
    std::vector<std::uint8_t>&& block_bytes
) {
    if (block_bytes.size() < 28U) {
        set_error_at(block_offset, "PCAPNG Section Header Block is too small");
        return std::nullopt;
    }

    std::array<std::uint8_t, 4> bom_bytes {
        block_bytes[8U], block_bytes[9U], block_bytes[10U], block_bytes[11U]
    };
    if (bom_bytes == kPcapNgBigEndianByteOrderMagicBytes) {
        set_error_at(block_offset, "big-endian PCAPNG sections are not supported");
        return std::nullopt;
    }

    if (bom_bytes != kPcapNgLittleEndianByteOrderMagicBytes) {
        set_error_at(block_offset, "invalid PCAPNG byte-order magic");
        return std::nullopt;
    }

    has_section_endianness_ = true;
    section_endianness_ = pc::bytes::Endianness::little;
    interfaces_.clear();

    PcapNgBlock block {};
    block.kind = PcapNgBlockKind::raw;
    block.type = kPcapNgSectionHeaderBlockType;
    block.block_offset = block_offset;
    block.raw_bytes = std::move(block_bytes);
    return block;
}

std::optional<PcapNgBlock> PcapNgReader::parse_interface_description_block(
    const std::uint64_t block_offset,
    std::vector<std::uint8_t>&& block_bytes
) {
    if (block_bytes.size() < 20U) {
        set_error_at(block_offset, "PCAPNG Interface Description Block is too small");
        return std::nullopt;
    }

    PcapNgInterfaceDescription description {};
    description.interface_id = static_cast<std::uint32_t>(interfaces_.size());
    description.link_type = read_u16_at(block_bytes, 8U, section_endianness_);
    description.snaplen = read_u32_at(block_bytes, 12U, section_endianness_);

    interfaces_.push_back({
        .valid = true,
        .link_type = description.link_type,
        .snaplen = description.snaplen,
    });

    PcapNgBlock block {};
    block.kind = PcapNgBlockKind::interface_description;
    block.type = kPcapNgInterfaceDescriptionBlockType;
    block.block_offset = block_offset;
    block.raw_bytes = std::move(block_bytes);
    block.interface_description = description;
    return block;
}

std::optional<PcapNgBlock> PcapNgReader::parse_enhanced_packet_block(
    const std::uint64_t block_offset,
    std::vector<std::uint8_t>&& block_bytes
) {
    if (block_bytes.size() < 32U) {
        set_error_at(block_offset, "PCAPNG Enhanced Packet Block is too small");
        return std::nullopt;
    }

    const auto interface_id = read_u32_at(block_bytes, 8U, section_endianness_);
    const auto timestamp_high = read_u32_at(block_bytes, 12U, section_endianness_);
    const auto timestamp_low = read_u32_at(block_bytes, 16U, section_endianness_);
    const auto captured_length = read_u32_at(block_bytes, 20U, section_endianness_);
    const auto original_length = read_u32_at(block_bytes, 24U, section_endianness_);

    if (captured_length > original_length) {
        std::ostringstream out {};
        out << "packet " << next_packet_index_
            << " at file offset " << block_offset
            << ": captured length " << captured_length
            << " exceeds original length " << original_length;
        set_error(out.str());
        return std::nullopt;
    }

    const auto padded_packet_length = pad_to_32bit(static_cast<std::size_t>(captured_length));
    const auto payload_end = 28U + padded_packet_length;
    if (payload_end + 4U > block_bytes.size()) {
        set_error_at(block_offset, "PCAPNG Enhanced Packet Block packet data exceeds block size");
        return std::nullopt;
    }

    std::vector<std::uint8_t> packet_bytes(captured_length);
    if (captured_length != 0U) {
        std::copy_n(block_bytes.begin() + 28U, captured_length, packet_bytes.begin());
    }

    std::vector<std::uint8_t> options_raw {};
    const auto options_size = block_bytes.size() - payload_end - 4U;
    if (options_size != 0U) {
        options_raw.assign(block_bytes.begin() + payload_end, block_bytes.end() - 4);
    }

    PcapNgEnhancedPacketBlock enhanced_packet {};
    enhanced_packet.interface_id = interface_id;
    enhanced_packet.timestamp_high = timestamp_high;
    enhanced_packet.timestamp_low = timestamp_low;
    enhanced_packet.interface_known = interface_id < interfaces_.size() && interfaces_[interface_id].valid;
    enhanced_packet.link_type = enhanced_packet.interface_known ? interfaces_[interface_id].link_type : 0U;
    enhanced_packet.packet = {
        .packet_index = next_packet_index_,
        .header_offset = block_offset,
        .data_offset = block_offset + 28U,
        .ts_sec = timestamp_high,
        .ts_fraction = timestamp_low,
        .captured_length = captured_length,
        .original_length = original_length,
        .bytes = std::move(packet_bytes),
    };
    enhanced_packet.options_raw = std::move(options_raw);

    ++next_packet_index_;

    PcapNgBlock block {};
    block.kind = PcapNgBlockKind::enhanced_packet;
    block.type = kPcapNgEnhancedPacketBlockType;
    block.block_offset = block_offset;
    block.raw_bytes = std::move(block_bytes);
    block.enhanced_packet = std::move(enhanced_packet);
    return block;
}

std::optional<PcapNgBlock> PcapNgReader::read_next() {
    if (!stream_.is_open() || has_error_) {
        return std::nullopt;
    }

    if (next_input_offset_ == file_size_) {
        return std::nullopt;
    }

    if (next_input_offset_ > file_size_) {
        set_error_at(next_input_offset_, "reader offset is past end of input file");
        return std::nullopt;
    }

    const auto block_offset = next_input_offset_;
    const auto remaining = file_size_ - block_offset;
    if (remaining < 12U) {
        set_error_at(block_offset, "unexpected EOF while reading PCAPNG block header");
        return std::nullopt;
    }

    std::vector<std::uint8_t> header_bytes(12U);
    if (!read_exact(block_offset, header_bytes)) {
        set_error_at(block_offset, "unexpected EOF while reading PCAPNG block header");
        return std::nullopt;
    }

    const bool is_section_header =
        header_bytes[0U] == kPcapNgSectionHeaderBlockTypeBytes[0U] &&
        header_bytes[1U] == kPcapNgSectionHeaderBlockTypeBytes[1U] &&
        header_bytes[2U] == kPcapNgSectionHeaderBlockTypeBytes[2U] &&
        header_bytes[3U] == kPcapNgSectionHeaderBlockTypeBytes[3U];

    pc::bytes::Endianness block_endianness = section_endianness_;
    if (is_section_header) {
        std::array<std::uint8_t, 4> bom_bytes {
            header_bytes[8U], header_bytes[9U], header_bytes[10U], header_bytes[11U]
        };
        if (bom_bytes == kPcapNgBigEndianByteOrderMagicBytes) {
            set_error_at(block_offset, "big-endian PCAPNG sections are not supported");
            return std::nullopt;
        }

        if (bom_bytes != kPcapNgLittleEndianByteOrderMagicBytes) {
            set_error_at(block_offset, "invalid PCAPNG byte-order magic");
            return std::nullopt;
        }

        block_endianness = pc::bytes::Endianness::little;
    } else if (!has_section_endianness_) {
        set_error_at(block_offset, "PCAPNG file does not begin with a Section Header Block");
        return std::nullopt;
    }

    const auto block_type = pc::bytes::read_u32(
        std::span<const std::uint8_t, 4>(header_bytes.data(), 4U),
        block_endianness
    );
    const auto block_total_length = pc::bytes::read_u32(
        std::span<const std::uint8_t, 4>(header_bytes.data() + 4U, 4U),
        block_endianness
    );

    if (block_total_length < 12U || (block_total_length % 4U) != 0U) {
        set_error_at(block_offset, "invalid PCAPNG block total length");
        return std::nullopt;
    }

    if (static_cast<std::uint64_t>(block_total_length) > remaining) {
        set_error_at(block_offset, "PCAPNG block total length exceeds remaining file data");
        return std::nullopt;
    }

    std::vector<std::uint8_t> block_bytes(block_total_length);
    if (!read_exact(block_offset, block_bytes)) {
        set_error_at(block_offset, "unexpected EOF while reading PCAPNG block");
        return std::nullopt;
    }

    const auto trailing_length = read_u32_at(
        block_bytes,
        block_bytes.size() - 4U,
        block_endianness
    );
    if (trailing_length != block_total_length) {
        set_error_at(block_offset, "PCAPNG block closing length does not match opening length");
        return std::nullopt;
    }

    next_input_offset_ += block_total_length;

    if (is_section_header) {
        return parse_section_header_block(block_offset, std::move(block_bytes));
    }

    if (block_type == kPcapNgInterfaceDescriptionBlockType) {
        return parse_interface_description_block(block_offset, std::move(block_bytes));
    }

    if (block_type == kPcapNgEnhancedPacketBlockType) {
        return parse_enhanced_packet_block(block_offset, std::move(block_bytes));
    }

    PcapNgBlock block {};
    block.kind = PcapNgBlockKind::raw;
    block.type = block_type;
    block.block_offset = block_offset;
    block.raw_bytes = std::move(block_bytes);
    return block;
}

bool PcapNgReader::is_open() const noexcept {
    return stream_.is_open();
}

bool PcapNgReader::has_error() const noexcept {
    return has_error_;
}

const std::string& PcapNgReader::error_message() const noexcept {
    return error_message_;
}

pc::bytes::Endianness PcapNgReader::section_endianness() const noexcept {
    return section_endianness_;
}

std::uint64_t PcapNgReader::packet_index() const noexcept {
    return next_packet_index_;
}

}  // namespace pc::pcap
