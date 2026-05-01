#include "pcap/PcapNgWriter.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <sstream>
#include <utility>
#include <vector>

#include "bytes/Endian.hpp"
#include "pcap/PcapNgFormat.hpp"

namespace pc::pcap {

namespace {

template <typename ByteContainer>
[[nodiscard]] bool write_all(std::ofstream& stream, const ByteContainer& bytes) {
    if (bytes.empty()) {
        return stream.good();
    }

    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream.good();
}

}  // namespace

void PcapNgWriter::set_error(std::string message) {
    has_error_ = true;
    error_message_ = std::move(message);
}

bool PcapNgWriter::open(const std::filesystem::path& path) {
    close();
    has_error_ = false;
    error_message_.clear();
    has_section_endianness_ = false;
    section_endianness_ = pc::bytes::Endianness::little;

    stream_ = std::ofstream(path, std::ios::binary | std::ios::trunc);
    if (!stream_.is_open()) {
        set_error("failed to open output file");
        return false;
    }

    return true;
}

bool PcapNgWriter::write_raw_block(const std::vector<std::uint8_t>& block_bytes) {
    if (!stream_.is_open()) {
        set_error("output file is not open");
        return false;
    }

    if (block_bytes.size() < 12U) {
        set_error("PCAPNG raw block is too small");
        return false;
    }

    const bool is_section_header =
        block_bytes[0U] == kPcapNgSectionHeaderBlockTypeBytes[0U] &&
        block_bytes[1U] == kPcapNgSectionHeaderBlockTypeBytes[1U] &&
        block_bytes[2U] == kPcapNgSectionHeaderBlockTypeBytes[2U] &&
        block_bytes[3U] == kPcapNgSectionHeaderBlockTypeBytes[3U];
    if (is_section_header) {
        std::array<std::uint8_t, 4> bom_bytes {
            block_bytes[8U], block_bytes[9U], block_bytes[10U], block_bytes[11U]
        };
        if (bom_bytes == kPcapNgBigEndianByteOrderMagicBytes) {
            set_error("big-endian PCAPNG sections are not supported for output");
            return false;
        }
        if (bom_bytes != kPcapNgLittleEndianByteOrderMagicBytes) {
            set_error("invalid PCAPNG Section Header Block byte-order magic");
            return false;
        }

        has_section_endianness_ = true;
        section_endianness_ = pc::bytes::Endianness::little;
    }

    if (!write_all(stream_, block_bytes)) {
        set_error("failed to write PCAPNG block");
        return false;
    }

    return true;
}

bool PcapNgWriter::write_enhanced_packet(const PcapNgEnhancedPacketBlock& block) {
    if (!stream_.is_open()) {
        set_error("output file is not open");
        return false;
    }

    if (!has_section_endianness_) {
        set_error("cannot write PCAPNG Enhanced Packet Block before a Section Header Block");
        return false;
    }

    const auto& packet = block.packet;
    if (packet.bytes.size() != packet.captured_length) {
        std::ostringstream out {};
        out << "packet " << packet.packet_index
            << ": byte buffer size does not match captured length";
        set_error(out.str());
        return false;
    }

    if (packet.captured_length > packet.original_length) {
        std::ostringstream out {};
        out << "packet " << packet.packet_index
            << ": captured length " << packet.captured_length
            << " exceeds original length " << packet.original_length;
        set_error(out.str());
        return false;
    }

    const auto padded_packet_length = pad_to_32bit(static_cast<std::size_t>(packet.captured_length));
    const auto block_total_length = 32U + padded_packet_length + static_cast<std::uint32_t>(block.options_raw.size());
    std::vector<std::uint8_t> bytes(block_total_length, 0U);

    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data(), 4U), kPcapNgEnhancedPacketBlockType, section_endianness_);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 4U, 4U), block_total_length, section_endianness_);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 8U, 4U), block.interface_id, section_endianness_);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 12U, 4U), block.timestamp_high, section_endianness_);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 16U, 4U), block.timestamp_low, section_endianness_);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 20U, 4U), packet.captured_length, section_endianness_);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 24U, 4U), packet.original_length, section_endianness_);

    if (!packet.bytes.empty()) {
        std::copy(packet.bytes.begin(), packet.bytes.end(), bytes.begin() + 28U);
    }

    if (!block.options_raw.empty()) {
        std::copy(
            block.options_raw.begin(),
            block.options_raw.end(),
            bytes.begin() + 28U + padded_packet_length
        );
    }

    pc::bytes::write_u32(
        std::span<std::uint8_t, 4>(bytes.data() + bytes.size() - 4U, 4U),
        block_total_length,
        section_endianness_
    );

    if (!write_all(stream_, bytes)) {
        set_error("failed to write PCAPNG Enhanced Packet Block");
        return false;
    }

    return true;
}

void PcapNgWriter::close() {
    if (stream_.is_open()) {
        stream_.close();
        if (!stream_ && !has_error_) {
            set_error("failed to close output file");
        }
    }
}

bool PcapNgWriter::is_open() const noexcept {
    return stream_.is_open();
}

bool PcapNgWriter::has_error() const noexcept {
    return has_error_;
}

const std::string& PcapNgWriter::error_message() const noexcept {
    return error_message_;
}

}  // namespace pc::pcap
