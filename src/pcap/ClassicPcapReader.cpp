#include "pcap/ClassicPcapReader.hpp"

#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <sstream>
#include <system_error>
#include <utility>
#include <vector>

#include "bytes/Endian.hpp"

namespace pc::pcap {

namespace {

[[nodiscard]] bool read_exact(std::ifstream& stream, std::span<std::uint8_t> out) {
    if (out.empty()) {
        return true;
    }

    stream.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    return stream.gcount() == static_cast<std::streamsize>(out.size());
}

[[nodiscard]] std::uint16_t read_field_u16(
    const std::array<std::uint8_t, kClassicPcapGlobalHeaderSize>& bytes,
    const std::size_t offset,
    const pc::bytes::Endianness endianness
) {
    return pc::bytes::read_u16(std::span<const std::uint8_t, 2>(bytes.data() + offset, 2U), endianness);
}

[[nodiscard]] std::uint32_t read_field_u32(
    const std::array<std::uint8_t, kClassicPcapGlobalHeaderSize>& bytes,
    const std::size_t offset,
    const pc::bytes::Endianness endianness
) {
    return pc::bytes::read_u32(std::span<const std::uint8_t, 4>(bytes.data() + offset, 4U), endianness);
}

[[nodiscard]] std::uint32_t read_packet_header_u32(
    const std::array<std::uint8_t, kClassicPcapPacketHeaderSize>& bytes,
    const std::size_t offset,
    const pc::bytes::Endianness endianness
) {
    return pc::bytes::read_u32(std::span<const std::uint8_t, 4>(bytes.data() + offset, 4U), endianness);
}

[[nodiscard]] std::string packet_error_prefix(const std::uint64_t packet_index, const std::uint64_t offset) {
    std::ostringstream out {};
    out << "packet " << packet_index << " at file offset " << offset << ": ";
    return out.str();
}

}  // namespace

void ClassicPcapReader::clear() {
    if (stream_.is_open()) {
        stream_.close();
    }

    global_header_ = {};
    file_size_ = 0;
    next_input_offset_ = 0;
    next_packet_index_ = 0;
    has_error_ = false;
    error_message_.clear();
}

void ClassicPcapReader::set_error(std::string message) {
    has_error_ = true;
    error_message_ = std::move(message);
}

void ClassicPcapReader::set_error_at(const std::uint64_t offset, std::string message) {
    std::ostringstream out {};
    out << "file offset " << offset << ": " << message;
    set_error(out.str());
}

bool ClassicPcapReader::open(const std::filesystem::path& path) {
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

    std::array<std::uint8_t, kClassicPcapGlobalHeaderSize> header_bytes {};
    if (!read_exact(stream_, std::span<std::uint8_t>(header_bytes.data(), header_bytes.size()))) {
        set_error_at(0, "unexpected EOF while reading PCAP global header");
        stream_.close();
        return false;
    }

    auto magic = std::span<const std::uint8_t, 4>(header_bytes.data(), 4U);
    pc::bytes::Endianness endianness {pc::bytes::Endianness::little};
    TimePrecision precision {TimePrecision::microsecond};
    if (!detect_magic(magic, endianness, precision)) {
        set_error_at(0, "unsupported classic PCAP magic number");
        stream_.close();
        return false;
    }

    global_header_.magic_bytes = {header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]};
    global_header_.endianness = endianness;
    global_header_.time_precision = precision;
    global_header_.version_major = read_field_u16(header_bytes, 4U, endianness);
    global_header_.version_minor = read_field_u16(header_bytes, 6U, endianness);
    global_header_.thiszone_bits = read_field_u32(header_bytes, 8U, endianness);
    global_header_.sigfigs = read_field_u32(header_bytes, 12U, endianness);
    global_header_.snaplen = read_field_u32(header_bytes, 16U, endianness);
    global_header_.link_type = read_field_u32(header_bytes, 20U, endianness);

    if (global_header_.version_major != 2U || global_header_.version_minor != 4U) {
        std::ostringstream out {};
        out << "unsupported classic PCAP version "
            << global_header_.version_major << "." << global_header_.version_minor;
        set_error_at(4U, out.str());
        stream_.close();
        return false;
    }

    if (global_header_.snaplen == 0U) {
        set_error_at(16U, "invalid PCAP snaplen 0");
        stream_.close();
        return false;
    }

    next_input_offset_ = kClassicPcapGlobalHeaderSize;
    return true;
}

std::optional<PacketRecord> ClassicPcapReader::read_next() {
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

    const auto remaining_for_header = file_size_ - next_input_offset_;
    if (remaining_for_header < kClassicPcapPacketHeaderSize) {
        set_error_at(next_input_offset_, "unexpected EOF while reading packet header");
        return std::nullopt;
    }

    const auto packet_header_offset = next_input_offset_;
    std::array<std::uint8_t, kClassicPcapPacketHeaderSize> header_bytes {};
    if (!read_exact(stream_, std::span<std::uint8_t>(header_bytes.data(), header_bytes.size()))) {
        set_error_at(packet_header_offset, "unexpected EOF while reading packet header");
        return std::nullopt;
    }

    const auto ts_sec = read_packet_header_u32(header_bytes, 0U, global_header_.endianness);
    const auto ts_fraction = read_packet_header_u32(header_bytes, 4U, global_header_.endianness);
    const auto captured_length = read_packet_header_u32(header_bytes, 8U, global_header_.endianness);
    const auto original_length = read_packet_header_u32(header_bytes, 12U, global_header_.endianness);

    if (captured_length > original_length) {
        std::ostringstream out {};
        out << packet_error_prefix(next_packet_index_, packet_header_offset)
            << "captured length " << captured_length
            << " exceeds original length " << original_length;
        set_error(out.str());
        return std::nullopt;
    }

    const auto data_offset = packet_header_offset + kClassicPcapPacketHeaderSize;
    const auto remaining_data = file_size_ - data_offset;
    if (static_cast<std::uint64_t>(captured_length) > remaining_data) {
        std::ostringstream out {};
        out << packet_error_prefix(next_packet_index_, packet_header_offset)
            << "captured length " << captured_length
            << " exceeds remaining file data " << remaining_data;
        set_error(out.str());
        return std::nullopt;
    }

    std::vector<std::uint8_t> bytes(captured_length);
    if (!read_exact(stream_, std::span<std::uint8_t>(bytes.data(), bytes.size()))) {
        std::ostringstream out {};
        out << packet_error_prefix(next_packet_index_, data_offset)
            << "unexpected EOF while reading packet data";
        set_error(out.str());
        return std::nullopt;
    }

    PacketRecord packet {
        .packet_index = next_packet_index_,
        .header_offset = packet_header_offset,
        .data_offset = data_offset,
        .ts_sec = ts_sec,
        .ts_fraction = ts_fraction,
        .captured_length = captured_length,
        .original_length = original_length,
        .bytes = std::move(bytes),
    };

    next_input_offset_ = data_offset + captured_length;
    ++next_packet_index_;
    return packet;
}

bool ClassicPcapReader::is_open() const noexcept {
    return stream_.is_open();
}

bool ClassicPcapReader::has_error() const noexcept {
    return has_error_;
}

const std::string& ClassicPcapReader::error_message() const noexcept {
    return error_message_;
}

const ClassicPcapGlobalHeader& ClassicPcapReader::global_header() const noexcept {
    return global_header_;
}

std::uint64_t ClassicPcapReader::packet_index() const noexcept {
    return next_packet_index_;
}

}  // namespace pc::pcap
