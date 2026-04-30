#include "pcap/ClassicPcapWriter.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <sstream>
#include <utility>

#include "bytes/Endian.hpp"

namespace pc::pcap {

namespace {

[[nodiscard]] std::array<std::uint8_t, kClassicPcapGlobalHeaderSize> make_global_header_bytes(
    const ClassicPcapGlobalHeader& header
) {
    std::array<std::uint8_t, kClassicPcapGlobalHeaderSize> bytes {};
    bytes[0] = header.magic_bytes[0];
    bytes[1] = header.magic_bytes[1];
    bytes[2] = header.magic_bytes[2];
    bytes[3] = header.magic_bytes[3];

    pc::bytes::write_u16(std::span<std::uint8_t, 2>(bytes.data() + 4U, 2U), header.version_major, header.endianness);
    pc::bytes::write_u16(std::span<std::uint8_t, 2>(bytes.data() + 6U, 2U), header.version_minor, header.endianness);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 8U, 4U), header.thiszone_bits, header.endianness);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 12U, 4U), header.sigfigs, header.endianness);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 16U, 4U), header.snaplen, header.endianness);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 20U, 4U), header.link_type, header.endianness);
    return bytes;
}

[[nodiscard]] std::array<std::uint8_t, kClassicPcapPacketHeaderSize> make_packet_header_bytes(
    const PacketRecord& packet,
    const pc::bytes::Endianness endianness
) {
    std::array<std::uint8_t, kClassicPcapPacketHeaderSize> bytes {};
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data(), 4U), packet.ts_sec, endianness);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 4U, 4U), packet.ts_fraction, endianness);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 8U, 4U), packet.captured_length, endianness);
    pc::bytes::write_u32(std::span<std::uint8_t, 4>(bytes.data() + 12U, 4U), packet.original_length, endianness);
    return bytes;
}

template <typename ByteContainer>
[[nodiscard]] bool write_all(std::ofstream& stream, const ByteContainer& bytes) {
    if (bytes.empty()) {
        return stream.good();
    }

    stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return stream.good();
}

}  // namespace

void ClassicPcapWriter::set_error(std::string message) {
    has_error_ = true;
    error_message_ = std::move(message);
}

bool ClassicPcapWriter::open(const std::filesystem::path& path, const ClassicPcapGlobalHeader& header) {
    close();
    has_error_ = false;
    error_message_.clear();
    header_ = header;

    stream_ = std::ofstream(path, std::ios::binary | std::ios::trunc);
    if (!stream_.is_open()) {
        set_error("failed to open output file");
        return false;
    }

    const auto header_bytes = make_global_header_bytes(header_);
    if (!write_all(stream_, header_bytes)) {
        set_error("failed to write PCAP global header");
        close();
        return false;
    }

    return true;
}

bool ClassicPcapWriter::write_packet(const PacketRecord& packet) {
    if (!stream_.is_open()) {
        set_error("output file is not open");
        return false;
    }

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

    const auto packet_header = make_packet_header_bytes(packet, header_.endianness);
    if (!write_all(stream_, packet_header)) {
        set_error("failed to write packet header");
        return false;
    }

    if (!write_all(stream_, packet.bytes)) {
        set_error("failed to write packet data");
        return false;
    }

    return true;
}

void ClassicPcapWriter::close() {
    if (stream_.is_open()) {
        stream_.close();
        if (!stream_ && !has_error_) {
            set_error("failed to close output file");
        }
    }
}

bool ClassicPcapWriter::is_open() const noexcept {
    return stream_.is_open();
}

bool ClassicPcapWriter::has_error() const noexcept {
    return has_error_;
}

const std::string& ClassicPcapWriter::error_message() const noexcept {
    return error_message_;
}

}  // namespace pc::pcap
