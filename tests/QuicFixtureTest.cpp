#include "TestHelpers.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <initializer_list>
#include <span>
#include <stdexcept>
#include <string>

using namespace pc::test;

namespace {

[[nodiscard]] bool quic_read_varint(
    const std::span<const std::uint8_t> bytes,
    std::size_t& offset,
    std::uint64_t& value
) {
    if (offset >= bytes.size()) {
        return false;
    }

    const auto first = bytes[offset];
    const auto length = static_cast<std::size_t>(1U) << (first >> 6U);
    if (offset > bytes.size() || length > bytes.size() - offset) {
        return false;
    }

    value = static_cast<std::uint64_t>(first & 0x3FU);
    for (std::size_t index = 1; index < length; ++index) {
        value = (value << 8U) | bytes[offset + index];
    }
    offset += length;
    return true;
}

[[nodiscard]] bool quic_parse_long_header_total(
    const std::span<const std::uint8_t> payload,
    const std::size_t start,
    std::size_t& total_size
) {
    if (start >= payload.size() || (payload[start] & 0x80U) == 0U || payload.size() - start < 7U) {
        return false;
    }

    const auto packet_type = static_cast<std::uint8_t>((payload[start] >> 4U) & 0x03U);
    const auto version =
        (static_cast<std::uint32_t>(payload[start + 1U]) << 24U) |
        (static_cast<std::uint32_t>(payload[start + 2U]) << 16U) |
        (static_cast<std::uint32_t>(payload[start + 3U]) << 8U) |
        static_cast<std::uint32_t>(payload[start + 4U]);
    if (version == 0U) {
        return false;
    }

    std::size_t offset = start + 5U;
    const auto dcid_length = payload[offset++];
    if (dcid_length > payload.size() - offset) {
        return false;
    }
    offset += dcid_length;
    if (offset >= payload.size()) {
        return false;
    }
    const auto scid_length = payload[offset++];
    if (scid_length > payload.size() - offset) {
        return false;
    }
    offset += scid_length;

    if (packet_type == 0U) {
        std::uint64_t token_length = 0;
        if (!quic_read_varint(payload, offset, token_length) ||
            token_length > payload.size() ||
            token_length > payload.size() - offset) {
            return false;
        }
        offset += static_cast<std::size_t>(token_length);
    } else if (packet_type == 3U) {
        total_size = payload.size() - start;
        return true;
    }

    std::uint64_t packet_length = 0;
    if (!quic_read_varint(payload, offset, packet_length) ||
        packet_length > payload.size() ||
        packet_length > payload.size() - offset) {
        return false;
    }

    total_size = offset + static_cast<std::size_t>(packet_length) - start;
    return total_size != 0U;
}

[[nodiscard]] std::size_t quic_find_final_short_header_offset(const pc::pcap::PacketRecord& packet) {
    const auto decoded = decode_packet(packet);
    require(decoded.decoded && decoded.transport == pc::decode::TransportProtocol::Udp, "expected decoded UDP packet");
    const auto payload = std::span<const std::uint8_t>(
        packet.bytes.data() + decoded.transport_payload_offset,
        decoded.transport_payload_size
    );

    std::size_t offset = 0;
    while (offset < payload.size() && (payload[offset] & 0x80U) != 0U) {
        std::size_t total_size = 0;
        require(quic_parse_long_header_total(payload, offset, total_size), "failed to parse QUIC long header");
        offset += total_size;
    }

    require(offset < payload.size(), "expected final QUIC short header");
    require((payload[offset] & 0x80U) == 0U && (payload[offset] & 0x40U) != 0U, "expected short-header-compatible QUIC packet");
    return offset;
}

void expect_udp_payload_size(
    const std::vector<pc::pcap::PacketRecord>& packets,
    const std::size_t packet_number,
    const std::size_t expected_size
) {
    const auto packet_index = packet_number - 1U;
    require(packet_index < packets.size(), "expected UDP packet index is out of range");
    const auto decoded = decode_packet(packets[packet_index]);
    require(decoded.decoded && decoded.transport == pc::decode::TransportProtocol::Udp, "expected decoded UDP packet");
    if (decoded.transport_payload_size != expected_size) {
        throw std::runtime_error(
            "packet #" + std::to_string(packet_number) +
            ": expected UDP payload " + std::to_string(expected_size) +
            ", actual " + std::to_string(decoded.transport_payload_size)
        );
    }
}

[[nodiscard]] TestContext make_quic_context() {
    const std::filesystem::path source_dir {PCAP_CONSTRICTOR_SOURCE_DIR};
    const std::filesystem::path binary_dir {PCAP_CONSTRICTOR_BINARY_DIR};
    return {
        .executable = std::filesystem::path {PCAP_CONSTRICTOR_EXE_PATH},
        .fixture = source_dir / "tests" / "fixtures" / "quic" / "quic_test_1.pcap",
        .output = binary_dir / "test-output" / "quic_test_1.out.pcap",
    };
}

}  // namespace

void run_quic_fixture_test() {
    const auto context = make_quic_context();
    std::filesystem::create_directories(context.output.parent_path());

    const int exit_code = run_constrict_command(context);
    if (exit_code == -1) {
        throw std::runtime_error(std::string("failed to spawn pcap-constrictor command: ") + std::strerror(errno));
    }
    require(exit_code == 0, "pcap-constrictor command failed");

    const auto input_packets = read_packets(context.fixture);
    const auto output_packets = read_packets(context.output);
    verify_common_packet_invariants(input_packets, output_packets);

    expect_udp_payload_size(output_packets, 1U, 1252U);
    expect_udp_payload_size(output_packets, 2U, 1252U);
    expect_udp_payload_size(output_packets, 3U, 43U);
    expect_udp_payload_size(output_packets, 4U, 1252U);
    expect_udp_payload_size(output_packets, 5U, 1252U);
    expect_udp_payload_size(output_packets, 6U, 1252U);
    expect_udp_payload_size(output_packets, 7U, 1252U);
    expect_udp_payload_size(output_packets, 8U, 1252U);
    expect_udp_payload_size(output_packets, 9U, 197U);
    expect_udp_payload_size(output_packets, 10U, 85U);

    const auto packet_11_short_offset = quic_find_final_short_header_offset(input_packets[10U]);
    expect_udp_payload_size(output_packets, 11U, packet_11_short_offset + 32U);
    expect_udp_payload_size(output_packets, 12U, 32U);
    expect_udp_payload_size(output_packets, 13U, 317U);
    expect_udp_payload_size(output_packets, 14U, 1185U);
    expect_udp_payload_size(output_packets, 15U, 32U);
    expect_udp_payload_size(output_packets, 16U, 31U);

    for (const auto packet_number : {11U, 12U, 15U}) {
        const auto packet_index = packet_number - 1U;
        require(output_packets[packet_index].captured_length < input_packets[packet_index].captured_length, "expected QUIC caplen to shrink");
    }

    for (const auto packet_number : {13U, 14U, 16U}) {
        const auto packet_index = packet_number - 1U;
        require(output_packets[packet_index].bytes == input_packets[packet_index].bytes, "expected QUIC packet to stay full");
    }
}