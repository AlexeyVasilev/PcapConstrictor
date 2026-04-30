#include "TestHelpers.hpp"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>

using namespace pc::test;

namespace {

struct ExpectedPayload {
    std::size_t packet_index {};
    std::size_t tcp_payload_size {};
};

constexpr ExpectedPayload kExpectedPayloads[] {
    {4U, 1900U},
    {7U, 1229U},
    {8U, 8U},
    {9U, 8U},
    {10U, 8U},
    {15U, 14U},
    {16U, 8U},
    {17U, 1025U},
};

constexpr std::size_t kExpectedTruncatedPackets[] {7U, 8U, 9U, 10U, 15U, 16U, 17U};
constexpr std::size_t kExpectedIdenticalPackets[] {1U, 2U, 3U, 4U, 5U, 6U, 11U, 12U, 13U, 14U};

[[nodiscard]] TestContext make_tls_context() {
    const std::filesystem::path source_dir {PCAP_CONSTRICTOR_SOURCE_DIR};
    const std::filesystem::path binary_dir {PCAP_CONSTRICTOR_BINARY_DIR};
    return {
        .executable = std::filesystem::path {PCAP_CONSTRICTOR_EXE_PATH},
        .fixture = source_dir / "tests" / "fixtures" / "tls" / "tls_test_1.pcap",
        .output = binary_dir / "test-output" / "tls_test_1.out.pcap",
    };
}

}  // namespace

void run_tls_fixture_test() {
    const auto context = make_tls_context();
    std::filesystem::create_directories(context.output.parent_path());

    const int exit_code = run_constrict_command(context);
    if (exit_code == -1) {
        throw std::runtime_error(std::string("failed to spawn pcap-constrictor command: ") + std::strerror(errno));
    }
    require(exit_code == 0, "pcap-constrictor command failed");

    const auto input_packets = read_packets(context.fixture);
    const auto output_packets = read_packets(context.output);
    verify_common_packet_invariants(input_packets, output_packets);

    pc::decode::PacketDecodeResult first_payload_flow {};
    bool saw_payload_flow = false;
    for (const auto expected : kExpectedPayloads) {
        const auto packet_index = expected.packet_index - 1U;
        require(packet_index < output_packets.size(), "expected packet index is out of range");

        const auto decoded = decode_packet(output_packets[packet_index]);
        require(decoded.decoded && decoded.transport == pc::decode::TransportProtocol::Tcp, "expected decoded TCP packet");
        if (decoded.transport_payload_size != expected.tcp_payload_size) {
            throw std::runtime_error(
                "packet #" + std::to_string(expected.packet_index) +
                ": expected TCP payload " + std::to_string(expected.tcp_payload_size) +
                ", actual " + std::to_string(decoded.transport_payload_size)
            );
        }

        const auto input_decoded = decode_packet(input_packets[packet_index]);
        if (input_decoded.decoded && input_decoded.transport_payload_size != 0U) {
            if (!saw_payload_flow) {
                first_payload_flow = input_decoded;
                saw_payload_flow = true;
            } else {
                const bool same_direction =
                    input_decoded.src_ip == first_payload_flow.src_ip &&
                    input_decoded.dst_ip == first_payload_flow.dst_ip &&
                    input_decoded.src_port == first_payload_flow.src_port &&
                    input_decoded.dst_port == first_payload_flow.dst_port;
                const bool reverse_direction =
                    input_decoded.src_ip == first_payload_flow.dst_ip &&
                    input_decoded.dst_ip == first_payload_flow.src_ip &&
                    input_decoded.src_port == first_payload_flow.dst_port &&
                    input_decoded.dst_port == first_payload_flow.src_port;
                require(same_direction || reverse_direction, "expected same TCP connection");
            }
        }
    }
    require(saw_payload_flow, "expected TLS TCP connection was not decoded");

    for (const auto packet_number : kExpectedTruncatedPackets) {
        const auto packet_index = packet_number - 1U;
        require(packet_index < output_packets.size(), "truncated packet index is out of range");
        require(output_packets[packet_index].captured_length < input_packets[packet_index].captured_length, "expected caplen to shrink");
    }

    for (const auto packet_number : kExpectedIdenticalPackets) {
        const auto packet_index = packet_number - 1U;
        require(packet_index < output_packets.size(), "identical packet index is out of range");
        require(output_packets[packet_index].bytes == input_packets[packet_index].bytes, "expected byte-identical output");
    }
}