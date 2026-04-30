#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iostream>
#ifdef _WIN32
#include <process.h>
#endif
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "decode/PacketDecode.hpp"
#include "pcap/ClassicPcapReader.hpp"
#include "pcap/LinkType.hpp"
#include "pcap/PacketRecord.hpp"

namespace {

struct TestContext {
    std::filesystem::path executable {};
    std::filesystem::path fixture {};
    std::filesystem::path output {};
};

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

#ifndef PCAP_CONSTRICTOR_SOURCE_DIR
#error "PCAP_CONSTRICTOR_SOURCE_DIR must be defined by CMake"
#endif

#ifndef PCAP_CONSTRICTOR_BINARY_DIR
#error "PCAP_CONSTRICTOR_BINARY_DIR must be defined by CMake"
#endif

#ifndef PCAP_CONSTRICTOR_EXE_PATH
#error "PCAP_CONSTRICTOR_EXE_PATH must be defined by CMake"
#endif

[[nodiscard]] TestContext make_context() {
    const std::filesystem::path source_dir {PCAP_CONSTRICTOR_SOURCE_DIR};
    const std::filesystem::path binary_dir {PCAP_CONSTRICTOR_BINARY_DIR};
    return {
        .executable = std::filesystem::path {PCAP_CONSTRICTOR_EXE_PATH},
        .fixture = source_dir / "tests" / "fixtures" / "tls" / "tls_test_1.pcap",
        .output = binary_dir / "test-output" / "tls_test_1.out.pcap",
    };
}

#ifndef _WIN32
[[nodiscard]] std::string quote_arg(const std::filesystem::path& path) {
    std::string raw = path.string();
    std::string quoted {"\""};
    for (const char ch : raw) {
        if (ch == '"') {
            quoted.push_back('"');
        }
        quoted.push_back(ch);
    }
    quoted.push_back('"');
    return quoted;
}
#endif

[[nodiscard]] std::vector<pc::pcap::PacketRecord> read_packets(const std::filesystem::path& path) {
    pc::pcap::ClassicPcapReader reader {};
    if (!reader.open(path)) {
        throw std::runtime_error("failed to open pcap: " + reader.error_message());
    }

    std::vector<pc::pcap::PacketRecord> packets {};
    while (auto packet = reader.read_next()) {
        packets.push_back(std::move(*packet));
    }

    if (reader.has_error()) {
        throw std::runtime_error("failed to read pcap: " + reader.error_message());
    }

    return packets;
}

[[nodiscard]] pc::decode::PacketDecodeResult decode_tcp(const pc::pcap::PacketRecord& packet) {
    return pc::decode::decode_packet(
        pc::pcap::kLinkTypeEthernet,
        std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size())
    );
}

void require(const bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

[[nodiscard]] int run_constrict_command(const TestContext& context) {
#ifdef _WIN32
    const std::wstring executable = context.executable.wstring();
    const std::wstring command = L"constrict";
    const std::wstring fixture = context.fixture.wstring();
    const std::wstring output = context.output.wstring();
    const std::wstring output_flag = L"-o";
    const std::wstring stats_flag = L"--stats";

    std::vector<const wchar_t*> argv {};
    argv.reserve(7U);
    argv.push_back(executable.c_str());
    argv.push_back(command.c_str());
    argv.push_back(fixture.c_str());
    argv.push_back(output_flag.c_str());
    argv.push_back(output.c_str());
    argv.push_back(stats_flag.c_str());
    argv.push_back(nullptr);

    return _wspawnv(_P_WAIT, executable.c_str(), argv.data());
#else
    const auto command = quote_arg(context.executable) +
        " constrict " + quote_arg(context.fixture) +
        " -o " + quote_arg(context.output) +
        " --stats";
    return std::system(command.c_str());
#endif
}

void run_tls_fixture_test() {
    const auto context = make_context();
    std::filesystem::create_directories(context.output.parent_path());

    const int exit_code = run_constrict_command(context);
    if (exit_code == -1) {
        throw std::runtime_error(std::string("failed to spawn pcap-constrictor command: ") + std::strerror(errno));
    }
    require(exit_code == 0, "pcap-constrictor command failed");

    const auto input_packets = read_packets(context.fixture);
    const auto output_packets = read_packets(context.output);
    require(input_packets.size() == output_packets.size(), "packet count changed");

    for (std::size_t index = 0; index < input_packets.size(); ++index) {
        const auto& before = input_packets[index];
        const auto& after = output_packets[index];
        require(before.ts_sec == after.ts_sec && before.ts_fraction == after.ts_fraction, "timestamp changed");
        require(before.original_length == after.original_length, "orig_len changed");
        require(after.captured_length <= before.captured_length, "caplen grew");
        require(after.bytes.size() == after.captured_length, "output byte size does not match caplen");
        require(
            std::equal(after.bytes.begin(), after.bytes.end(), before.bytes.begin()),
            "output packet is not an input prefix"
        );
    }

    pc::decode::PacketDecodeResult first_payload_flow {};
    bool saw_payload_flow = false;
    for (const auto expected : kExpectedPayloads) {
        const auto packet_index = expected.packet_index - 1U;
        require(packet_index < output_packets.size(), "expected packet index is out of range");

        const auto decoded = decode_tcp(output_packets[packet_index]);
        require(decoded.decoded && decoded.transport == pc::decode::TransportProtocol::Tcp, "expected decoded TCP packet");
        if (decoded.transport_payload_size != expected.tcp_payload_size) {
            throw std::runtime_error(
                "packet #" + std::to_string(expected.packet_index) +
                ": expected TCP payload " + std::to_string(expected.tcp_payload_size) +
                ", actual " + std::to_string(decoded.transport_payload_size)
            );
        }

        const auto input_decoded = decode_tcp(input_packets[packet_index]);
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

struct TestCase {
    std::string_view name {};
    void (*run)() {};
};

constexpr TestCase kTests[] {
    {"tls_fixture_constrict", &run_tls_fixture_test},
};

}  // namespace

int main(const int argc, char**) {
    if (argc != 1) {
        std::cerr << "pcap-constrictor-tests does not accept command-line arguments\n";
        return 2;
    }

    std::size_t failed = 0;
    for (const auto& test : kTests) {
        std::cout << "[ RUN  ] " << test.name << '\n';
        try {
            test.run();
            std::cout << "[ PASS ] " << test.name << '\n';
        } catch (const std::exception& error) {
            ++failed;
            std::cerr << "[ FAIL ] " << test.name << ": " << error.what() << '\n';
        }
    }

    if (failed != 0U) {
        std::cerr << failed << " test(s) failed\n";
        return 1;
    }

    std::cout << "All tests passed\n";
    return 0;
}
