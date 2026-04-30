#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <iostream>
#include <process.h>
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

struct TestArgs {
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

[[nodiscard]] bool parse_args(const int argc, char** argv, TestArgs& args) {
    for (int index = 1; index < argc; ++index) {
        const std::string_view arg = argv[index];
        if (arg == "--exe" && index + 1 < argc) {
            args.executable = argv[++index];
        } else if (arg == "--fixture" && index + 1 < argc) {
            args.fixture = argv[++index];
        } else if (arg == "--out" && index + 1 < argc) {
            args.output = argv[++index];
        } else {
            std::cerr << "unknown or incomplete argument: " << arg << '\n';
            return false;
        }
    }

    if (args.executable.empty() || args.fixture.empty() || args.output.empty()) {
        std::cerr << "usage: pcap-constrictor-tests --exe <pcap-constrictor> --fixture <input.pcap> --out <output.pcap>\n";
        return false;
    }

    return true;
}

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

[[nodiscard]] int run_constrict_command(const TestArgs& args) {
#ifdef _WIN32
    const std::wstring executable = args.executable.wstring();
    const std::wstring command = L"constrict";
    const std::wstring fixture = args.fixture.wstring();
    const std::wstring output = args.output.wstring();
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
    const auto command = quote_arg(args.executable) +
        " constrict " + quote_arg(args.fixture) +
        " -o " + quote_arg(args.output) +
        " --stats";
    return std::system(command.c_str());
#endif
}

void run_tls_fixture_test(const TestArgs& args) {
    std::filesystem::create_directories(args.output.parent_path());

    const int exit_code = run_constrict_command(args);
    if (exit_code == -1) {
        throw std::runtime_error(std::string("failed to spawn pcap-constrictor command: ") + std::strerror(errno));
    }
    require(exit_code == 0, "pcap-constrictor command failed");

    const auto input_packets = read_packets(args.fixture);
    const auto output_packets = read_packets(args.output);
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
        require(decoded.transport_payload_size == expected.tcp_payload_size, "unexpected TCP payload size");

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

}  // namespace

int main(const int argc, char** argv) {
    TestArgs args {};
    if (!parse_args(argc, argv, args)) {
        return 2;
    }

    try {
        run_tls_fixture_test(args);
    } catch (const std::exception& error) {
        std::cerr << "TLS fixture test failed: " << error.what() << '\n';
        return 1;
    }

    std::cout << "TLS fixture test passed\n";
    return 0;
}
