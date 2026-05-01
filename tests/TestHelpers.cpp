#include "TestHelpers.hpp"

#include <algorithm>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <process.h>
#endif

namespace pc::test {

namespace {

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

[[nodiscard]] int run_command(const TestContext& context, const wchar_t* command_wide, const char* command_narrow) {
#ifdef _WIN32
    static_cast<void>(command_narrow);

    const std::wstring executable = context.executable.wstring();
    const std::wstring command_value {command_wide};
    const std::wstring fixture = context.fixture.wstring();
    const std::wstring output = context.output.wstring();
    const std::wstring output_flag = L"-o";
    const std::wstring stats_flag = L"--stats";
    const std::wstring config_flag = L"--config";
    const std::wstring config = context.config.wstring();

    std::vector<const wchar_t*> argv {};
    argv.reserve(context.config.empty() ? 7U : 9U);
    argv.push_back(executable.c_str());
    argv.push_back(command_value.c_str());
    argv.push_back(fixture.c_str());
    argv.push_back(output_flag.c_str());
    argv.push_back(output.c_str());
    if (!context.config.empty()) {
        argv.push_back(config_flag.c_str());
        argv.push_back(config.c_str());
    }
    argv.push_back(stats_flag.c_str());
    argv.push_back(nullptr);

    return _wspawnv(_P_WAIT, executable.c_str(), argv.data());
#else
    auto cmd = quote_arg(context.executable) +
        " " + std::string(command_narrow) + " " + quote_arg(context.fixture) +
        " -o " + quote_arg(context.output);
    if (!context.config.empty()) {
        cmd += " --config " + quote_arg(context.config);
    }
    cmd += " --stats";
    return std::system(cmd.c_str());
#endif
}

}  // namespace

std::vector<pc::pcap::PacketRecord> read_packets(const std::filesystem::path& path) {
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

int run_constrict_command(const TestContext& context) {
    return run_command(context, L"constrict", "constrict");
}

int run_reinflate_command(const TestContext& context) {
    return run_command(context, L"reinflate", "reinflate");
}

void verify_common_packet_invariants(
    const std::vector<pc::pcap::PacketRecord>& input_packets,
    const std::vector<pc::pcap::PacketRecord>& output_packets
) {
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
}

}  // namespace pc::test
