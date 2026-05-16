#include "TestHelpers.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <sstream>
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
    std::filesystem::create_directories(context.output.parent_path());

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
    const std::wstring decision_log_flag = L"--decision-log";
    const std::wstring decision_log = context.decision_log.wstring();

    std::vector<const wchar_t*> argv {};
    argv.reserve((context.config.empty() ? 0U : 2U) + (context.decision_log.empty() ? 0U : 2U) + 7U);
    argv.push_back(executable.c_str());
    argv.push_back(command_value.c_str());
    argv.push_back(fixture.c_str());
    argv.push_back(output_flag.c_str());
    argv.push_back(output.c_str());
    if (!context.config.empty()) {
        argv.push_back(config_flag.c_str());
        argv.push_back(config.c_str());
    }
    if (!context.decision_log.empty()) {
        argv.push_back(decision_log_flag.c_str());
        argv.push_back(decision_log.c_str());
    }
    argv.push_back(stats_flag.c_str());
    argv.push_back(nullptr);

    return _wspawnv(_P_WAIT, executable.c_str(), argv.data());
#else
    static_cast<void>(command_wide);

    auto cmd = quote_arg(context.executable) +
        " " + std::string(command_narrow) + " " + quote_arg(context.fixture) +
        " -o " + quote_arg(context.output);
    if (!context.config.empty()) {
        cmd += " --config " + quote_arg(context.config);
    }
    if (!context.decision_log.empty()) {
        cmd += " --decision-log " + quote_arg(context.decision_log);
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

void compare_files_exact(
    const std::string_view scenario_name,
    const std::string_view stage_name,
    const std::filesystem::path& expected_path,
    const std::filesystem::path& actual_path
) {
    std::error_code error {};
    const auto expected_size = std::filesystem::file_size(expected_path, error);
    if (error) {
        throw std::runtime_error("failed to get expected file size: " + expected_path.string());
    }

    error.clear();
    const auto actual_size = std::filesystem::file_size(actual_path, error);
    if (error) {
        throw std::runtime_error("failed to get actual file size: " + actual_path.string());
    }

    std::ifstream expected(expected_path, std::ios::binary);
    if (!expected.is_open()) {
        throw std::runtime_error("failed to open expected file: " + expected_path.string());
    }

    std::ifstream actual(actual_path, std::ios::binary);
    if (!actual.is_open()) {
        throw std::runtime_error("failed to open actual file: " + actual_path.string());
    }

    std::array<char, 4096> expected_buffer {};
    std::array<char, 4096> actual_buffer {};
    std::uint64_t offset = 0;

    for (;;) {
        expected.read(expected_buffer.data(), static_cast<std::streamsize>(expected_buffer.size()));
        actual.read(actual_buffer.data(), static_cast<std::streamsize>(actual_buffer.size()));

        const auto expected_read = expected.gcount();
        const auto actual_read = actual.gcount();
        const auto chunk_size = std::min(expected_read, actual_read);

        for (std::streamsize index = 0; index < chunk_size; ++index) {
            const auto expected_byte = static_cast<unsigned char>(expected_buffer[static_cast<std::size_t>(index)]);
            const auto actual_byte = static_cast<unsigned char>(actual_buffer[static_cast<std::size_t>(index)]);
            if (expected_byte != actual_byte) {
                std::ostringstream out {};
                out << "scenario " << scenario_name
                    << ", stage " << stage_name
                    << ": file mismatch at byte offset " << (offset + static_cast<std::uint64_t>(index))
                    << ", expected file " << expected_path.string()
                    << ", actual file " << actual_path.string()
                    << ", expected size " << expected_size
                    << ", actual size " << actual_size
                    << ", expected byte " << static_cast<unsigned>(expected_byte)
                    << ", actual byte " << static_cast<unsigned>(actual_byte);
                throw std::runtime_error(out.str());
            }
        }

        if (expected_read != actual_read) {
            std::ostringstream out {};
            out << "scenario " << scenario_name
                << ", stage " << stage_name
                << ": file size/content mismatch after byte offset " << offset
                << ", expected file " << expected_path.string()
                << ", actual file " << actual_path.string()
                << ", expected size " << expected_size
                << ", actual size " << actual_size;
            throw std::runtime_error(out.str());
        }

        if (expected_read == 0) {
            break;
        }

        offset += static_cast<std::uint64_t>(expected_read);
    }

    if (!expected.eof() || !actual.eof()) {
        std::ostringstream out {};
        out << "scenario " << scenario_name
            << ", stage " << stage_name
            << ": failed while comparing files"
            << ", expected file " << expected_path.string()
            << ", actual file " << actual_path.string()
            << ", expected size " << expected_size
            << ", actual size " << actual_size;
        throw std::runtime_error(out.str());
    }
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
