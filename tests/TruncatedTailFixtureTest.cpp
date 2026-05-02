#include "TestHelpers.hpp"

#include <cerrno>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace pc::test;

namespace {

[[nodiscard]] TestContext make_truncated_tail_context() {
    const std::filesystem::path source_dir {PCAP_CONSTRICTOR_SOURCE_DIR};
    const std::filesystem::path binary_dir {PCAP_CONSTRICTOR_BINARY_DIR};
    return {
        .executable = std::filesystem::path {PCAP_CONSTRICTOR_EXE_PATH},
        .fixture = source_dir / "tests" / "fixtures" / "truncated" / "truncated_tail_test_1.pcap",
        .output = binary_dir / "test-output" / "truncated" / "truncated_tail_test_1.out.pcap",
    };
}

[[nodiscard]] std::vector<pc::pcap::PacketRecord> read_valid_prefix_packets(
    const std::filesystem::path& path,
    std::size_t& processed_packets
) {
    pc::pcap::ClassicPcapReader reader {};
    if (!reader.open(path)) {
        throw std::runtime_error("failed to open truncated fixture: " + reader.error_message());
    }

    std::vector<pc::pcap::PacketRecord> packets {};
    while (auto packet = reader.read_next()) {
        packets.push_back(std::move(*packet));
    }

    processed_packets = static_cast<std::size_t>(reader.packet_index());
    require(reader.has_error(), "expected truncated fixture to end with a read error");
    require(reader.incomplete_tail_info().has_value(), "expected truncated fixture to report an incomplete tail");
    return packets;
}

}  // namespace

void run_truncated_tail_fixture_test() {
    const auto context = make_truncated_tail_context();
    std::filesystem::create_directories(context.output.parent_path());

    const int exit_code = run_constrict_command(context);
    if (exit_code == -1) {
        throw std::runtime_error(std::string("failed to spawn truncated-tail constrict command: ") + std::strerror(errno));
    }
    require(exit_code != 0, "expected non-zero exit code for truncated input");
    require(std::filesystem::exists(context.output), "expected output file for partially processed truncated input");

    std::size_t expected_processed_packets = 0;
    const auto valid_prefix_packets = read_valid_prefix_packets(context.fixture, expected_processed_packets);
    const auto output_packets = read_packets(context.output);

    require(expected_processed_packets == valid_prefix_packets.size(), "reader packet index did not match valid prefix size");
    require(output_packets.size() == expected_processed_packets, "output packet count did not match processed prefix count");

    for (std::size_t index = 0; index < output_packets.size(); ++index) {
        require(
            output_packets[index].ts_sec == valid_prefix_packets[index].ts_sec &&
                output_packets[index].ts_fraction == valid_prefix_packets[index].ts_fraction,
            "output timestamp changed for successfully processed packet"
        );
        require(
            output_packets[index].original_length == valid_prefix_packets[index].original_length,
            "output orig_len changed for successfully processed packet"
        );
        require(
            output_packets[index].captured_length <= valid_prefix_packets[index].captured_length,
            "output caplen grew for successfully processed packet"
        );
        require(
            output_packets[index].bytes.size() == output_packets[index].captured_length,
            "output byte size did not match caplen"
        );
        require(
            std::equal(
                output_packets[index].bytes.begin(),
                output_packets[index].bytes.end(),
                valid_prefix_packets[index].bytes.begin()
            ),
            "output packet bytes were not preserved as an input prefix"
        );
    }
}
