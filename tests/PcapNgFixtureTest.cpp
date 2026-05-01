#include "TestHelpers.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "pcap/PcapNgFormat.hpp"
#include "pcap/PcapNgReader.hpp"

using namespace pc::test;

namespace {

[[nodiscard]] std::filesystem::path fixture_path() {
    const std::filesystem::path source_dir {PCAP_CONSTRICTOR_SOURCE_DIR};
    return source_dir / "tests" / "fixtures" / "pcapng" / "tls_quic_test_1.pcapng";
}

[[nodiscard]] std::filesystem::path output_dir() {
    const std::filesystem::path binary_dir {PCAP_CONSTRICTOR_BINARY_DIR};
    const auto path = binary_dir / "test-output" / "pcapng";
    std::filesystem::create_directories(path);
    return path;
}

[[nodiscard]] std::vector<pc::pcap::PcapNgBlock> read_pcapng_blocks(const std::filesystem::path& path) {
    pc::pcap::PcapNgReader reader {};
    if (!reader.open(path)) {
        throw std::runtime_error("failed to open pcapng: " + reader.error_message());
    }

    std::vector<pc::pcap::PcapNgBlock> blocks {};
    while (auto block = reader.read_next()) {
        blocks.push_back(std::move(*block));
    }

    if (reader.has_error()) {
        throw std::runtime_error("failed to read pcapng: " + reader.error_message());
    }

    return blocks;
}

void verify_pcapng_constrict_result(
    const std::vector<pc::pcap::PcapNgBlock>& input_blocks,
    const std::vector<pc::pcap::PcapNgBlock>& output_blocks
) {
    require(output_blocks.size() == input_blocks.size(), "pcapng block count changed");

    std::size_t section_headers = 0;
    std::size_t interface_descriptions = 0;
    std::size_t enhanced_packets = 0;
    bool saw_constricted_packet = false;

    for (std::size_t index = 0; index < input_blocks.size(); ++index) {
        const auto& before = input_blocks[index];
        const auto& after = output_blocks[index];
        require(before.kind == after.kind, "pcapng block kind changed");
        require(before.type == after.type, "pcapng block type changed");

        if (before.type == pc::pcap::kPcapNgSectionHeaderBlockType) {
            ++section_headers;
        }

        if (before.kind == pc::pcap::PcapNgBlockKind::raw) {
            require(after.raw_bytes == before.raw_bytes, "pcapng raw block changed");
            continue;
        }

        if (before.kind == pc::pcap::PcapNgBlockKind::interface_description) {
            ++interface_descriptions;
            require(after.raw_bytes == before.raw_bytes, "pcapng Interface Description Block changed");
            require(after.interface_description.interface_id == before.interface_description.interface_id, "pcapng interface id changed");
            require(after.interface_description.link_type == before.interface_description.link_type, "pcapng interface link type changed");
            require(after.interface_description.snaplen == before.interface_description.snaplen, "pcapng interface snaplen changed");
            continue;
        }

        ++enhanced_packets;
        const auto& before_packet = before.enhanced_packet;
        const auto& after_packet = after.enhanced_packet;
        require(after_packet.interface_id == before_packet.interface_id, "pcapng EPB interface id changed");
        require(after_packet.timestamp_high == before_packet.timestamp_high, "pcapng EPB timestamp high changed");
        require(after_packet.timestamp_low == before_packet.timestamp_low, "pcapng EPB timestamp low changed");
        require(after_packet.packet.original_length == before_packet.packet.original_length, "pcapng EPB original length changed");
        require(after_packet.packet.captured_length <= before_packet.packet.captured_length, "pcapng EPB captured length grew");
        require(after_packet.packet.bytes.size() == after_packet.packet.captured_length, "pcapng EPB byte size does not match captured length");
        require(
            std::equal(after_packet.packet.bytes.begin(), after_packet.packet.bytes.end(), before_packet.packet.bytes.begin()),
            "pcapng EPB output bytes are not an input prefix"
        );
        require(after_packet.options_raw == before_packet.options_raw, "pcapng EPB options changed");

        if (after_packet.packet.captured_length < before_packet.packet.captured_length) {
            saw_constricted_packet = true;
        }
    }

    require(section_headers != 0U, "expected at least one PCAPNG Section Header Block");
    require(interface_descriptions != 0U, "expected at least one PCAPNG Interface Description Block");
    require(enhanced_packets != 0U, "expected at least one PCAPNG Enhanced Packet Block");
    require(saw_constricted_packet, "expected at least one PCAPNG packet to be constricted");
}

void verify_pcapng_reinflate_result(
    const std::vector<pc::pcap::PcapNgBlock>& constricted_blocks,
    const std::vector<pc::pcap::PcapNgBlock>& reinflated_blocks
) {
    require(reinflated_blocks.size() == constricted_blocks.size(), "pcapng block count changed after reinflate");

    bool saw_restored_packet = false;

    for (std::size_t index = 0; index < constricted_blocks.size(); ++index) {
        const auto& before = constricted_blocks[index];
        const auto& after = reinflated_blocks[index];
        require(before.kind == after.kind, "pcapng block kind changed after reinflate");
        require(before.type == after.type, "pcapng block type changed after reinflate");

        if (before.kind == pc::pcap::PcapNgBlockKind::raw) {
            require(after.raw_bytes == before.raw_bytes, "pcapng raw block changed after reinflate");
            continue;
        }

        if (before.kind == pc::pcap::PcapNgBlockKind::interface_description) {
            require(after.raw_bytes == before.raw_bytes, "pcapng Interface Description Block changed after reinflate");
            continue;
        }

        const auto& before_packet = before.enhanced_packet;
        const auto& after_packet = after.enhanced_packet;
        require(after_packet.timestamp_high == before_packet.timestamp_high, "pcapng EPB timestamp high changed after reinflate");
        require(after_packet.timestamp_low == before_packet.timestamp_low, "pcapng EPB timestamp low changed after reinflate");
        require(after_packet.packet.original_length == before_packet.packet.original_length, "pcapng EPB original length changed after reinflate");
        require(after_packet.options_raw == before_packet.options_raw, "pcapng EPB options changed after reinflate");

        if (before_packet.packet.captured_length < before_packet.packet.original_length) {
            require(
                after_packet.packet.captured_length == before_packet.packet.original_length,
                "pcapng reinflate did not restore captured length to original length"
            );
            require(
                std::equal(
                    before_packet.packet.bytes.begin(),
                    before_packet.packet.bytes.end(),
                    after_packet.packet.bytes.begin()
                ),
                "pcapng reinflate did not preserve the captured prefix"
            );
            saw_restored_packet = true;
        } else {
            require(after_packet.packet.captured_length == before_packet.packet.captured_length, "pcapng reinflate changed full packet captured length");
            require(after_packet.packet.bytes == before_packet.packet.bytes, "pcapng reinflate changed full packet bytes");
        }
    }

    require(saw_restored_packet, "expected at least one PCAPNG packet to be restored by reinflate");
}

}  // namespace

void run_pcapng_fixture_test() {
    const auto input_path = fixture_path();
    const auto constricted_output = output_dir() / "tls_quic_test_1.constricted.pcapng";
    const auto reinflated_output = output_dir() / "tls_quic_test_1.reinflated.pcapng";

    {
        const TestContext context {
            .executable = std::filesystem::path {PCAP_CONSTRICTOR_EXE_PATH},
            .fixture = input_path,
            .output = constricted_output,
        };
        const int exit_code = run_constrict_command(context);
        if (exit_code == -1) {
            throw std::runtime_error(std::string("failed to spawn PCAPNG constrict command: ") + std::strerror(errno));
        }
        require(exit_code == 0, "PCAPNG constrict command failed");
    }

    const auto input_blocks = read_pcapng_blocks(input_path);
    const auto constricted_blocks = read_pcapng_blocks(constricted_output);
    verify_pcapng_constrict_result(input_blocks, constricted_blocks);

    {
        const TestContext context {
            .executable = std::filesystem::path {PCAP_CONSTRICTOR_EXE_PATH},
            .fixture = constricted_output,
            .output = reinflated_output,
        };
        const int exit_code = run_reinflate_command(context);
        if (exit_code == -1) {
            throw std::runtime_error(std::string("failed to spawn PCAPNG reinflate command: ") + std::strerror(errno));
        }
        require(exit_code == 0, "PCAPNG reinflate command failed");
    }

    const auto reinflated_blocks = read_pcapng_blocks(reinflated_output);
    verify_pcapng_reinflate_result(constricted_blocks, reinflated_blocks);
}
