#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "decode/PacketDecode.hpp"
#include "pcap/ClassicPcapReader.hpp"
#include "pcap/LinkType.hpp"
#include "pcap/PacketRecord.hpp"

#ifndef PCAP_CONSTRICTOR_SOURCE_DIR
#error "PCAP_CONSTRICTOR_SOURCE_DIR must be defined by CMake"
#endif

#ifndef PCAP_CONSTRICTOR_BINARY_DIR
#error "PCAP_CONSTRICTOR_BINARY_DIR must be defined by CMake"
#endif

#ifndef PCAP_CONSTRICTOR_EXE_PATH
#error "PCAP_CONSTRICTOR_EXE_PATH must be defined by CMake"
#endif

namespace pc::test {

struct TestContext {
    std::filesystem::path executable {};
    std::filesystem::path fixture {};
    std::filesystem::path output {};
    std::filesystem::path config {};
};

inline void require(const bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

[[nodiscard]] inline pc::decode::PacketDecodeResult decode_packet(const pc::pcap::PacketRecord& packet) {
    return pc::decode::decode_packet(
        pc::pcap::kLinkTypeEthernet,
        std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size())
    );
}

[[nodiscard]] std::vector<pc::pcap::PacketRecord> read_packets(const std::filesystem::path& path);

[[nodiscard]] int run_constrict_command(const TestContext& context);
[[nodiscard]] int run_reinflate_command(const TestContext& context);

void verify_common_packet_invariants(
    const std::vector<pc::pcap::PacketRecord>& input_packets,
    const std::vector<pc::pcap::PacketRecord>& output_packets
);

}  // namespace pc::test
