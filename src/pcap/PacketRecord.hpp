#pragma once

#include <cstdint>
#include <vector>

namespace pc::pcap {

struct PacketRecord {
    std::uint64_t packet_index {0};
    std::uint64_t header_offset {0};
    std::uint64_t data_offset {0};
    std::uint32_t ts_sec {0};
    std::uint32_t ts_fraction {0};
    std::uint32_t captured_length {0};
    std::uint32_t original_length {0};
    std::vector<std::uint8_t> bytes {};
};

}  // namespace pc::pcap

