#pragma once

#include <cstdint>
#include <iosfwd>

#include "pcap/ClassicPcapFormat.hpp"

namespace pc::stats {

struct Stats {
    std::uint64_t total_packets {0};
    std::uint64_t total_captured_bytes_read {0};
    std::uint64_t total_original_bytes_read {0};
    std::uint64_t total_captured_bytes_written {0};
    std::uint64_t total_original_bytes_written {0};
    std::uint64_t already_truncated_input_packets {0};
    std::uint64_t packets_reinflated {0};
    std::uint64_t filler_bytes_written {0};
};

void print_stats(std::ostream& out, const Stats& stats, const pc::pcap::ClassicPcapGlobalHeader& header);

}  // namespace pc::stats
