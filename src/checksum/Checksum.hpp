#pragma once

#include <cstdint>
#include <vector>

namespace pc::checksum {

struct RecomputeResult {
    std::uint64_t checksums_recomputed_ipv4 {0};
    std::uint64_t checksums_recomputed_tcp {0};
    std::uint64_t checksums_recomputed_udp {0};
    std::uint64_t checksum_recompute_skipped {0};
};

[[nodiscard]] RecomputeResult recompute_packet_checksums(
    std::uint32_t link_type,
    std::vector<std::uint8_t>& packet
);

}  // namespace pc::checksum
