#pragma once

#include <cstdint>
#include <vector>

namespace pc::checksum {

struct RecomputeResult {
    std::uint64_t checksums_recomputed_ipv4 {0};
    std::uint64_t checksums_recomputed_tcp {0};
    std::uint64_t checksums_recomputed_udp {0};
    std::uint64_t checksum_recompute_skipped {0};
    std::uint64_t checksum_recompute_skipped_unsupported_link_type {0};
    std::uint64_t checksum_recompute_skipped_decode_failed {0};
    std::uint64_t checksum_recompute_skipped_malformed {0};
    std::uint64_t checksum_recompute_skipped_fragment {0};
    std::uint64_t checksum_recompute_skipped_not_tcp_udp {0};
    std::uint64_t checksum_recompute_skipped_incomplete {0};
    std::uint64_t checksum_recompute_skipped_length_mismatch {0};
    std::uint64_t checksum_recompute_skipped_ipv4_total_length_zero {0};
};

[[nodiscard]] RecomputeResult recompute_packet_checksums(
    std::uint32_t link_type,
    std::vector<std::uint8_t>& packet
);

}  // namespace pc::checksum
