#pragma once

#include <cstdint>
#include <iosfwd>

#include "pcap/ClassicPcapFormat.hpp"

namespace pc::stats {

struct PcapNgStatsContext {
    pc::bytes::Endianness endianness {pc::bytes::Endianness::little};
};

struct Stats {
    std::uint64_t total_packets {0};
    std::uint64_t total_captured_bytes_read {0};
    std::uint64_t total_original_bytes_read {0};
    std::uint64_t total_captured_bytes_written {0};
    std::uint64_t total_original_bytes_written {0};
    std::uint64_t already_truncated_input_packets {0};
    std::uint64_t packets_reinflated {0};
    std::uint64_t filler_bytes_written {0};
    std::uint64_t decoded_tcp_packets {0};
    std::uint64_t decoded_udp_packets {0};
    std::uint64_t malformed_packets {0};
    std::uint64_t unsupported_link_type_packets {0};
    std::uint64_t tls_packets_truncated {0};
    std::uint64_t tls_bytes_saved {0};
    std::uint64_t tls_packets_kept_uncertain {0};
    std::uint64_t quic_packets_truncated {0};
    std::uint64_t quic_bytes_saved {0};
    std::uint64_t quic_packets_kept_uncertain {0};
    std::uint64_t quic_packets_kept_dcid_mismatch {0};
    bool checksum_recompute_requested {false};
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
    std::uint64_t pcapng_enhanced_packets {0};
    std::uint64_t pcapng_unknown_blocks_copied {0};
    std::uint64_t pcapng_unsupported_packets {0};
};

void print_stats(std::ostream& out, const Stats& stats, const pc::pcap::ClassicPcapGlobalHeader& header);
void print_stats(std::ostream& out, const Stats& stats, const PcapNgStatsContext& context);

}  // namespace pc::stats
