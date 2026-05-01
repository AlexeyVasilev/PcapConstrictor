#include "stats/Stats.hpp"

#include <ostream>

#include "bytes/Endian.hpp"

namespace pc::stats {

namespace {

void print_common_stats(std::ostream& out, const Stats& stats) {
    out << "total packets: " << stats.total_packets << '\n'
        << "total captured bytes read: " << stats.total_captured_bytes_read << '\n'
        << "total original bytes read: " << stats.total_original_bytes_read << '\n'
        << "total captured bytes written: " << stats.total_captured_bytes_written << '\n'
        << "total original bytes written: " << stats.total_original_bytes_written << '\n'
        << "already truncated input packets: " << stats.already_truncated_input_packets << '\n'
        << "packets reinflated: " << stats.packets_reinflated << '\n'
        << "filler bytes written: " << stats.filler_bytes_written << '\n'
        << "decoded TCP packets: " << stats.decoded_tcp_packets << '\n'
        << "decoded UDP packets: " << stats.decoded_udp_packets << '\n'
        << "malformed packets: " << stats.malformed_packets << '\n'
        << "unsupported link type packets: " << stats.unsupported_link_type_packets << '\n'
        << "TLS packets truncated: " << stats.tls_packets_truncated << '\n'
        << "TLS bytes saved: " << stats.tls_bytes_saved << '\n'
        << "TLS packets kept uncertain: " << stats.tls_packets_kept_uncertain << '\n'
        << "QUIC packets truncated: " << stats.quic_packets_truncated << '\n'
        << "QUIC bytes saved: " << stats.quic_bytes_saved << '\n'
        << "QUIC packets kept uncertain: " << stats.quic_packets_kept_uncertain << '\n'
        << "QUIC packets kept DCID mismatch: " << stats.quic_packets_kept_dcid_mismatch << '\n'
        << "checksums recomputed IPv4: " << stats.checksums_recomputed_ipv4 << '\n'
        << "checksums recomputed TCP: " << stats.checksums_recomputed_tcp << '\n'
        << "checksums recomputed UDP: " << stats.checksums_recomputed_udp << '\n'
        << "checksum recompute skipped: " << stats.checksum_recompute_skipped << '\n'
        << "checksum recompute skipped unsupported link type: " << stats.checksum_recompute_skipped_unsupported_link_type << '\n'
        << "checksum recompute skipped decode failed: " << stats.checksum_recompute_skipped_decode_failed << '\n'
        << "checksum recompute skipped malformed: " << stats.checksum_recompute_skipped_malformed << '\n'
        << "checksum recompute skipped fragment: " << stats.checksum_recompute_skipped_fragment << '\n'
        << "checksum recompute skipped not TCP/UDP: " << stats.checksum_recompute_skipped_not_tcp_udp << '\n'
        << "checksum recompute skipped incomplete: " << stats.checksum_recompute_skipped_incomplete << '\n'
        << "checksum recompute skipped length mismatch: " << stats.checksum_recompute_skipped_length_mismatch << '\n'
        << "checksum recompute skipped IPv4 total length zero: " << stats.checksum_recompute_skipped_ipv4_total_length_zero << '\n'
        << "pcapng enhanced packets: " << stats.pcapng_enhanced_packets << '\n'
        << "pcapng unknown blocks copied: " << stats.pcapng_unknown_blocks_copied << '\n'
        << "pcapng unsupported packets: " << stats.pcapng_unsupported_packets << '\n';
}

void print_warnings(std::ostream& out, const Stats& stats) {
    if (stats.already_truncated_input_packets != 0U) {
        out << "Warning: " << stats.already_truncated_input_packets
            << " input packets were already truncated and were kept unchanged.\n";
    }

    if (stats.checksum_recompute_requested && stats.checksum_recompute_skipped != 0U) {
        out << "Warning: checksum recomputation was skipped for " << stats.checksum_recompute_skipped
            << " packet(s):\n";

        if (stats.checksum_recompute_skipped_ipv4_total_length_zero != 0U) {
            out << "  ipv4_total_length_zero: " << stats.checksum_recompute_skipped_ipv4_total_length_zero << '\n';
        }
        if (stats.checksum_recompute_skipped_length_mismatch != 0U) {
            out << "  length_mismatch: " << stats.checksum_recompute_skipped_length_mismatch << '\n';
        }
        if (stats.checksum_recompute_skipped_incomplete != 0U) {
            out << "  incomplete: " << stats.checksum_recompute_skipped_incomplete << '\n';
        }
        if (stats.checksum_recompute_skipped_fragment != 0U) {
            out << "  fragment: " << stats.checksum_recompute_skipped_fragment << '\n';
        }
        if (stats.checksum_recompute_skipped_not_tcp_udp != 0U) {
            out << "  not_tcp_udp: " << stats.checksum_recompute_skipped_not_tcp_udp << '\n';
        }
        if (stats.checksum_recompute_skipped_malformed != 0U) {
            out << "  malformed: " << stats.checksum_recompute_skipped_malformed << '\n';
        }
        if (stats.checksum_recompute_skipped_decode_failed != 0U) {
            out << "  decode_failed: " << stats.checksum_recompute_skipped_decode_failed << '\n';
        }
        if (stats.checksum_recompute_skipped_unsupported_link_type != 0U) {
            out << "  unsupported_link_type: " << stats.checksum_recompute_skipped_unsupported_link_type << '\n';
        }

        out << "Skipped packets keep their existing checksum fields.\n";
    }
}

}  // namespace

void print_stats(std::ostream& out, const Stats& stats, const pc::pcap::ClassicPcapGlobalHeader& header) {
    out << "input format: pcap\n";
    print_common_stats(out, stats);
    out << "time precision: " << pc::pcap::to_string(header.time_precision) << '\n'
        << "endianness: " << pc::bytes::to_string(header.endianness) << '\n'
        << "link type: " << header.link_type << '\n'
        << "snaplen: " << header.snaplen << '\n';

    print_warnings(out, stats);
}

void print_stats(std::ostream& out, const Stats& stats, const PcapNgStatsContext& context) {
    out << "input format: pcapng\n";
    print_common_stats(out, stats);
    out << "endianness: " << pc::bytes::to_string(context.endianness) << '\n';
    print_warnings(out, stats);
}

}  // namespace pc::stats
