#include "stats/Stats.hpp"

#include <ostream>

#include "bytes/Endian.hpp"

namespace pc::stats {

void print_stats(std::ostream& out, const Stats& stats, const pc::pcap::ClassicPcapGlobalHeader& header) {
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
        << "time precision: " << pc::pcap::to_string(header.time_precision) << '\n'
        << "endianness: " << pc::bytes::to_string(header.endianness) << '\n'
        << "link type: " << header.link_type << '\n'
        << "snaplen: " << header.snaplen << '\n';

    if (stats.already_truncated_input_packets != 0U) {
        out << "Warning: " << stats.already_truncated_input_packets
            << " input packets were already truncated and were kept unchanged.\n";
    }
}

}  // namespace pc::stats
