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
        << "time precision: " << pc::pcap::to_string(header.time_precision) << '\n'
        << "endianness: " << pc::bytes::to_string(header.endianness) << '\n'
        << "link type: " << header.link_type << '\n'
        << "snaplen: " << header.snaplen << '\n';
}

}  // namespace pc::stats

