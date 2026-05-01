#include <cstdint>
#include <filesystem>
#include <iostream>
#include <span>
#include <system_error>

#include "checksum/Checksum.hpp"
#include "cli/Options.hpp"
#include "config/Config.hpp"
#include "decode/PacketDecode.hpp"
#include "pcap/ClassicPcapReader.hpp"
#include "pcap/ClassicPcapWriter.hpp"
#include "quic/QuicConstrictor.hpp"
#include "stats/Stats.hpp"
#include "tls/TlsConstrictor.hpp"

namespace {

[[nodiscard]] bool same_existing_file(const std::filesystem::path& left, const std::filesystem::path& right) {
    std::error_code error {};
    if (!std::filesystem::exists(left, error) || error) {
        return false;
    }

    error.clear();
    if (!std::filesystem::exists(right, error) || error) {
        return false;
    }

    error.clear();
    return std::filesystem::equivalent(left, right, error) && !error;
}

void reinflate_packet(
    pc::pcap::PacketRecord& packet,
    pc::stats::Stats& stats,
    const pc::config::Config& config,
    const std::uint32_t link_type
) {
    if (packet.captured_length == packet.original_length) {
        return;
    }

    const auto filler_bytes = static_cast<std::uint64_t>(packet.original_length - packet.captured_length);
    packet.bytes.resize(packet.original_length, config.reinflate.fill_byte);
    packet.captured_length = packet.original_length;

    ++stats.packets_reinflated;
    stats.filler_bytes_written += filler_bytes;

    if (config.reinflate.checksum_policy == pc::config::ChecksumPolicy::recompute) {
        stats.checksum_recompute_requested = true;
        const auto checksum_result = pc::checksum::recompute_packet_checksums(link_type, packet.bytes);
        stats.checksums_recomputed_ipv4 += checksum_result.checksums_recomputed_ipv4;
        stats.checksums_recomputed_tcp += checksum_result.checksums_recomputed_tcp;
        stats.checksums_recomputed_udp += checksum_result.checksums_recomputed_udp;
        stats.checksum_recompute_skipped += checksum_result.checksum_recompute_skipped;
    }
}

void record_decode_stats(const pc::decode::PacketDecodeResult& decoded, pc::stats::Stats& stats) {
    if (decoded.unsupported_link_type) {
        ++stats.unsupported_link_type_packets;
        return;
    }

    if (decoded.malformed) {
        ++stats.malformed_packets;
        return;
    }

    if (decoded.transport == pc::decode::TransportProtocol::Tcp) {
        ++stats.decoded_tcp_packets;
    } else if (decoded.transport == pc::decode::TransportProtocol::Udp) {
        ++stats.decoded_udp_packets;
    }
}

void apply_constrict_decision(
    pc::pcap::PacketRecord& packet,
    pc::stats::Stats& stats,
    const std::uint32_t link_type,
    pc::tls::TlsConstrictor& tls_constrictor,
    pc::quic::QuicConstrictor& quic_constrictor,
    const pc::config::Config& config
) {
    if (packet.captured_length < packet.original_length) {
        ++stats.already_truncated_input_packets;
        return;
    }

    const auto decoded = pc::decode::decode_packet(
        link_type,
        std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size())
    );
    record_decode_stats(decoded, stats);
    tls_constrictor.process_tcp_packet(packet, decoded, config, stats);
    quic_constrictor.process_udp_packet(packet, decoded, config, stats);

    // Future constriction decisions belong after this guard.
}

[[nodiscard]] int run_capture_command(const pc::cli::Options& options, const pc::config::Config& config) {
    if (same_existing_file(options.input_path, options.output_path)) {
        std::cerr << "error: input and output paths refer to the same file\n";
        return 1;
    }

    pc::pcap::ClassicPcapReader reader {};
    if (!reader.open(options.input_path)) {
        std::cerr << "error: " << reader.error_message() << '\n';
        return 1;
    }

    pc::pcap::ClassicPcapWriter writer {};
    if (!writer.open(options.output_path, reader.global_header())) {
        std::cerr << "error: " << writer.error_message() << '\n';
        return 1;
    }

    pc::stats::Stats stats {};
    pc::tls::TlsConstrictor tls_constrictor {};
    pc::quic::QuicConstrictor quic_constrictor {};

    while (auto packet = reader.read_next()) {
        stats.total_captured_bytes_read += packet->captured_length;
        stats.total_original_bytes_read += packet->original_length;

        if (options.command == pc::cli::Command::reinflate) {
            reinflate_packet(*packet, stats, config, reader.global_header().link_type);
        } else {
            apply_constrict_decision(
                *packet,
                stats,
                reader.global_header().link_type,
                tls_constrictor,
                quic_constrictor,
                config
            );
        }

        if (!writer.write_packet(*packet)) {
            std::cerr << "error: " << writer.error_message() << '\n';
            return 1;
        }

        ++stats.total_packets;
        stats.total_captured_bytes_written += packet->captured_length;
        stats.total_original_bytes_written += packet->original_length;
    }

    writer.close();

    if (reader.has_error()) {
        std::cerr << "error: " << reader.error_message() << '\n';
        return 1;
    }

    if (writer.has_error()) {
        std::cerr << "error: " << writer.error_message() << '\n';
        return 1;
    }

    if (options.print_stats) {
        pc::stats::print_stats(std::cout, stats, reader.global_header());
    }

    return 0;
}

}  // namespace

int main(const int argc, char** argv) {
    const auto parsed = pc::cli::parse_options(argc, argv);
    if (parsed.show_help) {
        std::cout << pc::cli::usage();
        return 0;
    }

    if (!parsed.ok) {
        std::cerr << "error: " << parsed.error << "\n\n" << pc::cli::usage();
        return 1;
    }

    pc::config::Config config {};
    if (parsed.options.config_path.has_value()) {
        const auto loaded = pc::config::load_config_file(*parsed.options.config_path);
        if (!loaded.ok) {
            std::cerr << "error: " << loaded.error << '\n';
            return 1;
        }
        config = loaded.config;
    }

    return run_capture_command(parsed.options, config);
}
