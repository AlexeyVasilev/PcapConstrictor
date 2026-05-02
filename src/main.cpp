#include <cstdint>
#include <filesystem>
#include <iostream>
#include <span>
#include <system_error>

#include "checksum/Checksum.hpp"
#include "cli/Options.hpp"
#include "config/Config.hpp"
#include "decode/PacketDecode.hpp"
#include "pcap/CaptureFormat.hpp"
#include "pcap/ClassicPcapReader.hpp"
#include "pcap/ClassicPcapWriter.hpp"
#include "pcap/PcapNgFormat.hpp"
#include "pcap/PcapNgReader.hpp"
#include "pcap/PcapNgWriter.hpp"
#include "quic/QuicConstrictor.hpp"
#include "stats/Stats.hpp"
#include "tls/TlsConstrictor.hpp"

namespace {

struct CompletionStatus {
    bool ok {true};
    bool incomplete_input {false};
};

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
    if (packet.captured_length < packet.original_length) {
        const auto filler_bytes = static_cast<std::uint64_t>(packet.original_length - packet.captured_length);
        packet.bytes.resize(packet.original_length, config.reinflate.fill_byte);
        packet.captured_length = packet.original_length;

        ++stats.packets_reinflated;
        stats.filler_bytes_written += filler_bytes;
    }

    if (config.reinflate.checksum_policy == pc::config::ChecksumPolicy::recompute) {
        stats.checksum_recompute_requested = true;
        const auto checksum_result = pc::checksum::recompute_packet_checksums(link_type, packet.bytes);
        stats.checksums_recomputed_ipv4 += checksum_result.checksums_recomputed_ipv4;
        stats.checksums_recomputed_tcp += checksum_result.checksums_recomputed_tcp;
        stats.checksums_recomputed_udp += checksum_result.checksums_recomputed_udp;
        stats.checksum_recompute_skipped += checksum_result.checksum_recompute_skipped;
        stats.checksum_recompute_skipped_unsupported_link_type +=
            checksum_result.checksum_recompute_skipped_unsupported_link_type;
        stats.checksum_recompute_skipped_decode_failed +=
            checksum_result.checksum_recompute_skipped_decode_failed;
        stats.checksum_recompute_skipped_malformed +=
            checksum_result.checksum_recompute_skipped_malformed;
        stats.checksum_recompute_skipped_fragment +=
            checksum_result.checksum_recompute_skipped_fragment;
        stats.checksum_recompute_skipped_not_tcp_udp +=
            checksum_result.checksum_recompute_skipped_not_tcp_udp;
        stats.checksum_recompute_skipped_incomplete +=
            checksum_result.checksum_recompute_skipped_incomplete;
        stats.checksum_recompute_skipped_length_mismatch +=
            checksum_result.checksum_recompute_skipped_length_mismatch;
        stats.checksum_recompute_skipped_ipv4_total_length_zero +=
            checksum_result.checksum_recompute_skipped_ipv4_total_length_zero;
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

void record_incomplete_classic_input(
    const pc::pcap::ClassicPcapReader& reader,
    pc::stats::Stats& stats,
    CompletionStatus& completion
) {
    if (!reader.incomplete_tail_info().has_value()) {
        return;
    }

    completion.ok = false;
    completion.incomplete_input = true;
    ++stats.input_incomplete_tail;

    const auto& info = *reader.incomplete_tail_info();
    if (info.kind == pc::pcap::ClassicPcapIncompleteTailKind::packet_header) {
        ++stats.input_incomplete_packet_records;
        stats.input_trailing_unprocessed_bytes += info.trailing_bytes;
    } else {
        ++stats.input_incomplete_packet_records;
        stats.input_trailing_unprocessed_bytes += info.available_payload_bytes;
        stats.input_missing_packet_payload_bytes += info.missing_payload_bytes;
    }
}

void record_incomplete_pcapng_input(
    const pc::pcap::PcapNgReader& reader,
    pc::stats::Stats& stats,
    CompletionStatus& completion
) {
    if (!reader.incomplete_tail_info().has_value()) {
        return;
    }

    completion.ok = false;
    completion.incomplete_input = true;
    ++stats.input_incomplete_tail;

    const auto& info = *reader.incomplete_tail_info();
    if (info.kind == pc::pcap::PcapNgIncompleteTailKind::block_header) {
        stats.input_trailing_unprocessed_bytes += info.trailing_bytes;
    } else {
        stats.input_trailing_unprocessed_bytes += info.available_block_bytes;
    }
}

[[nodiscard]] int run_classic_pcap_command(const pc::cli::Options& options, const pc::config::Config& config) {
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
    CompletionStatus completion {};

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
        record_incomplete_classic_input(reader, stats, completion);
        if (!completion.incomplete_input) {
            std::cerr << "error: " << reader.error_message() << '\n';
            return 1;
        }
    }

    if (writer.has_error()) {
        std::cerr << "error: " << writer.error_message() << '\n';
        return 1;
    }

    if (completion.incomplete_input) {
        std::cerr << "Warning: " << reader.error_message() << '\n'
            << "Warning: output contains only packets successfully processed before the incomplete tail.\n";
    }

    if (options.print_stats) {
        pc::stats::print_stats(std::cout, stats, reader.global_header());
    }

    return completion.ok ? 0 : 1;
}

[[nodiscard]] int run_pcapng_command(const pc::cli::Options& options, const pc::config::Config& config) {
    pc::pcap::PcapNgReader reader {};
    if (!reader.open(options.input_path)) {
        std::cerr << "error: " << reader.error_message() << '\n';
        return 1;
    }

    pc::pcap::PcapNgWriter writer {};
    if (!writer.open(options.output_path)) {
        std::cerr << "error: " << writer.error_message() << '\n';
        return 1;
    }

    pc::stats::Stats stats {};
    pc::tls::TlsConstrictor tls_constrictor {};
    pc::quic::QuicConstrictor quic_constrictor {};
    CompletionStatus completion {};

    while (auto block = reader.read_next()) {
        if (block->kind == pc::pcap::PcapNgBlockKind::raw) {
            if (block->type != pc::pcap::kPcapNgSectionHeaderBlockType) {
                ++stats.pcapng_unknown_blocks_copied;
            }

            if (!writer.write_raw_block(block->raw_bytes)) {
                std::cerr << "error: " << writer.error_message() << '\n';
                return 1;
            }
            continue;
        }

        if (block->kind == pc::pcap::PcapNgBlockKind::interface_description) {
            if (!writer.write_raw_block(block->raw_bytes)) {
                std::cerr << "error: " << writer.error_message() << '\n';
                return 1;
            }
            continue;
        }

        auto& enhanced_packet = block->enhanced_packet;
        auto& packet = enhanced_packet.packet;
        ++stats.pcapng_enhanced_packets;
        stats.total_captured_bytes_read += packet.captured_length;
        stats.total_original_bytes_read += packet.original_length;

        if (!enhanced_packet.interface_known) {
            ++stats.pcapng_unsupported_packets;
        } else if (options.command == pc::cli::Command::reinflate) {
            reinflate_packet(packet, stats, config, enhanced_packet.link_type);
        } else {
            apply_constrict_decision(
                packet,
                stats,
                enhanced_packet.link_type,
                tls_constrictor,
                quic_constrictor,
                config
            );
        }

        if (!writer.write_enhanced_packet(enhanced_packet)) {
            std::cerr << "error: " << writer.error_message() << '\n';
            return 1;
        }

        ++stats.total_packets;
        stats.total_captured_bytes_written += packet.captured_length;
        stats.total_original_bytes_written += packet.original_length;
    }

    writer.close();

    if (reader.has_error()) {
        record_incomplete_pcapng_input(reader, stats, completion);
        if (!completion.incomplete_input) {
            std::cerr << "error: " << reader.error_message() << '\n';
            return 1;
        }
    }

    if (writer.has_error()) {
        std::cerr << "error: " << writer.error_message() << '\n';
        return 1;
    }

    if (completion.incomplete_input) {
        std::cerr << "Warning: " << reader.error_message() << '\n'
            << "Warning: output contains only packets successfully processed before the incomplete tail.\n";
    }

    if (options.print_stats) {
        pc::stats::print_stats(
            std::cout,
            stats,
            pc::stats::PcapNgStatsContext {.endianness = reader.section_endianness()}
        );
    }

    return completion.ok ? 0 : 1;
}

[[nodiscard]] int run_capture_command(const pc::cli::Options& options, const pc::config::Config& config) {
    if (same_existing_file(options.input_path, options.output_path)) {
        std::cerr << "error: input and output paths refer to the same file\n";
        return 1;
    }

    const auto detected_format = pc::pcap::detect_capture_format(options.input_path);
    if (!detected_format.ok) {
        std::cerr << "error: " << detected_format.error << '\n';
        return 1;
    }

    if (detected_format.format == pc::pcap::CaptureFormat::classic_pcap) {
        return run_classic_pcap_command(options, config);
    }

    return run_pcapng_command(options, config);
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
