#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <span>
#include <system_error>

#include "bytes/Endian.hpp"
#include "checksum/Checksum.hpp"
#include "cli/Options.hpp"
#include "config/Config.hpp"
#include "constrict/DecisionLog.hpp"
#include "constrict/PacketDecision.hpp"
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

[[nodiscard]] std::string ip_to_string(const pc::decode::IpAddress& ip) {
    if (ip.length == 4U) {
        std::ostringstream out {};
        out << static_cast<unsigned>(ip.bytes[0]) << '.'
            << static_cast<unsigned>(ip.bytes[1]) << '.'
            << static_cast<unsigned>(ip.bytes[2]) << '.'
            << static_cast<unsigned>(ip.bytes[3]);
        return out.str();
    }

    if (ip.length == 16U) {
        std::ostringstream out {};
        out << std::hex;
        for (std::size_t index = 0; index < 16U; index += 2U) {
            if (index != 0U) {
                out << ':';
            }
            const auto value = static_cast<unsigned>((static_cast<unsigned>(ip.bytes[index]) << 8U) | ip.bytes[index + 1U]);
            out << value;
        }
        return out.str();
    }

    return {};
}

[[nodiscard]] std::string tcp_flags_to_string(const std::uint8_t flags) {
    std::ostringstream out {};
    out << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
        << static_cast<unsigned>(flags);
    return out.str();
}

[[nodiscard]] std::string join_notes(const std::initializer_list<std::string_view> notes) {
    std::string joined {};
    for (const auto note : notes) {
        if (note.empty()) {
            continue;
        }
        if (!joined.empty()) {
            joined += '|';
        }
        joined += note;
    }
    return joined;
}

[[nodiscard]] std::string decode_note_for_packet(
    const pc::pcap::PacketRecord& packet,
    const pc::decode::PacketDecodeResult& decoded
) {
    std::string ipv4_total_length_note {};
    std::string ignored_tail_note {};
    std::string truncated_transport_note {};

    if (decoded.src_ip.length == 4U &&
        packet.bytes.size() >= decoded.network_header_offset + 4U) {
        const auto total_length = pc::bytes::read_be16(
            std::span<const std::uint8_t, 2>(packet.bytes.data() + decoded.network_header_offset + 2U, 2U)
        );
        const auto captured_ip_bytes = packet.bytes.size() - decoded.network_header_offset;
        if (static_cast<std::size_t>(total_length) < captured_ip_bytes) {
            ipv4_total_length_note = "ipv4_total_length_smaller_than_captured_ip_bytes";
            ignored_tail_note = "captured_bytes_after_ipv4_total_length_ignored";
        }
    }

    if (decoded.decoded &&
        decoded.transport_payload_offset + decoded.transport_payload_size < packet.bytes.size()) {
        truncated_transport_note = "transport_payload_truncated_by_length_fields";
    }

    return join_notes({ipv4_total_length_note, ignored_tail_note, truncated_transport_note});
}

[[nodiscard]] bool should_log_decision_row(
    const pc::decode::PacketDecodeResult& decoded,
    const bool already_truncated
) {
    if (already_truncated || decoded.unsupported_link_type || decoded.malformed) {
        return true;
    }

    return decoded.transport == pc::decode::TransportProtocol::Tcp && decoded.transport_payload_size != 0U;
}

[[nodiscard]] pc::constrict::DecisionLogRow make_decision_log_row(
    const std::size_t packet_index,
    const pc::pcap::PacketRecord& before,
    const pc::pcap::PacketRecord& after,
    const pc::decode::PacketDecodeResult& decoded,
    const pc::constrict::PacketDecisionDiagnostics& diagnostics
) {
    return {
        .packet_index = packet_index,
        .src_ip = ip_to_string(decoded.src_ip),
        .src_port = decoded.src_port,
        .dst_ip = ip_to_string(decoded.dst_ip),
        .dst_port = decoded.dst_port,
        .transport = decoded.transport == pc::decode::TransportProtocol::Tcp ? "tcp" :
                     decoded.transport == pc::decode::TransportProtocol::Udp ? "udp" : "",
        .tcp_seq = decoded.tcp_seq,
        .tcp_ack = decoded.tcp_ack,
        .tcp_flags = decoded.transport == pc::decode::TransportProtocol::Tcp ? tcp_flags_to_string(decoded.tcp_flags) : "",
        .captured_length_before = before.captured_length,
        .captured_length_after = after.captured_length,
        .original_length = after.original_length,
        .transport_payload_size = decoded.transport_payload_size,
        .decision = diagnostics.decision,
        .reason = diagnostics.reason,
        .bytes_saved = static_cast<std::uint64_t>(before.captured_length - after.captured_length),
        .tls_state_before = diagnostics.tls_state_before,
        .tls_state_after = diagnostics.tls_state_after,
        .tls_active_record_remaining_before = diagnostics.tls_active_record_remaining_before,
        .tls_active_record_remaining_after = diagnostics.tls_active_record_remaining_after,
        .tls_record_event = diagnostics.tls_record_event,
        .decode_note = diagnostics.decode_note,
    };
}

[[nodiscard]] std::mt19937& reinflate_random_generator() {
    static std::mt19937 generator {std::random_device {}()};
    return generator;
}

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
        const auto old_size = packet.bytes.size();
        packet.bytes.resize(packet.original_length, config.reinflate.fill_byte);
        if (config.reinflate.fill_mode == pc::config::FillMode::random) {
            std::uniform_int_distribution<unsigned int> distribution(0U, 0xFFU);
            auto& generator = reinflate_random_generator();
            for (std::size_t index = old_size; index < packet.bytes.size(); ++index) {
                packet.bytes[index] = static_cast<std::uint8_t>(distribution(generator));
            }
        }
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

[[nodiscard]] pc::decode::PacketDecodeResult apply_constrict_decision(
    pc::pcap::PacketRecord& packet,
    pc::stats::Stats& stats,
    const std::uint32_t link_type,
    pc::tls::TlsConstrictor& tls_constrictor,
    pc::quic::QuicConstrictor& quic_constrictor,
    const pc::config::Config& config,
    pc::constrict::PacketDecisionDiagnostics* diagnostics = nullptr
) {
    if (packet.captured_length < packet.original_length) {
        ++stats.already_truncated_input_packets;
        if (diagnostics != nullptr) {
            diagnostics->decision = "keep";
            diagnostics->reason = "keep.already_truncated";
        }
        return {};
    }

    const auto decoded = pc::decode::decode_packet(
        link_type,
        std::span<const std::uint8_t>(packet.bytes.data(), packet.bytes.size())
    );
    record_decode_stats(decoded, stats);
    if (diagnostics != nullptr) {
        diagnostics->decode_note = decode_note_for_packet(packet, decoded);
        diagnostics->decision = "keep";
        if (decoded.unsupported_link_type) {
            diagnostics->reason = "keep.unsupported_link_type";
        } else if (decoded.malformed) {
            diagnostics->reason = "keep.decode_malformed";
        } else if (decoded.transport == pc::decode::TransportProtocol::Tcp && decoded.transport_payload_size == 0U) {
            diagnostics->reason = "keep.no_payload";
        } else if (decoded.transport != pc::decode::TransportProtocol::Tcp) {
            diagnostics->reason = "keep.not_tcp";
        } else {
            diagnostics->reason = "keep.no_candidate";
        }
    }
    tls_constrictor.process_tcp_packet(packet, decoded, config, stats, diagnostics);
    quic_constrictor.process_udp_packet(packet, decoded, config, stats);

    // Future constriction decisions belong after this guard.
    return decoded;
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
    pc::constrict::DecisionLogWriter decision_log_writer {};
    const bool write_decision_log = options.decision_log_path.has_value();
    if (write_decision_log && !decision_log_writer.open(*options.decision_log_path)) {
        std::cerr << "error: " << decision_log_writer.error_message() << '\n';
        return 1;
    }

    while (auto packet = reader.read_next()) {
        const auto before_packet = *packet;
        const auto packet_index = static_cast<std::size_t>(stats.total_packets + 1U);
        stats.total_captured_bytes_read += packet->captured_length;
        stats.total_original_bytes_read += packet->original_length;

        if (options.command == pc::cli::Command::reinflate) {
            reinflate_packet(*packet, stats, config, reader.global_header().link_type);
        } else {
            pc::constrict::PacketDecisionDiagnostics diagnostics {};
            const auto decoded = apply_constrict_decision(
                *packet,
                stats,
                reader.global_header().link_type,
                tls_constrictor,
                quic_constrictor,
                config,
                write_decision_log ? &diagnostics : nullptr
            );
            if (write_decision_log && should_log_decision_row(decoded, before_packet.captured_length < before_packet.original_length)) {
                if (!decision_log_writer.write_row(make_decision_log_row(packet_index, before_packet, *packet, decoded, diagnostics))) {
                    std::cerr << "error: " << decision_log_writer.error_message() << '\n';
                    return 1;
                }
            }
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
    decision_log_writer.close();

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

    if (write_decision_log && decision_log_writer.has_error()) {
        std::cerr << "error: " << decision_log_writer.error_message() << '\n';
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
            reader.global_header(),
            config.tls.app_data_continuation_policy
        );
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
    pc::constrict::DecisionLogWriter decision_log_writer {};
    const bool write_decision_log = options.decision_log_path.has_value();
    if (write_decision_log && !decision_log_writer.open(*options.decision_log_path)) {
        std::cerr << "error: " << decision_log_writer.error_message() << '\n';
        return 1;
    }

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
        const auto before_packet = packet;
        const auto packet_index = static_cast<std::size_t>(stats.total_packets + 1U);
        ++stats.pcapng_enhanced_packets;
        stats.total_captured_bytes_read += packet.captured_length;
        stats.total_original_bytes_read += packet.original_length;

        if (!enhanced_packet.interface_known) {
            ++stats.pcapng_unsupported_packets;
        } else if (options.command == pc::cli::Command::reinflate) {
            reinflate_packet(packet, stats, config, enhanced_packet.link_type);
        } else {
            pc::constrict::PacketDecisionDiagnostics diagnostics {};
            const auto decoded = apply_constrict_decision(
                packet,
                stats,
                enhanced_packet.link_type,
                tls_constrictor,
                quic_constrictor,
                config,
                write_decision_log ? &diagnostics : nullptr
            );
            if (write_decision_log && should_log_decision_row(decoded, before_packet.captured_length < before_packet.original_length)) {
                if (!decision_log_writer.write_row(make_decision_log_row(packet_index, before_packet, packet, decoded, diagnostics))) {
                    std::cerr << "error: " << decision_log_writer.error_message() << '\n';
                    return 1;
                }
            }
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
    decision_log_writer.close();

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

    if (write_decision_log && decision_log_writer.has_error()) {
        std::cerr << "error: " << decision_log_writer.error_message() << '\n';
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
            pc::stats::PcapNgStatsContext {
                .endianness = reader.section_endianness(),
                .tls_app_data_continuation_policy = config.tls.app_data_continuation_policy,
            }
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
    if (parsed.show_version) {
        std::cout << pc::cli::version_string() << '\n';
        return 0;
    }

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

    if (parsed.options.decision_log_path.has_value() &&
        parsed.options.command != pc::cli::Command::constrict) {
        std::cerr << "error: --decision-log is supported only with constrict mode\n";
        return 1;
    }

    return run_capture_command(parsed.options, config);
}
