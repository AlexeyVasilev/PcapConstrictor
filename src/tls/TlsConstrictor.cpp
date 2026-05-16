#include "tls/TlsConstrictor.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <span>

#include "bytes/Endian.hpp"

namespace pc::tls {

namespace {

constexpr std::uint8_t kTlsChangeCipherSpec = 0x14U;
constexpr std::uint8_t kTlsAlert = 0x15U;
constexpr std::uint8_t kTlsHandshake = 0x16U;
constexpr std::uint8_t kTlsApplicationData = 0x17U;
constexpr std::size_t kTlsRecordHeaderSize = 5U;
constexpr std::uint8_t kTcpFlagSyn = 0x02U;
constexpr std::uint8_t kTcpFlagRst = 0x04U;

[[nodiscard]] bool has_bytes(
    const std::span<const std::uint8_t> bytes,
    const std::size_t offset,
    const std::size_t count
) noexcept {
    return offset <= bytes.size() && count <= bytes.size() - offset;
}

[[nodiscard]] bool is_tls_content_type(const std::uint8_t content_type) noexcept {
    return content_type == kTlsChangeCipherSpec ||
           content_type == kTlsAlert ||
           content_type == kTlsHandshake ||
           content_type == kTlsApplicationData;
}

[[nodiscard]] bool read_tls_record_header(
    const std::span<const std::uint8_t> payload,
    const std::size_t offset,
    std::uint8_t& content_type,
    std::uint16_t& record_length
) noexcept {
    if (!has_bytes(payload, offset, kTlsRecordHeaderSize)) {
        return false;
    }

    content_type = payload[offset];
    if (!is_tls_content_type(content_type) || payload[offset + 1U] != 0x03U) {
        return false;
    }

    record_length = pc::bytes::read_be16(std::span<const std::uint8_t, 2>(payload.data() + offset + 3U, 2U));
    return true;
}

[[nodiscard]] std::uint32_t advance_tcp_seq(const std::uint32_t seq, const std::size_t payload_size) noexcept {
    return seq + static_cast<std::uint32_t>(payload_size);
}

[[nodiscard]] std::size_t clamped_keep_size(const std::uint32_t configured, const std::size_t available) noexcept {
    return std::min(static_cast<std::size_t>(configured), available);
}

enum class TlsTruncationKind {
    none,
    app_data_start,
    final_continuation,
    stream_continuation,
    bulk_continuation,
};

}  // namespace

bool TlsConstrictor::DirectionKey::operator==(const DirectionKey& other) const noexcept {
    return src_ip.length == other.src_ip.length &&
           dst_ip.length == other.dst_ip.length &&
           src_ip.bytes == other.src_ip.bytes &&
           dst_ip.bytes == other.dst_ip.bytes &&
           src_port == other.src_port &&
           dst_port == other.dst_port;
}

std::size_t TlsConstrictor::DirectionKeyHash::operator()(const DirectionKey& key) const noexcept {
    std::size_t hash = static_cast<std::size_t>(1469598103934665603ULL);
    auto mix = [&hash](const std::uint8_t value) noexcept {
        hash ^= value;
        hash *= static_cast<std::size_t>(1099511628211ULL);
    };

    mix(key.src_ip.length);
    for (std::size_t index = 0; index < key.src_ip.length; ++index) {
        mix(key.src_ip.bytes[index]);
    }
    mix(key.dst_ip.length);
    for (std::size_t index = 0; index < key.dst_ip.length; ++index) {
        mix(key.dst_ip.bytes[index]);
    }
    mix(static_cast<std::uint8_t>(key.src_port >> 8U));
    mix(static_cast<std::uint8_t>(key.src_port & 0x00FFU));
    mix(static_cast<std::uint8_t>(key.dst_port >> 8U));
    mix(static_cast<std::uint8_t>(key.dst_port & 0x00FFU));
    return hash;
}

void TlsConstrictor::process_tcp_packet(
    pc::pcap::PacketRecord& packet,
    const pc::decode::PacketDecodeResult& decoded,
    const pc::config::Config& config,
    pc::stats::Stats& stats,
    pc::constrict::PacketDecisionDiagnostics* diagnostics
) {
    if (!decoded.decoded || decoded.transport != pc::decode::TransportProtocol::Tcp) {
        return;
    }

    const DirectionKey key {
        .src_ip = decoded.src_ip,
        .dst_ip = decoded.dst_ip,
        .src_port = decoded.src_port,
        .dst_port = decoded.dst_port,
    };
    const DirectionKey reverse_key {
        .src_ip = decoded.dst_ip,
        .dst_ip = decoded.src_ip,
        .src_port = decoded.dst_port,
        .dst_port = decoded.src_port,
    };

    if ((decoded.tcp_flags & (kTcpFlagSyn | kTcpFlagRst)) != 0U) {
        directions_.erase(key);
        directions_.erase(reverse_key);
        ++stats.tls_packets_state_reset_on_syn_or_rst;
        if (diagnostics != nullptr) {
            diagnostics->tls_record_event = "syn_or_rst_state_reset";
        }
    }

    if (decoded.transport_payload_size == 0U) {
        return;
    }

    const auto existing_state = directions_.find(key);
    const bool state_existed_before = existing_state != directions_.end();
    const DirectionState state_before = state_existed_before ? existing_state->second : DirectionState {};

    auto& state = directions_[key];
    auto format_tls_state = [](const bool exists, const DirectionState& state_value) {
        if (!exists) {
            return std::string {"none"};
        }

        std::string value = state_value.confirmed_tls ? "confirmed" : "unconfirmed";
        value += state_value.synchronized ? "/synchronized" : "/unsynchronized";
        if (state_value.has_seen_application_data) {
            value += "/seen_app_data";
        }
        if (state_value.has_active_record) {
            value += state_value.active_record_constrictible ? "/active_app_data" : "/active_non_app_data";
        }
        return value;
    };
    auto clear_active_record = [&state]() noexcept {
        state.has_active_record = false;
        state.active_record_constrictible = false;
        state.active_record_content_type = 0U;
        state.active_record_remaining_bytes = 0U;
    };
    auto finalize_diagnostics = [&](const std::string& decision, const std::string& reason) {
        if (diagnostics == nullptr) {
            return;
        }

        diagnostics->decision = decision;
        diagnostics->reason = reason;
        const auto found_after = directions_.find(key);
        const bool state_exists_after = found_after != directions_.end();
        const DirectionState state_after = state_exists_after ? found_after->second : DirectionState {};
        diagnostics->tls_state_after = format_tls_state(state_exists_after, state_after);
        diagnostics->tls_active_record_remaining_after =
            state_exists_after && state_after.has_active_record ? state_after.active_record_remaining_bytes : 0U;
    };
    if (diagnostics != nullptr) {
        diagnostics->tls_state_before = format_tls_state(state_existed_before, state_before);
        diagnostics->tls_active_record_remaining_before =
            state_existed_before && state_before.has_active_record ? state_before.active_record_remaining_bytes : 0U;
    }
    const bool confirmed_tls = state.confirmed_tls;
    const auto payload = std::span<const std::uint8_t>(
        packet.bytes.data() + decoded.transport_payload_offset,
        decoded.transport_payload_size
    );
    bool saw_seq_mismatch = false;

    if (state.synchronized && decoded.tcp_seq != state.expected_tcp_seq) {
        ++stats.tls_packets_kept_tcp_seq_mismatch;
        ++stats.tls_packets_state_reset_on_seq_mismatch;
        saw_seq_mismatch = true;
        if (diagnostics != nullptr) {
            diagnostics->tls_record_event = "tcp_seq_mismatch";
        }
        clear_active_record();
        state.synchronized = false;
        state.expected_tcp_seq = 0U;
    }

    std::size_t payload_offset = 0;
    std::size_t candidate_payload_size = decoded.transport_payload_size;
    bool has_candidate = false;
    bool uncertain = false;
    bool reset_direction = false;
    TlsTruncationKind truncation_kind = TlsTruncationKind::none;
    bool kept_middle_continuation = false;
    bool kept_app_data_continuation_with_extra_bytes = false;
    bool resynchronized = false;
    bool resynchronized_app_data_start = false;
    bool stream_boundary_parse_pending = false;
    bool stream_boundary_parse_succeeded = false;
    bool app_data_start_after_stream_boundary = false;
    bool bulk_unsynchronized_candidate = false;

    if (state.has_active_record) {
        const auto remaining_record_bytes = static_cast<std::size_t>(state.active_record_remaining_bytes);
        if (remaining_record_bytes > payload.size()) {
            if (state.active_record_constrictible) {
                if (config.tls.app_data_continuation_policy != pc::config::TlsAppDataContinuationPolicy::final_only) {
                    candidate_payload_size = clamped_keep_size(
                        config.tls.app_data_continuation_keep_bytes,
                        payload.size()
                    );
                    has_candidate = true;
                    truncation_kind = TlsTruncationKind::stream_continuation;
                    if (diagnostics != nullptr) {
                        diagnostics->tls_record_event = "stream_continuation";
                    }
                } else {
                    kept_middle_continuation = true;
                    if (diagnostics != nullptr) {
                        diagnostics->tls_record_event = "middle_continuation";
                    }
                }
            }
            state.active_record_remaining_bytes -= static_cast<std::uint32_t>(payload.size());
            payload_offset = payload.size();
        } else if (remaining_record_bytes == payload.size()) {
            if (state.active_record_constrictible) {
                candidate_payload_size = clamped_keep_size(config.tls.app_data_continuation_keep_bytes, payload.size());
                has_candidate = true;
                truncation_kind = TlsTruncationKind::final_continuation;
                if (diagnostics != nullptr) {
                    diagnostics->tls_record_event = "final_continuation";
                }
            }

            payload_offset = payload.size();
            clear_active_record();
        } else {
            payload_offset = remaining_record_bytes;
            if (state.active_record_constrictible) {
                clear_active_record();
                if (config.tls.app_data_continuation_policy != pc::config::TlsAppDataContinuationPolicy::final_only) {
                    stream_boundary_parse_pending = true;
                    if (diagnostics != nullptr) {
                        diagnostics->tls_record_event = "app_data_continuation_boundary";
                    }
                } else {
                    reset_direction = true;
                    kept_app_data_continuation_with_extra_bytes = true;
                    if (diagnostics != nullptr) {
                        diagnostics->tls_record_event = "app_data_continuation_with_extra_bytes";
                    }
                }
            } else {
                clear_active_record();
            }
        }
    }

    while (!uncertain && !reset_direction && payload_offset < payload.size()) {
        std::uint8_t content_type = 0;
        std::uint16_t record_length = 0;
        if (!read_tls_record_header(payload, payload_offset, content_type, record_length)) {
            if (stream_boundary_parse_pending) {
                kept_app_data_continuation_with_extra_bytes = true;
                reset_direction = true;
                if (diagnostics != nullptr) {
                    diagnostics->tls_record_event = "app_data_continuation_boundary_parse_failed";
                }
                break;
            }
            if (!state.synchronized) {
                if (confirmed_tls &&
                    state.has_seen_application_data &&
                    config.tls.app_data_continuation_policy == pc::config::TlsAppDataContinuationPolicy::bulk) {
                    candidate_payload_size = clamped_keep_size(
                        config.tls.app_data_continuation_keep_bytes,
                        payload.size()
                    );
                    has_candidate = true;
                    bulk_unsynchronized_candidate = true;
                    truncation_kind = TlsTruncationKind::bulk_continuation;
                    if (diagnostics != nullptr) {
                        diagnostics->tls_record_event = "bulk_continuation";
                    }
                    break;
                }
                if (!confirmed_tls) {
                    directions_.erase(key);
                } else if (saw_seq_mismatch) {
                    ++stats.tls_packets_kept_uncertain;
                }
                finalize_diagnostics(
                    "keep",
                    saw_seq_mismatch ? "keep.tcp_seq_mismatch" : "keep.no_candidate"
                );
                return;
            }
            uncertain = true;
            break;
        }

        if (stream_boundary_parse_pending) {
            stream_boundary_parse_pending = false;
            stream_boundary_parse_succeeded = true;
        }

        if (!state.synchronized && content_type != kTlsHandshake && !confirmed_tls) {
            directions_.erase(key);
            ++stats.tls_packets_kept_uncertain;
            ++stats.tls_packets_kept_unsynchronized_non_handshake;
            if (diagnostics != nullptr) {
                diagnostics->tls_record_event = "unsynchronized_non_handshake";
            }
            finalize_diagnostics("keep", "keep.unsynchronized_non_handshake");
            return;
        }

        if (!state.synchronized && confirmed_tls) {
            resynchronized = true;
            if (content_type == kTlsApplicationData) {
                resynchronized_app_data_start = true;
            }
        }

        state.synchronized = true;
        if (content_type == kTlsHandshake) {
            state.confirmed_tls = true;
            directions_[reverse_key].confirmed_tls = true;
            if (diagnostics != nullptr && diagnostics->tls_record_event.empty()) {
                diagnostics->tls_record_event = "visible_handshake";
            }
        }
        const auto record_total_size = kTlsRecordHeaderSize + static_cast<std::size_t>(record_length);
        const auto remaining_payload = payload.size() - payload_offset;
        const auto is_app_data = content_type == kTlsApplicationData;

        if (record_total_size > remaining_payload) {
            if (is_app_data) {
                state.has_seen_application_data = true;
                if (stream_boundary_parse_succeeded) {
                    app_data_start_after_stream_boundary = true;
                }
                candidate_payload_size = payload_offset + clamped_keep_size(
                    config.tls.app_data_keep_record_bytes,
                    remaining_payload
                );
                has_candidate = true;
                truncation_kind = TlsTruncationKind::app_data_start;
                if (diagnostics != nullptr) {
                    diagnostics->tls_record_event = app_data_start_after_stream_boundary
                        ? "app_data_continuation_then_app_data_start"
                        : "app_data_start";
                }
            } else {
                has_candidate = false;
                truncation_kind = TlsTruncationKind::none;
            }

            state.has_active_record = true;
            state.active_record_content_type = content_type;
            state.active_record_remaining_bytes = static_cast<std::uint32_t>(record_total_size - remaining_payload);
            state.active_record_constrictible = is_app_data;
            payload_offset = payload.size();
            break;
        }

        if (is_app_data) {
            state.has_seen_application_data = true;
            candidate_payload_size = payload_offset + clamped_keep_size(
                config.tls.app_data_keep_record_bytes,
                record_total_size
            );
            has_candidate = true;
            truncation_kind = TlsTruncationKind::app_data_start;
            if (stream_boundary_parse_succeeded) {
                app_data_start_after_stream_boundary = true;
            }
            if (diagnostics != nullptr) {
                diagnostics->tls_record_event = app_data_start_after_stream_boundary
                    ? "app_data_continuation_then_app_data_start"
                    : "app_data_start";
            }
        } else {
            has_candidate = false;
            truncation_kind = TlsTruncationKind::none;
            if (stream_boundary_parse_succeeded && diagnostics != nullptr && diagnostics->tls_record_event.empty()) {
                diagnostics->tls_record_event = "app_data_continuation_then_visible_record";
            }
        }

        payload_offset += record_total_size;
    }

    state.expected_tcp_seq = advance_tcp_seq(decoded.tcp_seq, decoded.transport_payload_size);

    if (resynchronized) {
        ++stats.tls_packets_resynchronized;
    }
    if (resynchronized_app_data_start) {
        ++stats.tls_packets_resynchronized_app_data_start;
    }
    if (stream_boundary_parse_succeeded) {
        ++stats.tls_packets_stream_continuation_boundary_parsed;
    }

    if (reset_direction) {
        if (kept_app_data_continuation_with_extra_bytes) {
            ++stats.tls_packets_kept_app_data_continuation_with_extra_bytes;
        }
        const auto was_confirmed_tls = state.confirmed_tls;
        const auto had_seen_application_data = state.has_seen_application_data;
        directions_.erase(key);
        if (was_confirmed_tls) {
            directions_[key].confirmed_tls = true;
            directions_[key].has_seen_application_data = had_seen_application_data;
        }
        finalize_diagnostics("keep", "keep.app_data_continuation_with_extra_bytes");
        return;
    }

    if (uncertain) {
        ++stats.tls_packets_kept_uncertain;
        ++stats.tls_packets_kept_malformed_record;
        if (diagnostics != nullptr && diagnostics->tls_record_event.empty()) {
            diagnostics->tls_record_event = "malformed_tls_record";
        }
        finalize_diagnostics("keep", "keep.malformed_tls_record");
        return;
    }

    if (!state.synchronized) {
        if (bulk_unsynchronized_candidate) {
            // Keep moving with the original TCP byte count, but do not claim a record-aligned TLS state.
        } else {
            finalize_diagnostics("keep", "keep.no_candidate");
            return;
        }
    }

    if (kept_middle_continuation) {
        ++stats.tls_packets_kept_middle_continuation;
        finalize_diagnostics("keep", "keep.middle_continuation");
        return;
    }

    if (!has_candidate || candidate_payload_size >= decoded.transport_payload_size) {
        ++stats.tls_packets_kept_no_candidate;
        finalize_diagnostics("keep", "keep.no_candidate");
        return;
    }

    const auto new_caplen = decoded.transport_payload_offset + candidate_payload_size;
    const auto old_caplen = packet.bytes.size();
    if (new_caplen >= old_caplen || old_caplen - new_caplen < config.general.min_saved_bytes_per_packet) {
        ++stats.tls_packets_kept_min_savings;
        finalize_diagnostics("keep", "keep.min_savings");
        return;
    }

    packet.bytes.resize(new_caplen);
    packet.captured_length = static_cast<std::uint32_t>(new_caplen);
    ++stats.tls_packets_truncated;
    if (truncation_kind == TlsTruncationKind::app_data_start) {
        ++stats.tls_packets_truncated_app_data_start;
        finalize_diagnostics("truncate", "truncate.tls_app_data_start");
    } else if (truncation_kind == TlsTruncationKind::final_continuation) {
        ++stats.tls_packets_truncated_final_continuation;
        finalize_diagnostics("truncate", "truncate.tls_final_continuation");
    } else if (truncation_kind == TlsTruncationKind::stream_continuation) {
        ++stats.tls_packets_truncated_stream_continuation;
        finalize_diagnostics("truncate", "truncate.tls_stream_continuation");
    } else if (truncation_kind == TlsTruncationKind::bulk_continuation) {
        ++stats.tls_packets_truncated_bulk_continuation;
        finalize_diagnostics("truncate", "truncate.tls_bulk_continuation");
    } else {
        finalize_diagnostics("truncate", "truncate.unknown");
    }
    stats.tls_bytes_saved += old_caplen - new_caplen;
}

}  // namespace pc::tls
