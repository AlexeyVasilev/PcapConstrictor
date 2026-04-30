#include "tls/TlsConstrictor.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

#include "bytes/Endian.hpp"

namespace pc::tls {

namespace {

constexpr std::uint8_t kTlsChangeCipherSpec = 0x14U;
constexpr std::uint8_t kTlsAlert = 0x15U;
constexpr std::uint8_t kTlsHandshake = 0x16U;
constexpr std::uint8_t kTlsApplicationData = 0x17U;
constexpr std::size_t kTlsRecordHeaderSize = 5U;

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
    pc::stats::Stats& stats
) {
    if (!decoded.decoded ||
        decoded.transport != pc::decode::TransportProtocol::Tcp ||
        decoded.transport_payload_size == 0U) {
        return;
    }

    const DirectionKey key {
        .src_ip = decoded.src_ip,
        .dst_ip = decoded.dst_ip,
        .src_port = decoded.src_port,
        .dst_port = decoded.dst_port,
    };

    auto& state = directions_[key];
    const auto payload = std::span<const std::uint8_t>(
        packet.bytes.data() + decoded.transport_payload_offset,
        decoded.transport_payload_size
    );

    if (state.synchronized && decoded.tcp_seq != state.expected_tcp_seq) {
        ++stats.tls_packets_kept_uncertain;
        return;
    }

    std::size_t payload_offset = 0;
    std::size_t candidate_payload_size = decoded.transport_payload_size;
    bool has_candidate = false;
    bool uncertain = false;

    if (state.has_active_record) {
        const auto consumed = std::min<std::size_t>(state.active_record_remaining_bytes, payload.size());
        if (state.active_record_constrictible && consumed == payload.size()) {
            candidate_payload_size = clamped_keep_size(config.tls.app_data_continuation_keep_bytes, payload.size());
            has_candidate = true;
        } else if (consumed < payload.size()) {
            uncertain = true;
        }

        state.active_record_remaining_bytes -= static_cast<std::uint32_t>(consumed);
        payload_offset += consumed;
        if (state.active_record_remaining_bytes == 0U) {
            state.has_active_record = false;
            state.active_record_constrictible = false;
            state.active_record_content_type = 0;
        }
    }

    while (!uncertain && payload_offset < payload.size()) {
        std::uint8_t content_type = 0;
        std::uint16_t record_length = 0;
        if (!read_tls_record_header(payload, payload_offset, content_type, record_length)) {
            if (!state.synchronized) {
                directions_.erase(key);
                return;
            }
            uncertain = true;
            break;
        }

        if (!state.synchronized && content_type != kTlsHandshake) {
            directions_.erase(key);
            ++stats.tls_packets_kept_uncertain;
            return;
        }

        state.synchronized = true;
        const auto record_total_size = kTlsRecordHeaderSize + static_cast<std::size_t>(record_length);
        const auto remaining_payload = payload.size() - payload_offset;
        const auto is_app_data = content_type == kTlsApplicationData;

        if (record_total_size > remaining_payload) {
            if (is_app_data) {
                candidate_payload_size = payload_offset + clamped_keep_size(
                    config.tls.app_data_keep_record_bytes,
                    remaining_payload
                );
                has_candidate = true;
            } else {
                has_candidate = false;
            }

            state.has_active_record = true;
            state.active_record_content_type = content_type;
            state.active_record_remaining_bytes = static_cast<std::uint32_t>(record_total_size - remaining_payload);
            state.active_record_constrictible = is_app_data;
            payload_offset = payload.size();
            break;
        }

        if (is_app_data) {
            candidate_payload_size = payload_offset + clamped_keep_size(
                config.tls.app_data_keep_record_bytes,
                record_total_size
            );
            has_candidate = true;
        } else {
            has_candidate = false;
        }

        payload_offset += record_total_size;
    }

    state.expected_tcp_seq = advance_tcp_seq(decoded.tcp_seq, decoded.transport_payload_size);

    if (uncertain) {
        ++stats.tls_packets_kept_uncertain;
        return;
    }

    if (!state.synchronized || !has_candidate || candidate_payload_size >= decoded.transport_payload_size) {
        return;
    }

    const auto new_caplen = decoded.transport_payload_offset + candidate_payload_size;
    const auto old_caplen = packet.bytes.size();
    if (new_caplen >= old_caplen || old_caplen - new_caplen < config.general.min_saved_bytes_per_packet) {
        return;
    }

    packet.bytes.resize(new_caplen);
    packet.captured_length = static_cast<std::uint32_t>(new_caplen);
    ++stats.tls_packets_truncated;
    stats.tls_bytes_saved += old_caplen - new_caplen;
}

}  // namespace pc::tls
