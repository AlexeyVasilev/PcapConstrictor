#include "quic/QuicConstrictor.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace pc::quic {

namespace {

struct LongHeaderInfo {
    std::size_t total_size {0};
    std::uint8_t packet_type {0};
    std::uint32_t version {0};
    QuicConstrictor::ConnectionId dcid {};
    QuicConstrictor::ConnectionId scid {};
};

[[nodiscard]] bool has_bytes(
    const std::span<const std::uint8_t> bytes,
    const std::size_t offset,
    const std::size_t count
) noexcept {
    return offset <= bytes.size() && count <= bytes.size() - offset;
}

[[nodiscard]] std::uint32_t read_be32(const std::span<const std::uint8_t> bytes, const std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

[[nodiscard]] bool is_long_header(const std::uint8_t first_byte) noexcept {
    return (first_byte & 0x80U) != 0U;
}

[[nodiscard]] bool is_short_header_compatible(const std::uint8_t first_byte) noexcept {
    return (first_byte & 0x80U) == 0U && (first_byte & 0x40U) != 0U;
}

[[nodiscard]] bool read_varint(
    const std::span<const std::uint8_t> bytes,
    std::size_t& offset,
    std::uint64_t& value
) noexcept {
    if (!has_bytes(bytes, offset, 1U)) {
        return false;
    }

    const auto first = bytes[offset];
    const auto length = static_cast<std::size_t>(1U) << (first >> 6U);
    if (!has_bytes(bytes, offset, length)) {
        return false;
    }

    value = static_cast<std::uint64_t>(first & 0x3FU);
    for (std::size_t index = 1; index < length; ++index) {
        value = (value << 8U) | bytes[offset + index];
    }
    offset += length;
    return true;
}

[[nodiscard]] bool read_connection_id(
    const std::span<const std::uint8_t> bytes,
    std::size_t& offset,
    QuicConstrictor::ConnectionId& out
) noexcept {
    if (!has_bytes(bytes, offset, 1U)) {
        return false;
    }

    const auto length = bytes[offset++];
    if (length > out.bytes.size() || !has_bytes(bytes, offset, length)) {
        return false;
    }

    out = {};
    out.length = length;
    std::copy_n(bytes.data() + offset, length, out.bytes.data());
    offset += length;
    return true;
}

[[nodiscard]] bool parse_long_header(
    const std::span<const std::uint8_t> payload,
    const std::size_t start,
    LongHeaderInfo& out
) noexcept {
    if (!has_bytes(payload, start, 7U) || !is_long_header(payload[start])) {
        return false;
    }

    out = {};
    out.packet_type = static_cast<std::uint8_t>((payload[start] >> 4U) & 0x03U);
    out.version = read_be32(payload, start + 1U);
    if (out.version == 0U) {
        return false;
    }

    std::size_t offset = start + 5U;
    if (!read_connection_id(payload, offset, out.dcid) ||
        !read_connection_id(payload, offset, out.scid)) {
        return false;
    }

    if (out.packet_type == 0U) {
        std::uint64_t token_length = 0;
        if (!read_varint(payload, offset, token_length) ||
            token_length > payload.size() ||
            !has_bytes(payload, offset, static_cast<std::size_t>(token_length))) {
            return false;
        }
        offset += static_cast<std::size_t>(token_length);
    } else if (out.packet_type == 3U) {
        out.total_size = payload.size() - start;
        return true;
    }

    std::uint64_t packet_length = 0;
    if (!read_varint(payload, offset, packet_length)) {
        return false;
    }

    if (packet_length > payload.size() || !has_bytes(payload, offset, static_cast<std::size_t>(packet_length))) {
        return false;
    }

    out.total_size = offset + static_cast<std::size_t>(packet_length) - start;
    return out.total_size != 0U;
}

[[nodiscard]] QuicConstrictor::FlowKey reverse_flow(const QuicConstrictor::FlowKey& flow) noexcept {
    return {
        .src_ip = flow.dst_ip,
        .dst_ip = flow.src_ip,
        .src_port = flow.dst_port,
        .dst_port = flow.src_port,
    };
}

}  // namespace

std::size_t QuicConstrictor::FlowKeyHash::operator()(const FlowKey& key) const noexcept {
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

void QuicConstrictor::process_udp_packet(
    pc::pcap::PacketRecord& packet,
    const pc::decode::PacketDecodeResult& decoded,
    const pc::config::Config& config,
    pc::stats::Stats& stats
) {
    if (!decoded.decoded ||
        decoded.transport != pc::decode::TransportProtocol::Udp ||
        decoded.transport_payload_size == 0U) {
        return;
    }

    const FlowKey flow {
        .src_ip = decoded.src_ip,
        .dst_ip = decoded.dst_ip,
        .src_port = decoded.src_port,
        .dst_port = decoded.dst_port,
    };
    const auto payload = std::span<const std::uint8_t>(
        packet.bytes.data() + decoded.transport_payload_offset,
        decoded.transport_payload_size
    );

    std::size_t offset = 0;
    bool saw_long_header = false;
    while (offset < payload.size() && is_long_header(payload[offset])) {
        LongHeaderInfo long_header {};
        if (!parse_long_header(payload, offset, long_header)) {
            ++stats.quic_packets_kept_uncertain;
            return;
        }

        saw_long_header = true;
        if (long_header.packet_type == 0U) {
            const auto reverse = reverse_flow(flow);
            auto found = flow_to_connection_.find(flow);
            if (found == flow_to_connection_.end()) {
                const auto index = connections_.size();
                connections_.push_back({
                    .client_to_server = flow,
                    .server_to_client = reverse,
                });
                flow_to_connection_[flow] = index;
                flow_to_connection_[reverse] = index;
                found = flow_to_connection_.find(flow);
            }

            auto& connection = connections_[found->second];
            if (long_header.scid.length > 0U) {
                if (flow == connection.client_to_server) {
                    connection.client_scid = long_header.scid;
                    connection.original_dcid = long_header.dcid;
                } else {
                    connection.server_scid = long_header.scid;
                }
            }
        }

        offset += long_header.total_size;
    }

    if (offset == payload.size()) {
        return;
    }

    if (!is_short_header_compatible(payload[offset])) {
        if (saw_long_header) {
            ++stats.quic_packets_kept_uncertain;
        }
        return;
    }

    const auto found = flow_to_connection_.find(flow);
    if (found == flow_to_connection_.end()) {
        return;
    }

    const auto& connection = connections_[found->second];
    const bool client_to_server = flow == connection.client_to_server;
    const auto& expected_dcid = client_to_server ? connection.server_scid : connection.client_scid;
    if (!expected_dcid.has_value()) {
        if (!config.quic.allow_short_header_without_known_dcid) {
            ++stats.quic_packets_kept_uncertain;
            return;
        }
    } else if (config.quic.require_dcid_match && expected_dcid->length > 0U) {
        const auto dcid_offset = offset + 1U;
        if (!has_bytes(payload, dcid_offset, expected_dcid->length)) {
            ++stats.quic_packets_kept_uncertain;
            return;
        }
        if (!std::equal(
                expected_dcid->bytes.begin(),
                expected_dcid->bytes.begin() + expected_dcid->length,
                payload.begin() + static_cast<std::ptrdiff_t>(dcid_offset))) {
            ++stats.quic_packets_kept_dcid_mismatch;
            return;
        }
    }

    const auto dcid_length = expected_dcid.has_value() ? static_cast<std::size_t>(expected_dcid->length) : 0U;
    const auto keep_quic_bytes = std::max<std::size_t>(
        config.quic.short_header_keep_packet_bytes,
        1U + dcid_length
    );
    const auto short_payload_size = payload.size() - offset;
    const auto kept_short_payload_size = std::min(short_payload_size, keep_quic_bytes);
    const auto new_payload_size = offset + kept_short_payload_size;
    const auto new_caplen = decoded.transport_payload_offset + new_payload_size;
    const auto old_caplen = packet.bytes.size();
    if (new_caplen >= old_caplen || old_caplen - new_caplen < config.general.min_saved_bytes_per_packet) {
        return;
    }

    packet.bytes.resize(new_caplen);
    packet.captured_length = static_cast<std::uint32_t>(new_caplen);
    ++stats.quic_packets_truncated;
    stats.quic_bytes_saved += old_caplen - new_caplen;
}

}  // namespace pc::quic
