#include "decode/PacketDecode.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "bytes/Endian.hpp"
#include "pcap/LinkType.hpp"

namespace pc::decode {

namespace {

constexpr std::uint16_t kEtherTypeVlan = 0x8100U;
constexpr std::uint16_t kEtherTypeProviderBridge = 0x88A8U;
constexpr std::uint16_t kEtherTypeVlan9100 = 0x9100U;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;

constexpr std::uint8_t kIpProtocolTcp = 6U;
constexpr std::uint8_t kIpProtocolUdp = 17U;
constexpr std::uint8_t kIpv6HopByHop = 0U;
constexpr std::uint8_t kIpv6Routing = 43U;
constexpr std::uint8_t kIpv6Fragment = 44U;
constexpr std::uint8_t kIpv6Authentication = 51U;
constexpr std::uint8_t kIpv6DestinationOptions = 60U;

[[nodiscard]] bool has_bytes(
    const std::span<const std::uint8_t> packet,
    const std::size_t offset,
    const std::size_t count
) noexcept {
    return offset <= packet.size() && count <= packet.size() - offset;
}

[[nodiscard]] bool read_be16(
    const std::span<const std::uint8_t> packet,
    const std::size_t offset,
    std::uint16_t& out
) noexcept {
    if (!has_bytes(packet, offset, 2U)) {
        return false;
    }

    out = pc::bytes::read_be16(std::span<const std::uint8_t, 2>(packet.data() + offset, 2U));
    return true;
}

[[nodiscard]] bool read_be32(
    const std::span<const std::uint8_t> packet,
    const std::size_t offset,
    std::uint32_t& out
) noexcept {
    if (!has_bytes(packet, offset, 4U)) {
        return false;
    }

    out = pc::bytes::read_be32(std::span<const std::uint8_t, 4>(packet.data() + offset, 4U));
    return true;
}

[[nodiscard]] bool is_vlan_ethertype(const std::uint16_t ether_type) noexcept {
    return ether_type == kEtherTypeVlan ||
           ether_type == kEtherTypeProviderBridge ||
           ether_type == kEtherTypeVlan9100;
}

void copy_ip(IpAddress& out, const std::span<const std::uint8_t> packet, const std::size_t offset, const std::uint8_t length) {
    out = {};
    out.length = length;
    std::memcpy(out.bytes.data(), packet.data() + offset, length);
}

void decode_tcp(
    PacketDecodeResult& result,
    const std::span<const std::uint8_t> packet,
    const std::size_t transport_offset,
    const std::size_t transport_end
) {
    if (!has_bytes(packet, transport_offset, 20U) || transport_offset + 20U > transport_end) {
        result.malformed = true;
        return;
    }

    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    if (!read_be16(packet, transport_offset, src_port) ||
        !read_be16(packet, transport_offset + 2U, dst_port) ||
        !read_be32(packet, transport_offset + 4U, seq) ||
        !read_be32(packet, transport_offset + 8U, ack)) {
        result.malformed = true;
        return;
    }

    const auto header_length = static_cast<std::uint8_t>((packet[transport_offset + 12U] >> 4U) * 4U);
    if (header_length < 20U ||
        !has_bytes(packet, transport_offset, header_length) ||
        transport_offset + header_length > transport_end) {
        result.malformed = true;
        return;
    }

    result.decoded = true;
    result.transport = TransportProtocol::Tcp;
    result.transport_header_offset = transport_offset;
    result.transport_payload_offset = transport_offset + header_length;
    result.transport_payload_size = transport_end - result.transport_payload_offset;
    result.src_port = src_port;
    result.dst_port = dst_port;
    result.tcp_seq = seq;
    result.tcp_ack = ack;
    result.tcp_flags = packet[transport_offset + 13U];
    result.tcp_header_length = header_length;
}

void decode_udp(
    PacketDecodeResult& result,
    const std::span<const std::uint8_t> packet,
    const std::size_t transport_offset,
    const std::size_t transport_end
) {
    if (!has_bytes(packet, transport_offset, 8U) || transport_offset + 8U > transport_end) {
        result.malformed = true;
        return;
    }

    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint16_t udp_length = 0;
    if (!read_be16(packet, transport_offset, src_port) ||
        !read_be16(packet, transport_offset + 2U, dst_port) ||
        !read_be16(packet, transport_offset + 4U, udp_length)) {
        result.malformed = true;
        return;
    }

    if (udp_length < 8U) {
        result.malformed = true;
        return;
    }

    const auto udp_end = transport_offset + static_cast<std::size_t>(udp_length);
    if (udp_end > transport_end || udp_end > packet.size()) {
        result.malformed = true;
        return;
    }

    result.decoded = true;
    result.transport = TransportProtocol::Udp;
    result.transport_header_offset = transport_offset;
    result.transport_payload_offset = transport_offset + 8U;
    result.transport_payload_size = udp_end - result.transport_payload_offset;
    result.src_port = src_port;
    result.dst_port = dst_port;
    result.udp_length = udp_length;
}

void decode_transport(
    PacketDecodeResult& result,
    const std::span<const std::uint8_t> packet,
    const std::uint8_t protocol,
    const std::size_t transport_offset,
    const std::size_t transport_end
) {
    if (transport_offset > transport_end || transport_end > packet.size()) {
        result.malformed = true;
        return;
    }

    if (protocol == kIpProtocolTcp) {
        decode_tcp(result, packet, transport_offset, transport_end);
        return;
    }

    if (protocol == kIpProtocolUdp) {
        decode_udp(result, packet, transport_offset, transport_end);
    }
}

void decode_ipv4(PacketDecodeResult& result, const std::span<const std::uint8_t> packet, const std::size_t network_offset) {
    if (!has_bytes(packet, network_offset, 20U)) {
        result.malformed = true;
        return;
    }

    const auto version = static_cast<std::uint8_t>(packet[network_offset] >> 4U);
    const auto ihl = static_cast<std::uint8_t>((packet[network_offset] & 0x0FU) * 4U);
    if (version != 4U || ihl < 20U || !has_bytes(packet, network_offset, ihl)) {
        result.malformed = true;
        return;
    }

    std::uint16_t total_length = 0;
    std::uint16_t flags_fragment = 0;
    if (!read_be16(packet, network_offset + 2U, total_length) ||
        !read_be16(packet, network_offset + 6U, flags_fragment)) {
        result.malformed = true;
        return;
    }

    if (total_length < ihl) {
        result.malformed = true;
        return;
    }

    const auto more_fragments = (flags_fragment & 0x2000U) != 0U;
    const auto fragment_offset = static_cast<std::uint16_t>(flags_fragment & 0x1FFFU);
    if (more_fragments || fragment_offset != 0U) {
        return;
    }

    const auto ip_end = std::min(packet.size(), network_offset + static_cast<std::size_t>(total_length));
    const auto transport_offset = network_offset + ihl;
    result.network_header_offset = network_offset;
    copy_ip(result.src_ip, packet, network_offset + 12U, 4U);
    copy_ip(result.dst_ip, packet, network_offset + 16U, 4U);
    decode_transport(result, packet, packet[network_offset + 9U], transport_offset, ip_end);
}

[[nodiscard]] bool parse_ipv6_extensions(
    PacketDecodeResult& result,
    const std::span<const std::uint8_t> packet,
    std::uint8_t& next_header,
    std::size_t& offset,
    const std::size_t ipv6_end
) {
    for (;;) {
        if (next_header == kIpv6HopByHop ||
            next_header == kIpv6Routing ||
            next_header == kIpv6DestinationOptions) {
            if (!has_bytes(packet, offset, 2U) || offset + 2U > ipv6_end) {
                result.malformed = true;
                return false;
            }

            const auto header_length = (static_cast<std::size_t>(packet[offset + 1U]) + 1U) * 8U;
            if (!has_bytes(packet, offset, header_length) || offset + header_length > ipv6_end) {
                result.malformed = true;
                return false;
            }

            next_header = packet[offset];
            offset += header_length;
            continue;
        }

        if (next_header == kIpv6Fragment) {
            if (!has_bytes(packet, offset, 8U) || offset + 8U > ipv6_end) {
                result.malformed = true;
                return false;
            }

            std::uint16_t fragment_data = 0;
            if (!read_be16(packet, offset + 2U, fragment_data)) {
                result.malformed = true;
                return false;
            }

            const auto fragment_offset = static_cast<std::uint16_t>((fragment_data & 0xFFF8U) >> 3U);
            const auto more_fragments = (fragment_data & 0x0001U) != 0U;
            next_header = packet[offset];
            offset += 8U;
            if (fragment_offset != 0U || more_fragments) {
                return false;
            }
            continue;
        }

        if (next_header == kIpv6Authentication) {
            return false;
        }

        return true;
    }
}

void decode_ipv6(PacketDecodeResult& result, const std::span<const std::uint8_t> packet, const std::size_t network_offset) {
    if (!has_bytes(packet, network_offset, 40U)) {
        result.malformed = true;
        return;
    }

    const auto version = static_cast<std::uint8_t>(packet[network_offset] >> 4U);
    if (version != 6U) {
        result.malformed = true;
        return;
    }

    std::uint16_t payload_length = 0;
    if (!read_be16(packet, network_offset + 4U, payload_length)) {
        result.malformed = true;
        return;
    }

    const auto ipv6_end = std::min(packet.size(), network_offset + 40U + static_cast<std::size_t>(payload_length));
    auto next_header = packet[network_offset + 6U];
    auto transport_offset = network_offset + 40U;

    result.network_header_offset = network_offset;
    copy_ip(result.src_ip, packet, network_offset + 8U, 16U);
    copy_ip(result.dst_ip, packet, network_offset + 24U, 16U);

    if (!parse_ipv6_extensions(result, packet, next_header, transport_offset, ipv6_end)) {
        return;
    }

    decode_transport(result, packet, next_header, transport_offset, ipv6_end);
}

}  // namespace

PacketDecodeResult decode_packet(const std::uint32_t link_type, const std::span<const std::uint8_t> packet) {
    PacketDecodeResult result {};
    result.link_header_offset = 0U;

    if (link_type != pc::pcap::kLinkTypeEthernet) {
        result.unsupported_link_type = true;
        return result;
    }

    if (!has_bytes(packet, 0U, 14U)) {
        result.malformed = true;
        return result;
    }

    std::uint16_t ether_type = 0;
    if (!read_be16(packet, 12U, ether_type)) {
        result.malformed = true;
        return result;
    }

    std::size_t network_offset = 14U;
    while (is_vlan_ethertype(ether_type)) {
        if (!has_bytes(packet, network_offset, 4U)) {
            result.malformed = true;
            return result;
        }
        if (!read_be16(packet, network_offset + 2U, ether_type)) {
            result.malformed = true;
            return result;
        }
        network_offset += 4U;
    }

    if (ether_type == kEtherTypeIpv4) {
        decode_ipv4(result, packet, network_offset);
        return result;
    }

    if (ether_type == kEtherTypeIpv6) {
        decode_ipv6(result, packet, network_offset);
        return result;
    }

    return result;
}

}  // namespace pc::decode
