#include "checksum/Checksum.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "bytes/Endian.hpp"
#include "decode/PacketDecode.hpp"
#include "pcap/LinkType.hpp"

namespace pc::checksum {

namespace {

constexpr std::uint8_t kIpProtocolTcp = 6U;
constexpr std::uint8_t kIpProtocolUdp = 17U;
constexpr std::uint8_t kIpv6HopByHop = 0U;
constexpr std::uint8_t kIpv6Routing = 43U;
constexpr std::uint8_t kIpv6Fragment = 44U;
constexpr std::uint8_t kIpv6Authentication = 51U;
constexpr std::uint8_t kIpv6DestinationOptions = 60U;
constexpr std::uint16_t kEtherTypeVlan = 0x8100U;
constexpr std::uint16_t kEtherTypeProviderBridge = 0x88A8U;
constexpr std::uint16_t kEtherTypeVlan9100 = 0x9100U;
constexpr std::uint16_t kEtherTypeIpv4 = 0x0800U;
constexpr std::uint16_t kEtherTypeIpv6 = 0x86DDU;

enum class SkipReason {
    unsupported_link_type,
    decode_failed,
    malformed,
    fragment,
    not_tcp_udp,
    incomplete,
    length_mismatch,
    ipv4_total_length_zero,
};

[[nodiscard]] bool has_bytes(
    const std::span<const std::uint8_t> packet,
    const std::size_t offset,
    const std::size_t count
) noexcept {
    return offset <= packet.size() && count <= packet.size() - offset;
}

[[nodiscard]] bool is_vlan_ethertype(const std::uint16_t ether_type) noexcept {
    return ether_type == kEtherTypeVlan ||
           ether_type == kEtherTypeProviderBridge ||
           ether_type == kEtherTypeVlan9100;
}

[[nodiscard]] std::uint16_t read_be16(const std::span<const std::uint8_t> packet, const std::size_t offset) noexcept {
    return pc::bytes::read_be16(std::span<const std::uint8_t, 2>(packet.data() + offset, 2U));
}

void write_be16(std::vector<std::uint8_t>& packet, const std::size_t offset, const std::uint16_t value) noexcept {
    pc::bytes::write_u16(
        std::span<std::uint8_t, 2>(packet.data() + offset, 2U),
        value,
        pc::bytes::Endianness::big
    );
}

void add_u16(std::uint32_t& sum, const std::uint16_t value) noexcept {
    sum += value;
}

void add_u32(std::uint32_t& sum, const std::uint32_t value) noexcept {
    sum += static_cast<std::uint16_t>((value >> 16U) & 0xFFFFU);
    sum += static_cast<std::uint16_t>(value & 0xFFFFU);
}

void add_bytes(std::uint32_t& sum, const std::span<const std::uint8_t> bytes) noexcept {
    std::size_t offset = 0;
    while (offset + 1U < bytes.size()) {
        sum += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
            static_cast<std::uint16_t>(bytes[offset + 1U])
        );
        offset += 2U;
    }

    if (offset < bytes.size()) {
        sum += static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) << 8U);
    }
}

[[nodiscard]] std::uint16_t finalize_checksum(std::uint32_t sum) noexcept {
    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }

    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

[[nodiscard]] std::uint16_t checksum_bytes(const std::span<const std::uint8_t> bytes) noexcept {
    std::uint32_t sum = 0;
    add_bytes(sum, bytes);
    return finalize_checksum(sum);
}

[[nodiscard]] bool is_ipv4_fragment(const std::span<const std::uint8_t> packet, const std::size_t network_offset) noexcept {
    const auto flags_fragment = read_be16(packet, network_offset + 6U);
    return (flags_fragment & 0x2000U) != 0U || (flags_fragment & 0x1FFFU) != 0U;
}

[[nodiscard]] bool ipv6_has_fragment_header(
    const std::span<const std::uint8_t> packet,
    const std::size_t network_offset,
    const std::size_t transport_offset
) noexcept {
    auto next_header = packet[network_offset + 6U];
    auto offset = network_offset + 40U;
    while (offset < transport_offset) {
        if (next_header == kIpv6Fragment) {
            return true;
        }

        if (next_header == kIpv6HopByHop ||
            next_header == kIpv6Routing ||
            next_header == kIpv6DestinationOptions) {
            if (!has_bytes(packet, offset, 2U)) {
                return true;
            }

            const auto header_length = (static_cast<std::size_t>(packet[offset + 1U]) + 1U) * 8U;
            if (header_length == 0U || !has_bytes(packet, offset, header_length)) {
                return true;
            }

            next_header = packet[offset];
            offset += header_length;
            continue;
        }

        if (next_header == kIpv6Authentication) {
            return true;
        }

        return false;
    }

    return false;
}

[[nodiscard]] std::uint16_t transport_checksum_ipv4(
    const std::span<const std::uint8_t> packet,
    const std::size_t network_offset,
    const std::size_t transport_offset,
    const std::size_t transport_length,
    const std::uint8_t protocol
) noexcept {
    std::uint32_t sum = 0;
    add_bytes(sum, packet.subspan(network_offset + 12U, 8U));
    add_u16(sum, protocol);
    add_u16(sum, static_cast<std::uint16_t>(transport_length));
    add_bytes(sum, packet.subspan(transport_offset, transport_length));
    const auto checksum = finalize_checksum(sum);
    return checksum == 0U ? 0xFFFFU : checksum;
}

[[nodiscard]] std::uint16_t transport_checksum_ipv6(
    const std::span<const std::uint8_t> packet,
    const std::size_t network_offset,
    const std::size_t transport_offset,
    const std::size_t transport_length,
    const std::uint8_t protocol
) noexcept {
    std::uint32_t sum = 0;
    add_bytes(sum, packet.subspan(network_offset + 8U, 32U));
    add_u32(sum, static_cast<std::uint32_t>(transport_length));
    add_u16(sum, protocol);
    add_bytes(sum, packet.subspan(transport_offset, transport_length));
    const auto checksum = finalize_checksum(sum);
    return checksum == 0U ? 0xFFFFU : checksum;
}

[[nodiscard]] RecomputeResult skipped(const SkipReason reason) noexcept {
    RecomputeResult result {};
    result.checksum_recompute_skipped = 1U;
    switch (reason) {
        case SkipReason::unsupported_link_type:
            result.checksum_recompute_skipped_unsupported_link_type = 1U;
            break;
        case SkipReason::decode_failed:
            result.checksum_recompute_skipped_decode_failed = 1U;
            break;
        case SkipReason::malformed:
            result.checksum_recompute_skipped_malformed = 1U;
            break;
        case SkipReason::fragment:
            result.checksum_recompute_skipped_fragment = 1U;
            break;
        case SkipReason::not_tcp_udp:
            result.checksum_recompute_skipped_not_tcp_udp = 1U;
            break;
        case SkipReason::incomplete:
            result.checksum_recompute_skipped_incomplete = 1U;
            break;
        case SkipReason::length_mismatch:
            result.checksum_recompute_skipped_length_mismatch = 1U;
            break;
        case SkipReason::ipv4_total_length_zero:
            result.checksum_recompute_skipped_ipv4_total_length_zero = 1U;
            break;
    }
    return result;
}

[[nodiscard]] std::optional<SkipReason> sniff_skip_reason(
    const std::uint32_t link_type,
    const std::span<const std::uint8_t> packet
) noexcept {
    if (link_type != pc::pcap::kLinkTypeEthernet) {
        return SkipReason::unsupported_link_type;
    }

    if (!has_bytes(packet, 0U, 14U)) {
        return SkipReason::incomplete;
    }

    auto network_offset = static_cast<std::size_t>(14U);
    auto ether_type = read_be16(packet, 12U);
    while (is_vlan_ethertype(ether_type)) {
        if (!has_bytes(packet, network_offset, 4U)) {
            return SkipReason::incomplete;
        }
        ether_type = read_be16(packet, network_offset + 2U);
        network_offset += 4U;
    }

    if (ether_type == kEtherTypeIpv4) {
        if (!has_bytes(packet, network_offset, 20U)) {
            return SkipReason::incomplete;
        }

        const auto version = static_cast<std::uint8_t>(packet[network_offset] >> 4U);
        const auto ihl = static_cast<std::size_t>(packet[network_offset] & 0x0FU) * 4U;
        if (version != 4U) {
            return SkipReason::decode_failed;
        }

        if (ihl < 20U) {
            return SkipReason::malformed;
        }

        if (!has_bytes(packet, network_offset, ihl)) {
            return SkipReason::incomplete;
        }

        const auto total_length = static_cast<std::size_t>(read_be16(packet, network_offset + 2U));
        if (total_length == 0U) {
            return SkipReason::ipv4_total_length_zero;
        }

        if (total_length < ihl) {
            return SkipReason::length_mismatch;
        }

        if (!has_bytes(packet, network_offset, total_length)) {
            return SkipReason::incomplete;
        }

        if (is_ipv4_fragment(packet, network_offset)) {
            return SkipReason::fragment;
        }

        const auto protocol = packet[network_offset + 9U];
        if (protocol != kIpProtocolTcp && protocol != kIpProtocolUdp) {
            return SkipReason::not_tcp_udp;
        }

        return std::nullopt;
    }

    if (ether_type == kEtherTypeIpv6) {
        if (!has_bytes(packet, network_offset, 40U)) {
            return SkipReason::incomplete;
        }

        if (static_cast<std::uint8_t>(packet[network_offset] >> 4U) != 6U) {
            return SkipReason::decode_failed;
        }

        const auto payload_length = static_cast<std::size_t>(read_be16(packet, network_offset + 4U));
        if (!has_bytes(packet, network_offset, 40U + payload_length)) {
            return SkipReason::incomplete;
        }

        auto next_header = packet[network_offset + 6U];
        auto offset = network_offset + 40U;
        const auto ipv6_end = network_offset + 40U + payload_length;
        for (;;) {
            if (next_header == kIpv6HopByHop ||
                next_header == kIpv6Routing ||
                next_header == kIpv6DestinationOptions) {
                if (!has_bytes(packet, offset, 2U) || offset + 2U > ipv6_end) {
                    return SkipReason::incomplete;
                }

                const auto header_length = (static_cast<std::size_t>(packet[offset + 1U]) + 1U) * 8U;
                if (!has_bytes(packet, offset, header_length) || offset + header_length > ipv6_end) {
                    return SkipReason::incomplete;
                }

                next_header = packet[offset];
                offset += header_length;
                continue;
            }

            if (next_header == kIpv6Fragment) {
                return SkipReason::fragment;
            }

            if (next_header == kIpv6Authentication) {
                return SkipReason::decode_failed;
            }

            if (next_header != kIpProtocolTcp && next_header != kIpProtocolUdp) {
                return SkipReason::not_tcp_udp;
            }

            return std::nullopt;
        }
    }

    return SkipReason::decode_failed;
}

[[nodiscard]] RecomputeResult recompute_ipv4(
    std::vector<std::uint8_t>& packet_bytes,
    const pc::decode::PacketDecodeResult& decoded
) {
    const auto packet = std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size());
    const auto network_offset = decoded.network_header_offset;
    if (!has_bytes(packet, network_offset, 20U) || (packet[network_offset] >> 4U) != 4U) {
        return skipped(SkipReason::decode_failed);
    }

    const auto ihl = static_cast<std::size_t>(packet[network_offset] & 0x0FU) * 4U;
    if (ihl < 20U || !has_bytes(packet, network_offset, ihl)) {
        return skipped(SkipReason::incomplete);
    }

    const auto total_length = static_cast<std::size_t>(read_be16(packet, network_offset + 2U));
    if (total_length == 0U) {
        return skipped(SkipReason::ipv4_total_length_zero);
    }

    if (total_length < ihl) {
        return skipped(SkipReason::length_mismatch);
    }

    if (!has_bytes(packet, network_offset, total_length)) {
        return skipped(SkipReason::incomplete);
    }

    if (is_ipv4_fragment(packet, network_offset)) {
        return skipped(SkipReason::fragment);
    }

    const auto protocol = packet[network_offset + 9U];
    const auto transport_offset = decoded.transport_header_offset;
    if (transport_offset < network_offset + ihl || transport_offset > network_offset + total_length) {
        return skipped(SkipReason::length_mismatch);
    }

    const auto ip_end = network_offset + total_length;
    const auto transport_length = ip_end - transport_offset;
    RecomputeResult result {};

    if (decoded.transport == pc::decode::TransportProtocol::Tcp) {
        if (protocol != kIpProtocolTcp ||
            decoded.tcp_header_length < 20U ||
            transport_length < decoded.tcp_header_length ||
            !has_bytes(packet, transport_offset, transport_length)) {
            return skipped(protocol != kIpProtocolTcp ? SkipReason::not_tcp_udp : SkipReason::incomplete);
        }

        packet_bytes[network_offset + 10U] = 0U;
        packet_bytes[network_offset + 11U] = 0U;
        write_be16(packet_bytes, network_offset + 10U, checksum_bytes(std::span<const std::uint8_t>(packet_bytes.data() + network_offset, ihl)));

        packet_bytes[transport_offset + 16U] = 0U;
        packet_bytes[transport_offset + 17U] = 0U;
        write_be16(
            packet_bytes,
            transport_offset + 16U,
            transport_checksum_ipv4(std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()), network_offset, transport_offset, transport_length, protocol)
        );
        result.checksums_recomputed_ipv4 = 1U;
        result.checksums_recomputed_tcp = 1U;
        return result;
    }

    if (decoded.transport == pc::decode::TransportProtocol::Udp) {
        const auto udp_length = static_cast<std::size_t>(decoded.udp_length);
        if (protocol != kIpProtocolUdp ||
            udp_length < 8U ||
            udp_length != transport_length) {
            return skipped(protocol != kIpProtocolUdp ? SkipReason::not_tcp_udp : SkipReason::length_mismatch);
        }

        if (!has_bytes(packet, transport_offset, udp_length)) {
            return skipped(SkipReason::incomplete);
        }

        packet_bytes[network_offset + 10U] = 0U;
        packet_bytes[network_offset + 11U] = 0U;
        write_be16(packet_bytes, network_offset + 10U, checksum_bytes(std::span<const std::uint8_t>(packet_bytes.data() + network_offset, ihl)));

        packet_bytes[transport_offset + 6U] = 0U;
        packet_bytes[transport_offset + 7U] = 0U;
        write_be16(
            packet_bytes,
            transport_offset + 6U,
            transport_checksum_ipv4(std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()), network_offset, transport_offset, udp_length, protocol)
        );
        result.checksums_recomputed_ipv4 = 1U;
        result.checksums_recomputed_udp = 1U;
        return result;
    }

    return skipped(SkipReason::not_tcp_udp);
}

[[nodiscard]] RecomputeResult recompute_ipv6(
    std::vector<std::uint8_t>& packet_bytes,
    const pc::decode::PacketDecodeResult& decoded
) {
    const auto packet = std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size());
    const auto network_offset = decoded.network_header_offset;
    if (!has_bytes(packet, network_offset, 40U) || (packet[network_offset] >> 4U) != 6U) {
        return skipped(SkipReason::decode_failed);
    }

    const auto payload_length = static_cast<std::size_t>(read_be16(packet, network_offset + 4U));
    const auto ip_end = network_offset + 40U + payload_length;
    const auto transport_offset = decoded.transport_header_offset;
    if (!has_bytes(packet, network_offset, 40U + payload_length) ||
        transport_offset < network_offset + 40U ||
        transport_offset > ip_end) {
        return skipped(SkipReason::incomplete);
    }

    if (ipv6_has_fragment_header(packet, network_offset, transport_offset)) {
        return skipped(SkipReason::fragment);
    }

    const auto transport_length = ip_end - transport_offset;
    RecomputeResult result {};

    if (decoded.transport == pc::decode::TransportProtocol::Tcp) {
        if (decoded.tcp_header_length < 20U ||
            transport_length < decoded.tcp_header_length ||
            !has_bytes(packet, transport_offset, transport_length)) {
            return skipped(SkipReason::incomplete);
        }

        packet_bytes[transport_offset + 16U] = 0U;
        packet_bytes[transport_offset + 17U] = 0U;
        write_be16(
            packet_bytes,
            transport_offset + 16U,
            transport_checksum_ipv6(std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()), network_offset, transport_offset, transport_length, kIpProtocolTcp)
        );
        result.checksums_recomputed_tcp = 1U;
        return result;
    }

    if (decoded.transport == pc::decode::TransportProtocol::Udp) {
        const auto udp_length = static_cast<std::size_t>(decoded.udp_length);
        if (udp_length < 8U ||
            udp_length != transport_length) {
            return skipped(SkipReason::length_mismatch);
        }

        if (!has_bytes(packet, transport_offset, udp_length)) {
            return skipped(SkipReason::incomplete);
        }

        packet_bytes[transport_offset + 6U] = 0U;
        packet_bytes[transport_offset + 7U] = 0U;
        write_be16(
            packet_bytes,
            transport_offset + 6U,
            transport_checksum_ipv6(std::span<const std::uint8_t>(packet_bytes.data(), packet_bytes.size()), network_offset, transport_offset, udp_length, kIpProtocolUdp)
        );
        result.checksums_recomputed_udp = 1U;
        return result;
    }

    return skipped(SkipReason::not_tcp_udp);
}

}  // namespace

RecomputeResult recompute_packet_checksums(
    const std::uint32_t link_type,
    std::vector<std::uint8_t>& packet
) {
    const auto decoded = pc::decode::decode_packet(
        link_type,
        std::span<const std::uint8_t>(packet.data(), packet.size())
    );
    if (decoded.unsupported_link_type) {
        return skipped(SkipReason::unsupported_link_type);
    }

    if (decoded.malformed) {
        const auto reason = sniff_skip_reason(link_type, std::span<const std::uint8_t>(packet.data(), packet.size()));
        return skipped(reason.value_or(SkipReason::malformed));
    }

    if (!decoded.decoded) {
        const auto reason = sniff_skip_reason(link_type, std::span<const std::uint8_t>(packet.data(), packet.size()));
        return skipped(reason.value_or(SkipReason::decode_failed));
    }

    if (!has_bytes(std::span<const std::uint8_t>(packet.data(), packet.size()), decoded.network_header_offset, 1U)) {
        return skipped(SkipReason::incomplete);
    }

    const auto version = static_cast<std::uint8_t>(packet[decoded.network_header_offset] >> 4U);
    if (version == 4U) {
        return recompute_ipv4(packet, decoded);
    }

    if (version == 6U) {
        return recompute_ipv6(packet, decoded);
    }

    return skipped(SkipReason::decode_failed);
}

}  // namespace pc::checksum
