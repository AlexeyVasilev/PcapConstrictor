#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace pc::decode {

enum class TransportProtocol {
    None,
    Tcp,
    Udp,
};

struct IpAddress {
    std::array<std::uint8_t, 16> bytes {};
    std::uint8_t length {0};
};

struct PacketDecodeResult {
    bool decoded {false};
    bool malformed {false};
    bool unsupported_link_type {false};

    std::size_t link_header_offset {0};
    std::size_t network_header_offset {0};
    std::size_t transport_header_offset {0};
    std::size_t transport_payload_offset {0};
    std::size_t transport_payload_size {0};

    TransportProtocol transport {TransportProtocol::None};

    IpAddress src_ip {};
    IpAddress dst_ip {};
    std::uint16_t src_port {0};
    std::uint16_t dst_port {0};

    std::uint32_t tcp_seq {0};
    std::uint32_t tcp_ack {0};
    std::uint8_t tcp_flags {0};
    std::uint8_t tcp_header_length {0};

    std::uint16_t udp_length {0};
};

[[nodiscard]] PacketDecodeResult decode_packet(std::uint32_t link_type, std::span<const std::uint8_t> packet);

}  // namespace pc::decode
