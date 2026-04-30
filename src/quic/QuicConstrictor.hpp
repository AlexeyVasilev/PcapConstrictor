#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

#include "config/Config.hpp"
#include "decode/PacketDecode.hpp"
#include "pcap/PacketRecord.hpp"
#include "stats/Stats.hpp"

namespace pc::quic {

class QuicConstrictor {
public:
    struct ConnectionId {
        std::array<std::uint8_t, 20> bytes {};
        std::uint8_t length {0};

        [[nodiscard]] bool operator==(const ConnectionId& other) const noexcept = default;
    };

    struct FlowKey {
        pc::decode::IpAddress src_ip {};
        pc::decode::IpAddress dst_ip {};
        std::uint16_t src_port {0};
        std::uint16_t dst_port {0};

        [[nodiscard]] bool operator==(const FlowKey& other) const noexcept = default;
    };

    struct FlowKeyHash {
        [[nodiscard]] std::size_t operator()(const FlowKey& key) const noexcept;
    };

    void process_udp_packet(
        pc::pcap::PacketRecord& packet,
        const pc::decode::PacketDecodeResult& decoded,
        const pc::config::Config& config,
        pc::stats::Stats& stats
    );

private:
    struct QuicConnection {
        FlowKey client_to_server {};
        FlowKey server_to_client {};
        std::optional<ConnectionId> client_scid {};
        std::optional<ConnectionId> server_scid {};
        std::optional<ConnectionId> original_dcid {};
    };

    std::unordered_map<FlowKey, std::size_t, FlowKeyHash> flow_to_connection_ {};
    std::vector<QuicConnection> connections_ {};
};

}  // namespace pc::quic
