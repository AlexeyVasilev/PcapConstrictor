#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>

#include "constrict/PacketDecision.hpp"
#include "config/Config.hpp"
#include "decode/PacketDecode.hpp"
#include "pcap/PacketRecord.hpp"
#include "stats/Stats.hpp"

namespace pc::tls {

class TlsConstrictor {
public:
    void process_tcp_packet(
        pc::pcap::PacketRecord& packet,
        const pc::decode::PacketDecodeResult& decoded,
        const pc::config::Config& config,
        pc::stats::Stats& stats,
        pc::constrict::PacketDecisionDiagnostics* diagnostics = nullptr
    );

private:
    struct DirectionKey {
        pc::decode::IpAddress src_ip {};
        pc::decode::IpAddress dst_ip {};
        std::uint16_t src_port {0};
        std::uint16_t dst_port {0};

        [[nodiscard]] bool operator==(const DirectionKey& other) const noexcept;
    };

    struct DirectionKeyHash {
        [[nodiscard]] std::size_t operator()(const DirectionKey& key) const noexcept;
    };

    struct DirectionState {
        bool confirmed_tls {false};
        bool has_seen_application_data {false};
        bool synchronized {false};
        std::uint32_t expected_tcp_seq {0};
        bool has_active_record {false};
        std::uint8_t active_record_content_type {0};
        std::uint32_t active_record_remaining_bytes {0};
        bool active_record_constrictible {false};
    };

    std::unordered_map<DirectionKey, DirectionState, DirectionKeyHash> directions_ {};
};

}  // namespace pc::tls
