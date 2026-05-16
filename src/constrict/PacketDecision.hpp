#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace pc::constrict {

struct PacketTruncationDecision {
    bool truncate {false};
    std::size_t new_caplen {0};
    std::string reason {"passthrough"};
};

struct PacketDecisionDiagnostics {
    std::string decision {"keep"};
    std::string reason {"keep.no_candidate"};
    std::string tls_state_before {};
    std::string tls_state_after {};
    std::uint32_t tls_active_record_remaining_before {0};
    std::uint32_t tls_active_record_remaining_after {0};
    std::string tls_record_event {};
    std::string decode_note {};
};

struct DecisionLogRow {
    std::size_t packet_index {0};
    std::string src_ip {};
    std::uint16_t src_port {0};
    std::string dst_ip {};
    std::uint16_t dst_port {0};
    std::string transport {};
    std::uint32_t tcp_seq {0};
    std::uint32_t tcp_ack {0};
    std::string tcp_flags {};
    std::uint32_t captured_length_before {0};
    std::uint32_t captured_length_after {0};
    std::uint32_t original_length {0};
    std::size_t transport_payload_size {0};
    std::string decision {};
    std::string reason {};
    std::uint64_t bytes_saved {0};
    std::string tls_state_before {};
    std::string tls_state_after {};
    std::uint32_t tls_active_record_remaining_before {0};
    std::uint32_t tls_active_record_remaining_after {0};
    std::string tls_record_event {};
    std::string decode_note {};
};

}  // namespace pc::constrict
