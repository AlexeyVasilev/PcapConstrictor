#include "TestHelpers.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "config/Config.hpp"
#include "stats/Stats.hpp"
#include "tls/TlsConstrictor.hpp"

namespace {

using Payload = std::vector<std::uint8_t>;

constexpr std::uint16_t kSrcPort = 443U;
constexpr std::uint16_t kDstPort = 55555U;
constexpr std::uint8_t kIpv6A[16] {0x20U, 0x01U, 0x0dU, 0xb8U, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1U};
constexpr std::uint8_t kIpv6B[16] {0x20U, 0x01U, 0x0dU, 0xb8U, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2U};

[[nodiscard]] pc::decode::IpAddress make_ipv6(const std::uint8_t (&bytes)[16]) {
    pc::decode::IpAddress ip {};
    ip.length = 16U;
    for (std::size_t index = 0; index < 16U; ++index) {
        ip.bytes[index] = bytes[index];
    }
    return ip;
}

[[nodiscard]] pc::decode::PacketDecodeResult make_decoded(const std::uint32_t seq, const std::size_t payload_size) {
    pc::decode::PacketDecodeResult decoded {};
    decoded.decoded = true;
    decoded.transport = pc::decode::TransportProtocol::Tcp;
    decoded.transport_payload_offset = 0U;
    decoded.transport_payload_size = payload_size;
    decoded.src_ip = make_ipv6(kIpv6A);
    decoded.dst_ip = make_ipv6(kIpv6B);
    decoded.src_port = kSrcPort;
    decoded.dst_port = kDstPort;
    decoded.tcp_seq = seq;
    return decoded;
}

[[nodiscard]] pc::pcap::PacketRecord make_packet(const Payload& payload) {
    pc::pcap::PacketRecord packet {};
    packet.captured_length = static_cast<std::uint32_t>(payload.size());
    packet.original_length = static_cast<std::uint32_t>(payload.size());
    packet.bytes = payload;
    return packet;
}

[[nodiscard]] Payload make_tls_record(
    const std::uint8_t content_type,
    const std::uint16_t record_length,
    const std::uint8_t body_seed,
    const std::size_t body_bytes_present
) {
    Payload bytes {
        content_type,
        0x03U,
        0x03U,
        static_cast<std::uint8_t>(record_length >> 8U),
        static_cast<std::uint8_t>(record_length & 0x00FFU),
    };

    for (std::size_t index = 0; index < body_bytes_present; ++index) {
        bytes.push_back(static_cast<std::uint8_t>(body_seed + static_cast<std::uint8_t>(index)));
    }

    return bytes;
}

void append_bytes(Payload& target, const Payload& suffix) {
    target.insert(target.end(), suffix.begin(), suffix.end());
}

[[nodiscard]] Payload make_handshake_then_partial_appdata_payload(
    const std::uint16_t handshake_record_length,
    const std::uint8_t handshake_seed,
    const std::uint16_t appdata_record_length,
    const std::uint8_t appdata_seed,
    const std::size_t appdata_body_bytes_present
) {
    auto payload = make_tls_record(0x16U, handshake_record_length, handshake_seed, handshake_record_length);
    append_bytes(payload, make_tls_record(0x17U, appdata_record_length, appdata_seed, appdata_body_bytes_present));
    return payload;
}

void require_packet_kept_full(
    const pc::pcap::PacketRecord& packet,
    const Payload& original_payload,
    const std::string& message
) {
    pc::test::require(packet.bytes == original_payload, message);
    pc::test::require(packet.captured_length == original_payload.size(), message + ": caplen changed");
}

}  // namespace

void run_tls_continuation_policy_test() {
    pc::config::Config config {};
    config.general.min_saved_bytes_per_packet = 0U;

    {
        pc::tls::TlsConstrictor tls {};
        pc::stats::Stats stats {};

        const auto first_payload = make_tls_record(0x16U, 20U, 0x10U, 13U);
        auto first_packet = make_packet(first_payload);
        tls.process_tcp_packet(first_packet, make_decoded(1000U, first_payload.size()), config, stats);

        Payload second_payload(7U, 0x42U);
        append_bytes(second_payload, Payload {0x14U, 0x03U, 0x03U, 0x00U, 0x01U, 0x01U});
        append_bytes(second_payload, make_tls_record(0x17U, 32U, 0x80U, 10U));

        auto second_packet = make_packet(second_payload);
        tls.process_tcp_packet(second_packet, make_decoded(1000U + first_payload.size(), second_payload.size()), config, stats);

        pc::test::require(
            second_packet.captured_length == 21U,
            "non-AppData continuation followed by CCS and AppData start should truncate AppData start only"
        );
        pc::test::require(stats.tls_packets_truncated == 1U, "expected one TLS truncation for AppData start after visible continuation");
    }

    {
        pc::tls::TlsConstrictor tls {};
        pc::stats::Stats stats {};

        const auto first_payload = make_handshake_then_partial_appdata_payload(4U, 0x01U, 30U, 0x20U, 5U);
        auto first_packet = make_packet(first_payload);
        tls.process_tcp_packet(first_packet, make_decoded(2000U, first_payload.size()), config, stats);

        Payload middle_payload(10U, 0x33U);
        auto middle_packet = make_packet(middle_payload);
        tls.process_tcp_packet(middle_packet, make_decoded(2000U + first_payload.size(), middle_payload.size()), config, stats);

        require_packet_kept_full(
            middle_packet,
            middle_payload,
            "middle Application Data continuation should be kept full"
        );
    }

    {
        pc::tls::TlsConstrictor tls {};
        pc::stats::Stats stats {};

        const auto first_payload = make_handshake_then_partial_appdata_payload(4U, 0x02U, 20U, 0x50U, 10U);
        auto first_packet = make_packet(first_payload);
        tls.process_tcp_packet(first_packet, make_decoded(3000U, first_payload.size()), config, stats);

        Payload final_payload(10U, 0x44U);
        auto final_packet = make_packet(final_payload);
        tls.process_tcp_packet(final_packet, make_decoded(3000U + first_payload.size(), final_payload.size()), config, stats);

        pc::test::require(
            final_packet.captured_length == config.tls.app_data_continuation_keep_bytes,
            "exact final Application Data continuation should truncate to continuation keep bytes"
        );
    }

    {
        pc::tls::TlsConstrictor tls {};
        pc::stats::Stats stats {};

        const auto first_payload = make_handshake_then_partial_appdata_payload(4U, 0x03U, 10U, 0x70U, 5U);
        auto first_packet = make_packet(first_payload);
        tls.process_tcp_packet(first_packet, make_decoded(4000U, first_payload.size()), config, stats);

        Payload uncertain_payload(5U, 0x55U);
        append_bytes(uncertain_payload, Payload {0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU});
        auto uncertain_packet = make_packet(uncertain_payload);
        tls.process_tcp_packet(
            uncertain_packet,
            make_decoded(4000U + first_payload.size(), uncertain_payload.size()),
            config,
            stats
        );

        require_packet_kept_full(
            uncertain_packet,
            uncertain_payload,
            "Application Data continuation ending before packet end should be kept full"
        );

        const auto later_payload = make_tls_record(0x17U, 12U, 0x90U, 8U);
        auto later_packet = make_packet(later_payload);
        tls.process_tcp_packet(
            later_packet,
            make_decoded(4000U + first_payload.size() + uncertain_payload.size(), later_payload.size()),
            config,
            stats
        );

        require_packet_kept_full(
            later_packet,
            later_payload,
            "state should reset after Application Data continuation ends before packet end"
        );
        pc::test::require(
            stats.tls_packets_kept_uncertain == 1U,
            "post-reset non-handshake TLS packet should be treated as uncertain"
        );
    }
}
