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

[[nodiscard]] pc::decode::PacketDecodeResult make_decoded(
    const std::uint32_t seq,
    const std::size_t payload_size,
    const std::uint8_t tcp_flags = 0U
) {
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
    decoded.tcp_flags = tcp_flags;
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
            "default final_only policy should keep middle Application Data continuation full"
        );
    }

    {
        pc::config::Config stream_config = config;
        stream_config.tls.app_data_continuation_policy = pc::config::TlsAppDataContinuationPolicy::stream;

        pc::tls::TlsConstrictor tls {};
        pc::stats::Stats stats {};

        const auto first_payload = make_handshake_then_partial_appdata_payload(4U, 0x11U, 30U, 0x22U, 5U);
        auto first_packet = make_packet(first_payload);
        tls.process_tcp_packet(first_packet, make_decoded(2500U, first_payload.size()), stream_config, stats);

        Payload middle_payload(10U, 0x34U);
        auto middle_packet = make_packet(middle_payload);
        tls.process_tcp_packet(middle_packet, make_decoded(2500U + first_payload.size(), middle_payload.size()), stream_config, stats);

        pc::test::require(
            middle_packet.captured_length == stream_config.tls.app_data_continuation_keep_bytes,
            "stream policy should truncate middle Application Data continuation"
        );
        pc::test::require(
            stats.tls_packets_truncated_stream_continuation == 1U,
            "expected one stream continuation truncation"
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
            "final_only policy should truncate exact final Application Data continuation"
        );
    }

    {
        pc::config::Config stream_config = config;
        stream_config.tls.app_data_continuation_policy = pc::config::TlsAppDataContinuationPolicy::stream;

        pc::tls::TlsConstrictor tls {};
        pc::stats::Stats stats {};

        const auto first_payload = make_handshake_then_partial_appdata_payload(4U, 0x12U, 20U, 0x51U, 10U);
        auto first_packet = make_packet(first_payload);
        tls.process_tcp_packet(first_packet, make_decoded(3500U, first_payload.size()), stream_config, stats);

        Payload final_payload(10U, 0x45U);
        auto final_packet = make_packet(final_payload);
        tls.process_tcp_packet(final_packet, make_decoded(3500U + first_payload.size(), final_payload.size()), stream_config, stats);

        pc::test::require(
            final_packet.captured_length == stream_config.tls.app_data_continuation_keep_bytes,
            "stream policy should also truncate exact final Application Data continuation"
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

        pc::test::require(
            later_packet.captured_length == config.tls.app_data_keep_record_bytes,
            "confirmed TLS stream should resynchronize on later AppData start after state reset"
        );
        pc::test::require(
            stats.tls_packets_kept_app_data_continuation_with_extra_bytes == 1U,
            "expected state reset diagnostic when AppData continuation ends before packet end"
        );
        pc::test::require(
            stats.tls_packets_resynchronized == 1U,
            "expected later AppData-start packet to resynchronize after state reset"
        );
        pc::test::require(
            stats.tls_packets_resynchronized_app_data_start == 1U,
            "expected AppData-start resynchronization after state reset"
        );
    }

    {
        pc::config::Config stream_config = config;
        stream_config.tls.app_data_continuation_policy = pc::config::TlsAppDataContinuationPolicy::stream;

        pc::tls::TlsConstrictor tls {};
        pc::stats::Stats stats {};

        const auto first_payload = make_handshake_then_partial_appdata_payload(4U, 0x13U, 10U, 0x71U, 5U);
        auto first_packet = make_packet(first_payload);
        tls.process_tcp_packet(first_packet, make_decoded(4500U, first_payload.size()), stream_config, stats);

        Payload uncertain_payload(5U, 0x56U);
        append_bytes(uncertain_payload, Payload {0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU});
        auto uncertain_packet = make_packet(uncertain_payload);
        tls.process_tcp_packet(
            uncertain_packet,
            make_decoded(4500U + first_payload.size(), uncertain_payload.size()),
            stream_config,
            stats
        );

        require_packet_kept_full(
            uncertain_packet,
            uncertain_payload,
            "stream policy should keep full when AppData continuation ends before packet end"
        );
        pc::test::require(
            stats.tls_packets_kept_app_data_continuation_with_extra_bytes == 1U,
            "stream policy should still reset state when continuation ends before packet end"
        );
    }

    {
        pc::tls::TlsConstrictor tls {};
        pc::stats::Stats stats {};

        const auto handshake_payload = make_tls_record(0x16U, 12U, 0x20U, 12U);
        auto handshake_packet = make_packet(handshake_payload);
        tls.process_tcp_packet(handshake_packet, make_decoded(5000U, handshake_payload.size()), config, stats);

        const auto appdata_payload = make_tls_record(0x17U, 24U, 0xA0U, 24U);
        auto appdata_packet = make_packet(appdata_payload);
        tls.process_tcp_packet(
            appdata_packet,
            make_decoded(9999U, appdata_payload.size()),
            config,
            stats
        );

        pc::test::require(
            appdata_packet.captured_length == config.tls.app_data_keep_record_bytes,
            "confirmed TLS packet after seq mismatch should resynchronize and truncate AppData start"
        );
        pc::test::require(stats.tls_packets_kept_tcp_seq_mismatch == 1U, "expected one TCP seq mismatch");
        pc::test::require(stats.tls_packets_state_reset_on_seq_mismatch == 1U, "expected one state reset on seq mismatch");
        pc::test::require(stats.tls_packets_resynchronized == 1U, "expected one TLS resynchronization");
        pc::test::require(
            stats.tls_packets_resynchronized_app_data_start == 1U,
            "expected one AppData-start TLS resynchronization"
        );
        pc::test::require(stats.tls_packets_truncated == 1U, "expected one TLS truncation after resynchronization");
    }

    {
        pc::tls::TlsConstrictor tls {};
        pc::stats::Stats stats {};

        const auto appdata_payload = make_tls_record(0x17U, 16U, 0xB0U, 16U);
        auto appdata_packet = make_packet(appdata_payload);
        tls.process_tcp_packet(appdata_packet, make_decoded(6000U, appdata_payload.size()), config, stats);

        require_packet_kept_full(
            appdata_packet,
            appdata_payload,
            "unconfirmed direction with AppData start should be kept full"
        );
        pc::test::require(
            stats.tls_packets_kept_unsynchronized_non_handshake == 1U,
            "expected unsynchronized non-handshake diagnostic for unconfirmed AppData start"
        );
    }

    {
        pc::tls::TlsConstrictor tls {};
        pc::stats::Stats stats {};

        const auto handshake_payload = make_tls_record(0x16U, 12U, 0x30U, 12U);
        auto handshake_packet = make_packet(handshake_payload);
        tls.process_tcp_packet(handshake_packet, make_decoded(7000U, handshake_payload.size()), config, stats);

        auto syn_packet = make_packet(Payload {});
        tls.process_tcp_packet(syn_packet, make_decoded(0U, 0U, 0x02U), config, stats);

        const auto appdata_payload = make_tls_record(0x17U, 16U, 0xC0U, 16U);
        auto appdata_packet = make_packet(appdata_payload);
        tls.process_tcp_packet(appdata_packet, make_decoded(7012U, appdata_payload.size()), config, stats);

        require_packet_kept_full(
            appdata_packet,
            appdata_payload,
            "SYN should clear stale TLS state before later AppData-only packet"
        );
        pc::test::require(stats.tls_packets_state_reset_on_syn_or_rst == 1U, "expected one state reset on SYN/RST");
        pc::test::require(
            stats.tls_packets_kept_unsynchronized_non_handshake == 1U,
            "post-SYN AppData-only packet should not inherit stale TLS confirmation"
        );
    }
}
