#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "bytes/Endian.hpp"

namespace pc::pcap {

inline constexpr std::size_t kClassicPcapGlobalHeaderSize = 24U;
inline constexpr std::size_t kClassicPcapPacketHeaderSize = 16U;

enum class TimePrecision {
    microsecond,
    nanosecond,
};

[[nodiscard]] constexpr const char* to_string(const TimePrecision precision) noexcept {
    return precision == TimePrecision::microsecond ? "microsecond" : "nanosecond";
}

struct ClassicPcapGlobalHeader {
    std::array<std::uint8_t, 4> magic_bytes {};
    pc::bytes::Endianness endianness {pc::bytes::Endianness::little};
    TimePrecision time_precision {TimePrecision::microsecond};
    std::uint16_t version_major {0};
    std::uint16_t version_minor {0};
    std::uint32_t thiszone_bits {0};
    std::uint32_t sigfigs {0};
    std::uint32_t snaplen {0};
    std::uint32_t link_type {0};
};

[[nodiscard]] constexpr bool detect_magic(
    const std::span<const std::uint8_t, 4> magic,
    pc::bytes::Endianness& endianness,
    TimePrecision& precision
) noexcept {
    if (magic[0] == 0xd4U && magic[1] == 0xc3U && magic[2] == 0xb2U && magic[3] == 0xa1U) {
        endianness = pc::bytes::Endianness::little;
        precision = TimePrecision::microsecond;
        return true;
    }

    if (magic[0] == 0xa1U && magic[1] == 0xb2U && magic[2] == 0xc3U && magic[3] == 0xd4U) {
        endianness = pc::bytes::Endianness::big;
        precision = TimePrecision::microsecond;
        return true;
    }

    if (magic[0] == 0x4dU && magic[1] == 0x3cU && magic[2] == 0xb2U && magic[3] == 0xa1U) {
        endianness = pc::bytes::Endianness::little;
        precision = TimePrecision::nanosecond;
        return true;
    }

    if (magic[0] == 0xa1U && magic[1] == 0xb2U && magic[2] == 0x3cU && magic[3] == 0x4dU) {
        endianness = pc::bytes::Endianness::big;
        precision = TimePrecision::nanosecond;
        return true;
    }

    return false;
}

}  // namespace pc::pcap
