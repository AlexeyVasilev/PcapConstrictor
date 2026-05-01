#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace pc::pcap {

inline constexpr std::uint32_t kPcapNgSectionHeaderBlockType = 0x0A0D0D0AU;
inline constexpr std::uint32_t kPcapNgInterfaceDescriptionBlockType = 0x00000001U;
inline constexpr std::uint32_t kPcapNgEnhancedPacketBlockType = 0x00000006U;
inline constexpr std::uint32_t kPcapNgByteOrderMagic = 0x1A2B3C4DU;

inline constexpr std::array<std::uint8_t, 4> kPcapNgSectionHeaderBlockTypeBytes {0x0AU, 0x0DU, 0x0DU, 0x0AU};
inline constexpr std::array<std::uint8_t, 4> kPcapNgLittleEndianByteOrderMagicBytes {0x4DU, 0x3CU, 0x2BU, 0x1AU};
inline constexpr std::array<std::uint8_t, 4> kPcapNgBigEndianByteOrderMagicBytes {0x1AU, 0x2BU, 0x3CU, 0x4DU};

[[nodiscard]] constexpr std::size_t pad_to_32bit(const std::size_t size) noexcept {
    return (size + 3U) & ~static_cast<std::size_t>(3U);
}

}  // namespace pc::pcap
