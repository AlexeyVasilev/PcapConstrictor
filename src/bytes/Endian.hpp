#pragma once

#include <cstdint>
#include <span>

namespace pc::bytes {

enum class Endianness {
    little,
    big,
};

[[nodiscard]] constexpr const char* to_string(const Endianness endianness) noexcept {
    return endianness == Endianness::little ? "little" : "big";
}

[[nodiscard]] constexpr std::uint16_t read_le16(std::span<const std::uint8_t, 2> bytes) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(bytes[0]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[1]) << 8U)
    );
}

[[nodiscard]] constexpr std::uint16_t read_be16(std::span<const std::uint8_t, 2> bytes) noexcept {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[0]) << 8U) |
        static_cast<std::uint16_t>(bytes[1])
    );
}

[[nodiscard]] constexpr std::uint32_t read_le32(std::span<const std::uint8_t, 4> bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8U) |
           (static_cast<std::uint32_t>(bytes[2]) << 16U) |
           (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

[[nodiscard]] constexpr std::uint32_t read_be32(std::span<const std::uint8_t, 4> bytes) noexcept {
    return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
           (static_cast<std::uint32_t>(bytes[1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[2]) << 8U) |
           static_cast<std::uint32_t>(bytes[3]);
}

[[nodiscard]] constexpr std::uint16_t read_u16(
    std::span<const std::uint8_t, 2> bytes,
    const Endianness endianness
) noexcept {
    return endianness == Endianness::little ? read_le16(bytes) : read_be16(bytes);
}

[[nodiscard]] constexpr std::uint32_t read_u32(
    std::span<const std::uint8_t, 4> bytes,
    const Endianness endianness
) noexcept {
    return endianness == Endianness::little ? read_le32(bytes) : read_be32(bytes);
}

inline void write_u16(std::span<std::uint8_t, 2> out, const std::uint16_t value, const Endianness endianness) noexcept {
    if (endianness == Endianness::little) {
        out[0] = static_cast<std::uint8_t>(value & 0x00FFU);
        out[1] = static_cast<std::uint8_t>((value >> 8U) & 0x00FFU);
        return;
    }

    out[0] = static_cast<std::uint8_t>((value >> 8U) & 0x00FFU);
    out[1] = static_cast<std::uint8_t>(value & 0x00FFU);
}

inline void write_u32(std::span<std::uint8_t, 4> out, const std::uint32_t value, const Endianness endianness) noexcept {
    if (endianness == Endianness::little) {
        out[0] = static_cast<std::uint8_t>(value & 0x000000FFU);
        out[1] = static_cast<std::uint8_t>((value >> 8U) & 0x000000FFU);
        out[2] = static_cast<std::uint8_t>((value >> 16U) & 0x000000FFU);
        out[3] = static_cast<std::uint8_t>((value >> 24U) & 0x000000FFU);
        return;
    }

    out[0] = static_cast<std::uint8_t>((value >> 24U) & 0x000000FFU);
    out[1] = static_cast<std::uint8_t>((value >> 16U) & 0x000000FFU);
    out[2] = static_cast<std::uint8_t>((value >> 8U) & 0x000000FFU);
    out[3] = static_cast<std::uint8_t>(value & 0x000000FFU);
}

}  // namespace pc::bytes
