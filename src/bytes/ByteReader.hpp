#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "bytes/Endian.hpp"

namespace pc::bytes {

class ByteReader {
public:
    explicit constexpr ByteReader(std::span<const std::uint8_t> bytes) noexcept
        : bytes_(bytes) {}

    [[nodiscard]] constexpr std::size_t offset() const noexcept {
        return offset_;
    }

    [[nodiscard]] constexpr std::size_t remaining() const noexcept {
        return offset_ <= bytes_.size() ? bytes_.size() - offset_ : 0U;
    }

    [[nodiscard]] constexpr bool skip(const std::size_t count) noexcept {
        if (count > remaining()) {
            return false;
        }

        offset_ += count;
        return true;
    }

    [[nodiscard]] constexpr std::optional<std::uint8_t> read_u8() noexcept {
        if (remaining() < 1U) {
            return std::nullopt;
        }

        return bytes_[offset_++];
    }

    [[nodiscard]] constexpr std::optional<std::uint16_t> read_u16(const Endianness endianness) noexcept {
        if (remaining() < 2U) {
            return std::nullopt;
        }

        const auto value = pc::bytes::read_u16(std::span<const std::uint8_t, 2>(bytes_.data() + offset_, 2U), endianness);
        offset_ += 2U;
        return value;
    }

    [[nodiscard]] constexpr std::optional<std::uint32_t> read_u32(const Endianness endianness) noexcept {
        if (remaining() < 4U) {
            return std::nullopt;
        }

        const auto value = pc::bytes::read_u32(std::span<const std::uint8_t, 4>(bytes_.data() + offset_, 4U), endianness);
        offset_ += 4U;
        return value;
    }

    [[nodiscard]] constexpr std::optional<std::span<const std::uint8_t>> read_bytes(const std::size_t count) noexcept {
        if (count > remaining()) {
            return std::nullopt;
        }

        auto out = bytes_.subspan(offset_, count);
        offset_ += count;
        return out;
    }

private:
    std::span<const std::uint8_t> bytes_ {};
    std::size_t offset_ {0};
};

}  // namespace pc::bytes

