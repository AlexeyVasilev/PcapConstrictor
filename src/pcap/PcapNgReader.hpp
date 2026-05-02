#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "bytes/Endian.hpp"
#include "pcap/PacketRecord.hpp"

namespace pc::pcap {

struct PcapNgInterfaceDescription {
    std::uint32_t interface_id {0};
    std::uint16_t link_type {0};
    std::uint32_t snaplen {0};
};

struct PcapNgEnhancedPacketBlock {
    std::uint32_t interface_id {0};
    std::uint32_t timestamp_high {0};
    std::uint32_t timestamp_low {0};
    bool interface_known {false};
    std::uint32_t link_type {0};
    PacketRecord packet {};
    std::vector<std::uint8_t> options_raw {};
};

enum class PcapNgBlockKind {
    raw,
    interface_description,
    enhanced_packet,
};

struct PcapNgBlock {
    PcapNgBlockKind kind {PcapNgBlockKind::raw};
    std::uint32_t type {0};
    std::uint64_t block_offset {0};
    std::vector<std::uint8_t> raw_bytes {};
    PcapNgInterfaceDescription interface_description {};
    PcapNgEnhancedPacketBlock enhanced_packet {};
};

enum class PcapNgIncompleteTailKind {
    block_header,
    block_body,
};

struct PcapNgIncompleteTailInfo {
    PcapNgIncompleteTailKind kind {PcapNgIncompleteTailKind::block_header};
    std::uint64_t file_offset {0};
    std::uint64_t trailing_bytes {0};
    std::uint64_t expected_block_length {0};
    std::uint64_t available_block_bytes {0};
    std::uint64_t missing_block_bytes {0};
};

class PcapNgReader {
public:
    [[nodiscard]] bool open(const std::filesystem::path& path);
    [[nodiscard]] std::optional<PcapNgBlock> read_next();

    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] bool has_error() const noexcept;
    [[nodiscard]] const std::string& error_message() const noexcept;
    [[nodiscard]] pc::bytes::Endianness section_endianness() const noexcept;
    [[nodiscard]] std::uint64_t packet_index() const noexcept;
    [[nodiscard]] const std::optional<PcapNgIncompleteTailInfo>& incomplete_tail_info() const noexcept;

private:
    struct InterfaceState {
        bool valid {false};
        std::uint32_t link_type {0};
        std::uint32_t snaplen {0};
    };

    void clear();
    void set_error(std::string message);
    void set_error_at(std::uint64_t offset, std::string message);
    [[nodiscard]] bool read_exact(std::uint64_t offset, std::vector<std::uint8_t>& out);
    [[nodiscard]] std::optional<PcapNgBlock> parse_section_header_block(
        std::uint64_t block_offset,
        std::vector<std::uint8_t>&& block_bytes
    );
    [[nodiscard]] std::optional<PcapNgBlock> parse_interface_description_block(
        std::uint64_t block_offset,
        std::vector<std::uint8_t>&& block_bytes
    );
    [[nodiscard]] std::optional<PcapNgBlock> parse_enhanced_packet_block(
        std::uint64_t block_offset,
        std::vector<std::uint8_t>&& block_bytes
    );

    std::ifstream stream_ {};
    std::uint64_t file_size_ {0};
    std::uint64_t next_input_offset_ {0};
    std::uint64_t next_packet_index_ {0};
    bool has_error_ {false};
    std::string error_message_ {};
    std::optional<PcapNgIncompleteTailInfo> incomplete_tail_info_ {};
    bool has_section_endianness_ {false};
    pc::bytes::Endianness section_endianness_ {pc::bytes::Endianness::little};
    std::vector<InterfaceState> interfaces_ {};
};

}  // namespace pc::pcap
