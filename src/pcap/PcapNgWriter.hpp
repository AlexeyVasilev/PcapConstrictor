#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "bytes/Endian.hpp"
#include "pcap/PcapNgReader.hpp"

namespace pc::pcap {

class PcapNgWriter {
public:
    [[nodiscard]] bool open(const std::filesystem::path& path);
    [[nodiscard]] bool write_raw_block(const std::vector<std::uint8_t>& block_bytes);
    [[nodiscard]] bool write_enhanced_packet(const PcapNgEnhancedPacketBlock& block);
    void close();

    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] bool has_error() const noexcept;
    [[nodiscard]] const std::string& error_message() const noexcept;

private:
    void set_error(std::string message);

    std::ofstream stream_ {};
    bool has_error_ {false};
    std::string error_message_ {};
    bool has_section_endianness_ {false};
    pc::bytes::Endianness section_endianness_ {pc::bytes::Endianness::little};
};

}  // namespace pc::pcap
