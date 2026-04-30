#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

#include "pcap/ClassicPcapFormat.hpp"
#include "pcap/PacketRecord.hpp"

namespace pc::pcap {

class ClassicPcapReader {
public:
    [[nodiscard]] bool open(const std::filesystem::path& path);
    [[nodiscard]] std::optional<PacketRecord> read_next();

    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] bool has_error() const noexcept;
    [[nodiscard]] const std::string& error_message() const noexcept;
    [[nodiscard]] const ClassicPcapGlobalHeader& global_header() const noexcept;
    [[nodiscard]] std::uint64_t packet_index() const noexcept;

private:
    void clear();
    void set_error(std::string message);
    void set_error_at(std::uint64_t offset, std::string message);

    std::ifstream stream_ {};
    ClassicPcapGlobalHeader global_header_ {};
    std::uint64_t file_size_ {0};
    std::uint64_t next_input_offset_ {0};
    std::uint64_t next_packet_index_ {0};
    bool has_error_ {false};
    std::string error_message_ {};
};

}  // namespace pc::pcap

