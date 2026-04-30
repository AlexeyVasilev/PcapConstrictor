#pragma once

#include <filesystem>
#include <fstream>
#include <string>

#include "pcap/ClassicPcapFormat.hpp"
#include "pcap/PacketRecord.hpp"

namespace pc::pcap {

class ClassicPcapWriter {
public:
    [[nodiscard]] bool open(const std::filesystem::path& path, const ClassicPcapGlobalHeader& header);
    [[nodiscard]] bool write_packet(const PacketRecord& packet);
    void close();

    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] bool has_error() const noexcept;
    [[nodiscard]] const std::string& error_message() const noexcept;

private:
    void set_error(std::string message);

    std::ofstream stream_ {};
    ClassicPcapGlobalHeader header_ {};
    bool has_error_ {false};
    std::string error_message_ {};
};

}  // namespace pc::pcap

