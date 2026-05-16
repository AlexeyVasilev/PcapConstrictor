#pragma once

#include <filesystem>
#include <fstream>
#include <string>

#include "constrict/PacketDecision.hpp"

namespace pc::constrict {

class DecisionLogWriter {
public:
    [[nodiscard]] bool open(const std::filesystem::path& path);
    [[nodiscard]] bool write_row(const DecisionLogRow& row);
    void close();

    [[nodiscard]] bool has_error() const noexcept;
    [[nodiscard]] const std::string& error_message() const noexcept;

private:
    std::ofstream stream_ {};
    bool has_error_ {false};
    std::string error_message_ {};
};

}  // namespace pc::constrict
