#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace pc::cli {

enum class Command {
    constrict,
    reinflate,
};

struct Options {
    Command command {Command::constrict};
    std::filesystem::path input_path {};
    std::filesystem::path output_path {};
    std::optional<std::filesystem::path> config_path {};
    bool print_stats {false};
};

struct ParseResult {
    Options options {};
    bool ok {false};
    bool show_help {false};
    bool show_version {false};
    std::string error {};
};

[[nodiscard]] ParseResult parse_options(int argc, char** argv);
[[nodiscard]] std::string usage();
[[nodiscard]] std::string version_string();

}  // namespace pc::cli
