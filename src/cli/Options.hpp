#pragma once

#include <filesystem>
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
    bool print_stats {false};
};

struct ParseResult {
    Options options {};
    bool ok {false};
    bool show_help {false};
    std::string error {};
};

[[nodiscard]] ParseResult parse_options(int argc, char** argv);
[[nodiscard]] std::string usage();

}  // namespace pc::cli
