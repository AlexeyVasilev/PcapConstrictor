#include "cli/Options.hpp"

#include <sstream>
#include <string_view>

namespace pc::cli {

namespace {

[[nodiscard]] bool is_help_arg(const std::string_view arg) noexcept {
    return arg == "-h" || arg == "--help";
}

}  // namespace

std::string usage() {
    return
        "Usage:\n"
        "  pcap-constrictor constrict <input.pcap> -o <output.pcap> [--config config.ini] [--stats]\n"
        "  pcap-constrictor reinflate <input.pcap> -o <output.pcap> [--config config.ini] [--stats]\n"
        "  pcap-constrictor restore <input.pcap> -o <output.pcap> [--config config.ini] [--stats]\n"
        "\n"
        "Current behavior:\n"
        "  constrict performs classic PCAP passthrough.\n"
        "  reinflate/restore pads truncated packets and can preserve or recompute checksums via config.\n";
}

ParseResult parse_options(const int argc, char** argv) {
    ParseResult result {};

    if (argc <= 1) {
        result.show_help = true;
        return result;
    }

    for (int index = 1; index < argc; ++index) {
        if (is_help_arg(argv[index])) {
            result.show_help = true;
            return result;
        }
    }

    const std::string_view command = argv[1];
    if (command == "constrict") {
        result.options.command = Command::constrict;
    } else if (command == "reinflate" || command == "restore") {
        result.options.command = Command::reinflate;
    } else {
        result.error = "unsupported command: ";
        result.error += command;
        return result;
    }

    bool saw_output = false;
    bool saw_input = false;

    for (int index = 2; index < argc; ++index) {
        const std::string_view arg = argv[index];
        if (arg == "--stats") {
            result.options.print_stats = true;
            continue;
        }

        if (arg == "-o" || arg == "--output") {
            if (index + 1 >= argc) {
                result.error = "missing output path after ";
                result.error += arg;
                return result;
            }
            result.options.output_path = argv[++index];
            saw_output = true;
            continue;
        }

        if (arg == "--config") {
            if (index + 1 >= argc) {
                result.error = "missing config path after --config";
                return result;
            }
            result.options.config_path = argv[++index];
            continue;
        }

        if (!arg.empty() && arg.front() == '-') {
            result.error = "unknown option: ";
            result.error += arg;
            return result;
        }

        if (saw_input) {
            result.error = "unexpected extra positional argument: ";
            result.error += arg;
            return result;
        }

        result.options.input_path = argv[index];
        saw_input = true;
    }

    if (!saw_input) {
        result.error = "missing input path";
        return result;
    }

    if (!saw_output) {
        result.error = "missing output path; use -o <output.pcap>";
        return result;
    }

    result.ok = true;
    return result;
}

}  // namespace pc::cli
