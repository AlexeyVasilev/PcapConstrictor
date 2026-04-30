#include <filesystem>
#include <iostream>
#include <system_error>

#include "cli/Options.hpp"
#include "pcap/ClassicPcapReader.hpp"
#include "pcap/ClassicPcapWriter.hpp"
#include "stats/Stats.hpp"

namespace {

[[nodiscard]] bool same_existing_file(const std::filesystem::path& left, const std::filesystem::path& right) {
    std::error_code error {};
    if (!std::filesystem::exists(left, error) || error) {
        return false;
    }

    error.clear();
    if (!std::filesystem::exists(right, error) || error) {
        return false;
    }

    error.clear();
    return std::filesystem::equivalent(left, right, error) && !error;
}

[[nodiscard]] int run_constrict(const pc::cli::Options& options) {
    if (same_existing_file(options.input_path, options.output_path)) {
        std::cerr << "error: input and output paths refer to the same file\n";
        return 1;
    }

    pc::pcap::ClassicPcapReader reader {};
    if (!reader.open(options.input_path)) {
        std::cerr << "error: " << reader.error_message() << '\n';
        return 1;
    }

    pc::pcap::ClassicPcapWriter writer {};
    if (!writer.open(options.output_path, reader.global_header())) {
        std::cerr << "error: " << writer.error_message() << '\n';
        return 1;
    }

    pc::stats::Stats stats {};

    while (auto packet = reader.read_next()) {
        stats.total_captured_bytes_read += packet->captured_length;
        stats.total_original_bytes_read += packet->original_length;

        if (!writer.write_packet(*packet)) {
            std::cerr << "error: " << writer.error_message() << '\n';
            return 1;
        }

        ++stats.total_packets;
        stats.total_captured_bytes_written += packet->captured_length;
        stats.total_original_bytes_written += packet->original_length;
    }

    writer.close();

    if (reader.has_error()) {
        std::cerr << "error: " << reader.error_message() << '\n';
        return 1;
    }

    if (writer.has_error()) {
        std::cerr << "error: " << writer.error_message() << '\n';
        return 1;
    }

    if (options.print_stats) {
        pc::stats::print_stats(std::cout, stats, reader.global_header());
    }

    return 0;
}

}  // namespace

int main(const int argc, char** argv) {
    const auto parsed = pc::cli::parse_options(argc, argv);
    if (parsed.show_help) {
        std::cout << pc::cli::usage();
        return 0;
    }

    if (!parsed.ok) {
        std::cerr << "error: " << parsed.error << "\n\n" << pc::cli::usage();
        return 1;
    }

    return run_constrict(parsed.options);
}
