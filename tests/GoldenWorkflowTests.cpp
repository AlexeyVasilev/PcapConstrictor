#include "TestHelpers.hpp"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>

using namespace pc::test;

namespace {

[[nodiscard]] std::filesystem::path source_dir() {
    return std::filesystem::path {PCAP_CONSTRICTOR_SOURCE_DIR};
}

[[nodiscard]] std::filesystem::path binary_dir() {
    return std::filesystem::path {PCAP_CONSTRICTOR_BINARY_DIR};
}

[[nodiscard]] std::filesystem::path resolve_expected_output(
    const std::filesystem::path& scenario_dir,
    const std::filesystem::path& preferred_name,
    const std::filesystem::path& fallback_name
) {
    const auto preferred = scenario_dir / preferred_name;
    if (std::filesystem::exists(preferred)) {
        return preferred;
    }

    const auto fallback = scenario_dir / fallback_name;
    if (std::filesystem::exists(fallback)) {
        return fallback;
    }

    throw std::runtime_error(
        "missing expected golden output: " + preferred.string() +
        " (fallback also missing: " + fallback.string() + ")"
    );
}

void run_golden_pipeline_test(const std::string& scenario_name) {
    const auto scenario_dir = source_dir() / "tests" / "fixtures" / "golden" / scenario_name;
    const auto output_dir = binary_dir() / "test-output" / "golden" / scenario_name;
    std::filesystem::create_directories(output_dir);

    const auto input_path = scenario_dir / "input.pcap";
    const auto constrict_config = scenario_dir / "constrict.ini";
    const auto reinflate_preserve_config = scenario_dir / "reinflate_preserve.ini";
    const auto reinflate_recompute_config = scenario_dir / "reinflate_recompute.ini";

    const auto expected_constricted = resolve_expected_output(
        scenario_dir,
        "constricted.pcap",
        "actual.constricted.pcap"
    );
    const auto expected_reinflated_preserve = resolve_expected_output(
        scenario_dir,
        "reinflated_preserve_checksum.pcap",
        "actual.reinflated_preserve_checksum.pcap"
    );
    const auto expected_reinflated_recompute = resolve_expected_output(
        scenario_dir,
        "reinflated_recompute_checksum.pcap",
        "actual.reinflated_recompute_checksum.pcap"
    );

    const auto actual_constricted = output_dir / "actual.constricted.pcap";
    const auto actual_reinflated_preserve = output_dir / "actual.reinflated_preserve_checksum.pcap";
    const auto actual_reinflated_recompute = output_dir / "actual.reinflated_recompute_checksum.pcap";

    {
        const TestContext context {
            .executable = std::filesystem::path {PCAP_CONSTRICTOR_EXE_PATH},
            .fixture = input_path,
            .output = actual_constricted,
            .config = constrict_config,
        };
        const int exit_code = run_constrict_command(context);
        if (exit_code == -1) {
            throw std::runtime_error(
                "scenario " + scenario_name +
                ", stage constrict: failed to spawn pcap-constrictor command: " +
                std::strerror(errno)
            );
        }
        require(exit_code == 0, "scenario " + scenario_name + ", stage constrict: pcap-constrictor command failed");
    }

    compare_files_exact(scenario_name, "constrict", expected_constricted, actual_constricted);

    {
        const TestContext context {
            .executable = std::filesystem::path {PCAP_CONSTRICTOR_EXE_PATH},
            .fixture = actual_constricted,
            .output = actual_reinflated_preserve,
            .config = reinflate_preserve_config,
        };
        const int exit_code = run_reinflate_command(context);
        if (exit_code == -1) {
            throw std::runtime_error(
                "scenario " + scenario_name +
                ", stage reinflate_preserve_checksum: failed to spawn pcap-constrictor command: " +
                std::strerror(errno)
            );
        }
        require(
            exit_code == 0,
            "scenario " + scenario_name + ", stage reinflate_preserve_checksum: pcap-constrictor command failed"
        );
    }

    compare_files_exact(
        scenario_name,
        "reinflate_preserve_checksum",
        expected_reinflated_preserve,
        actual_reinflated_preserve
    );

    {
        const TestContext context {
            .executable = std::filesystem::path {PCAP_CONSTRICTOR_EXE_PATH},
            .fixture = actual_constricted,
            .output = actual_reinflated_recompute,
            .config = reinflate_recompute_config,
        };
        const int exit_code = run_reinflate_command(context);
        if (exit_code == -1) {
            throw std::runtime_error(
                "scenario " + scenario_name +
                ", stage reinflate_recompute_checksum: failed to spawn pcap-constrictor command: " +
                std::strerror(errno)
            );
        }
        require(
            exit_code == 0,
            "scenario " + scenario_name + ", stage reinflate_recompute_checksum: pcap-constrictor command failed"
        );
    }

    compare_files_exact(
        scenario_name,
        "reinflate_recompute_checksum",
        expected_reinflated_recompute,
        actual_reinflated_recompute
    );
}

}  // namespace

void run_golden_tls_test_2() {
    run_golden_pipeline_test("tls_test_2");
}

void run_golden_quic_test_2() {
    run_golden_pipeline_test("quic_test_2");
}

void run_golden_ipv6_ipv4_test_1() {
    run_golden_pipeline_test("ipv6_ipv4_test_1");
}
