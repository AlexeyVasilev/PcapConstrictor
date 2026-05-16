#include "TestHelpers.hpp"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

using namespace pc::test;

namespace {

[[nodiscard]] TestContext make_decision_log_context() {
    const std::filesystem::path source_dir {PCAP_CONSTRICTOR_SOURCE_DIR};
    const std::filesystem::path binary_dir {PCAP_CONSTRICTOR_BINARY_DIR};
    const auto output_dir = binary_dir / "test-output" / "decision-log";
    return {
        .executable = std::filesystem::path {PCAP_CONSTRICTOR_EXE_PATH},
        .fixture = source_dir / "tests" / "fixtures" / "tls" / "tls_test_1.pcap",
        .output = output_dir / "tls_test_1.out.pcap",
        .decision_log = output_dir / "decisions.csv",
    };
}

}  // namespace

void run_decision_log_fixture_test() {
    const auto context = make_decision_log_context();
    std::filesystem::create_directories(context.output.parent_path());

    const int exit_code = run_constrict_command(context);
    if (exit_code == -1) {
        throw std::runtime_error(std::string("failed to spawn pcap-constrictor command: ") + std::strerror(errno));
    }
    require(exit_code == 0, "pcap-constrictor constrict with decision log failed");
    require(std::filesystem::exists(context.decision_log), "decision log file was not created");

    std::ifstream input(context.decision_log, std::ios::binary);
    require(input.is_open(), "failed to open decision log file");

    std::string header {};
    std::getline(input, header);
    require(!header.empty(), "decision log header is empty");
    require(
        header.find("packet_index,src_ip,src_port,dst_ip,dst_port,transport") == 0U,
        "decision log header is missing expected leading columns"
    );
    require(
        header.find("decision,reason,bytes_saved") != std::string::npos,
        "decision log header is missing decision columns"
    );

    std::string first_row {};
    std::getline(input, first_row);
    require(!first_row.empty(), "decision log should contain at least one data row");
}
