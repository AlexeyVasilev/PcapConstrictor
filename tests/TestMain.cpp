#include <cstddef>
#include <exception>
#include <iostream>
#include <string_view>

void run_config_parsing_tests();
void run_golden_ipv6_ipv4_test_1();
void run_golden_tls_test_2();
void run_golden_quic_test_2();
void run_pcapng_fixture_test();
void run_reinflate_checksum_policy_test();
void run_truncated_tail_fixture_test();
void run_tls_fixture_test();
void run_quic_fixture_test();

namespace {

struct TestCase {
    std::string_view name {};
    void (*run)() {};
};

constexpr TestCase kTests[] {
    {"config_parsing", &run_config_parsing_tests},
    {"golden_ipv6_ipv4_test_1", &run_golden_ipv6_ipv4_test_1},
    {"golden_tls_test_2", &run_golden_tls_test_2},
    {"golden_quic_test_2", &run_golden_quic_test_2},
    {"pcapng_fixture_workflow", &run_pcapng_fixture_test},
    {"reinflate_checksum_policy", &run_reinflate_checksum_policy_test},
    {"truncated_tail_fixture", &run_truncated_tail_fixture_test},
    {"tls_fixture_constrict", &run_tls_fixture_test},
    {"quic_fixture_constrict", &run_quic_fixture_test},
};

}  // namespace

int main(const int argc, char**) {
    if (argc != 1) {
        std::cerr << "pcap-constrictor-tests does not accept command-line arguments\n";
        return 2;
    }

    std::size_t failed = 0;
    for (const auto& test : kTests) {
        std::cout << "[ RUN  ] " << test.name << '\n';
        try {
            test.run();
            std::cout << "[ PASS ] " << test.name << '\n';
        } catch (const std::exception& error) {
            ++failed;
            std::cerr << "[ FAIL ] " << test.name << ": " << error.what() << '\n';
        }
    }

    if (failed != 0U) {
        std::cerr << failed << " test(s) failed\n";
        return 1;
    }

    std::cout << "All tests passed\n";
    return 0;
}
