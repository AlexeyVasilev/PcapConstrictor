#include "TestHelpers.hpp"

#include <filesystem>
#include <fstream>
#include <string>

#include "config/Config.hpp"

namespace {

[[nodiscard]] std::filesystem::path config_test_dir() {
    auto path = std::filesystem::path(PCAP_CONSTRICTOR_BINARY_DIR) / "test-output" / "config";
    std::filesystem::create_directories(path);
    return path;
}

[[nodiscard]] pc::config::LoadResult load_config_text(const std::string& file_name, const std::string& text) {
    const auto path = config_test_dir() / file_name;
    std::ofstream out(path, std::ios::binary);
    pc::test::require(out.is_open(), "failed to create config test file");
    out << text;
    out.close();
    pc::test::require(out.good(), "failed to write config test file");
    return pc::config::load_config_file(path);
}

}  // namespace

void run_config_parsing_tests() {
    {
        const pc::config::Config defaults {};
        pc::test::require(
            defaults.reinflate.fill_mode == pc::config::FillMode::fixed_byte,
            "default reinflate fill mode should be fixed byte"
        );
        pc::test::require(
            defaults.reinflate.fill_byte == 0xABU,
            "default reinflate fill byte should be 0xAB"
        );
        pc::test::require(
            defaults.reinflate.checksum_policy == pc::config::ChecksumPolicy::preserve,
            "default reinflate checksum policy should be preserve"
        );
    }

    {
        const auto loaded = load_config_text(
            "fill_byte_hex.ini",
            "[reinflate]\n"
            "fill_byte = 0xAB\n"
        );
        pc::test::require(loaded.ok, "fill_byte = 0xAB should parse");
        pc::test::require(
            loaded.config.reinflate.fill_mode == pc::config::FillMode::fixed_byte,
            "fill_byte hex should select fixed byte mode"
        );
        pc::test::require(
            loaded.config.reinflate.fill_byte == 0xABU,
            "fill_byte hex was not stored as 0xAB"
        );
    }

    {
        const auto loaded = load_config_text(
            "fill_byte_decimal.ini",
            "[reinflate]\n"
            "fill_byte = 171\n"
        );
        pc::test::require(loaded.ok, "fill_byte = 171 should parse");
        pc::test::require(
            loaded.config.reinflate.fill_mode == pc::config::FillMode::fixed_byte,
            "fill_byte decimal should select fixed byte mode"
        );
        pc::test::require(
            loaded.config.reinflate.fill_byte == 0xABU,
            "fill_byte decimal was not stored as 0xAB"
        );
    }

    {
        const auto loaded = load_config_text(
            "fill_byte_random.ini",
            "[reinflate]\n"
            "fill_byte = random\n"
        );
        pc::test::require(loaded.ok, "fill_byte = random should parse");
        pc::test::require(
            loaded.config.reinflate.fill_mode == pc::config::FillMode::random,
            "fill_byte = random should select random mode"
        );
    }

    {
        const auto loaded = load_config_text(
            "fill_byte_invalid.ini",
            "[reinflate]\n"
            "fill_byte = banana\n"
        );
        pc::test::require(!loaded.ok, "invalid fill_byte should fail config parsing");
        pc::test::require(
            loaded.error.find("fill_byte") != std::string::npos,
            "invalid fill_byte error should name the key"
        );
    }

    {
        const auto loaded = load_config_text(
            "checksum_preserve.ini",
            "[reinflate]\n"
            "checksum_policy = preserve\n"
        );
        pc::test::require(loaded.ok, "checksum_policy = preserve should parse");
        pc::test::require(
            loaded.config.reinflate.checksum_policy == pc::config::ChecksumPolicy::preserve,
            "checksum_policy = preserve was not stored"
        );
    }

    {
        const auto loaded = load_config_text(
            "checksum_recompute.ini",
            "[reinflate]\n"
            "checksum_policy = recompute\n"
        );
        pc::test::require(loaded.ok, "checksum_policy = recompute should parse");
        pc::test::require(
            loaded.config.reinflate.checksum_policy == pc::config::ChecksumPolicy::recompute,
            "checksum_policy = recompute was not stored"
        );
    }

    {
        const auto loaded = load_config_text(
            "checksum_invalid.ini",
            "[reinflate]\n"
            "checksum_policy = zero\n"
        );
        pc::test::require(!loaded.ok, "invalid checksum_policy should fail config parsing");
        pc::test::require(
            loaded.error.find("checksum_policy") != std::string::npos,
            "invalid checksum_policy error should name the key"
        );
    }
}
