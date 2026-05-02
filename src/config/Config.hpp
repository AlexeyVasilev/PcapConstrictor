#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace pc::config {

enum class FillMode {
    fixed_byte,
    random,
};

enum class ChecksumPolicy {
    preserve,
    recompute,
};

struct GeneralConfig {
    std::uint32_t min_saved_bytes_per_packet {16};
};

struct TlsConfig {
    std::uint32_t app_data_keep_record_bytes {8};
    std::uint32_t app_data_continuation_keep_bytes {8};
};

struct QuicConfig {
    std::uint32_t short_header_keep_packet_bytes {32};
    bool require_dcid_match {true};
    bool allow_short_header_without_known_dcid {false};
};

struct ReinflateConfig {
    FillMode fill_mode {FillMode::fixed_byte};
    std::uint8_t fill_byte {0xABU};
    ChecksumPolicy checksum_policy {ChecksumPolicy::preserve};
};

struct Config {
    GeneralConfig general {};
    TlsConfig tls {};
    QuicConfig quic {};
    ReinflateConfig reinflate {};
};

struct LoadResult {
    Config config {};
    bool ok {true};
    std::string error {};
};

[[nodiscard]] LoadResult load_config_file(const std::filesystem::path& path);

}  // namespace pc::config
