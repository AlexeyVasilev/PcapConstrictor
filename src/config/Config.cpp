#include "config/Config.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>

namespace pc::config {

namespace {

[[nodiscard]] std::string_view trim(std::string_view value) noexcept {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.remove_prefix(1U);
    }

    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.remove_suffix(1U);
    }

    return value;
}

[[nodiscard]] std::string_view remove_comment(std::string_view line) noexcept {
    const auto hash = line.find('#');
    const auto semicolon = line.find(';');
    const auto first = std::min(
        hash == std::string_view::npos ? line.size() : hash,
        semicolon == std::string_view::npos ? line.size() : semicolon
    );
    return line.substr(0U, first);
}

[[nodiscard]] std::string make_error(const std::uint64_t line_number, std::string_view message) {
    std::ostringstream out {};
    out << "config line " << line_number << ": " << message;
    return out.str();
}

[[nodiscard]] bool parse_u32(std::string_view text, std::uint32_t& out) noexcept {
    text = trim(text);
    if (text.empty() || text.front() == '-') {
        return false;
    }

    unsigned base = 10U;
    if (text.size() > 2U && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2U);
        base = 16U;
    }

    if (text.empty()) {
        return false;
    }

    std::uint64_t value = 0;
    const auto* begin = text.data();
    const auto* end = text.data() + text.size();
    const auto result = std::from_chars(begin, end, value, static_cast<int>(base));
    if (result.ec != std::errc {} || result.ptr != end) {
        return false;
    }

    if (value > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }

    out = static_cast<std::uint32_t>(value);
    return true;
}

[[nodiscard]] bool parse_bool(std::string_view text, bool& out) noexcept {
    text = trim(text);
    if (text == "true") {
        out = true;
        return true;
    }

    if (text == "false") {
        out = false;
        return true;
    }

    return false;
}

[[nodiscard]] bool parse_byte(std::string_view text, std::uint8_t& out) noexcept {
    std::uint32_t value = 0;
    if (!parse_u32(text, value) || value > std::numeric_limits<std::uint8_t>::max()) {
        return false;
    }

    out = static_cast<std::uint8_t>(value);
    return true;
}

[[nodiscard]] bool parse_fill_mode_and_byte(
    std::string_view text,
    FillMode& fill_mode,
    std::uint8_t& fill_byte
) noexcept {
    text = trim(text);
    if (text == "random") {
        fill_mode = FillMode::random;
        return true;
    }

    if (!parse_byte(text, fill_byte)) {
        return false;
    }

    fill_mode = FillMode::fixed_byte;
    return true;
}

[[nodiscard]] bool parse_checksum_policy(std::string_view text, ChecksumPolicy& out) noexcept {
    text = trim(text);
    if (text == "preserve") {
        out = ChecksumPolicy::preserve;
        return true;
    }

    if (text == "recompute") {
        out = ChecksumPolicy::recompute;
        return true;
    }

    return false;
}

[[nodiscard]] bool parse_tls_app_data_continuation_policy(
    std::string_view text,
    TlsAppDataContinuationPolicy& out
) noexcept {
    text = trim(text);
    if (text == "final_only") {
        out = TlsAppDataContinuationPolicy::final_only;
        return true;
    }

    if (text == "stream") {
        out = TlsAppDataContinuationPolicy::stream;
        return true;
    }

    if (text == "bulk") {
        out = TlsAppDataContinuationPolicy::bulk;
        return true;
    }

    return false;
}

[[nodiscard]] bool assign_value(
    Config& config,
    std::string_view section,
    std::string_view key,
    std::string_view value,
    std::string& error
) {
    if (section == "general") {
        if (key == "min_saved_bytes_per_packet") {
            if (!parse_u32(value, config.general.min_saved_bytes_per_packet)) {
                error = "invalid value for general.min_saved_bytes_per_packet";
                return false;
            }
            return true;
        }
    } else if (section == "tls") {
        if (key == "app_data_keep_record_bytes") {
            if (!parse_u32(value, config.tls.app_data_keep_record_bytes) ||
                config.tls.app_data_keep_record_bytes < 5U) {
                error = "invalid value for tls.app_data_keep_record_bytes; expected integer >= 5";
                return false;
            }
            return true;
        }

        if (key == "app_data_continuation_keep_bytes") {
            if (!parse_u32(value, config.tls.app_data_continuation_keep_bytes)) {
                error = "invalid value for tls.app_data_continuation_keep_bytes; expected integer >= 0";
                return false;
            }
            return true;
        }

        if (key == "app_data_continuation_policy") {
            if (!parse_tls_app_data_continuation_policy(value, config.tls.app_data_continuation_policy)) {
                error = "invalid value for tls.app_data_continuation_policy; expected final_only, stream, or bulk";
                return false;
            }
            return true;
        }
    } else if (section == "quic") {
        if (key == "short_header_keep_packet_bytes") {
            if (!parse_u32(value, config.quic.short_header_keep_packet_bytes) ||
                config.quic.short_header_keep_packet_bytes < 1U) {
                error = "invalid value for quic.short_header_keep_packet_bytes; expected integer >= 1";
                return false;
            }
            return true;
        }

        if (key == "require_dcid_match") {
            if (!parse_bool(value, config.quic.require_dcid_match)) {
                error = "invalid value for quic.require_dcid_match; expected true or false";
                return false;
            }
            return true;
        }

        if (key == "allow_short_header_without_known_dcid") {
            if (!parse_bool(value, config.quic.allow_short_header_without_known_dcid)) {
                error = "invalid value for quic.allow_short_header_without_known_dcid; expected true or false";
                return false;
            }
            return true;
        }
    } else if (section == "reinflate") {
        if (key == "fill_byte") {
            if (!parse_fill_mode_and_byte(value, config.reinflate.fill_mode, config.reinflate.fill_byte)) {
                error = "invalid value for reinflate.fill_byte; expected byte value 0..255 or random";
                return false;
            }
            return true;
        }

        if (key == "checksum_policy") {
            if (!parse_checksum_policy(value, config.reinflate.checksum_policy)) {
                error = "invalid value for reinflate.checksum_policy; expected preserve or recompute";
                return false;
            }
            return true;
        }
    } else if (section.empty()) {
        error = "key appears before any section";
        return false;
    } else {
        error = "unknown config section: ";
        error += section;
        return false;
    }

    error = "unknown config key: ";
    error += section;
    error += ".";
    error += key;
    return false;
}

}  // namespace

LoadResult load_config_file(const std::filesystem::path& path) {
    LoadResult result {};

    std::ifstream input(path);
    if (!input.is_open()) {
        result.ok = false;
        result.error = "failed to open config file";
        return result;
    }

    std::string section {};
    std::string line {};
    std::uint64_t line_number = 0;
    while (std::getline(input, line)) {
        ++line_number;
        const auto text = trim(remove_comment(line));
        if (text.empty()) {
            continue;
        }

        if (text.front() == '[') {
            if (text.back() != ']') {
                result.ok = false;
                result.error = make_error(line_number, "invalid section header");
                return result;
            }

            const auto section_name = trim(text.substr(1U, text.size() - 2U));
            if (section_name != "general" && section_name != "tls" &&
                section_name != "quic" && section_name != "reinflate") {
                result.ok = false;
                result.error = make_error(line_number, "unknown config section: " + std::string(section_name));
                return result;
            }

            section = std::string(section_name);
            continue;
        }

        const auto equals = text.find('=');
        if (equals == std::string_view::npos) {
            result.ok = false;
            result.error = make_error(line_number, "expected key = value");
            return result;
        }

        const auto key = trim(text.substr(0U, equals));
        const auto value = trim(text.substr(equals + 1U));
        if (key.empty() || value.empty()) {
            result.ok = false;
            result.error = make_error(line_number, "expected non-empty key and value");
            return result;
        }

        std::string assign_error {};
        if (!assign_value(result.config, section, key, value, assign_error)) {
            result.ok = false;
            result.error = make_error(line_number, assign_error);
            return result;
        }
    }

    if (input.bad()) {
        result.ok = false;
        result.error = "failed while reading config file";
        return result;
    }

    return result;
}

std::string_view to_string(const TlsAppDataContinuationPolicy policy) noexcept {
    switch (policy) {
    case TlsAppDataContinuationPolicy::final_only:
        return "final_only";
    case TlsAppDataContinuationPolicy::stream:
        return "stream";
    case TlsAppDataContinuationPolicy::bulk:
        return "bulk";
    }

    return "unknown";
}

}  // namespace pc::config
