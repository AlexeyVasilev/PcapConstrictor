#pragma once

#include <filesystem>
#include <string>

namespace pc::pcap {

enum class CaptureFormat {
    classic_pcap,
    pcapng,
};

struct DetectCaptureFormatResult {
    CaptureFormat format {CaptureFormat::classic_pcap};
    bool ok {false};
    std::string error {};
};

[[nodiscard]] DetectCaptureFormatResult detect_capture_format(const std::filesystem::path& path);

}  // namespace pc::pcap
