#include "pcap/CaptureFormat.hpp"

#include <array>
#include <cstdint>
#include <fstream>
#include <span>

#include "bytes/Endian.hpp"
#include "pcap/ClassicPcapFormat.hpp"
#include "pcap/PcapNgFormat.hpp"

namespace pc::pcap {

DetectCaptureFormatResult detect_capture_format(const std::filesystem::path& path) {
    DetectCaptureFormatResult result {};

    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        result.error = "failed to open input file";
        return result;
    }

    std::array<std::uint8_t, 4> bytes {};
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (input.gcount() != static_cast<std::streamsize>(bytes.size())) {
        result.error = "input file is too small to detect capture format";
        return result;
    }

    if (bytes == kPcapNgSectionHeaderBlockTypeBytes) {
        result.format = CaptureFormat::pcapng;
        result.ok = true;
        return result;
    }

    auto magic = std::span<const std::uint8_t, 4>(bytes.data(), 4U);
    pc::bytes::Endianness endianness {pc::bytes::Endianness::little};
    TimePrecision precision {TimePrecision::microsecond};
    if (detect_magic(magic, endianness, precision)) {
        static_cast<void>(endianness);
        static_cast<void>(precision);
        result.format = CaptureFormat::classic_pcap;
        result.ok = true;
        return result;
    }

    result.error = "unsupported input capture format";
    return result;
}

}  // namespace pc::pcap
