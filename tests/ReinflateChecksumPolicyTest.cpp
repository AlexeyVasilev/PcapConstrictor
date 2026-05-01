#include "TestHelpers.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "bytes/Endian.hpp"
#include "pcap/ClassicPcapFormat.hpp"
#include "pcap/ClassicPcapWriter.hpp"
#include "pcap/LinkType.hpp"

using namespace pc::test;

namespace {

constexpr std::size_t kIpv4HeaderOffset = 14U;
constexpr std::size_t kIpv4ChecksumOffset = kIpv4HeaderOffset + 10U;
constexpr std::size_t kUdpHeaderOffset = kIpv4HeaderOffset + 20U;
constexpr std::size_t kUdpChecksumOffset = kUdpHeaderOffset + 6U;

[[nodiscard]] std::filesystem::path test_output_dir() {
    const std::filesystem::path binary_dir {PCAP_CONSTRICTOR_BINARY_DIR};
    const auto path = binary_dir / "test-output" / "reinflate-checksum";
    std::filesystem::create_directories(path);
    return path;
}

[[nodiscard]] std::uint16_t read_be16(const std::vector<std::uint8_t>& bytes, const std::size_t offset) {
    return pc::bytes::read_be16(std::span<const std::uint8_t, 2>(bytes.data() + offset, 2U));
}

void write_be16(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint16_t value) {
    pc::bytes::write_u16(
        std::span<std::uint8_t, 2>(bytes.data() + offset, 2U),
        value,
        pc::bytes::Endianness::big
    );
}

void add_bytes(std::uint32_t& sum, const std::uint8_t* bytes, const std::size_t size) {
    std::size_t offset = 0;
    while (offset + 1U < size) {
        sum += static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
            static_cast<std::uint16_t>(bytes[offset + 1U])
        );
        offset += 2U;
    }

    if (offset < size) {
        sum += static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) << 8U);
    }
}

[[nodiscard]] std::uint16_t finalize_checksum(std::uint32_t sum) {
    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16U);
    }

    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

[[nodiscard]] std::uint16_t compute_ipv4_header_checksum(std::vector<std::uint8_t> bytes) {
    bytes[kIpv4ChecksumOffset] = 0U;
    bytes[kIpv4ChecksumOffset + 1U] = 0U;

    std::uint32_t sum = 0;
    add_bytes(sum, bytes.data() + kIpv4HeaderOffset, 20U);
    return finalize_checksum(sum);
}

[[nodiscard]] std::uint16_t compute_udp_checksum(std::vector<std::uint8_t> bytes) {
    bytes[kUdpChecksumOffset] = 0U;
    bytes[kUdpChecksumOffset + 1U] = 0U;

    std::uint32_t sum = 0;
    add_bytes(sum, bytes.data() + kIpv4HeaderOffset + 12U, 8U);
    sum += 17U;
    sum += 12U;
    add_bytes(sum, bytes.data() + kUdpHeaderOffset, 12U);

    const auto checksum = finalize_checksum(sum);
    return checksum == 0U ? 0xFFFFU : checksum;
}

[[nodiscard]] std::vector<std::uint8_t> make_ipv4_udp_packet_bytes() {
    return {
        0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU, 0x08U, 0x00U,
        0x45U, 0x00U, 0x00U, 0x20U, 0x12U, 0x34U, 0x00U, 0x00U, 0x40U, 0x11U, 0x99U, 0x99U, 0xC0U, 0xA8U,
        0x01U, 0x01U, 0xC0U, 0xA8U, 0x01U, 0x02U, 0x1FU, 0x90U, 0x00U, 0x35U, 0x00U, 0x0CU, 0x12U, 0x34U,
        0x41U, 0x42U, 0x43U, 0x44U,
    };
}

void write_fixture_pcap(const std::filesystem::path& path, const std::vector<std::uint8_t>& packet_bytes) {
    pc::pcap::ClassicPcapWriter writer {};
    const pc::pcap::ClassicPcapGlobalHeader header {
        .magic_bytes = {0xd4U, 0xc3U, 0xb2U, 0xa1U},
        .endianness = pc::bytes::Endianness::little,
        .time_precision = pc::pcap::TimePrecision::microsecond,
        .version_major = 2U,
        .version_minor = 4U,
        .thiszone_bits = 0U,
        .sigfigs = 0U,
        .snaplen = 65535U,
        .link_type = pc::pcap::kLinkTypeEthernet,
    };
    require(writer.open(path, header), "failed to open fixture pcap for writing");

    pc::pcap::PacketRecord packet {};
    packet.packet_index = 0U;
    packet.ts_sec = 123U;
    packet.ts_fraction = 456U;
    packet.captured_length = static_cast<std::uint32_t>(packet_bytes.size());
    packet.original_length = static_cast<std::uint32_t>(packet_bytes.size());
    packet.bytes = packet_bytes;

    require(writer.write_packet(packet), "failed to write fixture packet");
    writer.close();
    require(!writer.has_error(), "failed to close fixture pcap");
}

void write_config_file(const std::filesystem::path& path, const std::string& checksum_policy) {
    std::ofstream out(path, std::ios::binary);
    require(out.is_open(), "failed to create reinflate config file");
    out << "[reinflate]\n"
        << "checksum_policy = " << checksum_policy << '\n';
    out.close();
    require(out.good(), "failed to write reinflate config file");
}

[[nodiscard]] TestContext make_context(
    const std::filesystem::path& fixture,
    const std::filesystem::path& output,
    const std::filesystem::path& config
) {
    return {
        .executable = std::filesystem::path {PCAP_CONSTRICTOR_EXE_PATH},
        .fixture = fixture,
        .output = output,
        .config = config,
    };
}

}  // namespace

void run_reinflate_checksum_policy_test() {
    const auto dir = test_output_dir();
    const auto fixture = dir / "checksum_input.pcap";
    const auto preserve_output = dir / "checksum_preserve.out.pcap";
    const auto recompute_output = dir / "checksum_recompute.out.pcap";
    const auto preserve_config = dir / "preserve.ini";
    const auto recompute_config = dir / "recompute.ini";

    const auto input_bytes = make_ipv4_udp_packet_bytes();
    write_fixture_pcap(fixture, input_bytes);
    write_config_file(preserve_config, "preserve");
    write_config_file(recompute_config, "recompute");

    {
        const auto context = make_context(fixture, preserve_output, preserve_config);
        const int exit_code = run_reinflate_command(context);
        if (exit_code == -1) {
            throw std::runtime_error(std::string("failed to spawn preserve reinflate command: ") + std::strerror(errno));
        }
        require(exit_code == 0, "preserve reinflate command failed");
    }

    {
        const auto context = make_context(fixture, recompute_output, recompute_config);
        const int exit_code = run_reinflate_command(context);
        if (exit_code == -1) {
            throw std::runtime_error(std::string("failed to spawn recompute reinflate command: ") + std::strerror(errno));
        }
        require(exit_code == 0, "recompute reinflate command failed");
    }

    const auto input_packets = read_packets(fixture);
    const auto preserve_packets = read_packets(preserve_output);
    const auto recompute_packets = read_packets(recompute_output);

    require(input_packets.size() == 1U, "expected one input packet");
    require(preserve_packets.size() == 1U, "expected one preserve output packet");
    require(recompute_packets.size() == 1U, "expected one recompute output packet");

    const auto& input_packet = input_packets.front();
    const auto& preserve_packet = preserve_packets.front();
    const auto& recompute_packet = recompute_packets.front();

    require(preserve_packet.ts_sec == input_packet.ts_sec && preserve_packet.ts_fraction == input_packet.ts_fraction, "preserve timestamp changed");
    require(recompute_packet.ts_sec == input_packet.ts_sec && recompute_packet.ts_fraction == input_packet.ts_fraction, "recompute timestamp changed");
    require(preserve_packet.original_length == input_packet.original_length, "preserve orig_len changed");
    require(recompute_packet.original_length == input_packet.original_length, "recompute orig_len changed");
    require(preserve_packet.captured_length == input_packet.captured_length, "preserve caplen changed");
    require(recompute_packet.captured_length == input_packet.captured_length, "recompute caplen changed");

    require(preserve_packet.bytes == input_packet.bytes, "preserve should keep checksum fields unchanged");

    const auto expected_ipv4_checksum = compute_ipv4_header_checksum(input_packet.bytes);
    const auto expected_udp_checksum = compute_udp_checksum(input_packet.bytes);
    require(
        read_be16(recompute_packet.bytes, kIpv4ChecksumOffset) == expected_ipv4_checksum,
        "recompute should update IPv4 header checksum on complete non-padded packet"
    );
    require(
        read_be16(recompute_packet.bytes, kUdpChecksumOffset) == expected_udp_checksum,
        "recompute should update UDP checksum on complete non-padded packet"
    );
    require(
        read_be16(recompute_packet.bytes, kIpv4ChecksumOffset) != read_be16(input_packet.bytes, kIpv4ChecksumOffset),
        "recompute should change intentionally wrong IPv4 checksum"
    );
    require(
        read_be16(recompute_packet.bytes, kUdpChecksumOffset) != read_be16(input_packet.bytes, kUdpChecksumOffset),
        "recompute should change intentionally wrong UDP checksum"
    );

    auto normalized_input = input_packet.bytes;
    auto normalized_recompute = recompute_packet.bytes;
    write_be16(normalized_input, kIpv4ChecksumOffset, 0U);
    write_be16(normalized_input, kUdpChecksumOffset, 0U);
    write_be16(normalized_recompute, kIpv4ChecksumOffset, 0U);
    write_be16(normalized_recompute, kUdpChecksumOffset, 0U);
    require(normalized_recompute == normalized_input, "recompute should only change checksum fields for complete non-padded packet");
}
