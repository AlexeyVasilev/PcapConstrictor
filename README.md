# PcapConstrictor

PcapConstrictor is a C++20 command-line tool for reducing packet capture files while preserving packet metadata and protocol-visible information.

The current implementation supports classic PCAP constrict and reinflate workflows. `constrict` reads a classic PCAP sequentially and either keeps packets full or reduces only the PCAP captured length when a safe suffix-only truncation decision exists.

Future phases are planned to broaden packet parsing and capture format support. PcapConstrictor does not decrypt TLS or QUIC, does not extract secrets, and does not capture unauthorized traffic.

Classic PCAP stores both a captured length and an original length for each packet. That length model is what will later allow PcapConstrictor to perform conservative suffix-only truncation: the captured length can shrink while the original wire length is preserved.

## Usage

```sh
pcap-constrictor constrict input.pcap -o output.pcap --config config.ini --stats
pcap-constrictor reinflate input.pcap -o output.pcap --config config.ini --stats
pcap-constrictor restore input.pcap -o output.pcap --config config.ini --stats
```

Current `--stats` output includes packet and byte totals, time precision, endianness, link type, snaplen, protocol counters, and checksum recomputation counters.

In `constrict` mode, packets that are already truncated on input are kept unchanged. This avoids losing information because classic PCAP stores only the current captured length and original length, not any previous captured length. Constrict mode never recomputes checksums, never modifies IP/TCP/UDP length fields, and only reduces PCAP captured length when a safe suffix-only truncation decision exists.

`reinflate` and its alias `restore` pad packets whose captured length is smaller than their original length. Missing captured bytes are filled with the configured reinflate fill byte, which defaults to `0xAB`. The packet record captured length is set to the original length, and the original length is left unchanged. This does not recover original encrypted bytes.

`checksum_policy = preserve` is the default. It pads missing captured bytes when needed and never changes checksum fields, including checksum-offload partial checksums that were present in the input capture.

`checksum_policy = recompute` pads missing captured bytes when needed and then attempts to recompute checksums for every supported complete IPv4/IPv6 TCP/UDP packet in the reinflate output. This applies even to packets that did not need padding. It recomputes the IPv4 header checksum where applicable and recomputes TCP/UDP checksums where supported. Unsupported, malformed, fragmented, incomplete, or inconsistent packets keep their existing checksum fields and are reported in stats.

PcapConstrictor now has internal packet decoding for Ethernet, VLAN, IPv4, IPv6, TCP, and UDP offsets. This is plumbing for suffix-only TLS constriction and future QUIC constriction.

TLS Application Data constriction is implemented for conservative in-order TCP streams. Packets that are uncertain, out of order, retransmitted, malformed, or already truncated on input are kept full.

QUIC short-header constriction is implemented conservatively for known UDP 5-tuples with matching Destination Connection IDs. QUIC long-header packets are kept full, and QUIC is never decrypted.

## Configuration

Defaults are used when `--config` is omitted. A config file can override the currently supported keys with a simple INI-like format:

```ini
[general]
min_saved_bytes_per_packet = 16

[tls]
app_data_keep_record_bytes = 8
app_data_continuation_keep_bytes = 8

[quic]
short_header_keep_packet_bytes = 32
require_dcid_match = true
allow_short_header_without_known_dcid = false

[reinflate]
fill_byte = 0xAB
checksum_policy = preserve
```

Supported checksum policy values:

```ini
[reinflate]
checksum_policy = preserve
```

```ini
[reinflate]
checksum_policy = recompute
```

## Current Scope

Supported now:

- classic PCAP passthrough
- classic PCAP reinflate / restore with configurable filler byte and preserve/recompute checksum policy
- internal Ethernet/VLAN/IPv4/IPv6/TCP/UDP offset decoding
- conservative TLS Application Data constriction for in-order TCP streams
- conservative QUIC short-header constriction for known UDP flows and matching DCIDs
- little-endian and big-endian PCAP
- microsecond and nanosecond timestamp precision
- sequential processing without loading the whole capture into memory

Not implemented yet:

- PCAPNG
- live capture or eBPF

## Tests

The project includes one standalone C++ test executable named `pcap-constrictor-tests`, wired into CTest. It runs small config/unit-style checks, packet-layout fixture tests, and golden end-to-end PCAP workflow tests.

Fixture captures live under `tests/fixtures/`. Golden workflow fixtures live under `tests/fixtures/golden/`. Each golden scenario contains `input.pcap`, `constricted.pcap`, `reinflated_preserve_checksum.pcap`, `reinflated_recompute_checksum.pcap`, `constrict.ini`, `reinflate_preserve.ini`, and `reinflate_recompute.ini`. The golden tests generate actual outputs under the build directory and compare them byte-for-byte against those committed expected outputs.

```sh
cmake --build build
ctest --test-dir build --output-on-failure
```

You can also run the standalone test binary directly:

```sh
.\build\pcap-constrictor-tests.exe
```
