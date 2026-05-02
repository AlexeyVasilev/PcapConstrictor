# PcapConstrictor

[![CI](https://github.com/AlexeyVasilev/PcapConstrictor/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexeyVasilev/PcapConstrictor/actions/workflows/ci.yml)

PcapConstrictor is a C++20 command-line tool for reducing PCAP and PCAPNG
captures in a protocol-aware way. It preserves packet metadata and
flow-analysis value, and removes encrypted payload bulk only when a safe
suffix-only truncation decision exists.

## Why

Encrypted payload bytes often dominate capture size in modern traffic.
Without keys, those bytes are usually not useful for offline analysis.

Packet timing, packet sizes, 5-tuples, TLS handshakes, QUIC Initial packets,
and original packet lengths still carry useful information.
PcapConstrictor behaves like a protocol-aware adaptive snaplen tool: it tries
to keep the parts of a capture that remain useful while dropping encrypted
bulk when that can be done safely.

## Features

- classic PCAP input/output
- little-endian PCAPNG input/output for Section Header Blocks, Interface
  Description Blocks, and Enhanced Packet Blocks
- TLS Application Data constriction for conservative in-order TCP streams
- QUIC short-header constriction for known UDP flows with matching Destination
  Connection IDs
- reinflate/restore mode
- `checksum_policy = preserve` and `checksum_policy = recompute`
- INI-style config file support
- standalone C++ test runner with fixture tests and golden workflow tests

## Safety and non-goals

- no TLS or QUIC decryption
- no secret extraction
- no credential or token extraction
- no unauthorized packet capture
- no packet injection
- no traffic replay guarantee
- constrict mode does not rewrite IP/TCP/UDP length fields and does not
  recompute checksums

## Usage

```sh
pcap-constrictor constrict input.pcap -o output.pcap --config config.ini --stats
pcap-constrictor constrict input.pcapng -o output.pcapng --config config.ini --stats
pcap-constrictor reinflate input.pcap -o output.pcap --config config.ini --stats
pcap-constrictor restore input.pcapng -o output.pcapng --config config.ini --stats
```

`constrict` reduces captured length only when a safe suffix-only decision
exists. Already-truncated input packets where `caplen < orig_len` are kept
unchanged.

`reinflate` pads missing captured bytes with `fill_byte` and restores captured
length back to original length. `restore` is an alias for `reinflate`.

If input ends unexpectedly, PcapConstrictor preserves successfully processed
packets, warns about the incomplete tail, prints stats when `--stats` is
enabled, and returns a non-zero exit code.

## Configuration

Defaults are used when `--config` is omitted. The current config format is a
small INI-like file:

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

Key settings:

- `general.min_saved_bytes_per_packet`: avoids tiny truncations that do not
  materially reduce file size
- `tls.app_data_keep_record_bytes`: bytes to keep from the start of a TLS
  Application Data record, including the 5-byte TLS record header
- `tls.app_data_continuation_keep_bytes`: bytes to keep from TCP payload that
  contains only continuation bytes from an already identified TLS Application
  Data record
- `quic.short_header_keep_packet_bytes`: bytes to keep from the start of an
  eligible QUIC short-header packet
- `quic.require_dcid_match`: requires the short-header DCID to match tracked
  connection state
- `quic.allow_short_header_without_known_dcid`: allows short-header truncation
  even when the expected DCID is unknown
- `reinflate.fill_byte`: byte value used to pad missing captured bytes during
  reinflate
- `reinflate.checksum_policy`: checksum handling policy for reinflate output

Checksum policies:

- `preserve`: default behavior; pads missing captured bytes when needed and
  does not modify checksum fields, including checksum-offload partial
  checksums
- `recompute`: pads missing captured bytes when needed and then attempts to
  recompute checksums for every supported complete IPv4/IPv6 TCP/UDP packet in
  reinflate output, including packets that did not need padding

## Current scope

Supported:

- classic PCAP little-endian and big-endian input/output
- classic PCAP microsecond and nanosecond timestamp precision
- little-endian PCAPNG Section Header, Interface Description, and Enhanced
  Packet Block input/output
- Ethernet, VLAN, IPv4, IPv6, TCP, and UDP decoding
- TLS Application Data constriction
- QUIC short-header constriction
- reinflate checksum policies
- sequential processing without loading the whole capture into memory

Not implemented yet:

- big-endian PCAPNG sections
- broader PCAPNG block interpretation beyond safe copying plus SHB/IDB/EPB
- live capture or eBPF
- QUIC migration
- advanced TLS retransmission or overlap handling
- partial or truncated tail recovery

## Build

```sh
cmake -S . -B build
cmake --build build
```

Portable CMake presets are also included for Ninja-based debug and release
builds. If you need local compiler, toolchain, or generator overrides, put
them in `CMakeUserPresets.json`.

## Tests

Normal workflow:

```sh
cmake --build build
ctest --test-dir build --output-on-failure
```

Direct test binary launch on Windows:

```powershell
.\build\pcap-constrictor-tests.exe
```

Direct test binary launch on Unix-like systems:

```sh
./build/pcap-constrictor-tests
```

The standalone C++ test binary covers:

- unit-style checks
- packet-layout fixture tests
- golden end-to-end PCAP workflow tests
- PCAPNG fixture tests

## Fixtures

Committed fixtures live under `tests/fixtures`. Golden fixtures live under
`tests/fixtures/golden`.

Golden scenarios include:

- `input.pcap`
- `constricted.pcap`
- `reinflated_preserve_checksum.pcap`
- `reinflated_recompute_checksum.pcap`
- `constrict.ini`
- `reinflate_preserve.ini`
- `reinflate_recompute.ini`

Golden workflow tests generate outputs under the build directory and compare
them byte-for-byte against committed expected outputs. Expected outputs should
only be updated intentionally after manual verification.

Golden scenarios may also cover mixed captures, including combinations of
IPv4, IPv6, TLS, QUIC, ARP, and DNS traffic.

All committed captures and PCAPNG fixtures must be safe to publish.

## Limitations

- ECH can hide SNI from passive inspection
- offload-style captures may contain partial checksums or IPv4 total length `0`
- checksum recompute does not normalize offload pseudo-packets or rewrite IP
  length fields
- unsupported, malformed, fragmented, incomplete, inconsistent, or otherwise
  uncertain packets are kept full
