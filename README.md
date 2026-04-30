# PcapConstrictor

PcapConstrictor is a C++20 command-line tool for reducing packet capture files while preserving packet metadata and protocol-visible information.

The current implementation is intentionally small: it supports classic PCAP passthrough and reinflate mode. The `constrict` command reads a classic PCAP file sequentially and writes a classic PCAP file sequentially without changing packet bytes or packet record metadata.

Future phases are planned to broaden packet parsing and capture format support. PcapConstrictor does not decrypt TLS or QUIC, does not extract secrets, and does not capture unauthorized traffic.

Classic PCAP stores both a captured length and an original length for each packet. That length model is what will later allow PcapConstrictor to perform conservative suffix-only truncation: the captured length can shrink while the original wire length is preserved.

## Usage

```sh
pcap-constrictor constrict input.pcap -o output.pcap --config config.ini --stats
pcap-constrictor reinflate input.pcap -o output.pcap --config config.ini --stats
pcap-constrictor restore input.pcap -o output.pcap --config config.ini --stats
```

Current `--stats` output includes packet and byte totals, time precision, endianness, link type, and snaplen.

In `constrict` mode, packets that are already truncated on input are kept unchanged. This avoids losing information because classic PCAP stores only the current captured length and original length, not any previous captured length.

`reinflate` and its alias `restore` pad packets whose captured length is smaller than their original length. Missing captured bytes are filled with the configured reinflate fill byte, which defaults to `0xAB`. The packet record captured length is set to the original length, and the original length is left unchanged. This does not recover original encrypted bytes, recompute checksums, or modify protocol headers.

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
```

## Current Scope

Supported now:

- classic PCAP passthrough
- classic PCAP reinflate / restore with configurable filler byte
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

The project includes a C++ test executable named `pcap-constrictor-tests`, wired into CTest for fixture-driven checks. The TLS and QUIC scenario fixtures live under `tests/fixtures/`.

```sh
cmake --build build
ctest --test-dir build --output-on-failure
```

You can also run the standalone test binary directly:

```sh
.\build\pcap-constrictor-tests.exe
```
