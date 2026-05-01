# RFC 0001: PcapConstrictor Design

Status: Draft  
Project: PcapConstrictor  
Binary: `pcap-constrictor`  
Scope: Offline CLI tool, cross-platform, C++20

## 1. Summary

PcapConstrictor is an offline command-line tool that reads packet capture files and writes reduced packet capture files.

The core idea is to preserve packet metadata and protocol-visible information while truncating encrypted payload bytes that are usually not useful for traffic and flow analysis.

The output should remain a normal capture file. PcapConstrictor behaves like a protocol-aware adaptive snaplen tool, not like a packet rewriter.

The first supported input/output format is classic libpcap. PCAPNG support is planned later.

## 2. Goals

- Reduce storage size of packet captures.
- Preserve packet count.
- Preserve packet timestamps.
- Preserve original packet lengths.
- Preserve packet ordering.
- Preserve L2/L3/L4 headers as captured.
- Preserve non-target traffic unchanged.
- Preserve TLS and QUIC handshake-visible metadata when possible.
- Truncate encrypted TLS and QUIC payloads only when the tool is confident it is safe according to the configured policy.
- Provide a reinflate mode that pads truncated packets back to their original captured size using synthetic bytes.
- Keep the project CLI-only and cross-platform.
- Reuse small, self-contained parts of PcapFlowLab where useful.

## 3. Non-goals

- No TLS decryption.
- No QUIC decryption.
- No secret extraction.
- No credential, cookie, token, or key extraction.
- No unauthorized packet capture.
- No traffic replay guarantee.
- No packet injection.
- No evasion functionality.
- No IP/MAC anonymization in the first version.
- No checksum recomputation in constrict mode.
- No modification of IP/TCP/UDP length fields in constrict mode.
- No eBPF or live capture in the first version.
- No PCAPNG support in the first version, unless it is added after classic PCAP support is stable.

## 4. Core capture invariant

Each input packet record produces exactly one output packet record.

PcapConstrictor must never:

- drop a packet record;
- duplicate a packet record;
- merge packet records;
- split one packet record into multiple records;
- reorder packet records;
- synthesize new packet records in constrict mode.

## 5. Core truncation invariant

For every packet record, PcapConstrictor may perform at most one truncation operation.

The truncation operation must be suffix-only.

Allowed:

```text
input bytes:  [0 ................................ old_caplen)
output bytes: [0 ........ new_caplen)
dropped:                     [new_caplen ........ old_caplen)
```

Forbidden:

- removing bytes from the middle of a packet;
- keeping multiple byte ranges from one packet;
- removing one TLS/QUIC record while preserving later bytes from the same captured packet;
- modifying packet bytes before `new_caplen` in constrict mode.

This means the tool can only reduce `captured length`. It must preserve `original length`.

## 6. PCAP length model

Classic PCAP packet records contain:

- captured packet length: number of bytes stored in the capture file;
- original packet length: packet length on the wire before capture truncation.

Constrict mode reduces captured packet length but preserves original packet length.

Example:

```text
Before constriction:
  caplen   = 1514
  orig_len = 1514

After constriction:
  caplen   = 128
  orig_len = 1514
```

The output is intentionally a truncated capture.

## 7. Application modes

### 7.1 Constrict mode

Command shape:

```bash
pcap-constrictor constrict input.pcap -o output.pcap
```

Behavior:

- read input sequentially;
- analyze each packet independently plus limited per-flow state;
- optionally reduce captured length using suffix-only truncation;
- preserve original packet length;
- preserve timestamp;
- preserve packet order;
- write output sequentially;
- do not load the whole file into memory.

### 7.2 Reinflate mode

Command shape:

```bash
pcap-constrictor reinflate input.pcap -o output.pcap
```

Alias:

```bash
pcap-constrictor restore input.pcap -o output.pcap
```

Behavior:

```text
if caplen < orig_len:
    append fill_byte until caplen == orig_len
    set caplen = orig_len

if checksum_policy == preserve:
    keep checksum fields unchanged

if checksum_policy == recompute:
    attempt checksum recomputation for every supported complete packet in the output capture
```

Default fill byte:

```text
0xAB
```

Important: reinflate does not recover original bytes. It only pads missing captured bytes with synthetic filler bytes.

Checksum policies:

```ini
[reinflate]
checksum_policy = preserve
```

- default;
- pads missing captured bytes when needed;
- never changes checksum fields;
- preserves original checksum fields, including checksum-offload partial checksums.

```ini
[reinflate]
checksum_policy = recompute
```

- pads missing captured bytes when needed;
- then recomputes checksums for all supported complete IPv4/IPv6 TCP/UDP packets in the output capture;
- may modify checksum fields even for packets that were not padded;
- can replace checksum-offload partial checksums with normal full checksums;
- skips unsupported, malformed, fragmented, incomplete, or inconsistent packets and reports skipped recomputations in stats.

## 8. General safety policy

Default behavior must be conservative.

If the tool is uncertain, it must keep the packet full.

Keep full when:

- packet is malformed;
- packet is already truncated in a way that prevents safe parsing;
- L2/L3/L4 parsing fails;
- TCP sequence state is missing or inconsistent for TLS stateful processing;
- TLS record parsing is uncertain;
- QUIC header parsing is uncertain;
- QUIC short-header DCID validation fails;
- protocol is unknown;
- configured minimum saved bytes would not be reached.

## 9. Configuration model

Configuration sources, from lowest to highest priority:

```text
defaults < config file < command-line options
```

Initial config shape:

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

Notes:

- `tls.app_data_keep_record_bytes` includes the 5-byte TLS record header.
- `tls.app_data_keep_record_bytes` must be at least 5.
- `quic.short_header_keep_packet_bytes` is counted from the beginning of the QUIC packet inside the UDP payload.
- `min_saved_bytes_per_packet` prevents tiny truncations that do not materially reduce file size.
- `reinflate.checksum_policy` accepts only `preserve` or `recompute`.

## 10. Packet decoding requirements

The packet decoder should expose offsets, not owned protocol objects where possible.

Required offsets:

- link-layer header start/end;
- network-layer header start/end;
- transport-layer header start/end;
- transport payload start;
- transport payload size.

Initially supported link/network/transport layers:

- Ethernet II;
- optional VLAN tags;
- IPv4;
- IPv6;
- TCP;
- UDP.

Later support may include:

- Linux cooked capture SLL/SLL2;
- additional link types already supported by PcapFlowLab;
- IPv6 extension header improvements;
- fragmented packet handling improvements.

All binary parsing must avoid undefined behavior.

Requirements:

- no unaligned `reinterpret_cast` over byte buffers;
- use explicit endian helpers;
- bounds-check every read;
- return conservative parse failure when data is incomplete.

## 11. TLS constriction policy

### 11.1 TLS scope

TLS support applies to TLS records carried over TCP.

The tool does not decrypt TLS.

The main target for truncation is TLS Application Data records.

TLS record header:

```text
content_type: 1 byte
legacy_version: 2 bytes
length: 2 bytes
```

TLS Application Data content type:

```text
23 / 0x17
```

### 11.2 TLS default behavior

Default policy:

- preserve non-Application-Data TLS records fully;
- preserve TLS ClientHello fully when visible;
- preserve TLS ServerHello and other clear handshake records fully when visible;
- truncate TLS Application Data only when the suffix-only invariant can be satisfied;
- keep full when unsure.

### 11.3 TLS record keep size

For constricted TLS Application Data records:

```text
keep bytes from record start = tls.app_data_keep_record_bytes
```

Default:

```text
tls.app_data_keep_record_bytes = 8
```

This includes the 5-byte TLS record header.

Example:

```text
TLS AppData record 60 bytes
app_data_keep_record_bytes = 8

Output keeps:
  5-byte TLS record header
  3 bytes of encrypted fragment
```

### 11.4 TLS suffix-only planning

The TLS analyzer must not think in terms of deleting arbitrary TLS records.

It must compute a single packet-level `new_caplen`.

The analyzer may only truncate from a point after which all remaining captured bytes are allowed to be dropped.

For each TCP packet:

- bytes before the selected cut point are preserved exactly;
- bytes after the selected cut point are dropped;
- original packet length is unchanged.

### 11.5 TLS example: multiple records in one TCP packet

Input TCP payload:

```text
TLS AppData #1: 20 bytes
TLS AppData #2: 20 bytes
TLS AppData #3: 60 bytes
```

Config:

```text
tls.app_data_keep_record_bytes = 8
```

Expected output TCP payload:

```text
TLS AppData #1: 20 bytes, full
TLS AppData #2: 20 bytes, full
TLS AppData #3: 8 bytes, constricted
```

Total output TCP payload size:

```text
20 + 20 + 8 = 48 bytes
```

Only one suffix cut is performed.

### 11.6 TLS example: record crossing TCP packet boundary

Input:

```text
Packet #1 TCP payload 100 bytes:
  TLS AppData #1: 40 bytes
  TLS AppData #2 first part: 60 bytes

Packet #2 TCP payload 100 bytes:
  TLS AppData #2 continuation: 20 bytes
  TLS AppData #3: 80 bytes
```

TLS AppData #2 total length:

```text
60 + 20 = 80 bytes
```

Config:

```text
tls.app_data_keep_record_bytes = 8
```

Expected output:

```text
Packet #1 TCP payload:
  TLS AppData #1: 40 bytes, full
  TLS AppData #2: 8 bytes, constricted

Total Packet #1 output payload = 48 bytes

Packet #2 TCP payload:
  TLS AppData #2 continuation: 20 bytes, preserved
  TLS AppData #3: 8 bytes, constricted

Total Packet #2 output payload = 28 bytes
```

Rationale for Packet #2:

The first 20 bytes are continuation bytes from the previous TLS record. They must be preserved in order to reach the next TLS record boundary and preserve the prefix of TLS AppData #3. Since only suffix truncation is allowed, these continuation bytes cannot be removed while preserving the later TLS record prefix.

### 11.7 TLS TCP state

TLS over TCP requires per-direction state.

Required state:

- TCP flow key;
- direction key;
- expected TCP sequence number for in-order processing;
- active TLS record crossing packet boundary, if any;
- remaining bytes in active TLS record;
- whether the active record is constrictible;
- record start context needed to compute keep bytes.

Default conservative behavior:

- out-of-order packet: keep full;
- retransmission: keep full, unless later explicitly supported;
- mid-flow start without TLS synchronization: keep full;
- malformed TLS length: keep full;
- incomplete TLS header: keep full.

## 12. QUIC constriction policy

### 12.1 QUIC scope

QUIC support applies to UDP packets.

The tool does not decrypt QUIC.

The first QUIC implementation targets QUIC v1-style Initial detection and short-header 1-RTT truncation.

### 12.2 QUIC connection model

QUIC is connection-oriented, not just flow-oriented.

PcapConstrictor should model a QUIC connection as two UDP 5-tuples:

```text
client -> server UDP flow
server -> client UDP flow
```

A `QuicConnection` is created when a valid QUIC Initial long-header packet is observed.

The direct 5-tuple and reverse 5-tuple are mapped to the same `QuicConnection`.

### 12.3 QUIC flow key

UDP flow key:

```text
src_ip
src_port
dst_ip
dst_port
protocol = UDP
```

Reverse key:

```text
dst_ip
dst_port
src_ip
src_port
protocol = UDP
```

### 12.4 QUIC Initial detection

A UDP datagram is considered a QUIC Initial candidate when:

- UDP payload is long enough for long-header parsing;
- first byte indicates QUIC long header;
- version is non-zero;
- long-header packet type is Initial;
- DCID length and SCID length can be parsed safely;
- packet is syntactically valid enough for conservative connection tracking.

When a client Initial is observed:

- keep the packet full;
- create or update `QuicConnection`;
- store original DCID;
- store client SCID;
- map direct and reverse UDP 5-tuples to the connection.

When a server Initial is observed:

- keep the packet full;
- update the existing `QuicConnection` if found;
- store server SCID;
- update expected DCIDs by direction.

### 12.5 QUIC connection IDs

Long-header packets contain both DCID and SCID.

Short-header packets contain DCID but do not encode DCID length in the packet itself.

Therefore, short-header truncation should use connection state.

Expected behavior:

```text
client Initial:
  DCID = original destination connection ID
  SCID = client-chosen connection ID

server Initial:
  DCID = client-chosen connection ID
  SCID = server-chosen connection ID

later client -> server short header:
  expected DCID = server-chosen connection ID

later server -> client short header:
  expected DCID = client-chosen connection ID
```

### 12.6 QUIC short-header truncation

A UDP packet may be truncated as QUIC short-header traffic only if:

- the UDP 5-tuple is known to belong to a `QuicConnection`;
- UDP payload starts with a short-header-compatible first byte;
- if expected DCID is known and non-empty, the DCID in the packet matches one of the expected DCIDs for this direction;
- if expected DCID is unknown, default behavior is keep full;
- if expected DCID length is zero, 5-tuple match is sufficient.

Default short-header keep size:

```text
quic.short_header_keep_packet_bytes = 32
```

Actual keep size should be at least enough to preserve first byte plus expected DCID:

```text
keep_quic_bytes = max(
    quic.short_header_keep_packet_bytes,
    1 + expected_dcid_length
)
```

Packet-level caplen:

```text
new_caplen = udp_payload_offset + min(udp_payload_length, keep_quic_bytes)
```

Apply truncation only if:

```text
old_caplen - new_caplen >= general.min_saved_bytes_per_packet
```

### 12.7 QUIC long-header packets

First version behavior:

- keep QUIC Initial full;
- keep QUIC Retry full;
- keep QUIC Version Negotiation full;
- keep QUIC Handshake full;
- keep QUIC 0-RTT full;
- keep unknown long-header packets full.

Rationale:

- Initial packets contain important handshake metadata.
- Long-header packets can be coalesced in one UDP datagram.
- Keeping long-header packets full is more conservative for the first implementation.
- Short-header packets are the main target for QUIC encrypted bulk truncation.

### 12.8 QUIC coalesced packets

A UDP datagram may contain multiple QUIC packets.

First version behavior:

- parse enough to identify Initial and other long-header packets when possible;
- keep all long-header packets full;
- if a short-header packet appears as the final packet in the UDP datagram and connection state allows truncation, truncate the suffix from inside that short-header packet;
- otherwise keep full.

Because only one suffix cut is allowed, the tool must not remove an earlier protected QUIC packet while preserving later data in the same UDP datagram.

### 12.9 QUIC migration

Connection migration is out of scope for the first version.

The first version tracks QUIC connections by observed direct and reverse UDP 5-tuples.

Future versions may add connection-ID based lookup across changed 5-tuples, but NEW_CONNECTION_ID frames are generally protected and may not be visible without decryption.

## 13. Truncation decision model

Protocol analyzers should return a packet-level decision, not mutate packet bytes directly.

Suggested structure:

```cpp
struct PacketTruncationDecision {
    bool truncate = false;
    std::size_t new_caplen = 0;
    std::string reason;
};
```

Decision requirements:

- `new_caplen <= old_caplen`;
- `new_caplen >= minimum valid header prefix for the packet`;
- `old_caplen - new_caplen >= min_saved_bytes_per_packet`, unless forced by explicit option;
- if no safe decision exists, return `truncate = false`.

Example reason codes:

```text
tls.app_data.last_record
tls.app_data.continuation
quic.short_header.dcid_match
keep.unknown_protocol
keep.tls_uncertain
keep.quic_dcid_mismatch
keep.already_truncated
```

## 14. Statistics

The tool should support `--stats`.

Suggested counters:

```text
packets_total
packets_written
packets_truncated
packets_kept_full
bytes_read_caplen
bytes_read_origlen
bytes_written_caplen
bytes_written_origlen
bytes_saved_caplen
tls_packets_truncated
quic_packets_truncated
kept_unknown_protocol
kept_uncertain
kept_already_truncated
malformed_packets
```

Optional later:

```text
reason_code histogram
per-protocol byte savings
per-flow byte savings
```

## 15. Dry-run mode

Optional but useful:

```bash
pcap-constrictor constrict input.pcap --dry-run --stats
```

Behavior:

- analyze packets;
- compute decisions and statistics;
- do not write output file.

## 16. PcapFlowLab reuse strategy

PcapConstrictor should be a separate repository/project.

For the first version, do not extract a shared library from PcapFlowLab.

Instead:

- inspect the local PcapFlowLab repository;
- identify small reusable components;
- copy or adapt only minimal self-contained code;
- preserve license notices where code is copied or substantially adapted;
- keep PcapConstrictor CLI-only and small.

Potentially reusable PcapFlowLab areas:

- classic PCAP reader;
- PCAPNG reader, later;
- classic PCAP writer/exporter;
- endian helpers;
- safe binary parsing helpers;
- packet decode code for Ethernet/VLAN/IPv4/IPv6/TCP/UDP;
- UDP/TCP flow key logic;
- TLS record parsing logic;
- QUIC Initial/long-header parsing logic;
- conservative fallback patterns.

Do not import:

- Qt UI;
- charts;
- session layer;
- index persistence;
- large application-level flow analysis UI code;
- unrelated desktop features.

## 17. Initial implementation phases

### Phase 0: Documentation

- RFC 0001 design spec.
- TLS/QUIC scenario document.
- Config draft.

### Phase 1: Codebase foundation

- Codex inspects PcapFlowLab and writes a reuse plan.
- Create new CLI-only C++20 project.
- Copy/adapt minimal pcap reader/writer/helpers.
- Implement classic pcap passthrough.
- Implement stats.

### Phase 2: Reinflate mode

- Implement `reinflate` command.
- Add `restore` alias.
- Fill missing bytes with `0xAB` by default.
- Add tests.

### Phase 3: Config

- Add default config model.
- Add config file parsing.
- Add CLI overrides.

### Phase 4: Packet parsing

- Ethernet/VLAN/IPv4/IPv6/TCP/UDP.
- Expose offsets and transport payload views.
- Add malformed packet tests.

### Phase 5: TLS constriction

- TLS record parsing.
- One suffix cut only.
- TCP direction state.
- Application Data truncation.
- Tests based on scenario document.

### Phase 6: QUIC constriction

- Initial detection.
- QuicConnection table.
- DCID/SCID tracking.
- Short-header truncation.
- Tests based on scenario document.

### Phase 7: Polish

- README.
- Examples.
- Benchmarks.
- Compatibility notes.
- More stats.

## 18. Compatibility notes

Constricted output captures are intentionally truncated.

Some tools may display warnings such as packet bytes missing from capture. This is expected.

Reinflate mode can make `caplen == orig_len` again, but the padded bytes are synthetic and not the original encrypted bytes.

In constrict mode, checksums are preserved as originally captured.

In reinflate mode with `checksum_policy = preserve`, synthetic padding may leave existing checksum fields inconsistent with the padded payload. This is expected.

In reinflate mode with `checksum_policy = recompute`, the tool attempts to replace those fields with normal full checksums for all supported complete IPv4/IPv6 TCP/UDP packets in the output capture.
