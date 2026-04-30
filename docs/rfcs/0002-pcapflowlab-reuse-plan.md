# RFC 0002: PcapFlowLab Reuse Plan

Status: Draft  
Project: PcapConstrictor  
Scope: Reuse planning only, no code import yet

## 1. Summary

This plan was prepared after reading the current PcapConstrictor design documents and inspecting the local PcapFlowLab repository at:

```text
C:\My2\Projects\C++\PcapFlowLab\PcapFlowLab_1\PcapFlowLab
```

The requested PcapConstrictor source document paths under `docs/rfcs` and `docs/test-cases` do not exist yet in this repository. The currently present documents are:

```text
docs/0001_pcap_constrictor_design.md
docs/0001_tls_scenarios.md
docs/0002_quic_scenarios.md
```

The local PcapFlowLab checkout is enough for this reuse review. The GitHub repository does not need to be consulted for the first reuse plan unless the local checkout becomes suspect or stale.

PcapFlowLab contains several useful small components and patterns for PcapConstrictor:

- classic PCAP reader and writer code as a starting point;
- PCAPNG reader as a later, optional reference;
- link type constants for Ethernet, Linux SLL, and SLL2;
- safe-ish packet decode patterns for Ethernet, VLAN, IPv4, IPv6, TCP, and UDP;
- flow key and symmetric connection key types;
- QUIC long-header parsing ideas and QUIC varint helpers;
- TLS record and ClientHello parsing ideas;
- conservative fallback patterns for malformed packets, truncation, gaps, and uncertain protocol state;
- synthetic packet and capture test helper ideas.

The main reuse rule should be: copy or adapt only small self-contained pieces into a new PcapConstrictor design. Do not import PcapFlowLab as a dependency and do not extract a shared library at this stage.

Parts that should not be reused directly:

- Qt UI and QML code;
- `app/session` as an application-facing session layer;
- index and checkpoint persistence;
- selected-flow analysis, charts, UI models, and query surfaces;
- bounded stream presentation code as production truncation logic;
- QUIC Initial decryption code, because PcapConstrictor explicitly does not decrypt QUIC and should avoid OpenSSL/bcrypt dependencies in the first version.

## 2. Candidate Files And Modules

### 2.1 Licensing

| Candidate | Purpose | Dependencies | Reuse mode | Risks or cleanup needed |
| --- | --- | --- | --- | --- |
| `LICENSE` | Apache License 2.0 for PcapFlowLab. | None. | Reference for attribution and compatibility. | PcapConstrictor needs its own explicit license decision. If PcapFlowLab code is copied or substantially adapted, preserve applicable notices and license attribution. |

### 2.2 Capture IO

| Candidate | Purpose | Dependencies | Reuse mode | Risks or cleanup needed |
| --- | --- | --- | --- | --- |
| `src/core/io/LinkType.h` | Link type constants for Ethernet, Linux SLL, and SLL2. | Standard library only. | Copy or lightly adapt. | First PcapConstrictor version should probably focus on Ethernet. Keep SLL/SLL2 constants available only if support is deliberately enabled. |
| `src/core/open_failure_info.h` and `core/open_failure_info.h` | Lightweight open error context. | Standard library only. | Adapt. | There are duplicate copies in PcapFlowLab. PcapConstrictor should keep one small error type in its own namespace. |
| `src/core/io/PcapReader.h` and `src/core/io/PcapReader.cpp` | Sequential classic PCAP reader returning packet metadata and bytes. | `LinkType.h`, `OpenFailureInfo`, standard streams. | Adapt, not direct copy. | Current implementation assumes little-endian classic PCAP and reads C++ structs directly from the stream. PcapConstrictor should use explicit byte reads/endian helpers to avoid host-endian and padding assumptions. Add caplen/orig_len validation policy, preserve global header fields needed by the writer, and support streaming stats. |
| `src/core/io/PcapWriter.h` and `src/core/io/PcapWriter.cpp` | Classic PCAP writer used for export. | `PacketRef`, `LinkType.h`, standard streams. | Adapt. | Current writer emits a fixed little-endian global header with snaplen 65535 and uses `PacketRef.captured_length`. PcapConstrictor writer should preserve input link type and likely preserve input snaplen/time precision where possible. It must support `captured_length != original_length` for constrict mode. |
| `src/core/io/PcapNgReader.h` and `src/core/io/PcapNgReader.cpp` | PCAPNG Section Header, Interface Description, and Enhanced Packet reader. | `PcapReader` raw packet type, `LinkType.h`, `OpenFailureInfo`. | Reference or later adapted copy. | Clean enough to isolate, but PCAPNG is not first-version scope. It currently normalizes timestamps to sec/usec and skips unsupported link types. It should not delay the classic PCAP-first skeleton. |
| `src/core/io/IByteSource.h`, `FileByteSource.*`, `PacketDataReader.*`, `CaptureFilePacketReader.*` | Random access packet byte reads by file offset. | `PacketRef`, standard streams. | Reference only for now. | PcapConstrictor should process captures sequentially. Random access is useful for PcapFlowLab's UI and export workflows, not for first-pass constriction. |
| `src/core/index/CaptureIndex.h` and `src/core/index/CaptureIndex.cpp` | Contains `detect_capture_source_format` for classic PCAP vs PCAPNG magic. | Standard library. | Adapt only the tiny magic detection idea. | Do not bring index persistence, fingerprints, source validation, or exact-version index policies into PcapConstrictor. |

### 2.3 Byte And Packet Decoding

| Candidate | Purpose | Dependencies | Reuse mode | Risks or cleanup needed |
| --- | --- | --- | --- | --- |
| `src/core/decode/PacketDecodeSupport.h` | Big-endian reads, link-layer parsing, VLAN traversal, IPv6 extension header traversal, protocol constants. | `LinkType.h`, standard library. | Adapt heavily. | The helper functions assume callers have checked bounds before some reads. PcapConstrictor should centralize bounds-checked `read_be16`, `read_be24`, `read_be32`, and QUIC varint helpers. Preserve the conservative `std::optional` style. |
| `src/core/decode/PacketDecoder.h` and `src/core/decode/PacketDecoder.cpp` | Converts raw packet bytes into IPv4/IPv6 flow keys and packet metadata. Supports Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, fragments. | `PcapReader`, `PacketRef`, `FlowKey`, `ProtocolId`, `PacketDecodeSupport`. | Adapt, not direct copy. | PcapConstrictor needs offset-rich packet views, not owned ingestion objects. The adapted decoder should return link/network/transport payload offsets, transport payload size, TCP sequence number, TCP flags, UDP length, and parse confidence. |
| `src/core/services/PacketPayloadService.*` | Extracts TCP/UDP payload bytes from a packet. | `PacketDecodeSupport`, `LinkType.h`. | Reference only. | It copies payload bytes into a vector. PcapConstrictor should keep spans/views into the packet buffer and carry offsets for suffix-only cut planning. |
| `src/core/services/PacketDetailsService.*` and `src/core/domain/PacketDetails.*` | Packet detail decoding with TCP sequence and ACK fields. | `PacketDecodeSupport`, `PacketRef`. | Reference only. | Useful source for TCP seq/ack extraction and malformed packet behavior, but detail structs are UI-oriented and lack the exact cut-planning model needed by PcapConstrictor. |

### 2.4 Flow Keys And Connection Direction

| Candidate | Purpose | Dependencies | Reuse mode | Risks or cleanup needed |
| --- | --- | --- | --- | --- |
| `src/core/domain/ProtocolId.h` | Small protocol enum. | Standard library only. | Copy or adapt. | PcapConstrictor may need only TCP and UDP initially. Keep enum compact. |
| `src/core/domain/Direction.h` | Direction enum. | None. | Copy or adapt. | Good fit for TLS per-direction state and QUIC connection state. |
| `src/core/domain/FlowKey.h` and `src/core/domain/FlowKey.cpp` | IPv4/IPv6 5-tuple keys and hashes. | `ProtocolId.h`, standard library. | Copy or adapt. | Good candidate, but rename namespace and keep only needed fields. |
| `src/core/domain/ConnectionKey.h` and `src/core/domain/ConnectionKey.cpp` | Symmetric bidirectional connection keys and direction resolution. | `Direction.h`, `FlowKey.h`. | Adapt. | Useful for TCP TLS direction state. QUIC should still model direct and reverse UDP 5-tuples plus connection IDs, not only a symmetric key. |
| `src/core/domain/Flow.*`, `Connection.*`, `ConnectionTable.*`, `CaptureSummary.*`, `CaptureState.h` | Runtime flow aggregation model. | Flow and connection key types. | Reference only. | These store packet lists and support PcapFlowLab's flow UI. PcapConstrictor should not load whole captures or keep packet lists in memory. |

### 2.5 Import And Iteration Patterns

| Candidate | Purpose | Dependencies | Reuse mode | Risks or cleanup needed |
| --- | --- | --- | --- | --- |
| `src/core/services/CaptureImportProcessor.*`, `FastCaptureImporter.*`, `CaptureImporter.*` | Sequential packet read loop and conservative partial-open behavior. | Readers, decoder, flow hints, `CaptureState`, `OpenContext`, index format detection. | Reference only. | The packet loop is useful conceptually, but the dependency graph is too large. PcapConstrictor should have a smaller streaming pipeline: reader -> decoder/analyzers -> decision -> writer -> stats. |
| `src/core/services/PacketIngestor.*` | Adds decoded packets into flow tables and summary stats. | `CaptureState`, `ConnectionTable`. | Reference only. | Not needed for a reducer. PcapConstrictor stats should be packet/byte/reason counters, not flow-table aggregation. |
| `src/core/services/FlowExportService.*` | Reads selected packet bytes and writes classic PCAP. | Random access readers, `PcapWriter`. | Reference only. | Useful confirmation that writer round trips timestamps and bytes. Not directly useful for sequential full-capture constriction. |

### 2.6 TLS

| Candidate | Purpose | Dependencies | Reuse mode | Risks or cleanup needed |
| --- | --- | --- | --- | --- |
| `src/core/services/TlsPacketProtocolAnalyzer.*` | Packet-level TLS text analyzer for the first visible TLS record. | `PacketPayloadService`, `TlsHandshakeDetails`, `LinkType.h`. | Reference only. | It is presentation-oriented and handles only available packet payload, not TCP stream state. It can inspire record header validation and record type text, but not truncation policy. |
| `src/core/services/TlsHandshakeDetails.*` | Parses TLS ClientHello, ServerHello, Certificate details for display. | Standard library only. | Reference only, maybe later adapt tiny helpers. | Much of it is display formatting and certificate summary parsing. PcapConstrictor needs to preserve visible handshake records, not display them. Avoid dragging ASN.1/cipher text tables into the first implementation. |
| `src/core/services/FlowHintService.*` TLS helpers | Cheap TLS record detection and ClientHello SNI extraction. | `PacketPayloadService`, `QuicInitialParser`, `AnalysisSettings`. | Reference only. | Contains useful `looks_like_tls_record` and ClientHello/SNI traversal ideas, but the class mixes many protocols and depends on analysis settings and QUIC SNI support. |
| `src/app/session/SessionTlsPresentation.*` | TLS stream item construction and bounded reassembly presentation. | `CaptureSession`, reassembly, formatting/session code. | Reference only. | Contains record iteration and conservative partial-record labels. Do not copy the session/presentation layer. PcapConstrictor must implement packet-level suffix decisions with original TCP payload length advancement, not UI stream items. |
| `tests/unit/StreamQueryTests.cpp` TLS cases | Synthetic examples for multiple TLS records, partial records, gaps, and AppData labels. | Test support and session layer. | Reference for future PcapConstrictor tests. | Tests are not directly reusable because they exercise UI/session stream behavior, but scenarios are valuable. |

TLS conclusion: implement a new small TLS record parser for PcapConstrictor. Use PcapFlowLab only as a reference for conservative record validation, malformed fallback, and test ideas.

### 2.7 QUIC

| Candidate | Purpose | Dependencies | Reuse mode | Risks or cleanup needed |
| --- | --- | --- | --- | --- |
| `src/core/services/QuicPacketProtocolAnalyzer.*` | QUIC packet text analyzer with long-header parsing, short-header detection, varint reading, frame summaries, and payload extraction. | `PacketDecodeSupport`, `PacketPayloadService`, `QuicInitialParser`, `TlsHandshakeDetails`, formatting code. | Adapt selected parser ideas. | Good source for long-header syntax, DCID/SCID parsing, version negotiation, retry, initial, handshake, and QUIC varints. Strip all presentation text, port heuristics, frame summaries, TLS handshake display, and decrypting Initial integration. |
| `src/core/services/QuicInitialParser.*` | QUIC Initial decryption, crypto frame assembly, and SNI extraction. | Windows bcrypt or OpenSSL, crypto helpers, TLS ClientHello parsing. | Reference only. | Do not copy into PcapConstrictor first version. The PcapConstrictor design explicitly says no QUIC decryption, and this file would add a heavy dependency graph. Some header and varint parsing ideas can be reimplemented without crypto. |
| `src/app/session/SessionQuicPresentation.*` | Selected-flow QUIC presentation and bounded handshake-aware display. | `CaptureSession`, session helpers, `QuicInitialParser`. | Reference only. | Too coupled to the session layer. Useful only for understanding conservative bounded QUIC handling and direction-specific presentation. |
| `tests/unit/QuicInitialParserTests.cpp`, `tests/unit/PacketProtocolDetailsTests.cpp`, QUIC fixtures | QUIC parsing and fixture behavior. | Test framework, session layer, crypto parser. | Reference for future synthetic tests. | Avoid importing decrypt/SNI expectations into PcapConstrictor's first QUIC truncation tests. PcapConstrictor needs connection ID and short-header safety tests instead. |

QUIC conclusion: build a new non-decrypting QUIC parser around long-header connection ID extraction, QUIC varints, known UDP 5-tuples, and short-header DCID matching. Use PcapFlowLab text analyzers only as reference material.

### 2.8 TCP Gap And Retransmission Patterns

| Candidate | Purpose | Dependencies | Reuse mode | Risks or cleanup needed |
| --- | --- | --- | --- | --- |
| `src/app/session/SessionTcpStreamSupport.*` | Detects duplicate TCP payloads, overlap, contiguous sequence tracking, and gaps for selected flow presentation. | `CaptureSession`, `PacketDetailsService`, packet byte reads. | Reference only. | The conservative state-machine ideas are useful, but the implementation is session-bound and selected-flow oriented. PcapConstrictor TLS state should be streaming, per-direction, and should keep full packets when sequence state is missing, out of order, retransmitted, or inconsistent. |
| `src/core/reassembly/ReassemblyTypes.h`, `ReassemblyService.*` | Bounded selected-flow TCP payload concatenation with quality flags. | `CaptureSession`, flow lists. | Reference only. | Do not use for truncation. PcapConstrictor should not reassemble whole streams; it needs only enough per-direction state to decide whether a packet can be safely suffix-truncated. |

### 2.9 Tests And Fixtures

| Candidate | Purpose | Dependencies | Reuse mode | Risks or cleanup needed |
| --- | --- | --- | --- | --- |
| `tests/unit/PcapTestUtils.h` | Synthetic classic PCAP, PCAPNG, Ethernet, VLAN, IPv4, IPv6, TCP, UDP, SLL/SLL2 packet builders. | Standard library. | Adapt for future tests. | Useful after PcapConstrictor test skeleton exists. Keep test helpers separate from production code. |
| `tests/unit/ExportTests.cpp` | PCAP writer round-trip examples. | Session and writer. | Reference for future writer tests. | Use the ideas, not the session-dependent test shape. |
| `tests/unit/MalformedPacketHandlingTests.cpp` | Conservative malformed packet expectations. | Decoder, details, payload service, session. | Reference for future decoder tests. | Valuable for "keep full when unsure" behavior. |
| `tests/unit/VlanTests.cpp`, `LinuxCookedTests.cpp`, `PcapNgTests.cpp`, `FlowKeyTests.cpp` | Decoder and key behavior coverage. | PcapFlowLab test framework and session. | Reference or partial adaptation later. | First implementation should prioritize classic PCAP and Ethernet/VLAN; SLL/SLL2 and PCAPNG can wait unless explicitly selected. |

### 2.10 Build And Documentation

| Candidate | Purpose | Dependencies | Reuse mode | Risks or cleanup needed |
| --- | --- | --- | --- | --- |
| `CMakeLists.txt` | C++20 core library, CLI, optional Qt UI, tests, OpenSSL/bcrypt linkage. | CMake 3.24, optional Qt, OpenSSL/bcrypt. | Reference only. | PcapConstrictor should start with a much smaller CLI-only CMake setup and no Qt, OpenSSL, bcrypt, index, or UI targets. |
| `README.md`, `docs/architecture.md`, related RFCs | Documents PcapFlowLab architecture and boundaries. | None. | Reference only. | Useful for understanding what not to copy: session layer, index path, on-demand analysis, UI, and bounded stream presentation are not PcapConstrictor foundations. |

## 3. Recommended Extraction Order

### 3.1 Safe byte and endian helpers

Create PcapConstrictor-owned helpers first:

- `read_u8`, `read_be16`, `read_be24`, `read_be32`;
- `read_le16`, `read_le32`;
- bounded span checks;
- QUIC varint reader returning value and new offset;
- small link type constants.

Use PcapFlowLab's `PacketDecodeSupport.h`, `PcapNgReader.cpp`, and QUIC analyzers as references, but consolidate duplicated endian helpers into one PcapConstrictor module.

### 3.2 Classic PCAP reader and writer

Adapt PcapFlowLab's `PcapReader` and `PcapWriter` next, but with PcapConstrictor-specific constraints:

- read sequentially;
- preserve timestamp and original length;
- expose input global header metadata;
- allow output packet captured length to be smaller than original length;
- keep packet bytes unchanged up to `new_caplen`;
- use explicit endian parsing instead of raw struct reads;
- collect basic read/write errors and stats.

PCAPNG should remain deferred unless there is a deliberate scope change.

### 3.3 Packet decoding

Adapt the decoder after classic PCAP passthrough exists.

PcapConstrictor's decoder should return offsets rather than flow-ingestion objects:

```text
link_header_start/end
network_header_start/end
transport_header_start/end
transport_payload_offset
transport_payload_size
ip_total_or_payload_end
tcp_seq/tcp_ack/tcp_flags when TCP
udp_length when UDP
flow key when TCP/UDP
fragmentation/malformed flags
```

Use PcapFlowLab's Ethernet, VLAN, IPv4, IPv6, TCP, UDP, and IPv6 extension traversal as the starting reference. Avoid ARP/ICMP detail work unless needed for stats or passthrough classification.

### 3.4 Flow keys

Adapt `FlowKey`, `ConnectionKey`, and `Direction` after packet decoding.

Use them for:

- TLS per-direction TCP state;
- QUIC UDP 5-tuple mapping;
- reasoned conservative handling of reverse directions.

Do not copy PcapFlowLab's flow tables or connection packet lists.

### 3.5 TLS parser

Build a new PcapConstrictor TLS module:

- parse TLS record headers;
- classify content type;
- track TCP direction state and expected sequence;
- remember active record continuation;
- compute one packet-level suffix cut;
- advance state using original TCP payload lengths, not reduced output lengths.

Use PcapFlowLab TLS analyzers and stream presentation code only as references for record validation and malformed fallback behavior.

### 3.6 QUIC parser

Build a new non-decrypting QUIC module:

- parse QUIC long headers enough to identify Initial, Retry, Version Negotiation, Handshake, 0-RTT/long protected type;
- extract DCID and SCID;
- map direct and reverse UDP 5-tuples to a `QuicConnection`;
- derive expected short-header DCIDs from observed Initial packets;
- truncate short-header packets only when flow and DCID state allow it.

Use PcapFlowLab's QUIC varint and long-header parsing ideas. Do not copy Initial decryption, crypto frame assembly, or SNI extraction.

## 4. Minimal First Skeleton Recommendation

After this reuse plan, the smallest useful PcapConstrictor skeleton should be CLI-only and classic PCAP-focused.

Recommended shape:

```text
CMakeLists.txt
src/
  cli/
    main.cpp
  core/
    bytes/
      ByteReader.h
    io/
      ClassicPcapReader.h/.cpp
      ClassicPcapWriter.h/.cpp
      LinkType.h
    stats/
      Stats.h
    constrict/
      PacketDecision.h
```

Initial behavior for the first implementation phase:

- CMake with C++20 and one executable named `pcap-constrictor`;
- no Qt, no OpenSSL, no bcrypt;
- command-line parser for `constrict input.pcap -o output.pcap`;
- classic PCAP passthrough only;
- one output record per input record;
- preserve packet order, timestamps, captured bytes, and original lengths;
- stats counters for packets and bytes read/written;
- no TLS and no QUIC truncation yet;
- no config file yet unless the skeleton needs defaults plumbing;
- no PCAPNG unless explicitly approved.

This gives a narrow foundation that can later accept packet decoding, reinflate mode, TLS, and QUIC without inheriting PcapFlowLab's UI/session/index architecture.

## 5. Things To Avoid

Do not copy or depend on:

- `src/ui/**`;
- `src/ui/qml/**`;
- Qt model classes such as `FlowListModel`, `PacketListModel`, `StreamListModel`, and `MainController`;
- `assets/**`, screenshots, release assets, build directories, or packaged artifacts;
- `src/app/session/**` as an architectural layer;
- `src/core/index/**` except as a reference for tiny capture format magic detection;
- checkpoint and index persistence;
- `src/core/reassembly/**` as production truncation logic;
- selected-flow stream presentation and analysis code;
- chart, histogram, timeline, top-summary, query, and analysis services;
- DNS, HTTP, SSH, STUN, DHCP, SMTP, POP3, IMAP, BitTorrent analyzers unless later needed for non-target keep-full classification;
- `QuicInitialParser` decryption and crypto support;
- OpenSSL or bcrypt dependencies for the first version;
- PcapFlowLab's CLI command surface.

Also avoid copying broad test files unchanged. Future PcapConstrictor tests should be built around the PcapConstrictor invariants:

- one input packet record produces one output packet record;
- suffix-only truncation;
- original length and timestamps preserved;
- unknown or malformed packets kept full;
- TLS state advances by original payload length;
- QUIC short-header truncation requires known connection and DCID state.

## 6. Open Questions

1. Should PcapConstrictor reorganize the existing docs into the requested `docs/rfcs` and `docs/test-cases` layout, or keep the current flat `docs` layout for now?

2. Should PcapConstrictor use Apache License 2.0 like PcapFlowLab, or a different open-source license?

3. Should the first classic PCAP reader support only little-endian microsecond PCAP, matching PcapFlowLab's current reader, or should it support big-endian and nanosecond PCAP from the start?

4. Should the first writer preserve the input global header fields exactly where possible, or normalize output to little-endian classic PCAP with the same link type?

5. Should Linux cooked captures SLL/SLL2 be included in the first packet decoder pass, or deferred behind Ethernet/VLAN/IPv4/IPv6/TCP/UDP?

6. Should PCAPNG be explicitly deferred until after TLS and QUIC constriction, even though PcapFlowLab has a separable reader?

7. For TLS state, should the first implementation keep all retransmissions full, or eventually allow exact duplicate retransmission handling after the conservative baseline is stable?

8. For QUIC, should PcapConstrictor ever reuse QUIC Initial decryption ideas for metadata extraction, or should the no-decryption boundary remain strict permanently?

9. Should future synthetic tests adapt PcapFlowLab's `PcapTestUtils.h` style, or should PcapConstrictor create a smaller fixture generator that only covers reducer invariants?

