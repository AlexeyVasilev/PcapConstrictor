# PcapConstrictor

PcapConstrictor is a C++20 command-line tool for reducing packet capture files while preserving packet metadata and protocol-visible information.

The current implementation is intentionally small: it supports only classic PCAP passthrough. The `constrict` command currently reads a classic PCAP file sequentially and writes a classic PCAP file sequentially without changing packet bytes or packet record metadata.

Future phases are planned to add reinflate mode, packet parsing, TLS constriction, and QUIC constriction. PcapConstrictor does not decrypt TLS or QUIC, does not extract secrets, and does not capture unauthorized traffic.

Classic PCAP stores both a captured length and an original length for each packet. That length model is what will later allow PcapConstrictor to perform conservative suffix-only truncation: the captured length can shrink while the original wire length is preserved.

## Usage

```sh
pcap-constrictor constrict input.pcap -o output.pcap --stats
```

Current `--stats` output includes packet and byte totals, time precision, endianness, link type, and snaplen.

## Current Scope

Supported now:

- classic PCAP passthrough
- little-endian and big-endian PCAP
- microsecond and nanosecond timestamp precision
- sequential processing without loading the whole capture into memory

Not implemented yet:

- packet parsing
- TLS parsing or truncation
- QUIC parsing or truncation
- reinflate / restore mode
- config file parsing
- PCAPNG
- live capture or eBPF

