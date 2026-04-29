# Test Scenarios 0002: QUIC Packet Constriction

Status: Draft  
Project: PcapConstrictor  
Related design: RFC 0001 PcapConstrictor Design

## 1. Purpose

This document describes QUIC packet-level scenarios that should later be converted into tests for PcapConstrictor.

The scenarios are intentionally written in a packet-layout form first. They can later be implemented as synthetic PCAP fixtures or generated packet streams.

## 2. Shared assumptions

Unless a scenario says otherwise:

```text
quic.short_header_keep_packet_bytes = 32
quic.require_dcid_match = true
quic.allow_short_header_without_known_dcid = false
general.min_saved_bytes_per_packet = 16
```

PcapConstrictor must preserve the original packet length and timestamp for every packet. Constrict mode may only reduce captured length using one suffix-only cut per packet.

## 3. QUIC configuration terms

### 3.1 `quic.short_header_keep_packet_bytes`

This setting controls how many bytes to preserve from the beginning of a QUIC short-header packet when that packet is eligible for constriction.

Example:

```text
quic.short_header_keep_packet_bytes = 32
```

This preserves the first 32 bytes of the QUIC short-header packet, counted from the beginning of the QUIC packet inside the UDP payload.

If the expected Destination Connection ID length is known, the preserved prefix must be large enough to include the first byte and the expected DCID:

```text
keep_quic_bytes = max(
    quic.short_header_keep_packet_bytes,
    1 + expected_dcid_length
)
```

If the UDP payload is shorter than or equal to the keep size, the packet is kept full because there is nothing useful to save.

### 3.2 `quic.require_dcid_match`

This setting controls whether a QUIC short-header packet must match an expected Destination Connection ID before it can be truncated.

Default:

```text
quic.require_dcid_match = true
```

When enabled, short-header packets are truncated only if:

- the UDP 5-tuple is mapped to a known `QuicConnection`;
- the direction has a known expected DCID, or the expected DCID length is zero;
- the DCID in the short-header packet matches the expected DCID for that direction.

### 3.3 `quic.allow_short_header_without_known_dcid`

Default:

```text
quic.allow_short_header_without_known_dcid = false
```

When disabled, PcapConstrictor must keep short-header-looking UDP packets full if they are not associated with a known QUIC connection and expected DCID state.

This prevents unrelated UDP packets or unrelated QUIC connections from being truncated just because their first byte looks like a QUIC short header.

## 4. QUIC connection model for this scenario

The analyzed QUIC connection uses two UDP directions:

```text
A -> B
B -> A
```

The connection is discovered from QUIC Initial long-header packets.

The relevant connection IDs are:

```text
Client-chosen Source Connection ID: af0214
Server-chosen Source Connection ID: 0fe878970900ce24
Original Destination Connection ID: fc664bb01563cf93
```

Expected short-header DCID by direction after the server Initial is observed:

```text
A -> B short header expected DCID: 0fe878970900ce24
B -> A short header expected DCID: af0214
```

Packets #13 and #14 are intentionally unrelated QUIC short-header-looking packets. They must not be truncated because they are not part of the discovered `A <-> B` `QuicConnection` and their DCID state does not match that connection.

## 5. Input packet sequence

```text
#1 A -> B UDP, payload = 1252
    QUIC Initial (Long Header), length = 945
      Destination Connection ID = fc664bb01563cf93
      Source Connection ID      = af0214
    Filler data, all zeros

#2 A -> B UDP, payload = 1252
    QUIC Initial (Long Header), length = 941
      Destination Connection ID = fc664bb01563cf93
      Source Connection ID      = af0214
    Filler data, all zeros

#3 B -> A UDP, payload = 43
    QUIC Initial (Long Header), length = 22
      Destination Connection ID = af0214
      Source Connection ID      = 0fe878970900ce24

#4 B -> A UDP, payload = 1252
    QUIC Initial (Long Header), length = 1231
      Destination Connection ID = af0214
      Source Connection ID      = 0fe878970900ce24

#5 B -> A UDP, payload = 1252
    QUIC Initial (Long Header), length = 1231
      Destination Connection ID = af0214
      Source Connection ID      = 0fe878970900ce24

#6 B -> A UDP, payload = 1252
    QUIC Handshake (Long Header), length = 1232
      Destination Connection ID = af0214
      Source Connection ID      = 0fe878970900ce24

#7 B -> A UDP, payload = 1252
    QUIC Handshake (Long Header), length = 1232
      Destination Connection ID = af0214
      Source Connection ID      = 0fe878970900ce24

#8 B -> A UDP, payload = 1252
    QUIC Handshake (Long Header), length = 1232
      Destination Connection ID = af0214
      Source Connection ID      = 0fe878970900ce24

#9 B -> A UDP, payload = 197
    QUIC Handshake (Long Header), length = 177
      Destination Connection ID = af0214
      Source Connection ID      = 0fe878970900ce24

#10 A -> B UDP, payload = 85
    QUIC Initial (Long Header), length = 22
      Destination Connection ID = 0fe878970900ce24
      Source Connection ID      = af0214
    QUIC Handshake (Long Header), length = 22
      Destination Connection ID = 0fe878970900ce24
      Source Connection ID      = af0214

#11 A -> B UDP, payload = 141
    QUIC Handshake (Long Header), length = 72
      Destination Connection ID = 0fe878970900ce24
      Source Connection ID      = af0214
    QUIC Protected Payload (Short Header)
      Destination Connection ID = 0fe878970900ce24

#12 A -> B UDP, payload = 63
    QUIC Protected Payload (Short Header)
      Destination Connection ID = 0fe878970900ce24

#13 C -> D UDP, payload = 317
    QUIC Protected Payload (Short Header)

#14 E -> F UDP, payload = 1185
    QUIC Protected Payload (Short Header)

#15 B -> A UDP, payload = 290
    QUIC Protected Payload (Short Header)
      Destination Connection ID = af0214

#16 A -> B UDP, payload = 31
    QUIC Protected Payload (Short Header)
      Destination Connection ID = 0fe878970900ce24
```

## 6. Expected connection tracking behavior

### 6.1 Packets #1 and #2

Packets #1 and #2 are client Initial packets.

Expected behavior:

- keep full;
- create or update `QuicConnection` for `A -> B` and `B -> A`;
- store original DCID `fc664bb01563cf93`;
- store client SCID `af0214`;
- map direct and reverse UDP 5-tuples to the connection.

The trailing zero filler data must be kept full in this first version. PcapConstrictor should not truncate unknown trailing bytes after an Initial long-header packet.

### 6.2 Packets #3, #4, and #5

Packets #3, #4, and #5 are server Initial packets.

Expected behavior:

- keep full;
- update the existing `QuicConnection`;
- observe server SCID `0fe878970900ce24`;
- set expected A -> B short-header DCID to `0fe878970900ce24`;
- keep expected B -> A short-header DCID as `af0214`.

### 6.3 Packets #6 through #10

Packets #6 through #10 contain QUIC long-header Initial and/or Handshake packets.

Expected behavior:

- keep full;
- update connection state if useful;
- do not truncate long-header packets in the first QUIC implementation.

Packet #10 contains coalesced long-header packets. It must still be kept full.

### 6.4 Packet #11

Packet #11 contains a long-header Handshake packet followed by a QUIC short-header protected packet.

Expected behavior:

- keep the long-header Handshake packet full;
- if the following short-header packet is the final packet in the UDP datagram and its DCID matches expected A -> B DCID `0fe878970900ce24`, truncate the suffix inside the short-header packet;
- perform only one suffix cut for the whole UDP datagram.

Expected output UDP payload size:

```text
short_header_offset + quic.short_header_keep_packet_bytes
```

Where `short_header_offset` is the byte offset from the start of the UDP payload to the beginning of the short-header packet. The exact offset should be derived by the parser from the actual QUIC long-header packet bytes.

If the resulting saved bytes are less than `general.min_saved_bytes_per_packet`, keep full.

### 6.5 Packet #12

Packet #12 is an A -> B QUIC short-header protected packet with matching DCID:

```text
expected DCID = 0fe878970900ce24
actual DCID   = 0fe878970900ce24
```

Expected behavior:

- truncate to 32 bytes of UDP payload;
- preserve original packet length;
- perform only one suffix cut.

Expected output UDP payload size:

```text
32 bytes
```

Expected saved UDP payload bytes:

```text
63 - 32 = 31 bytes
```

### 6.6 Packets #13 and #14

Packets #13 and #14 are QUIC short-header-looking packets that do not belong to the discovered `A <-> B` connection.

Expected behavior:

- keep full;
- do not truncate;
- do not classify them as part of the existing `QuicConnection`;
- do not rely only on the short-header-looking first byte.

Rationale:

A QUIC short-header-looking packet is not enough to prove that the packet belongs to a known connection. PcapConstrictor must require known flow state and, when available, matching DCID state.

### 6.7 Packet #15

Packet #15 is a B -> A QUIC short-header protected packet with matching DCID:

```text
expected DCID = af0214
actual DCID   = af0214
```

Expected behavior:

- truncate to 32 bytes of UDP payload;
- preserve original packet length;
- perform only one suffix cut.

Expected output UDP payload size:

```text
32 bytes
```

Expected saved UDP payload bytes:

```text
290 - 32 = 258 bytes
```

### 6.8 Packet #16

Packet #16 is an A -> B QUIC short-header protected packet with matching DCID:

```text
expected DCID = 0fe878970900ce24
actual DCID   = 0fe878970900ce24
```

However, the UDP payload is shorter than the configured short-header keep size:

```text
payload size = 31
keep size    = 32
```

Expected behavior:

- keep full;
- do not truncate;
- reason: no useful byte savings.

## 7. Expected packet payload summary

```text
#1  keep full, UDP payload output = 1252
#2  keep full, UDP payload output = 1252
#3  keep full, UDP payload output = 43
#4  keep full, UDP payload output = 1252
#5  keep full, UDP payload output = 1252
#6  keep full, UDP payload output = 1252
#7  keep full, UDP payload output = 1252
#8  keep full, UDP payload output = 1252
#9  keep full, UDP payload output = 197
#10 keep full, UDP payload output = 85
#11 constrict if short-header suffix saves enough bytes, UDP payload output = short_header_offset + 32
#12 constrict, UDP payload output = 32
#13 keep full, UDP payload output = 317
#14 keep full, UDP payload output = 1185
#15 constrict, UDP payload output = 32
#16 keep full, UDP payload output = 31
```

## 8. Expected saved UDP payload bytes

Known exact savings:

```text
#12: 63 - 32  = 31 bytes saved
#15: 290 - 32 = 258 bytes saved
#16: 31 - 31  = 0 bytes saved
```

Packet #11 savings depend on the parsed `short_header_offset`:

```text
#11: 141 - (short_header_offset + 32) bytes saved
```

Packets #13 and #14 must save 0 bytes because they are unrelated packets and must be kept full.

## 9. Future QUIC scenarios to add

- QUIC short-header packet on known 5-tuple but mismatched DCID.
- QUIC short-header packet on known 5-tuple before server SCID is known.
- QUIC zero-length DCID behavior.
- QUIC long-header-only datagram is kept full.
- QUIC coalesced datagram with Initial, Handshake, and final short-header packet.
- QUIC Retry updates connection ID expectations.
- QUIC Version Negotiation is kept full.
- QUIC packet with malformed long-header length is kept full.
- QUIC packet with unknown version is kept full unless explicitly configured otherwise.

