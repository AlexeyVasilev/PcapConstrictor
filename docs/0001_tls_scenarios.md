# Test Scenarios 0001: TLS Packet Constriction

Status: Draft  
Project: PcapConstrictor  
Related design: RFC 0001 PcapConstrictor Design

## 1. Purpose

This document describes TLS packet-level scenarios that should later be converted into tests for PcapConstrictor.

The scenarios are intentionally written in a packet-layout form first. They can later be implemented as synthetic PCAP fixtures or generated packet streams.

## 2. Shared assumptions

Unless a scenario says otherwise:

```text
tls.app_data_keep_record_bytes = 8
tls.app_data_continuation_keep_bytes = 8
general.min_saved_bytes_per_packet = 16
```

TLS record lengths in these scenarios are interpreted as TLS record payload lengths, excluding the 5-byte TLS record header.

Therefore:

```text
TLS record total bytes in TCP payload = 5 + TLS record length field
```

PcapConstrictor must preserve the original packet length and timestamp for every packet. Constrict mode may only reduce captured length using one suffix-only cut per packet.

## 3. TLS configuration terms

### 3.1 `tls.app_data_keep_record_bytes`

This setting controls how many bytes to preserve from the beginning of a TLS Application Data record when that record starts in the current TCP packet.

The value includes the 5-byte TLS record header.

Example:

```text
tls.app_data_keep_record_bytes = 8
```

This preserves:

```text
5 bytes TLS record header
3 bytes encrypted Application Data fragment
```

### 3.2 `tls.app_data_continuation_keep_bytes`

This setting controls how many bytes to preserve from a TCP packet that contains only a continuation of a previously identified TLS Application Data record.

A continuation packet does not contain a new TLS record header at its beginning. It only contains encrypted bytes that continue a TLS record that started in an earlier TCP packet.

Example:

```text
tls.app_data_continuation_keep_bytes = 8
```

This preserves the first 8 bytes of the TCP payload in a continuation-only packet.

### 3.3 State update rule

TLS stream state must be updated using original TCP payload lengths, not reduced captured lengths.

Example:

```text
Input TCP payload  = 2800 bytes
Output TCP payload = 8 bytes
```

The TLS stream state must still advance by 2800 bytes.

## 4. TLS scenario: one connection with ClientHello, ServerHello, large server Application Data, and client Application Data records

### 4.1 Input packet sequence

All packets belong to the same TCP connection, with one 5-tuple and its reverse direction.

```text
#1 A -> B TCP SYN, payload = 0
#2 B -> A TCP SYN ACK, payload = 0
#3 A -> B TCP ACK, payload = 0

#4 A -> B TCP payload = 1900
    TLS record: Handshake / Client Hello, record length = 1895
    TLS handshake message: Client Hello, handshake length = 1891

#5 B -> A TCP ACK, payload = 0
#6 B -> A TCP ACK, payload = 0

#7 B -> A TCP payload = 2800
    TLS Server Hello, record length = 1210
    TLS Change Cipher Spec, length = 1
    TLS Application Data #1 partial, length = 9089

#8 B -> A TCP payload = 2800
    TLS Application Data #1 continuation

#9 B -> A TCP payload = 2800
    TLS Application Data #1 continuation

#10 B -> A TCP payload = 1915
    TLS Application Data #1 continuation

#11 A -> B TCP ACK, payload = 0
#12 A -> B TCP ACK, payload = 0
#13 A -> B TCP ACK, payload = 0
#14 A -> B TCP ACK, payload = 0

#15 A -> B TCP payload = 64
    TLS Change Cipher Spec, length = 1
    TLS Application Data #2, length = 53

#16 A -> B TCP payload = 92
    TLS Application Data #3, length = 87

#17 A -> B TCP payload = 1165
    TLS Application Data #4, length = 424
    TLS Application Data #5, length = 145
    TLS Application Data #6, length = 144
    TLS Application Data #7, length = 144
    TLS Application Data #8, length = 135
    TLS Application Data #9, length = 143
```

### 4.2 Notes about the input

Packet #4 has a TCP payload of 1900 bytes. Wireshark shows a TLS record length of 1895 bytes and a ClientHello handshake message length of 1891 bytes. The full TLS record size is therefore:

```text
5 + 1895 = 1900 bytes
```

So the whole TCP payload is exactly one TLS ClientHello record. The implementation should keep Packet #4 full because ClientHello is visible handshake metadata and must be preserved.

Packet #7 contains the start of a large TLS Application Data record after visible non-Application-Data records:

```text
Server Hello TLS record length field = 1210
  (= 1 byte handshake type + 3 bytes handshake length + 1206 bytes ServerHello data)
Server Hello total bytes       = 5 + 1210 = 1215
Change Cipher Spec total bytes = 5 + 1    = 6
Bytes before AppData #1        = 1221
Packet #7 payload bytes        = 2800
Visible AppData #1 bytes in #7 = 2800 - 1221 = 1579
```

TLS Application Data #1 total size is:

```text
5 + 9089 = 9094 bytes
```

The visible bytes listed in Packets #7 through #10 account for:

```text
362 + 2800 + 2800 + 1915 = 7877 bytes
```

So Application Data #1 still has remaining bytes after Packet #10 unless later packets outside this scenario continue it.

## 5. Expected constrict behavior

Packets without TCP payload are kept full.

Packet #4 is kept full because it contains ClientHello.

Packet #7 can be truncated after preserving ServerHello, Change Cipher Spec, and the first 8 bytes of TLS Application Data #1:

```text
Packet #7 output TCP payload:
  TLS Server Hello full:        1215 bytes
  TLS Change Cipher Spec full:  6 bytes
  TLS AppData #1 prefix:        8 bytes

Expected output TCP payload = 1215 + 6 + 8 = 1229 bytes
```

Packets #8, #9, and #10 are continuations of the already identified TLS Application Data #1 record. Because the active TLS record is known to be constrictible and no later TLS record boundary is visible inside these packets, each packet may be truncated to the configured continuation prefix:

```text
Packet #8 output TCP payload  = 8 bytes
Packet #9 output TCP payload  = 8 bytes
Packet #10 output TCP payload = 8 bytes
```

The implementation must update TLS record remaining length using the original TCP payload lengths, not the reduced captured lengths.

Packet #15 contains Change Cipher Spec followed by a complete TLS Application Data record:

```text
Change Cipher Spec total bytes = 5 + 1  = 6
TLS AppData #2 total bytes     = 5 + 53 = 58
```

Expected output:

```text
Packet #15 output TCP payload:
  TLS Change Cipher Spec full: 6 bytes
  TLS AppData #2 prefix:       8 bytes

Expected output TCP payload = 14 bytes
```

Packet #16 contains one complete TLS Application Data record:

```text
TLS AppData #3 total bytes = 5 + 87 = 92
```

Expected output:

```text
Packet #16 output TCP payload = 8 bytes
```

Packet #17 contains several complete TLS Application Data records in one TCP packet:

```text
TLS AppData #4 total bytes = 5 + 424 = 429
TLS AppData #5 total bytes = 5 + 145 = 150
TLS AppData #6 total bytes = 5 + 144 = 149
TLS AppData #7 total bytes = 5 + 144 = 149
TLS AppData #8 total bytes = 5 + 135 = 140
TLS AppData #9 total bytes = 5 + 143 = 148
```

Because only one suffix cut is allowed, the implementation must preserve all earlier records fully and may only constrict the last record:

```text
Packet #17 output TCP payload:
  TLS AppData #4 full:   429 bytes
  TLS AppData #5 full:   150 bytes
  TLS AppData #6 full:   149 bytes
  TLS AppData #7 full:   149 bytes
  TLS AppData #8 full:   140 bytes
  TLS AppData #9 prefix: 8 bytes

Expected output TCP payload = 429 + 150 + 149 + 149 + 140 + 8 = 1025 bytes
```

## 6. Expected packet payload summary

```text
#1  keep full, TCP payload output = 0
#2  keep full, TCP payload output = 0
#3  keep full, TCP payload output = 0
#4  keep full, TCP payload output = 1900
#5  keep full, TCP payload output = 0
#6  keep full, TCP payload output = 0
#7  constrict, TCP payload output = 1229
#8  constrict, TCP payload output = 8
#9  constrict, TCP payload output = 8
#10 constrict, TCP payload output = 8
#11 keep full, TCP payload output = 0
#12 keep full, TCP payload output = 0
#13 keep full, TCP payload output = 0
#14 keep full, TCP payload output = 0
#15 constrict, TCP payload output = 14
#16 constrict, TCP payload output = 8
#17 constrict, TCP payload output = 1025
```

## 7. Expected saved TCP payload bytes

```text
#7:  2800 - 1229 = 1571 bytes saved
#8:  2800 - 8    = 2792 bytes saved
#9:  2800 - 8    = 2792 bytes saved
#10: 1915 - 8    = 1907 bytes saved
#15: 64 - 14     = 50 bytes saved
#16: 92 - 8      = 84 bytes saved
#17: 1165 - 1025 = 140 bytes saved
```

Total saved TCP payload bytes in the listed packets:

```text
1571 + 2792 + 2792 + 1907 + 50 + 84 + 140 = 9336 bytes
```

The actual saved captured bytes at the PCAP record level should equal the TCP payload savings when the transport payload suffix is truncated and lower-layer headers are preserved unchanged.

## 8. Future TLS scenarios to add

- TLS Application Data record split across two packets, followed by a new TLS record in the second packet.
- TLS packet with out-of-order TCP sequence number.
- TLS retransmission.
- TLS malformed record length.
- TLS capture beginning mid-stream.
- TLS packet with only continuation data and no later TLS record boundary.
- TLS packet with Application Data followed by a non-Application-Data record, requiring keep-full behavior because only suffix truncation is allowed.

