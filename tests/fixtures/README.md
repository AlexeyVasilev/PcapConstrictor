# Test Fixtures

This directory contains packet captures that are intentionally part of the repository and may be used by automated or manual tests.

Committed PCAP fixtures must be safe to publish.

Golden fixtures under `tests/fixtures/golden/` include input captures and committed expected output captures for end-to-end workflow tests.

Each golden scenario contains `input.pcap`, `constricted.pcap`, `reinflated_preserve_checksum.pcap`, `reinflated_recompute_checksum.pcap`, `constrict.ini`, `reinflate_preserve.ini`, and `reinflate_recompute.ini`.

Golden workflow tests generate actual outputs under the build directory and compare them byte-for-byte against the committed expected outputs.

Expected output captures should only be updated intentionally after manual verification.

Committed PCAPNG fixtures under `tests/fixtures/pcapng/` must also be safe to publish. PCAPNG fixture tests should preserve block structure where possible. Golden PCAPNG expected outputs can be added later after manual verification.

Local scratch captures should stay under `temp/`, `tests/private/`, or use the `*.private.pcap` suffix.
