# Test Fixtures

This directory contains packet captures that are intentionally part of the repository and may be used by automated or manual tests.

Committed PCAP fixtures must be safe to publish.

Golden fixtures under `tests/fixtures/golden/` include input captures and committed expected output captures for end-to-end workflow tests.

Expected output captures should only be updated intentionally after manual verification.

Local scratch captures should stay under `temp/`, `tests/private/`, or use the `*.private.pcap` suffix.
