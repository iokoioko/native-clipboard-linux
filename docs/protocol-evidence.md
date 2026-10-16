# Protocol evidence and validation boundaries

This snapshot is a source publication of an experimental iPhone → Linux receiver.
The private hardware validation used an enrolled Linux-owned identity, an iPhone,
and existing Mac public IDS routing metadata. The Mac was not the clipboard
content relay. This does not prove that all participating Apple services are
independent of that Mac, nor that another account/device can be enrolled using
only this repository.

The tested path accepts an incoming Companion-link connection, verifies the
trusted peer's Pair-Verify signature, derives encrypted session keys, exchanges
system information, requests pasteboard types, and requests pasteboard data.
Responses are correlated with the outstanding transaction. The receiver parses
`rActPayload` as a restricted NSKeyedArchiver graph; inline extra-data type 2 with
valid `public.utf8-plain-text` content is eligible for clipboard output.
Unknown signatures, mismatched requests, malformed archives and unsupported
representations must not be treated as clipboard text.

A controlled live background session delivered a fresh 24-byte synthetic text
value. Exact clipboard readback matched, and ordinary pasting was confirmed by
the operator. Earlier bounded tests also demonstrated authenticated text delivery.
Raw session logs, account/device metadata and captured archives remain private.
This narrative is a sanitized report, not an included hardware-test fixture.

The initial sanitized publication candidate passed `cargo test --locked
--no-default-features`: **155 passed, zero failed, two ignored**. The ignored
cases require external interoperability tooling or hardware. Rust formatting,
Python syntax checks, launcher fault-injection, and isolated installer tests
passed. A headless build also passed. These offline checks do not establish
compatibility with another phone or substitute for the hardware test above.

The binary plist in `tests/fixtures` is different evidence: it was generated from
our synthetic Swift reference-model classes using Foundation NSKeyedArchiver on
macOS 15.7. Its payload is a fixed artificial test string. It contains no captured
Apple clipboard traffic, credentials, peer metadata, or Apple executable code.
The generator and provenance JSON are included beside it. This tests parser and
serialization interoperability, not live receiving.

Primary protocol references:

- [Handoff authentication research](https://github.com/seemoo-lab/handoff-authentication-swift/tree/4518b75b6bc5c66decc40fefba49d0bb7adab21d): historical message names, Pair-Verify and pasteboard model.
- [pyatv Companion protocol documentation](https://pyatv.dev/documentation/protocols/#companion): independent wire framing/reference fixture.
- [pyatv OPACK](https://github.com/postlund/pyatv/blob/master/pyatv/support/opack.py): serialization cross-check.
- [Continuity tools](https://github.com/seemoo-lab/apple-continuity-tools/tree/b93207b5887c6bef8c9e0e16a442149fb3520e28): research context.

Research references are not runtime dependencies. No Apple binaries, SDK files,
private keychain dumps, or GPL research implementation sources are distributed
with this MIT snapshot. Protocol observations and independently written Rust
implementation must be distinguished from any source copying; see provenance.

The OPACK reference-table regression vectors in `tests/fixtures/opack-native-synthetic-oracle.json`
were generated/decoded through a native macOS CoreUtils oracle using only our
synthetic arrays and dictionaries. They reproduce a lost top-level `_i` selector:
empty strings/data and small integers must not consume reference slots, while
each eligible literal occurrence consumes a slot even when its value repeats.
The corresponding Rust regression tests include nested message dictionaries.
Only synthetic wire data and sanitized provenance are distributed.

## Retained receiver candidate

The opt-in BLE-triggered retained connection adds exact trusted signer selection,
metadata/content provider UUID correlation when metadata supplies a UUID, initial
baseline and periodic fallback, and the existing conservative clipboard policy.
A controlled native diagnostic fetched exact synthetic text 128 ms after the BLE
hint with clipboard writes disabled. The continuous fast receiver's live write and
ordinary paste result is pending; this is not an end-to-end latency receipt.

The test-only `clipboard_serve.rs` helper creates synthetic text archives for the
retained receiver's encrypted loopback tests. It is excluded from runtime builds
and does not expose a reverse clipboard service. No sender implementation, image
transfer, private identity-mapping diagnostic, account material, or native binary
is added by this update.

The sanitized retained-receiver update passed its own headless suite: **172 passed,
zero failed, three ignored**. Formatting, three launcher tests and the isolated
installer test passed. The headless build passed. These counts exclude unpublished
key diagnostics, reverse sender and image preparation.
