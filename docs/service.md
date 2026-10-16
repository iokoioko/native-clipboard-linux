# Continuous receiver behavior

## Synchronization policy

- Authenticate the peer and correlate all requests before accepting text.
- Require inline type-2 data and valid `public.utf8-plain-text` bytes.
- Baseline the first remote value on service startup instead of importing
  potentially old clipboard data. An authenticated empty response also establishes
  a baseline, allowing the next fresh value to sync.
- Keep hashes in memory to suppress duplicate remote text. Recopying identical
  text is not a distinguishable new event in this version.
- Read the local clipboard before a handshake and again before applying text.
  Preserve local changes detected between connections or during retrieval.
  A suppressed remote value is remembered, so it cannot overwrite the local
  clipboard on the next reconnect.
- Use an independent, bounded-start clipboard-owner unit so stopping or restarting
  sync does not terminate the selection owner. Report successful writes only after
  exact hash readback; cancel a failed or timed-out owner start.
- Skip updates when the local clipboard cannot be read within two seconds or
  exceeds 8 MiB per supported format (32 MiB total). No clipboard bytes are written into status logs.

These checks are conservative. A local edit can cause an overlapping phone
copy to be skipped; copy a different value on the phone to retry. The final
clipboard comparison and write are not an atomic compositor transaction.
Hash-based ordering does not establish exact cross-device copy timestamps.

## Connection lifecycle

The listener keeps its Bonjour advertisement alive and accepts new connections
without the diagnostic 16-client/five-minute limit. Individual authentication
and request timeouts remain bounded. It checks the configured interface address
every ten seconds; on change, systemd restarts it after ten seconds and the
launcher resolves the new IPv4 address. If the interface has no address, the
launcher waits without a restart storm. Launcher recovery from a missing interface and absent address passed a fault-injection
test (`scripts/test_native_clipboard_launcher.py`). Real sleep/resume and AP
roaming still need live validation.

The configured network and nearby iPhone must still support native Continuity
discovery. This does not implement Linux-to-iPhone transfer, separate Apple stream transport,
or AirPods switching. Inline PNG reception is implemented but live image
interoperability remains unverified.

See [protocol evidence](protocol-evidence.md) for the hardware validation limits.

## Opt-in retained receiver

With both private BLE key and exact signer fingerprint paths in configuration,
the launcher selects `ble-listen-probe` in explicit continuous/write mode. The
receiver retains one exact verified-signing-key channel. Up to eight bounded
handshakes can proceed concurrently so one slow unrelated connection cannot
block the target. One verified reconnect may wait; shared synchronization state
survives reconnects.

A readiness barrier precedes the first baseline query. Fresh BLE hints coalesce;
requests in flight retain their local clipboard snapshot and provider identity.
Five-second authenticated fallback queries cover missed hints and scanner startup
or runtime failure; closed scanner channels do not spin. An initial unsupported
representation is skipped, so the first later usable text may establish the
baseline and be skipped as well. Missing provider UUIDs are compatibility cases,
not proof of exact copy ordering.

One reader task owns framing across hints and timer events; partial frames have
a deadline. Writes have a bounded transport timeout and terminate the session on
failure. Interface checks continue during the retained session. Continuous mode
logs event categories, sizes, timing, provider digests and clipboard outcomes,
never raw clipboard bytes or decrypted BLE packets. Bounded diagnostics remain
separate and require their own explicit invocation.

Native fast-path validation currently establishes fetching only: a controlled
synthetic text value matched 128 ms after a BLE hint without writing the clipboard.
Live continuous fast-path paste validation is pending. Offline tests do not
substitute for that final step.

## Typed PNG reception

The existing write opt-in enables both UTF-8 text and validated static inline PNG.
PNG metadata/content must match provider UUID, UTI and size; missing PNG generation
metadata is rejected. Text retains compatibility with absent size/UUID metadata.
Text takes priority when both representations are present. PNG decoding checks
CRC, dimensions and allocation limits (1 MiB encoded, 16 million pixels,
64 MiB decoded); animated PNG and streamed images are unsupported.

Local snapshots include all offered MIME names and bounded supported text/PNG
bytes. The writer uses explicit MIME and exact typed readback; a changed mixed
selection is protected even when its text alternative stays identical. Clipboard
ownership survives stopping the receiver. The final comparison/write still is
not atomic with local compositor changes.

The PNG-capable candidate is installed on the research machine; no live iPhone
image delivery is claimed. Existing bootstrap configuration remains necessary.
