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
  exceeds 8 MiB. No clipboard bytes are written into status logs.

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
discovery. This does not yet implement Linux-to-iPhone transfer, image clipboard
sync, separate Apple stream transport, or AirPods switching.

See [protocol evidence](protocol-evidence.md) for the hardware validation limits.
