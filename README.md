# Native Clipboard for Linux — experimental

Receive native iPhone clipboard text directly on Linux over the local network.
The receiver also supports bounded inline PNGs in code; live image transfer is unverified.
This research prototype has received authenticated iPhone text on Arch Linux,
written it to a Wayland clipboard, and passed an ordinary user paste check.
There is no companion app on the phone and no Mac clipboard-content relay.

**This is not a general-purpose installer for Universal Clipboard.** The working
setup still depends on manually prepared Apple-account trust material and an
existing Mac's public IDS routing identifier. Independent Linux IDS enrollment is not packaged in this MIT snapshot,
and the research bootstrap is not provided here. If you do not
already have these prerequisites, building the code alone will not connect your
phone. Linux → iPhone clipboard transfer is not implemented in this snapshot.

Derived from [cristim/adhoc-cross-device-connection](https://github.com/cristim/adhoc-cross-device-connection)
at `c6c4a2154fdbb70657ecf653e0d05a8807cb3297`, with additional clipboard research
changes. The inherited application also contains AirDrop-compatible and BLE
experiments; those are separate capabilities and do not establish native clipboard
interoperability. The inherited MIT license and attribution are preserved.

## What works, and what remains experimental

- Native Companion-link Pair-Verify authentication with trusted peer signatures.
- Encrypted request exchange, correlated `_systemInfo`, `pbtypes`, and `pbpaste2` responses.
- Bounded keyed-archive parsing, UTF-8 plain text, and validated static inline PNG extraction.
- Continuous receiving, duplicate suppression, conservative local-edit protection,
  and verified Wayland clipboard readback.
- A user service, pause/resume CLI, and optional PySide6 tray.

Live image interoperability, file-handle/stream transfers, independent Apple-account enrollment,
and broad device/OS compatibility are unverified or unsupported; Linux → iPhone
clipboard transfer is not implemented.
Sleep/resume and access-point roaming need live validation. This publishes source
and a reproducible synthetic fixture, not private device captures or Apple binaries.
See [protocol evidence](docs/protocol-evidence.md) and [service behavior](docs/service.md).

## Build and offline checks

On Arch Linux, install Rust, a C toolchain, `pkgconf`, `dbus`, `openssl`, Python 3,
`iproute2`, `wl-clipboard`, and systemd. The tray requires `pyside6`; install it before using autostart or pass
`--no-tray` to the installer. Run in a
Wayland desktop session for clipboard output. The headless build avoids the
optional desktop UI and its additional graphics dependencies.

```sh
cargo build --locked --no-default-features
cargo test --locked --no-default-features
python3 scripts/test_native_clipboard_launcher.py
python3 scripts/test_native_clipboard_installer.py
```

The binary remains named `ac-dc`. `target/debug/ac-dc --help` lists experimental
diagnostic commands; these are not an end-user enrollment flow.

## Prerequisites before enabling receiving

You must independently prepare all of the following for your own devices:

1. A Linux-owned Ed25519 identity that your phone already trusts through the
   same-account Rapport identity mechanism, together with your phone's trusted
   public signing key. `ac-dc init-identity --private PATH --public PATH` only
   generates local files; it does **not** enroll the identity or establish trust.
   The private JSON schema uses `ed_sk`, `dirk`, `identifier`, and `peers`
   (`label` / `edpk`). Keep both generated files private: the provisioning file
   also contains a device IRK.
2. A compatible Linux-owned Bonjour TXT JSON file for `_companion-link._tcp`,
   consistent with that identity. The loader accepts string-valued TXT entries.
   Generating and enrolling this metadata is currently a manual research step.
3. A private text file containing the existing Mac's public IDS UUID used for
   compatibility routing. This identifier is not a signing key, but it is still
   identifying metadata. It does not give Linux an independently enrolled IDS identity.
4. Your iPhone configured for Handoff, suitable local-network discovery and
   connectivity, and the correct Linux interface name (obtain it with `ip link`).

No account credentials, signing material, IRKs, or device identifiers are provided
by this repository. Do not upload your generated configuration or diagnostic captures.
There is deliberately no claim that the above manual research steps constitute
complete, portable onboarding instructions.

## Install with an existing bootstrap

Create a private JSON configuration with absolute paths; replace every placeholder:

```json
{
  "interface": "YOUR_NETWORK_INTERFACE",
  "identity": "/ABSOLUTE/PRIVATE/identity.json",
  "bonjour": "/ABSOLUTE/PRIVATE/bonjour-txt.json",
  "ids_identifier": "/ABSOLUTE/PRIVATE/mac-public-ids.txt"
}
```

```sh
chmod 600 /path/to/config.json
python3 scripts/install-native-clipboard.py --config /path/to/config.json
systemctl --user enable --now native-clipboard.service
native-clipboard status
```

The installer validates the supplied paths, preserves an existing installed
configuration, installs under `~/.local`, and reloads user systemd units. It does
not enable/start the service until you run the explicit command above. Use
`--binary PATH` for a different build. Edit `~/.config/native-clipboard/config.json`
to change an existing installation, then restart the service.

The first remote value after startup establishes a baseline and is not copied.
Copy a fresh, different text value on the phone after connecting. Use
`native-clipboard pause`, `resume`, `logs`, or `disable`. Clipboard contents are
sensitive; normal continuous service logs omit the text, while diagnostic modes
can create private archives. The tray reports service state, not reachability.

## License and provenance

MIT; see [LICENSE](LICENSE), [additional attribution](LICENSES/omdrop-plugin-MIT.txt),
and [source and research references](docs/provenance.md). This is an unofficial
research project, unaffiliated with Apple. Use only devices and accounts you control.

## Optional retained connection with BLE hints

An experimental faster receiver keeps one authenticated connection and uses
fresh BLE copy hints to request supported text or inline PNG. It still requires the manual trust and
Mac IDS bootstrap above. **The fast path has fetched exact synthetic iPhone text
128 ms after a BLE hint in a bounded no-write diagnostic; its continuous clipboard
write/paste path has not yet been validated on a live phone.** This is a fetch
measurement, not copy-to-paste latency or a performance guarantee.

To opt in, add both entries to your private installed configuration:

```json
{
  "ble_keys": "/ABSOLUTE/PRIVATE/target-continuity-ble-key.json",
  "peer_signing_fingerprint_file": "/ABSOLUTE/PRIVATE/target-signing-key-sha256.txt"
}
```

These entries supplement the existing configuration, not replace it. The BLE
key JSON must contain exactly one target key, in the existing keystore format
`{"keys":[{"id":"operator-label","key":"AES_KEY_HEX"}]}`. Obtain the key for your
own account/devices independently; exporting/enrolling it is not packaged here.
The fingerprint file contains the 64-character hexadecimal SHA-256 of the trusted
phone's long-term Ed25519 public key, not its ephemeral session key. A BLE key or
copy hint alone never authorizes clipboard content. The launcher rejects partial
fast-path configuration and malformed fingerprints.

Restart the user service after editing configuration. Removing both optional
entries restores the original receiver. The installer preserves existing config.
BlueZ and an available Bluetooth adapter are needed for BLE acceleration; missing
or failed scanning falls back to authenticated queries every five seconds on a
ready connection. This does not establish a connection if the phone never discovers
or contacts Linux. `ble-listen-probe --help` exposes a 2–60 second fallback setting
for direct CLI use; its bounded default does not write the clipboard. Writes
require both `--continuous` and `--copy-verified-text`.

Initial data establishes a baseline, duplicate text stays suppressed, and detected
local edits win. Metadata/content provider UUIDs are compared when metadata includes
a UUID; missing metadata UUIDs use compatibility behavior and do not prove ordering.
The fast receiver remains receive-only. The existing `--copy-verified-text` write
opt-in also enables validated PNG reception; no extra configuration is required.
Text is preferred if both text and PNG are advertised. The PNG-capable binary is
installed on the research system with its previous binary retained for rollback;
live iPhone image delivery and Linux → iPhone clipboard transfer remain unverified.
This public snapshot contains no reverse clipboard sender.

## PNG limits and local clipboard protection

Only `public.png` with inline extra-data type 2 is supported. PNG metadata and
content must agree on provider UUID, UTI and encoded size. Files must be static,
CRC-valid PNGs no larger than 1 MiB, 16 million pixels and 64 MiB decoded.
Animated PNG, JPEG/HEIC, file handles and streamed image transport are unsupported.

Local-change detection fingerprints the offered MIME set and supported text/PNG
bytes, including image changes alongside an unchanged text alternative. Reads
are bounded to two seconds, 8 MiB per supported format and 32 MiB total. Writes
use explicit `image/png`, an independent clipboard owner and exact typed readback.
Unreadable local selections fail closed. The first usable remote value after
startup establishes a baseline; copy a different value afterward. Logs contain
categories, byte counts and hashes, never image or text contents.

`ac-dc public-adapter-check --address YOUR_PUBLIC_MAC` performs read-only checks
for an experimental public-identity Bluetooth path. It requires matching public
identity, power/BR-EDR/LE enabled, privacy off and force-static off. Exact
force-static verification may use existing noninteractive sudo permission to read
one validated controller debugfs flag; no policy or controller settings change.
Unavailable verification fails closed. The command never advertises or offers
keys and does not establish cloud pairing. Default broadcast behavior is unchanged.
