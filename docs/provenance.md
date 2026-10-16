# Omdrop ideas and provenance

Reviewed plugin commit `daee7a3ed9620b5d1bad277f731fdf9eabc38d53` from
[brentkearney/omdrop-plugin](https://github.com/brentkearney/omdrop-plugin) (MIT).
The Rust receiver implements the documented wire formats; it does not execute
Omdrop's Python or shell tools.

| Idea | Implementation |
| --- | --- |
| Report observed state and unknown transport separately | `health.rs`, `awdlctl status/doctor/probe` |
| Separate privileged radio control and user application | standalone `brcmfmac-awdl` repository, JSON CLI |
| Bounded radio use and Wi-Fi-band restoration | `awdlctl window`, persisted connection-UUID journal |
| Peer registration and table inspection | `awdlctl peer`, `iovar awdl_peer_op`, `diagnose` |
| Firmware counter/election/advertiser decoding | driver `diagnostics.rs` |
| Management-frame endpoint discovery | driver `frames.rs`, `events`; application event fallback |
| Use observed channel schedules | `awdlctl schedule --frame`, explicit window schedule input |
| BlueZ advertisement lifecycle | `advertise.rs`, bounded duration and signal cleanup |
| Clipboard ownership beyond service lifetime | `clipboard_out.rs`, separate user unit |
| Shared-link/file-to-clipboard workflow | Rust `airdrop/` receiver |
| Current Airdrop-compatible chunked requests, DVZip, Ask-only links | `airdrop/http.rs`, `archive.rs`, `mod.rs` |

The radio-side protocol work comes from
[brentkearney/omdrop-awdl](https://github.com/brentkearney/omdrop-awdl) and earlier
[andreanicassio/brcmfmac-awdl](https://github.com/andreanicassio/brcmfmac-awdl).
GPL-derived driver tooling stays in the separate GPL repository.

Two upstream findings require careful interpretation: an iPhone accepted outbound
TCP/TLS/Discover despite file sending remaining incomplete; and successful
receiving with infrastructure Wi-Fi on 2.4 GHz still used mostly 5 GHz AWDL
slots. Neither finding establishes this project's BCM4378 interoperability.

Prior Continuity references remain relevant:
[handoff-ble-viewer](https://github.com/seemoo-lab/handoff-ble-viewer),
[handoff-authentication-swift](https://github.com/seemoo-lab/handoff-authentication-swift),
[apple-continuity-tools](https://github.com/seemoo-lab/apple-continuity-tools), and
[openwifipass](https://github.com/seemoo-lab/openwifipass).

## Airdrop-compatible sending and native UI

The Rust sender independently implements the Discover/Ask/Upload wire contract
observed in [OpenDrop](https://github.com/seemoo-lab/opendrop): self-signed
Everyone-mode TLS, binary-plist requests, regular-file metadata, and DVZip/CPIO
over chunked HTTP. OpenDrop is a research reference, not a runtime dependency;
its GPL Python implementation has not been incorporated into this MIT crate.
The inherited optional desktop UI uses Rust and GPUI. Firmware template/packet work remains in the GPL
driver repository.

The OPACK corrections cross-check [pyatv](https://github.com/postlund/pyatv/blob/master/pyatv/support/opack.py)'s
protocol encoding. See [protocol evidence](protocol-evidence.md) for clipboard references and validation boundaries.


## Clipboard additions and publication boundary

The additional Rust authentication, keyed-archive parser, listener, synchronization
policy, and process helpers were authored for this prototype using protocol
research and native observations. Historical Swift model coding keys are protocol
references; the Foundation fixture generator is our synthetic model source.
`wl-copy` is an external executable; its documented selection-owner behavior
informed lifecycle management, and its GPL C implementation is not included.

This repository is a clean source snapshot based on upstream commit
`c6c4a2154fdbb70657ecf653e0d05a8807cb3297`, plus local clipboard research changes.
Original upstream author attribution and license remain in `LICENSE`.
Upstream history is not republished: machine-specific notes, macOS tooling,
packaging, private research artifacts and prior commit metadata are excluded.
The current snapshot audit does not independently establish the provenance of
every historical upstream line. No Apple disassembly, binaries or SDK material
is distributed here.

The inherited AirDrop sender uses Hyper's connection API and tokio-openssl.
OpenDrop is a protocol research reference, not a runtime dependency; inherited
provenance records no incorporated GPL Python implementation. Separate GPL radio
driver tooling is not part of this repository. Cargo dependencies retain their
own licenses and are resolved by `Cargo.lock`.


The typed PNG receiver, local MIME fingerprinting and read-only Bluetooth
management checks were independently authored for this prototype. Linux/BlueZ
public API and source behavior informed the latter; no kernel/BlueZ source code
is bundled. The PNG decoder is the Rust `png` crate under its own license.
Private enrollment/registration implementations and their SSPL dependency tree
are excluded; this publication retains the MIT application boundary.
