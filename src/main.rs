//! Adhoc Cross-Device Connection protocol and diagnostic tools.
mod advert;
mod advertise;
mod airdrop;
mod auth_probe;
mod clipboard;
mod clipboard_out;
mod clipboard_sync;
mod companion;
mod companion_client;
mod daemon;
mod discover;
mod gcm;
mod health;
mod identity_init;
mod keystore;
mod listen_probe;
mod opack;
mod orchestrate;
mod pair_probe;
mod scan;
mod tlv8;
mod transfer;
mod transfer_ble;
#[cfg(feature = "desktop-ui")]
mod ui;
#[cfg(feature = "desktop-ui")]
mod ui_widgets;

use anyhow::Result;
use clap::{ArgAction, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ac-dc", version, about)]
struct Cli {
    /// Increase diagnostic logging (-v enables debug, -vv enables trace). RUST_LOG overrides this.
    #[arg(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create local Linux signing material; does not establish Apple-account trust.
    InitIdentity {
        /// New private identity file (created mode 0600, never overwritten).
        #[arg(long)]
        private: PathBuf,
        /// New provisioning file containing public key and sensitive device IRK.
        #[arg(long)]
        public: PathBuf,
    },
    /// Run the privileged local Airdrop-compatible protocol service.
    Daemon {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// Send a JSON command to the local Airdrop-compatible service.
    Ctl {
        op: String,
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        directory: Option<PathBuf>,
        #[arg(long)]
        file: Vec<PathBuf>,
        #[arg(long)]
        link: Vec<String>,
        #[arg(long)]
        seconds: Option<u64>,
        #[arg(long)]
        ble_wake: Option<bool>,
    },
    /// Open the native Airdrop-compatible send/receive window.
    #[cfg(feature = "desktop-ui")]
    Ui,
    /// Observe Pair-Verify M2 using only an optional public key; never send M3.
    Probe {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        /// Explicit peer Ed25519 public key: a raw 32-byte file or 64 hex characters.
        /// Verification stops after M2 and never sends M3.
        #[arg(long)]
        peer_public_key: Option<PathBuf>,
    },
    /// Complete Pair-Verify M1-M4 with a supplied RPIdentity, then close.
    AuthProbe {
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        /// RPIdentity JSON containing the local signing identity and trusted peer keys.
        #[arg(long)]
        identity: PathBuf,
    },
    /// Advertise a bounded inbound Pair-Verify diagnostic with explicit control opt-ins.
    ListenProbe {
        /// Explicit local IPv4 address belonging to --iface (no wildcard).
        #[arg(long)]
        bind: std::net::Ipv4Addr,
        #[arg(long)]
        iface: String,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=300))]
        seconds: u64,
        #[arg(long)]
        identity: PathBuf,
        /// Explicit JSON object of string TXT properties. Omitted means empty TXT.
        #[arg(long)]
        txt: Option<PathBuf>,
        /// After authentication, observe up to four encrypted control messages for ten seconds.
        #[arg(long)]
        observe_system_info: bool,
        /// Request pasteboard type metadata once after an authenticated system-info request.
        #[arg(long, requires = "observe_system_info")]
        probe_pasteboard_types: bool,
        /// Diagnostic only: private UUID file overriding advertised _idsID, never signing/requester identity.
        #[arg(long, requires = "observe_system_info")]
        system_info_ids_id_file: Option<PathBuf>,
        /// Await a correlated reply to our system-info request before querying types (8 messages/15 seconds).
        #[arg(long, requires = "probe_pasteboard_types")]
        system_info_readiness_barrier: bool,
        /// Fetch data once after successful type metadata; report only metadata and test-text match.
        #[arg(long, requires_all = ["probe_pasteboard_types", "system_info_readiness_barrier"])]
        probe_pasteboard_data: bool,
        /// Copy one authenticated, validated UTF-8 text result to Wayland and stop.
        #[arg(long, requires = "probe_pasteboard_data")]
        copy_verified_text: bool,
        /// Keep serving authenticated clipboard connections until stopped.
        #[arg(long, requires = "copy_verified_text")]
        continuous: bool,
    },
    /// Discover nearby Everyone-mode Airdrop-compatible recipients.
    Peers {
        #[arg(long, default_value = "awdl0")]
        iface: String,
        #[arg(long)]
        tls_identity: PathBuf,
    },
    /// Send files or HTTP(S) links to a selected Airdrop-compatible endpoint.
    Send {
        #[arg(long)]
        host: String,
        #[arg(long, default_value_t = 8770)]
        port: u16,
        #[arg(long)]
        tls_identity: PathBuf,
        #[arg(long, default_value = "Linux")]
        name: String,
        #[arg(long)]
        url: Vec<String>,
        files: Vec<PathBuf>,
    },
    /// Scan for and decrypt Handoff / Universal Clipboard BLE adverts.
    Scan {
        /// Path to the key file exported from macOS (see macos/export-keys.sh).
        #[arg(short, long, default_value = "keys.json")]
        keys: PathBuf,
    },
    /// Capture raw Handoff adverts as hex (no keys needed), to grab a packet
    /// for validating the decrypt against your own devices.
    Capture,
    /// Browse for `_companion-link._tcp` over mDNS (no keys needed). The live
    /// test of whether the M2 content channel is reachable over plain LAN vs.
    /// AWDL-only. See src/discover.rs.
    Discover {
        #[arg(long, default_value = "awdl0")]
        iface: String,
        #[arg(long)]
        lan: bool,
    },
    /// Report missing runtime prerequisites without changing the radio.
    Doctor {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        keys: Option<PathBuf>,
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Report observed AWDL state; link readiness is not proof of transport.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Register captured/reconstructed Apple TLVs through BlueZ for a bounded experiment.
    Advertise {
        #[arg(
            long,
            required_unless_present = "airdrop_wake",
            conflicts_with = "airdrop_wake"
        )]
        data: Option<String>,
        #[arg(long)]
        airdrop_wake: bool,
        #[arg(long, default_value_t = 30)]
        seconds: u64,
        #[arg(long, default_value_t = 100)]
        interval_ms: u64,
    },
    /// Receive Airdrop-compatible links/files for a bounded Everyone-mode window (experimental).
    Receive {
        #[arg(long, default_value = "awdl0")]
        iface: String,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        tls_identity: PathBuf,
        #[arg(long, default_value = "ac-dc")]
        name: String,
        #[arg(long, default_value_t = 8771)]
        port: u16,
        #[arg(long, default_value_t = 600)]
        seconds: u64,
        #[arg(long)]
        once: bool,
        #[arg(long)]
        notify: bool,
        /// Advertise a Bluetooth wake hint during receiving.
        #[arg(long)]
        ble_wake: bool,
    },
    /// Receive an exported `keys.json` from a Mac over Bluetooth LE.
    ///
    /// Runs a GATT server; on the Mac run `ac-dc send-key`. An ephemeral X25519
    /// handshake protects the untrusted BLE link; both ends print a 6-digit
    /// code (SAS) that you must compare before confirming. keys.json is written
    /// (mode 0600) only after you confirm the codes matched.
    ReceiveKey {
        /// Where to write the received key file.
        #[arg(short, long, default_value = "keys.json")]
        out: PathBuf,
    },
    /// Decrypt a single advertisement supplied as a hex string (offline test).
    Decrypt {
        #[arg(short, long)]
        keys: PathBuf,
        /// Manufacturer data hex, e.g. "0c0e082a0099dead...".
        #[arg(short, long)]
        data: String,
    },
    /// Milestone 2: pull Universal Clipboard content over companion-link.
    ///
    /// Run TCP, Pair-Verify, then source-backed clipboard requests. A real
    /// peer requires trusted signing identities and validated request context.
    /// An explicit port can select a LAN endpoint; clipboard interoperability
    /// on that route is still experimental. --loopback uses a synthetic peer.
    Pull {
        /// Peer address. Normally supplied later by `discover` over awdl0.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Peer companion-link TCP port.
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// BLE keystore path (kept for CLI parity; used as the identity source
        /// if --identity is not given). See macos/export-keys.sh.
        #[arg(short, long, default_value = "keys.json")]
        keys: PathBuf,
        /// RPIdentity keys (Ed25519 signing key + known peers) for Pair-Verify.
        /// See macos/RPIDENTITY.md for the exporter and expected schema.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Sender identifier and advertisement bytes from a validated request context.
        #[arg(long, required_unless_present = "loopback")]
        requester_id: Option<String>,
        #[arg(long, required_unless_present = "loopback")]
        advertisement_payload: Option<String>,
        #[arg(long, default_value = "pbpaste2", value_parser = ["pbtypes", "pbpaste2"])]
        clipboard_command: String,
        /// Run against an in-process loopback mock peer (no network, no keys).
        #[arg(long)]
        loopback: bool,
        /// Fresh JSONL from awdlctl events, used if mDNS resolution fails.
        #[arg(long, requires = "peer_mac")]
        events: Option<PathBuf>,
        #[arg(long)]
        peer_mac: Option<String>,
    },
    /// Experimental BLE-triggered pulls using one fixed, manually supplied request context.
    Auto {
        #[arg(long, default_value = "keys.json")]
        keys: PathBuf,
        /// Explicit mDNS instance; otherwise match the triggering BLE address to rpBA.
        #[arg(long)]
        instance: Option<String>,
        #[arg(long)]
        notify: bool,
        /// RPIdentity keys for Pair-Verify (real flow only).
        #[arg(long, default_value = "keys.json")]
        identity: PathBuf,
        #[arg(long, required_unless_present = "loopback")]
        requester_id: Option<String>,
        #[arg(long, required_unless_present = "loopback")]
        advertisement_payload: Option<String>,
        /// Drive the wiring against the in-process loopback mock (no AWDL).
        #[arg(long)]
        loopback: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let default_filter = match cli.verbose {
        0 => "ac_dc=info",
        1 => "ac_dc=debug",
        _ => "ac_dc=trace",
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| default_filter.into()),
        )
        .init();

    tracing::debug!(verbose = cli.verbose, command = ?cli.cmd, "ac-dc command starting");
    // `ui::run` owns the main thread for the window loop and drives its own
    // runtime, joining the engine with `block_on` once the window closes. That
    // panics inside a runtime context, so the UI must be dispatched before one
    // exists rather than from an async main.
    match cli.cmd {
        #[cfg(feature = "desktop-ui")]
        Cmd::Ui => ui::run(),
        cmd => tokio::runtime::Runtime::new()?.block_on(command(cmd)),
    }
}

async fn command(cmd: Cmd) -> Result<()> {
    match cmd {
        #[cfg(feature = "desktop-ui")]
        Cmd::Ui => unreachable!("dispatched by main before the runtime starts"),
        Cmd::Probe {
            host,
            port,
            peer_public_key,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &pair_probe::run(&host, port, peer_public_key.as_deref()).await?
                )?
            );
        }
        Cmd::AuthProbe {
            host,
            port,
            identity,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&auth_probe::run(&host, port, &identity).await?)?
            );
        }
        Cmd::ListenProbe {
            bind,
            iface,
            port,
            seconds,
            identity,
            txt,
            observe_system_info,
            probe_pasteboard_types,
            system_info_ids_id_file,
            system_info_readiness_barrier,
            probe_pasteboard_data,
            copy_verified_text,
            continuous,
        } => {
            listen_probe::run(listen_probe::Config {
                bind,
                iface,
                port,
                seconds,
                identity,
                txt,
                observe_system_info,
                probe_pasteboard_types,
                system_info_ids_id_file,
                system_info_readiness_barrier,
                probe_pasteboard_data,
                copy_verified_text,
                continuous,
            })
            .await?;
        }
        Cmd::InitIdentity { private, public } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&identity_init::generate(&private, &public)?)?
            );
        }
        Cmd::Daemon { socket } => {
            daemon::run(socket.unwrap_or_else(daemon::default_socket)).await?
        }
        Cmd::Ctl {
            op,
            host,
            port,
            name,
            directory,
            file,
            link,
            seconds,
            ble_wake,
        } => {
            let reply = daemon::ctl(
                daemon::default_socket(),
                daemon::Request {
                    op,
                    host,
                    port,
                    name,
                    directory,
                    files: file,
                    links: link,
                    seconds,
                    ble_wake,
                },
            )
            .await?;
            println!("{}", serde_json::to_string(&reply)?);
        }
        Cmd::Peers {
            iface,
            tls_identity,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &airdrop::peers::browse(&iface, &tls_identity, 8).await?
                )?
            );
        }
        Cmd::Send {
            host,
            port,
            tls_identity,
            name,
            url,
            files,
        } => {
            let address = discover::socket_target(&host, port).await?;
            let client = airdrop::send::Client::new(address, &tls_identity)?;
            let receiver = client.discover().await?;
            tracing::info!(receiver, "Sending Airdrop-compatible transfer");
            client.transfer(&name, files, url).await?;
            println!("Transfer accepted by {receiver}");
        }
        Cmd::Receive {
            iface,
            directory,
            tls_identity,
            name,
            port,
            seconds,
            once,
            notify,
            ble_wake,
        } => {
            airdrop::run(airdrop::Config {
                radio_managed: false,
                ble_wake,
                approval: None,
                iface,
                directory,
                identity: tls_identity,
                name,
                port,
                seconds,
                once,
                notify,
                open_destination: true,
            })
            .await?;
        }
        Cmd::Doctor {
            json,
            keys,
            identity,
        } => {
            let report = health::report(keys.as_deref(), identity.as_deref()).await;
            println!(
                "{}",
                if json {
                    serde_json::to_string(&report)?
                } else {
                    serde_json::to_string_pretty(&report)?
                }
            );
        }
        Cmd::Status { json } => {
            let report = health::radio().await?;
            println!(
                "{}",
                if json {
                    serde_json::to_string(&report)?
                } else {
                    serde_json::to_string_pretty(&report)?
                }
            );
        }
        Cmd::Advertise {
            data,
            airdrop_wake,
            seconds,
            interval_ms,
        } => {
            let data = if airdrop_wake {
                advertise::airdrop_wake()
            } else {
                hex::decode(data.unwrap_or_default())?
            };
            advertise::broadcast(data, seconds, interval_ms).await?;
        }
        Cmd::Scan { keys } => {
            let store = keystore::KeyStore::load(&keys)?;
            if store.is_empty() {
                tracing::warn!("no keys loaded; adverts will be detected but not decrypted");
            } else {
                tracing::info!(count = store.keys.len(), "loaded keys");
            }
            let scanner = scan::Scanner::new(store).await?;
            tokio::select! {
                r = scanner.run() => r?,
                _ = shutdown() => tracing::info!("stopping"),
            }
        }
        Cmd::Capture => {
            let scanner = scan::Scanner::new_capture().await?;
            tokio::select! {
                r = scanner.run_capture() => r?,
                _ = shutdown() => tracing::info!("stopping"),
            }
        }
        Cmd::Discover { iface, lan } => {
            tokio::select! {
                r = discover::run(if lan { None } else { Some(&iface) }) => r?,
                _ = shutdown() => tracing::info!("stopping"),
            }
        }
        Cmd::ReceiveKey { out } => {
            tokio::select! {
                r = transfer_ble::receive_key(&out) => r?,
                _ = shutdown() => tracing::info!("stopping"),
            }
        }
        Cmd::Decrypt { keys, data } => {
            let store = keystore::KeyStore::load(&keys)?;
            let bytes = hex::decode(data.trim())?;
            let ble = advert::HandoffBle::parse(&bytes)
                .ok_or_else(|| anyhow::anyhow!("not a Handoff advertisement"))?;
            let mut ok = false;
            for k in &store.keys {
                if let Some(plain) = gcm::open_truncated(
                    &k.key,
                    &ble.counter_iv,
                    &[ble.status],
                    &ble.ciphertext,
                    &ble.tag,
                )? {
                    let payload = advert::HandoffPayload::parse(&plain);
                    println!("decrypted with key {}: {}", k.id, hex::encode(&plain));
                    if let Some(p) = payload {
                        println!(
                            "  clipboard_available={} url={} activity_hash={}",
                            p.flags.clipboard_available(),
                            p.flags.has_url(),
                            hex::encode(p.activity_hash)
                        );
                    }
                    ok = true;
                    break;
                }
            }
            if !ok {
                println!("no key authenticated this advertisement");
            }
        }
        Cmd::Pull {
            host,
            port,
            keys,
            identity,
            loopback,
            events,
            peer_mac,
            requester_id,
            advertisement_payload,
            clipboard_command,
        } => {
            if loopback {
                tracing::info!("running companion-link pull against in-process loopback mock");
                let (peer, board) = companion_client::loopback_demo().await?;
                print_pasteboard(&peer, &board);
                land_on_clipboard(&board);
                return Ok(());
            }

            // Once awdl0 is up, `companion_link_target` resolves
            // `_companion-link._tcp` scoped to it (a non-zero --port is still a
            // manual override). See src/discover.rs and docs/architecture.md §4.
            let (host, port) = match discover::companion_link_target(&host, port).await {
                Ok(target) => target,
                Err(e) => {
                    if let Some(path) = events {
                        tracing::warn!(error=%e, "mDNS failed; checking captured management-frame service records");
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_millis() as u64;
                        discover::from_events(
                            &path,
                            peer_mac.as_deref().unwrap_or(""),
                            "awdl0",
                            now,
                        )?
                    } else {
                        return Err(e);
                    }
                }
            };

            // Pair-Verify uses a separate RPIdentity export, not the BLE key schema.
            let identity_path = identity.unwrap_or(keys);
            let ident = companion::PairingIdentity::load(&identity_path)?;

            tracing::info!(%host, port, "connecting to selected companion-link endpoint");
            let mut session = companion_client::connect(&host, port, ident).await?;
            let peer = session
                .system_info_exchange(&companion_client::SystemInfo {
                    name: "ac-dc (Linux)".into(),
                    model: "ac-dc,client".into(),
                    os_version: env!("CARGO_PKG_VERSION").into(),
                })
                .await?;
            let requester_id = requester_id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing requester id"))?;
            let advertisement_payload =
                hex::decode(advertisement_payload.as_deref().unwrap_or_default())?;
            if clipboard_command == clipboard::COMMAND_PB_TYPES {
                let metadata = session
                    .fetch_pasteboard_metadata_with(requester_id, &advertisement_payload)
                    .await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "protocol_version": metadata.protocol_version,
                        "extra_data_type": metadata.extra_data_type,
                        "data_size": metadata.data_size,
                        "representations": metadata.representations.iter().map(|item| serde_json::json!({
                            "uti": item.uti, "offset": item.offset, "size": item.size,
                            "inline_data_available": item.data.is_some(),
                        })).collect::<Vec<_>>(),
                    }))?
                );
                return Ok(());
            }
            let board = session
                .fetch_pasteboard_with(requester_id, &advertisement_payload, &clipboard_command)
                .await?;
            print_pasteboard(&peer, &board);
            land_on_clipboard(&board);
        }
        Cmd::Auto {
            keys,
            identity,
            instance,
            loopback,
            notify,
            requester_id,
            advertisement_payload,
        } => {
            orchestrate::run(orchestrate::AutoConfig {
                keys,
                identity_path: identity,
                instance,
                loopback,
                notify,
                requester_id,
                advertisement_payload,
            })
            .await?;
        }
    }
    Ok(())
}

/// Put a successfully fetched pasteboard on the Wayland clipboard via
/// `clipboard_out`, printing what was copied. Best-effort: a clipboard failure
/// is logged, not fatal, since the fetch itself already succeeded.
fn land_on_clipboard(board: &companion_client::Pasteboard) {
    match clipboard_out::copy_pasteboard(board) {
        Ok(Some(outcome)) => println!("clipboard: copied {}", outcome.describe()),
        Ok(None) => println!("clipboard: nothing to copy (empty pasteboard)"),
        Err(e) => tracing::error!(error = %e, "failed to put pasteboard on the clipboard"),
    }
}

/// Print a fetched pasteboard and the peer's system info to stdout.
fn print_pasteboard(peer: &companion_client::SystemInfo, board: &companion_client::Pasteboard) {
    println!(
        "peer: name={:?} model={:?} os={:?}",
        peer.name, peer.model, peer.os_version
    );
    if board.items.is_empty() {
        println!("pasteboard: (empty)");
    }
    for (i, item) in board.items.iter().enumerate() {
        match std::str::from_utf8(&item.data) {
            Ok(s) if item.uti.contains("text") => {
                println!("item[{i}] {} ({} bytes): {s:?}", item.uti, item.data.len());
            }
            _ => {
                println!(
                    "item[{i}] {} ({} bytes): {}",
                    item.uti,
                    item.data.len(),
                    hex::encode(&item.data)
                );
            }
        }
    }
}

/// Handle service termination as well as interactive cancellation.
async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
}
