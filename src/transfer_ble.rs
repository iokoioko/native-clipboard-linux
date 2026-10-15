//! Bluetooth LE transport for `ac-dc receive-key` (the Linux side of the key
//! transfer). This is the GATT *server*; the macOS `ac-dc send-key` helper is
//! the GATT central that connects to it.
//!
//! ⚠️ UNVALIDATED AGAINST HARDWARE. None of the BlueZ/GATT plumbing in this file
//! has been exercised against a real Bluetooth adapter or a real macOS central
//! yet — only the crypto/framing core in `transfer.rs` is unit-tested. Treat
//! this as "plausibly correct, unverified" (the same status the rest of the
//! project's BLE code carries). All security-relevant logic is kept in
//! `transfer.rs` precisely so the tests cover it; this file only moves bytes.
//!
//! See the WIRE FORMAT block in `transfer.rs` for the exact handshake order and
//! chunk layout. The macOS counterpart mirrors it.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use bluer::adv::Advertisement;
use bluer::gatt::local::{
    Application, Characteristic, CharacteristicRead, CharacteristicWrite,
    CharacteristicWriteMethod, Service,
};
use bluer::Uuid;
use futures::FutureExt;
use tokio::sync::{Mutex, Notify};

use crate::transfer::{self, EphemeralKeyPair, Reassembler, KEY_LEN};

// ---------------------------------------------------------------------------
// Hardcoded custom 128-bit UUIDs for the key-transfer GATT service.
//
// These are private random UUIDs invented for this project (NOT assigned by the
// Bluetooth SIG and NOT any Apple service). The macOS `send-key` helper scans
// for SERVICE_UUID and must use the same characteristic UUIDs. Their canonical
// string forms (used verbatim in the Swift helper) are:
//   service       ACDC5A5A-7C1D-4E2B-9F00-000000000001
//   receiver pub  ACDC5A5A-7C1D-4E2B-9F00-000000000002
//   sender pub    ACDC5A5A-7C1D-4E2B-9F00-000000000003
//   payload       ACDC5A5A-7C1D-4E2B-9F00-000000000004
// ---------------------------------------------------------------------------

/// The key-transfer GATT service.
const SERVICE_UUID: Uuid = Uuid::from_u128(0xacdc_5a5a_7c1d_4e2b_9f00_0000_0000_0001);
/// Receiver's ephemeral X25519 public key (32 bytes, read by the sender).
const RECEIVER_PUB_UUID: Uuid = Uuid::from_u128(0xacdc_5a5a_7c1d_4e2b_9f00_0000_0000_0002);
/// Sender's ephemeral X25519 public key (32 bytes, written by the sender).
const SENDER_PUB_UUID: Uuid = Uuid::from_u128(0xacdc_5a5a_7c1d_4e2b_9f00_0000_0000_0003);
/// Chunked, length-prefixed sealed payload (written by the sender, one frame
/// per GATT write). See `transfer::frame_payload`.
const PAYLOAD_UUID: Uuid = Uuid::from_u128(0xacdc_5a5a_7c1d_4e2b_9f00_0000_0000_0004);

/// Shared state the GATT write callbacks populate; the main task waits on it.
#[derive(Default)]
struct Inbound {
    sender_pub: Mutex<Option<[u8; KEY_LEN]>>,
    reassembler: Mutex<Reassembler>,
}

/// Run the Linux receiver: advertise the GATT service, complete the handshake,
/// confirm the SAS interactively, decrypt, and write `out` at mode 0600.
pub async fn receive_key(out: &Path) -> Result<()> {
    let keypair = EphemeralKeyPair::generate();
    let receiver_pub = keypair.public_bytes();

    let session = bluer::Session::new()
        .await
        .context("opening BlueZ session")?;
    let adapter = session
        .default_adapter()
        .await
        .context("getting default Bluetooth adapter")?;
    adapter
        .set_powered(true)
        .await
        .context("powering on adapter")?;
    tracing::info!(adapter = %adapter.name(), "receive-key: serving GATT key-transfer service");

    let inbound = Arc::new(Inbound::default());
    let notify = Arc::new(Notify::new());

    let app = build_application(receiver_pub, inbound.clone(), notify.clone());
    let _app_handle = adapter
        .serve_gatt_application(app)
        .await
        .context("registering GATT application")?;

    let adv = Advertisement {
        service_uuids: vec![SERVICE_UUID].into_iter().collect(),
        discoverable: Some(true),
        local_name: Some("ac-dc receive-key".to_string()),
        ..Default::default()
    };
    let _adv_handle = adapter
        .advertise(adv)
        .await
        .context("starting LE advertisement")?;

    println!("Waiting for a Mac running `ac-dc send-key` to connect over Bluetooth...");
    println!("(Ctrl-C to abort.)");

    // Wait until the sender pubkey has arrived AND the payload is fully
    // reassembled. Each relevant GATT write wakes us.
    let (sender_pub, sealed) = loop {
        notify.notified().await;
        let sp = *inbound.sender_pub.lock().await;
        let reasm = inbound.reassembler.lock().await;
        if let (Some(sp), true) = (sp, reasm.is_complete()) {
            let sealed = reasm
                .take_payload()
                .ok_or_else(|| anyhow!("payload reported complete but could not be taken"))?;
            break (sp, sealed);
        }
    };

    // Derive the session key and SAS (fixed transcript order: receiver||sender).
    let shared = keypair.agree(&sender_pub);
    let key = transfer::session_key(&shared, &receiver_pub, &sender_pub);
    let sas = transfer::sas(&receiver_pub, &sender_pub);

    println!();
    println!("  Security code (SAS): {sas}");
    println!();
    println!("Compare this with the code shown on the Mac. They MUST be identical.");

    if !confirm_match().await? {
        anyhow::bail!("aborted: security codes did not match (possible man-in-the-middle)");
    }

    let plaintext = transfer::open(&key, &sealed)
        .context("decrypting received payload (bad tag: wrong code or tampering)")?;

    write_0600(out, &plaintext).with_context(|| format!("writing {}", out.display()))?;
    println!(
        "Wrote {} ({} bytes, mode 0600).",
        out.display(),
        plaintext.len()
    );
    Ok(())
}

/// Build the GATT application: receiver pubkey (read), sender pubkey (write),
/// and chunked payload (write).
fn build_application(
    receiver_pub: [u8; KEY_LEN],
    inbound: Arc<Inbound>,
    notify: Arc<Notify>,
) -> Application {
    // Receiver public key: readable by the sender.
    let receiver_pub_char = Characteristic {
        uuid: RECEIVER_PUB_UUID,
        read: Some(CharacteristicRead {
            read: true,
            fun: Box::new(move |_req| async move { Ok(receiver_pub.to_vec()) }.boxed()),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Sender public key: written once by the sender.
    let sender_inbound = inbound.clone();
    let sender_notify = notify.clone();
    let sender_pub_char = Characteristic {
        uuid: SENDER_PUB_UUID,
        write: Some(CharacteristicWrite {
            write: true,
            write_without_response: true,
            method: CharacteristicWriteMethod::Fun(Box::new(move |value, _req| {
                let inbound = sender_inbound.clone();
                let notify = sender_notify.clone();
                async move {
                    match <[u8; KEY_LEN]>::try_from(value.as_slice()) {
                        Ok(pk) => {
                            *inbound.sender_pub.lock().await = Some(pk);
                            notify.notify_one();
                            Ok(())
                        }
                        Err(_) => {
                            tracing::warn!(len = value.len(), "sender pubkey wrong length");
                            // Reject malformed writes at the GATT layer.
                            Err(bluer::gatt::local::ReqError::NotSupported)
                        }
                    }
                }
                .boxed()
            })),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Chunked sealed payload: one frame per write.
    let payload_inbound = inbound;
    let payload_notify = notify;
    let payload_char = Characteristic {
        uuid: PAYLOAD_UUID,
        write: Some(CharacteristicWrite {
            write: true,
            write_without_response: true,
            method: CharacteristicWriteMethod::Fun(Box::new(move |value, _req| {
                let inbound = payload_inbound.clone();
                let notify = payload_notify.clone();
                async move {
                    let mut reasm = inbound.reassembler.lock().await;
                    if let Err(e) = reasm.push_frame(&value) {
                        tracing::warn!(error = %e, "bad payload frame");
                        return Err(bluer::gatt::local::ReqError::NotSupported);
                    }
                    drop(reasm);
                    notify.notify_one();
                    Ok(())
                }
                .boxed()
            })),
            ..Default::default()
        }),
        ..Default::default()
    };

    Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![receiver_pub_char, sender_pub_char, payload_char],
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// Interactive y/N confirmation that the SAS matched. Reads stdin on a blocking
/// thread so we don't stall the tokio runtime.
async fn confirm_match() -> Result<bool> {
    tokio::task::spawn_blocking(|| {
        use std::io::Write;
        print!("Do the codes match? Type y to accept and write the key file [y/N]: ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
    })
    .await
    .context("reading confirmation")?
}

/// Write `data` to `path`, creating it with mode 0600 (and tightening an
/// existing file to 0600 as well).
fn write_0600(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data)?;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}
