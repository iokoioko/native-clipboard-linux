//! BLE scanning via BlueZ (D-Bus). Listens for Apple manufacturer data, tries
//! to parse it as a Handoff/Universal-Clipboard advertisement, and (in scan
//! mode) decrypts it with every key we hold until one authenticates.
//!
//! Two modes share the discovery loop:
//!   * `run()` – decrypt-and-report (needs keys).
//!   * `run_capture()` – print each raw Handoff advert as hex, ready to paste
//!     into `ac-dc decrypt --data <hex>`. Needs no keys; used to grab a
//!     validation packet from your own devices.

use anyhow::{Context, Result};
use bluer::{Adapter, AdapterEvent, DeviceEvent, DeviceProperty};
use futures::{pin_mut, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::advert::{self, HandoffBle, HandoffPayload};
use crate::gcm;
use crate::keystore::{HandoffKey, KeyStore};

/// Per-device dedupe state: last (counter, activity_hash) seen for each key id.
/// Keying on the device *key* (not the BLE address) collapses both Apple's
/// address rotation and the constant re-broadcasts into one line per real copy.
type SeenMap = Arc<Mutex<HashMap<String, (u16, [u8; 7])>>>;

#[derive(Debug, Clone)]
pub struct CopyEvent {
    pub device: String,
    pub address: String,
    pub key_id: String,
    pub activity: String,
    /// BlueZ Apple manufacturer data bytes, preserving the exact Handoff TLV
    /// observed for this event (BlueZ has already removed company ID 0x004c).
    pub raw_advertisement: Vec<u8>,
    pub status: u8,
    /// The two counter bytes exactly as observed on the wire (little-endian).
    pub counter_iv: [u8; 2],
    /// Plaintext returned by successful BLE GCM verification. This is the
    /// activity metadata payload, not clipboard content.
    pub decrypted_payload: Vec<u8>,
    /// Preserve the complete raw flags byte, including bits not yet modeled.
    pub flags: u8,
    /// Unix milliseconds when this advertisement was received from BlueZ.
    pub observed_at_unix_ms: u64,
}

pub struct Scanner {
    adapter: Adapter,
    keys: Vec<HandoffKey>,
    capture: bool,
    seen: SeenMap,
    events: Option<tokio::sync::mpsc::Sender<CopyEvent>>,
}

impl Scanner {
    pub async fn new(store: KeyStore) -> Result<Self> {
        Self::build(store.keys, false).await
    }

    /// Keyless capture mode: just surface raw Handoff adverts as hex.
    pub async fn new_capture() -> Result<Self> {
        Self::build(Vec::new(), true).await
    }

    async fn build(keys: Vec<HandoffKey>, capture: bool) -> Result<Self> {
        let session = bluer::Session::new()
            .await
            .context("connecting to bluetoothd")?;
        let adapter = session.default_adapter().await.context("no BLE adapter")?;
        adapter
            .set_powered(true)
            .await
            .context("powering on adapter")?;
        tracing::info!(adapter = %adapter.name(), "using BLE adapter");
        Ok(Scanner {
            adapter,
            keys,
            capture,
            seen: Arc::new(Mutex::new(HashMap::new())),
            events: None,
        })
    }

    pub fn with_events(mut self, events: tokio::sync::mpsc::Sender<CopyEvent>) -> Self {
        self.events = Some(events);
        self
    }

    pub async fn run(&self) -> Result<()> {
        tracing::info!("scanning for Apple Continuity advertisements (Ctrl-C to stop)");
        self.discover_loop().await
    }

    pub async fn run_capture(&self) -> Result<()> {
        tracing::info!("capture mode: printing raw Handoff adverts (Ctrl-C to stop)");
        println!("# paste a line into: ac-dc decrypt --keys keys.json --data <hex>");
        self.discover_loop().await
    }

    async fn discover_loop(&self) -> Result<()> {
        let discover = self.adapter.discover_devices().await?;
        pin_mut!(discover);

        while let Some(evt) = discover.next().await {
            let AdapterEvent::DeviceAdded(addr) = evt else {
                continue;
            };
            let device = match self.adapter.device(addr) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if let Ok(Some(md)) = device.manufacturer_data().await {
                self.worker().handle(addr, &md).await;
            }
            let events = match device.events().await {
                Ok(e) => e,
                Err(_) => continue,
            };
            // One lightweight follower per device so several phones/Macs can
            // announce concurrently.
            let worker = self.worker();
            tokio::spawn(async move {
                pin_mut!(events);
                while let Some(ev) = events.next().await {
                    if let DeviceEvent::PropertyChanged(DeviceProperty::ManufacturerData(md)) = ev {
                        worker.handle(addr, &md).await;
                    }
                }
            });
        }
        Ok(())
    }

    fn worker(&self) -> Worker {
        Worker {
            keys: self.keys.clone(),
            capture: self.capture,
            adapter: self.adapter.clone(),
            seen: self.seen.clone(),
            events: self.events.clone(),
        }
    }
}

#[derive(Clone)]
struct Worker {
    keys: Vec<HandoffKey>,
    capture: bool,
    adapter: Adapter,
    seen: SeenMap,
    events: Option<tokio::sync::mpsc::Sender<CopyEvent>>,
}

impl Worker {
    async fn handle(&self, addr: bluer::Address, md: &HashMap<u16, Vec<u8>>) {
        let Some(data) = advert::apple_manufacturer_data(md) else {
            return;
        };
        let observed_at_unix_ms = unix_timestamp_ms();
        let Some(ble) = HandoffBle::parse(data) else {
            return;
        };
        tracing::debug!(%addr, status = ble.status, ctr = ?ble.counter_iv, "handoff advert");

        if self.capture {
            self.capture_line(addr, data, &ble);
            return;
        }

        // Try each key until the 1-byte tag authenticates.
        for k in &self.keys {
            let plain = match gcm::open_truncated(
                &k.key,
                &ble.counter_iv,
                &[ble.status],
                &ble.ciphertext,
                &ble.tag,
            ) {
                Ok(Some(plain)) => plain,
                Ok(None) => continue,
                Err(e) => {
                    tracing::error!(key = %k.id, error = %e, "skipping key");
                    continue;
                }
            };
            if let Some(payload) = HandoffPayload::parse(&plain) {
                let counter = u16::from_le_bytes(ble.counter_iv);
                self.report(
                    addr,
                    &k.id,
                    counter,
                    &payload,
                    data,
                    &ble,
                    &plain,
                    observed_at_unix_ms,
                )
                .await;
                return;
            }
        }
    }

    /// Print a raw advert for offline validation. We emit the normalized
    /// `0c ..` TLV (what `decrypt --data` and `HandoffBle::parse` accept),
    /// plus the decoded framing so byte-order assumptions can be eyeballed.
    fn capture_line(&self, addr: bluer::Address, raw: &[u8], ble: &HandoffBle) {
        let mut tlv = Vec::with_capacity(2 + ble.ciphertext.len() + 4);
        let len = (1 + 2 + 1 + ble.ciphertext.len()) as u8; // status+iv+tag+ct
        tlv.push(0x0c);
        tlv.push(len);
        tlv.push(ble.status);
        tlv.extend_from_slice(&ble.counter_iv);
        tlv.extend_from_slice(&ble.tag);
        tlv.extend_from_slice(&ble.ciphertext);
        println!(
            "{addr}  {tlv}   # raw_mfg={raw} status={status:#04x} iv={iv} tag={tag} ct={ct}",
            addr = addr,
            tlv = hex::encode(&tlv),
            raw = hex::encode(raw),
            status = ble.status,
            iv = hex::encode(ble.counter_iv),
            tag = hex::encode(ble.tag),
            ct = hex::encode(&ble.ciphertext),
        );
    }

    async fn report(
        &self,
        addr: bluer::Address,
        key_id: &str,
        counter: u16,
        p: &HandoffPayload,
        raw_advertisement: &[u8],
        ble: &HandoffBle,
        decrypted_payload: &[u8],
        observed_at_unix_ms: u64,
    ) {
        if !p.flags.clipboard_available() {
            tracing::debug!(%addr, key = key_id, "handoff advert without clipboard flag");
            return;
        }

        // Collapse address rotation + re-broadcasts: one line per (device, copy).
        {
            let sig = (counter, p.activity_hash);
            let mut seen = self.seen.lock().await;
            if seen.get(key_id) == Some(&sig) {
                return;
            }
            seen.insert(key_id.to_string(), sig);
        }

        let who = self.device_label(addr).await;
        let activity = p.activity_label();
        tracing::info!(
            %addr,
            device = %who,
            key = key_id,
            activity = %activity,
            "CLIPBOARD AVAILABLE"
        );
        if let Some(events) = &self.events {
            let event = copy_event(
                who.clone(),
                addr.to_string(),
                key_id,
                &activity,
                raw_advertisement,
                ble,
                decrypted_payload,
                p.flags.raw,
                observed_at_unix_ms,
            );
            if let Err(e) = events.try_send(event) {
                tracing::warn!(error = %e, "copy event queue full or closed");
            }
        } else {
            println!("📋  {who} copied — {activity}   [device key {key_id}]");
        }
    }

    /// A friendly name for the advertiser if BlueZ knows one (e.g. a paired
    /// iPhone/Mac), else its Bluetooth address. Handoff advertisers usually
    /// expose no name, so this is often the (rotating) address.
    async fn device_label(&self, addr: bluer::Address) -> String {
        if let Ok(dev) = self.adapter.device(addr) {
            if let Ok(Some(name)) = dev.name().await {
                if !name.is_empty() {
                    return name;
                }
            }
            if let Ok(alias) = dev.alias().await {
                if !alias.is_empty() && alias != addr.to_string() {
                    return alias;
                }
            }
        }
        addr.to_string()
    }
}

fn copy_event(
    device: String,
    address: String,
    key_id: &str,
    activity: &str,
    raw_advertisement: &[u8],
    ble: &HandoffBle,
    decrypted_payload: &[u8],
    flags: u8,
    observed_at_unix_ms: u64,
) -> CopyEvent {
    CopyEvent {
        device,
        address,
        key_id: key_id.into(),
        activity: activity.into(),
        raw_advertisement: raw_advertisement.to_vec(),
        status: ble.status,
        counter_iv: ble.counter_iv,
        decrypted_payload: decrypted_payload.to_vec(),
        flags,
        observed_at_unix_ms,
    }
}

fn unix_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod event_tests {
    use super::*;
    use crate::advert::HandoffFlags;

    #[test]
    fn preserves_synthetic_handoff_event_context() {
        let key = [0x42; 16];
        let status = 0x08;
        let counter_iv = [0x34, 0x12];
        let mut plaintext = vec![status, 1, 2, 3, 4, 5, 6, 7, 0x28, 0];
        // Set clipboard_available (0x08) and auto_pull (0x20), retaining the
        // unmodeled raw byte for a downstream consumer.
        plaintext[8] = 0x28;
        let (ciphertext, tag) =
            crate::gcm::seal_truncated(&key, &counter_iv, &[status], &plaintext, 1).unwrap();
        let mut raw_advertisement = vec![0x0c, (4 + ciphertext.len()) as u8, status];
        raw_advertisement.extend_from_slice(&counter_iv);
        raw_advertisement.extend_from_slice(&tag);
        raw_advertisement.extend_from_slice(&ciphertext);

        let parsed = HandoffBle::parse(&raw_advertisement).unwrap();
        let decrypted = crate::gcm::open_truncated(
            &key,
            &parsed.counter_iv,
            &[parsed.status],
            &parsed.ciphertext,
            &parsed.tag,
        )
        .unwrap()
        .unwrap();
        let payload = HandoffPayload::parse(&decrypted).unwrap();
        let event = copy_event(
            "synthetic iPhone".into(),
            "AA:BB:CC:DD:EE:FF".into(),
            "fixture-key",
            &payload.activity_label(),
            &raw_advertisement,
            &parsed,
            &decrypted,
            payload.flags.raw,
            1_797_090_000_123,
        );

        assert_eq!(event.raw_advertisement, raw_advertisement);
        assert_eq!(event.status, status);
        assert_eq!(event.counter_iv, counter_iv);
        assert_eq!(event.decrypted_payload, plaintext);
        assert_eq!(event.flags, 0x28);
        assert_eq!(event.observed_at_unix_ms, 1_797_090_000_123);
        assert!(HandoffFlags::from_byte(event.flags).clipboard_available());
        assert!(HandoffFlags::from_byte(event.flags).auto_pull());
    }
}
