//! Loading the Continuity BLE encryption keys that were exported from macOS.
//!
//! On macOS these live in the keychain as generic-password items with service
//! `com.apple.continuity.encryption`; the item's data is a binary plist with at
//! least `keyData`, `keyIdentifier` and `lastUsedCounter` (see seemoo-lab
//! handoff-ble-viewer `KeychainAccess.swift`). They are iCloud-synced across all
//! devices on the same Apple ID, so any one of your Apple devices carries the
//! same keys your iPhone advertises with.
//!
//! Because Asahi and macOS never run at the same time, we cannot read a live
//! keychain. Instead `macos/export-keys.sh` writes the keys to a JSON file that
//! this module loads. We accept two shapes:
//!
//!   1. Our own simple JSON: `{ "keys": [ { "id": "...", "key": "<hex>" }, ... ] }`
//!   2. A raw exported binary plist (one item), parsed via the `plist` crate.
//!
//! Every key must be 16, 24 or 32 bytes (AES-128/192/256); loading fails on any
//! other length.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

use crate::gcm;

#[derive(Debug, Clone)]
pub struct HandoffKey {
    pub id: String,
    pub key: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct JsonKeyFile {
    keys: Vec<JsonKey>,
}

#[derive(Debug, Deserialize)]
struct JsonKey {
    #[serde(default)]
    id: String,
    /// Hex-encoded AES key bytes (16, 24 or 32 bytes).
    key: String,
}

#[derive(Debug, Deserialize)]
struct PlistKeyItem {
    #[serde(rename = "keyData")]
    key_data: plist::Value,
    #[serde(rename = "keyIdentifier", default)]
    key_identifier: Option<String>,
}

pub struct KeyStore {
    pub keys: Vec<HandoffKey>,
}

impl KeyStore {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes =
            std::fs::read(path).with_context(|| format!("reading key file {}", path.display()))?;

        // Try our JSON format first.
        if let Ok(jf) = serde_json::from_slice::<JsonKeyFile>(&bytes) {
            let keys = jf
                .keys
                .into_iter()
                .map(|k| {
                    Ok(HandoffKey {
                        id: k.id,
                        key: hex::decode(k.key.trim()).context("decoding hex key")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            return Self::validated(keys);
        }

        // Fall back to a single raw binary plist keychain item.
        if let Ok(item) = plist::from_bytes::<PlistKeyItem>(&bytes) {
            let key = match item.key_data {
                plist::Value::Data(d) => d,
                other => anyhow::bail!("keyData was not binary data: {other:?}"),
            };
            return Self::validated(vec![HandoffKey {
                id: item.key_identifier.unwrap_or_default(),
                key,
            }]);
        }

        anyhow::bail!(
            "could not parse {} as either ac-dc JSON or a keychain plist",
            path.display()
        )
    }

    fn validated(keys: Vec<HandoffKey>) -> Result<Self> {
        for k in &keys {
            gcm::validate_key(&k.key).with_context(|| format!("key {:?}", k.id))?;
        }
        Ok(KeyStore { keys })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_json(name: &str, json: &str) -> Result<KeyStore> {
        let path =
            std::env::temp_dir().join(format!("ac-dc-keystore-{}-{name}.json", std::process::id()));
        std::fs::write(&path, json).unwrap();
        let result = KeyStore::load(&path);
        std::fs::remove_file(&path).unwrap();
        result
    }

    #[test]
    fn loads_16_and_32_byte_keys() {
        let json = format!(
            r#"{{"keys":[{{"id":"a","key":"{}"}},{{"id":"b","key":"{}"}}]}}"#,
            "11".repeat(16),
            "22".repeat(32)
        );
        let store = load_json("ok", &json).expect("load");
        assert_eq!(store.keys.len(), 2);
        assert_eq!(store.keys[0].key.len(), 16);
        assert_eq!(store.keys[1].key.len(), 32);
    }

    #[test]
    fn rejects_key_of_unsupported_length() {
        let json = format!(r#"{{"keys":[{{"id":"bad","key":"{}"}}]}}"#, "33".repeat(20));
        let err = load_json("bad", &json)
            .err()
            .expect("20-byte key must be rejected");
        let msg = format!("{err:#}");
        assert!(msg.contains("bad") && msg.contains("got 20"), "{msg}");
    }
}
