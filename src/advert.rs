//! Parsing of Apple Continuity "Handoff" (type 0x0c) BLE manufacturer data,
//! which is also what Universal Clipboard uses to announce a copy event.
//!
//! Wire layout of the manufacturer-specific data (company id 0x004c = Apple):
//!
//! ```text
//!   4c 00 | 0c | LEN | STATUS | CTR(2, LE) | TAG(1) | CIPHERTEXT(10)
//! ```
//!
//! After AES-GCM decryption the 10-byte payload is:
//!
//! ```text
//!   STATUS(1) | ACTIVITY_HASH(7) | FLAGS(1) | UNUSED(1)
//! ```
//!
//! Reference: seemoo-lab handoff-ble-viewer `HandoffBLE.swift` /
//! `HandoffAdvertisement.swift`, and Stute et al., USENIX Security 2021.

const APPLE_COMPANY_ID: u16 = 0x004c;
const TYPE_HANDOFF: u8 = 0x0c;

/// The encrypted, on-the-wire Handoff advertisement.
#[derive(Debug, Clone)]
pub struct HandoffBle {
    pub status: u8,
    /// Counter, used as the GCM IV. Kept in wire (little-endian) byte order.
    pub counter_iv: [u8; 2],
    pub tag: [u8; 1],
    pub ciphertext: Vec<u8>,
}

impl HandoffBle {
    /// Parse from the *manufacturer data* bytes as reported by BlueZ for
    /// company id 0x004c. BlueZ strips the company-id prefix, so `data` here
    /// begins at the first Continuity TLV (`0c ...`). We accept both framings:
    /// with the leading `4c 00` (raw HCI) and without (BlueZ ManufacturerData).
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Locate the 0x0c TLV. Two common shapes:
        //   raw:   4c 00 0c len ...
        //   bluez: 0c len ...   (company id already consumed)
        let body = if data.len() >= 3 && data[0] == 0x4c && data[1] == 0x00 {
            &data[2..]
        } else {
            data
        };

        if body.len() < 2 || body[0] != TYPE_HANDOFF {
            return None;
        }
        let len = body[1] as usize;
        let content = body.get(2..2 + len)?;
        if content.len() < 4 {
            return None;
        }
        let status = content[0];
        let counter_iv = [content[1], content[2]];
        let tag = [content[3]];
        let ciphertext = content[4..].to_vec();
        Some(HandoffBle {
            status,
            counter_iv,
            tag,
            ciphertext,
        })
    }
}

/// Helper for callers that hold BlueZ `ManufacturerData` (a map of company id
/// -> bytes). Returns the Apple entry if present.
pub fn apple_manufacturer_data(map: &std::collections::HashMap<u16, Vec<u8>>) -> Option<&Vec<u8>> {
    map.get(&APPLE_COMPANY_ID)
}

/// The decrypted 10-byte Handoff payload.
#[derive(Debug, Clone)]
pub struct HandoffPayload {
    /// Decrypted status byte. Retained for M2 (companion-link) diagnostics.
    #[allow(dead_code)]
    pub status: u8,
    pub activity_hash: [u8; 7],
    pub flags: HandoffFlags,
}

impl HandoffPayload {
    pub fn parse(plain: &[u8]) -> Option<Self> {
        if plain.len() < 10 {
            return None;
        }
        let mut activity_hash = [0u8; 7];
        activity_hash.copy_from_slice(&plain[1..8]);
        Some(HandoffPayload {
            status: plain[0],
            activity_hash,
            flags: HandoffFlags::from_byte(plain[8]),
        })
    }

    /// Best-effort human label for the activity behind a copy.
    ///
    /// NOTE: the advert does **not** carry the clipboard contents — only the
    /// URL flag and a truncated SHA-512 hash of the activity-type string. We map
    /// that hash against known Apple activities (from seemoo-lab
    /// handoff-ble-viewer). The actual copied text travels over companion-link
    /// (AWDL), which we can't reach — so this names the app/activity, not the
    /// text.
    pub fn activity_label(&self) -> String {
        if self.flags.has_url() {
            return "web page / browsing (Safari)".to_string();
        }
        let hex = hex::encode(self.activity_hash);
        let known = match hex.as_str() {
            "88085c342dc9ed" => "Notes — editing a note",
            "9d98584545c05e" => "Mail — viewing a mailbox",
            "86f6a0732b418e" => "Mail — viewing a message",
            "a564c399758208" => "Mail — composing a message",
            "90ec0d1c7a00f7" => "Keynote — editing a presentation",
            "a2f08c1c87dc98" => "Pages — editing a document",
            "855912d27f7828" => "Numbers — editing a document",
            "b64729d1a4296b" => "Calendar — date selection",
            "88acfe99cad770" => "Calendar — event selection",
            "a32a9f48308fdc" => "Messages",
            "a37b6b65fc4f5f" => "Podcasts",
            "99bee8c360dd13" => "2Do — selected list",
            "b2a2abdd925ef5" => "2Do — editing a task",
            "00000000000000" => "clearing last activity",
            _ => return format!("unknown activity (hash {hex})"),
        };
        known.to_string()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HandoffFlags {
    pub raw: u8,
}

// `file_provider_url`, `cloud_docs`, and `auto_pull` describe the full flag set
// but are only consumed starting in M2 (deciding what to pull); keep them.
#[allow(dead_code)]
impl HandoffFlags {
    pub fn from_byte(b: u8) -> Self {
        HandoffFlags { raw: b }
    }
    pub fn has_url(&self) -> bool {
        self.raw & 0x01 != 0
    }
    pub fn file_provider_url(&self) -> bool {
        self.raw & 0x02 != 0
    }
    pub fn cloud_docs(&self) -> bool {
        self.raw & 0x04 != 0
    }
    /// The bit we care about most: the clipboard has data ready to pull.
    pub fn clipboard_available(&self) -> bool {
        self.raw & 0x08 != 0
    }
    pub fn auto_pull(&self) -> bool {
        self.raw & 0x20 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bluez_framing() {
        // 0c 0e | status=08 | ctr=2a00 | tag=99 | ct(10)
        let mut data = vec![0x0c, 0x0e, 0x08, 0x2a, 0x00, 0x99];
        data.extend_from_slice(&[0xde; 10]);
        let h = HandoffBle::parse(&data).expect("should parse");
        assert_eq!(h.status, 0x08);
        assert_eq!(h.counter_iv, [0x2a, 0x00]);
        assert_eq!(h.tag, [0x99]);
        assert_eq!(h.ciphertext.len(), 10);
    }

    #[test]
    fn parses_raw_framing() {
        let mut data = vec![0x4c, 0x00, 0x0c, 0x0e, 0x08, 0x2a, 0x00, 0x99];
        data.extend_from_slice(&[0xde; 10]);
        assert!(HandoffBle::parse(&data).is_some());
    }

    #[test]
    fn flags_clipboard_bit() {
        assert!(HandoffFlags::from_byte(0x08).clipboard_available());
        assert!(!HandoffFlags::from_byte(0x01).clipboard_available());
    }
}
