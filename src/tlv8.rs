//! TLV8 — the type-length-value framing used inside Pair-Verify pairing data.
//!
//! Each item is `type(1) | length(1) | value(length)`. A value longer than 255
//! bytes is split into consecutive fragments of the *same* type, each up to 255
//! bytes; a reader concatenates consecutive same-type fragments back together.
//!
//! Ported from seemoo-lab openwifipass `TLV8.py` (with the fragmentation rule
//! from the HomeKit Accessory Protocol, which Continuity's Pair-Verify reuses).

#![allow(dead_code)] // M2/M3 scaffolding: exercised by unit tests; wired into the runtime once macOS keys exist.

use anyhow::{ensure, Result};

/// An ordered list of TLV items. Duplicate types are allowed (that's how
/// fragmentation is expressed on the wire); `get` returns the first merged run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tlv8 {
    pub items: Vec<(u8, Vec<u8>)>,
}

impl Tlv8 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, type_: u8, value: impl Into<Vec<u8>>) -> &mut Self {
        self.items.push((type_, value.into()));
        self
    }

    pub fn push_u8(&mut self, type_: u8, value: u8) -> &mut Self {
        self.push(type_, vec![value])
    }

    /// Serialize, fragmenting any value longer than 255 bytes into consecutive
    /// same-type chunks.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (type_, value) in &self.items {
            if value.is_empty() {
                out.push(*type_);
                out.push(0);
                continue;
            }
            for chunk in value.chunks(255) {
                out.push(*type_);
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
        }
        out
    }

    /// Decode, merging consecutive fragments of the same type into one value.
    pub fn decode(data: &[u8]) -> Self {
        let mut items: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut pos = 0;
        while pos + 2 <= data.len() {
            let type_ = data[pos];
            let len = data[pos + 1] as usize;
            let end = (pos + 2 + len).min(data.len());
            let payload = &data[pos + 2..end];
            pos = end;
            match items.last_mut() {
                Some((t, buf)) if *t == type_ => buf.extend_from_slice(payload),
                _ => items.push((type_, payload.to_vec())),
            }
        }
        Tlv8 { items }
    }

    /// Decode TLV8 while rejecting incomplete headers, truncated values, and
    /// repeated adjacent types that cannot be valid continuation fragments.
    /// A repeated type continues the previous value only when the previous
    /// chunk filled its 255-byte length field, as required by TLV8.
    pub fn decode_checked(data: &[u8]) -> Result<Self> {
        let mut items: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut pos = 0;
        let mut last_type = None;
        let mut last_chunk_len = 0usize;

        while pos < data.len() {
            ensure!(data.len() - pos >= 2, "truncated TLV8 header");
            let type_ = data[pos];
            let len = data[pos + 1] as usize;
            pos += 2;
            ensure!(len <= data.len() - pos, "truncated TLV8 value");
            let payload = &data[pos..pos + len];
            pos += len;

            if last_type == Some(type_) {
                ensure!(
                    last_chunk_len == u8::MAX as usize,
                    "duplicate TLV8 type {type_:#04x} is not a continuation fragment"
                );
                items
                    .last_mut()
                    .expect("last type implies an item")
                    .1
                    .extend_from_slice(payload);
            } else {
                items.push((type_, payload.to_vec()));
            }
            last_type = Some(type_);
            last_chunk_len = len;
        }

        Ok(Tlv8 { items })
    }

    /// First value for a given type (after fragment merging).
    pub fn get(&self, type_: u8) -> Option<&[u8]> {
        self.items
            .iter()
            .find(|(t, _)| *t == type_)
            .map(|(_, v)| v.as_slice())
    }

    pub fn types(&self) -> Vec<u8> {
        self.items.iter().map(|(t, _)| *t).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_roundtrip() {
        let mut t = Tlv8::new();
        t.push_u8(0x06, 1)
            .push(0x03, vec![0xAA; 32])
            .push_u8(0x19, 1);
        let enc = t.encode();
        let dec = Tlv8::decode(&enc);
        assert_eq!(dec.get(0x06), Some([1u8].as_slice()));
        assert_eq!(dec.get(0x03), Some([0xAA; 32].as_slice()));
        assert_eq!(dec.get(0x19), Some([1u8].as_slice()));
    }

    #[test]
    fn fragmentation_over_255() {
        let value: Vec<u8> = (0..300).map(|i| (i % 256) as u8).collect();
        let mut t = Tlv8::new();
        t.push(0x05, value.clone());
        let enc = t.encode();
        // Must have split into 255 + 45, i.e. two headers of the same type.
        assert_eq!(enc[0], 0x05);
        assert_eq!(enc[1], 255);
        assert_eq!(enc[2 + 255], 0x05);
        assert_eq!(enc[2 + 255 + 1], 45);
        // And decode must merge them back.
        let dec = Tlv8::decode(&enc);
        assert_eq!(dec.get(0x05), Some(value.as_slice()));
    }

    #[test]
    fn empty_value() {
        let mut t = Tlv8::new();
        t.push(0x01, Vec::new());
        let enc = t.encode();
        assert_eq!(enc, vec![0x01, 0x00]);
        assert_eq!(Tlv8::decode(&enc).get(0x01), Some([].as_slice()));
    }

    #[test]
    fn checked_decode_accepts_legitimate_fragments() {
        let value: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
        let mut encoded = Tlv8::new();
        encoded.push(0x0A, value.clone());
        let decoded = Tlv8::decode_checked(&encoded.encode()).unwrap();
        assert_eq!(decoded.get(0x0A), Some(value.as_slice()));
        assert_eq!(decoded.items.len(), 1);
    }

    #[test]
    fn checked_decode_rejects_truncation_and_ambiguous_adjacent_type() {
        assert!(Tlv8::decode_checked(&[0x06]).is_err());
        assert!(Tlv8::decode_checked(&[0x06, 0x02, 0x04]).is_err());
        assert!(Tlv8::decode_checked(&[0x06, 1, 4, 0x06, 1, 4]).is_err());

        // The legacy decoder remains available to unrelated callers.
        assert_eq!(Tlv8::decode(&[0x06, 0x02, 0x04]).get(0x06), Some(&[4][..]));
    }
}
