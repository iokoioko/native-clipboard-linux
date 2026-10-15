//! Transport-independent core of the `ac-dc receive-key` / `ac-dc send-key`
//! key-transfer feature: an authenticated, end-to-end-encrypted channel for
//! moving the exported `keys.json` from a Mac to this Linux box over an
//! *untrusted* Bluetooth LE link.
//!
//! The BLE link carries no trust of its own, so we run an ephemeral X25519 key
//! agreement and confirm it out-of-band with a 6-digit Short Authentication
//! String (SAS) that a human compares on both screens. This defeats a
//! man-in-the-middle: an attacker who relays or substitutes public keys forces
//! the two derived transcripts apart, so the SAS shown on the two devices will
//! not match and the human aborts.
//!
//! Everything in this module is transport-agnostic and fully unit-tested with
//! no Bluetooth involved. The BLE plumbing lives in `transfer_ble.rs` (Linux
//! receiver) and in the Swift helper under `macos/ac-dc-send/` (macOS sender);
//! both are thin I/O shells that call into the functions here so that the
//! security-relevant code is exercised by the tests below.
//!
//! ===========================================================================
//! WIRE FORMAT  (mirrored verbatim in macos/ac-dc-send/Sources/ac-dc/Transfer.swift)
//! ===========================================================================
//!
//! Roles: the RECEIVER (Linux, `receive-key`) is the GATT server; the SENDER
//! (macOS, `send-key`) is the GATT central/client.
//!
//! All public keys are 32-byte X25519 public keys, little-endian as produced by
//! `x25519_dalek::PublicKey::to_bytes()` (RFC 7748 u-coordinate encoding).
//!
//! Handshake (in order):
//!   1. Receiver generates an ephemeral X25519 keypair and publishes its 32-byte
//!      public key on the RECEIVER-PUBKEY characteristic (readable).
//!   2. Sender generates an ephemeral X25519 keypair, READS the receiver pubkey,
//!      then WRITES its own 32-byte public key to the SENDER-PUBKEY
//!      characteristic.
//!   3. Both sides compute ECDH: shared = X25519(own_secret, peer_public).
//!   4. Both sides derive the session key:
//!         session_key = HKDF-SHA512(
//!             ikm  = shared,
//!             salt = "ac-dc-key-transfer-v1",
//!             info = "ac-dc session key" || receiver_pub || sender_pub)[..32]
//!      Note the FIXED transcript order (receiver_pub then sender_pub),
//!      independent of who is sending.
//!   5. Both sides derive the SAS:
//!         sas = ( u64_be( SHA-512(receiver_pub || sender_pub)[..8] ) )
//!               mod 1_000_000, formatted as 6 zero-padded decimal digits.
//!      Same fixed order. Shown on both screens; the human confirms they match.
//!
//! Payload:
//!   6. Sender seals the keys.json bytes:
//!         sealed = nonce(12) || ChaCha20-Poly1305_seal(session_key, nonce, plaintext, aad="")
//!      nonce is 12 random bytes; the 16-byte Poly1305 tag is appended to the
//!      ciphertext by the AEAD (RFC 8439).
//!   7. Sender frames `sealed` for the GATT MTU. The framed byte stream is:
//!         stream = u32_be(sealed.len()) || sealed
//!      split into chunks of at most (max_frame - 2) bytes; each chunk is sent
//!      as one GATT write / one frame:
//!         frame = u16_be(chunk.len()) || chunk
//!   8. Receiver reassembles the frames back into `sealed`, then (only after the
//!      human confirms the SAS matched) opens it with the session key and writes
//!      keys.json to disk at mode 0600.
//! ===========================================================================

// The wire-format block above is laid out for human readability (and to be
// mirrored verbatim in the Swift helper), so allow its indented continuation
// lines rather than reflow them.
#![allow(clippy::doc_overindented_list_items)]

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// HKDF salt for the session-key derivation. Versioned so a future change to
/// the scheme cannot be confused with this one.
pub const HKDF_SALT: &[u8] = b"ac-dc-key-transfer-v1";
/// HKDF info prefix; the two public keys are appended (fixed order) so the
/// session key is bound to the exact transcript.
pub const HKDF_INFO_PREFIX: &[u8] = b"ac-dc session key";

/// Length of an X25519 public key / the ChaCha20-Poly1305 key.
pub const KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length (RFC 8439).
pub const NONCE_LEN: usize = 12;

/// An ephemeral X25519 keypair. The secret is single-use: [`Self::agree`]
/// consumes it, which is exactly the ephemeral-DH lifecycle we want.
pub struct EphemeralKeyPair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl EphemeralKeyPair {
    /// Generate a fresh ephemeral keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// This side's 32-byte public key, to be sent to the peer.
    pub fn public_bytes(&self) -> [u8; KEY_LEN] {
        self.public.to_bytes()
    }

    /// Perform the X25519 agreement with the peer's public key, consuming this
    /// keypair, and return the 32-byte shared secret.
    pub fn agree(self, peer_public: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
        let peer = PublicKey::from(*peer_public);
        self.secret.diffie_hellman(&peer).to_bytes()
    }
}

/// Derive the 32-byte session key from the ECDH shared secret, binding it to
/// the full transcript (fixed order: receiver public key then sender public
/// key). Both sides pass the same three inputs and get the same key.
pub fn session_key(
    shared: &[u8; KEY_LEN],
    receiver_pub: &[u8; KEY_LEN],
    sender_pub: &[u8; KEY_LEN],
) -> [u8; KEY_LEN] {
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 2 * KEY_LEN);
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(receiver_pub);
    info.extend_from_slice(sender_pub);

    let hk = Hkdf::<Sha512>::new(Some(HKDF_SALT), shared);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info, &mut okm)
        .expect("HKDF output length within SHA-512 limit");
    okm
}

/// Derive the 6-digit Short Authentication String from the transcript. Fixed
/// order (receiver public key then sender public key) so both ends compute the
/// same value. The result is always exactly 6 ASCII digits, zero-padded.
pub fn sas(receiver_pub: &[u8; KEY_LEN], sender_pub: &[u8; KEY_LEN]) -> String {
    let mut h = Sha512::new();
    h.update(receiver_pub);
    h.update(sender_pub);
    let digest = h.finalize();
    let mut first8 = [0u8; 8];
    first8.copy_from_slice(&digest[..8]);
    let n = u64::from_be_bytes(first8) % 1_000_000;
    format!("{n:06}")
}

/// Seal a plaintext under `key`: returns `nonce(12) || ciphertext+tag`. A fresh
/// random nonce is generated for each call.
///
/// This is the SENDER side of the channel (the macOS helper does the equivalent
/// in Swift); the Rust receiver only ever [`open`]s. Kept here — and covered by
/// the unit tests — so the wire format has one authoritative implementation.
#[allow(dead_code)]
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: b"",
            },
        )
        .map_err(|_| anyhow!("chacha20poly1305 seal failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a `nonce(12) || ciphertext+tag` blob produced by [`seal`]. Returns an
/// error (never a panic) if the blob is malformed or the tag does not verify —
/// i.e. any tampering or a wrong key is rejected here.
pub fn open(key: &[u8; KEY_LEN], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN {
        bail!("sealed payload too short to contain a nonce");
    }
    let (nonce_bytes, ct) = sealed.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ct, aad: b"" })
        .map_err(|_| anyhow!("chacha20poly1305 open failed / bad tag (tampered or wrong key)"))
}

/// Split a sealed payload into length-prefixed frames sized for a GATT MTU.
///
/// `max_frame` is the largest number of bytes we may put in a single GATT
/// write, including the 2-byte length prefix. See the wire-format block above
/// for the exact layout.
///
/// This is the SENDER side (the macOS helper mirrors it); the Rust receiver
/// consumes frames via [`Reassembler`]. Kept and unit-tested here so both ends
/// share one authoritative framing definition.
#[allow(dead_code)]
pub fn frame_payload(sealed: &[u8], max_frame: usize) -> Result<Vec<Vec<u8>>> {
    if max_frame <= 2 {
        bail!("max_frame must be greater than 2 (need room past the length prefix)");
    }
    let chunk_len = max_frame - 2;

    // stream = u32_be(sealed.len()) || sealed
    let total = u32::try_from(sealed.len()).map_err(|_| anyhow!("payload too large to frame"))?;
    let mut stream = Vec::with_capacity(4 + sealed.len());
    stream.extend_from_slice(&total.to_be_bytes());
    stream.extend_from_slice(sealed);

    let mut frames = Vec::new();
    for chunk in stream.chunks(chunk_len) {
        let mut frame = Vec::with_capacity(2 + chunk.len());
        frame.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        frame.extend_from_slice(chunk);
        frames.push(frame);
    }
    Ok(frames)
}

/// Reassembles length-prefixed frames back into the original sealed payload.
#[derive(Default)]
pub struct Reassembler {
    /// Accumulated `u32_be(len) || sealed` stream bytes.
    stream: Vec<u8>,
    /// Expected sealed length, learned once the 4-byte header has arrived.
    expected: Option<usize>,
}

impl Reassembler {
    #[allow(dead_code)] // used by tests; the BLE receiver builds it via Default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one frame (exactly as produced by [`frame_payload`], i.e. one GATT
    /// write). Returns an error on malformed framing.
    pub fn push_frame(&mut self, frame: &[u8]) -> Result<()> {
        if frame.len() < 2 {
            bail!("frame shorter than its 2-byte length prefix");
        }
        let declared = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        if frame.len() != declared + 2 {
            bail!(
                "frame length prefix ({declared}) does not match frame body ({})",
                frame.len() - 2
            );
        }
        self.stream.extend_from_slice(&frame[2..]);
        if self.expected.is_none() && self.stream.len() >= 4 {
            let len = u32::from_be_bytes([
                self.stream[0],
                self.stream[1],
                self.stream[2],
                self.stream[3],
            ]) as usize;
            self.expected = Some(len);
        }
        Ok(())
    }

    /// True once every byte of the declared payload has been received.
    pub fn is_complete(&self) -> bool {
        match self.expected {
            Some(len) => self.stream.len() >= 4 + len,
            None => false,
        }
    }

    /// Return the reassembled sealed payload once [`Self::is_complete`], else
    /// `None`.
    pub fn take_payload(&self) -> Option<Vec<u8>> {
        let len = self.expected?;
        if self.stream.len() >= 4 + len {
            Some(self.stream[4..4 + len].to_vec())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp_pair() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        // Returns (receiver_shared, sender_shared, receiver_pub, sender_pub).
        let receiver = EphemeralKeyPair::generate();
        let sender = EphemeralKeyPair::generate();
        let r_pub = receiver.public_bytes();
        let s_pub = sender.public_bytes();
        let r_shared = receiver.agree(&s_pub);
        let s_shared = sender.agree(&r_pub);
        (r_shared, s_shared, r_pub, s_pub)
    }

    #[test]
    fn keypairs_are_distinct_and_32_bytes() {
        let a = EphemeralKeyPair::generate();
        let b = EphemeralKeyPair::generate();
        assert_eq!(a.public_bytes().len(), 32);
        assert_ne!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn ecdh_both_sides_agree() {
        let (r_shared, s_shared, ..) = kp_pair();
        assert_eq!(r_shared, s_shared);
        assert_ne!(r_shared, [0u8; 32]);
    }

    #[test]
    fn session_key_matches_on_both_sides_and_is_transcript_bound() {
        let (r_shared, s_shared, r_pub, s_pub) = kp_pair();
        let k_recv = session_key(&r_shared, &r_pub, &s_pub);
        let k_send = session_key(&s_shared, &r_pub, &s_pub);
        assert_eq!(k_recv, k_send);
        // A different transcript order / different pubkey yields a different key.
        let k_swapped = session_key(&r_shared, &s_pub, &r_pub);
        assert_ne!(k_recv, k_swapped);
    }

    #[test]
    fn sas_agrees_and_is_six_digits() {
        let (_, _, r_pub, s_pub) = kp_pair();
        let sas_recv = sas(&r_pub, &s_pub);
        let sas_send = sas(&r_pub, &s_pub);
        assert_eq!(sas_recv, sas_send);
        assert_eq!(sas_recv.len(), 6);
        assert!(sas_recv.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn sas_differs_for_different_transcript() {
        let (_, _, r_pub, s_pub) = kp_pair();
        let other = EphemeralKeyPair::generate().public_bytes();
        // A MITM that substitutes one public key changes the transcript, so the
        // SAS the two ends show will differ (that is what the human catches).
        assert_ne!(sas(&r_pub, &s_pub), sas(&r_pub, &other));
    }

    #[test]
    fn sas_zero_pads() {
        // The SAS is always 6 chars regardless of magnitude; lock the zero-pad
        // contract that `sas` relies on for small values.
        assert_eq!(format!("{:06}", 42u64), "000042");
        assert_eq!(format!("{:06}", 999_999u64), "999999");
    }

    #[test]
    fn seal_open_roundtrips() {
        let key = [7u8; 32];
        let msg = b"{\"keys\":[{\"id\":\"abc\",\"key\":\"00112233\"}]}";
        let sealed = seal(&key, msg).unwrap();
        assert!(sealed.len() > msg.len()); // nonce + tag overhead
        let opened = open(&key, &sealed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let key = [9u8; 32];
        let mut sealed = seal(&key, b"secret payload").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01; // flip a bit in the tag
        assert!(open(&key, &sealed).is_err());
        // Flip a ciphertext byte too.
        let mut sealed2 = seal(&key, b"secret payload").unwrap();
        sealed2[NONCE_LEN] ^= 0x80;
        assert!(open(&key, &sealed2).is_err());
    }

    #[test]
    fn open_rejects_wrong_key() {
        let sealed = seal(&[1u8; 32], b"hello").unwrap();
        assert!(open(&[2u8; 32], &sealed).is_err());
    }

    #[test]
    fn open_rejects_too_short() {
        assert!(open(&[0u8; 32], b"short").is_err());
    }

    #[test]
    fn framing_roundtrips_single_frame() {
        let sealed = seal(&[3u8; 32], b"small").unwrap();
        let frames = frame_payload(&sealed, 512).unwrap();
        assert_eq!(frames.len(), 1);
        let mut r = Reassembler::new();
        for f in &frames {
            r.push_frame(f).unwrap();
        }
        assert!(r.is_complete());
        assert_eq!(r.take_payload().unwrap(), sealed);
    }

    #[test]
    fn framing_roundtrips_many_frames_tiny_mtu() {
        // A payload large enough to need many frames under a tiny MTU.
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let sealed = seal(&[4u8; 32], &payload).unwrap();
        let frames = frame_payload(&sealed, 23).unwrap(); // classic BLE 23-byte MTU
        assert!(frames.len() > 1);
        for f in &frames {
            assert!(f.len() <= 23);
        }
        let mut r = Reassembler::new();
        assert!(!r.is_complete());
        for f in &frames {
            r.push_frame(f).unwrap();
        }
        assert!(r.is_complete());
        let reassembled = r.take_payload().unwrap();
        assert_eq!(reassembled, sealed);
        assert_eq!(open(&[4u8; 32], &reassembled).unwrap(), payload);
    }

    #[test]
    fn reassembler_rejects_corrupt_frame() {
        let mut r = Reassembler::new();
        // Length prefix says 5 but only 2 body bytes follow.
        assert!(r.push_frame(&[0x00, 0x05, 0xaa, 0xbb]).is_err());
        assert!(r.push_frame(&[0x00]).is_err());
    }

    #[test]
    fn frame_payload_rejects_degenerate_mtu() {
        assert!(frame_payload(b"x", 2).is_err());
    }

    #[test]
    fn end_to_end_handshake_and_transfer() {
        // Full transport-free run of the protocol both sides.
        let receiver = EphemeralKeyPair::generate();
        let sender = EphemeralKeyPair::generate();
        let r_pub = receiver.public_bytes();
        let s_pub = sender.public_bytes();

        // Exchange + agree.
        let r_shared = receiver.agree(&s_pub);
        let s_shared = sender.agree(&r_pub);

        // Both derive the same key + SAS.
        let k_recv = session_key(&r_shared, &r_pub, &s_pub);
        let k_send = session_key(&s_shared, &r_pub, &s_pub);
        assert_eq!(k_recv, k_send);
        assert_eq!(sas(&r_pub, &s_pub), sas(&r_pub, &s_pub));

        // Sender seals + frames keys.json; receiver reassembles + opens.
        let keys_json = br#"{"keys":[{"id":"KEY-1","key":"0011223344556677"}]}"#;
        let sealed = seal(&k_send, keys_json).unwrap();
        let frames = frame_payload(&sealed, 185).unwrap();

        let mut r = Reassembler::new();
        for f in &frames {
            r.push_frame(f).unwrap();
        }
        assert!(r.is_complete());
        let got = open(&k_recv, &r.take_payload().unwrap()).unwrap();
        assert_eq!(got, keys_json);
    }

    #[test]
    fn end_to_end_mitm_makes_sas_diverge() {
        // Attacker sits in the middle with its own keypair per side.
        let receiver = EphemeralKeyPair::generate();
        let sender = EphemeralKeyPair::generate();
        let mitm_to_recv = EphemeralKeyPair::generate();
        let mitm_to_send = EphemeralKeyPair::generate();

        let r_pub = receiver.public_bytes();
        let s_pub = sender.public_bytes();
        let m_r = mitm_to_recv.public_bytes(); // what the receiver believes is "sender"
        let m_s = mitm_to_send.public_bytes(); // what the sender believes is "receiver"

        // Receiver's transcript uses its own pub + the MITM's pub.
        let sas_recv = sas(&r_pub, &m_r);
        // Sender's transcript uses the MITM's pub (as receiver) + its own pub.
        let sas_send = sas(&m_s, &s_pub);
        assert_ne!(sas_recv, sas_send);
    }
}
