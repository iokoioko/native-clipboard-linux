//! Milestone 2: the companion-link service that carries the actual clipboard
//! content, after the BLE advert tells us a copy is available.
//!
//! Flow (from Stute et al. 2021 and seemoo-lab handoff-authentication-swift):
//!   1. discover `_companion-link._tcp` over mDNS (see `discover.rs`)
//!   2. TCP connect, run Pair-Verify (Curve25519 ECDH + Ed25519 signatures over
//!      the long-term `RPIdentity-SameAccountDevice` keys)
//!   3. derive per-direction keys and run a ChaCha20-Poly1305 channel
//!   4. exchange OPACK payloads; the clipboard content comes back in one.
//!
//! A live macOS 15.7 probe confirmed that this Pair-Verify nonce construction
//! decrypts the server's M2 AEAD payload. Full authentication remains unverified:
//! no known-peer signature, M3/M4 exchange, or authenticated content packet has
//! yet been observed against a real device. The actual long-term identity keys
//! also require a local `RPIdentity` export (see `PairingIdentity` / `load`).

#![allow(dead_code)] // M2/M3 scaffolding: exercised by unit tests; wired into the runtime once macOS keys exist.

use anyhow::{bail, ensure, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha512;
use std::path::Path;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::opack::{self, Value};
use crate::tlv8::Tlv8;

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// HKDF-SHA512, mirroring Apple's CoreUtils `CryptoHKDF` (extract + expand).
/// An empty salt is treated as all-zeros per RFC 5869.
pub fn hkdf_sha512(secret: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha512>::new(Some(salt), secret);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .expect("HKDF output length within SHA-512 limit");
    okm
}

const KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 content channel
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Client,
    Server,
}

/// The post-Pair-Verify encrypted channel. Keys are derived from the ECDH
/// shared secret with the info strings from `HandoffCryptor.swift`; each
/// direction has its own key and a 64-bit little-endian counter nonce
/// zero-padded to the 96-bit RFC 8439 nonce.
pub struct ContentChannel {
    enc_key: [u8; KEY_LEN],
    dec_key: [u8; KEY_LEN],
    enc_nonce: u64,
    dec_nonce: u64,
}

impl ContentChannel {
    pub fn from_shared_secret(secret: &[u8], role: Role) -> Self {
        let server = hkdf_sha512(secret, b"", b"ServerEncrypt-main", KEY_LEN);
        let client = hkdf_sha512(secret, b"", b"ClientEncrypt-main", KEY_LEN);
        let (enc, dec) = match role {
            Role::Client => (client, server),
            Role::Server => (server, client),
        };
        let mut enc_key = [0u8; KEY_LEN];
        let mut dec_key = [0u8; KEY_LEN];
        enc_key.copy_from_slice(&enc);
        dec_key.copy_from_slice(&dec);
        ContentChannel {
            enc_key,
            dec_key,
            enc_nonce: 0,
            dec_nonce: 0,
        }
    }

    fn nonce(counter: u64) -> Nonce {
        // 8-byte LE counter, then 4 zero bytes => 12-byte RFC 8439 nonce.
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&counter.to_le_bytes());
        *Nonce::from_slice(&n)
    }

    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.enc_key));
        let out = cipher
            .encrypt(
                &Self::nonce(self.enc_nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("chacha encrypt failed"))?;
        self.enc_nonce = self
            .enc_nonce
            .checked_add(1)
            .context("content encryption nonce exhausted")?;
        Ok(out)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.dec_key));
        let out = cipher
            .decrypt(
                &Self::nonce(self.dec_nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("chacha decrypt failed / bad tag"))?;
        self.dec_nonce = self
            .dec_nonce
            .checked_add(1)
            .context("content decryption nonce exhausted")?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// ContinuityPacket framing (4-byte header + body)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PacketType {
    PairVerifyPublicKey = 0x05,
    PairVerifyContinue = 0x06,
    EncryptedData = 0x08,
    Finished = 0x01,
}

impl PacketType {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x05 => PacketType::PairVerifyPublicKey,
            0x06 => PacketType::PairVerifyContinue,
            0x08 => PacketType::EncryptedData,
            0x01 => PacketType::Finished,
            _ => return None,
        })
    }
}

/// `type(1) | wire_body_len_be(3) | body`. Encrypted bodies include their tag.
pub struct ContinuityPacket {
    pub ptype: PacketType,
    pub body: Vec<u8>,
}

impl ContinuityPacket {
    pub fn new(ptype: PacketType, body: Vec<u8>) -> Self {
        ContinuityPacket { ptype, body }
    }

    pub fn header(ptype: PacketType, wire_body_len: usize) -> Result<[u8; 4]> {
        ensure!(
            wire_body_len <= 0xff_ffff,
            "continuity body exceeds 24-bit wire length"
        );
        let n = wire_body_len as u32;
        Ok([ptype as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8])
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = Self::header(self.ptype, self.body.len())?.to_vec();
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            bail!("continuity packet shorter than header");
        }
        let ptype = PacketType::from_u8(data[0])
            .with_context(|| format!("unknown packet type {:#04x}", data[0]))?;
        let length = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
        ensure!(
            data.len() == 4 + length,
            "continuity header/body length mismatch"
        );
        Ok(ContinuityPacket {
            ptype,
            body: data[4..].to_vec(),
        })
    }

    /// Body is `OPACK({ "_pd": <TLV8 bytes> })`. Extract and decode the TLV.
    pub fn pairing_tlv(&self) -> Result<Tlv8> {
        let dict = opack::decode(&self.body)?;
        let pd = dict
            .get("_pd")
            .and_then(Value::as_bytes)
            .context("no _pd in packet")?;
        let tlv = Tlv8::decode_checked(pd).context("invalid Pair-Verify TLV8")?;
        validate_pairing_fields(&tlv)?;
        Ok(tlv)
    }
}

fn wrap_pairing_data(tlv: &Tlv8) -> Vec<u8> {
    opack::encode(&Value::dict([("_pd", Value::Bytes(tlv.encode()))]))
}

fn require_pairing_phase(packet: &ContinuityPacket, ptype: PacketType, state: u8) -> Result<Tlv8> {
    ensure!(
        packet.ptype == ptype,
        "Pair-Verify state {state} arrived in {:?} frame, expected {:?}",
        packet.ptype,
        ptype
    );
    let tlv = packet.pairing_tlv()?;
    let actual_state = tlv
        .get(tlv_type::STATE)
        .and_then(|value| value.first())
        .copied();
    let state_description = actual_state
        .map(|actual| format!("state {actual}"))
        .unwrap_or_else(|| "state missing".to_string());
    if let Some(error) = tlv.get(tlv_type::ERROR) {
        // Pair-Verify errors are small HAP error codes. Keep diagnostics to
        // these protocol fields; never include encrypted/key payload bytes.
        anyhow::bail!(
            "Pair-Verify peer returned error TLV type 0x07 value {}; {state_description} (expected state {state})",
            error[0]
        );
    }
    ensure!(
        actual_state == Some(state),
        "Pair-Verify packet has {state_description}; expected state {state}"
    );
    if state == 4 {
        ensure!(
            tlv.items.len() == 1,
            "Pair-Verify M4 must contain only its state TLV"
        );
    }
    Ok(tlv)
}

// Pair-Verify TLV types (from PairingSession.swift PairingTLV).
mod tlv_type {
    pub const IDENTITY_ID: u8 = 0x01;
    pub const PUBLIC_KEY: u8 = 0x03;
    pub const ENCRYPTED_DATA: u8 = 0x05;
    pub const STATE: u8 = 0x06;
    pub const ERROR: u8 = 0x07;
    pub const SIGNATURE: u8 = 0x0A;
    pub const APP_FLAGS: u8 = 0x19;
}

fn validate_pairing_fields(tlv: &Tlv8) -> Result<()> {
    for type_ in [
        tlv_type::IDENTITY_ID,
        tlv_type::STATE,
        tlv_type::ERROR,
        tlv_type::PUBLIC_KEY,
        tlv_type::ENCRYPTED_DATA,
        tlv_type::SIGNATURE,
        tlv_type::APP_FLAGS,
    ] {
        ensure!(
            tlv.items.iter().filter(|(t, _)| *t == type_).count() <= 1,
            "duplicate Pair-Verify TLV type {type_:#04x}"
        );
    }
    for (type_, expected_len, name) in [
        (tlv_type::STATE, 1, "state"),
        (tlv_type::ERROR, 1, "error"),
        (tlv_type::PUBLIC_KEY, 32, "public key"),
        (tlv_type::SIGNATURE, 64, "signature"),
        (tlv_type::APP_FLAGS, 1, "app flags"),
    ] {
        if let Some(value) = tlv.get(type_) {
            ensure!(
                value.len() == expected_len,
                "Pair-Verify {name} must be {expected_len} bytes, got {}",
                value.len()
            );
        }
    }
    if let Some(value) = tlv.get(tlv_type::ENCRYPTED_DATA) {
        ensure!(
            value.len() >= 16,
            "Pair-Verify encrypted data is shorter than its tag"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Long-term pairing identity (from RPIdentity-SameAccountDevice)
// ---------------------------------------------------------------------------

/// Our own device identity plus, for peer verification, the peers' Ed25519
/// public keys. The Ed25519 secret and the peer public keys are iCloud-synced
/// keychain material; they arrive from an export like keys.json.
///
/// Export instructions and the JSON schema live in macos/RPIDENTITY.md.
pub struct PairingIdentity {
    pub signing: SigningKey,
    pub device_irk: [u8; 16],
    /// Known peer devices' Ed25519 verifying keys (edPK), by label.
    pub peers: Vec<(String, VerifyingKey)>,
}

#[derive(Deserialize)]
struct IdentityFile {
    /// 32-byte Ed25519 seed (hex).
    ed_sk: String,
    /// 16-byte device IRK (hex).
    #[serde(default)]
    dirk: String,
    #[serde(default)]
    peers: Vec<PeerFile>,
}

#[derive(Deserialize)]
struct PeerFile {
    #[serde(default)]
    label: String,
    /// 32-byte Ed25519 public key (hex).
    edpk: String,
}

impl PairingIdentity {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let f: IdentityFile = serde_json::from_slice(&bytes).context("parsing identity JSON")?;
        let sk_bytes: [u8; 32] = hex::decode(f.ed_sk.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("ed_sk must be 32 bytes"))?;
        let device_irk: [u8; 16] = if f.dirk.is_empty() {
            [0u8; 16]
        } else {
            hex::decode(f.dirk.trim())?
                .try_into()
                .map_err(|_| anyhow::anyhow!("dirk must be 16 bytes"))?
        };
        let mut peers = Vec::new();
        for p in f.peers {
            let pk: [u8; 32] = hex::decode(p.edpk.trim())?
                .try_into()
                .map_err(|_| anyhow::anyhow!("peer edpk must be 32 bytes"))?;
            peers.push((p.label, VerifyingKey::from_bytes(&pk)?));
        }
        Ok(PairingIdentity {
            signing: SigningKey::from_bytes(&sk_bytes),
            device_irk,
            peers,
        })
    }
}

// ---------------------------------------------------------------------------
// Pair-Verify client state machine (M1..M4)
// ---------------------------------------------------------------------------

fn pair_verify_key(shared_secret: &[u8]) -> [u8; KEY_LEN] {
    let k = hkdf_sha512(
        shared_secret,
        b"Pair-Verify-Encrypt-Salt",
        b"Pair-Verify-Encrypt-Info",
        KEY_LEN,
    );
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&k);
    out
}

/// Pair-Verify supplies an 8-byte message label. The pyatv implementation
/// expands short nonces by prefixing four zero bytes, matching this RFC 8439
/// nonce layout and the Swift reference's 64x64 call.
fn pv_nonce(label: &[u8; 8]) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(label);
    *Nonce::from_slice(&n)
}

pub struct PairVerifyClient {
    ephemeral: Option<EphemeralSecret>,
    public: PublicKey,
    signing: Option<SigningKey>,
    peers: Vec<(String, VerifyingKey)>,
    shared: Option<[u8; 32]>,
    peer_public: Option<[u8; 32]>,
    peer_verified: bool,
    m3_built: bool,
}

impl PairVerifyClient {
    pub fn new(identity: PairingIdentity) -> Self {
        Self::with_keys(Some(identity.signing), identity.peers)
    }

    /// Construct a verifier that has only explicitly trusted peer public keys.
    /// It can build M1 and verify M2, but contains no signing key and cannot
    /// construct M3.
    pub fn verifier_only(peers: Vec<(String, VerifyingKey)>) -> Self {
        Self::with_keys(None, peers)
    }

    fn with_keys(signing: Option<SigningKey>, peers: Vec<(String, VerifyingKey)>) -> Self {
        let ephemeral = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&ephemeral);
        PairVerifyClient {
            ephemeral: Some(ephemeral),
            public,
            signing,
            peers,
            shared: None,
            peer_public: None,
            peer_verified: false,
            m3_built: false,
        }
    }

    /// M1: our public key + state=1 + appFlags=1, wrapped OPACK("_pd": TLV).
    pub fn build_m1(&self) -> ContinuityPacket {
        let mut tlv = Tlv8::new();
        tlv.push(tlv_type::PUBLIC_KEY, self.public.as_bytes().to_vec())
            .push_u8(tlv_type::STATE, 1)
            .push_u8(tlv_type::APP_FLAGS, 1);
        ContinuityPacket::new(PacketType::PairVerifyPublicKey, wrap_pairing_data(&tlv))
    }

    /// Verify the peer's M2 without signing or constructing M3. This method is
    /// suitable for diagnostics that must stop after public-key verification.
    pub fn verify_m2_only(&mut self, m2: &ContinuityPacket) -> Result<String> {
        let tlv = require_pairing_phase(m2, PacketType::PairVerifyContinue, 2)?;
        let peer_pub_bytes: [u8; 32] = tlv
            .get(tlv_type::PUBLIC_KEY)
            .context("M2 missing peer public key")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("peer public key not 32 bytes"))?;
        let peer_pub = PublicKey::from(peer_pub_bytes);

        let eph = self.ephemeral.take().context("M1 not sent")?;
        let secret = eph.diffie_hellman(&peer_pub);
        if !secret.was_contributory() {
            bail!("invalid low-order X25519 peer key");
        }
        let shared = secret.to_bytes();
        self.shared = Some(shared);

        let key = pair_verify_key(&shared);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        // Decrypt the peer's signature blob (a TLV containing SIGNATURE).
        let enc = tlv
            .get(tlv_type::ENCRYPTED_DATA)
            .context("M2 missing encrypted data")?;
        let dec = cipher
            .decrypt(&pv_nonce(b"PV-Msg02"), enc)
            .map_err(|_| anyhow::anyhow!("PV-Msg02 decrypt failed (key or nonce mismatch)"))?;
        let inner = Tlv8::decode_checked(&dec).context("invalid decrypted M2 TLV8")?;
        validate_pairing_fields(&inner)?;
        let sig_bytes = inner
            .get(tlv_type::SIGNATURE)
            .context("no signature in M2")?;
        let signature = Signature::from_slice(sig_bytes).context("bad signature length")?;

        // Peer signs peer_pub || our_pub.
        let mut signed = Vec::with_capacity(64);
        signed.extend_from_slice(&peer_pub_bytes);
        signed.extend_from_slice(self.public.as_bytes());
        let verified = self
            .peers
            .iter()
            .find(|(_, vk)| vk.verify(&signed, &signature).is_ok())
            .map(|(label, _)| label.clone());
        if let Some(label) = &verified {
            tracing::info!(peer = %label, "Pair-Verify: peer signature verified");
        } else {
            bail!("Pair-Verify rejected an unknown peer signature");
        }
        self.peer_verified = true;
        self.peer_public = Some(peer_pub_bytes);
        Ok(verified.expect("verified label exists after branch"))
    }

    /// Process the peer's M2 and produce M3 (our encrypted signature + state=3).
    /// Verifier-only instances intentionally fail before producing any M3.
    pub fn process_m2(&mut self, m2: &ContinuityPacket) -> Result<ContinuityPacket> {
        self.verify_m2_only(m2)?;
        let peer_pub_bytes = self
            .peer_public
            .context("M2 peer key missing after verification")?;
        let signing = self
            .signing
            .as_ref()
            .context("M3 generation requires local signing material")?;
        let shared = self
            .shared
            .context("M2 shared secret missing after verification")?;
        let key = pair_verify_key(&shared);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        // M3: sign our_pub || peer_pub, encrypt, send with state=3.
        let mut our_signed = Vec::with_capacity(64);
        our_signed.extend_from_slice(self.public.as_bytes());
        our_signed.extend_from_slice(&peer_pub_bytes);
        let our_sig = signing.sign(&our_signed);
        let mut inner_tlv = Tlv8::new();
        inner_tlv.push(tlv_type::SIGNATURE, our_sig.to_bytes().to_vec());
        let sealed = cipher
            .encrypt(&pv_nonce(b"PV-Msg03"), inner_tlv.encode().as_slice())
            .map_err(|_| anyhow::anyhow!("PV-Msg03 encrypt failed"))?;

        let mut out = Tlv8::new();
        out.push(tlv_type::ENCRYPTED_DATA, sealed)
            .push_u8(tlv_type::STATE, 3);
        let m3 = ContinuityPacket::new(PacketType::PairVerifyContinue, wrap_pairing_data(&out));
        self.m3_built = true;
        Ok(m3)
    }

    /// M4: peer confirms with state=4 and nothing else.
    pub fn check_m4(&self, m4: &ContinuityPacket) -> Result<ContentChannel> {
        require_pairing_phase(m4, PacketType::PairVerifyContinue, 4)?;
        ensure!(
            self.peer_verified,
            "Pair-Verify cannot finish before the peer signature is verified"
        );
        ensure!(
            self.m3_built,
            "Pair-Verify cannot finish before a local M3 has been constructed"
        );
        let shared = self
            .shared
            .context("no shared secret; M2 verification not run")?;
        Ok(ContentChannel::from_shared_secret(&shared, Role::Client))
    }

    #[allow(dead_code)]
    pub fn identity_id_type() -> u8 {
        tlv_type::IDENTITY_ID
    }
}

// ---------------------------------------------------------------------------
// Pair-Verify server state machine (M1..M4)
// ---------------------------------------------------------------------------

/// The peer (accessory) side of Pair-Verify. This mirrors [`PairVerifyClient`]
/// so the same TLV/OPACK/ChaCha wiring can be exercised end-to-end against an
/// in-process loopback peer (see `companion_client.rs` tests). The bounded
/// `listen-probe` diagnostic also exercises this role against incoming peers;
/// native Apple-device interoperability remains to be established.
pub struct PairVerifyServer {
    ephemeral: Option<EphemeralSecret>,
    public: PublicKey,
    identity: PairingIdentity,
    shared: Option<[u8; 32]>,
    client_pub: Option<[u8; 32]>,
}

impl PairVerifyServer {
    pub fn new(identity: PairingIdentity) -> Self {
        let ephemeral = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&ephemeral);
        PairVerifyServer {
            ephemeral: Some(ephemeral),
            public,
            identity,
            shared: None,
            client_pub: None,
        }
    }

    /// Consume the client's M1 (their public key), run ECDH, and produce M2:
    /// our public key + our encrypted signature over `server_pub || client_pub`,
    /// with state=2.
    pub fn process_m1(&mut self, m1: &ContinuityPacket) -> Result<ContinuityPacket> {
        let tlv = require_pairing_phase(m1, PacketType::PairVerifyPublicKey, 1)?;
        ensure!(
            tlv.get(tlv_type::APP_FLAGS) == Some(&[1][..]),
            "server supports only observed application Pair-Verify flag 1"
        );
        let client_pub_bytes: [u8; 32] = tlv
            .get(tlv_type::PUBLIC_KEY)
            .context("M1 missing client public key")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("client public key not 32 bytes"))?;
        let client_pub = PublicKey::from(client_pub_bytes);

        let eph = self
            .ephemeral
            .take()
            .context("server ephemeral already consumed")?;
        let secret = eph.diffie_hellman(&client_pub);
        if !secret.was_contributory() {
            bail!("invalid low-order X25519 client key");
        }
        let shared = secret.to_bytes();
        self.shared = Some(shared);
        self.client_pub = Some(client_pub_bytes);

        let key = pair_verify_key(&shared);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        // We sign server_pub || client_pub; the client verifies exactly this.
        let mut signed = Vec::with_capacity(64);
        signed.extend_from_slice(self.public.as_bytes());
        signed.extend_from_slice(&client_pub_bytes);
        let our_sig = self.identity.signing.sign(&signed);
        let mut inner = Tlv8::new();
        inner.push(tlv_type::SIGNATURE, our_sig.to_bytes().to_vec());
        // Native macOS 15.7 M2 includes this inside the encrypted TLV, as
        // corroborated by the independent M2 schema probe (not an outer flag).
        inner.push_u8(tlv_type::APP_FLAGS, 1);
        let sealed = cipher
            .encrypt(&pv_nonce(b"PV-Msg02"), inner.encode().as_slice())
            .map_err(|_| anyhow::anyhow!("PV-Msg02 encrypt failed"))?;

        let mut out = Tlv8::new();
        out.push(tlv_type::PUBLIC_KEY, self.public.as_bytes().to_vec())
            .push(tlv_type::ENCRYPTED_DATA, sealed)
            .push_u8(tlv_type::STATE, 2);
        Ok(ContinuityPacket::new(
            PacketType::PairVerifyContinue,
            wrap_pairing_data(&out),
        ))
    }

    /// Verify the client's M3 signature over `client_pub || server_pub`, and on
    /// success produce M4 (state=4) plus the server-role content channel.
    pub fn process_m3(
        &mut self,
        m3: &ContinuityPacket,
    ) -> Result<(ContinuityPacket, ContentChannel)> {
        let tlv = require_pairing_phase(m3, PacketType::PairVerifyContinue, 3)?;
        let shared = self.shared.context("process_m1 not run before M3")?;
        let client_pub = self.client_pub.context("process_m1 not run before M3")?;

        let key = pair_verify_key(&shared);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let enc = tlv
            .get(tlv_type::ENCRYPTED_DATA)
            .context("M3 missing encrypted data")?;
        let dec = cipher
            .decrypt(&pv_nonce(b"PV-Msg03"), enc)
            .map_err(|_| anyhow::anyhow!("PV-Msg03 decrypt failed (key or nonce mismatch)"))?;
        let inner = Tlv8::decode_checked(&dec).context("invalid decrypted M3 TLV8")?;
        validate_pairing_fields(&inner)?;
        let sig_bytes = inner
            .get(tlv_type::SIGNATURE)
            .context("no signature in M3")?;
        let signature = Signature::from_slice(sig_bytes).context("bad signature length")?;

        let mut signed = Vec::with_capacity(64);
        signed.extend_from_slice(&client_pub);
        signed.extend_from_slice(self.public.as_bytes());
        let verified = self
            .identity
            .peers
            .iter()
            .find(|(_, vk)| vk.verify(&signed, &signature).is_ok())
            .map(|(label, _)| label.clone());
        if let Some(label) = &verified {
            tracing::info!(peer = %label, "Pair-Verify(server): client signature verified");
        } else {
            bail!("Pair-Verify rejected an unknown client signature");
        }

        let mut out = Tlv8::new();
        out.push_u8(tlv_type::STATE, 4);
        let m4 = ContinuityPacket::new(PacketType::PairVerifyContinue, wrap_pairing_data(&out));
        Ok((
            m4,
            ContentChannel::from_shared_secret(&shared, Role::Server),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_m2_matches_native_encrypted_application_flag_schema() {
        let (client_identity, server_identity) =
            crate::companion_client::matched_loopback_identities();
        let mut client = PairVerifyClient::new(client_identity);
        let mut server = PairVerifyServer::new(server_identity);
        let m2 = server.process_m1(&client.build_m1()).unwrap();
        client.verify_m2_only(&m2).unwrap();
        let outer = m2.pairing_tlv().unwrap();
        let encrypted = outer.get(tlv_type::ENCRYPTED_DATA).unwrap();
        // Native M2 oracle: 85 encrypted bytes, containing signature(64) and flag(1).
        assert_eq!(encrypted.len(), 85);
        let key = pair_verify_key(&client.shared.unwrap());
        let plain = ChaCha20Poly1305::new(Key::from_slice(&key))
            .decrypt(&pv_nonce(b"PV-Msg02"), encrypted)
            .unwrap();
        let inner = Tlv8::decode_checked(&plain).unwrap();
        assert_eq!(inner.items.len(), 2);
        assert_eq!(inner.get(tlv_type::APP_FLAGS), Some(&[1][..]));
        assert_eq!(inner.get(tlv_type::SIGNATURE).unwrap().len(), 64);
    }

    #[test]
    fn pyatv_pair_verify_m1_wire_fixture() {
        // Documented example from pyatv's Companion protocol documentation.
        // Keep this independent of our encoder so shared framing/OPACK bugs do
        // not make the test pass by construction.
        let wire = hex::decode(concat!(
            "05000033E2435F706491250601010320",
            "6665D845056F6D32584C8D213EB2E8B365F569084D5006268FDD9B818028FB23",
            "455F617554790C"
        ))
        .unwrap();
        let packet = ContinuityPacket::parse(&wire).unwrap();
        assert_eq!(packet.ptype, PacketType::PairVerifyPublicKey);
        let tlv = packet.pairing_tlv().unwrap();
        assert_eq!(tlv.get(tlv_type::STATE), Some(&[1][..]));
        assert_eq!(tlv.get(tlv_type::PUBLIC_KEY).unwrap().len(), 32);
    }

    #[test]
    fn pair_verify_nonce_matches_short_nonce_expansion() {
        assert_eq!(pv_nonce(b"PV-Msg02").as_slice(), b"\0\0\0\0PV-Msg02");
        assert_eq!(pv_nonce(b"PV-Msg03").as_slice(), b"\0\0\0\0PV-Msg03");
    }

    #[test]
    fn pair_verify_rejects_wrong_outer_type_and_state() {
        let wrong_type = ContinuityPacket::new(
            PacketType::PairVerifyPublicKey,
            wrap_pairing_data(&Tlv8::new()),
        );
        assert!(require_pairing_phase(&wrong_type, PacketType::PairVerifyContinue, 2).is_err());

        let mut wrong_state_tlv = Tlv8::new();
        wrong_state_tlv.push_u8(tlv_type::STATE, 1);
        let wrong_state = ContinuityPacket::new(
            PacketType::PairVerifyContinue,
            wrap_pairing_data(&wrong_state_tlv),
        );
        assert!(require_pairing_phase(&wrong_state, PacketType::PairVerifyContinue, 2).is_err());
    }

    #[test]
    fn pairing_parser_rejects_truncated_and_duplicate_security_fields() {
        let truncated = ContinuityPacket::new(
            PacketType::PairVerifyContinue,
            opack::encode(&Value::dict([(
                "_pd",
                Value::Bytes(vec![tlv_type::STATE, 1, 2, tlv_type::PUBLIC_KEY, 32, 0xAA]),
            )])),
        );
        assert!(truncated.pairing_tlv().is_err());

        // A separated duplicate state is not a legal continuation fragment.
        let duplicate_state = ContinuityPacket::new(
            PacketType::PairVerifyContinue,
            opack::encode(&Value::dict([(
                "_pd",
                Value::Bytes(vec![
                    tlv_type::STATE,
                    1,
                    2,
                    tlv_type::APP_FLAGS,
                    1,
                    1,
                    tlv_type::STATE,
                    1,
                    2,
                ]),
            )])),
        );
        assert!(duplicate_state.pairing_tlv().is_err());

        let short_state = ContinuityPacket::new(
            PacketType::PairVerifyContinue,
            opack::encode(&Value::dict([(
                "_pd",
                Value::Bytes(vec![tlv_type::STATE, 2, 4, 4]),
            )])),
        );
        assert!(short_state.pairing_tlv().is_err());
    }

    #[test]
    fn pair_verify_m4_rejects_any_tlv_other_than_state() {
        use rand::rngs::OsRng;

        let client = PairVerifyClient::new(PairingIdentity {
            signing: SigningKey::generate(&mut OsRng),
            device_irk: [0; 16],
            peers: Vec::new(),
        });
        let mut tlv = Tlv8::new();
        tlv.push_u8(tlv_type::STATE, 4).push_u8(0x07, 1);
        let m4 = ContinuityPacket::new(PacketType::PairVerifyContinue, wrap_pairing_data(&tlv));
        assert!(client.check_m4(&m4).is_err());
    }

    #[test]
    fn pair_verify_surfaces_hap_errors_and_m4_state_safely() {
        let mut error_m4 = Tlv8::new();
        error_m4
            .push_u8(tlv_type::STATE, 4)
            .push_u8(tlv_type::ERROR, 6);
        let packet =
            ContinuityPacket::new(PacketType::PairVerifyContinue, wrap_pairing_data(&error_m4));
        let error = require_pairing_phase(&packet, PacketType::PairVerifyContinue, 4)
            .unwrap_err()
            .to_string();
        assert!(error.contains("error TLV type 0x07 value 6"));
        assert!(error.contains("state 4"));

        let mut missing_state = Tlv8::new();
        missing_state.push_u8(tlv_type::ERROR, 2);
        let packet = ContinuityPacket::new(
            PacketType::PairVerifyContinue,
            wrap_pairing_data(&missing_state),
        );
        let error = require_pairing_phase(&packet, PacketType::PairVerifyContinue, 4)
            .unwrap_err()
            .to_string();
        assert!(error.contains("error TLV type 0x07 value 2"));
        assert!(error.contains("state missing"));
    }

    #[test]
    fn pair_verify_error_tlv_must_be_single_and_one_byte() {
        let duplicate = ContinuityPacket::new(
            PacketType::PairVerifyContinue,
            opack::encode(&Value::dict([(
                "_pd",
                Value::Bytes(vec![tlv_type::ERROR, 1, 2, tlv_type::ERROR, 1, 3]),
            )])),
        );
        assert!(duplicate.pairing_tlv().is_err());

        let invalid_length = ContinuityPacket::new(
            PacketType::PairVerifyContinue,
            opack::encode(&Value::dict([(
                "_pd",
                Value::Bytes(vec![tlv_type::ERROR, 2, 2, 3]),
            )])),
        );
        assert!(invalid_length.pairing_tlv().is_err());
    }

    #[test]
    fn pair_verify_m4_rejected_after_m2_only_verification() {
        use rand::rngs::OsRng;

        let peer_signing = SigningKey::generate(&mut OsRng);
        let peer_verifying = peer_signing.verifying_key();

        // Exercise both the verifier-only probe client (no private signing
        // key at all) and a regular client that has deliberately stopped at
        // the M2-only verification API.
        for verifier_only in [true, false] {
            let mut client = if verifier_only {
                PairVerifyClient::verifier_only(vec![("peer".into(), peer_verifying)])
            } else {
                PairVerifyClient::new(PairingIdentity {
                    signing: SigningKey::generate(&mut OsRng),
                    device_irk: [0; 16],
                    peers: vec![("peer".into(), peer_verifying)],
                })
            };
            let m1 = client.build_m1();
            let client_pub: [u8; 32] = m1
                .pairing_tlv()
                .unwrap()
                .get(tlv_type::PUBLIC_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let peer_eph = EphemeralSecret::random_from_rng(OsRng);
            let peer_pub = PublicKey::from(&peer_eph);
            let shared = peer_eph
                .diffie_hellman(&PublicKey::from(client_pub))
                .to_bytes();
            let key = pair_verify_key(&shared);
            let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
            let mut signed = peer_pub.as_bytes().to_vec();
            signed.extend_from_slice(&client_pub);
            let signature = peer_signing.sign(&signed);
            let mut inner = Tlv8::new();
            inner.push(tlv_type::SIGNATURE, signature.to_bytes().to_vec());
            let encrypted = cipher
                .encrypt(&pv_nonce(b"PV-Msg02"), inner.encode().as_slice())
                .unwrap();
            let mut outer = Tlv8::new();
            outer
                .push(tlv_type::PUBLIC_KEY, peer_pub.as_bytes().to_vec())
                .push(tlv_type::ENCRYPTED_DATA, encrypted)
                .push_u8(tlv_type::STATE, 2);
            let m2 =
                ContinuityPacket::new(PacketType::PairVerifyContinue, wrap_pairing_data(&outer));

            assert_eq!(client.verify_m2_only(&m2).unwrap(), "peer");
            assert!(client.peer_verified);
            assert!(!client.m3_built);

            // Shape-valid M4 cannot mint a channel when the local M3 was not
            // constructed, even though the peer's signature checked out.
            let mut m4_tlv = Tlv8::new();
            m4_tlv.push_u8(tlv_type::STATE, 4);
            let m4 =
                ContinuityPacket::new(PacketType::PairVerifyContinue, wrap_pairing_data(&m4_tlv));
            assert!(client.check_m4(&m4).is_err());
        }
    }

    #[test]
    fn pair_verify_m4_rejected_after_untrusted_m2_signature() {
        use rand::rngs::OsRng;

        // The peer has a valid ECDH key and a well-formed encrypted signature,
        // but its signing key is absent from our trusted peer list.
        let mut client = PairVerifyClient::new(PairingIdentity {
            signing: SigningKey::generate(&mut OsRng),
            device_irk: [0; 16],
            peers: Vec::new(),
        });
        let client_pub: [u8; 32] = client
            .build_m1()
            .pairing_tlv()
            .unwrap()
            .get(tlv_type::PUBLIC_KEY)
            .unwrap()
            .try_into()
            .unwrap();

        let untrusted_signing = SigningKey::generate(&mut OsRng);
        let peer_eph = EphemeralSecret::random_from_rng(OsRng);
        let peer_pub = PublicKey::from(&peer_eph);
        let shared = peer_eph
            .diffie_hellman(&PublicKey::from(client_pub))
            .to_bytes();
        let key = pair_verify_key(&shared);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut signed = peer_pub.as_bytes().to_vec();
        signed.extend_from_slice(&client_pub);
        let signature = untrusted_signing.sign(&signed);
        let mut inner = Tlv8::new();
        inner.push(tlv_type::SIGNATURE, signature.to_bytes().to_vec());
        let encrypted = cipher
            .encrypt(&pv_nonce(b"PV-Msg02"), inner.encode().as_slice())
            .unwrap();
        let mut outer = Tlv8::new();
        outer
            .push(tlv_type::PUBLIC_KEY, peer_pub.as_bytes().to_vec())
            .push(tlv_type::ENCRYPTED_DATA, encrypted)
            .push_u8(tlv_type::STATE, 2);
        let m2 = ContinuityPacket::new(PacketType::PairVerifyContinue, wrap_pairing_data(&outer));

        assert!(client.process_m2(&m2).is_err());

        // Even a correctly shaped state=4 must not mint the channel after M2
        // failed peer authentication (shared ECDH material alone is not trust).
        let mut m4_tlv = Tlv8::new();
        m4_tlv.push_u8(tlv_type::STATE, 4);
        let m4 = ContinuityPacket::new(PacketType::PairVerifyContinue, wrap_pairing_data(&m4_tlv));
        assert!(client.check_m4(&m4).is_err());
    }

    #[test]
    fn hkdf_is_deterministic_and_sized() {
        let a = hkdf_sha512(b"secret", b"salt", b"info", 32);
        let b = hkdf_sha512(b"secret", b"salt", b"info", 32);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert_ne!(a, hkdf_sha512(b"secret", b"salt", b"other", 32));
    }

    #[test]
    fn content_channel_roundtrip_and_direction() {
        // Client and server derive mirrored keys from the same secret.
        let secret = [7u8; 32];
        let mut client = ContentChannel::from_shared_secret(&secret, Role::Client);
        let mut server = ContentChannel::from_shared_secret(&secret, Role::Server);

        let ct = client.encrypt(b"hello", b"").unwrap();
        assert_eq!(server.decrypt(&ct, b"").unwrap(), b"hello");
        // Nonces advanced in lock-step.
        let ct2 = client.encrypt(b"world", b"").unwrap();
        assert_eq!(server.decrypt(&ct2, b"").unwrap(), b"world");
        // Reverse direction.
        let sc = server.encrypt(b"back", b"").unwrap();
        assert_eq!(client.decrypt(&sc, b"").unwrap(), b"back");
    }

    #[test]
    fn ecdh_agreement() {
        let a = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let a_pub = PublicKey::from(&a);
        let b = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let b_pub = PublicKey::from(&b);
        assert_eq!(
            a.diffie_hellman(&b_pub).to_bytes(),
            b.diffie_hellman(&a_pub).to_bytes()
        );
    }

    #[test]
    fn ed25519_verify_over_concatenated_pubkeys() {
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let mut msg = vec![1u8; 32];
        msg.extend_from_slice(&[2u8; 32]);
        let sig = sk.sign(&msg);
        assert!(vk.verify(&msg, &sig).is_ok());
    }

    #[test]
    fn continuity_packet_roundtrip() {
        let body = opack::encode(&Value::dict([(
            "_pd",
            Value::Bytes(vec![0x06, 0x01, 0x04]),
        )]));
        let pkt = ContinuityPacket::new(PacketType::PairVerifyPublicKey, body.clone());
        let wire = pkt.serialize().unwrap();
        assert_eq!(wire[0], 0x05);
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]) as usize, body.len());
        let parsed = ContinuityPacket::parse(&wire).unwrap();
        assert_eq!(parsed.ptype, PacketType::PairVerifyPublicKey);
        assert_eq!(parsed.body, body);
    }

    #[test]
    fn encrypted_packet_len_includes_tag() {
        let pkt = ContinuityPacket::new(PacketType::EncryptedData, vec![0u8; 10]);
        let wire = pkt.serialize().unwrap();
        // The supplied body is already ciphertext plus its tag.
        assert_eq!(u16::from_be_bytes([wire[2], wire[3]]), 10);
    }

    /// Exercise the M1->M3 framing end-to-end with a locally-built peer so the
    /// TLV/OPACK/ChaCha wiring is covered even without real keys. (This is NOT
    /// a real Pair-Verify against a device.)
    #[test]
    fn pair_verify_local_loopback() {
        use rand::rngs::OsRng;

        // Peer identity.
        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_vk = peer_sk.verifying_key();

        // Our identity knows the peer's edPK.
        let our_sk = SigningKey::generate(&mut OsRng);
        let identity = PairingIdentity {
            signing: our_sk,
            device_irk: [0u8; 16],
            peers: vec![("peer".into(), peer_vk)],
        };

        let mut client = PairVerifyClient::new(identity);
        let m1 = client.build_m1();
        // Client's ephemeral public from M1.
        let m1_tlv = m1.pairing_tlv().unwrap();
        let client_pub: [u8; 32] = m1_tlv
            .get(tlv_type::PUBLIC_KEY)
            .unwrap()
            .try_into()
            .unwrap();

        // Build a peer M2: peer ephemeral, ECDH, sign peer_pub||client_pub.
        let peer_eph = EphemeralSecret::random_from_rng(OsRng);
        let peer_pub = PublicKey::from(&peer_eph);
        let shared = peer_eph
            .diffie_hellman(&PublicKey::from(client_pub))
            .to_bytes();
        let key = pair_verify_key(&shared);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut signed = peer_pub.as_bytes().to_vec();
        signed.extend_from_slice(&client_pub);
        let sig = peer_sk.sign(&signed);
        let mut inner = Tlv8::new();
        inner.push(tlv_type::SIGNATURE, sig.to_bytes().to_vec());
        let sealed = cipher
            .encrypt(&pv_nonce(b"PV-Msg02"), inner.encode().as_slice())
            .unwrap();
        let mut m2_tlv = Tlv8::new();
        m2_tlv
            .push(tlv_type::PUBLIC_KEY, peer_pub.as_bytes().to_vec())
            .push(tlv_type::ENCRYPTED_DATA, sealed)
            .push_u8(tlv_type::STATE, 2);
        let m2 = ContinuityPacket::new(PacketType::PairVerifyContinue, wrap_pairing_data(&m2_tlv));

        // Client processes M2 -> M3; verify M3 decrypts and carries our sig.
        let m3 = client.process_m2(&m2).expect("process M2");
        let m3_tlv = m3.pairing_tlv().unwrap();
        assert_eq!(m3_tlv.get(tlv_type::STATE), Some(&[3][..]));
        let enc = m3_tlv.get(tlv_type::ENCRYPTED_DATA).unwrap();
        let dec = cipher.decrypt(&pv_nonce(b"PV-Msg03"), enc).unwrap();
        assert!(Tlv8::decode(&dec).get(tlv_type::SIGNATURE).is_some());

        // M4 -> content channel.
        let mut m4_tlv = Tlv8::new();
        m4_tlv.push_u8(tlv_type::STATE, 4);
        let m4 = ContinuityPacket::new(PacketType::PairVerifyContinue, wrap_pairing_data(&m4_tlv));
        assert!(client.check_m4(&m4).is_ok());
    }
}
