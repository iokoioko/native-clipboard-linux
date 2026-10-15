//! A bounded, credential-free M1/M2 observation. Never sends M3 or accepts trust.
use anyhow::{ensure, Context, Result};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use std::io::Read;
use std::path::Path;
use tokio::net::TcpStream;

use crate::companion::PairVerifyClient;
use crate::companion_client::{read_packet_with_noops, write_packet};

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub tcp_connected: bool,
    pub m1_sent: bool,
    pub response_received: bool,
    pub empty_noop_frames: usize,
    pub response_frame_type: u8,
    pub response_body_bytes: usize,
    pub response_state: Option<u8>,
    pub m1_schema: Option<serde_json::Value>,
    pub response_schema: Option<serde_json::Value>,
    pub processing_result: String,
    pub signature_verified: bool,
    pub verified_peer: Option<String>,
    pub authenticated: bool,
    pub m3_sent: bool,
}

pub async fn run(
    host: &str,
    port: u16,
    peer_public_key_path: Option<&Path>,
) -> Result<ProbeReport> {
    ensure!(port != 0, "probe requires an explicit nonzero port");
    let trusted_peers = match peer_public_key_path {
        Some(path) => vec![load_peer_public_key(path)?],
        None => Vec::new(),
    };
    tokio::time::timeout(std::time::Duration::from_secs(25), async {
        let target = crate::discover::socket_target(host, port).await?;
        let mut socket = TcpStream::connect(target)
            .await
            .context("probe TCP connect")?;
        socket.set_nodelay(true)?;
        observe(&mut socket, PairVerifyClient::verifier_only(trusted_peers)).await
    })
    .await
    .context("probe exceeded 25-second budget")?
}

async fn observe<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    mut client: PairVerifyClient,
) -> Result<ProbeReport> {
    let m1 = client.build_m1();
    let m1_schema = handshake_schema(&m1);
    write_packet(stream, &m1)
        .await
        .context("probe sending M1")?;
    let (response, empty_noop_frames) = read_packet_with_noops(stream)
        .await
        .context("probe reading M2")?;
    let state = response
        .pairing_tlv()
        .ok()
        .and_then(|t| t.get(6).filter(|b| b.len() == 1).map(|b| b[0]));
    // This verifier-only API owns no signing key and cannot construct M3.
    let (processing_result, verified_peer) = match client.verify_m2_only(&response) {
        Ok(label) => (
            format!("M2 signature verified for {label}; stopped before M3"),
            Some(label),
        ),
        Err(error) => (error.to_string(), None),
    };
    let signature_verified = verified_peer.is_some();
    Ok(ProbeReport {
        tcp_connected: true,
        m1_sent: true,
        response_received: true,
        empty_noop_frames,
        response_frame_type: response.ptype as u8,
        response_body_bytes: response.body.len(),
        response_state: state,
        m1_schema,
        response_schema: handshake_schema(&response),
        processing_result,
        signature_verified,
        verified_peer,
        authenticated: false,
        m3_sent: false,
    })
}

/// Structural diagnostics only. No arbitrary strings or bytes reach the report.
/// Bodies above 64 KiB are omitted; output fields and TLVs are independently capped.
pub(crate) fn handshake_schema(
    packet: &crate::companion::ContinuityPacket,
) -> Option<serde_json::Value> {
    use crate::opack::{self, Value};
    use serde_json::json;
    if packet.body.len() > 65536 {
        return None;
    }
    let Value::Dict(pairs) = opack::decode(&packet.body).ok()? else {
        return None;
    };
    let mut fields = Vec::new();
    let mut unknown = 0usize;
    let mut omitted = 0usize;
    let mut tlvs = Vec::new();
    let mut tlv_omitted = 0usize;
    let mut tlv_valid = None;
    for (key, value) in &pairs {
        let name = match key {
            Value::Str(s) => match s.as_str() {
                "_pd" => "_pd",
                "_auTy" => "_auTy",
                "_flags" => "_flags",
                "_state" => "_state",
                _ => {
                    unknown += 1;
                    continue;
                }
            },
            _ => {
                unknown += 1;
                continue;
            }
        };
        if fields.len() >= 16 {
            omitted += 1;
            continue;
        }
        let (kind, length) = match value {
            Value::Null => ("null", 0),
            Value::Float(_) => ("float", 8),
            Value::Uuid(_) => ("uuid", 16),
            Value::Time(_) => ("time", 8),
            Value::Bool(_) => ("bool", 1),
            Value::Int(_) => ("integer", 8),
            Value::Str(v) => ("string", v.len()),
            Value::Bytes(v) => ("bytes", v.len()),
            Value::Array(v) => ("array", v.len()),
            Value::Dict(v) => ("dict", v.len()),
        };
        let scalar = if matches!(name, "_auTy" | "_flags" | "_state") {
            value.as_u64().filter(|v| *v <= u32::MAX as u64)
        } else {
            None
        };
        fields.push(json!({"key":name,"type":kind,"length":length,"scalar":scalar}));
        if name == "_pd" {
            if let Value::Bytes(bytes) = value {
                match crate::tlv8::Tlv8::decode_checked(bytes) {
                    Ok(tlv) => {
                        tlv_valid = Some(true);
                        for (kind, bytes) in tlv.items {
                            if tlvs.len() >= 32 {
                                tlv_omitted += 1;
                                continue;
                            }
                            let scalar = if matches!(kind, 0x06 | 0x19) && bytes.len() == 1 {
                                Some(bytes[0])
                            } else {
                                None
                            };
                            tlvs.push(json!({"type":kind,"length":bytes.len(),"scalar":scalar}));
                        }
                    }
                    Err(_) => tlv_valid = Some(false),
                }
            }
        }
    }
    Some(
        json!({"frame_type":packet.ptype as u8,"body_bytes":packet.body.len(),"fields":fields,"unknown_field_count":unknown,"omitted_field_count":omitted,"tlv_valid":tlv_valid,"tlvs":tlvs,"omitted_tlv_count":tlv_omitted}),
    )
}

/// Load one explicitly supplied Ed25519 public key. Accept either 32 raw bytes
/// or 64 hexadecimal characters (optionally followed by whitespace/newline).
/// Private identity JSON is not accepted by this input path.
fn load_peer_public_key(path: &Path) -> Result<(String, VerifyingKey)> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening peer public key {}", path.display()))?;
    let mut bytes = Vec::with_capacity(4097);
    file.take(4097)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading peer public key {}", path.display()))?;
    ensure!(
        bytes.len() <= 4096,
        "peer public-key file exceeds 4096-byte cap"
    );
    let key_bytes = if bytes.len() == 32 {
        bytes
    } else {
        let text = std::str::from_utf8(&bytes)
            .context("peer public key is neither raw bytes nor UTF-8 hex")?;
        let text = text.trim().strip_prefix("0x").unwrap_or(text.trim());
        ensure!(
            text.len() == 64,
            "peer public key hex must contain exactly 64 characters"
        );
        hex::decode(text).context("decoding peer public key hex")?
    };
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("peer public key must be exactly 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_array).context("invalid Ed25519 peer public key")?;
    let label = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("explicit-peer-public-key")
        .to_string();
    Ok((label, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companion::PairVerifyServer;
    use crate::companion_client::read_packet;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn observes_encrypted_m2_but_never_sends_m3() {
        let (_, server_id) = crate::companion_client::matched_loopback_identities();
        let untrusted = PairVerifyClient::verifier_only(Vec::new());
        let (mut client_stream, mut peer_stream) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let mut peer = PairVerifyServer::new(server_id);
            let m1 = read_packet(&mut peer_stream).await.unwrap();
            write_packet(
                &mut peer_stream,
                &crate::companion::ContinuityPacket::new(
                    crate::companion::PacketType::Finished,
                    vec![],
                ),
            )
            .await
            .unwrap();
            let m2 = peer.process_m1(&m1).unwrap();
            write_packet(&mut peer_stream, &m2).await.unwrap();
            let mut byte = [0];
            peer_stream.read(&mut byte).await.unwrap()
        });
        let report = observe(&mut client_stream, untrusted).await.unwrap();
        assert!(report.response_received);
        assert_eq!(report.response_state, Some(2));
        assert_eq!(report.empty_noop_frames, 1);
        assert_eq!(
            report.processing_result,
            "Pair-Verify rejected an unknown peer signature"
        );
        assert!(!report.signature_verified && report.verified_peer.is_none());
        assert!(!report.authenticated && !report.m3_sent);
        drop(client_stream);
        assert_eq!(task.await.unwrap(), 0);
    }

    #[tokio::test]
    async fn verifies_explicit_public_key_but_never_sends_m3() {
        let (_, server_id) = crate::companion_client::matched_loopback_identities();
        let server_public_key = server_id.signing.verifying_key();
        let verifier =
            PairVerifyClient::verifier_only(vec![("fixture-peer".to_string(), server_public_key)]);
        let (mut client_stream, mut peer_stream) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let mut peer = PairVerifyServer::new(server_id);
            let m1 = read_packet(&mut peer_stream).await.unwrap();
            let m2 = peer.process_m1(&m1).unwrap();
            write_packet(&mut peer_stream, &m2).await.unwrap();
            let mut byte = [0];
            peer_stream.read(&mut byte).await.unwrap()
        });

        let report = observe(&mut client_stream, verifier).await.unwrap();
        assert!(report.signature_verified);
        assert_eq!(report.verified_peer.as_deref(), Some("fixture-peer"));
        assert!(report.processing_result.contains("stopped before M3"));
        assert!(!report.authenticated && !report.m3_sent);
        drop(client_stream);
        assert_eq!(task.await.unwrap(), 0);
    }

    #[test]
    fn loads_only_one_raw_or_hex_public_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("peer-edpk.hex");
        let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let public = signing.verifying_key().to_bytes();
        std::fs::write(&path, format!("{}\n", hex::encode(public))).unwrap();
        let (label, key) = load_peer_public_key(&path).unwrap();
        assert_eq!(label, "peer-edpk.hex");
        assert_eq!(key.to_bytes(), public);

        std::fs::write(&path, vec![0x24u8; 33]).unwrap();
        assert!(load_peer_public_key(&path).is_err());
    }
    #[test]
    fn handshake_metadata_omits_private_bytes_and_unknown_keys() {
        use crate::{
            companion::{ContinuityPacket, PacketType},
            opack::{self, Value},
            tlv8::Tlv8,
        };
        let mut tlv = Tlv8::new();
        tlv.push_u8(6, 1)
            .push_u8(0x19, 1)
            .push(3, b"PRIVATE_KEY_SENTINEL".to_vec())
            .push(10, b"PRIVATE_SIGNATURE_SENTINEL".to_vec());
        let packet = ContinuityPacket::new(
            PacketType::PairVerifyPublicKey,
            opack::encode(&Value::dict([
                ("_pd", Value::Bytes(tlv.encode())),
                ("_auTy", Value::Int(4)),
                (
                    "PRIVATE_KEY_NAME",
                    Value::Str("PRIVATE_VALUE_SENTINEL".into()),
                ),
                ("_flags", Value::Str("PRIVATE_FLAGS_SENTINEL".into())),
            ])),
        );
        let schema = handshake_schema(&packet).unwrap();
        let output = schema.to_string();
        assert!(!output.contains("PRIVATE"));
        assert_eq!(schema["unknown_field_count"], 1);
        assert_eq!(schema["fields"][1]["scalar"], 4);
        assert_eq!(schema["tlvs"][0]["scalar"], 1);
        assert!(schema["tlvs"][2]["scalar"].is_null());
        assert!(schema["fields"][2]["scalar"].is_null());
    }

    #[test]
    fn handshake_metadata_bounds_unknown_and_repeated_fields() {
        use crate::{
            companion::{ContinuityPacket, PacketType},
            opack::{self, Value},
        };
        let mut pairs = Vec::new();
        for i in 0..100 {
            pairs.push((
                Value::Str(format!("secret-{i}")),
                Value::Str("hidden".into()),
            ));
            pairs.push((Value::Str("_state".into()), Value::Int(i)));
        }
        let packet = ContinuityPacket::new(
            PacketType::PairVerifyPublicKey,
            opack::encode(&Value::Dict(pairs)),
        );
        let schema = handshake_schema(&packet).unwrap();
        assert_eq!(schema["unknown_field_count"], 100);
        assert_eq!(schema["omitted_field_count"], 84);
        assert_eq!(schema["fields"].as_array().unwrap().len(), 16);
        assert!(!schema.to_string().contains("secret-"));
        let large = ContinuityPacket::new(PacketType::PairVerifyPublicKey, vec![0; 65537]);
        assert!(handshake_schema(&large).is_none());
    }
}
