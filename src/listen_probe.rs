//! Bounded inbound Pair-Verify diagnostic with explicit encrypted-control opt-ins.
use crate::{
    companion::{ContentChannel, PairVerifyServer, PairingIdentity},
    companion_client::{read_packet, write_packet},
};
use anyhow::{ensure, Context, Result};
use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};
use serde::Serialize;
use std::{collections::HashMap, net::Ipv4Addr, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
};

const SERVICE: &str = "_companion-link._tcp.local.";
const MAX_CLIENTS: usize = 16;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct Config {
    pub bind: Ipv4Addr,
    pub iface: String,
    pub port: u16,
    pub seconds: u64,
    pub identity: PathBuf,
    pub txt: Option<PathBuf>,
    pub observe_system_info: bool,
    pub probe_pasteboard_types: bool,
    pub system_info_ids_id_file: Option<PathBuf>,
    pub system_info_readiness_barrier: bool,
    pub probe_pasteboard_data: bool,
    pub copy_verified_text: bool,
    pub continuous: bool,
}

struct ControlIdentity {
    system_info: crate::opack::Value,

    ids_id_override: bool,
}

struct Advertisement(ServiceDaemon, String);
impl Drop for Advertisement {
    fn drop(&mut self) {
        // Wait briefly for the unregister command before shutting down the daemon.
        if let Ok(done) = self.0.unregister(&self.1) {
            let _ = done.recv_timeout(Duration::from_secs(1));
        }
        if let Ok(done) = self.0.shutdown() {
            let _ = done.recv_timeout(Duration::from_secs(1));
        }
    }
}

pub(crate) fn validate_interface(ip: Ipv4Addr, iface: &str) -> Result<()> {
    ensure!(
        !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        "explicit unicast bind address required"
    );
    let name = std::ffi::CString::new(iface)?;
    // getifaddrs provides the actual local addresses, avoiding wildcard binds
    // or accidentally advertising an address belonging to another interface.
    let mut head = std::ptr::null_mut();
    ensure!(
        unsafe { libc::getifaddrs(&mut head) } == 0,
        "cannot inspect local interfaces"
    );
    let mut found = false;
    let mut cur = head;
    unsafe {
        while !cur.is_null() {
            let entry = &*cur;
            if !entry.ifa_addr.is_null()
                && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET
                && std::ffi::CStr::from_ptr(entry.ifa_name) == name.as_c_str()
            {
                let address = &*(entry.ifa_addr as *const libc::sockaddr_in);
                found |= Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()) == ip;
            }
            cur = entry.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    ensure!(found, "bind address is not assigned to requested interface");
    Ok(())
}

#[derive(Debug, Serialize)]
struct ClientReport {
    event: &'static str,
    stage: &'static str,
    outcome: &'static str,
    authenticated: bool,
    reason: Option<&'static str>,
    m1_schema: Option<serde_json::Value>,
    m2_schema: Option<serde_json::Value>,
    content_requests_sent: bool,
    control_outcome: Option<&'static str>,
    control_schemas: Vec<serde_json::Value>,
    system_info_responses: usize,
    pasteboard_types: Option<serde_json::Value>,
    pasteboard_data: Option<serde_json::Value>,
    #[serde(skip)]
    verified_text: Option<Vec<u8>>,
    #[serde(skip)]
    verified_png: Option<Vec<u8>>,
    #[serde(skip)]
    authenticated_peer_fingerprint: Option<[u8; 32]>,
    clipboard_write: Option<serde_json::Value>,
    system_info_ids_id_override: bool,
    system_info_readiness: &'static str,
}
impl ClientReport {
    fn new() -> Self {
        Self {
            event: "client_result",
            stage: "await_m1",
            outcome: "pending",
            authenticated: false,
            reason: None,
            m1_schema: None,
            m2_schema: None,
            content_requests_sent: false,
            control_outcome: None,
            control_schemas: Vec::new(),
            system_info_responses: 0,
            pasteboard_types: None,
            pasteboard_data: None,
            verified_text: None,
            verified_png: None,
            authenticated_peer_fingerprint: None,
            clipboard_write: None,
            system_info_ids_id_override: false,
            system_info_readiness: "not_requested",
        }
    }
}

async fn verify<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: PairingIdentity,
    report: &mut ClientReport,
) -> Result<ContentChannel> {
    let mut verifier = PairVerifyServer::new(identity);
    // Shared reader bounds each phase to four empty NoOps and ten seconds.
    let m1 = read_packet(stream).await?;
    report.m1_schema = crate::pair_probe::handshake_schema(&m1);
    report.stage = "validate_m1";
    let m2 = verifier.process_m1(&m1)?;
    report.m2_schema = crate::pair_probe::handshake_schema(&m2);
    report.stage = "send_m2";
    write_packet(stream, &m2).await?;
    report.stage = "await_m3";
    let m3 = read_packet(stream).await?;
    report.stage = "validate_m3";
    let (m4, channel) = verifier.process_m3(&m3)?;
    report.stage = "send_m4";
    write_packet(stream, &m4).await?;
    report.stage = "complete";
    report.authenticated = true;
    report.authenticated_peer_fingerprint = verifier.authenticated_peer_fingerprint();
    Ok(channel)
}

#[cfg(test)]
async fn bounded_verify<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: PairingIdentity,
    duration: Duration,
) -> ClientReport {
    bounded_session(stream, identity, duration, None, false, false, false).await
}

#[cfg(test)]
async fn bounded_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: PairingIdentity,
    duration: Duration,
    system_info: Option<&ControlIdentity>,
    probe_types: bool,
    readiness_barrier: bool,
    probe_data: bool,
) -> ClientReport {
    bounded_session_with_capture(
        stream,
        identity,
        duration,
        system_info,
        probe_types,
        readiness_barrier,
        probe_data,
        true,
    )
    .await
}

async fn bounded_session_with_capture<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: PairingIdentity,
    duration: Duration,
    system_info: Option<&ControlIdentity>,
    probe_types: bool,
    readiness_barrier: bool,
    probe_data: bool,
    capture_archives: bool,
) -> ClientReport {
    let mut report = ClientReport::new();
    report.system_info_ids_id_override = system_info.is_some_and(|info| info.ids_id_override);
    match tokio::time::timeout(duration, verify(stream, identity, &mut report)).await {
        Ok(Ok(mut channel)) => {
            report.outcome = "authenticated";
            if let Some(ours) = system_info {
                report.stage = "observe_control";
                report.control_outcome = Some(
                    match tokio::time::timeout(
                        Duration::from_secs(if readiness_barrier { 15 } else { 10 }),
                        observe_control(
                            stream,
                            &mut channel,
                            ours,
                            &mut report,
                            probe_types,
                            readiness_barrier,
                            probe_data,
                            capture_archives,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(())) => "message_limit",
                        Ok(Err(error)) => classify_error(&error),
                        Err(_) => "timeout",
                    },
                );
                report.stage = "complete";
            }
        }
        Ok(Err(error)) => {
            report.reason = Some(classify_error(&error));
            report.outcome = "protocol_or_transport_rejected";
        }
        Err(_) => report.outcome = "timeout",
    }
    report
}

async fn observe_control<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    channel: &mut ContentChannel,
    ours: &ControlIdentity,
    report: &mut ClientReport,
    probe_types: bool,
    readiness_barrier: bool,
    probe_data: bool,
    capture_archives: bool,
) -> Result<()> {
    use crate::{
        companion_client::{recv_opack, send_opack},
        opack::Value,
    };
    let mut pending = None;
    let mut pending_data = None;
    let mut png_metadata = None;
    let mut readiness_xid = None;
    let mut peer_system_xid = None;
    for _ in 0..if readiness_barrier { 8 } else { 4 } {
        let message = recv_opack(stream, channel).await?;
        report.control_schemas.push(control_schema(&message));
        let response_xid = if message.get("_t").and_then(Value::as_u64) == Some(3) {
            message.get("_x").and_then(Value::as_u64)
        } else {
            None
        };
        if let Some(xid) = pending {
            if response_xid == Some(xid) {
                if let Ok(crate::clipboard::PayloadResponse::Archive(bytes)) =
                    crate::clipboard::validate_payload_response(&message, xid)
                {
                    if let Ok(board) = crate::clipboard::decode_pasteboard_archive(&bytes) {
                        png_metadata = crate::clipboard_sync::image::representation(&board)
                            .filter(|(kind, _)| *kind == crate::clipboard_sync::image::Kind::Png)
                            .and_then(|(_, r)| Some((r.provider_id?, r.size?)));
                    }
                }
                let metadata = pasteboard_metadata(&message, xid);
                let nonempty = metadata.get("outcome").and_then(serde_json::Value::as_str)
                    == Some("decoded_metadata")
                    && metadata
                        .get("representations")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|items| !items.is_empty());
                report.pasteboard_types = Some(metadata);
                pending = None;
                if probe_data
                    && nonempty
                    && report.system_info_readiness == "acknowledged"
                    && report.pasteboard_data.is_none()
                {
                    let mut data_xid = 0x4c4e5901;
                    while Some(data_xid) == peer_system_xid
                        || Some(data_xid) == readiness_xid
                        || data_xid == xid
                    {
                        data_xid += 1;
                    }
                    let request = crate::clipboard::build_payload_request(
                        data_xid,
                        crate::clipboard::COMMAND_PB_PASTE2,
                        &uuid::Uuid::new_v4().to_string(),
                        b"pbpaste!",
                    )?;
                    send_opack(stream, channel, &request).await?;
                    report.pasteboard_data =
                        Some(serde_json::json!({"outcome":"awaiting_response"}));
                    pending_data = Some(data_xid);
                }
            }
        }
        if let Some(xid) = pending_data {
            if response_xid == Some(xid) {
                report.pasteboard_data =
                    Some(pasteboard_data_diagnostic(&message, xid, capture_archives));
                if let Ok(crate::clipboard::PayloadResponse::Archive(bytes)) =
                    crate::clipboard::validate_payload_response(&message, xid)
                {
                    if let Ok(board) = crate::clipboard::decode_pasteboard_archive(&bytes) {
                        report.verified_text = verified_inline_text(&board);
                        if let Some(payload) = crate::clipboard_sync::image::inline(&board) {
                            if payload.kind == crate::clipboard_sync::image::Kind::Png {
                                let rep = crate::clipboard_sync::image::representation(&board)
                                    .unwrap()
                                    .1;
                                if png_metadata.is_some()
                                    && png_metadata == rep.provider_id.zip(rep.size)
                                {
                                    report.verified_png = Some(payload.bytes.to_vec());
                                }
                            }
                        }
                    }
                }
                pending_data = None;
                if report.verified_text.is_some() {
                    return Ok(());
                }
            }
        }
        if let Some(xid) = readiness_xid {
            if response_xid == Some(xid) && report.system_info_readiness == "awaiting_response" {
                if message.get("_em").is_some()
                    || message.get("_ec").is_some_and(|v| v.as_u64() != Some(0))
                {
                    report.system_info_readiness = "peer_error";
                } else if !matches!(message.get("_c"), Some(Value::Dict(_))) {
                    report.system_info_readiness = "invalid_response";
                } else {
                    report.system_info_readiness = "acknowledged";
                    if probe_types && !report.content_requests_sent {
                        pending = Some(
                            send_types_request(
                                stream,
                                channel,
                                ours,
                                report,
                                peer_system_xid,
                                Some(xid),
                            )
                            .await?,
                        );
                    }
                }
            }
        }
        if message.get("_t").and_then(Value::as_u64) == Some(2)
            && message.get("_i").and_then(Value::as_str) == Some("_systemInfo")
        {
            if let Some(xid) = message.get("_x").and_then(Value::as_u64) {
                send_opack(
                    stream,
                    channel,
                    &Value::dict([
                        ("_t", Value::Int(3)),
                        ("_x", Value::Int(xid)),
                        ("_c", ours.system_info.clone()),
                    ]),
                )
                .await?;
                report.system_info_responses += 1;
                if readiness_barrier && readiness_xid.is_none() {
                    peer_system_xid = Some(xid);
                    let ours_xid = if xid == 0x4c4e5701 {
                        0x4c4e5702
                    } else {
                        0x4c4e5701
                    };
                    let request = crate::clipboard::build_system_info_request(
                        ours_xid,
                        ours.system_info.clone(),
                    )?;
                    send_opack(stream, channel, &request).await?;
                    readiness_xid = Some(ours_xid);
                    report.system_info_readiness = "awaiting_response";
                } else if !readiness_barrier && probe_types && !report.content_requests_sent {
                    pending = Some(
                        send_types_request(stream, channel, ours, report, Some(xid), None).await?,
                    );
                }
            }
        }
    }
    Ok(())
}

async fn send_types_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    channel: &mut ContentChannel,
    _ours: &ControlIdentity,
    report: &mut ClientReport,
    peer_xid: Option<u64>,
    readiness_xid: Option<u64>,
) -> Result<u64> {
    let mut xid = 0x4c4e5801;
    while Some(xid) == peer_xid || Some(xid) == readiness_xid {
        xid += 1;
    }
    // Native sharingd creates a fresh UUID per payload request; this is not
    // the signing identity, advertised IDS identity, or target device ID.
    let request = crate::clipboard::build_payload_request(
        xid,
        crate::clipboard::COMMAND_PB_TYPES,
        &uuid::Uuid::new_v4().to_string(),
        b"pbtypes!",
    )?;
    crate::companion_client::send_opack(stream, channel, &request).await?;
    report.content_requests_sent = true;
    report.pasteboard_types = Some(serde_json::json!({"outcome":"awaiting_response"}));
    Ok(xid)
}

fn pasteboard_metadata(message: &crate::opack::Value, xid: u64) -> serde_json::Value {
    use crate::clipboard::{decode_pasteboard_archive, validate_payload_response, PayloadResponse};
    use serde_json::json;
    match validate_payload_response(message, xid) {
        Ok(PayloadResponse::RemoteError(_)) => {
            json!({"outcome":"peer_error", "diagnostic": protocol_diagnostic(message)})
        }
        Ok(PayloadResponse::Archive(bytes)) => match decode_pasteboard_archive(&bytes) {
            Ok(board) => {
                let representations: Vec<_> = board
                    .representations
                    .iter()
                    .take(64)
                    .map(|r| {
                        let uti = if r.uti.len() <= 255
                            && r.uti
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
                        {
                            r.uti.as_str()
                        } else {
                            "redacted-invalid-uti"
                        };
                        json!({"uti":uti,"offset":r.offset,"size":r.size})
                    })
                    .collect();
                json!({"outcome":"decoded_metadata","archive_bytes":bytes.len(),"protocol_version":board.protocol_version,"extra_data_type":board.extra_data_type,"data_size":board.data_size,"representations":representations,"omitted_representations":board.representations.len().saturating_sub(64)})
            }
            Err(error) => {
                let failure = archive_failure(&error);
                let outcome = if failure == "no_remote_pasteboard" {
                    "no_remote_pasteboard"
                } else {
                    "unsupported_archive"
                };
                json!({"outcome":outcome,"archive_bytes":bytes.len(),"parse_failure":failure,"archive_schema":archive_schema(&bytes)})
            }
        },
        Err(_) => json!({"outcome":"invalid_response_envelope"}),
    }
}

fn verified_inline_text(board: &crate::clipboard::DecodedPasteboard) -> Option<Vec<u8>> {
    if board.extra_data_type != Some(2) {
        return None;
    }
    board.representations.iter().find_map(|r| {
        if r.uti != "public.utf8-plain-text" {
            return None;
        }
        let bytes = r.data.as_ref()?;
        std::str::from_utf8(bytes).ok()?;
        Some(bytes.clone())
    })
}

fn pasteboard_data_diagnostic(
    message: &crate::opack::Value,
    xid: u64,
    capture_archives: bool,
) -> serde_json::Value {
    let mut diagnostic = pasteboard_metadata(message, xid);
    if let Ok(crate::clipboard::PayloadResponse::Archive(bytes)) =
        crate::clipboard::validate_payload_response(message, xid)
    {
        let decoded = crate::clipboard::decode_pasteboard_archive(&bytes).ok();
        if let Some(board) = decoded
            .as_ref()
            .filter(|board| board.extra_data_type == Some(2))
        {
            let inline: Vec<_> = board
                .representations
                .iter()
                .filter_map(|r| r.data.as_deref())
                .collect();
            let matches = board.representations.iter().any(|representation| {
                representation.uti == "public.utf8-plain-text"
                    && representation
                        .data
                        .as_deref()
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        == Some("native clipboard test 45")
            });
            if let Some(fields) = diagnostic.as_object_mut() {
                fields.insert(
                    "inline_representation_count".into(),
                    serde_json::json!(inline.len()),
                );
                fields.insert(
                    "inline_total_bytes".into(),
                    serde_json::json!(inline.iter().map(|bytes| bytes.len()).sum::<usize>()),
                );
                fields.insert(
                    "matches_expected_probe_text45".into(),
                    serde_json::json!(matches),
                );
            }
        } else {
            if let Some(board) = decoded.as_ref() {
                if let Some(fields) = diagnostic.as_object_mut() {
                    fields.insert(
                        "outcome".into(),
                        serde_json::json!(if board.extra_data_type == Some(1) {
                            "stream_endpoint"
                        } else {
                            "unsupported_extra_data_type"
                        }),
                    );
                }
            }
            if !capture_archives {
                return diagnostic;
            }
            let capture = capture_data_archive(&bytes);
            if let Some(fields) = diagnostic.as_object_mut() {
                match capture {
                    Ok(path) => {
                        fields.insert("private_capture_path".into(), serde_json::json!(path));
                    }
                    Err(_) => {
                        fields.insert("private_capture_status".into(), serde_json::json!("failed"));
                    }
                }
            }
        }
    }
    diagnostic
}

fn capture_data_archive(bytes: &[u8]) -> Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let base = PathBuf::from(std::env::var_os("HOME").context("home directory absent")?)
        .join(".local/share/native-clipboard-research");
    let metadata = std::fs::symlink_metadata(&base)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "capture directory must be private and owned"
    );
    let path = base.join(format!("pbpaste2-capture-{}.bplist", uuid::Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(bytes)?;
    Ok(path)
}

fn archive_failure(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        match cause.to_string().as_str() {
            "clipboard archive contains a remote NSError" => return "remote_ns_error",
            "clipboard archive contains no pasteboard info" => return "no_remote_pasteboard",
            "parsing keyed archive plist" => return "invalid_plist",
            "plist is not an NSKeyedArchiver archive" => return "not_keyed_archive",
            "file-handle-backed pasteboard data is unsupported" => return "file_handle_backed",
            "path-backed pasteboard data is unsupported" => return "path_backed",
            "wrapper is missing pasteboard info" => return "missing_pasteboard_info",
            _ => {}
        }
    }
    "unsupported_archive_shape"
}

/// Inspect an inert property list without logging archived content or userInfo.
fn archive_schema(bytes: &[u8]) -> serde_json::Value {
    use plist::Value as P;
    use serde_json::json;
    if bytes.len() > 65536 {
        return json!({"diagnostic":"size_limit"});
    }
    let Ok(root) = P::from_reader(std::io::Cursor::new(bytes)) else {
        return json!({"diagnostic":"invalid_plist"});
    };
    fn describe(value: &P) -> serde_json::Value {
        match value {
            P::Array(v) => json!({"type":"array","count":v.len()}),
            P::Dictionary(v) => json!({"type":"dictionary","count":v.len()}),
            P::Data(v) => json!({"type":"data","bytes":v.len()}),
            P::String(v) => json!({"type":"string","bytes":v.len()}),
            P::Uid(v) => json!({"type":"uid","index":v.get()}),
            P::Integer(_) => json!({"type":"integer"}),
            P::Real(_) => json!({"type":"real"}),
            P::Boolean(_) => json!({"type":"boolean"}),
            P::Date(_) => json!({"type":"date"}),
            _ => json!({"type":"unknown"}),
        }
    }
    fn known_key(key: &str) -> bool {
        matches!(
            key,
            "$archiver"
                | "$version"
                | "$objects"
                | "$top"
                | "root"
                | "$class"
                | "$classes"
                | "$classname"
                | "NS.keys"
                | "NS.objects"
                | "NS.data"
                | "NS.string"
                | "NSCode"
                | "NSDomain"
                | "NSUserInfo"
                | "UASharedPasteboardInfoWrapperErrorKey"
                | "UASharedPasteboardInfoWrapperExtraTypeKey"
                | "UASharedPasteboardInfoWrapperProtocolVersionKey"
                | "UASharedPasteboardInfoWrapperExtraDataKey"
                | "UASharedPasteboardInfoWrapperPBInfoKey"
                | "UASharedPasteboardInfoDataSizeKey"
                | "UASharedPasteboardInfoDataFileKey"
                | "UASharedPasteboardInfoDataPathKey"
                | "UASharedPasteboardInfoExtensionKey"
                | "UASharedPasteboardInfoItemsKey"
                | "UASharedPasteboardItemInfoTypesKey"
                | "UASharedPasteboardTypeInfoTypeKey"
                | "UASharedPasteboardTypeInfoUUIDKey"
                | "UASharedPasteboardTypeInfoDataFileKey"
                | "UASharedPasteboardTypeInfoIndex"
                | "UASharedPasteboardTypeInfoOffsetKey"
                | "UASharedPasteboardTypeInfoSizeKey"
        )
    }
    fn fields(value: &P) -> serde_json::Value {
        let Some(dict) = value.as_dictionary() else {
            return describe(value);
        };
        let mut result = Vec::new();
        let mut unknown = 0;
        let mut omitted = 0;
        for (key, value) in dict {
            if !known_key(key) {
                unknown += 1;
                continue;
            }
            if result.len() >= 32 {
                omitted += 1;
                continue;
            }
            result.push(json!({"key":key,"value_schema":describe(value)}));
        }
        json!({"type":"dictionary","count":dict.len(),"fields":result,"unknown_keys":unknown,"omitted_fields":omitted})
    }
    fn resolve<'a>(value: &'a P, objects: &'a [P]) -> Option<&'a P> {
        let mut current = value;
        for _ in 0..16 {
            match current {
                P::Uid(uid) => current = objects.get(usize::try_from(uid.get()).ok()?)?,
                _ => return Some(current),
            }
        }
        None
    }
    fn safe_name(text: &str) -> Option<&str> {
        (!text.is_empty()
            && text.len() <= 96
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)))
        .then_some(text)
    }
    let Some(dict) = root.as_dictionary() else {
        return json!({"root":describe(&root)});
    };
    let objects = dict
        .get("$objects")
        .and_then(P::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let descriptions: Vec<_> = objects
        .iter()
        .take(64)
        .enumerate()
        .map(|(index, value)| json!({"index":index,"schema":fields(value)}))
        .collect();
    let mut classes = std::collections::BTreeSet::new();
    for object in objects.iter().take(256) {
        if let Some(name) = object
            .as_dictionary()
            .and_then(|v| v.get("$classname"))
            .and_then(P::as_string)
            .and_then(safe_name)
        {
            if classes.len() < 32 {
                classes.insert(name);
            }
        }
    }
    let remote_error = (|| {
        let wrapper_ref = dict.get("$top")?.as_dictionary()?.get("root")?;
        let wrapper = resolve(wrapper_ref, objects)?.as_dictionary()?;
        let error = resolve(
            wrapper.get("UASharedPasteboardInfoWrapperErrorKey")?,
            objects,
        )?
        .as_dictionary()?;
        let class = resolve(error.get("$class")?, objects)?.as_dictionary()?;
        if class.get("$classname")?.as_string()? != "NSError" {
            return None;
        }
        let domain = error
            .get("NSDomain")
            .and_then(|v| resolve(v, objects))
            .and_then(P::as_string)
            .and_then(safe_name);
        let code = error
            .get("NSCode")
            .and_then(|v| resolve(v, objects))
            .and_then(P::as_signed_integer);
        Some(
            json!({"class":"NSError","domain":domain,"code":code,"user_info_present":error.contains_key("NSUserInfo")}),
        )
    })();
    json!({"root":fields(&root),"top":dict.get("$top").map(fields),"object_count":objects.len(),"objects":descriptions,"omitted_objects":objects.len().saturating_sub(64),"classes":classes,"remote_error":remote_error})
}

/// Only the protocol's error/selector fields are eligible for bounded text
/// diagnostics. Never inspect nested content, clipboard bytes, or peer names.
fn protocol_diagnostic(message: &crate::opack::Value) -> serde_json::Value {
    use crate::opack::Value;
    fn bounded_ascii(text: &str) -> Option<&str> {
        (!text.is_empty() && text.len() <= 96 && text.bytes().all(|b| (0x20..=0x7e).contains(&b)))
            .then_some(text)
    }
    let error = message.get("_em").and_then(Value::as_str);
    let error_code = message.get("_ec").and_then(Value::as_u64);
    let selector = message.get("_i").and_then(Value::as_str).and_then(|s| {
        bounded_ascii(s).filter(|s| {
            (s.starts_with('_') || s.starts_with("com.apple."))
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    });
    serde_json::json!({
        "selector": selector,
        "error_code": error_code,
        "error_message": error.and_then(bounded_ascii),
        "error_message_bytes": error.map(str::len),
        "error_message_redacted": error.is_some() && error.and_then(bounded_ascii).is_none(),
    })
}

fn control_schema(message: &crate::opack::Value) -> serde_json::Value {
    use crate::opack::Value;
    use serde_json::json;
    fn fields(value: &Value, content: bool) -> serde_json::Value {
        let Value::Dict(pairs) = value else {
            return json!({"dictionary":false});
        };
        let mut fields = Vec::new();
        let mut unknown = 0;
        let mut unknown_protocol_keys = Vec::new();
        let mut unknown_key_shapes = Vec::new();
        let mut omitted = 0;
        for (key, value) in pairs {
            let name = match key {
                Value::Str(key)
                    if (!content
                        && matches!(key.as_str(), "_i" | "_t" | "_x" | "_c" | "_em" | "_ec"))
                        || (content
                            && matches!(
                                key.as_str(),
                                "name"
                                    | "model"
                                    | "_sv"
                                    | "_idsID"
                                    | "_pubID"
                                    | "_cf"
                                    | "_clFl"
                                    | "_sf"
                                    | "rActPayload"
                                    | "rClientCommand"
                                    | "rIdentifier"
                                    | "rAdvPayload"
                            )) =>
                {
                    key.as_str()
                }
                _ => {
                    unknown += 1;
                    if !content && unknown_key_shapes.len() < 8 {
                        let shape = match key {
                            Value::Str(name) => {
                                if name.len() <= 96
                                    && (name.starts_with('_')
                                        || name.starts_with('$')
                                        || name.starts_with("com.apple.")
                                        || matches!(name.as_str(), "name" | "model"))
                                    && name
                                        .bytes()
                                        .all(|b| b.is_ascii_alphanumeric() || b"._-$".contains(&b))
                                {
                                    unknown_protocol_keys.push(name.as_str());
                                }
                                json!({"type":"string","bytes":name.len()})
                            }
                            Value::Bytes(bytes) => json!({"type":"bytes","bytes":bytes.len()}),
                            Value::Int(_) => json!({"type":"integer"}),
                            _ => json!({"type":"other"}),
                        };
                        unknown_key_shapes.push(shape);
                    }
                    continue;
                }
            };
            if fields.len() >= 24 {
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
            fields.push(json!({"key":name,"type":kind,"length":length}));
        }
        json!({"dictionary":true,"fields":fields,"unknown_field_count":unknown,"omitted_field_count":omitted,"unknown_protocol_keys":unknown_protocol_keys,"unknown_key_shapes":unknown_key_shapes})
    }
    let selector = match message.get("_i").and_then(Value::as_str) {
        Some("_systemInfo") => "_systemInfo",
        Some("com.apple.handoff.payload-request") => "com.apple.handoff.payload-request",
        Some(_) => "unknown",
        None => "absent",
    };
    json!({"top":fields(message,false),"content":message.get("_c").map(|v|fields(v,true)),"selector":selector,"message_type":message.get("_t").and_then(Value::as_u64).filter(|v| (1..=3).contains(v)),"diagnostic":protocol_diagnostic(message)})
}

fn own_system_info(
    identity_path: &std::path::Path,
    properties: &HashMap<String, String>,
    ids_id_file: Option<&std::path::Path>,
) -> Result<ControlIdentity> {
    use crate::opack::Value;
    #[derive(serde::Deserialize)]
    struct Metadata {
        identifier: String,
    }
    let metadata: Metadata = serde_json::from_slice(&std::fs::read(identity_path)?)
        .context("identity requires its own identifier for system-info observation")?;
    uuid::Uuid::parse_str(&metadata.identifier).context("own identifier must be a UUID")?;
    let address = properties
        .get("rpBA")
        .context("system-info observation requires own rpBA in supplied TXT")?;
    ensure!(
        address.len() == 17
            && address.split(':').count() == 6
            && address
                .split(':')
                .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit())),
        "own rpBA must be a six-byte colon-separated address"
    );
    let version = properties
        .get("rpVr")
        .context("system-info observation requires rpVr in supplied TXT")?;
    ensure!(
        !version.is_empty()
            && version.len() <= 32
            && version.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        "rpVr must be a numeric dotted protocol version"
    );
    let advertised_ids_id = match ids_id_file {
        Some(path) => read_private_ids_id(path)?,
        None => metadata.identifier.clone(),
    };
    Ok(ControlIdentity {
        ids_id_override: ids_id_file.is_some(),
        system_info: Value::dict([
            ("name", Value::Str("Arch Clipboard Research".into())),
            ("model", Value::Str("Linux".into())),
            ("_sv", Value::Str(version.clone())),
            ("_idsID", Value::Str(advertised_ids_id)),
            ("_pubID", Value::Str(address.clone())),
        ]),
    })
}

fn read_private_ids_id(path: &std::path::Path) -> Result<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .context("cannot open private system-info IDS identifier file")?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "IDS identifier file must be regular");
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o077 == 0,
        "IDS identifier file must be owned by current user and inaccessible to group/others"
    );
    let mut text = String::new();
    file.take(129)
        .read_to_string(&mut text)
        .context("IDS identifier file must contain UTF-8")?;
    ensure!(
        text.len() <= 128,
        "IDS identifier file exceeds 128-byte bound"
    );
    let identifier = text.trim();
    uuid::Uuid::parse_str(identifier).context("IDS identifier file must contain one UUID")?;
    Ok(identifier.to_owned())
}

fn classify_error(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::UnexpectedEof => "peer_closed",
                std::io::ErrorKind::ConnectionReset => "connection_reset",
                _ => "io_error",
            };
        }
        let text = cause.to_string();
        if text.starts_with("Pair-Verify peer returned error TLV") {
            return "peer_hap_error";
        }
        if text == "Pair-Verify rejected an unknown client signature" {
            return "untrusted_client_signature";
        }
        if text == "more than four empty NoOp frames before packet" {
            return "noop_limit";
        }
        if text == "continuity read timed out" {
            return "read_timeout";
        }
    }
    "invalid_protocol"
}

pub async fn run(c: Config) -> Result<()> {
    ensure!(
        !c.continuous || c.copy_verified_text,
        "continuous mode requires verified text copying"
    );
    ensure!(
        !c.copy_verified_text || (c.probe_pasteboard_data && c.system_info_readiness_barrier),
        "clipboard copy requires data probe and readiness barrier"
    );
    ensure!(
        !c.probe_pasteboard_data || (c.probe_pasteboard_types && c.system_info_readiness_barrier),
        "data probe requires metadata and readiness barrier"
    );
    ensure!(
        !c.system_info_readiness_barrier || (c.observe_system_info && c.probe_pasteboard_types),
        "readiness barrier requires system-info and pasteboard-types probes"
    );
    ensure!(
        c.system_info_ids_id_file.is_none() || c.observe_system_info,
        "system-info IDS override requires system-info observation"
    );
    ensure!(
        !c.probe_pasteboard_types || c.observe_system_info,
        "pasteboard types probe requires system-info observation"
    );
    ensure!(
        (1..=300).contains(&c.seconds),
        "duration must be 1..=300 seconds"
    );
    validate_interface(c.bind, &c.iface)?;
    let identity = PairingIdentity::load(&c.identity)?;
    let properties: HashMap<String, String> = match c.txt {
        Some(path) => {
            ensure!(
                std::fs::metadata(&path)?.len() <= 4096,
                "TXT file exceeds 4096 bytes"
            );
            serde_json::from_slice(&std::fs::read(path)?)
                .context("TXT must be a JSON object of strings")?
        }
        None => HashMap::new(),
    };
    ensure!(properties.len() <= 32, "too many TXT properties");
    for (key, value) in &properties {
        ensure!(
            !key.is_empty()
                && key.bytes().all(|b| (0x20..=0x7e).contains(&b) && b != b'=')
                && key.len() + value.len() + 1 <= 255,
            "invalid TXT property"
        );
    }
    let system_info = if c.observe_system_info {
        Some(own_system_info(
            &c.identity,
            &properties,
            c.system_info_ids_id_file.as_deref(),
        )?)
    } else {
        None
    };
    let listener = TcpListener::bind((c.bind, c.port)).await?;
    let port = listener.local_addr()?.port();
    // Fresh Linux-only hostname, never an Apple peer's instance/hostname.
    let hostname = format!("linux-clipboard-{}.local.", uuid::Uuid::new_v4().simple());
    let info = ServiceInfo::new(
        SERVICE,
        "Linux Clipboard Research",
        &hostname,
        c.bind.to_string().as_str(),
        port,
        properties,
    )?;
    let daemon = ServiceDaemon::new()?;
    let announcement = Advertisement(daemon, info.get_fullname().to_owned());
    announcement.0.disable_interface(IfKind::All)?;
    announcement.0.enable_interface(c.iface.as_str())?;
    announcement.0.register(info)?;
    println!(
        "{}",
        serde_json::json!({"event":"listening", "bind":c.bind,"port":port,"iface":c.iface,"seconds":if c.continuous { None } else { Some(c.seconds) },"continuous":c.continuous,"max_clients":if c.continuous { None } else { Some(MAX_CLIENTS) },"hostname":hostname,"content_requests_sent":false})
    );
    let deadline = tokio::time::sleep(Duration::from_secs(c.seconds));
    tokio::pin!(deadline);
    let stop = crate::shutdown();
    tokio::pin!(stop);
    let mut network_check = tokio::time::interval(Duration::from_secs(10));
    network_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut clients = 0;
    let mut content_requests_sent = false;
    let mut sync_state = crate::clipboard_sync::SyncState::new();
    let reason = loop {
        let accepted = tokio::select! {
            _ = &mut deadline, if !c.continuous => break "expired",
            _ = &mut stop => break "signal",
            _ = network_check.tick(), if c.continuous => {
                validate_interface(c.bind, &c.iface).context("listening interface address changed")?;
                continue;
            },
            result = listener.accept() => result,
        };
        let (mut stream, peer) = accepted?;
        clients += 1;
        if !c.continuous {
            println!(
                "{}",
                serde_json::json!({"event":"accepted","client":clients,"peer":peer})
            );
        }
        let clipboard_before = if c.continuous {
            sync_state.snapshot().await
        } else {
            None
        };
        // Clone only local in-memory identity material; never serialize it.
        let client_identity = PairingIdentity {
            signing: identity.signing.clone(),
            device_irk: identity.device_irk,
            peers: identity.peers.clone(),
        };
        let mut report = tokio::select! {
            _ = &mut deadline, if !c.continuous => break "expired_during_client",
            _ = &mut stop => break "signal_during_client",
            report = bounded_session_with_capture(&mut stream, client_identity, CLIENT_TIMEOUT, system_info.as_ref(), c.probe_pasteboard_types, c.system_info_readiness_barrier, c.probe_pasteboard_data, !c.continuous) => report,
        };
        content_requests_sent |= report.content_requests_sent;
        drop(stream);
        if c.continuous
            && report.authenticated
            && report
                .pasteboard_types
                .as_ref()
                .and_then(|v| v.get("outcome"))
                .and_then(serde_json::Value::as_str)
                == Some("no_remote_pasteboard")
        {
            sync_state.observe_empty();
        }
        let mut clipboard_written = false;
        if c.copy_verified_text && report.authenticated {
            if let Some(bytes) = report.verified_png.take() {
                let result = sync_state
                    .apply_typed(
                        clipboard_before,
                        crate::clipboard_sync::image::Kind::Png,
                        &bytes,
                    )
                    .await;
                clipboard_written = result
                    .get("written")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                report.clipboard_write = Some(result);
            } else if let Some(bytes) = report.verified_text.take() {
                if c.continuous {
                    let result = sync_state.apply_remote(clipboard_before, &bytes).await;
                    clipboard_written = result
                        .get("written")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    report.clipboard_write = Some(result);
                } else {
                    let pb = crate::companion_client::Pasteboard {
                        items: vec![crate::companion_client::PasteboardItem {
                            uti: "public.utf8-plain-text".into(),
                            data: bytes,
                        }],
                    };
                    report.clipboard_write = Some(
                        match crate::clipboard_out::copy_pasteboard(&pb) {
                            Ok(Some(outcome)) => {
                                clipboard_written = outcome.spawned;
                                serde_json::json!({"written":outcome.spawned,"bytes":outcome.bytes,"uti":outcome.uti})
                            }
                            _ => {
                                serde_json::json!({"written":false,"reason":"clipboard_copy_failed"})
                            }
                        },
                    );
                }
            }
        }
        if c.continuous {
            println!(
                "{}",
                serde_json::json!({"event":"sync_result","client":clients,"authenticated":report.authenticated,"reason":report.reason,"readiness":report.system_info_readiness,"clipboard":report.clipboard_write,"pasteboard_outcome":report.pasteboard_types.as_ref().and_then(|value| value.get("outcome"))})
            );
        } else {
            println!("{}", serde_json::to_string(&report)?);
        }
        if clipboard_written && !c.continuous {
            break "clipboard_written";
        }
        if clients >= MAX_CLIENTS && !c.continuous {
            break "client_limit";
        }
    };
    drop(listener);
    drop(announcement);
    println!(
        "{}",
        serde_json::json!({"event":"stopped","reason":reason,"clients":clients,"content_requests_sent":content_requests_sent})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn server_case(untrusted: bool) {
        let (client, mut server) = crate::companion_client::matched_loopback_identities();
        if untrusted {
            server.peers.clear();
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            bounded_verify(&mut stream, server, Duration::from_secs(2)).await
        });
        let result = crate::companion_client::connect("127.0.0.1", addr.port(), client).await;
        if untrusted {
            assert!(result.is_err());
        } else {
            assert!(result.is_ok());
        }
        drop(result);
        let report = task.await.unwrap();
        assert_eq!(report.authenticated, !untrusted);
        assert_eq!(
            report.stage,
            if untrusted { "validate_m3" } else { "complete" }
        );
        assert!(!report.content_requests_sent);
        if untrusted {
            assert_eq!(report.reason, Some("untrusted_client_signature"));
        }
    }
    #[tokio::test]
    async fn matched_loopback_authenticates() {
        server_case(false).await;
    }
    #[tokio::test]
    async fn unknown_client_rejected_at_m3() {
        server_case(true).await;
    }

    #[tokio::test]
    async fn malformed_and_excess_noops_rejected() {
        for bytes in [vec![0xff, 0, 0, 0], vec![1, 0, 0, 0].repeat(5)] {
            let (_, identity) = crate::companion_client::matched_loopback_identities();
            let (mut input, mut stream) = tokio::io::duplex(64);
            input.write_all(&bytes).await.unwrap();
            let report = bounded_verify(&mut stream, identity, Duration::from_secs(1)).await;
            assert_eq!(report.outcome, "protocol_or_transport_rejected");
            assert!(!report.authenticated);
            drop(stream);
            let mut byte = [0];
            assert_eq!(input.read(&mut byte).await.unwrap(), 0);
        }
    }
    #[tokio::test(start_paused = true)]
    async fn silent_client_times_out() {
        let (_, identity) = crate::companion_client::matched_loopback_identities();
        let (_input, mut stream) = tokio::io::duplex(64);
        let report = bounded_verify(&mut stream, identity, Duration::from_secs(1)).await;
        assert_eq!(report.outcome, "timeout");
        assert_eq!(report.stage, "await_m1");
    }
    #[test]
    fn rejects_wildcard_and_wrong_interface() {
        assert!(validate_interface(Ipv4Addr::UNSPECIFIED, "lo").is_err());
        assert!(validate_interface(Ipv4Addr::LOCALHOST, "nonexistent-interface").is_err());
        assert!(validate_interface(Ipv4Addr::LOCALHOST, "lo").is_ok());
    }
    fn assert_probe_request(
        value: &crate::opack::Value,
        xid: u64,
        command: &str,
        payload: &[u8],
    ) -> String {
        use crate::opack::Value;
        let identifier = value
            .get("_c")
            .and_then(|v| v.get("rIdentifier"))
            .and_then(Value::as_str)
            .unwrap();
        assert!(uuid::Uuid::parse_str(identifier).is_ok());
        assert_ne!(identifier, "00000000-0000-4000-8000-000000000001");
        assert_ne!(identifier, "00000000-0000-4000-8000-000000000099");
        assert_eq!(
            value,
            &crate::clipboard::build_payload_request(xid, command, identifier, payload).unwrap()
        );
        identifier.into()
    }
    fn test_system_info() -> ControlIdentity {
        use crate::opack::Value;
        ControlIdentity {
            ids_id_override: false,
            system_info: Value::dict([
                ("name", Value::Str("Arch Clipboard Research".into())),
                ("model", Value::Str("Linux".into())),
                ("_sv", Value::Str("680.1.1".into())),
                (
                    "_idsID",
                    Value::Str("00000000-0000-4000-8000-000000000001".into()),
                ),
                ("_pubID", Value::Str("02:00:00:00:00:01".into())),
            ]),
        }
    }

    async fn test_handshake(
        stream: &mut tokio::io::DuplexStream,
        identity: PairingIdentity,
    ) -> ContentChannel {
        let mut client = crate::companion::PairVerifyClient::new(identity);
        write_packet(stream, &client.build_m1()).await.unwrap();
        let m2 = read_packet(stream).await.unwrap();
        let m3 = client.process_m2(&m2).unwrap();
        write_packet(stream, &m3).await.unwrap();
        let m4 = read_packet(stream).await.unwrap();
        client.check_m4(&m4).unwrap()
    }

    #[tokio::test]
    async fn encrypted_system_info_only_returns_truthful_metadata() {
        use crate::{
            companion_client::{recv_opack, send_opack},
            opack::Value,
        };
        let (client, server) = crate::companion_client::matched_loopback_identities();
        let (mut input, mut stream) = tokio::io::duplex(16384);
        let task = tokio::spawn(async move {
            bounded_session(
                &mut stream,
                server,
                Duration::from_secs(2),
                Some(&test_system_info()),
                false,
                false,
                false,
            )
            .await
        });
        let mut channel = test_handshake(&mut input, client).await;
        for xid in 1..=4 {
            let req = crate::clipboard::build_system_info_request(
                xid,
                Value::dict([("name", Value::Str("PRIVATE_PEER_NAME".into()))]),
            )
            .unwrap();
            send_opack(&mut input, &mut channel, &req).await.unwrap();
            let response = recv_opack(&mut input, &mut channel).await.unwrap();
            assert_eq!(response.get("_x").and_then(Value::as_u64), Some(xid));
            assert_eq!(response.get("_t").and_then(Value::as_u64), Some(3));
            assert_eq!(response.get("_c"), Some(&test_system_info().system_info));
        }
        let report = task.await.unwrap();
        assert!(report.authenticated);
        assert_eq!(report.system_info_responses, 4);
        assert_eq!(report.control_outcome, Some("message_limit"));
        assert!(!report.content_requests_sent);
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("PRIVATE_PEER_NAME"));
        let mut byte = [0];
        assert_eq!(input.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn types_request_once_after_system_info_and_matches_transaction() {
        use crate::{
            companion_client::{recv_opack, send_opack},
            opack::Value,
        };
        let (client, server) = crate::companion_client::matched_loopback_identities();
        let (mut input, mut stream) = tokio::io::duplex(16384);
        let task = tokio::spawn(async move {
            let mut ours = test_system_info();
            if let Value::Dict(fields) = &mut ours.system_info {
                let (_, id) = fields
                    .iter_mut()
                    .find(|(key, _)| key.as_str() == Some("_idsID"))
                    .unwrap();
                *id = Value::Str("00000000-0000-4000-8000-000000000099".into());
            }
            ours.ids_id_override = true;
            bounded_session(
                &mut stream,
                server,
                Duration::from_secs(2),
                Some(&ours),
                true,
                false,
                false,
            )
            .await
        });
        let mut channel = test_handshake(&mut input, client).await;
        // No proactive request is sent merely because Pair-Verify succeeded.
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), input.read(&mut byte))
                .await
                .is_err()
        );
        let request =
            crate::clipboard::build_system_info_request(0x4c4e5801, Value::dict([])).unwrap();
        send_opack(&mut input, &mut channel, &request)
            .await
            .unwrap();
        let response = recv_opack(&mut input, &mut channel).await.unwrap();
        assert_eq!(response.get("_x").and_then(Value::as_u64), Some(0x4c4e5801));
        assert_eq!(
            response
                .get("_c")
                .and_then(|v| v.get("_idsID"))
                .and_then(Value::as_str),
            Some("00000000-0000-4000-8000-000000000099")
        );
        let types = recv_opack(&mut input, &mut channel).await.unwrap();
        assert_probe_request(&types, 0x4c4e5802, "pbtypes", b"pbtypes!");
        // Wrong transaction cannot replace the eventual valid correlated result.
        for xid in [99, 0x4c4e5802] {
            send_opack(
                &mut input,
                &mut channel,
                &Value::dict([
                    ("_t", Value::Int(3)),
                    ("_x", Value::Int(xid)),
                    ("_em", Value::Str("No request handler".into())),
                ]),
            )
            .await
            .unwrap();
        }
        // A repeated system-info request gets a reply, never a second pbtypes.
        send_opack(&mut input, &mut channel, &request)
            .await
            .unwrap();
        let reply = recv_opack(&mut input, &mut channel).await.unwrap();
        assert_eq!(reply.get("_t").and_then(Value::as_u64), Some(3));
        let report = task.await.unwrap();
        assert!(report.authenticated && report.content_requests_sent);
        assert!(report.system_info_ids_id_override);
        assert_eq!(report.system_info_responses, 2);
        assert_eq!(report.pasteboard_types.unwrap()["outcome"], "peer_error");
        assert!(!serde_json::to_string(&report.control_schemas)
            .unwrap()
            .contains("PRIVATE_PEER_ERROR"));
        assert_eq!(input.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn untrusted_client_never_enters_control_exchange() {
        let (client, mut server) = crate::companion_client::matched_loopback_identities();
        server.peers.clear();
        let (input, mut stream) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            bounded_session(
                &mut stream,
                server,
                Duration::from_secs(2),
                Some(&test_system_info()),
                true,
                false,
                false,
            )
            .await
        });
        assert!(crate::companion_client::Session::handshake(input, client)
            .await
            .is_err());
        let report = task.await.unwrap();
        assert!(!report.authenticated && !report.content_requests_sent);
        assert!(report.control_schemas.is_empty());
        assert!(report.pasteboard_types.is_none());
        assert_eq!(report.system_info_responses, 0);
    }

    #[test]
    fn control_schema_never_prints_peer_values_or_unknown_keys() {
        use crate::opack::Value;
        let message = Value::dict([
            ("_i", Value::Str("PRIVATE_SELECTOR".into())),
            ("PRIVATE_KEY", Value::Str("PRIVATE_VALUE".into())),
            (
                "_c",
                Value::dict([
                    ("_idsID", Value::Str("PRIVATE_IDENTIFIER".into())),
                    ("name", Value::Str("PRIVATE_NAME".into())),
                ]),
            ),
        ]);
        let schema = control_schema(&message);
        assert!(!schema.to_string().contains("PRIVATE"));
        assert_eq!(schema["selector"], "unknown");
        assert_eq!(schema["top"]["unknown_field_count"], 1);
    }
    #[test]
    fn protocol_diagnostics_expose_bounded_errors_and_protocol_selectors() {
        use crate::opack::Value;
        for selector in [
            "_systemInfoUpdate",
            "com.apple.continuity.activity.discovered",
        ] {
            let message = Value::dict([
                ("_i", Value::Str(selector.into())),
                ("_ec", Value::Int(4294960553)),
                ("_em", Value::Str("No request handler".into())),
                (
                    "_c",
                    Value::dict([
                        ("name", Value::Str("PRIVATE_NAME".into())),
                        ("rActPayload", Value::Bytes(b"PRIVATE_CLIPBOARD".to_vec())),
                    ]),
                ),
            ]);
            let result = control_schema(&message);
            assert_eq!(result["diagnostic"]["selector"], selector);
            assert_eq!(result["diagnostic"]["error_code"], 4294960553u64);
            assert_eq!(result["diagnostic"]["error_message"], "No request handler");
            assert!(!result.to_string().contains("PRIVATE"));
        }
        for error in [
            "x".repeat(97),
            "line\ncontrol".into(),
            "\u{1b}[31mterminal".into(),
            "é".into(),
        ] {
            let result = protocol_diagnostic(&Value::dict([("_em", Value::Str(error))]));
            assert!(result["error_message"].is_null());
            assert_eq!(result["error_message_redacted"], true);
        }
    }
    #[test]
    fn ids_override_changes_only_advertised_id_not_requester_or_key_material() {
        use crate::opack::Value;
        use std::io::Write;
        let mut identity = tempfile::NamedTempFile::new().unwrap();
        write!(
            identity,
            "{{\"identifier\":\"00000000-0000-4000-8000-000000000001\"}}"
        )
        .unwrap();
        let mut override_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(override_file, "00000000-0000-4000-8000-000000000099").unwrap();
        let properties = HashMap::from([
            ("rpBA".into(), "02:00:00:00:00:01".into()),
            ("rpVr".into(), "680.1.1".into()),
        ]);
        let ordinary = own_system_info(identity.path(), &properties, None).unwrap();
        let overridden =
            own_system_info(identity.path(), &properties, Some(override_file.path())).unwrap();
        assert_eq!(
            ordinary.system_info.get("_idsID").and_then(Value::as_str),
            Some("00000000-0000-4000-8000-000000000001")
        );
        assert_eq!(
            overridden.system_info.get("_idsID").and_then(Value::as_str),
            Some("00000000-0000-4000-8000-000000000099")
        );
        assert!(!ordinary.ids_id_override && overridden.ids_id_override);
        for key in ["_pubID", "name", "model", "_sv"] {
            assert_eq!(
                ordinary.system_info.get(key),
                overridden.system_info.get(key)
            );
        }
        for key in ["_dIRK", "_edPK"] {
            assert!(overridden.system_info.get(key).is_none());
        }
    }

    #[test]
    fn ids_override_file_rejects_exposure_symlinks_malformed_and_oversized_inputs() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id");
        std::fs::write(&path, "00000000-0000-4000-8000-000000000001").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_private_ids_id(&path).is_ok());
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_private_ids_id(&link).is_err());
        assert!(read_private_ids_id(dir.path()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_ids_id(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        for value in ["bad-id".to_owned(), "x".repeat(129)] {
            std::fs::write(&path, value).unwrap();
            assert!(read_private_ids_id(&path).is_err());
        }
    }
    #[test]
    fn archive_schema_reports_ns_error_domain_code_without_user_info() {
        use plist::{Dictionary, Uid, Value as P};
        fn dict(items: Vec<(&str, P)>) -> P {
            P::Dictionary(
                items
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect::<Dictionary>(),
            )
        }
        let root = dict(vec![
            ("$archiver", P::String("NSKeyedArchiver".into())),
            ("$top", dict(vec![("root", P::Uid(Uid::new(1)))])),
            (
                "$objects",
                P::Array(vec![
                    P::String("$null".into()),
                    dict(vec![
                        ("UASharedPasteboardInfoWrapperErrorKey", P::Uid(Uid::new(2))),
                        ("$class", P::Uid(Uid::new(5))),
                    ]),
                    dict(vec![
                        ("$class", P::Uid(Uid::new(3))),
                        ("NSDomain", P::Uid(Uid::new(4))),
                        ("NSCode", P::Integer((-123i64).into())),
                        ("NSUserInfo", P::Uid(Uid::new(6))),
                    ]),
                    dict(vec![
                        ("$classname", P::String("NSError".into())),
                        (
                            "$classes",
                            P::Array(vec![
                                P::String("NSError".into()),
                                P::String("NSObject".into()),
                            ]),
                        ),
                    ]),
                    P::String("NSOSStatusErrorDomain".into()),
                    dict(vec![
                        (
                            "$classname",
                            P::String("UASharedPasteboardInfoWrapper".into()),
                        ),
                        (
                            "$classes",
                            P::Array(vec![
                                P::String("UASharedPasteboardInfoWrapper".into()),
                                P::String("NSObject".into()),
                            ]),
                        ),
                    ]),
                    dict(vec![("PRIVATE_KEY", P::String("PRIVATE_CLIPBOARD".into()))]),
                ]),
            ),
        ]);
        let mut bytes = Vec::new();
        root.to_writer_binary(&mut bytes).unwrap();
        let error = crate::clipboard::decode_pasteboard_archive(&bytes).unwrap_err();
        assert_eq!(archive_failure(&error), "remote_ns_error");
        let schema = archive_schema(&bytes);
        assert_eq!(schema["remote_error"]["domain"], "NSOSStatusErrorDomain");
        assert_eq!(schema["remote_error"]["code"], -123);
        assert!(!schema.to_string().contains("PRIVATE"));
        assert_eq!(schema["object_count"], 7);
    }

    #[test]
    fn archive_schema_caps_size_and_object_count() {
        use plist::{Dictionary, Value as P};
        assert_eq!(archive_schema(&vec![0; 65537])["diagnostic"], "size_limit");
        assert_eq!(
            archive_schema(b"not a plist")["diagnostic"],
            "invalid_plist"
        );
        let mut root = Dictionary::new();
        root.insert(
            "$objects".into(),
            P::Array(vec![P::String("PRIVATE_DATA".into()); 100]),
        );
        let mut bytes = Vec::new();
        P::Dictionary(root).to_writer_binary(&mut bytes).unwrap();
        let schema = archive_schema(&bytes);
        assert_eq!(schema["objects"].as_array().unwrap().len(), 64);
        assert_eq!(schema["omitted_objects"], 36);
        assert!(!schema.to_string().contains("PRIVATE_DATA"));
    }
    #[tokio::test]
    async fn readiness_waits_for_correlated_encrypted_ack_before_types() {
        use crate::{
            companion_client::{recv_opack, send_opack},
            opack::Value,
        };
        let (client, server) = crate::companion_client::matched_loopback_identities();
        let (mut input, mut stream) = tokio::io::duplex(16384);
        let task = tokio::spawn(async move {
            bounded_session(
                &mut stream,
                server,
                Duration::from_secs(2),
                Some(&test_system_info()),
                true,
                true,
                false,
            )
            .await
        });
        let mut channel = test_handshake(&mut input, client).await;
        // Exercise collision avoidance for the locally initiated system-info xid.
        let request =
            crate::clipboard::build_system_info_request(0x4c4e5701, Value::dict([])).unwrap();
        send_opack(&mut input, &mut channel, &request)
            .await
            .unwrap();
        let reply = recv_opack(&mut input, &mut channel).await.unwrap();
        assert_eq!(reply.get("_t").and_then(Value::as_u64), Some(3));
        let readiness = recv_opack(&mut input, &mut channel).await.unwrap();
        assert_eq!(
            readiness.get("_i").and_then(Value::as_str),
            Some("_systemInfo")
        );
        assert_eq!(readiness.get("_c"), Some(&test_system_info().system_info));
        let xid = readiness.get("_x").and_then(Value::as_u64).unwrap();
        assert_eq!(xid, 0x4c4e5702);
        let event = Value::dict([
            ("_t", Value::Int(1)),
            ("_i", Value::Str("_systemInfoUpdate".into())),
            ("_c", Value::dict([])),
        ]);
        send_opack(&mut input, &mut channel, &event).await.unwrap();
        let ack = |id| {
            Value::dict([
                ("_t", Value::Int(3)),
                ("_x", Value::Int(id)),
                ("_c", Value::dict([])),
            ])
        };
        send_opack(&mut input, &mut channel, &ack(xid + 100))
            .await
            .unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), input.read(&mut byte))
                .await
                .is_err()
        );
        send_opack(&mut input, &mut channel, &ack(xid))
            .await
            .unwrap();
        let types = recv_opack(&mut input, &mut channel).await.unwrap();
        assert_probe_request(&types, 0x4c4e5801, "pbtypes", b"pbtypes!");
        send_opack(
            &mut input,
            &mut channel,
            &Value::dict([
                ("_t", Value::Int(3)),
                ("_x", Value::Int(0x4c4e5801)),
                ("_em", Value::Str("No request handler".into())),
            ]),
        )
        .await
        .unwrap();
        for _ in 0..3 {
            send_opack(&mut input, &mut channel, &event).await.unwrap();
        }
        let report = task.await.unwrap();
        assert_eq!(report.system_info_readiness, "acknowledged");
        assert_eq!(report.control_schemas.len(), 8);
        assert_eq!(report.control_outcome, Some("message_limit"));
        assert!(report.authenticated && report.content_requests_sent);
        assert_eq!(input.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn readiness_error_ack_never_sends_clipboard_request() {
        use crate::{
            companion_client::{recv_opack, send_opack},
            opack::Value,
        };
        let (client, server) = crate::companion_client::matched_loopback_identities();
        let (mut input, mut stream) = tokio::io::duplex(16384);
        let task = tokio::spawn(async move {
            bounded_session(
                &mut stream,
                server,
                Duration::from_secs(2),
                Some(&test_system_info()),
                true,
                true,
                false,
            )
            .await
        });
        let mut channel = test_handshake(&mut input, client).await;
        send_opack(
            &mut input,
            &mut channel,
            &crate::clipboard::build_system_info_request(1, Value::dict([])).unwrap(),
        )
        .await
        .unwrap();
        let _ = recv_opack(&mut input, &mut channel).await.unwrap();
        let request = recv_opack(&mut input, &mut channel).await.unwrap();
        let xid = request.get("_x").and_then(Value::as_u64).unwrap();
        send_opack(
            &mut input,
            &mut channel,
            &Value::dict([
                ("_t", Value::Int(3)),
                ("_x", Value::Int(xid)),
                ("_em", Value::Str("Not supported".into())),
            ]),
        )
        .await
        .unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), input.read(&mut byte))
                .await
                .is_err()
        );
        drop(input);
        let report = task.await.unwrap();
        assert_eq!(report.system_info_readiness, "peer_error");
        assert!(report.authenticated && !report.content_requests_sent);
    }
    fn response_archive(xid: u64, bytes: Vec<u8>) -> crate::opack::Value {
        use crate::opack::Value;
        Value::dict([
            ("_t", Value::Int(3)),
            ("_x", Value::Int(xid)),
            ("_c", Value::dict([("rActPayload", Value::Bytes(bytes))])),
        ])
    }
    fn data_fixture45() -> Vec<u8> {
        use plist::Value as P;
        let mut archive = P::from_reader(std::io::Cursor::new(include_bytes!(
            "../tests/fixtures/foundation-macos15-clipboard.bplist"
        )))
        .unwrap();
        for item in archive
            .as_dictionary_mut()
            .unwrap()
            .get_mut("$objects")
            .unwrap()
            .as_array_mut()
            .unwrap()
        {
            match item {
                P::Data(bytes) => *bytes = b"native clipboard test 45".to_vec(),
                P::Dictionary(dict) => {
                    if dict.contains_key("UASharedPasteboardInfoWrapperExtraTypeKey") {
                        dict.insert(
                            "UASharedPasteboardInfoWrapperExtraTypeKey".into(),
                            P::Integer(2.into()),
                        );
                    }
                    for key in [
                        "UASharedPasteboardTypeInfoSizeKey",
                        "UASharedPasteboardInfoDataSizeKey",
                    ] {
                        if dict.contains_key(key) {
                            dict.insert(
                                key.into(),
                                P::Integer((b"native clipboard test 45".len() as u64).into()),
                            );
                        }
                    }
                    if dict.contains_key("UASharedPasteboardTypeInfoOffsetKey") {
                        dict.insert(
                            "UASharedPasteboardTypeInfoOffsetKey".into(),
                            P::Integer(0.into()),
                        );
                    }
                }
                _ => {}
            }
        }
        let mut bytes = Vec::new();
        archive.to_writer_binary(&mut bytes).unwrap();
        bytes
    }

    #[tokio::test]
    async fn data_probe_waits_for_valid_metadata_uses_fresh_ids_and_never_logs_text() {
        use crate::{
            companion_client::{recv_opack, send_opack},
            opack::Value,
        };
        let (client, server) = crate::companion_client::matched_loopback_identities();
        let (mut input, mut stream) = tokio::io::duplex(32768);
        let task = tokio::spawn(async move {
            bounded_session(
                &mut stream,
                server,
                Duration::from_secs(2),
                Some(&test_system_info()),
                true,
                true,
                true,
            )
            .await
        });
        let mut channel = test_handshake(&mut input, client).await;
        send_opack(
            &mut input,
            &mut channel,
            &crate::clipboard::build_system_info_request(1, Value::dict([])).unwrap(),
        )
        .await
        .unwrap();
        let _ = recv_opack(&mut input, &mut channel).await.unwrap();
        let readiness = recv_opack(&mut input, &mut channel).await.unwrap();
        let rxid = readiness.get("_x").and_then(Value::as_u64).unwrap();
        send_opack(
            &mut input,
            &mut channel,
            &Value::dict([
                ("_t", Value::Int(3)),
                ("_x", Value::Int(rxid)),
                ("_c", Value::dict([])),
            ]),
        )
        .await
        .unwrap();
        let types = recv_opack(&mut input, &mut channel).await.unwrap();
        let tid = assert_probe_request(&types, 0x4c4e5801, "pbtypes", b"pbtypes!");
        let fixture =
            include_bytes!("../tests/fixtures/foundation-macos15-clipboard.bplist").to_vec();
        send_opack(
            &mut input,
            &mut channel,
            &response_archive(99, fixture.clone()),
        )
        .await
        .unwrap();
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), input.read(&mut byte))
                .await
                .is_err()
        );
        send_opack(
            &mut input,
            &mut channel,
            &response_archive(0x4c4e5801, fixture),
        )
        .await
        .unwrap();
        let data = recv_opack(&mut input, &mut channel).await.unwrap();
        let did = assert_probe_request(&data, 0x4c4e5901, "pbpaste2", b"pbpaste!");
        assert_ne!(tid, did);
        send_opack(
            &mut input,
            &mut channel,
            &response_archive(0x4c4e5901, data_fixture45()),
        )
        .await
        .unwrap();
        drop(input);
        let report = task.await.unwrap();
        assert_eq!(
            report.pasteboard_data.as_ref().unwrap()["matches_expected_probe_text45"],
            true
        );
        let logged = serde_json::to_string(&report).unwrap();
        assert!(!logged.contains("native clipboard test 45"));
        assert!(!logged.contains("native-clipboard-fixture-20261015"));
    }

    #[tokio::test]
    async fn data_probe_never_fetches_after_error_or_unavailable_metadata() {
        use crate::{
            companion_client::{recv_opack, send_opack},
            opack::Value,
        };
        for empty in [false, true] {
            let (client, server) = crate::companion_client::matched_loopback_identities();
            let (mut input, mut stream) = tokio::io::duplex(16384);
            let task = tokio::spawn(async move {
                bounded_session(
                    &mut stream,
                    server,
                    Duration::from_secs(2),
                    Some(&test_system_info()),
                    true,
                    true,
                    true,
                )
                .await
            });
            let mut channel = test_handshake(&mut input, client).await;
            send_opack(
                &mut input,
                &mut channel,
                &crate::clipboard::build_system_info_request(1, Value::dict([])).unwrap(),
            )
            .await
            .unwrap();
            let _ = recv_opack(&mut input, &mut channel).await.unwrap();
            let readiness = recv_opack(&mut input, &mut channel).await.unwrap();
            let rxid = readiness.get("_x").and_then(Value::as_u64).unwrap();
            send_opack(
                &mut input,
                &mut channel,
                &Value::dict([
                    ("_t", Value::Int(3)),
                    ("_x", Value::Int(rxid)),
                    ("_c", Value::dict([])),
                ]),
            )
            .await
            .unwrap();
            let _types = recv_opack(&mut input, &mut channel).await.unwrap();
            let response = if empty {
                use plist::{Uid, Value as P};
                let mut archive = P::from_reader(std::io::Cursor::new(include_bytes!(
                    "../tests/fixtures/foundation-macos15-clipboard.bplist"
                )))
                .unwrap();
                let objects = archive
                    .as_dictionary_mut()
                    .unwrap()
                    .get_mut("$objects")
                    .unwrap()
                    .as_array_mut()
                    .unwrap();
                objects[1].as_dictionary_mut().unwrap().insert(
                    "UASharedPasteboardInfoWrapperPBInfoKey".into(),
                    P::Uid(Uid::new(0)),
                );
                let mut bytes = Vec::new();
                archive.to_writer_binary(&mut bytes).unwrap();
                response_archive(0x4c4e5801, bytes)
            } else {
                Value::dict([
                    ("_t", Value::Int(3)),
                    ("_x", Value::Int(0x4c4e5801)),
                    ("_em", Value::Str("No request handler".into())),
                ])
            };
            send_opack(&mut input, &mut channel, &response)
                .await
                .unwrap();
            let mut byte = [0];
            assert!(
                tokio::time::timeout(Duration::from_millis(20), input.read(&mut byte))
                    .await
                    .is_err()
            );
            drop(input);
            let report = task.await.unwrap();
            assert!(report.pasteboard_data.is_none());
        }
    }
    #[test]
    fn unknown_top_protocol_key_names_are_bounded_without_values() {
        use crate::opack::Value;
        let message = Value::dict([
            ("_nativeUnknown", Value::Str("PRIVATE_VALUE".into())),
            ("PRIVATE_KEY", Value::Str("PRIVATE_VALUE".into())),
            ("_bad\nkey", Value::Str("PRIVATE_VALUE".into())),
        ]);
        let schema = control_schema(&message);
        assert_eq!(
            schema["top"]["unknown_protocol_keys"],
            serde_json::json!(["_nativeUnknown"])
        );
        assert!(!schema.to_string().contains("PRIVATE"));
        assert!(!schema.to_string().contains("_bad"));
    }

    #[test]
    fn expected_text_match_requires_utf8_plain_text_uti() {
        use plist::Value as P;
        let mut archive = P::from_reader(std::io::Cursor::new(data_fixture45())).unwrap();
        for object in archive
            .as_dictionary_mut()
            .unwrap()
            .get_mut("$objects")
            .unwrap()
            .as_array_mut()
            .unwrap()
        {
            if let P::String(value) = object {
                if value == "public.utf8-plain-text" {
                    *value = "public.data".into();
                }
            }
        }
        let mut bytes = Vec::new();
        archive.to_writer_binary(&mut bytes).unwrap();
        let diagnostic = pasteboard_data_diagnostic(&response_archive(1, bytes), 1, false);
        assert_eq!(diagnostic["matches_expected_probe_text45"], false);
        assert!(!diagnostic.to_string().contains("native clipboard test 45"));
    }
    #[test]
    fn clipboard_selection_requires_inline_valid_utf8_text() {
        let mut board = crate::clipboard::decode_pasteboard_archive(&data_fixture45()).unwrap();
        assert_eq!(
            verified_inline_text(&board).as_deref(),
            Some(b"native clipboard test 45".as_slice())
        );
        board.extra_data_type = Some(1);
        assert!(verified_inline_text(&board).is_none());
        board.extra_data_type = Some(2);
        for r in &mut board.representations {
            r.uti = "public.data".into();
        }
        assert!(verified_inline_text(&board).is_none());
        board.representations[0].uti = "public.utf8-plain-text".into();
        board.representations[0].data = Some(vec![255]);
        assert!(verified_inline_text(&board).is_none());
        let mut report = ClientReport::new();
        report.verified_text = Some(b"private clipboard bytes".to_vec());
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("private clipboard"));
    }
    #[test]
    fn continuous_diagnostics_do_not_capture_archives() {
        let bytes =
            include_bytes!("../tests/fixtures/foundation-macos15-clipboard.bplist").to_vec();
        let diagnostic = pasteboard_data_diagnostic(&response_archive(9, bytes), 9, false);
        assert_eq!(diagnostic["outcome"], "stream_endpoint");
        assert!(diagnostic.get("private_capture_path").is_none());
        assert!(diagnostic.get("private_capture_status").is_none());
    }
}

/// Authenticate for the retained receiver without exposing the diagnostic report.
pub(crate) async fn verify_for_ble<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: PairingIdentity,
) -> Result<(ContentChannel, [u8; 32])> {
    let mut report = ClientReport::new();
    let channel = verify(stream, identity, &mut report).await?;
    Ok((
        channel,
        report
            .authenticated_peer_fingerprint
            .context("missing verified signer")?,
    ))
}

pub(crate) fn system_info_for_ble(
    identity: &std::path::Path,
    properties: &HashMap<String, String>,
    ids: Option<&std::path::Path>,
) -> Result<crate::opack::Value> {
    Ok(own_system_info(identity, properties, ids)?.system_info)
}
