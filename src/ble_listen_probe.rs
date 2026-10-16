//! Experimental bounded retained-channel receiver. BLE authentication is only a
//! scheduling hint; clipboard authority is the exact verified signing key.
//! Clipboard writes require explicit continuous + write opt-ins. No key registration or content logging.
use crate::{
    companion::{ContinuityPacket, PacketType, PairingIdentity},
    companion_client::send_opack,
    opack::{self, Value},
};
use anyhow::{ensure, Context, Result};
use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpStream,
    sync::mpsc,
    time::Instant,
};

pub struct Config {
    pub bind: Ipv4Addr,
    pub iface: String,
    pub port: u16,
    pub seconds: u64,
    pub identity: PathBuf,
    pub txt: PathBuf,
    pub keys: PathBuf,
    pub peer_signing_fingerprint: String,
    pub system_info_ids_id_file: Option<PathBuf>,
    pub expected_test_text: Option<String>,
    pub continuous: bool,
    pub copy_verified_text: bool,
    pub fallback_seconds: u64,
}
struct Abort<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Advert(ServiceDaemon, String);
impl Drop for Advert {
    fn drop(&mut self) {
        let _ = self.0.unregister(&self.1);
        let _ = self.0.shutdown();
    }
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// This future is owned by one reader task, never selected against BLE hints.
/// Idle header wait is bounded by the session lifetime; after its first byte,
/// the rest of the frame must complete in five seconds or the socket is closed.
async fn frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<ContinuityPacket> {
    let mut h = [0; 4];
    r.read_exact(&mut h[..1]).await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        r.read_exact(&mut h[1..]).await?;
        let ptype = PacketType::from_u8(h[0]).context("invalid frame type")?;
        let n = ((h[1] as usize) << 16) | ((h[2] as usize) << 8) | h[3] as usize;
        ensure!(n <= 4 * 1024 * 1024, "frame too large");
        ensure!(
            ptype != PacketType::EncryptedData || n >= 16,
            "short encrypted frame"
        );
        let mut body = vec![0; n];
        r.read_exact(&mut body).await?;
        Ok(ContinuityPacket { ptype, body })
    })
    .await
    .context("partial frame deadline")?
}
async fn reader<R: AsyncRead + Unpin>(mut r: R, tx: mpsc::Sender<Result<ContinuityPacket>>) {
    let mut window = Instant::now();
    let mut count = 0;
    loop {
        let packet = frame(&mut r).await;
        if let Ok(p) = &packet {
            if p.ptype == PacketType::Finished && p.body.is_empty() {
                if window.elapsed() >= Duration::from_secs(10) {
                    window = Instant::now();
                    count = 0;
                }
                count += 1;
                if count > 16 {
                    let _ = tx.send(Err(anyhow::anyhow!("NoOp rate exceeded"))).await;
                    return;
                }
                continue;
            }
        }
        let failed = packet.is_err();
        if tx.send(packet).await.is_err() || failed {
            return;
        }
    }
}
#[derive(Default)]
struct Hints {
    latest: Option<u64>,
}
impl Hints {
    fn push(&mut self, timestamp: u64) {
        self.latest = Some(self.latest.unwrap_or(0).max(timestamp));
    }
    fn take(&mut self) -> Option<u64> {
        self.latest.take()
    }
}
fn fresh_hint(observed: u64, now: u64) -> bool {
    observed <= now && now - observed <= 5000
}
fn valid_readiness(msg: &Value) -> bool {
    matches!(msg.get("_c"), Some(Value::Dict(_)))
        && msg.get("_em").is_none()
        && msg.get("_ec").is_none_or(|v| v.as_u64() == Some(0))
}
struct Pending {
    snapshot: Option<crate::clipboard_sync::Snapshot>,
    trigger: &'static str,
    provider: Option<[u8; 16]>,
    xid: u64,
    data: bool,
    hint_ms: u64,
    sent_ms: u64,
    deadline: Instant,
}

async fn session(
    mut socket: TcpStream,
    c: &Config,
    signer: [u8; 32],
    ours: Value,
    events: &mut mpsc::Receiver<crate::scan::CopyEvent>,
) -> Result<()> {
    let (channel, actual) = tokio::time::timeout(
        Duration::from_secs(15),
        crate::listen_probe::verify_for_ble(&mut socket, PairingIdentity::load(&c.identity)?),
    )
    .await??;
    ensure!(actual == signer, "different verified signer");
    let mut sync = crate::clipboard_sync::SyncState::new();
    control_session(socket, c, channel, ours, events, &mut sync).await
}

async fn control_session(
    socket: TcpStream,
    c: &Config,
    mut channel: crate::companion::ContentChannel,
    ours: Value,
    events: &mut mpsc::Receiver<crate::scan::CopyEvent>,
    sync: &mut crate::clipboard_sync::SyncState,
) -> Result<()> {
    let (read, mut write) = socket.into_split();
    let (tx, mut frames) = mpsc::channel(2);
    let _reader = Abort(tokio::spawn(reader(read, tx)));
    println!("{}", json!({"event":"ble_session_authenticated"}));
    let mut readiness = None;
    let mut ready = false;
    let mut hints = Hints::default();
    let mut pending: Option<Pending> = None;
    let mut next_xid = 0x4c4e7000u64;
    let ready_deadline = Instant::now() + Duration::from_secs(15);
    let mut scanner_open = true;
    let mut baseline_due = c.continuous;
    let mut fallback_at = Instant::now() + Duration::from_secs(c.fallback_seconds);
    loop {
        if ready && pending.is_none() {
            let hint = hints.take();
            let trigger = if baseline_due {
                Some((now_ms(), "baseline"))
            } else if let Some(ms) = hint {
                Some((ms, "ble"))
            } else if c.continuous && Instant::now() >= fallback_at {
                Some((now_ms(), "fallback"))
            } else {
                None
            };
            if let Some((hint_ms, trigger)) = trigger {
                if trigger == "ble" && !fresh_hint(hint_ms, now_ms()) {
                    println!("{}", json!({"event":"ble_hint_dropped","reason":"stale"}));
                    continue;
                }
                baseline_due = false;
                fallback_at = Instant::now() + Duration::from_secs(c.fallback_seconds);
                let snapshot = if c.copy_verified_text {
                    sync.snapshot().await
                } else {
                    None
                };
                next_xid += 1;
                let msg = crate::clipboard::build_payload_request(
                    next_xid,
                    "pbtypes",
                    &uuid::Uuid::new_v4().to_string(),
                    b"pbtypes!",
                )?;
                send_opack(&mut write, &mut channel, &msg).await?;
                let sent_ms = now_ms();
                println!(
                    "{}",
                    json!({"event":"ble_types_sent","trigger":trigger,"hint_to_request_ms":sent_ms.saturating_sub(hint_ms)})
                );
                pending = Some(Pending {
                    snapshot,
                    trigger,
                    xid: next_xid,
                    data: false,
                    provider: None,
                    hint_ms,
                    sent_ms,
                    deadline: Instant::now() + Duration::from_secs(10),
                });
            }
        }
        let deadline = pending.as_ref().map(|p| p.deadline).unwrap_or_else(|| {
            if ready && c.continuous {
                fallback_at
            } else if ready {
                Instant::now() + Duration::from_secs(120)
            } else {
                ready_deadline
            }
        });
        tokio::select! {
            event=events.recv(), if scanner_open=>{ match event {
                Some(e)=>{if fresh_hint(e.observed_at_unix_ms,now_ms()) {hints.push(e.observed_at_unix_ms);} else {println!("{}",json!({"event":"ble_hint_dropped","reason":"stale"}));}},
                None=>{scanner_open=false;println!("{}",json!({"event":"ble_scanner_stopped","fallback":c.continuous}));if !c.continuous {anyhow::bail!("scanner stopped");}}
            }}
            _=tokio::time::sleep_until(deadline)=>{ if ready && pending.is_none() && c.continuous {continue;} anyhow::bail!("control response deadline"); }
            packet=frames.recv()=>{
                let p=packet.context("reader stopped")??;
                ensure!(p.ptype==PacketType::EncryptedData,"unexpected packet");
                let h=ContinuityPacket::header(p.ptype,p.body.len())?;
                let msg=opack::decode(&channel.decrypt(&p.body,&h)?)?;
                let kind=msg.get("_t").and_then(Value::as_u64);
                let xid=msg.get("_x").and_then(Value::as_u64);
                if kind==Some(2) && msg.get("_i").and_then(Value::as_str)==Some("_systemInfo") {
                    let x=xid.context("system info xid missing")?;
                    send_opack(&mut write,&mut channel,&Value::dict([("_t",Value::Int(3)),("_x",Value::Int(x)),("_c",ours.clone())])).await?;
                    if readiness.is_none() { let x=if x==0x4c4e6001 {0x4c4e6002} else {0x4c4e6001};
                        send_opack(&mut write,&mut channel,&crate::clipboard::build_system_info_request(x,ours.clone())?).await?; readiness=Some(x); }
                    continue;
                }
                if kind==Some(3) && xid==readiness && readiness.is_some() {
                    ensure!(valid_readiness(&msg),"readiness denied");
                    ready=true; println!("{}",json!({"event":"ble_session_ready"})); continue;
                }
                if kind!=Some(3) || !pending.as_ref().is_some_and(|p|Some(p.xid)==xid) {continue;}
                let previous=pending.take().unwrap();
                let response=crate::clipboard::validate_payload_response(&msg,previous.xid)?;
                let crate::clipboard::PayloadResponse::Archive(bytes)=response else {
                    println!("{}",json!({"event":"ble_reply","outcome":"peer_error"})); continue;
                };
                let board=match crate::clipboard::decode_pasteboard_archive(&bytes) {
                    Ok(board)=>board,
                    Err(error) if error.chain().any(|e|e.to_string()=="clipboard archive contains no pasteboard info") => {
                        if c.copy_verified_text {sync.observe_empty();}
                        println!("{}",json!({"event":"ble_reply","trigger":previous.trigger,"outcome":"no_remote_pasteboard","hint_to_reply_ms":now_ms().saturating_sub(previous.hint_ms)})); continue;
                    },
                    Err(error)=>return Err(error),
                };
                let text=board.representations.iter().find(|r|r.uti=="public.utf8-plain-text");
                let provider_id=text.and_then(|r|r.provider_id);
                let provider=provider_id.map(|id|hex::encode(Sha256::digest(id)));
                if !previous.data && text.is_some() {
                    next_xid+=1;
                    let req=crate::clipboard::build_payload_request(next_xid,"pbpaste2",&uuid::Uuid::new_v4().to_string(),b"pbpaste!")?;
                    send_opack(&mut write,&mut channel,&req).await?;
                    pending=Some(Pending{xid:next_xid,data:true,provider:provider_id,deadline:Instant::now()+Duration::from_secs(10),..previous});
                } else {
                    let generation_matches=previous.provider.is_none() || previous.provider==provider_id;
                    let bytes=if generation_matches && board.extra_data_type==Some(2) {text.and_then(|r|r.data.as_ref()).filter(|b| std::str::from_utf8(b).is_ok())} else {None};
                    let applied=if c.copy_verified_text {if let Some(bytes)=bytes {Some(sync.apply_remote(previous.snapshot,bytes).await)}else{None}}else{None};
                    println!("{}",json!({"event":"ble_reply","trigger":previous.trigger,"clipboard":applied,"outcome":if bytes.is_some(){"inline_text"}else{"no_inline_text"},"hint_to_reply_ms":now_ms().saturating_sub(previous.hint_ms),"request_to_reply_ms":now_ms().saturating_sub(previous.sent_ms),"provider_digest":provider,"generation_matches":generation_matches,"text_bytes":bytes.map(|b|b.len()),"test_match":c.expected_test_text.as_ref().map(|expected|bytes.is_some_and(|b|b==expected.as_bytes()))}));
                }
            }
        }
    }
}

/// Bounded concurrent handshakes keep unrelated peers from occupying the target
/// accept path for fifteen seconds. Only one authenticated control session owns
/// SyncState; at most one reconnect may wait, and its socket has no reader task.
async fn accept_verified(
    listener: tokio::net::TcpListener,
    identity: PathBuf,
    signer: [u8; 32],
    tx: mpsc::Sender<(TcpStream, crate::companion::ContentChannel)>,
) -> Result<()> {
    let mut handshakes = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted=listener.accept()=>{
                let (mut socket,_)=accepted?;
                if handshakes.len()>=8 {continue;}
                let identity=identity.clone();
                handshakes.spawn(async move {
                    let (channel,actual)=tokio::time::timeout(Duration::from_secs(15),async {
                        crate::listen_probe::verify_for_ble(&mut socket,PairingIdentity::load(&identity)?).await
                    }).await.context("handshake deadline")??;
                    ensure!(actual==signer,"different verified signer");
                    anyhow::Ok((socket,channel))
                });
            }
            result=handshakes.join_next(), if !handshakes.is_empty()=>{
                if let Some(Ok(Ok(connection)))=result {let _=tx.try_send(connection);}
            }
        }
    }
}

fn safe_failure(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::UnexpectedEof => "peer_closed",
                std::io::ErrorKind::ConnectionReset => "connection_reset",
                std::io::ErrorKind::BrokenPipe => "broken_pipe",
                _ => "transport_error",
            };
        }
    }
    if error
        .chain()
        .any(|e| e.downcast_ref::<tokio::time::error::Elapsed>().is_some())
    {
        return "timeout";
    }
    match error.to_string().as_str() {
        "different verified signer" => "wrong_signer",
        "control response deadline" => "control_timeout",
        "readiness denied" => "readiness_denied",
        "NoOp rate exceeded" => "noop_rate_exceeded",
        _ => "protocol_rejected",
    }
}

pub async fn run(c: Config) -> Result<()> {
    ensure!(
        (1..=120).contains(&c.seconds),
        "duration must be 1..=120 seconds"
    );
    ensure!(
        c.continuous == c.copy_verified_text,
        "continuous and clipboard writes require both explicit opt-ins"
    );
    ensure!(
        (2..=60).contains(&c.fallback_seconds),
        "fallback interval must be 2..=60 seconds"
    );
    let signer: [u8; 32] = hex::decode(&c.peer_signing_fingerprint)
        .context("signer must be hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signer must be SHA256"))?;
    crate::listen_probe::validate_interface(c.bind, &c.iface)?;
    ensure!(std::fs::metadata(&c.txt)?.len() <= 4096, "TXT too large");
    let properties: HashMap<String, String> = serde_json::from_slice(&std::fs::read(&c.txt)?)?;
    ensure!(properties.len() <= 32, "too many TXT properties");
    for (k, v) in &properties {
        ensure!(
            !k.is_empty()
                && k.bytes().all(|b| (0x20..=0x7e).contains(&b) && b != b'=')
                && k.len() + v.len() + 1 <= 255,
            "invalid TXT"
        );
    }
    let ours = crate::listen_probe::system_info_for_ble(
        &c.identity,
        &properties,
        c.system_info_ids_id_file.as_deref(),
    )?;
    let store = crate::keystore::KeyStore::load(&c.keys)?;
    ensure!(
        store.keys.len() == 1,
        "diagnostic requires exactly one target BLE key"
    );
    let (tx, mut events) = mpsc::channel(8);
    let _scan = match crate::scan::Scanner::new(store).await {
        Ok(scanner) => {
            let scanner = scanner.with_quiet_events(tx);
            Some(Abort(tokio::spawn(async move { scanner.run().await })))
        }
        Err(_) if c.continuous => {
            println!(
                "{}",
                json!({"event":"ble_scanner_unavailable","fallback":true})
            );
            drop(tx);
            None
        }
        Err(error) => return Err(error),
    };
    let listener = tokio::net::TcpListener::bind((c.bind, c.port)).await?;
    let hostname = format!("linux-clipboard-{}.local.", uuid::Uuid::new_v4().simple());
    let info = ServiceInfo::new(
        "_companion-link._tcp.local.",
        "Linux Clipboard Research",
        &hostname,
        c.bind.to_string().as_str(),
        listener.local_addr()?.port(),
        properties,
    )?;
    let advertisement = Advert(ServiceDaemon::new()?, info.get_fullname().to_owned());
    advertisement.0.disable_interface(IfKind::All)?;
    advertisement.0.enable_interface(c.iface.as_str())?;
    advertisement.0.register(info)?;
    println!(
        "{}",
        json!({"event":"ble_listening","seconds":if c.continuous {None}else{Some(c.seconds)},"clipboard_writes":c.copy_verified_text})
    );
    let work = async {
        if c.continuous {
            let (tx, mut incoming) = mpsc::channel(1);
            let _accept = Abort(tokio::spawn(accept_verified(
                listener,
                c.identity.clone(),
                signer,
                tx,
            )));
            let mut sync = crate::clipboard_sync::SyncState::new();
            loop {
                let (socket, channel) = incoming.recv().await.context("accept task stopped")?;
                crate::listen_probe::validate_interface(c.bind, &c.iface)?;
                let result =
                    control_session(socket, &c, channel, ours.clone(), &mut events, &mut sync)
                        .await;
                println!(
                    "{}",
                    json!({"event":"ble_session_closed","failed":result.is_err(),"reason":result.as_ref().err().map(safe_failure)})
                );
            }
        }
        for _ in 0..16 {
            let (socket, _) = listener.accept().await?;
            let result = session(socket, &c, signer, ours.clone(), &mut events).await;
            println!(
                "{}",
                json!({"event":"ble_session_closed","failed":result.is_err(),"reason":result.as_ref().err().map(safe_failure)})
            );
        }
        anyhow::Ok(())
    };
    tokio::pin!(work);
    let deadline = tokio::time::sleep(Duration::from_secs(c.seconds));
    tokio::pin!(deadline);
    let stop = crate::shutdown();
    tokio::pin!(stop);
    let mut network_check = tokio::time::interval(Duration::from_secs(10));
    network_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result=&mut work=>{result?;break;},
            _=&mut deadline, if !c.continuous=>break,
            _=&mut stop=>break,
            _=network_check.tick()=>{crate::listen_probe::validate_interface(c.bind,&c.iface)?;}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    #[tokio::test]
    async fn partial_frame_survives_unrelated_event() {
        for split in [1, 2, 3, 4, 7, 18] {
            let (mut w, r) = tokio::io::duplex(64);
            let (tx, mut rx) = mpsc::channel(2);
            let task = Abort(tokio::spawn(reader(r, tx)));
            let p = ContinuityPacket {
                ptype: PacketType::EncryptedData,
                body: vec![42; 20],
            };
            let bytes = p.serialize().unwrap();
            w.write_all(&bytes[..split]).await.unwrap();
            tokio::select! { _=tokio::time::sleep(Duration::from_millis(2))=>{}, _=rx.recv()=>panic!("partial frame exposed") }
            w.write_all(&bytes[split..]).await.unwrap();
            let received = rx.recv().await.unwrap().unwrap();
            assert_eq!(received.body, p.body);
            drop(task);
        }
    }
    #[tokio::test]
    async fn rejects_oversized_header_without_body() {
        let (mut w, mut r) = tokio::io::duplex(16);
        w.write_all(&[8, 0x40, 0, 1]).await.unwrap();
        assert!(frame(&mut r).await.is_err());
    }
    #[test]
    fn readiness_and_freshness_are_bounded() {
        let mut msg = Value::dict([("_c", Value::dict([])), ("_ec", Value::Int(0))]);
        assert!(valid_readiness(&msg));
        msg = Value::dict([("_c", Value::Null)]);
        assert!(!valid_readiness(&msg));
        assert!(fresh_hint(5000, 10000));
        assert!(!fresh_hint(4999, 10000));
        assert!(!fresh_hint(10001, 10000));
    }
    #[test]
    fn hints_coalesce_and_keep_latest() {
        let mut h = Hints::default();
        h.push(2);
        h.push(5);
        h.push(3);
        assert_eq!(h.take(), Some(5));
        assert_eq!(h.take(), None);
    }
    fn hint() -> crate::scan::CopyEvent {
        crate::scan::CopyEvent {
            device: String::new(),
            address: String::new(),
            key_id: "synthetic".into(),
            activity: String::new(),
            raw_advertisement: vec![],
            status: 0,
            counter_iv: [0; 2],
            decrypted_payload: vec![],
            flags: 8,
            observed_at_unix_ms: now_ms(),
        }
    }
    async fn client_verify(
        socket: &mut TcpStream,
        identity: PairingIdentity,
    ) -> crate::companion::ContentChannel {
        use crate::companion_client::{read_packet, write_packet};
        let mut verifier = crate::companion::PairVerifyClient::new(identity);
        write_packet(socket, &verifier.build_m1()).await.unwrap();
        let m2 = read_packet(socket).await.unwrap();
        write_packet(socket, &verifier.process_m2(&m2).unwrap())
            .await
            .unwrap();
        verifier
            .check_m4(&read_packet(socket).await.unwrap())
            .unwrap()
    }
    fn archive_reply(
        xid: u64,
        kind: crate::clipboard_serve::ArchiveKind,
        available: bool,
    ) -> Value {
        let snapshot = available.then_some(crate::clipboard_serve::TextSnapshot {
            text: "synthetic retained session",
            provider_id: [0x47; 16],
        });
        Value::dict([
            ("_t", Value::Int(3)),
            ("_x", Value::Int(xid)),
            (
                "_c",
                Value::dict([(
                    "rActPayload",
                    Value::Bytes(
                        crate::clipboard_serve::encode_text_archive(snapshot, kind).unwrap(),
                    ),
                )]),
            ),
        ])
    }
    async fn loopback_fixture(
        wrong_signer: bool,
    ) -> (
        TcpStream,
        crate::companion::ContentChannel,
        mpsc::Sender<crate::scan::CopyEvent>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        loopback_fixture_mode(wrong_signer, false).await
    }
    async fn loopback_fixture_mode(
        wrong_signer: bool,
        continuous: bool,
    ) -> (
        TcpStream,
        crate::companion::ContentChannel,
        mpsc::Sender<crate::scan::CopyEvent>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let (client, server) = crate::companion_client::matched_loopback_identities();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        write!(
            file,
            "{}",
            json!({"ed_sk":hex::encode(server.signing.to_bytes()),
            "peers":[{"edpk":hex::encode(client.signing.verifying_key().to_bytes())}]})
        )
        .unwrap();
        let signer = if wrong_signer {
            [0; 32]
        } else {
            Sha256::digest(client.signing.verifying_key().to_bytes()).into()
        };
        let config = Config {
            bind: Ipv4Addr::LOCALHOST,
            iface: "lo".into(),
            port: 0,
            seconds: 5,
            identity: file.path().into(),
            txt: PathBuf::new(),
            keys: PathBuf::new(),
            peer_signing_fingerprint: String::new(),
            system_info_ids_id_file: None,
            expected_test_text: Some("synthetic retained session".into()),
            continuous,
            copy_verified_text: false,
            fallback_seconds: 2,
        };
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let mut socket = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server_socket, _) = listener.accept().await.unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        let task = tokio::spawn(async move {
            let _keep_identity_file = file;
            tokio::time::timeout(
                Duration::from_secs(5),
                session(server_socket, &config, signer, Value::dict([]), &mut rx),
            )
            .await
            .unwrap()
        });
        let channel = client_verify(&mut socket, client).await;
        (socket, channel, tx, task)
    }
    #[tokio::test]
    async fn actual_session_retains_encrypted_connection_across_hints_and_unavailable() {
        use crate::clipboard_serve::ArchiveKind;
        use crate::companion_client::recv_opack;
        let (mut socket, mut channel, tx, task) = loopback_fixture(false).await;
        // A hint before readiness cannot cause clipboard requests before the barrier.
        tx.send(hint()).await.unwrap();
        send_opack(
            &mut socket,
            &mut channel,
            &crate::clipboard::build_system_info_request(11, Value::dict([])).unwrap(),
        )
        .await
        .unwrap();
        let ack = recv_opack(&mut socket, &mut channel).await.unwrap();
        assert_eq!(ack.get("_x").and_then(Value::as_u64), Some(11));
        let readiness = recv_opack(&mut socket, &mut channel).await.unwrap();
        assert_eq!(
            readiness.get("_i").and_then(Value::as_str),
            Some("_systemInfo")
        );
        let ready_xid = readiness.get("_x").and_then(Value::as_u64).unwrap();
        // Peek is cancellation safe and consumes no partial encrypted frame.
        let mut peek = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(15), socket.peek(&mut peek))
                .await
                .is_err()
        );
        send_opack(
            &mut socket,
            &mut channel,
            &Value::dict([
                ("_t", Value::Int(3)),
                ("_x", Value::Int(ready_xid)),
                ("_ec", Value::Int(0)),
                ("_c", Value::dict([])),
            ]),
        )
        .await
        .unwrap();
        let mut previous_xid = None;
        for cycle in 0..3 {
            if cycle > 0 {
                tx.send(hint()).await.unwrap();
            }
            let types = recv_opack(&mut socket, &mut channel).await.unwrap();
            let xid = types.get("_x").and_then(Value::as_u64).unwrap();
            assert_ne!(Some(xid), previous_xid);
            let content = types.get("_c").unwrap();
            assert_eq!(
                content.get("rAdvPayload").and_then(Value::as_bytes),
                Some(b"pbtypes!".as_slice())
            );
            // Wrong xid must not advance into a data fetch.
            send_opack(
                &mut socket,
                &mut channel,
                &archive_reply(xid + 1000, ArchiveKind::Types, true),
            )
            .await
            .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(15), socket.peek(&mut peek))
                    .await
                    .is_err()
            );
            // First copy is unavailable; subsequent copies transfer inline on this same socket.
            send_opack(
                &mut socket,
                &mut channel,
                &archive_reply(xid, ArchiveKind::Types, cycle > 0),
            )
            .await
            .unwrap();
            if cycle > 0 {
                let data = recv_opack(&mut socket, &mut channel).await.unwrap();
                let data_xid = data.get("_x").and_then(Value::as_u64).unwrap();
                assert_ne!(data_xid, xid);
                assert_eq!(
                    data.get("_c")
                        .unwrap()
                        .get("rAdvPayload")
                        .and_then(Value::as_bytes),
                    Some(b"pbpaste!".as_slice())
                );
                send_opack(
                    &mut socket,
                    &mut channel,
                    &archive_reply(data_xid, ArchiveKind::InlineData, true),
                )
                .await
                .unwrap();
            }
            // Ordered control ack proves the session consumed the preceding reply and survived it.
            let sync_xid = 100 + cycle;
            send_opack(
                &mut socket,
                &mut channel,
                &crate::clipboard::build_system_info_request(sync_xid, Value::dict([])).unwrap(),
            )
            .await
            .unwrap();
            let sync = recv_opack(&mut socket, &mut channel).await.unwrap();
            assert_eq!(sync.get("_x").and_then(Value::as_u64), Some(sync_xid));
            previous_xid = Some(xid);
        }
        drop(socket);
        assert!(task.await.unwrap().is_err());
    }
    #[tokio::test]
    async fn actual_session_wrong_target_signer_closes_without_control() {
        let (mut socket, _channel, _tx, task) = loopback_fixture(true).await;
        assert!(task
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("different verified signer"));
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
    }
    #[tokio::test]
    async fn persistent_mode_baselines_without_hint_and_polls_after_scanner_stops() {
        use crate::clipboard_serve::ArchiveKind;
        use crate::companion_client::recv_opack;
        let (mut socket, mut channel, tx, task) = loopback_fixture_mode(false, true).await;
        send_opack(
            &mut socket,
            &mut channel,
            &crate::clipboard::build_system_info_request(11, Value::dict([])).unwrap(),
        )
        .await
        .unwrap();
        let _ = recv_opack(&mut socket, &mut channel).await.unwrap();
        let readiness = recv_opack(&mut socket, &mut channel).await.unwrap();
        let xid = readiness.get("_x").and_then(Value::as_u64).unwrap();
        let ack = Value::dict([
            ("_t", Value::Int(3)),
            ("_x", Value::Int(xid)),
            ("_c", Value::dict([])),
        ]);
        send_opack(&mut socket, &mut channel, &ack).await.unwrap();
        let baseline = recv_opack(&mut socket, &mut channel).await.unwrap();
        let baseline_xid = baseline.get("_x").and_then(Value::as_u64).unwrap();
        send_opack(
            &mut socket,
            &mut channel,
            &archive_reply(baseline_xid, ArchiveKind::Types, false),
        )
        .await
        .unwrap();
        drop(tx); // no BLE scanner: poll still runs, without spinning on closed receiver.
        let started = Instant::now();
        send_opack(&mut socket, &mut channel, &ack).await.unwrap(); // replay cannot reset baseline
        let fallback = recv_opack(&mut socket, &mut channel).await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(1500));
        let fallback_xid = fallback.get("_x").and_then(Value::as_u64).unwrap();
        assert_ne!(fallback_xid, baseline_xid);
        send_opack(
            &mut socket,
            &mut channel,
            &archive_reply(fallback_xid, ArchiveKind::Types, true),
        )
        .await
        .unwrap();
        let data = recv_opack(&mut socket, &mut channel).await.unwrap();
        let data_xid = data.get("_x").and_then(Value::as_u64).unwrap();
        send_opack(
            &mut socket,
            &mut channel,
            &archive_reply(data_xid, ArchiveKind::InlineData, true),
        )
        .await
        .unwrap();
        drop(socket);
        assert!(task.await.unwrap().is_err());
    }
    #[tokio::test]
    async fn slow_unverified_socket_does_not_block_exact_target_handshake() {
        let (client, server) = crate::companion_client::matched_loopback_identities();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        write!(file,"{}",json!({"ed_sk":hex::encode(server.signing.to_bytes()),"peers":[{"edpk":hex::encode(client.signing.verifying_key().to_bytes())}]})).unwrap();
        let signer = Sha256::digest(client.signing.verifying_key().to_bytes()).into();
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let accept = Abort(tokio::spawn(accept_verified(
            listener,
            file.path().into(),
            signer,
            tx,
        )));
        let _slow = TcpStream::connect(address).await.unwrap(); // never sends M1
        let mut target = TcpStream::connect(address).await.unwrap();
        let mut channel =
            tokio::time::timeout(Duration::from_secs(2), client_verify(&mut target, client))
                .await
                .unwrap();
        let (mut server_socket, mut server_channel) =
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
        let message = Value::dict([
            ("_t", Value::Int(1)),
            ("_i", Value::Str("synthetic".into())),
        ]);
        send_opack(&mut target, &mut channel, &message)
            .await
            .unwrap();
        assert_eq!(
            crate::companion_client::recv_opack(&mut server_socket, &mut server_channel)
                .await
                .unwrap(),
            message
        );
        drop(accept);
    }
    #[test]
    fn errors_never_expose_payload_strings() {
        assert_eq!(
            safe_failure(&anyhow::anyhow!("private clipboard secret")),
            "protocol_rejected"
        );
        assert_eq!(
            safe_failure(&std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()),
            "peer_closed"
        );
    }
}
