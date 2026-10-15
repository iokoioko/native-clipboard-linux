//! Explicit, bounded Airdrop-compatible receive sessions. Independent of same-account Universal Clipboard.
mod archive;
mod cancel;
mod client_http;
mod http;
mod outgoing;
pub mod peers;
pub mod send;
mod storage;
use crate::companion_client::{Pasteboard, PasteboardItem};
use anyhow::{ensure, Context, Result};
use std::{
    io::Cursor,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    },
    TlsAcceptor,
};

fn identity(dir: &Path) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{X509NameBuilder, X509},
    };
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let cert_path = dir.join("certificate.pem");
    let key_path = dir.join("key.pem");
    if !cert_path.exists() && !key_path.exists() {
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "Adhoc Cross-Device Connection")?;
        let name = name.build();
        let mut x = X509::builder()?;
        x.set_version(2)?;
        let mut bn = BigNum::new()?;
        bn.rand(128, MsbOption::MAYBE_ZERO, false)?;
        let serial = bn.to_asn1_integer()?;
        x.set_serial_number(&serial)?;
        x.set_subject_name(&name)?;
        x.set_issuer_name(&name)?;
        x.set_pubkey(&key)?;
        let start = Asn1Time::days_from_now(0)?;
        let end = Asn1Time::days_from_now(365)?;
        x.set_not_before(&start)?;
        x.set_not_after(&end)?;
        let san = openssl::x509::extension::SubjectAlternativeName::new()
            .dns("ac-dc.local")
            .build(&x.x509v3_context(None, None))?;
        x.append_extension(san)?;
        x.sign(&key, MessageDigest::sha256())?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)?;
        f.write_all(&key.private_key_to_pem_pkcs8()?)?;
        f.sync_all()?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&cert_path)?;
        f.write_all(&x.build().to_pem()?)?;
        f.sync_all()?;
    }
    let cert = X509::from_pem(&fs::read(cert_path)?)?;
    let key = PKey::private_key_from_pem(&fs::read(key_path)?)?;
    ensure!(
        cert.public_key()?.public_eq(&key),
        "Airdrop-compatible certificate/key do not match"
    );
    Ok((
        CertificateDer::from(cert.to_der()?),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.private_key_to_pkcs8()?)),
    ))
}
pub fn service_id(identity_dir: &Path) -> Result<String> {
    if let Ok(mac) = std::fs::read_to_string("/sys/class/net/awdl0/address") {
        let id = mac.trim().replace(':', "");
        if id.len() == 12 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(id.to_ascii_lowercase());
        }
    }
    let (cert, _) = identity(identity_dir)?;
    use sha2::{Digest, Sha256};
    Ok(hex::encode(&Sha256::digest(cert.as_ref())[..6]))
}
pub fn radio_state() -> Option<serde_json::Value> {
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read("/run/brcmfmac-awdl/discovery.json").ok()?).ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    (v["active"] == true
        && v["expires_at"].as_u64().is_some_and(|t| t > now)
        && v["updated_at"]
            .as_u64()
            .is_some_and(|t| t <= now && now - t < 15))
    .then_some(v)
}
fn tls(dir: &Path) -> Result<TlsAcceptor> {
    let (cert, key) = identity(dir)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn response(name: &str) -> Result<Vec<u8>> {
    let mut d = plist::Dictionary::new();
    d.insert("ReceiverComputerName".into(), name.into());
    d.insert("ReceiverModelName".into(), "MacBookPro18,3".into());
    d.insert(
        "ReceiverMediaCapabilities".into(),
        plist::Value::Data(br#"{"Version":1}"#.to_vec()),
    );
    let mut bytes = Vec::new();
    plist::Value::Dictionary(d).to_writer_binary(&mut bytes)?;
    Ok(bytes)
}
fn board(entries: &[archive::Entry]) -> Pasteboard {
    Pasteboard {
        items: entries
            .iter()
            .filter_map(|e| {
                let ext = Path::new(&e.name)
                    .extension()?
                    .to_str()?
                    .to_ascii_lowercase();
                let uti = match ext.as_str() {
                    "txt" if std::str::from_utf8(&e.bytes).is_ok() => "public.utf8-plain-text",
                    "png" => "public.png",
                    "jpg" | "jpeg" => "public.jpeg",
                    "gif" => "com.compuserve.gif",
                    "webp" => "public.webp",
                    _ => return None,
                };
                Some(PasteboardItem {
                    uti: uti.into(),
                    data: e.bytes.clone(),
                })
            })
            .collect(),
    }
}
async fn deliver(entries: Vec<archive::Entry>, dest: PathBuf, notify: bool) -> Result<()> {
    ensure!(
        !entries.is_empty(),
        "transfer contains no supported regular files"
    );
    let paths = archive::store(&dest, &entries)?;
    let pb = board(&entries);
    let copied = match crate::clipboard_out::copy_pasteboard(&pb) {
        Ok(out) => out.is_some_and(|o| o.spawned),
        Err(e) => {
            tracing::warn!(error=%e,"files saved but clipboard unavailable");
            false
        }
    };
    tracing::info!(
        files = paths.len(),
        copied,
        "Airdrop-compatible transfer received"
    );
    for p in paths {
        println!("{}", serde_json::json!({"received":p,"copied":copied}));
    }
    if notify {
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::process::Command::new("notify-send")
                .args([
                    "Airdrop-compatible received",
                    if copied {
                        "Saved and copied to clipboard"
                    } else {
                        "Saved to the receive folder"
                    },
                ])
                .kill_on_drop(true)
                .status(),
        )
        .await;
    }
    Ok(())
}
async fn open_directory(directory: &Path, opener: &str) -> Result<()> {
    let status = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(opener)
            .arg(directory)
            .kill_on_drop(true)
            .status(),
    )
    .await
    .context("opening the receive folder timed out")??;
    anyhow::ensure!(status.success(), "{opener} exited with {status}");
    Ok(())
}
fn is_link_transfer(value: Option<&plist::Value>) -> bool {
    match value {
        Some(plist::Value::Dictionary(d)) => d.contains_key("links"),
        Some(plist::Value::Array(a)) => a.iter().any(|v| v.as_string() == Some("links")),
        _ => false,
    }
}
pub struct Incoming {
    pub sender: String,
    pub items: Vec<String>,
    pub decision: tokio::sync::oneshot::Sender<bool>,
}
#[derive(Clone, Default)]
struct Sessions {
    approved:
        Arc<std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, std::time::Instant>>>,
    approval: Option<tokio::sync::mpsc::Sender<Incoming>>,
}
#[allow(clippy::too_many_arguments)]
async fn connection(
    stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    name: String,
    dest: PathBuf,
    notify: bool,
    open_destination: bool,
    completed: tokio::sync::mpsc::Sender<()>,
    sessions: Sessions,
) -> Result<()> {
    let peer = stream.peer_addr()?.ip();
    let started = std::time::Instant::now();
    tracing::info!(%peer,"Airdrop-compatible TCP accepted");
    let tls = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream))
        .await
        .context("Airdrop-compatible TLS timed out")??;
    tracing::info!(%peer,elapsed_ms=started.elapsed().as_millis() as u64,"Airdrop-compatible TLS established");
    let mut io = tokio::io::BufReader::new(tls);
    for _ in 0..32 {
        let req = tokio::time::timeout(
            Duration::from_secs(3600),
            http::read_spooled(&mut io, || {
                sessions
                    .approved
                    .lock()
                    .unwrap()
                    .remove(&peer)
                    .is_some_and(|t| t.elapsed() < Duration::from_secs(120))
            }),
        )
        .await
        .context("Airdrop-compatible request timed out")??;
        tracing::info!(%peer,endpoint=%req.path,"Airdrop-compatible incoming request");
        let result = match req.path.as_str() {
            "/Discover" => {
                plist::Value::from_reader(Cursor::new(&req.body))
                    .context("invalid Discover plist")?;
                Ok((response(&name)?, false))
            }
            "/Ask" => {
                let value = plist::Value::from_reader(Cursor::new(&req.body))?;
                let dict = value.as_dictionary().context("Ask must be a dictionary")?;
                let links = is_link_transfer(dict.get("TransferType"))
                    || (dict.contains_key("Items") && !dict.contains_key("Files"));
                if let Some(approval) = &sessions.approval {
                    let sender = dict
                        .get("SenderComputerName")
                        .and_then(plist::Value::as_string)
                        .unwrap_or("Nearby device")
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(128)
                        .collect();
                    let items = if links {
                        dict.get("Items")
                    } else {
                        dict.get("Files")
                    }
                    .and_then(plist::Value::as_array)
                    .context("Ask has no items")?
                    .iter()
                    .take(512)
                    .map(|v| {
                        if links {
                            v.as_string()
                        } else {
                            v.as_dictionary()
                                .and_then(|d| d.get("FileName"))
                                .and_then(plist::Value::as_string)
                        }
                        .unwrap_or("File")
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(256)
                        .collect()
                    })
                    .collect();
                    let (decision, result) = tokio::sync::oneshot::channel();
                    let accepted = match approval.try_send(Incoming {
                        sender,
                        items,
                        decision,
                    }) {
                        Ok(()) => tokio::time::timeout(Duration::from_secs(90), result)
                            .await
                            .ok()
                            .and_then(Result::ok)
                            .unwrap_or(false),
                        Err(_) => false,
                    };
                    if !accepted {
                        http::respond(io.get_mut(), 403, b"").await?;
                        continue;
                    }
                }
                if links {
                    let mut entries = Vec::new();
                    for url in dict
                        .get("Items")
                        .and_then(plist::Value::as_array)
                        .context("link Items missing")?
                    {
                        let url = url.as_string().context("link is not text")?;
                        ensure!(
                            (url.starts_with("https://") || url.starts_with("http://"))
                                && !url.chars().any(char::is_control),
                            "unsupported link"
                        );
                        entries.push(archive::Entry {
                            name: "shared-link.txt".into(),
                            bytes: url.as_bytes().to_vec(),
                        });
                    }
                    deliver(entries, dest.clone(), notify).await?;
                }
                if !links {
                    let mut grants = sessions.approved.lock().unwrap();
                    grants.retain(|_, t| t.elapsed() < Duration::from_secs(120));
                    ensure!(grants.len() < 128, "too many pending transfers");
                    grants.insert(peer, std::time::Instant::now());
                }
                Ok((response(&name)?, links))
            }
            "/Upload" => {
                let ty = req
                    .headers
                    .get("content-type")
                    .map(|s| s.split(';').next().unwrap_or(""))
                    .unwrap_or("");
                if !matches!(ty, "application/x-cpio" | "application/x-dvzip") {
                    http::respond(io.get_mut(), 415, b"").await?;
                    continue;
                }
                let upload = req.upload.context("upload spool missing")?;
                let ty = ty.to_owned();
                let directory = dest.clone();
                let cancellation = cancel::Guard(cancel::Token::default());
                let token = cancellation.0.clone();
                let saved = tokio::task::spawn_blocking(move || {
                    use std::io::Seek;
                    let mut file = upload.reopen()?;
                    file.rewind()?;
                    storage::receive_cancel(file, &ty, &directory, token)
                })
                .await??;
                let copied = crate::clipboard_out::copy_pasteboard(&board(&saved.clipboard))
                    .ok()
                    .is_some_and(|v| v.is_some_and(|v| v.spawned));
                tracing::info!(
                    files = saved.files,
                    bytes = saved.bytes,
                    copied,
                    "Airdrop-compatible transfer received"
                );
                println!(
                    "{}",
                    serde_json::json!({"received":saved.directory,"files":saved.files,"bytes":saved.bytes,"copied":copied})
                );
                if notify {
                    let _ = tokio::process::Command::new("notify-send")
                        .args([
                            "Airdrop-compatible received",
                            &format!(
                                "Saved {} file(s) in {}",
                                saved.files,
                                saved.directory.display()
                            ),
                        ])
                        .kill_on_drop(true)
                        .spawn();
                }
                Ok((Vec::new(), true))
            }
            _ => Err(anyhow::anyhow!(
                "Upload requires Ask on the same TLS connection"
            )),
        };
        match result {
            Ok((body, done)) => {
                if req.path == "/Discover" {
                    http::respond_close(io.get_mut(), 200, &body).await?;
                    tracing::debug!(%peer, "Airdrop-compatible discovery response sent; closing discovery connection");
                    return Ok(());
                }
                http::respond(io.get_mut(), 200, &body).await?;
                if done {
                    let _ = completed.try_send(());
                    if open_destination {
                        let dest = dest.clone();
                        tokio::spawn(async move {
                            if let Err(e) = open_directory(&dest, "xdg-open").await {
                                tracing::warn!(error=%format!("{e:#}"), "open the receive folder");
                            }
                        });
                    }
                }
            }
            Err(e) => {
                http::respond(io.get_mut(), 400, b"").await?;
                return Err(e);
            }
        }
    }
    Ok(())
}
/// Bounds the receive window. Enforced here and by the daemon's control socket,
/// which must reject an out-of-range request before it starts the radio.
pub const RECEIVE_SECONDS: std::ops::RangeInclusive<u64> = 1..=3600;

/// One wording for the rejection, so the daemon and `run` cannot drift apart.
pub fn receive_seconds_error() -> String {
    format!(
        "receive duration must be {}..{} seconds",
        RECEIVE_SECONDS.start(),
        RECEIVE_SECONDS.end()
    )
}

pub struct Config {
    pub iface: String,
    pub directory: PathBuf,
    pub identity: PathBuf,
    pub name: String,
    pub port: u16,
    pub seconds: u64,
    pub once: bool,
    pub notify: bool,
    pub open_destination: bool,
    pub radio_managed: bool,
    pub ble_wake: bool,
    pub approval: Option<tokio::sync::mpsc::Sender<Incoming>>,
}
pub async fn run(c: Config) -> Result<()> {
    ensure!(
        RECEIVE_SECONDS.contains(&c.seconds),
        "{}",
        receive_seconds_error()
    );
    ensure!(c.port > 0, "port must be nonzero");
    ensure!(
        !c.name.is_empty() && c.name.len() <= 63 && !c.name.chars().any(char::is_control),
        "invalid receiver name"
    );
    let r = crate::health::radio().await?;
    ensure!(
        r["ready"] == true && r["interface"] == c.iface,
        "AWDL radio is not ready on {}",
        c.iface
    );
    let ip: IpAddr = r["link_local"]
        .as_str()
        .context("AWDL link-local missing")?
        .parse()?;
    let mut addr = crate::discover::scope_address(ip, &c.iface)?;
    addr.set_port(c.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    std::fs::create_dir_all(&c.directory)?;
    let dest = c.directory.canonicalize()?;
    let acceptor = tls(&c.identity)?;
    let daemon = mdns_sd::ServiceDaemon::new()?;
    daemon.disable_interface(mdns_sd::IfKind::All)?;
    daemon.enable_interface(c.iface.as_str())?;
    let id = std::fs::read_to_string(format!("/sys/class/net/{}/address", c.iface))?
        .trim()
        .replace(':', "");
    let hostname = format!("ac-dc-{id}.local.");
    let info = mdns_sd::ServiceInfo::new(
        "_airdrop._tcp.local.",
        &id,
        &hostname,
        &ip.to_string()[..],
        c.port,
        &[("flags", "137")][..],
    )?;
    struct Announce(mdns_sd::ServiceDaemon, String);
    impl Drop for Announce {
        fn drop(&mut self) {
            let _ = self.0.unregister(&self.1);
            let _ = self.0.shutdown();
        }
    }
    let fullname = info.get_fullname().to_string();
    daemon.register(info)?;
    let _announce = Announce(daemon, fullname);
    tracing::info!(address=%addr,seconds=c.seconds,radio_managed=c.radio_managed,"Airdrop-compatible receive window open (Everyone; experimental)");
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let end = tokio::time::sleep(Duration::from_secs(c.seconds));
    tokio::pin!(end);
    let shutdown = crate::shutdown();
    tokio::pin!(shutdown);
    let sessions = Sessions {
        approval: c.approval.clone(),
        ..Default::default()
    };
    let mut tasks = tokio::task::JoinSet::new();
    let wake = crate::advertise::broadcast(crate::advertise::airdrop_wake(), c.seconds, 100);
    tokio::pin!(wake);
    let mut wake_done = !c.ble_wake;
    loop {
        tokio::select! {
            result=&mut wake, if !wake_done=>{wake_done=true;if let Err(e)=result{tracing::warn!(error=%e,"Airdrop-compatible Bluetooth wake unavailable");}},
            // The discovery state file can briefly disappear while awdlctl
            // refreshes it. The managed radio child and this bounded timer are
            // the authoritative lifetime; do not abort receiving on a stale
            // or transiently missing state file.
            _=&mut end=>{tracing::info!("Airdrop-compatible receive window ended");break;},
            _=&mut shutdown=>break,
            Some(())=rx.recv()=>{if c.once{break;}},
            Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if let Ok(Err(e))=result{tracing::info!(error=%format!("{e:#}"),"Airdrop-compatible connection ended");}},
            result=listener.accept()=>{let (s,_)=result?;if tasks.len()>=4{drop(s);continue;}tasks.spawn(connection(s,acceptor.clone(),c.name.clone(),dest.clone(),c.notify,c.open_destination,tx.clone(),sessions.clone()));}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[tokio::test]
    async fn tls_ask_upload_stores_file_without_touching_clipboard() {
        let tmp = Temp(std::env::temp_dir().join(format!(
            "ac-dc-airdrop-test-{:032x}",
            rand::random::<u128>()
        )));
        std::fs::create_dir(&tmp.0).unwrap();
        let dest = tmp.0.join("received");
        std::fs::create_dir(&dest).unwrap();
        let id = tmp.0.join("identity");
        let acceptor = tls(&id).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let server_dest = dest.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            connection(
                stream,
                acceptor,
                "Test".into(),
                server_dest,
                false,
                false,
                tx,
                Sessions::default(),
            )
            .await
        });
        let cert =
            openssl::x509::X509::from_pem(&std::fs::read(id.join("certificate.pem")).unwrap())
                .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert.to_der().unwrap()))
            .unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client = tokio_rustls::TlsConnector::from(Arc::new(config));
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut stream = client
            .connect("ac-dc.local".try_into().unwrap(), stream)
            .await
            .unwrap();
        let mut ask = Vec::new();
        plist::Value::Dictionary(plist::Dictionary::new())
            .to_writer_binary(&mut ask)
            .unwrap();
        stream
            .write_all(
                format!(
                    "POST /Ask HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
                    ask.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(&ask).await.unwrap();
        // Keep the same TLS connection and reader for the next request.
        use tokio::io::{AsyncBufReadExt, AsyncReadExt};
        let mut io = tokio::io::BufReader::new(stream);
        let mut line = String::new();
        io.read_line(&mut line).await.unwrap();
        assert!(line.contains("200"));
        let mut size = 0;
        loop {
            line.clear();
            io.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some(v) = line.strip_prefix("Content-Length: ") {
                size = v.trim().parse::<usize>().unwrap();
            }
        }
        let mut response = vec![0; size];
        io.read_exact(&mut response).await.unwrap();
        let mut archive = archive_fixture("./blob.bin", b"test bytes");
        archive.extend(archive_fixture("TRAILER!!!", b""));
        let mut dvzip = ((archive.len() as u32) | 0x8000_0000)
            .to_be_bytes()
            .to_vec();
        dvzip.extend(archive);
        io.get_mut().write_all(format!("POST /Upload HTTP/1.1\r\nContent-Type: application/x-dvzip\r\nContent-Length: {}\r\n\r\n",dvzip.len()).as_bytes()).await.unwrap();
        io.get_mut().write_all(&dvzip).await.unwrap();
        line.clear();
        io.read_line(&mut line).await.unwrap();
        assert!(line.contains("200"), "{line}");
        rx.recv().await.unwrap();
        assert_eq!(std::fs::read(dest.join("blob.bin")).unwrap(), b"test bytes");
        drop(io);
        server.abort();
        let _ = server.await;
    }
    fn archive_fixture(name: &str, data: &[u8]) -> Vec<u8> {
        let header = format!(
            "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            0,
            1,
            0o100600,
            0,
            0,
            1,
            0,
            0,
            name.len() + 1,
            data.len()
        );
        assert_eq!(header.len(), 76);
        let mut b = header.into_bytes();
        b.extend(name.as_bytes());
        b.push(0);
        b.extend(data);
        b
    }
    #[test]
    fn cpio_flattens_paths_and_preserves_payload() {
        let mut b = archive_fixture("../../file.txt", b"hello");
        b.extend(archive_fixture("TRAILER!!!", b""));
        let e = archive::cpio(&b).unwrap();
        assert_eq!(e[0].name, "file.txt");
        assert_eq!(e[0].bytes, b"hello");
    }
    #[test]
    fn filename_collisions_preserve_both_files() {
        let tmp =
            Temp(std::env::temp_dir().join(format!("ac-dc-files-{:032x}", rand::random::<u128>())));
        std::fs::create_dir(&tmp.0).unwrap();
        let entries = vec![
            archive::Entry {
                name: "one.txt".into(),
                bytes: b"first".to_vec(),
            },
            archive::Entry {
                name: "one.txt".into(),
                bytes: b"second".to_vec(),
            },
        ];
        let files = archive::store(&tmp.0, &entries).unwrap();
        assert_ne!(files[0], files[1]);
        assert_eq!(std::fs::read(&files[0]).unwrap(), b"first");
        assert_eq!(std::fs::read(&files[1]).unwrap(), b"second");
    }
    #[tokio::test]
    async fn open_directory_launches_the_opener_with_the_destination() {
        let tmp = Temp(
            std::env::temp_dir().join(format!("ac-dc-open-test-{:032x}", rand::random::<u128>())),
        );
        std::fs::create_dir(&tmp.0).unwrap();
        let stub = tmp.0.join("xdg-open");
        std::fs::write(
            &stub,
            "#!/bin/sh\nprintf '%s\\n' \"$1\" > \"$(dirname \"$0\")/opened.txt\"\n",
        )
        .unwrap();
        let mut perms = std::fs::metadata(&stub).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&stub, perms).unwrap();
        let dest = tmp.0.join("received");
        open_directory(&dest, stub.to_str().unwrap()).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(tmp.0.join("opened.txt"))
                .unwrap()
                .trim(),
            dest.to_str().unwrap()
        );
    }
}

#[cfg(test)]
mod link_tests {
    use super::*;
    #[test]
    fn supports_both_transfer_type_containers() {
        let mut d = plist::Dictionary::new();
        d.insert("links".into(), true.into());
        assert!(is_link_transfer(Some(&plist::Value::Dictionary(d))));
        assert!(is_link_transfer(Some(&plist::Value::Array(vec![
            "links".into()
        ]))));
        assert!(!is_link_transfer(Some(&plist::Value::Array(vec![
            "files".into()
        ]))));
    }
}

#[cfg(test)]
mod sender_tests {
    use super::*;
    #[tokio::test]
    async fn rust_sender_receiver_with_approval_and_decline() {
        let root = std::env::temp_dir().join(format!("acdc-send-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(root.join("receive")).unwrap();
        let file = root.join("example.bin");
        std::fs::write(&file, b"end-to-end Rust transfer").unwrap();
        let acceptor = tls(&root.join("server-id")).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (approval, mut prompts) = tokio::sync::mpsc::channel(4);
        let sessions = Sessions {
            approval: Some(approval),
            ..Default::default()
        };
        let (done, mut completed) = tokio::sync::mpsc::channel(4);
        let dest = root.join("receive");
        let server = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let (s, _) = listener.accept().await.unwrap();
                tasks.spawn(connection(
                    s,
                    acceptor.clone(),
                    "Test Mac".into(),
                    dest.clone(),
                    false,
                    false,
                    done.clone(),
                    sessions.clone(),
                ));
            }
        });
        let client = send::Client::new(address, &root.join("client-id")).unwrap();
        assert_eq!(client.discover().await.unwrap(), "Test Mac");
        let transfer =
            tokio::spawn(async move { client.transfer("Test Linux", vec![file], vec![]).await });
        let prompt = tokio::time::timeout(Duration::from_secs(5), prompts.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prompt.sender, "Test Linux");
        assert_eq!(prompt.items, vec!["example.bin"]);
        prompt.decision.send(true).unwrap();
        transfer.await.unwrap().unwrap();
        completed.recv().await.unwrap();
        assert_eq!(
            std::fs::read(root.join("receive/example.bin")).unwrap(),
            b"end-to-end Rust transfer"
        );
        let client = send::Client::new(address, &root.join("client-id")).unwrap();
        let file = root.join("example.bin");
        let transfer =
            tokio::spawn(
                async move { client.transfer("Declined sender", vec![file], vec![]).await },
            );
        prompts.recv().await.unwrap().decision.send(false).unwrap();
        let error = transfer.await.unwrap().unwrap_err();
        assert!(format!("{error:#}").contains("403"));
        assert_eq!(std::fs::read_dir(root.join("receive")).unwrap().count(), 1);
        server.abort();
        let _ = server.await;
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod upload_wire_tests {
    use super::*;
    async fn sender_fixture(close_ask: bool) {
        let root = std::env::temp_dir().join(format!("acdc-wire-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("test.bin");
        std::fs::write(&path, b"wire fixture").unwrap();
        let (client_cert, _) = identity(&root.join("client")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(client_cert).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let (cert, key) = identity(&root.join("server")).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // Match OpenDrop CLI: discovery has its own TLS connection.
            let (stream, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(stream).await.unwrap();
            assert!(tls
                .get_ref()
                .1
                .peer_certificates()
                .is_some_and(|c| !c.is_empty()));
            let mut discovery = tokio::io::BufReader::new(tls);
            let req = http::read(&mut discovery).await.unwrap();
            assert_eq!(req.path, "/Discover");
            assert_eq!(req.headers["connection"], "keep-alive");
            http::respond(discovery.get_mut(), 200, &response("Wire Mac").unwrap())
                .await
                .unwrap();
            drop(discovery);
            let (stream, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(stream).await.unwrap();
            let mut io = tokio::io::BufReader::new(tls);
            let mut transfer_id = None;
            for endpoint in ["/Ask", "/Upload"] {
                let req = http::read(&mut io).await.unwrap();
                assert_eq!(req.headers["connection"], "keep-alive");
                assert_eq!(req.path, endpoint);
                if endpoint == "/Ask" {
                    let ask = plist::Value::from_reader(std::io::Cursor::new(&req.body)).unwrap();
                    let dict = ask.as_dictionary().unwrap();
                    let id = dict["TransferID"].as_dictionary().unwrap()["id"]
                        .as_string()
                        .unwrap()
                        .to_owned();
                    assert_eq!(
                        dict["TransferType"].as_dictionary().unwrap()["files"],
                        plist::Value::Dictionary(plist::Dictionary::new())
                    );
                    transfer_id = Some(id);
                } else {
                    assert_eq!(
                        req.headers.get("transfer-encoding").map(String::as_str),
                        Some("chunked")
                    );
                    assert!(!req.headers.contains_key("content-length"));
                    assert_eq!(req.headers["content-type"], "application/x-dvzip");
                    assert_eq!(req.headers["transferid"], transfer_id.as_deref().unwrap());
                    assert_eq!(req.headers["totalbytes"], req.body.len().to_string());
                    assert!(req.headers["senderpseudonym"].starts_with("pseud:"));
                    assert_eq!(req.headers["senderpushtoken"].len(), 64);
                    assert_eq!(req.headers["expect"], "100-continue");
                    let plain = archive::dvzip(&req.body).unwrap();
                    let entries = archive::cpio(&plain).unwrap();
                    assert_eq!(entries[0].bytes, b"wire fixture");
                }
                if endpoint == "/Ask" && close_ask {
                    use tokio::io::AsyncWriteExt;
                    io.get_mut()
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    io.get_mut().shutdown().await.unwrap();
                    let (stream, _) = listener.accept().await.unwrap();
                    let tls = acceptor.accept(stream).await.unwrap();
                    io = tokio::io::BufReader::new(tls);
                } else {
                    http::respond(io.get_mut(), 200, &response("Wire Mac").unwrap())
                        .await
                        .unwrap();
                }
            }
        });
        let client = send::Client::new(addr, &root.join("client")).unwrap();
        assert_eq!(client.discover().await.unwrap(), "Wire Mac");
        client.transfer("Sender", vec![path], vec![]).await.unwrap();
        server.await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
    #[tokio::test]
    async fn sender_upload_matches_current_apple_wire_shape() {
        tokio::time::timeout(Duration::from_secs(10), sender_fixture(false))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn sender_reconnects_when_ask_response_closes_connection() {
        tokio::time::timeout(Duration::from_secs(10), sender_fixture(true))
            .await
            .unwrap();
    }
}
