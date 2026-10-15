//! Everyone-mode Airdrop-compatible HTTPS client. Discovery names are not authenticated identities.
use anyhow::{ensure, Context, Result};
use plist::{Dictionary, Value};
use rand::RngCore;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

pub struct Client {
    tls: openssl::ssl::SslConnector,
    address: SocketAddr,
    sender_id: String,
}
impl Client {
    pub fn new(address: SocketAddr, identity_dir: &Path) -> Result<Self> {
        super::identity(identity_dir)?;
        Ok(Self {
            tls: super::client_http::connector(identity_dir)?,
            address,
            sender_id: super::service_id(identity_dir)?,
        })
    }
    pub async fn discover(&self) -> Result<String> {
        let mut session = super::client_http::Session::connect(self.address, &self.tls).await?;
        let payload = plist(Dictionary::new())?;
        let size = payload.len() as u64;
        let bytes = session
            .post(
                "/Discover",
                "application/octet-stream",
                super::client_http::bytes(payload),
                size,
            )
            .await?;
        let value = Value::from_reader(std::io::Cursor::new(bytes))?;
        let name = value
            .as_dictionary()
            .and_then(|v| v.get("ReceiverComputerName"))
            .and_then(Value::as_string)
            .context("peer did not offer Everyone-mode discovery")?;
        ensure!(
            !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control),
            "invalid peer display name"
        );
        Ok(name.into())
    }
    pub async fn transfer(
        &self,
        sender: &str,
        files: Vec<PathBuf>,
        links: Vec<String>,
    ) -> Result<()> {
        self.transfer_with_progress(sender, files, links, None)
            .await
    }
    pub async fn transfer_with_progress(
        &self,
        sender: &str,
        files: Vec<PathBuf>,
        links: Vec<String>,
        progress: Option<tokio::sync::watch::Sender<(u64, u64)>>,
    ) -> Result<()> {
        ensure!(
            !sender.is_empty() && sender.len() <= 63 && !sender.chars().any(char::is_control),
            "invalid sender name"
        );
        ensure!(
            files.is_empty() != links.is_empty(),
            "choose files or links"
        );
        // Discovery owns a separate connection. Ask and Upload share this
        // transfer's dedicated connection, matching the OpenDrop CLI flow.
        let cancellation = super::cancel::Guard(super::cancel::Token::default());
        let token = cancellation.0.clone();
        let mut prepared = if files.is_empty() {
            None
        } else {
            Some(
                tokio::task::spawn_blocking(move || super::outgoing::prepare_cancel(&files, token))
                    .await??,
            )
        };
        let mut ask = Dictionary::new();
        let upload = UploadIdentity::new();
        ask.insert("SenderComputerName".into(), sender.into());
        ask.insert("SenderModelName".into(), "ac-dc".into());
        ask.insert("SenderID".into(), self.sender_id.clone().into());
        ask.insert("BundleID".into(), "com.apple.finder".into());
        ask.insert("ConvertMediaFormats".into(), false.into());
        let mut transfer_id = Dictionary::new();
        transfer_id.insert("id".into(), upload.transfer_id.clone().into());
        ask.insert("TransferID".into(), Value::Dictionary(transfer_id));
        if !links.is_empty() {
            ensure!(links.len() <= 128, "too many links");
            for url in &links {
                ensure!(
                    url.len() <= 8192
                        && (url.starts_with("https://") || url.starts_with("http://"))
                        && !url.chars().any(char::is_control),
                    "only HTTP(S) links are supported"
                );
            }
            ask.insert(
                "Items".into(),
                Value::Array(links.into_iter().map(Value::String).collect()),
            );
            ask.insert("TransferType".into(), Value::Array(vec!["links".into()]));
        } else {
            let mut transfer_type = Dictionary::new();
            transfer_type.insert("files".into(), Value::Dictionary(Dictionary::new()));
            ask.insert("TransferType".into(), Value::Dictionary(transfer_type));
            ask.insert(
                "Files".into(),
                Value::Array(std::mem::take(&mut prepared.as_mut().unwrap().metadata)),
            );
        }
        if let Some(tx) = &progress {
            let _ = tx.send((0, prepared.as_ref().map(|p| p.bytes).unwrap_or(1)));
        }
        let mut session = super::client_http::Session::connect(self.address, &self.tls).await?;
        let payload = plist(ask)?;
        let size = payload.len() as u64;
        session
            .post(
                "/Ask",
                "application/octet-stream",
                super::client_http::bytes(payload),
                size,
            )
            .await?;
        if let Some(prepared) = prepared {
            // Like HTTPConnection, reconnect only when the previous response
            // closed the session. Never replay an Upload after an ambiguous error.
            if session.is_closed() {
                session = super::client_http::Session::connect(self.address, &self.tls).await?;
            }
            use futures::StreamExt;
            let total = prepared.bytes;
            let uploaded = Arc::new(AtomicU64::new(0));
            let uploaded_for_stream = uploaded.clone();
            let file = tokio::fs::File::from_std(prepared.archive.reopen()?);
            let mut sent = 0u64;
            let stream =
                tokio_util::io::ReaderStream::with_capacity(file, 8 * 1024).map(move |chunk| {
                    if let Ok(bytes) = &chunk {
                        sent += bytes.len() as u64;
                        uploaded_for_stream.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                        if let Some(tx) = &progress {
                            let _ = tx.send((sent, total));
                        }
                    }
                    chunk
                });
            use http_body_util::BodyExt;
            let body = http_body_util::StreamBody::new(
                stream.map(|chunk| chunk.map(hyper::body::Frame::data)),
            )
            .boxed_unsync();
            let headers = [
                ("TotalBytes", total.to_string()),
                ("SenderPseudonym", upload.pseudonym),
                ("SenderPushToken", upload.push_token),
                ("TransferID", upload.transfer_id),
                ("Expect", "100-continue".into()),
            ];
            let result = session
                .post_with_headers("/Upload", "application/x-dvzip", body, total, &headers)
                .await;
            if let Err(error) = result {
                let sent = uploaded.load(Ordering::Relaxed);
                let text = format!("{error:#}");
                if sent == total && text.contains("connection closed before message completed") {
                    // Some Apple receivers close TLS after consuming Upload rather
                    // than sending an HTTP final response. Once every byte is on
                    // the wire, this is an accepted completion signal; an early
                    // close remains a real transfer failure.
                    tracing::warn!(
                        bytes = sent,
                        "Apple receiver closed after complete Upload without a final HTTP response"
                    );
                } else {
                    return Err(error);
                }
            }
        }
        Ok(())
    }
}
struct UploadIdentity {
    transfer_id: String,
    pseudonym: String,
    push_token: String,
}
impl UploadIdentity {
    fn new() -> Self {
        use base64::Engine;
        let mut pseudonym = [0u8; 16];
        let mut push_token = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut pseudonym);
        rand::thread_rng().fill_bytes(&mut push_token);
        Self {
            transfer_id: uuid::Uuid::new_v4().hyphenated().to_string().to_uppercase(),
            pseudonym: format!(
                "pseud:{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pseudonym)
            ),
            push_token: hex::encode_upper(push_token),
        }
    }
}
fn plist(dict: Dictionary) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    Value::Dictionary(dict).to_writer_binary(&mut b)?;
    Ok(b)
}
#[cfg(test)]
fn entry(out: &mut Vec<u8>, name: &str, data: &[u8], ino: usize) {
    out.extend(
        format!(
            "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            0,
            ino,
            0o100600,
            0,
            0,
            1,
            0,
            0,
            name.len() + 1,
            data.len()
        )
        .bytes(),
    );
    out.extend(name.as_bytes());
    out.push(0);
    out.extend(data);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_archive_decodes() {
        let mut b = Vec::new();
        entry(&mut b, "./hello.txt", b"hello", 1);
        entry(&mut b, "TRAILER!!!", b"", 2);
        let result = super::super::archive::cpio(&b).unwrap();
        assert_eq!(result[0].bytes, b"hello");
        assert_eq!(result[0].name, "hello.txt");
    }
}
