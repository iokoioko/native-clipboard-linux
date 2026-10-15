//! BLE-triggered clipboard pull. Radio configuration belongs to awdlctl.
use crate::{
    clipboard_out,
    companion::PairingIdentity,
    companion_client::{self, SystemInfo},
    discover, health,
    keystore::KeyStore,
    scan::Scanner,
};
use anyhow::{Context, Result};
use std::{path::PathBuf, time::Duration};
pub struct AutoConfig {
    pub keys: PathBuf,
    pub identity_path: PathBuf,
    pub instance: Option<String>,
    pub loopback: bool,
    pub notify: bool,
    pub requester_id: Option<String>,
    pub advertisement_payload: Option<String>,
}
pub async fn run(cfg: AutoConfig) -> Result<()> {
    if cfg.loopback {
        let (_, board) = companion_client::loopback_demo().await?;
        clipboard_out::copy_pasteboard(&board)?;
        return Ok(());
    }
    // Fail at startup on bad credentials; do not retry malformed key exports forever.
    PairingIdentity::load(&cfg.identity_path)?;
    let requester_id = cfg
        .requester_id
        .as_deref()
        .context("missing clipboard requester id")?;
    let advertisement_payload = hex::decode(
        cfg.advertisement_payload
            .as_deref()
            .context("missing validated clipboard advertisement payload")?,
    )?;
    tracing::warn!("fixed-context experiment: request context is reused; binding it to each BLE copy event remains unvalidated");
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let scanner = Scanner::new(KeyStore::load(&cfg.keys)?)
        .await?
        .with_events(tx);
    let process = async {
        while let Some(event) = rx.recv().await {
            tracing::info!(device=%event.device, key=%event.key_id, activity=%event.activity,"copy detected");
            let result = tokio::time::timeout(Duration::from_secs(40), async {
                health::require_radio().await?;
                let (host, port) = discover::resolve(
                    "awdl0",
                    cfg.instance.as_deref(),
                    Some(&event.address),
                    Duration::from_secs(10),
                )
                .await?;
                let mut session = companion_client::connect(
                    &host,
                    port,
                    PairingIdentity::load(&cfg.identity_path)?,
                )
                .await?;
                session
                    .system_info_exchange(&SystemInfo {
                        name: "ac-dc".into(),
                        model: "Linux".into(),
                        os_version: env!("CARGO_PKG_VERSION").into(),
                    })
                    .await?;
                let board = session
                    .fetch_pasteboard_with(
                        requester_id,
                        &advertisement_payload,
                        crate::clipboard::COMMAND_PB_PASTE2,
                    )
                    .await?;
                let outcome = clipboard_out::copy_pasteboard(&board)?;
                if let Some(out) = outcome {
                    tracing::info!(
                        bytes = out.bytes,
                        copied = out.spawned,
                        "clipboard transfer complete"
                    );
                    if cfg.notify && out.spawned {
                        let _ = tokio::process::Command::new("notify-send")
                            .args(["Clipboard received", &format!("From {}", event.device)])
                            .kill_on_drop(true)
                            .status()
                            .await;
                    }
                }
                anyhow::Ok(())
            })
            .await
            .context("clipboard transaction timed out")
            .and_then(|r| r);
            if let Err(e) = result {
                tracing::warn!(error=%format!("{e:#}"),"clipboard pull failed; waiting for next copy");
            }
        }
        anyhow::Ok(())
    };
    tokio::select! {r=scanner.run()=>r, r=process=>r, _=crate::shutdown()=>Ok(())}
}
