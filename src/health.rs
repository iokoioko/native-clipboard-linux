use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;
/// How long a single `awdlctl status` probe may take. Callers that wait on a
/// readiness loop have to add this to their own budget: the loop can start a
/// probe just before its deadline and still owe it this long.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn radio() -> Result<Value> {
    let output = tokio::time::timeout(
        PROBE_TIMEOUT,
        tokio::process::Command::new("awdlctl")
            .args(["status", "--json"])
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("awdlctl status timed out")?
    .context("awdlctl is not installed; build the sibling brcmfmac-awdl repository")?;
    ensure!(
        output.status.success(),
        "awdlctl: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
pub async fn require_radio() -> Result<()> {
    let r = radio().await?;
    ensure!(
        r["ready"] == true,
        "AWDL link unavailable: {}",
        r["reason"].as_str().unwrap_or("unknown")
    );
    Ok(())
}
pub async fn report(keys: Option<&std::path::Path>, identity: Option<&std::path::Path>) -> Value {
    let radio = radio().await;
    let mut missing = Vec::new();
    match &radio {
        Ok(r) if r["ready"] == true => {}
        Ok(r) => missing.push(format!("radio: {}", r["reason"])),
        Err(e) => missing.push(format!("radio: {e:#}")),
    }
    for (label, path) in [("BLE keys", keys), ("Pair-Verify identity", identity)] {
        if let Some(p) = path {
            let valid = if label == "BLE keys" {
                crate::keystore::KeyStore::load(p).map(|k| !k.is_empty())
            } else {
                crate::companion::PairingIdentity::load(p).map(|_| true)
            };
            if !matches!(valid, Ok(true)) {
                missing.push(format!("{label}: missing or invalid at {}", p.display()));
            }
        }
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        missing.push("Wayland display unavailable".into());
    }
    if !std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|p| p.join("wl-copy").is_file()))
    {
        missing.push("wl-copy is not installed".into());
    }
    json!({"ready":missing.is_empty(),"missing":missing,"radio":radio.ok(),"protocol_validated":false})
}
