//! Bounded BlueZ advertisement registration. No raw HCI ownership or implicit key/nonce use.
use anyhow::{ensure, Result};
use std::{collections::BTreeMap, time::Duration};
pub fn validate(data: &[u8]) -> Result<()> {
    ensure!(
        data.len() >= 2 && data.len() <= 24,
        "Apple manufacturer TLV must fit a legacy BLE advertisement"
    );
    let mut off = 0;
    while off < data.len() {
        ensure!(data.len() - off >= 2, "truncated advertisement TLV");
        let n = data[off + 1] as usize;
        ensure!(off + 2 + n <= data.len(), "truncated advertisement payload");
        off += 2 + n;
    }
    Ok(())
}
pub fn airdrop_wake() -> Vec<u8> {
    let mut out = vec![5, 18, 0x40, 0, 0, 0, 0, 0, 0, 0, 3];
    out.extend([0; 9]);
    out
}
pub async fn broadcast(data: Vec<u8>, seconds: u64, interval_ms: u64) -> Result<()> {
    validate(&data)?;
    ensure!(
        (1..=3600).contains(&seconds),
        "duration must be 1..3600 seconds"
    );
    ensure!(
        (100..=1000).contains(&interval_ms),
        "interval must be 100..1000 ms"
    );
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    ensure!(
        adapter.is_powered().await?,
        "Bluetooth adapter is powered off"
    );
    let advertisement = bluer::adv::Advertisement {
        advertisement_type: bluer::adv::Type::Broadcast,
        manufacturer_data: BTreeMap::from([(0x004c, data)]),
        timeout: Some(Duration::from_secs(seconds)),
        min_interval: Some(Duration::from_millis(interval_ms)),
        max_interval: Some(Duration::from_millis(interval_ms)),
        ..Default::default()
    };
    let handle = adapter.advertise(advertisement).await?;
    tracing::info!(adapter=%adapter.name(),seconds,"BLE advertisement registered");
    tokio::select! {_=tokio::time::sleep(Duration::from_secs(seconds))=>{},_=crate::shutdown()=>{}}
    drop(handle);
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_truncated_tlv() {
        assert!(validate(&[5, 18, 0]).is_err());
        assert!(validate(&[5]).is_err());
        assert!(validate(&airdrop_wake()).is_ok());
        assert_eq!(airdrop_wake().len(), 20);
    }
}
