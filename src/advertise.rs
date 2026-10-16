//! Bounded BlueZ advertisement registration. No raw HCI ownership or implicit key/nonce use.
use anyhow::{ensure, Context, Result};
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
/// Dropping this owner unregisters only this application's advertisement.
pub struct Broadcast {
    _handle: bluer::adv::AdvertisementHandle,
    _session: bluer::Session,
}

/// Experimental public-identity mode. It never changes controller settings.
#[derive(Clone, Copy, Debug, Default)]
pub enum Mode {
    #[default]
    Broadcast,
    PublicPeripheral(bluer::Address),
}

fn check_info(info: &[u8], expected: bluer::Address) -> Result<()> {
    ensure!(info.len() == 280, "invalid controller information length");
    let mut address: [u8; 6] = info[..6].try_into()?;
    address.reverse();
    ensure!(
        address != [0; 6] && address == expected.0,
        "controller public identity mismatch"
    );
    let settings = u32::from_le_bytes(info[13..17].try_into()?);
    ensure!(
        settings & ((1 << 0) | (1 << 7) | (1 << 9)) == ((1 << 0) | (1 << 7) | (1 << 9)),
        "powered BR/EDR and LE controller required"
    );
    ensure!(
        settings & ((1 << 13) | (1 << 15)) == 0,
        "privacy or static identity enabled"
    );
    Ok(())
}

/// Only MGMT Read Controller Information (0x0004); no HCI controller commands.
fn read_info(index: u16) -> Result<Vec<u8>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    #[repr(C)]
    struct HciAddress {
        family: libc::sa_family_t,
        dev: u16,
        channel: u16,
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_BLUETOOTH,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            1,
        )
    };
    ensure!(
        raw >= 0,
        "read-only Bluetooth management socket unavailable"
    );
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let address = HciAddress {
        family: libc::AF_BLUETOOTH as _,
        dev: 0xffff,
        channel: 3,
    };
    let result = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &address as *const _ as *const libc::sockaddr,
            std::mem::size_of::<HciAddress>() as _,
        )
    };
    ensure!(result == 0, "read-only Bluetooth management bind failed");
    let [lo, hi] = index.to_le_bytes();
    let request = [4, 0, lo, hi, 0, 0];
    ensure!(
        unsafe { libc::send(fd.as_raw_fd(), request.as_ptr().cast(), request.len(), 0) }
            == request.len() as libc::ssize_t,
        "controller information request failed"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    for _ in 0..32 {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        ensure!(!remaining.is_zero(), "controller information timed out");
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        ensure!(
            unsafe { libc::poll(&mut poll, 1, remaining.as_millis().min(2000) as i32) } > 0,
            "controller information unavailable"
        );
        let mut buffer = [0u8; 1024];
        let len =
            unsafe { libc::recv(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        ensure!(len >= 6, "invalid management response");
        let frame = &buffer[..len as usize];
        ensure!(
            u16::from_le_bytes([frame[4], frame[5]]) as usize == frame.len() - 6,
            "invalid management frame length"
        );
        if frame[2..4] != index.to_le_bytes() {
            continue;
        }
        let event = u16::from_le_bytes([frame[0], frame[1]]);
        if (event == 1 || event == 2) && frame.len() >= 9 && frame[6..8] == [4, 0] {
            ensure!(
                frame[8] == 0 && event == 1,
                "controller information rejected"
            );
            return Ok(frame[9..].to_vec());
        }
    }
    anyhow::bail!("too many unrelated management events")
}

async fn verify_adapter(adapter: &bluer::Adapter, expected: bluer::Address) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let suffix = adapter
        .name()
        .strip_prefix("hci")
        .context("invalid controller name")?;
    let index: u16 = suffix.parse().context("invalid controller index")?;
    ensure!(
        adapter.name() == format!("hci{index}"),
        "noncanonical controller name"
    );
    let info = tokio::task::spawn_blocking(move || read_info(index)).await??;
    check_info(&info, expected)?;
    let path = format!("/sys/kernel/debug/bluetooth/hci{index}/force_static_address");
    let flag = match tokio::fs::File::open(&path).await {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(4).read_to_end(&mut bytes).await?;
            bytes
        }
        Err(_) => {
            // Existing read-only sudo policy only. No shell or policy modification.
            let mut child = tokio::process::Command::new("/usr/bin/sudo")
                .args(["-n", "/usr/bin/cat", &path])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let mut bytes = Vec::new();
            child
                .stdout
                .take()
                .context("missing flag reader")?
                .take(4)
                .read_to_end(&mut bytes)
                .await?;
            ensure!(
                child.wait().await?.success(),
                "force-static verification unavailable"
            );
            bytes
        }
    };
    ensure!(
        flag == b"N\n",
        "force-static flag must be verifiably disabled"
    );
    ensure!(
        adapter.address().await? == expected,
        "adapter identity changed"
    );
    Ok(())
}

pub async fn preflight(mode: Mode) -> Result<()> {
    if let Mode::PublicPeripheral(expected) = mode {
        tokio::time::timeout(Duration::from_secs(5), async {
            let session = bluer::Session::new().await?;
            verify_adapter(&session.default_adapter().await?, expected).await
        })
        .await
        .context("public controller verification timed out")??;
    }
    Ok(())
}

pub async fn register(data: Vec<u8>, seconds: u64, interval_ms: u64) -> Result<Broadcast> {
    register_with_mode(data, seconds, interval_ms, Mode::Broadcast).await
}

pub async fn register_with_mode(
    data: Vec<u8>,
    seconds: u64,
    interval_ms: u64,
    mode: Mode,
) -> Result<Broadcast> {
    validate(&data)?;
    ensure!(
        (1..=3600).contains(&seconds),
        "duration must be 1..3600 seconds"
    );
    ensure!(
        (100..=1000).contains(&interval_ms),
        "interval must be 100..1000 ms"
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;
        ensure!(
            adapter.is_powered().await?,
            "Bluetooth adapter is powered off"
        );
        if let Mode::PublicPeripheral(expected) = mode {
            verify_adapter(&adapter, expected).await?;
        }
        let advertisement = bluer::adv::Advertisement {
            advertisement_type: match mode {
                Mode::Broadcast => bluer::adv::Type::Broadcast,
                Mode::PublicPeripheral(_) => bluer::adv::Type::Peripheral,
            },
            manufacturer_data: BTreeMap::from([(0x004c, data)]),
            timeout: Some(Duration::from_secs(seconds)),
            min_interval: Some(Duration::from_millis(interval_ms)),
            max_interval: Some(Duration::from_millis(interval_ms)),
            ..Default::default()
        };
        let handle = adapter.advertise(advertisement).await?;
        if let Mode::PublicPeripheral(expected) = mode {
            verify_adapter(&adapter, expected).await?;
        }
        tracing::info!(adapter=%adapter.name(),seconds,"BLE advertisement registered");
        Ok(Broadcast {
            _handle: handle,
            _session: session,
        })
    })
    .await
    .map_err(|_| anyhow::anyhow!("Bluetooth advertisement registration timed out"))?
}

pub async fn broadcast(data: Vec<u8>, seconds: u64, interval_ms: u64) -> Result<()> {
    let handle = register(data, seconds, interval_ms).await?;
    tokio::select! {_=tokio::time::sleep(Duration::from_secs(seconds))=>{},_=crate::shutdown()=>{}}
    drop(handle);
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_mode_requires_matching_enabled_public_identity() {
        let expected = bluer::Address([2, 3, 4, 5, 6, 7]);
        let mut info = vec![0u8; 280];
        info[..6].copy_from_slice(&[7, 6, 5, 4, 3, 2]);
        let required: u32 = (1 << 0) | (1 << 7) | (1 << 9);
        info[13..17].copy_from_slice(&required.to_le_bytes());
        assert!(check_info(&info, expected).is_ok());
        for forbidden in [1 << 13, 1 << 15] {
            info[13..17].copy_from_slice(&(required | forbidden).to_le_bytes());
            assert!(check_info(&info, expected).is_err());
        }
        for missing in [1 << 0, 1 << 7, 1 << 9] {
            info[13..17].copy_from_slice(&(required & !missing).to_le_bytes());
            assert!(check_info(&info, expected).is_err());
        }
        info[13..17].copy_from_slice(&required.to_le_bytes());
        assert!(check_info(&info, bluer::Address([3; 6])).is_err());
        assert!(check_info(&info[..279], expected).is_err());
        info[..6].fill(0);
        assert!(check_info(&info, bluer::Address([0; 6])).is_err());
    }

    #[test]
    fn rejects_truncated_tlv() {
        assert!(validate(&[5, 18, 0]).is_err());
        assert!(validate(&[5]).is_err());
        assert!(validate(&airdrop_wake()).is_ok());
        assert_eq!(airdrop_wake().len(), 20);
    }
}
