//! Conservative text sync: first remote value is a baseline, local changes win.
//! Only hashes survive between requests; clipboard bytes are never logged.
use sha2::{Digest, Sha256};
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    hash: [u8; 32],
    local_changed: bool,
}

#[derive(Default)]
pub struct SyncState {
    local: Option<[u8; 32]>,
    remote: Option<[u8; 32]>,
    local_change_pending: bool,
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// Bound both memory and wall time, including clipboard owners which never reply.
async fn read_local() -> Option<[u8; 32]> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut child = tokio::process::Command::new("wl-paste")
            .arg("--no-newline")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .ok()?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()?
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .ok()?;
        if bytes.len() > 8 * 1024 * 1024 {
            return None;
        }
        if !child.wait().await.ok()?.success() {
            return None;
        }
        Some(digest(&bytes))
    })
    .await
    .ok()
    .flatten()
}

// wl-copy forks only after acquiring the selection. Keep its entire process
// group cancellable until successful completion, including any forked child.
async fn run_copy_command(
    mut command: tokio::process::Command,
    bytes: &[u8],
    limit: Duration,
) -> bool {
    use std::os::unix::process::CommandExt;
    command.as_std_mut().process_group(0);
    let Ok(mut child) = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    else {
        return false;
    };
    struct GroupGuard(Option<u32>);
    impl Drop for GroupGuard {
        fn drop(&mut self) {
            if let Some(pid) = self.0 {
                unsafe {
                    libc::kill(-(pid as i32), libc::SIGKILL);
                }
            }
        }
    }
    let mut guard = GroupGuard(child.id());
    let result = tokio::time::timeout(limit, async {
        let mut input = child.stdin.take()?;
        input.write_all(bytes).await.ok()?;
        drop(input);
        child.wait().await.ok().map(|status| status.success())
    })
    .await;
    if matches!(result, Ok(Some(true))) {
        guard.0 = None;
        true
    } else {
        false
    }
}

async fn write_text(bytes: &[u8]) -> bool {
    // An independent owner unit preserves the selection across sync pause/restart.
    // Type=forking waits for wl-copy's post-selection parent exit, not mere exec.
    let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") else {
        return false;
    };
    let Ok(mut file) = tempfile::NamedTempFile::new_in(runtime) else {
        return false;
    };
    if std::io::Write::write_all(&mut file, bytes).is_err() {
        return false;
    }
    let unit = format!(
        "native-clipboard-owner-{}.service",
        uuid::Uuid::new_v4().simple()
    );
    let mut command = tokio::process::Command::new("systemd-run");
    command
        .args(["--user", "--quiet", "--collect", "--service-type=forking"])
        .arg(format!("--unit={unit}"))
        .arg(format!(
            "--property=StandardInput=file:{}",
            file.path().display()
        ))
        .args([
            "--property=TimeoutStartSec=3",
            "--property=TimeoutStopSec=2",
            "--property=UMask=0077",
        ]);
    // Explicitly retain the active session's display rather than stale manager values.
    for name in ["WAYLAND_DISPLAY", "XDG_RUNTIME_DIR"] {
        if let Ok(value) = std::env::var(name) {
            command.arg(format!("--setenv={name}={value}"));
        }
    }
    command.args(["--", "wl-copy", "--type", "text/plain;charset=utf-8"]);
    let started = run_copy_command(command, b"", Duration::from_secs(5)).await;
    let verified = started && read_local().await == Some(digest(bytes));
    if !verified {
        // Killing systemd-run alone cannot cancel its independent unit. Explicit
        // stop cancels any pending start; TimeoutStartSec also bounds the owner.
        let mut stop = tokio::process::Command::new("systemctl");
        stop.args(["--user", "stop", &unit]);
        let _ = run_copy_command(stop, b"", Duration::from_secs(4)).await;
    }
    verified
}

impl SyncState {
    pub fn new() -> Self {
        Self::default()
    }

    // An authenticated empty remote response establishes that no old value is
    // waiting; the next nonempty value can be considered a fresh copy.
    pub fn observe_empty(&mut self) {
        self.local_change_pending = false;
        if self.remote.is_none() {
            self.remote = Some(digest(b""));
        }
    }

    pub async fn snapshot(&mut self) -> Option<Snapshot> {
        let hash = read_local().await?;
        self.local_change_pending |= self.local.is_some_and(|old| old != hash);
        let local_changed = self.local_change_pending;
        self.local = Some(hash);
        Some(Snapshot {
            hash,
            local_changed,
        })
    }

    fn decide(
        &mut self,
        before: Option<Snapshot>,
        after: Option<[u8; 32]>,
        remote: [u8; 32],
    ) -> &'static str {
        let previous_remote = self.remote.replace(remote);
        self.local_change_pending = false;
        if let Some(after) = after {
            self.local = Some(after);
        }
        if previous_remote.is_none() {
            return "remote_baseline";
        }
        if previous_remote == Some(remote) {
            return "duplicate_remote";
        }
        let (Some(before), Some(after)) = (before, after) else {
            return "local_clipboard_unavailable";
        };
        if before.local_changed || before.hash != after {
            return "newer_local_clipboard";
        }
        if after == remote {
            return "already_on_clipboard";
        }
        "write"
    }

    pub async fn apply_remote(
        &mut self,
        before: Option<Snapshot>,
        bytes: &[u8],
    ) -> serde_json::Value {
        let remote = digest(bytes);
        let after = read_local().await;
        let reason = self.decide(before, after, remote);
        if reason != "write" {
            return serde_json::json!({"written": false, "reason": reason});
        }
        let written = write_text(bytes).await;
        if written {
            self.local = Some(remote);
        }
        serde_json::json!({"written": written, "reason": if written { "remote_text_received" } else { "clipboard_write_failed" }, "bytes": bytes.len()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snap(value: &[u8], changed: bool) -> Option<Snapshot> {
        Some(Snapshot {
            hash: digest(value),
            local_changed: changed,
        })
    }
    #[tokio::test]
    #[ignore = "explicit live Wayland check; reoffers current UTF-8 clipboard bytes"]
    async fn live_owner_reoffers_current_text_and_verifies_readback() {
        let output = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::process::Command::new("wl-paste")
                .arg("--no-newline")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(output.status.success());
        assert!(output.stdout.len() <= 1024 * 1024);
        std::str::from_utf8(&output.stdout)
            .expect("current clipboard must be UTF-8 for this explicit check");
        // Abort if a local copy changed while preparing the check.
        assert_eq!(read_local().await, Some(digest(&output.stdout)));
        assert!(write_text(&output.stdout).await);
    }

    #[tokio::test]
    async fn timed_out_writer_cannot_finish_later() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("late-write");
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.args(["-c", "(sleep 0.2; printf late > \"$1\") & wait", "test"])
            .arg(&marker);
        assert!(!run_copy_command(cmd, b"test", Duration::from_millis(30)).await);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!marker.exists());
    }
    #[test]
    fn empty_remote_baseline_allows_the_next_fresh_text() {
        let mut s = SyncState::new();
        s.observe_empty();
        assert_eq!(
            s.decide(
                snap(b"local", false),
                Some(digest(b"local")),
                digest(b"new phone")
            ),
            "write"
        );
    }
    #[test]
    fn startup_never_imports_an_old_remote_clipboard() {
        let mut s = SyncState::new();
        assert_eq!(
            s.decide(
                snap(b"local", false),
                Some(digest(b"local")),
                digest(b"old phone")
            ),
            "remote_baseline"
        );
        assert_eq!(
            s.decide(
                snap(b"local", false),
                Some(digest(b"local")),
                digest(b"old phone")
            ),
            "duplicate_remote"
        );
        assert_eq!(
            s.decide(
                snap(b"local", false),
                Some(digest(b"local")),
                digest(b"new phone")
            ),
            "write"
        );
    }
    #[test]
    fn local_change_during_fetch_wins_and_remote_is_not_replayed() {
        let mut s = SyncState::new();
        s.remote = Some(digest(b"baseline"));
        assert_eq!(
            s.decide(
                snap(b"old", false),
                Some(digest(b"new local")),
                digest(b"phone")
            ),
            "newer_local_clipboard"
        );
        assert_eq!(
            s.decide(
                snap(b"new local", false),
                Some(digest(b"new local")),
                digest(b"phone")
            ),
            "duplicate_remote"
        );
    }
    #[test]
    fn local_change_between_connections_and_failed_reads_are_conservative() {
        let mut s = SyncState::new();
        s.remote = Some(digest(b"baseline"));
        assert_eq!(
            s.decide(
                snap(b"local", true),
                Some(digest(b"local")),
                digest(b"phone1")
            ),
            "newer_local_clipboard"
        );
        assert_eq!(
            s.decide(None, None, digest(b"phone2")),
            "local_clipboard_unavailable"
        );
        assert_eq!(
            s.decide(snap(b"same", false), Some(digest(b"same")), digest(b"same")),
            "already_on_clipboard"
        );
    }
}
