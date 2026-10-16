//! Conservative typed text/PNG sync: first remote value is a baseline, local changes win.
//! Only hashes survive between requests; clipboard bytes are never logged.
#[path = "clipboard_image.rs"]
pub(crate) mod image;
use image::{PNG_MIME, TEXT_MIME};
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

fn typed_digest(mime: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((mime.len() as u64).to_be_bytes());
    hash.update(mime.as_bytes());
    hash.update(bytes);
    hash.finalize().into()
}
async fn paste(command: &std::path::Path, args: &[&str], limit: usize) -> Option<Vec<u8>> {
    let mut child = tokio::process::Command::new(command)
        .args(args)
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
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .ok()?;
    if bytes.len() > limit || !child.wait().await.ok()?.success() {
        return None;
    }
    Some(bytes)
}
async fn read_local_with(command: &std::path::Path) -> Option<[u8; 32]> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let types = paste(command, &["--list-types"], 16384).await?;
        let types = std::str::from_utf8(&types).ok()?;
        let mut offered = types.lines().collect::<Vec<_>>();
        offered.sort_unstable();
        offered.dedup();
        if offered.len() > 128
            || offered
                .iter()
                .any(|mime| mime.is_empty() || mime.len() > 256)
        {
            return None;
        }
        let supported = [TEXT_MIME, "text/plain", "UTF8_STRING", PNG_MIME];
        let mut hash = Sha256::new();
        hash.update(b"clipboard-snapshot-v1");
        for mime in &offered {
            hash.update((mime.len() as u64).to_be_bytes());
            hash.update(mime.as_bytes());
        }
        // Preserve the existing 8 MiB per-format text allowance, including
        // clipboard owners advertising several text aliases. Four supported
        // formats bound aggregate reads to 32 MiB; only one buffer is live.
        let mut remaining = 32 * 1024 * 1024;
        let mut count = 0;
        for mime in offered.into_iter().filter(|mime| supported.contains(mime)) {
            let bytes = paste(
                command,
                &["--no-newline", "--type", mime],
                remaining.min(8 * 1024 * 1024),
            )
            .await?;
            remaining = remaining.checked_sub(bytes.len())?;
            hash.update((mime.len() as u64).to_be_bytes());
            hash.update(mime.as_bytes());
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(&bytes);
            count += 1;
        }
        if count == 0 {
            return None;
        }
        Some(hash.finalize().into())
    })
    .await
    .ok()
    .flatten()
}
// Explicit MIME queries avoid wl-paste selecting an unrelated text alternative
// when verifying an image. No newline conversion is applied to binary PNG bytes.
async fn read_typed_with(command: &std::path::Path, mime: &str) -> Option<[u8; 32]> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let bytes = paste(command, &["--no-newline", "--type", mime], 8 * 1024 * 1024).await?;
        Some(typed_digest(mime, &bytes))
    })
    .await
    .ok()
    .flatten()
}
async fn read_typed(mime: &str) -> Option<[u8; 32]> {
    read_typed_with(std::path::Path::new("wl-paste"), mime).await
}
async fn read_local() -> Option<[u8; 32]> {
    read_local_with(std::path::Path::new("wl-paste")).await
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

async fn write_typed(mime: &str, bytes: &[u8]) -> Option<[u8; 32]> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")?;
    write_typed_with(
        mime,
        bytes,
        std::path::Path::new(&runtime),
        std::path::Path::new("systemd-run"),
        std::path::Path::new("systemctl"),
        std::path::Path::new("wl-paste"),
    )
    .await
}
async fn write_typed_with(
    mime: &str,
    bytes: &[u8],
    runtime: &std::path::Path,
    runner: &std::path::Path,
    stop_program: &std::path::Path,
    paste_program: &std::path::Path,
) -> Option<[u8; 32]> {
    // Independent Type=forking owner preserves the selection across sync stops.
    let Ok(mut file) = tempfile::NamedTempFile::new_in(runtime) else {
        return None;
    };
    if std::io::Write::write_all(&mut file, bytes).is_err() {
        return None;
    }
    let unit = format!(
        "native-clipboard-owner-{}.service",
        uuid::Uuid::new_v4().simple()
    );
    let mut command = tokio::process::Command::new(runner);
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
    command.args(["--", "wl-copy", "--type", mime]);
    let started = run_copy_command(command, b"", Duration::from_secs(5)).await;
    let local = if started {
        read_local_with(paste_program).await
    } else {
        None
    };
    let verified = local.is_some()
        && read_typed_with(paste_program, mime).await == Some(typed_digest(mime, bytes));
    if !verified {
        // Killing systemd-run alone cannot cancel its independent unit. Explicit
        // stop cancels any pending start; TimeoutStartSec also bounds the owner.
        let mut stop = tokio::process::Command::new(stop_program);
        stop.args(["--user", "stop", &unit]);
        let _ = run_copy_command(stop, b"", Duration::from_secs(4)).await;
    }
    if verified {
        local
    } else {
        None
    }
}

#[cfg(test)]
async fn write_text(bytes: &[u8]) -> bool {
    write_typed(TEXT_MIME, bytes).await.is_some()
}

impl SyncState {
    pub fn new() -> Self {
        Self::default()
    }

    // An authenticated empty remote response establishes that no old value is
    // waiting; the next nonempty value can be considered a fresh copy.
    pub fn observe_empty(&mut self) {
        // An empty response ends the pending interval for FUTURE snapshots.
        // The current session's snapshot still protects an overlapping local copy.
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
        self.apply_typed(before, image::Kind::Text, bytes).await
    }
    pub async fn apply_typed(
        &mut self,
        before: Option<Snapshot>,
        kind: image::Kind,
        bytes: &[u8],
    ) -> serde_json::Value {
        let mime = kind.mime();
        let valid = match kind {
            image::Kind::Text => {
                std::str::from_utf8(bytes).is_ok() && bytes.len() <= 8 * 1024 * 1024
            }
            image::Kind::Png => image::validate_png(bytes).is_ok(),
        };
        if !valid {
            return serde_json::json!({"written":false,"reason":"invalid_typed_payload"});
        }
        let remote = typed_digest(mime, bytes);
        let after = read_local().await;
        let reason = self.decide(before, after, remote);
        if reason != "write" {
            return serde_json::json!({"written":false,"reason":reason});
        }
        if read_typed(mime).await == Some(remote) {
            return serde_json::json!({"written":false,"reason":"already_on_clipboard"});
        }
        // MIME-specific readback above must not open a new local-edit window.
        if read_local().await != after {
            return serde_json::json!({"written":false,"reason":"newer_local_clipboard"});
        }
        let owner_snapshot = write_typed(mime, bytes).await;
        let written = owner_snapshot.is_some();
        if written {
            self.local = owner_snapshot;
        }
        serde_json::json!({"written":written,"reason":if written {if kind==image::Kind::Png {"remote_png_received"}else{"remote_text_received"}}else{"clipboard_write_failed"},"bytes":bytes.len(),"mime":mime})
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
        let before = read_local()
            .await
            .expect("readable local selection required");
        let output = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::process::Command::new("wl-paste")
                .args(["--no-newline", "--type", TEXT_MIME])
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
        assert_eq!(read_local().await, Some(before));
        assert_eq!(
            read_typed(TEXT_MIME).await,
            Some(typed_digest(TEXT_MIME, &output.stdout))
        );
        assert!(write_text(&output.stdout).await);
    }

    #[tokio::test]
    async fn mixed_mime_image_change_with_identical_text_is_a_local_edit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let command = dir.path().join("paste");
        std::fs::write(&command,b"#!/bin/sh\nif [ \"$1\" = --list-types ]; then cat \"$0.types\"; elif [ \"$3\" = image/png ]; then cat \"$0.png\"; else cat \"$0.text\"; fi\n").unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            dir.path().join("paste.types"),
            format!("{PNG_MIME}\n{TEXT_MIME}\n"),
        )
        .unwrap();
        std::fs::write(dir.path().join("paste.text"), b"unchanged text").unwrap();
        std::fs::write(dir.path().join("paste.png"), b"synthetic first image bytes").unwrap();
        let first = read_local_with(&command).await.unwrap();
        std::fs::write(
            dir.path().join("paste.png"),
            b"synthetic changed image bytes",
        )
        .unwrap();
        let changed = read_local_with(&command).await.unwrap();
        assert_ne!(first, changed);
        let mut sync = SyncState::new();
        sync.remote = Some(digest(b"baseline"));
        assert_eq!(
            sync.decide(
                Some(Snapshot {
                    hash: first,
                    local_changed: false
                }),
                Some(changed),
                typed_digest(PNG_MIME, b"phone image")
            ),
            "newer_local_clipboard"
        );
        assert_ne!(
            typed_digest(TEXT_MIME, b"same"),
            typed_digest(PNG_MIME, b"same")
        );
    }
    #[tokio::test]
    async fn png_owner_pipeline_preserves_binary_mime_and_stops_failed_readback() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let runner = dir.path().join("runner");
        let paste = dir.path().join("paste");
        let stop = dir.path().join("stop");
        std::fs::write(
            &runner,
            r#"#!/bin/sh
base=${0%/*}
for arg in "$@"; do
 case "$arg" in --property=StandardInput=file:*) file=${arg#--property=StandardInput=file:};; esac
 mime=$arg
done
[ "$mime" = image/png ] || exit 1
cat "$file" > "$base/payload"
printf 'image/png\n' > "$base/types"
"#,
        )
        .unwrap();
        std::fs::write(
            &paste,
            r#"#!/bin/sh
base=${0%/*}
if [ "$1" = --list-types ]; then cat "$base/types"
elif [ "$3" = image/png ]; then
 if [ -e "$base/bad-readback" ]; then printf bad; else cat "$base/payload"; fi
else exit 1
fi
"#,
        )
        .unwrap();
        std::fs::write(
            &stop,
            r#"#!/bin/sh
base=${0%/*}
printf '%s\n' "$@" > "$base/stopped"
"#,
        )
        .unwrap();
        for command in [&runner, &paste, &stop] {
            std::fs::set_permissions(command, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let png = image::tests::png();
        image::validate_png(&png).unwrap();
        let owner = write_typed_with(PNG_MIME, &png, dir.path(), &runner, &stop, &paste)
            .await
            .unwrap();
        assert_eq!(std::fs::read(dir.path().join("payload")).unwrap(), png);
        assert_eq!(read_local_with(&paste).await, Some(owner));
        assert_eq!(
            read_typed_with(&paste, PNG_MIME).await,
            Some(typed_digest(PNG_MIME, &png))
        );
        assert!(!dir.path().join("stopped").exists());
        std::fs::write(dir.path().join("bad-readback"), b"").unwrap();
        assert!(
            write_typed_with(PNG_MIME, &png, dir.path(), &runner, &stop, &paste)
                .await
                .is_none()
        );
        let stopped = std::fs::read_to_string(dir.path().join("stopped")).unwrap();
        assert!(stopped.contains("native-clipboard-owner-") && stopped.contains("stop"));
    }
    #[tokio::test]
    async fn invalid_png_is_rejected_before_clipboard_commands() {
        let mut sync = SyncState::new();
        let outcome = sync
            .apply_typed(None, image::Kind::Png, b"invalid PNG")
            .await;
        assert_eq!(outcome["reason"], "invalid_typed_payload");
        assert!(sync.remote.is_none());
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
    fn empty_remote_ends_old_pending_interval_but_preserves_current_snapshot() {
        let mut s = SyncState::new();
        s.local_change_pending = true;
        let before = snap(b"local edit", s.local_change_pending);
        s.observe_empty();
        assert!(!s.local_change_pending);
        assert_eq!(
            s.decide(before, Some(digest(b"local edit")), digest(b"phone")),
            "newer_local_clipboard"
        );
        // A later copy may arrive after earlier empty sessions; an old local
        // edit must not suppress it indefinitely.
        assert_eq!(
            s.decide(
                snap(b"local edit", s.local_change_pending),
                Some(digest(b"local edit")),
                digest(b"later phone copy")
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
