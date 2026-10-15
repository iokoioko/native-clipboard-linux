//! Milestone 2 output stage: take the pasteboard fetched over companion-link
//! and put it on the Linux Wayland clipboard via `wl-copy` (wl-clipboard).
//!
//! ## What is real vs. gated
//!
//! **REAL, works today** (no AWDL, no hardware): the `wl-copy` spawn and the
//! item/MIME selection logic. `ac-dc pull --loopback` fetches the mock
//! pasteboard and lands it on your actual Wayland clipboard through this module.
//!
//! The interesting decision — *which* representation of a copy to hand to the
//! clipboard and under *what* MIME type (Apple pasteboards carry several UTI
//! reps of one copy) — is pure and unit-tested below WITHOUT spawning anything.
//! The `wl-copy` spawn itself is isolated in [`run_wl_copy`] and gated on
//! `WAYLAND_DISPLAY` being set, so a headless `cargo test` never tries to reach
//! a compositor.

use anyhow::{bail, Context, Result};

// Reuse the M2 pull client's pasteboard types — do NOT duplicate them.
use crate::companion_client::Pasteboard;

/// The category of representation we picked, in preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanKind {
    /// Plain text — copied with wl-copy's default text MIME.
    Text,
    /// A recognised image UTI — copied with an explicit `--type image/...`.
    Image,
    /// Anything else — copied as `application/octet-stream`.
    Other,
}

impl PlanKind {
    /// Lower rank = higher preference. Text beats image beats everything else.
    fn rank(self) -> u8 {
        match self {
            PlanKind::Text => 0,
            PlanKind::Image => 1,
            PlanKind::Other => 2,
        }
    }
}

/// The decision of what to copy: which pasteboard item, and the `wl-copy`
/// `--type` MIME to use (`None` = let wl-copy use its default, which is text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyPlan {
    /// Index into `Pasteboard::items` of the representation we chose.
    pub index: usize,
    /// UTI of the chosen representation (for logging).
    pub uti: String,
    /// `--type` MIME for wl-copy. `None` => wl-copy default
    /// (`text/plain;charset=utf-8`), which is what we want for text items.
    pub mime: Option<String>,
    pub kind: PlanKind,
}

/// What actually happened after a copy attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyOutcome {
    pub uti: String,
    pub mime: Option<String>,
    pub bytes: usize,
    pub kind: PlanKind,
    /// True if we spawned `wl-copy`; false if skipped because there was no
    /// Wayland display (headless / no `WAYLAND_DISPLAY`).
    pub spawned: bool,
}

impl CopyOutcome {
    /// A one-line human summary for the CLI.
    pub fn describe(&self) -> String {
        let mime = self.mime.as_deref().unwrap_or("text/plain;charset=utf-8");
        let dest = if self.spawned {
            "onto the Wayland clipboard"
        } else {
            "(skipped: WAYLAND_DISPLAY unset)"
        };
        format!("{} bytes of {} as {mime} {dest}", self.bytes, self.uti)
    }
}

/// Map a UTI to its category and the MIME we'd hand `wl-copy`.
///
/// Text is deliberately `None` (wl-copy defaults to `text/plain;charset=utf-8`,
/// which is exactly right); images get an explicit `--type`; everything else
/// falls back to `application/octet-stream`.
fn classify(uti: &str) -> (PlanKind, Option<String>) {
    if is_text_uti(uti) {
        (PlanKind::Text, None)
    } else if let Some(mime) = image_mime(uti) {
        (PlanKind::Image, Some(mime.to_string()))
    } else {
        (
            PlanKind::Other,
            Some("application/octet-stream".to_string()),
        )
    }
}

/// Apple UTIs that carry UTF-8 / plain text we can drop straight onto the
/// clipboard as text.
fn is_text_uti(uti: &str) -> bool {
    matches!(
        uti,
        "public.utf8-plain-text"
            | "public.plain-text"
            | "public.text"
            | "com.apple.traditional-mac-plain-text"
    ) || uti.ends_with("plain-text")
}

/// Recognised image UTIs -> their MIME type.
fn image_mime(uti: &str) -> Option<&'static str> {
    match uti {
        "public.png" => Some("image/png"),
        "public.jpeg" => Some("image/jpeg"),
        "public.tiff" => Some("image/tiff"),
        "com.compuserve.gif" => Some("image/gif"),
        "public.heic" => Some("image/heic"),
        "public.webp" | "org.webmproject.webp" => Some("image/webp"),
        _ => None,
    }
}

/// Pure selection logic: pick the best representation to copy from a pasteboard.
///
/// Prefers a text item, then an image, then anything else; ties (same category)
/// go to the earliest representation, matching how Apple orders reps
/// best-first. Returns `None` for an empty pasteboard. This is the load-bearing
/// logic and is unit-tested without touching `wl-copy`.
pub fn plan_copy(pb: &Pasteboard) -> Option<CopyPlan> {
    let mut best: Option<CopyPlan> = None;
    for (i, item) in pb.items.iter().enumerate() {
        let (kind, mime) = classify(&item.uti);
        let better = match &best {
            None => true,
            Some(b) => kind.rank() < b.kind.rank(),
        };
        if better {
            best = Some(CopyPlan {
                index: i,
                uti: item.uti.clone(),
                mime,
                kind,
            });
        }
    }
    best
}

/// Is a Wayland compositor reachable? Gate for spawning `wl-copy` so headless
/// `cargo test` (and CI) don't fail trying to reach one.
fn wayland_available() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty())
}

/// Choose the best representation and put it on the Wayland clipboard.
///
/// Returns `Ok(None)` if the pasteboard was empty. If there's no Wayland
/// display, the selection is still reported but `wl-copy` is NOT spawned
/// (`CopyOutcome::spawned == false`).
pub fn copy_pasteboard(pb: &Pasteboard) -> Result<Option<CopyOutcome>> {
    let Some(plan) = plan_copy(pb) else {
        tracing::warn!("nothing to copy: pasteboard had no items");
        return Ok(None);
    };
    let item = &pb.items[plan.index];

    let spawned = if wayland_available() {
        run_wl_copy(plan.mime.as_deref(), &item.data).context("wl-copy failed")?;
        true
    } else {
        tracing::warn!(
            bytes = item.data.len(),
            mime = ?plan.mime,
            "WAYLAND_DISPLAY unset; not spawning wl-copy (selection still reported)"
        );
        false
    };

    Ok(Some(CopyOutcome {
        uti: plan.uti,
        mime: plan.mime,
        bytes: item.data.len(),
        kind: plan.kind,
        spawned,
    }))
}

/// Thin, side-effecting wrapper around the `wl-copy` process: spawn it (with an
/// explicit `--type` for non-text MIMEs), stream `data` to its stdin, and wait.
///
/// This is the ONE impure function; everything above it is testable without it.
/// `wl-copy` forks a background process to serve the selection and then exits,
/// so a successful `wait()` means the clipboard is now owned.
fn run_wl_copy(mime: Option<&str>, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // A wl-copy child in a short-lived systemd service dies with its cgroup.
    // Give the clipboard owner a separate unit; exec readiness ensures the
    // service opened the private stdin file before we unlink it.
    if std::env::var_os("INVOCATION_ID").is_some() {
        return service_copy(mime, data);
    }
    let mut cmd = Command::new("wl-copy");
    if let Some(m) = mime {
        cmd.arg("--type").arg(m);
    }
    // wl-copy forks a background daemon to serve the selection; if that daemon
    // inherits our stdout/stderr it holds those fds open, which hangs any caller
    // piping our output (the daemon becomes a lingering writer). Point them at
    // /dev/null so only wl-copy's stdin (the payload) matters.
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning wl-copy (is wl-clipboard installed?)")?;

    child
        .stdin
        .take()
        .context("wl-copy stdin was not captured")?
        .write_all(data)
        .context("writing pasteboard bytes to wl-copy stdin")?;

    let status = child.wait().context("waiting for wl-copy to exit")?;
    if !status.success() {
        bail!("wl-copy exited with {status}");
    }
    Ok(())
}

fn service_copy(mime: Option<&str>, data: &[u8]) -> Result<()> {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, process::Command};
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .context("XDG_RUNTIME_DIR unavailable for clipboard service")?;
    let path = std::path::PathBuf::from(runtime)
        .join(format!("ac-dc-clipboard-{:032x}", rand::random::<u128>()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    struct Remove(std::path::PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _remove = Remove(path.clone());
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    let mut cmd = Command::new("systemd-run");
    cmd.args(["--user", "--quiet", "--collect", "--service-type=exec"])
        .arg(format!("--property=StandardInput=file:{}", path.display()))
        .arg("--property=UMask=0077")
        .arg("--")
        .arg("wl-copy")
        .arg("--foreground");
    if let Some(m) = mime {
        cmd.args(["--type", m]);
    }
    let out = cmd
        .output()
        .context("starting independent clipboard owner")?;
    if !out.status.success() {
        bail!(
            "clipboard service failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::companion_client::PasteboardItem;

    fn item(uti: &str, data: &[u8]) -> PasteboardItem {
        PasteboardItem {
            uti: uti.into(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn prefers_text_over_image() {
        // Image listed first, but text must still win.
        let pb = Pasteboard {
            items: vec![
                item("public.png", &[0x89, 0x50]),
                item("public.utf8-plain-text", b"hi"),
            ],
        };
        let plan = plan_copy(&pb).unwrap();
        assert_eq!(plan.kind, PlanKind::Text);
        assert_eq!(plan.mime, None); // wl-copy default text MIME
        assert_eq!(plan.index, 1);
    }

    #[test]
    fn image_uti_maps_to_right_mime() {
        for (uti, mime) in [
            ("public.png", "image/png"),
            ("public.jpeg", "image/jpeg"),
            ("public.tiff", "image/tiff"),
            ("com.compuserve.gif", "image/gif"),
            ("public.heic", "image/heic"),
        ] {
            let pb = Pasteboard {
                items: vec![item(uti, &[0])],
            };
            let plan = plan_copy(&pb).unwrap();
            assert_eq!(plan.kind, PlanKind::Image, "{uti}");
            assert_eq!(plan.mime.as_deref(), Some(mime), "{uti}");
        }
    }

    #[test]
    fn unknown_uti_falls_back_to_octet_stream() {
        let pb = Pasteboard {
            items: vec![item("com.acme.proprietary", &[1, 2, 3])],
        };
        let plan = plan_copy(&pb).unwrap();
        assert_eq!(plan.kind, PlanKind::Other);
        assert_eq!(plan.mime.as_deref(), Some("application/octet-stream"));
    }

    #[test]
    fn empty_pasteboard_has_no_plan() {
        assert!(plan_copy(&Pasteboard::default()).is_none());
    }

    #[test]
    fn earliest_text_representation_wins_on_tie() {
        // Two text reps: the earliest (best-first, per Apple's ordering) wins.
        let pb = Pasteboard {
            items: vec![
                item("public.text", b"a"),
                item("public.utf8-plain-text", b"b"),
            ],
        };
        let plan = plan_copy(&pb).unwrap();
        assert_eq!(plan.index, 0);
        assert_eq!(plan.kind, PlanKind::Text);
    }

    #[test]
    fn outcome_describe_is_human_readable() {
        let out = CopyOutcome {
            uti: "public.png".into(),
            mime: Some("image/png".into()),
            bytes: 42,
            kind: PlanKind::Image,
            spawned: false,
        };
        let s = out.describe();
        assert!(s.contains("42 bytes"));
        assert!(s.contains("image/png"));
        assert!(s.contains("skipped"));
    }
}
