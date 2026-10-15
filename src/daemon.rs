//! Privileged, single-owner Airdrop-compatible protocol service for the Omarchy widget and CLI.
use crate::airdrop;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};

/// How long `start_radio` waits for awdlctl to report the radio ready.
const RADIO_READY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long `discover` waits for the peer browse before giving up on it.
const BROWSE_TIMEOUT: Duration = Duration::from_secs(20);

/// Wait for the asynchronous AWDL setup before the protocol checks awdl0.
async fn start_radio(seconds: u64) -> Result<tokio::process::Child> {
    let mut child = tokio::process::Command::new("/usr/bin/awdlctl")
        .args(["discoverable", "--seconds", &seconds.to_string()])
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("start AWDL radio")?;
    let deadline = tokio::time::Instant::now() + RADIO_READY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().context("check awdlctl startup")? {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                use tokio::io::AsyncReadExt;
                let _ = pipe.read_to_string(&mut stderr).await;
            }
            let detail = stderr.trim();
            anyhow::bail!(
                "awdlctl exited while starting AWDL radio ({status}){}",
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            );
        }
        if crate::health::radio()
            .await
            .ok()
            .is_some_and(|r| r["ready"] == true && r["interface"] == "awdl0")
        {
            return Ok(child);
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("AWDL radio did not become ready within 10 seconds");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Request {
    pub op: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub directory: Option<PathBuf>,
    #[serde(default)]
    pub files: Vec<PathBuf>,
    #[serde(default)]
    pub links: Vec<String>,
    #[serde(default)]
    pub seconds: Option<u64>,
    #[serde(default)]
    pub ble_wake: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Reply {
    pub ok: bool,
    pub state: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

struct State {
    phase: String,
    task: Option<tokio::task::JoinHandle<()>>,
    pending: Option<Pending>,
}

struct Pending {
    sender: String,
    items: Vec<String>,
    decision: tokio::sync::oneshot::Sender<bool>,
}

const SOCKET: &str = "/run/ac-dc/control.sock";
const DIRECTORY: &str = "/var/lib/ac-dc/received";
// The daemon is root-owned and sandboxed; keep its TLS identity in its own
// writable state directory instead of trying to chmod a user's home tree.
const IDENTITY: &str = "/var/lib/ac-dc/airdrop";

pub async fn run(socket: PathBuf) -> Result<()> {
    if let Some(parent) = socket.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let _ = tokio::fs::remove_file(&socket).await;
    let listener =
        UnixListener::bind(&socket).with_context(|| format!("bind {}", socket.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))?;
        let raw = std::ffi::CString::new(socket.as_os_str().as_encoded_bytes())?;
        // The desktop user is granted access through the local administrators
        // group used by this installation; the daemon itself remains root.
        let rc = unsafe { libc::chown(raw.as_ptr(), 0, 998) };
        if rc != 0 {
            anyhow::bail!(
                "set daemon socket group: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    let state = Arc::new(Mutex::new(State {
        phase: "idle".into(),
        task: None,
        pending: None,
    }));
    tracing::info!(path=%socket.display(), "ac-dc daemon listening");
    loop {
        let (stream, _) = listener.accept().await?;
        tracing::debug!("accepted daemon control connection");
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, state).await {
                tracing::debug!(error=%e, "daemon client disconnected");
            }
        });
    }
}

async fn handle(stream: UnixStream, state: Arc<Mutex<State>>) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    BufReader::new(read).read_line(&mut line).await?;
    let request: Request = serde_json::from_str(line.trim()).context("invalid daemon request")?;
    tracing::debug!(
        op = %request.op,
        host = ?request.host,
        port = ?request.port,
        name = ?request.name,
        directory = ?request.directory,
        files = request.files.len(),
        links = request.links.len(),
        "daemon request"
    );
    let reply = match request.op.as_str() {
        "status" => {
            let s = state.lock().await;
            let pending = s
                .pending
                .as_ref()
                .map(|p| serde_json::json!({"sender": p.sender, "items": p.items}));
            Reply {
                ok: true,
                state: s.phase.clone(),
                message: s.phase.clone(),
                data: pending,
            }
        }
        "receive" => start_receive(state.clone(), request).await,
        "stop" => stop(state.clone()).await,
        "approve" => decide(state.clone(), true).await,
        "reject" => decide(state.clone(), false).await,
        "send" => start_send(state.clone(), request).await,
        "peers" => discover(state.clone()).await,
        _ => Reply {
            ok: false,
            state: "idle".into(),
            message: "unknown operation".into(),
            data: None,
        },
    };
    write
        .write_all(serde_json::to_string(&reply)?.as_bytes())
        .await?;
    write.write_all(b"\n").await?;
    Ok(())
}

async fn start_receive(state: Arc<Mutex<State>>, request: Request) -> Reply {
    let directory = request
        .directory
        .unwrap_or_else(|| PathBuf::from(DIRECTORY));
    let name = request.name.unwrap_or_else(|| "Omarchy".into());
    let seconds = request.seconds.unwrap_or(600);
    let ble_wake = request.ble_wake.unwrap_or(true);
    let mut s = state.lock().await;
    if !airdrop::RECEIVE_SECONDS.contains(&seconds) {
        return Reply {
            ok: false,
            state: s.phase.clone(),
            message: airdrop::receive_seconds_error(),
            data: None,
        };
    }
    if s.task.as_ref().is_some_and(|t| !t.is_finished()) {
        return Reply {
            ok: true,
            state: s.phase.clone(),
            message: "already receiving".into(),
            data: None,
        };
    }
    s.phase = "starting".into();
    let task_state = state.clone();
    s.task = Some(tokio::spawn(async move {
        let result = async {
            let mut radio = start_radio(seconds).await?;
            {
                task_state.lock().await.phase = "receiving".into();
            }
            let (approval_tx, mut approval_rx) = tokio::sync::mpsc::channel(8);
            let receive = airdrop::run(airdrop::Config {
                radio_managed: true,
                ble_wake,
                approval: Some(approval_tx),
                iface: "awdl0".into(),
                directory,
                identity: PathBuf::from(IDENTITY),
                name,
                port: 8771,
                seconds,
                once: false,
                notify: true,
                open_destination: false,
            });
            tokio::pin!(receive);
            let result = loop {
                tokio::select! {
                    result = &mut receive => break result,
                    Some(incoming) = approval_rx.recv() => {
                        let mut s = task_state.lock().await;
                        s.pending = Some(Pending { sender: incoming.sender, items: incoming.items, decision: incoming.decision });
                    }
                }
            };
            let _ = radio.kill().await;
            result
        }
        .await;
        let mut s = task_state.lock().await;
        s.phase = if result.is_ok() { "idle" } else { "error" }.into();
        s.task = None;
        if let Err(e) = result {
            tracing::error!(error=%e, "Airdrop-compatible receiver stopped");
        }
    }));
    Reply {
        ok: true,
        state: s.phase.clone(),
        message: "receive window starting".into(),
        data: None,
    }
}

async fn stop(state: Arc<Mutex<State>>) -> Reply {
    let mut s = state.lock().await;
    if let Some(task) = s.task.take() {
        task.abort();
    }
    s.phase = "idle".into();
    s.pending = None;
    Reply {
        ok: true,
        state: "idle".into(),
        message: "stopped".into(),
        data: None,
    }
}

async fn decide(state: Arc<Mutex<State>>, accepted: bool) -> Reply {
    let mut s = state.lock().await;
    let Some(pending) = s.pending.take() else {
        return Reply {
            ok: false,
            state: s.phase.clone(),
            message: "no transfer is waiting for approval".into(),
            data: None,
        };
    };
    let _ = pending.decision.send(accepted);
    Reply {
        ok: true,
        state: s.phase.clone(),
        message: if accepted {
            "transfer approved"
        } else {
            "transfer rejected"
        }
        .into(),
        data: None,
    }
}

async fn discover(state: Arc<Mutex<State>>) -> Reply {
    let mut radio = match start_radio(30).await {
        Ok(child) => child,
        Err(e) => {
            return Reply {
                ok: false,
                state: state.lock().await.phase.clone(),
                message: format!("start radio: {e:#}"),
                data: None,
            }
        }
    };
    let result = tokio::time::timeout(
        BROWSE_TIMEOUT,
        airdrop::peers::browse("awdl0", &PathBuf::from(IDENTITY), 8),
    )
    .await;
    let _ = radio.kill().await;
    match result {
        Ok(Ok(peers)) => Reply {
            ok: true,
            state: state.lock().await.phase.clone(),
            message: format!("{} recipient(s)", peers.len()),
            data: Some(serde_json::to_value(peers).unwrap_or_default()),
        },
        Ok(Err(e)) => Reply {
            ok: false,
            state: state.lock().await.phase.clone(),
            message: format!("{e:#}"),
            data: None,
        },
        Err(e) => Reply {
            ok: false,
            state: state.lock().await.phase.clone(),
            message: format!("{e:#}"),
            data: None,
        },
    }
}

async fn start_send(state: Arc<Mutex<State>>, request: Request) -> Reply {
    let host = match request.host {
        Some(v) => v,
        None => {
            return Reply {
                ok: false,
                state: "idle".into(),
                message: "send requires host".into(),
                data: None,
            }
        }
    };
    let port = request.port.unwrap_or(8770);
    let name = request.name.unwrap_or_else(|| "Linux".into());
    let files = request.files;
    let links = request.links;
    let task_state = state.clone();
    {
        let mut s = state.lock().await;
        if s.task.as_ref().is_some_and(|t| !t.is_finished()) {
            return Reply {
                ok: false,
                state: s.phase.clone(),
                message: "another operation is active".into(),
                data: None,
            };
        }
        s.phase = "sending".into();
        s.task = Some(tokio::spawn(async move {
            let result = async {
                let mut radio = start_radio(600).await?;
                let address = crate::discover::socket_target(&host, port).await?;
                let client = airdrop::send::Client::new(address, &PathBuf::from(IDENTITY))?;
                let receiver = client.discover().await?;
                client.transfer(&name, files, links).await?;
                let _ = radio.kill().await;
                Ok::<String, anyhow::Error>(receiver)
            }
            .await;
            let mut s = task_state.lock().await;
            s.phase = if result.is_ok() { "idle" } else { "error" }.into();
            s.task = None;
            if let Err(e) = result {
                tracing::error!(error=%e, "Airdrop-compatible send failed");
            }
        }));
    }
    Reply {
        ok: true,
        state: "sending".into(),
        message: "send started".into(),
        data: None,
    }
}

/// Most handlers answer from state they already hold, so a request still
/// outstanding after this long is one the daemon will never answer. The UI awaits
/// `ctl` in its single engine loop, where an indefinite wait also blocks stop,
/// approve and quit.
const CTL_TIMEOUT: Duration = Duration::from_secs(5);

/// The work `discover` does before it replies, and therefore what a `peers`
/// request has to be allowed to wait for. The readiness loop checks its deadline
/// only after awaiting a probe, so a probe starting just inside
/// `RADIO_READY_TIMEOUT` still runs for up to `health::PROBE_TIMEOUT` more.
const DISCOVER_WORST_CASE: Duration = RADIO_READY_TIMEOUT
    .saturating_add(crate::health::PROBE_TIMEOUT)
    .saturating_add(BROWSE_TIMEOUT);

/// `peers` is the exception: `discover` works before it replies, so its deadline
/// covers that work plus the slack every other operation gets.
fn ctl_timeout(op: &str) -> Duration {
    match op {
        "peers" => DISCOVER_WORST_CASE + CTL_TIMEOUT,
        _ => CTL_TIMEOUT,
    }
}

pub async fn ctl(socket: PathBuf, request: Request) -> Result<Reply> {
    tokio::time::timeout(ctl_timeout(&request.op), async move {
        tracing::debug!(socket=%socket.display(), op=%request.op, "connecting to daemon");
        let mut stream = UnixStream::connect(socket)
            .await
            .context("connect ac-dc daemon")?;
        stream
            .write_all(serde_json::to_string(&request)?.as_bytes())
            .await?;
        stream.write_all(b"\n").await?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).await?;
        tracing::debug!(response=%line.trim(), "daemon response received");
        serde_json::from_str(&line).context("parse daemon response")
    })
    .await
    .context("ac-dc daemon did not respond")?
}

pub fn default_socket() -> PathBuf {
    PathBuf::from(SOCKET)
}

pub fn request(op: impl Into<String>) -> Request {
    Request {
        op: op.into(),
        host: None,
        port: None,
        name: None,
        directory: None,
        files: Vec::new(),
        links: Vec::new(),
        seconds: None,
        ble_wake: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idle_state() -> Arc<Mutex<State>> {
        Arc::new(Mutex::new(State {
            phase: "idle".into(),
            task: None,
            pending: None,
        }))
    }

    #[tokio::test]
    async fn start_receive_rejects_a_window_outside_the_allowed_range() {
        for seconds in [0, 3601] {
            let state = idle_state();
            let mut req = request("receive");
            req.seconds = Some(seconds);

            let reply = start_receive(state.clone(), req).await;

            assert!(!reply.ok, "{seconds}s was accepted");
            assert!(
                reply.message.contains("1..3600"),
                "unexpected message: {}",
                reply.message
            );
            let s = state.lock().await;
            assert!(s.task.is_none(), "{seconds}s started a receive task");
            assert_eq!(s.phase, "idle");
        }
    }

    #[test]
    fn peers_outlasts_the_radio_and_browse_it_waits_on() {
        // The readiness loop can overrun its own deadline by one probe, so the
        // probe budget counts too; leaving it out is what made 35s too tight.
        let work = RADIO_READY_TIMEOUT + crate::health::PROBE_TIMEOUT + BROWSE_TIMEOUT;
        assert!(
            ctl_timeout("peers") > work,
            "peers deadline {:?} does not cover {:?}",
            ctl_timeout("peers"),
            work
        );
        assert_eq!(ctl_timeout("status"), CTL_TIMEOUT);
        assert_eq!(ctl_timeout("receive"), CTL_TIMEOUT);
    }

    // `start_paused` lets the runtime jump the CTL_TIMEOUT deadline as soon as
    // both sides are idle, so this costs no wall-clock time.
    #[tokio::test(start_paused = true)]
    async fn ctl_gives_up_when_the_daemon_accepts_but_never_answers() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mute = tokio::spawn(async move {
            let _connection = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });

        let error = tokio::time::timeout(CTL_TIMEOUT * 4, ctl(socket, request("status")))
            .await
            .expect("ctl ignored its own deadline")
            .unwrap_err();

        assert!(
            error.to_string().contains("did not respond"),
            "unexpected error: {error:#}"
        );
        mute.abort();
    }
}
