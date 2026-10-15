//! Native GPUI desktop controls. Protocol and radio work runs on a private Tokio runtime.
use crate::airdrop::{self, peers::Peer};
use crate::daemon;
use crate::ui_widgets as w;
use anyhow::{Context as _, Result};
use gpui::{
    actions, div, prelude::*, px, rgb, size, white, App, Bounds, Context, Entity, FocusHandle,
    Focusable, KeyBinding, MouseButton, MouseUpEvent, PathPromptOptions, TitlebarOptions, Window,
    WindowBounds, WindowOptions,
};
use gpui_platform::application;
use std::{path::PathBuf, rc::Rc, sync::mpsc, time::Duration};

actions!(ac_dc, [Quit]);

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Preferences {
    name: String,
    directory: PathBuf,
    #[serde(default = "default_ble_wake")]
    ble_wake: bool,
}
fn default_ble_wake() -> bool {
    true
}
impl Default for Preferences {
    fn default() -> Self {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        Self {
            name: "Linux".into(),
            directory: home.join("Downloads/Adhoc"),
            ble_wake: true,
        }
    }
}
enum Action {
    Start(Preferences),
    Stop,
    Browse,
    Send(Peer, Preferences, Vec<PathBuf>, Vec<String>),
    Quit,
    Cancel,
    Approve(usize),
    Decline(usize),
}
enum Event {
    Status(String),
    Radio(String),
    Peers(Vec<Peer>),
    Incoming(String, Vec<String>),
    IncomingCleared(usize),
    IncomingAllCleared,
}
fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}
fn identity() -> PathBuf {
    home().join(".local/share/ac-dc/airdrop")
}
async fn command(program: &str, args: &[&str]) -> Result<()> {
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    anyhow::ensure!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr).trim()
    );
    Ok(())
}

/// Recipient discovery is brokered by the root daemon. The full GUI must
/// not invoke pkexec merely to browse nearby devices.
async fn daemon_peers() -> Result<Vec<Peer>> {
    let output = tokio::process::Command::new("/usr/bin/ac-dc")
        .args(["ctl", "peers"])
        .kill_on_drop(true)
        .output()
        .await?;
    anyhow::ensure!(
        output.status.success(),
        "ac-dc peers failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    anyhow::ensure!(
        reply["ok"] == true,
        "{}",
        reply["message"]
            .as_str()
            .unwrap_or("recipient discovery failed")
    );
    Ok(serde_json::from_value(reply["data"].clone())?)
}
async fn radio_start() -> Result<()> {
    let requested = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    command(
        "pkexec",
        &[
            "/usr/bin/systemctl",
            "reload-or-restart",
            "ac-dc-airdrop-radio.service",
        ],
    )
    .await?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        let announced = airdrop::radio_state().is_some_and(|s| {
            s["expires_at"]
                .as_u64()
                .is_some_and(|end| end >= requested + 590)
        });
        if announced && crate::health::radio().await?["ready"] == true {
            return Ok(());
        }
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "Airdrop-compatible radio did not become ready; inspect journalctl -u ac-dc-airdrop-radio"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
async fn engine(
    mut actions: tokio::sync::mpsc::UnboundedReceiver<Action>,
    events: std::sync::mpsc::Sender<Event>,
) {
    let socket = daemon::default_socket();
    let mut radio_owned = false;
    let mut transfers: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut browsing: Option<tokio::task::JoinHandle<()>> = None;
    let mut last_pending: Option<(String, Vec<String>)> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        let action = tokio::select! {
            action=actions.recv()=>{let Some(a)=action else{break};a},
            _=tick.tick()=>{
                let text=if let Some(state)=airdrop::radio_state(){
                    let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    let remaining=state["expires_at"].as_u64().unwrap_or(now).saturating_sub(now);
                    format!("Radio: {}:{:02} remaining · received frames: {} · TX completions: {}{}",remaining/60,remaining%60,state["received_frames"],state["tx_completions"],if state["phase"]=="data_observed"{" · traffic observed"}else{" · transport unproven"})
                }else{"Radio window closed".into()};
                let _=events.send(Event::Radio(text));
                // The daemon is the receiver now; surface its pending transfer
                // as an incoming card.
                if let Ok(reply)=daemon::ctl(socket.clone(), daemon::request("status")).await {
                    let pending = reply.data.as_ref().and_then(|d| {
                        let sender = d.get("sender")?.as_str()?.to_string();
                        let items = d.get("items")?.as_array()?.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect::<Vec<_>>();
                        Some((sender, items))
                    });
                    if pending != last_pending {
                        match &pending {
                            Some((sender, items)) => {
                                let _ =
                                    events.send(Event::Incoming(sender.clone(), items.clone()));
                            }
                            None => {
                                let _ = events.send(Event::IncomingAllCleared);
                            }
                        }
                        last_pending = pending;
                    }
                }
                continue;
            }
        };
        transfers.retain(|h| !h.is_finished());
        match action {
            Action::Start(p) => {
                // Visibility is the daemon's job; it owns the radio window and
                // the receiver, so no pkexec prompt is needed.
                let _ = command("systemctl", &["--user", "stop", "ac-dc-receive.service"]).await;
                let result = daemon::ctl(
                    socket.clone(),
                    daemon::Request {
                        op: "receive".into(),
                        host: None,
                        port: None,
                        name: Some(p.name),
                        directory: Some(p.directory),
                        files: Vec::new(),
                        links: Vec::new(),
                        seconds: Some(600),
                        ble_wake: Some(p.ble_wake),
                    },
                )
                .await;
                let _ = events.send(Event::Status(match result {
                    Ok(reply) if reply.ok => {
                        if reply.message == "already receiving" {
                            "Receive window is already active".into()
                        } else {
                            "Receiving for 10 minutes. Incoming transfers require your approval. Open Airdrop-compatible on your iPhone or Mac.".into()
                        }
                    }
                    Ok(reply) => format!("Could not start receiving: {}", reply.message),
                    Err(e) => format!("Could not reach the ac-dc daemon: {e:#}"),
                }));
            }
            Action::Stop | Action::Quit => {
                let quit = matches!(action, Action::Quit);
                for h in transfers.drain(..) {
                    h.abort();
                    let _ = h.await;
                }
                if let Some(h) = browsing.take() {
                    h.abort();
                    let _ = h.await;
                }
                if radio_owned {
                    let result = command(
                        "pkexec",
                        &["/usr/bin/systemctl", "stop", "ac-dc-airdrop-radio.service"],
                    )
                    .await;
                    radio_owned = false;
                    let _ = events.send(Event::Status(match result {
                        Ok(()) => "Airdrop-compatible stopped".into(),
                        Err(e) => format!("Receiver stopped; radio cleanup: {e:#}"),
                    }));
                }
                match daemon::ctl(socket.clone(), daemon::request("stop")).await {
                    Ok(reply) => {
                        let _ = events.send(Event::Status(match reply.message.as_str() {
                            "stopped" => "Airdrop-compatible stopped".into(),
                            message => message.into(),
                        }));
                        // The daemon has dropped its pending transfer, so the next
                        // poll sees None == None and emits nothing: clear here or
                        // the card stays with live approve/reject buttons.
                        last_pending = None;
                        let _ = events.send(Event::IncomingAllCleared);
                    }
                    Err(e) => {
                        let _ = events.send(Event::Status(format!(
                            "Could not stop the ac-dc daemon: {e:#}"
                        )));
                        // Leave last_pending alone: the daemon may still hold the
                        // transfer, and resetting it would re-append the card.
                    }
                }
                if quit {
                    break;
                }
            }
            Action::Approve(id) | Action::Decline(id) => {
                let accepted = matches!(action, Action::Approve(_));
                match daemon::ctl(
                    socket.clone(),
                    daemon::request(if accepted { "approve" } else { "reject" }),
                )
                .await
                {
                    Ok(reply) => {
                        let _ = events.send(Event::Status(reply.message));
                    }
                    Err(e) => {
                        let _ = events.send(Event::Status(format!(
                            "Could not reach the ac-dc daemon: {e:#}"
                        )));
                    }
                }
                // If the pending transfer changed while deciding, drop the
                // stale card so the next status poll repaints the current one.
                last_pending = None;
                let _ = events.send(Event::IncomingCleared(id));
            }
            Action::Browse => {
                let _=events.send(Event::Status("Looking for nearby recipients. Set the Apple device to Everyone for 10 Minutes.".into()));
                if browsing.as_ref().is_some_and(|h| !h.is_finished()) {
                    continue;
                }
                let ev = events.clone();
                browsing = Some(tokio::spawn(async move {
                    match daemon_peers().await {
                        Ok(peers) => {
                            let _ = ev
                                .send(Event::Status(format!("Found {} recipient(s)", peers.len())));
                            let _ = ev.send(Event::Peers(peers));
                        }
                        Err(e) => {
                            let _ = ev.send(Event::Status(format!("Discovery: {e:#}")));
                        }
                    }
                }));
            }
            Action::Cancel => {
                for h in transfers.drain(..) {
                    h.abort();
                    let _ = h.await;
                }
                let _ = events.send(Event::Status("Outgoing transfer cancelled".into()));
            }
            Action::Send(peer, p, files, links) => {
                if !transfers.is_empty() {
                    let _ = events.send(Event::Status(
                        "A transfer is already running; cancel it before sending again".into(),
                    ));
                    continue;
                }
                if let Err(e) = radio_start().await {
                    let _ = events.send(Event::Status(format!("Radio: {e:#}")));
                    continue;
                }
                radio_owned = true;
                let ev = events.clone();
                transfers.push(tokio::spawn(async move {
                    let _ = ev.send(Event::Status(format!(
                        "Preparing transfer for {}…",
                        peer.name
                    )));
                    let result = async {
                        let client = airdrop::send::Client::new(peer.address, &identity())?;
                        let(tx,mut progress)=tokio::sync::watch::channel((0u64,0u64));
                        let transfer=client.transfer_with_progress(&p.name, files, links,Some(tx));
                        let wake=crate::advertise::broadcast(crate::advertise::airdrop_wake(),600,100);
                        tokio::pin!(transfer);tokio::pin!(wake);
                        let mut wake_done=false;
                        let mut interval=tokio::time::interval(Duration::from_millis(250));
                        loop {tokio::select! {
                            result=&mut transfer=>break result,
                            result=&mut wake,if !wake_done=>{wake_done=true;if let Err(error)=result{tracing::warn!(%error,"Bluetooth wake failed");}},
                            _=interval.tick()=>{let(sent,total)=*progress.borrow_and_update();if total>0{let _=ev.send(Event::Status(if sent==0 {format!("Waiting for {} to accept…",peer.name)}else if sent==total {format!("Upload sent to {}; waiting for confirmation…",peer.name)}else{format!("Sending to {}: {:.1} / {:.1} MiB ({}%)",peer.name,sent as f64/1048576.0,total as f64/1048576.0,sent*100/total)}));}}
                        }}
                    }
                    .await;
                    let _ = ev.send(Event::Status(match result {
                        Ok(()) => format!("Transfer delivered to {}", peer.name),
                        Err(e) => format!("Transfer failed: {e:#}"),
                    }));
                }));
            }
        }
    }
    for h in transfers {
        h.abort();
    }
    if let Some(h) = browsing {
        h.abort();
    }
}

struct IncomingCard {
    id: usize,
    label: String,
}

struct AcDcApp {
    name: Entity<w::TextField>,
    directory: Entity<w::TextField>,
    link: Entity<w::TextField>,
    ble_wake_checked: bool,
    peers: Vec<Peer>,
    peers_display: Vec<String>,
    peer_selected: usize,
    peer_drop_open: bool,
    files: Vec<PathBuf>,
    file_label: String,
    status: String,
    radio_text: String,
    incoming: Vec<IncomingCard>,
    incoming_counter: usize,
    actions_tx: tokio::sync::mpsc::UnboundedSender<Action>,
    prefs_path: PathBuf,
    focus_handle: FocusHandle,
}

impl AcDcApp {
    fn new(
        actions_tx: tokio::sync::mpsc::UnboundedSender<Action>,
        events_rx: mpsc::Receiver<Event>,
        prefs_path: PathBuf,
        prefs: &Preferences,
        cx: &mut Context<Self>,
    ) -> Self {
        let name = cx.new(|cx| w::TextField::new(&prefs.name, "Your device name", cx));
        let directory = cx
            .new(|cx| w::TextField::new(&prefs.directory.to_string_lossy(), "Receive folder", cx));
        let link = cx.new(|cx| w::TextField::new("", "Or paste an https:// link", cx));
        let view = Self {
            name,
            directory,
            link,
            ble_wake_checked: prefs.ble_wake,
            peers: Vec::new(),
            peers_display: Vec::new(),
            peer_selected: 0,
            peer_drop_open: false,
            files: Vec::new(),
            file_label: "No files selected".into(),
            status: "Ready. Everyone mode only; Apple-device compatibility is being tested.".into(),
            radio_text: "Radio window closed".into(),
            incoming: Vec::new(),
            incoming_counter: 0,
            actions_tx,
            prefs_path,
            focus_handle: cx.focus_handle(),
        };

        // Event pump: forwards engine events into the view and requests a redraw. Polling
        // is cheap (a non-blocking channel read) so a steady cadence only matters while idle.
        cx.spawn(async move |weak, cx| {
            let rx = events_rx;
            loop {
                let mut changed = false;
                while let Ok(event) = rx.try_recv() {
                    changed = true;
                    cx.update(|cx| {
                        if let Some(entity) = weak.upgrade() {
                            entity.update(cx, |this, cx| {
                                match event {
                                    Event::Status(text) => this.status = text,
                                    Event::Radio(text) => this.radio_text = text,
                                    Event::Peers(list) => {
                                        this.peers = list;
                                        this.peers_display = this
                                            .peers
                                            .iter()
                                            .map(|p| format!("{} — {}", p.name, p.address))
                                            .collect();
                                        this.peer_selected = 0;
                                        this.peer_drop_open = false;
                                    }
                                    Event::Incoming(sender, items) => {
                                        this.incoming_counter += 1;
                                        this.incoming.push(IncomingCard {
                                            id: this.incoming_counter,
                                            label: format!(
                                                "{sender} wants to share:\n{}",
                                                items.join("\n")
                                            ),
                                        });
                                    }
                                    Event::IncomingCleared(id) => {
                                        this.incoming.retain(|card| card.id != id);
                                    }
                                    Event::IncomingAllCleared => this.incoming.clear(),
                                }
                                cx.notify();
                            });
                        }
                    });
                }
                if !changed {
                    cx.background_executor()
                        .timer(Duration::from_millis(100))
                        .await;
                }
            }
        })
        .detach();

        view
    }

    fn read_prefs(&self, cx: &App) -> Result<Preferences> {
        let p = Preferences {
            name: self.name.read(cx).text.to_string(),
            directory: PathBuf::from(self.directory.read(cx).text.to_string()),
            ble_wake: self.ble_wake_checked,
        };
        anyhow::ensure!(
            !p.name.is_empty() && p.name.len() <= 63,
            "Use a device name between 1 and 63 bytes"
        );
        anyhow::ensure!(
            p.directory.is_absolute(),
            "Use an absolute receive folder path"
        );
        Ok(p)
    }

    fn save_prefs(&self, cx: &App) -> Result<()> {
        let prefs = self.read_prefs(cx)?;
        let dir = self.prefs_path.parent().context("preferences directory")?;
        std::fs::create_dir_all(dir)?;
        std::fs::write(&self.prefs_path, serde_json::to_vec_pretty(&prefs)?)?;
        Ok(())
    }

    fn on_receive(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        match self.read_prefs(cx) {
            Ok(prefs) => {
                let _ = self.save_prefs(cx);
                let _ = self.actions_tx.send(Action::Start(prefs));
            }
            Err(e) => {
                self.status = e.to_string();
                cx.notify();
            }
        }
    }

    fn on_stop(&mut self, _: &MouseUpEvent, _: &mut Window, _: &mut Context<Self>) {
        let _ = self.actions_tx.send(Action::Stop);
    }

    fn on_find(&mut self, _: &MouseUpEvent, _: &mut Window, _: &mut Context<Self>) {
        let _ = self.actions_tx.send(Action::Browse);
    }

    fn on_choose_files(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: Some("Choose files to send".into()),
        });
        cx.spawn(async move |weak, cx| {
            if let Ok(Ok(Some(paths))) = rx.await {
                cx.update(|cx| {
                    if let Some(view) = weak.upgrade() {
                        view.update(cx, |this, cx| {
                            let count = paths.len();
                            this.files = paths;
                            this.file_label = format!("{count} file(s) selected");
                            cx.notify();
                        });
                    }
                });
            }
        })
        .detach();
    }

    fn on_choose_folder(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("Choose folder to send".into()),
        });
        cx.spawn(async move |weak, cx| {
            if let Ok(Ok(Some(paths))) = rx.await {
                cx.update(|cx| {
                    if let Some(view) = weak.upgrade() {
                        view.update(cx, |this, cx| {
                            if let Some(path) = paths.into_iter().next() {
                                this.file_label = format!("Folder: {}", path.display());
                                this.files = vec![path];
                            }
                            cx.notify();
                        });
                    }
                });
            }
        })
        .detach();
    }

    fn on_send(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        let peer = self.peers.get(self.peer_selected).cloned();
        let Some(peer) = peer else {
            self.status = "Choose a recipient first".into();
            cx.notify();
            return;
        };
        let link_text = self.link.read(cx).text.clone();
        let links = if link_text.trim().is_empty() {
            vec![]
        } else {
            vec![link_text.trim().into()]
        };
        let files = if links.is_empty() {
            self.files.clone()
        } else {
            vec![]
        };
        let prefs = match self.read_prefs(cx) {
            Ok(p) => p,
            Err(e) => {
                self.status = e.to_string();
                cx.notify();
                return;
            }
        };
        let _ = self
            .actions_tx
            .send(Action::Send(peer, prefs, files, links));
    }

    fn on_cancel(&mut self, _: &MouseUpEvent, _: &mut Window, _: &mut Context<Self>) {
        let _ = self.actions_tx.send(Action::Cancel);
    }

    fn on_toggle_ble(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.ble_wake_checked = !self.ble_wake_checked;
        cx.notify();
    }
}

impl Focusable for AcDcApp {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl Render for AcDcApp {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let weak = cx.entity().downgrade();

        let on_toggle_peer = {
            let weak = weak.clone();
            Rc::new(move |cx: &mut App| {
                if let Some(view) = weak.upgrade() {
                    view.update(cx, |this, cx| {
                        this.peer_drop_open = !this.peer_drop_open;
                        cx.notify();
                    });
                }
            })
        };
        let on_select_peer = {
            let weak = weak.clone();
            Rc::new(move |idx: usize, cx: &mut App| {
                if let Some(view) = weak.upgrade() {
                    view.update(cx, |this, cx| {
                        this.peer_selected = idx;
                        this.peer_drop_open = false;
                        cx.notify();
                    });
                }
            })
        };
        let on_accept = {
            let weak = weak.clone();
            let actions = self.actions_tx.clone();
            Rc::new(move |id: usize, cx: &mut App| {
                if let Some(view) = weak.upgrade() {
                    view.update(cx, |this, cx| {
                        let _ = actions.send(Action::Approve(id));
                        this.incoming.retain(|card| card.id != id);
                        cx.notify();
                    });
                }
            })
        };
        let on_decline = {
            let weak = weak.clone();
            let actions = self.actions_tx.clone();
            Rc::new(move |id: usize, cx: &mut App| {
                if let Some(view) = weak.upgrade() {
                    view.update(cx, |this, cx| {
                        let _ = actions.send(Action::Decline(id));
                        this.incoming.retain(|card| card.id != id);
                        cx.notify();
                    });
                }
            })
        };

        let file_label = self.file_label.clone();
        let radio_text = self.radio_text.clone();
        let status = self.status.clone();
        let peer_display = self.peers_display.clone();
        let peer_selected = self.peer_selected;
        let peer_drop_open = self.peer_drop_open;
        let ble_checked = self.ble_wake_checked;
        let cards: Vec<_> = self
            .incoming
            .iter()
            .map(|card| {
                let id = card.id;
                let label = card.label.clone();
                let on_accept = on_accept.clone();
                let on_decline = on_decline.clone();
                div()
                    .p_3()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(0xBBBBBB))
                    .bg(rgb(0xFFF8E1))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(div().text_sm().child(label))
                    .child(
                        div()
                            .flex()
                            .gap_2()
                            .child(
                                div()
                                    .px_3()
                                    .py_1()
                                    .rounded_md()
                                    .bg(rgb(0x007AFF))
                                    .text_color(white())
                                    .text_sm()
                                    .cursor_pointer()
                                    .on_mouse_down(MouseButton::Left, move |_, _, cx| {
                                        on_accept(id, cx)
                                    })
                                    .child("Accept"),
                            )
                            .child(
                                div()
                                    .px_3()
                                    .py_1()
                                    .rounded_md()
                                    .bg(rgb(0xCCCCCC))
                                    .text_color(rgb(0x333333))
                                    .text_sm()
                                    .cursor_pointer()
                                    .on_mouse_down(MouseButton::Left, move |_, _, cx| {
                                        on_decline(id, cx)
                                    })
                                    .child("Decline"),
                            ),
                    )
            })
            .collect();

        div().flex().flex_col().w_full().h_full().child(
            div()
                .id("ac-dc-scroll")
                .flex()
                .flex_col()
                .w_full()
                .h_full()
                .overflow_y_scroll()
                .p_6()
                .gap_4()
                .child(div().text_xl().child("Airdrop-compatible"))
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(0x666666))
                        .child("Share files and links with nearby Apple devices"),
                )
                .child(self.name.clone())
                .child(self.directory.clone())
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .on_mouse_up(MouseButton::Left, cx.listener(Self::on_toggle_ble))
                        .child(
                            div()
                                .w(px(20.))
                                .h(px(20.))
                                .rounded_md()
                                .border_1()
                                .border_color(rgb(0x666666))
                                .when(ble_checked, |d| {
                                    d.bg(rgb(0x007AFF))
                                        .child(div().text_size(px(12.)).child("✓"))
                                }),
                        )
                        .child(
                            div()
                                .text_sm()
                                .child("Use Bluetooth to help nearby devices find me"),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(
                            div()
                                .h(px(34.))
                                .px_4()
                                .rounded_md()
                                .bg(rgb(0x007AFF))
                                .text_color(white())
                                .flex()
                                .items_center()
                                .justify_center()
                                .cursor_pointer()
                                .on_mouse_up(MouseButton::Left, cx.listener(Self::on_receive))
                                .child("Receive for 10 minutes"),
                        )
                        .child(
                            div()
                                .h(px(34.))
                                .px_4()
                                .rounded_md()
                                .bg(rgb(0xCCCCCC))
                                .text_color(rgb(0x333333))
                                .flex()
                                .items_center()
                                .justify_center()
                                .cursor_pointer()
                                .on_mouse_up(MouseButton::Left, cx.listener(Self::on_stop))
                                .child("Stop receiving"),
                        ),
                )
                .child(div().h(px(1.)).w_full().bg(rgb(0xDDDDDD)))
                .child(
                    div()
                        .flex()
                        .gap_2()
                        .child(w::dropdown(
                            &peer_display,
                            peer_selected,
                            peer_drop_open,
                            on_toggle_peer,
                            on_select_peer,
                        ))
                        .child(
                            div()
                                .h(px(34.))
                                .px_4()
                                .rounded_md()
                                .bg(rgb(0xCCCCCC))
                                .text_color(rgb(0x333333))
                                .flex()
                                .items_center()
                                .justify_center()
                                .cursor_pointer()
                                .on_mouse_up(MouseButton::Left, cx.listener(Self::on_find))
                                .child("Find recipients"),
                        ),
                )
                .child(
                    div()
                        .h(px(34.))
                        .px_4()
                        .rounded_md()
                        .bg(rgb(0xCCCCCC))
                        .text_color(rgb(0x333333))
                        .flex()
                        .items_center()
                        .cursor_pointer()
                        .on_mouse_up(MouseButton::Left, cx.listener(Self::on_choose_files))
                        .child("Choose files…"),
                )
                .child(
                    div()
                        .h(px(34.))
                        .px_4()
                        .rounded_md()
                        .bg(rgb(0xCCCCCC))
                        .text_color(rgb(0x333333))
                        .flex()
                        .items_center()
                        .cursor_pointer()
                        .on_mouse_up(MouseButton::Left, cx.listener(Self::on_choose_folder))
                        .child("Choose folder…"),
                )
                .child(div().text_sm().text_color(rgb(0x444444)).child(file_label))
                .child(self.link.clone())
                .child(
                    div()
                        .h(px(34.))
                        .px_4()
                        .rounded_md()
                        .bg(rgb(0x007AFF))
                        .text_color(white())
                        .flex()
                        .items_center()
                        .justify_center()
                        .cursor_pointer()
                        .on_mouse_up(MouseButton::Left, cx.listener(Self::on_send))
                        .child("Send to selected recipient"),
                )
                .child(
                    div()
                        .h(px(34.))
                        .px_4()
                        .rounded_md()
                        .bg(rgb(0xCCCCCC))
                        .text_color(rgb(0x333333))
                        .flex()
                        .items_center()
                        .justify_center()
                        .cursor_pointer()
                        .on_mouse_up(MouseButton::Left, cx.listener(Self::on_cancel))
                        .child("Cancel outgoing transfer"),
                )
                .child(div().text_sm().child(radio_text))
                .child(div().text_sm().child(status))
                .children(cards),
        )
    }
}

pub fn run() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let prefs_path = home().join(".config/ac-dc/ui.json");
    let prefs: Preferences = std::fs::read(&prefs_path)
        .ok()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or_default();
    let (actions_tx, actions_rx) = tokio::sync::mpsc::unbounded_channel();
    let (events_tx, events_rx) = mpsc::channel();
    let worker = runtime.spawn(engine(actions_rx, events_tx));

    let shutdown = actions_tx.clone();
    let final_shutdown = shutdown.clone();
    application().run(move |cx: &mut App| {
        w::bind_text_input_keys(cx);
        cx.bind_keys([
            KeyBinding::new("escape", Quit, None),
            KeyBinding::new("secondary-q", Quit, None),
        ]);

        let close_actions = shutdown.clone();
        cx.on_window_closed(move |cx, _window_id| {
            let _ = close_actions.send(Action::Quit);
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();

        let quit_actions = shutdown.clone();
        cx.on_action(move |_: &Quit, cx| {
            let _ = quit_actions.send(Action::Quit);
            cx.quit();
        });

        let bounds = Bounds::centered(None, size(px(640.), px(720.)), cx);
        cx.open_window(
            WindowOptions {
                titlebar: Some(TitlebarOptions {
                    title: Some(
                        format!("ac-dc {} · Airdrop-compatible", env!("CARGO_PKG_VERSION")).into(),
                    ),
                    appears_transparent: false,
                    traffic_light_position: None,
                }),
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            move |window, cx| {
                let actions = shutdown.clone();
                let view = cx.new(|cx| AcDcApp::new(actions, events_rx, prefs_path, &prefs, cx));
                window.focus(&view.focus_handle(cx), cx);
                cx.activate(true);
                view
            },
        )
        .unwrap();
    });

    // The window has closed. Tell the engine to tear down and join it so radio
    // cleanup and pkexec stops complete before the runtime is dropped.
    let _ = final_shutdown.send(Action::Quit);
    runtime.block_on(worker)?;
    Ok(())
}
