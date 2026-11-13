//! eframe App: owns host entries, drains events, lays out the IDE regions
//! in the order given by ui-spec §2, and runs the dialogs.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use egui::{CentralPanel, Frame, Key, KeyboardShortcut, Margin, Modifiers, Panel, RichText, Ui};
use egui_phosphor::regular as ph;
use parking_lot::Mutex;
use sw_core::Section;
use sw_core::alerts::Severity;
use sw_core::config::{HostConfig, HostsFile, ServiceMode};
use sw_core::logs::sanitize;
use sw_ssh::api::{
    AuthSpec, Command, ConnState, ConnectSpec, EventKind, HostId, KnownHosts, PtyId, Throttle,
};
use sw_ssh::{Event, HostHandle, Net, Waker, spawn_demo_host_rate};
use sw_term::{Size, TermEvent, Terminal, TerminalView};

use crate::dialogs::{
    AuthOutcome, AuthPrompt, ConnectDialog, ConnectOutcome, HostKeyPrompt, SudoOutcome, SudoPrompt,
};
use crate::panels::terminal::{Banner, TermTab};
use crate::panels::{dock, status, system, terminal, topbar, watch};
use crate::state::{DockTab, HostUi, HostView};
use crate::store::{self, Store};
use crate::theme::{self, tok::*};
use crate::widgets as w;

struct HostEntry {
    handle: HostHandle,
    view: HostView,
    ui: HostUi,
    demo: bool,
    config: Option<HostConfig>,
    tabs: Vec<TermTab>,
    active_tab: usize,
    next_pty: PtyId,
    key_prompt: Option<HostKeyPrompt>,
    sudo_prompt: Option<SudoPrompt>,
    picker: crate::dialogs::ServicePicker,
    log_dialog: crate::dialogs::LogSourcesDialog,
    auth_prompt: Option<AuthPrompt>,
    last_error: Option<String>,
}

impl HostEntry {
    fn new_tab(&mut self) {
        let id = self.next_pty;
        self.next_pty += 1;
        let title = Arc::new(Mutex::new(None));
        let (tx, t2) = (self.handle.sender(), title.clone());
        // Runs on the net thread while the terminal parses output.
        let sink: sw_term::EventSink = Arc::new(move |e| match e {
            TermEvent::PtyWrite(bytes) => tx.send(Command::PtyInput { pty: id, bytes }),
            TermEvent::Title(t) => *t2.lock() = Some(sanitize(&t)),
            TermEvent::ResetTitle => *t2.lock() = None,
            TermEvent::Bell => {}
        });
        let term = Terminal::new(
            Size {
                cols: 100,
                rows: 30,
            },
            10_000,
            sink,
        );
        self.handle.send(Command::OpenPty {
            pty: id,
            term: term.clone(),
        });
        self.tabs.push(TermTab {
            id,
            term,
            view: TerminalView::new((self.handle.id, id), theme::mono(13.0)),
            title,
            exited: None,
        });
        self.active_tab = self.tabs.len() - 1;
    }

    fn close_tab(&mut self, i: usize) {
        if i < self.tabs.len() {
            let t = self.tabs.remove(i);
            self.handle.send(Command::ClosePty(t.id));
            self.active_tab = self.active_tab.min(self.tabs.len().saturating_sub(1));
        }
    }
}

pub struct SecureWireApp {
    events_tx: Sender<Event>,
    events: Receiver<Event>,
    wake: Waker,
    net: Option<Net>,
    hosts: Vec<HostEntry>,
    active: usize,
    next_host: HostId,
    layout: topbar::Layout3,
    throttle: Throttle,
    toast: Option<(String, Instant)>,
    store: Store,
    saved: HostsFile,
    connect: ConnectDialog,
    palette: sw_term::Palette,
    term_focused: bool,
    /// `SW_FRAME_STATS=<file>`: append frames-per-10s lines (perf diagnostics).
    frame_stats: Option<(std::path::PathBuf, Instant, u32)>,
    /// `--bench-ui`: demo host at 50 log lines/s, frame times → report file, then exit.
    bench: Option<Bench>,
}

impl SecureWireApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        demo: bool,
        prefill: Option<HostConfig>,
        bench: Option<std::path::PathBuf>,
    ) -> Self {
        let demo = demo || bench.is_some();
        theme::install(&cc.egui_ctx);
        let (events_tx, events) = mpsc::channel();
        let ctx = cc.egui_ctx.clone();
        let wake: Waker = Arc::new(move || ctx.request_repaint());
        let store = Store::open();
        let mut toast = None;
        let saved = store.load_hosts().unwrap_or_else(|e| {
            toast = Some((format!("hosts.toml not loaded: {e}"), Instant::now()));
            HostsFile::default()
        });
        let mut app = Self {
            events_tx,
            events,
            wake,
            net: None,
            hosts: vec![],
            active: 0,
            next_host: 1,
            layout: topbar::Layout3 {
                left: true,
                bottom: true,
                right: true,
            },
            throttle: Throttle::Normal,
            toast,
            store,
            saved,
            connect: ConnectDialog::default(),
            palette: theme::terminal_palette(),
            term_focused: false,
            frame_stats: std::env::var_os("SW_FRAME_STATS").map(|p| (p.into(), Instant::now(), 0)),
            bench: bench.map(|out| Bench {
                out,
                start: Instant::now(),
                ms: Vec::new(),
            }),
        };
        if demo {
            let id = app.alloc_id();
            let rate = app.bench.as_ref().map(|_| 50.0);
            let handle = spawn_demo_host_rate(id, app.events_tx.clone(), app.wake.clone(), rate);
            app.push_host(handle, "prod-web-01 (demo)", None, true);
        } else if let Some(h) = prefill {
            let saved = app
                .saved
                .hosts
                .iter()
                .find(|s| s.address == h.address && s.user == h.user && s.port == h.port)
                .cloned();
            app.connect.open_for(&saved.unwrap_or(h));
        } else if app.saved.hosts.is_empty() {
            app.connect.open_new();
        }
        app
    }

    fn alloc_id(&mut self) -> HostId {
        self.next_host += 1;
        self.next_host
    }

    fn push_host(
        &mut self,
        handle: HostHandle,
        name: &str,
        config: Option<HostConfig>,
        demo: bool,
    ) {
        self.hosts.push(HostEntry {
            handle,
            view: HostView::new(name),
            ui: HostUi::default(),
            demo,
            config,
            tabs: vec![],
            active_tab: 0,
            next_pty: 1,
            key_prompt: None,
            sudo_prompt: None,
            picker: Default::default(),
            log_dialog: Default::default(),
            auth_prompt: None,
            last_error: None,
        });
        self.active = self.hosts.len() - 1;
    }

    fn connect_host(&mut self, config: HostConfig, auth: AuthSpec) {
        if self.net.is_none() {
            match Net::start() {
                Ok(n) => self.net = Some(n),
                Err(e) => {
                    self.toast(format!("Could not start network thread: {e}"));
                    return;
                }
            }
        }
        self.saved.upsert(config.clone());
        if let Err(e) = self.store.save_hosts(&self.saved) {
            self.toast(format!("Could not save hosts.toml: {e}"));
        }
        if let Some(i) = self.hosts.iter().position(|h| h.view.name == config.name) {
            // Already open: just switch to it.
            self.active = i;
            return;
        }
        let spec = ConnectSpec {
            name: config.name.clone(),
            address: config.address.clone(),
            port: config.port,
            user: config.user.clone(),
            auth,
            known_hosts: KnownHosts {
                user_file: store::user_known_hosts(),
                app_file: self.store.known_hosts_path(),
            },
            connect_timeout: ConnectSpec::DEFAULT_TIMEOUT,
        };
        let id = self.alloc_id();
        let Some(net) = &self.net else { return };
        let handle = net.connect(id, spec, self.events_tx.clone(), self.wake.clone());
        let name = config.name.clone();
        self.push_host(handle, &name, Some(config), false);
        if let Some(h) = self.hosts.last_mut() {
            if let Some(c) = &h.config {
                // The actor keeps these while offline and replays them onto every collector.
                h.ui.service_mode = c.services.mode;
                h.ui.poll_secs = c.services.poll_secs;
                h.handle
                    .send(Command::SetServices(c.services.units.clone()));
                h.handle.send(Command::SetServiceMode {
                    mode: c.services.mode,
                    poll_secs: c.services.poll_secs,
                });
                h.view.set_log_cap(c.log_cap as usize);
                h.handle.send(Command::SetLogSources {
                    sources: c.logs.clone(),
                    backlog: c.log_backlog,
                });
            }
            h.new_tab();
        }
    }

    /// Apply and persist a host's log sources.
    fn update_logs(
        &mut self,
        idx: usize,
        sources: Vec<sw_core::config::LogSourceConfig>,
        backlog: u32,
        cap: u32,
    ) {
        let Some(h) = self.hosts.get_mut(idx) else {
            return;
        };
        // Source indices change with the list, so lines already held would be mislabelled.
        h.view.set_log_cap(cap as usize);
        h.ui.filter.dirty = true;
        h.handle.send(Command::SetLogSources {
            sources: sources.clone(),
            backlog,
        });
        let Some(c) = &mut h.config else { return };
        c.logs = sources;
        c.log_backlog = backlog;
        c.log_cap = cap;
        let c = c.clone();
        self.saved.upsert(c);
        if let Err(e) = self.store.save_hosts(&self.saved) {
            self.toast(format!("Could not save hosts.toml: {e}"));
        }
    }

    /// Apply and persist a host's watched services / status mode.
    fn update_services(
        &mut self,
        idx: usize,
        units: Option<Vec<String>>,
        mode: ServiceMode,
        poll_secs: u32,
    ) {
        let Some(h) = self.hosts.get_mut(idx) else {
            return;
        };
        h.ui.service_mode = mode;
        h.ui.poll_secs = poll_secs;
        if let Some(u) = &units {
            h.handle.send(Command::SetServices(u.clone()));
        }
        h.handle.send(Command::SetServiceMode { mode, poll_secs });
        if mode == ServiceMode::Manual {
            h.handle.send(Command::Now(Section::Svc));
        }
        let Some(c) = &mut h.config else { return };
        if let Some(u) = units {
            c.services.units = u;
        }
        c.services.mode = mode;
        c.services.poll_secs = poll_secs;
        let c = c.clone();
        self.saved.upsert(c);
        if let Err(e) = self.store.save_hosts(&self.saved) {
            self.toast(format!("Could not save hosts.toml: {e}"));
        }
    }

    fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    fn drain(&mut self) {
        for ev in self.events.try_iter() {
            let Some(h) = self.hosts.iter_mut().find(|h| h.handle.id == ev.host) else {
                continue;
            };
            match ev.kind {
                EventKind::HostKeyPrompt {
                    algorithm,
                    fingerprint,
                    status,
                } => {
                    let host = h
                        .config
                        .as_ref()
                        .map_or(h.view.name.clone(), |c| c.address.clone());
                    h.key_prompt = Some(HostKeyPrompt::new(host, algorithm, fingerprint, status));
                }
                EventKind::SudoPrompt {
                    message,
                    attempts_left,
                } => {
                    h.sudo_prompt =
                        Some(SudoPrompt::new(h.view.name.clone(), message, attempts_left));
                }
                EventKind::AuthFailed(msg) => {
                    let (method, key) = h
                        .config
                        .as_ref()
                        .map_or_else(Default::default, |c| (c.auth, c.key_path.clone()));
                    h.auth_prompt = Some(AuthPrompt::new(h.view.name.clone(), msg, method, key));
                }
                EventKind::Error(msg) => h.last_error = Some(msg),
                EventKind::PtyClosed { pty, exit } => {
                    if let Some(t) = h.tabs.iter_mut().find(|t| t.id == pty) {
                        t.exited = Some(exit);
                        let code = exit.map_or("?".to_owned(), |c| c.to_string());
                        t.term.advance(format!("\r\n\x1b[2m[shell exited ({code}) — press Enter to start a new one]\x1b[0m\r\n").as_bytes());
                    }
                }
                kind => {
                    if matches!(kind, EventKind::State(ConnState::Connected)) {
                        h.last_error = None;
                    }
                    // A prompt from a handshake that has since ended is stale.
                    if matches!(
                        kind,
                        EventKind::State(
                            ConnState::Connected
                                | ConnState::Disconnected
                                | ConnState::Reconnecting { .. }
                        )
                    ) {
                        h.key_prompt = None;
                    }
                    let logs_visible = self.layout.bottom && h.ui.dock_tab == DockTab::Logs;
                    h.view.apply(kind, logs_visible);
                }
            }
        }
    }

    fn shortcuts(&mut self, ui: &Ui) {
        let sc = |m: Modifiers, k: Key| KeyboardShortcut::new(m, k);
        let cs = Modifiers::COMMAND | Modifiers::SHIFT;
        let mut new_tab = false;
        let mut close_tab = false;
        let mut next_tab = false;
        ui.input_mut(|i| {
            if i.consume_shortcut(&sc(cs, Key::B)) {
                self.layout.left = !self.layout.left;
            }
            if i.consume_shortcut(&sc(cs, Key::R)) {
                self.layout.right = !self.layout.right;
            }
            if i.consume_shortcut(&sc(cs, Key::J)) {
                self.layout.bottom = !self.layout.bottom;
            }
            if i.consume_shortcut(&sc(cs, Key::P)) {
                self.toast = Some(("Command palette arrives in M5".into(), Instant::now()));
            }
            new_tab = i.consume_shortcut(&sc(cs, Key::T));
            close_tab = i.consume_shortcut(&sc(cs, Key::W));
            next_tab = i.consume_shortcut(&sc(Modifiers::COMMAND, Key::Tab));
        });
        if let Some(h) = self.hosts.get_mut(self.active).filter(|h| !h.demo) {
            if new_tab {
                h.new_tab();
            }
            if close_tab {
                h.close_tab(h.active_tab);
            }
            if next_tab && !h.tabs.is_empty() {
                h.active_tab = (h.active_tab + 1) % h.tabs.len();
                if let Some(t) = h.tabs.get_mut(h.active_tab) {
                    t.view.request_focus();
                }
            }
        }
        // F5 belongs to the terminal (htop, mc…) when it has focus.
        if !self.term_focused
            && ui.input_mut(|i| i.consume_key(Modifiers::NONE, Key::F5))
            && let Some(h) = self.hosts.get(self.active)
        {
            for (s, on) in &h.ui.sent_on {
                if *on {
                    h.handle.send(Command::Now(*s));
                }
            }
        }
    }

    /// Focus-aware throttling (protocol §5): the active host follows the window
    /// (focused / unfocused / minimized); every other host tab runs Hidden.
    fn update_throttle(&mut self, ui: &Ui) {
        let (focused, minimized) = ui.input(|i| {
            (
                i.viewport().focused.unwrap_or(true),
                i.viewport().minimized.unwrap_or(false),
            )
        });
        self.throttle = if minimized {
            Throttle::Hidden
        } else if !focused {
            Throttle::Background
        } else {
            Throttle::Normal
        };
        let active = self.active;
        for (i, h) in self.hosts.iter_mut().enumerate() {
            let t = if i == active {
                self.throttle
            } else {
                Throttle::Hidden
            };
            if h.ui.sent_throttle != Some(t) {
                let was_slower = h.ui.sent_throttle.is_some_and(|p| p != Throttle::Normal);
                h.ui.sent_throttle = Some(t);
                h.handle.send(Command::Throttle(t));
                if was_slower && t == Throttle::Normal {
                    // Fresh numbers immediately instead of at the next tick.
                    h.handle.send(Command::Now(Section::Cpu));
                    h.handle.send(Command::Now(Section::Mem));
                }
            }
        }
    }

    /// Diff visible sections against what the collector has ON (protocol §5).
    fn sync_sections(&mut self) {
        let l = &self.layout;
        for h in &mut self.hosts {
            let u = &h.ui;
            let left = |k| l.left && u.is_open(k);
            let right = |k| l.right && u.is_open(k);
            let wanted: [(Section, bool); 14] = [
                (Section::Mem, left("mem")),
                (Section::Net, left("net")),
                (Section::Df, left("disk")),
                (Section::Dio, left("disk")),
                (Section::Who, left("who")),
                (
                    Section::Svc,
                    right("services") && u.service_mode != ServiceMode::Manual,
                ),
                (Section::Ports, left("net")),
                (
                    Section::Conns,
                    l.bottom && u.dock_tab == DockTab::Connections,
                ),
                (Section::Fw, right("firewall")),
                (Section::F2b, right("security")),
                (Section::Auth, right("security")),
                (Section::Timers, right("scheduled")),
                (Section::Ps, l.bottom && u.dock_tab == DockTab::Processes),
                (Section::Cpu, true),
            ];
            let sent: &mut HashMap<Section, bool> = &mut h.ui.sent_on;
            for (s, on) in wanted {
                if sent.get(&s) != Some(&on) {
                    sent.insert(s, on);
                    h.handle.send(Command::SetSection { section: s, on });
                }
            }
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        let connected: Vec<String> = self.hosts.iter().map(|h| h.view.name.clone()).collect();
        match self.connect.show(ctx, &self.saved, &connected) {
            ConnectOutcome::Connect { config, auth } => self.connect_host(*config, auth),
            ConnectOutcome::Delete(name) => {
                self.saved.hosts.retain(|h| h.name != name);
                if let Err(e) = self.store.save_hosts(&self.saved) {
                    self.toast(format!("Could not save hosts.toml: {e}"));
                }
            }
            ConnectOutcome::None => {}
        }
        let Some(h) = self.hosts.get_mut(self.active) else {
            return;
        };
        if h.log_dialog.open {
            let (cands, name) = (h.view.log_candidates.clone(), h.view.name.clone());
            if let crate::dialogs::LogsOutcome::Apply {
                sources,
                backlog,
                cap,
            } = h.log_dialog.show(ctx, &cands, &name)
            {
                let idx = self.active;
                self.update_logs(idx, sources, backlog, cap);
            }
            return;
        }
        if h.picker.open {
            let (units, name) = (h.view.units.clone(), h.view.name.clone());
            if let crate::dialogs::PickerOutcome::Apply {
                units: u,
                mode,
                poll_secs,
            } = h.picker.show(ctx, &units, &name)
            {
                let idx = self.active;
                self.update_services(idx, Some(u), mode, poll_secs);
            }
            return;
        }
        if let Some(p) = &mut h.key_prompt {
            if let Some(d) = p.show(ctx) {
                h.handle.send(Command::HostKey(d));
                h.key_prompt = None;
            }
            return;
        }
        if let Some(p) = &mut h.sudo_prompt {
            match p.show(ctx) {
                SudoOutcome::Submit(pw) => {
                    h.handle.send(Command::SudoPassword(Some(pw)));
                    h.sudo_prompt = None;
                }
                SudoOutcome::Skip => {
                    h.handle.send(Command::SudoPassword(None));
                    h.sudo_prompt = None;
                }
                SudoOutcome::None => {}
            }
            return;
        }
        let mut close_host = false;
        if let Some(p) = &mut h.auth_prompt {
            match p.show(ctx) {
                AuthOutcome::Retry(auth) => {
                    h.handle.send(Command::Retry(Some(auth)));
                    h.auth_prompt = None;
                }
                AuthOutcome::Cancel => close_host = true,
                AuthOutcome::None => {}
            }
        }
        if close_host {
            self.close_host(self.active);
        }
    }

    fn close_host(&mut self, i: usize) {
        if i < self.hosts.len() {
            self.hosts.remove(i); // dropping the handle shuts the actor down
            self.active = self.active.min(self.hosts.len().saturating_sub(1));
        }
    }

    fn welcome(&mut self, ui: &mut Ui) {
        ui.add_space(ui.available_height() * 0.22);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new(ph::PLUGS_CONNECTED).size(40.0).color(ACC));
            ui.label(RichText::new("SecureWire").size(22.0).color(TX0));
            ui.label(w::dim(
                "Connect to a server to open a terminal and its live panels.",
            ));
            ui.add_space(12.0);
            if ui
                .add(
                    egui::Button::new(
                        RichText::new(format!("{}  Connect to a host", ph::PLUS)).color(BG0),
                    )
                    .fill(ACC),
                )
                .clicked()
            {
                self.connect.open_new();
            }
            ui.add_space(16.0);
            let mut pick = None;
            for h in &self.saved.hosts {
                if ui
                    .button(format!(
                        "{}  {}  ·  {}@{}",
                        ph::HARD_DRIVES,
                        h.name,
                        h.user,
                        h.address
                    ))
                    .clicked()
                {
                    pick = Some(h.clone());
                }
            }
            if let Some(h) = pick {
                self.connect.open_for(&h);
            }
        });
    }
}

fn pending_panel(ui: &mut Ui, title: &str, text: &str) {
    crate::panels::panel_header(ui, title, |_| {});
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.add_space(12.0);
        ui.label(w::dim(text));
    });
}

impl eframe::App for SecureWireApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let frame_start = Instant::now();
        if let Some((path, since, n)) = &mut self.frame_stats {
            *n += 1;
            if since.elapsed() >= Duration::from_secs(10) {
                use std::io::Write as _;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&*path)
                {
                    let _ = writeln!(f, "{} frames in {:.1}s", n, since.elapsed().as_secs_f32());
                }
                *since = Instant::now();
                *n = 0;
            }
        }
        self.drain();
        self.shortcuts(ui);
        self.update_throttle(ui);

        let tabs: Vec<topbar::HostTab<'_>> = self
            .hosts
            .iter()
            .map(|h| topbar::HostTab {
                name: &h.view.name,
                state: h.view.state,
                has_error: h.view.alerts.iter().any(|a| a.severity == Severity::Error),
                has_warn: !h.view.alerts.is_empty(),
                tooltip: h.view.info.as_ref().map_or(h.view.name.clone(), |i| {
                    format!("{}@{}:{}", i.user, i.address, i.port)
                }),
            })
            .collect();
        let bar = |fill| Frame::NONE.fill(fill);
        let act = Panel::top("topbar")
            .exact_size(38.0)
            .frame(bar(BG2).inner_margin(Margin {
                left: 10,
                right: 8,
                top: 0,
                bottom: 0,
            }))
            .show(ui, |ui| {
                topbar::show(ui, &tabs, self.active, &mut self.layout)
            })
            .inner;
        drop(tabs);
        if act.connect {
            self.connect.open_new();
        }
        if act.palette {
            self.toast("Command palette arrives in M5");
        }
        if let Some(i) = act.select {
            self.active = i;
        }
        if let Some(i) = act.close {
            self.close_host(i);
        }

        let throttle = self.throttle;
        let Some(h) = self.hosts.get_mut(self.active) else {
            Panel::bottom("status")
                .exact_size(24.0)
                .frame(bar(BG2))
                .show(ui, |ui| {
                    ui.horizontal_centered(|ui| {
                        ui.add_space(10.0);
                        ui.label(RichText::new("Not connected").size(11.5).color(TX2));
                    });
                });
            CentralPanel::no_frame()
                .frame(bar(BG0))
                .show(ui, |ui| self.welcome(ui));
            self.dialogs(ui.ctx());
            self.finish(ui);
            return;
        };

        let ask_sudo = Panel::bottom("status")
            .exact_size(24.0)
            .frame(bar(BG2))
            .show(ui, |ui| status::show(ui, &h.view, throttle))
            .inner;
        if ask_sudo {
            h.handle.send(Command::SudoAsk);
        }

        if self.layout.left {
            Panel::left("system")
                .resizable(true)
                .default_size(288.0)
                .size_range(200.0..=480.0)
                .frame(bar(BG1))
                .show(ui, |ui| {
                    if h.demo || h.view.probe.is_some() {
                        system::show(ui, &h.view, &mut h.ui)
                    } else {
                        pending_panel(ui, "SYSTEM", "Probing the host…")
                    }
                });
        }
        let mut watch_action = watch::Action::None;
        let mut set_live: Option<ServiceMode> = None;
        if self.layout.right {
            Panel::right("watch")
                .resizable(true)
                .default_size(312.0)
                .size_range(220.0..=520.0)
                .frame(bar(BG1))
                .show(ui, |ui| {
                    if h.demo || h.view.probe.is_some() {
                        let (mode, poll) = (h.ui.service_mode, h.ui.poll_secs);
                        watch_action = watch::show(ui, &h.view, &mut h.ui, mode, poll);
                    } else {
                        pending_panel(ui, "WATCH", "Probing the host…");
                    }
                });
            match watch_action {
                watch::Action::RefreshServices => h.handle.send(Command::Now(Section::Svc)),
                watch::Action::OpenPicker => {
                    let units = h
                        .config
                        .as_ref()
                        .map(|c| c.services.units.clone())
                        .unwrap_or_default();
                    h.picker
                        .open_with(&units, h.ui.service_mode, h.ui.poll_secs);
                    h.handle.send(Command::ListUnits);
                }
                watch::Action::SetLive(on) => {
                    set_live = Some(if on {
                        ServiceMode::Live
                    } else {
                        ServiceMode::Manual
                    });
                }
                watch::Action::None => {}
            }
        }
        if self.layout.bottom {
            let max = (ui.available_height() - 200.0).max(120.0);
            let mut hide = false;
            Panel::bottom("dock")
                .resizable(true)
                .default_size(248.0)
                .size_range(120.0..=max)
                .frame(bar(BG1))
                .show(ui, |ui| dock::show(ui, &mut h.view, &mut h.ui, &mut hide));
            if hide {
                self.layout.bottom = false;
            }
        }

        let h = &mut self.hosts[self.active];
        let user = h
            .view
            .info
            .as_ref()
            .map(|i| i.user.clone())
            .or_else(|| h.config.as_ref().map(|c| c.user.clone()))
            .unwrap_or_default();
        let fallback = format!("{user}@{}", h.view.name);
        let pal = &self.palette;
        let mut term_focused = false;
        let modal_open = self.connect.open
            || h.picker.open
            || h.log_dialog.open
            || h.key_prompt.is_some()
            || h.auth_prompt.is_some()
            || h.sudo_prompt.is_some();
        CentralPanel::no_frame().frame(bar(BG0)).show(ui, |ui| {
            if h.demo {
                terminal::demo_screen(ui, &h.view.name, &user);
                return;
            }
            let banner = Banner {
                state: h.view.state,
                error: h.last_error.as_deref(),
            };
            let out = terminal::show(
                ui,
                &mut h.tabs,
                h.active_tab,
                &fallback,
                banner,
                pal,
                !modal_open,
            );
            term_focused = out.focused;
            if let Some((pty, bytes)) = out.input {
                h.handle.send(Command::PtyInput { pty, bytes });
            }
            if let Some((pty, s)) = out.resize {
                h.handle.send(Command::PtyResize {
                    pty,
                    cols: s.cols,
                    rows: s.rows,
                });
            }
            if let Some(pty) = out.reopen
                && let Some(t) = h.tabs.iter_mut().find(|t| t.id == pty)
            {
                t.exited = None;
                h.handle.send(Command::OpenPty {
                    pty,
                    term: t.term.clone(),
                });
            }
            if out.reconnect {
                h.last_error = None;
                h.handle.send(Command::Retry(None));
            }
            if let Some(i) = out.select {
                h.active_tab = i;
                if let Some(t) = h.tabs.get_mut(i) {
                    t.view.request_focus();
                }
            }
            if let Some(i) = out.close {
                h.close_tab(i);
            }
            if out.new_tab {
                h.new_tab();
            }
        });
        self.term_focused = term_focused;
        if let Some(h) = self
            .hosts
            .get_mut(self.active)
            .filter(|h| h.ui.want_log_dialog)
        {
            h.ui.want_log_dialog = false;
            let (cur, backlog, cap) = h.config.as_ref().map_or((vec![], 200, 10_000), |c| {
                (c.logs.clone(), c.log_backlog, c.log_cap)
            });
            h.log_dialog.open_with(&cur, backlog, cap);
            h.handle.send(Command::DiscoverLogs);
        }
        if let Some(mode) = set_live {
            let (idx, poll) = (self.active, self.hosts[self.active].ui.poll_secs);
            self.update_services(idx, None, mode, poll);
        }

        self.sync_sections();
        self.dialogs(ui.ctx());
        self.finish(ui);
        self.bench_tick(ui, frame_start);
    }
}

impl SecureWireApp {
    fn finish(&mut self, ui: &Ui) {
        if let Some((msg, at)) = &self.toast {
            if at.elapsed() < Duration::from_millis(3000) {
                egui::Area::new("toast".into())
                    .order(egui::Order::Tooltip)
                    .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -36.0))
                    .show(ui.ctx(), |ui| {
                        Frame::NONE
                            .fill(BG2)
                            .stroke(egui::Stroke::new(1.0, LINE2))
                            .corner_radius(3)
                            .inner_margin(Margin::symmetric(12, 8))
                            .show(ui, |ui| ui.label(RichText::new(msg).color(TX1)));
                    });
                ui.ctx().request_repaint_after(Duration::from_millis(250));
            } else {
                self.toast = None;
            }
        }
        // Data arrival drives repaints. Only when samples stop arriving on a host that has a
        // collector do we tick once per second so stale ages keep counting.
        let fast = self.throttle.tiers().0 as f32;
        if let Some(h) = self.hosts.get(self.active)
            && h.view.age_s(Section::Cpu).is_some_and(|a| a > fast + 1.0)
        {
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }
    }
}

pub struct Bench {
    out: std::path::PathBuf,
    start: Instant,
    /// Time spent building each frame (layout + tessellation input), ms.
    ms: Vec<f32>,
}

impl SecureWireApp {
    /// Record this frame; after 3 s warm-up and 20 s of samples, write the report and close.
    fn bench_tick(&mut self, ui: &Ui, frame_start: Instant) {
        let Some(b) = &mut self.bench else { return };
        let t = b.start.elapsed();
        if t > Duration::from_secs(3) {
            b.ms.push(frame_start.elapsed().as_secs_f32() * 1000.0);
        }
        if t < Duration::from_secs(23) {
            return;
        }
        let mut v = b.ms.clone();
        v.sort_by(f32::total_cmp);
        let pct = |p: f32| {
            v.get(((v.len() as f32 - 1.0) * p).round() as usize)
                .copied()
                .unwrap_or(0.0)
        };
        let lines = self
            .hosts
            .first()
            .map_or(0, |h| h.view.logs.iter_seq().count());
        let report = format!(
            "SecureWire --bench-ui: demo host, 50 log lines/s, 20 s\nframes {}  ({:.1}/s)\nframe ms  p50 {:.2}  p95 {:.2}  p99 {:.2}  max {:.2}\nlog lines held {lines}\nbudget: < 4 ms per frame → {}\n",
            v.len(),
            v.len() as f32 / 20.0,
            pct(0.5),
            pct(0.95),
            pct(0.99),
            v.last().copied().unwrap_or(0.0),
            if pct(0.99) < 4.0 { "PASS" } else { "FAIL" }
        );
        let _ = std::fs::write(&b.out, report);
        self.bench = None;
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
    }
}
