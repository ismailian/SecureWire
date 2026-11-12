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
use sw_core::config::{HostConfig, HostsFile};
use sw_core::logs::sanitize;
use sw_ssh::api::{
    AuthSpec, Command, ConnState, ConnectSpec, EventKind, HostId, KnownHosts, PtyId, Throttle,
};
use sw_ssh::{Event, HostHandle, Net, Waker, spawn_demo_host};
use sw_term::{Size, TermEvent, Terminal, TerminalView};

use crate::dialogs::{AuthOutcome, AuthPrompt, ConnectDialog, ConnectOutcome, HostKeyPrompt};
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
}

impl SecureWireApp {
    pub fn new(cc: &eframe::CreationContext<'_>, demo: bool, prefill: Option<HostConfig>) -> Self {
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
        };
        if demo {
            let id = app.alloc_id();
            let handle = spawn_demo_host(id, app.events_tx.clone(), app.wake.clone());
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
            h.new_tab();
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

    /// Focus-aware throttling (protocol §5).
    fn update_throttle(&mut self, ui: &Ui) {
        let (focused, minimized) = ui.input(|i| {
            (
                i.viewport().focused.unwrap_or(true),
                i.viewport().minimized.unwrap_or(false),
            )
        });
        let t = if minimized {
            Throttle::Hidden
        } else if !focused {
            Throttle::Background
        } else {
            Throttle::Normal
        };
        if t != self.throttle {
            let was_slower = self.throttle != Throttle::Normal;
            self.throttle = t;
            for h in &self.hosts {
                h.handle.send(Command::Throttle(t));
                if was_slower && t == Throttle::Normal {
                    h.handle.send(Command::Now(Section::Cpu));
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
            let wanted: [(Section, bool); 8] = [
                (Section::Mem, left("mem")),
                (Section::Net, left("net")),
                (Section::Df, left("disk")),
                (Section::Dio, left("disk")),
                (Section::Who, left("who")),
                (Section::Svc, l.right && u.is_open("services")),
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
        if let Some(p) = &mut h.key_prompt {
            if let Some(d) = p.show(ctx) {
                h.handle.send(Command::HostKey(d));
                h.key_prompt = None;
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

fn pending_panel(ui: &mut Ui, title: &str) {
    crate::panels::panel_header(ui, title, |_| {});
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        ui.add_space(12.0);
        ui.vertical(|ui| {
            ui.label(w::dim("Live metrics arrive with the collector (M2)."));
            ui.label(w::faint("This connection already carries the terminal; the collector will run as another channel on it."));
        });
    });
}

impl eframe::App for SecureWireApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
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

        Panel::bottom("status")
            .exact_size(24.0)
            .frame(bar(BG2))
            .show(ui, |ui| status::show(ui, &h.view, throttle));

        if self.layout.left {
            Panel::left("system")
                .resizable(true)
                .default_size(288.0)
                .size_range(200.0..=480.0)
                .frame(bar(BG1))
                .show(ui, |ui| {
                    if h.demo {
                        system::show(ui, &h.view, &mut h.ui)
                    } else {
                        pending_panel(ui, "SYSTEM")
                    }
                });
        }
        if self.layout.right {
            Panel::right("watch")
                .resizable(true)
                .default_size(312.0)
                .size_range(220.0..=520.0)
                .frame(bar(BG1))
                .show(ui, |ui| {
                    if !h.demo {
                        pending_panel(ui, "WATCH");
                    } else if let watch::Action::RefreshServices =
                        watch::show(ui, &h.view, &mut h.ui)
                    {
                        h.handle.send(Command::Now(Section::Svc));
                    }
                });
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
        let modal_open = self.connect.open || h.key_prompt.is_some() || h.auth_prompt.is_some();
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

        self.sync_sections();
        self.dialogs(ui.ctx());
        self.finish(ui);
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
        if let Some(h) = self.hosts.get(self.active).filter(|h| h.demo)
            && h.view.age_s(Section::Cpu).is_none_or(|a| a > fast + 1.0)
        {
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }
    }
}
