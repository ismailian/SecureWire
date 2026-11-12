//! eframe App: owns host entries, drains events, lays out the IDE regions
//! in the order given by ui-spec §2.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use egui::{CentralPanel, Frame, Key, KeyboardShortcut, Margin, Modifiers, Panel, Ui};
use sw_core::Section;
use sw_core::alerts::Severity;
use sw_ssh::api::{Command, Throttle};
use sw_ssh::{Event, HostHandle, spawn_demo_host};

use crate::panels::{dock, status, system, terminal, topbar, watch};
use crate::state::{DockTab, HostUi, HostView};
use crate::theme::tok::*;

struct HostEntry {
    handle: HostHandle,
    view: HostView,
    ui: HostUi,
}

pub struct SecureWireApp {
    events: Receiver<Event>,
    hosts: Vec<HostEntry>,
    active: usize,
    layout: topbar::Layout3,
    throttle: Throttle,
    toast: Option<(String, Instant)>,
}

impl SecureWireApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::theme::install(&cc.egui_ctx);
        let (tx, events) = mpsc::channel();
        let ctx = cc.egui_ctx.clone();
        let wake: sw_ssh::Waker = Arc::new(move || ctx.request_repaint());
        let handle = spawn_demo_host(0, tx, wake);
        Self {
            events,
            hosts: vec![HostEntry { handle, view: HostView::new("prod-web-01"), ui: HostUi::default() }],
            active: 0,
            layout: topbar::Layout3 { left: true, bottom: true, right: true },
            throttle: Throttle::Normal,
            toast: None,
        }
    }

    fn drain(&mut self) {
        for ev in self.events.try_iter() {
            if let Some(h) = self.hosts.iter_mut().find(|h| h.handle.id == ev.host) {
                let logs_visible = self.layout.bottom && h.ui.dock_tab == DockTab::Logs;
                h.view.apply(ev.kind, logs_visible);
            }
        }
    }

    fn shortcuts(&mut self, ui: &Ui) {
        let sc = |m: Modifiers, k: Key| KeyboardShortcut::new(m, k);
        ui.input_mut(|i| {
            if i.consume_shortcut(&sc(Modifiers::COMMAND | Modifiers::ALT, Key::B)) {
                self.layout.right = !self.layout.right;
            }
            if i.consume_shortcut(&sc(Modifiers::COMMAND, Key::B)) {
                self.layout.left = !self.layout.left;
            }
            if i.consume_shortcut(&sc(Modifiers::COMMAND, Key::J)) {
                self.layout.bottom = !self.layout.bottom;
            }
            if i.consume_shortcut(&sc(Modifiers::COMMAND, Key::K)) {
                self.toast = Some(("Command palette arrives in M5".into(), Instant::now()));
            }
        });
        if ui.input_mut(|i| i.consume_key(Modifiers::NONE, Key::F5)) {
            let h = &self.hosts[self.active];
            for (s, on) in &h.ui.sent_on {
                if *on {
                    h.handle.send(Command::Now(*s));
                }
            }
        }
    }

    /// Focus-aware throttling (protocol §5).
    fn update_throttle(&mut self, ui: &Ui) {
        let (focused, minimized) = ui.input(|i| (i.viewport().focused.unwrap_or(true), i.viewport().minimized.unwrap_or(false)));
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
                    h.handle.send(Command::Now(Section::Cpu)); // fresh numbers instantly
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
                (Section::Cpu, true), // carries the remote clock for all rate math
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
                tooltip: h.view.info.as_ref().map_or(h.view.name.clone(), |i| format!("{}@{}:{}", i.user, i.address, i.port)),
            })
            .collect();
        let mut toast = None;
        let bar = |fill| Frame::NONE.fill(fill);

        Panel::top("topbar").exact_size(38.0).frame(bar(BG2).inner_margin(Margin { left: 10, right: 8, top: 0, bottom: 0 })).show(ui, |ui| {
            topbar::show(ui, &tabs, self.active, &mut self.layout, &mut toast);
        });
        drop(tabs);

        let throttle = self.throttle;
        let h = &mut self.hosts[self.active];
        Panel::bottom("status").exact_size(24.0).frame(bar(BG2)).show(ui, |ui| status::show(ui, &h.view, throttle));

        if self.layout.left {
            Panel::left("system")
                .resizable(true)
                .default_size(288.0)
                .size_range(200.0..=480.0)
                .frame(bar(BG1))
                .show(ui, |ui| system::show(ui, &h.view, &mut h.ui));
        }
        if self.layout.right {
            Panel::right("watch")
                .resizable(true)
                .default_size(312.0)
                .size_range(220.0..=520.0)
                .frame(bar(BG1))
                .show(ui, |ui| {
                    if let watch::Action::RefreshServices = watch::show(ui, &h.view, &mut h.ui) {
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
        let user = h.view.info.as_ref().map_or("root".to_owned(), |i| i.user.clone());
        let name = h.view.name.clone();
        CentralPanel::no_frame().frame(bar(BG0)).show(ui, |ui| terminal::show(ui, &name, &user));

        self.sync_sections();

        if let Some(t) = toast {
            self.toast = Some((t, Instant::now()));
        }
        if let Some((msg, at)) = &self.toast {
            if at.elapsed() < Duration::from_millis(2200) {
                egui::Area::new("toast".into())
                    .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -36.0))
                    .show(ui.ctx(), |ui| {
                        Frame::NONE
                            .fill(BG2)
                            .stroke(egui::Stroke::new(1.0, LINE2))
                            .corner_radius(3)
                            .inner_margin(Margin::symmetric(12, 8))
                            .show(ui, |ui| ui.label(egui::RichText::new(msg).color(TX1)));
                    });
                ui.ctx().request_repaint_after(Duration::from_millis(250));
            } else {
                self.toast = None;
            }
        }

        // Data arrival drives repaints. Only when samples stop arriving do we tick
        // once per second so the stale ages in headers/status bar keep counting.
        let fast = self.throttle.tiers().0 as f32;
        if self.hosts[self.active].view.age_s(Section::Cpu).is_none_or(|a| a > fast + 1.0) {
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }
    }
}
