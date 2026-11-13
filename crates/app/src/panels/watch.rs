//! Right panel — WATCH (ui-spec §3.5): services, firewall, security, scheduled.

use egui::{Align, Layout, RichText, ScrollArea, Sense, Ui, vec2};
use egui_phosphor::regular as ph;
use sw_core::Section;
use sw_core::config::ServiceMode;
use sw_core::format;
use sw_core::metrics::RingBuffer;
use sw_core::model::{ActiveState, ServiceInfo};

use crate::state::{HostUi, HostView};
use crate::theme::tok::*;
use crate::widgets::{self as w, right, section};

pub enum Action {
    None,
    RefreshServices,
    OpenPicker,
    SetLive(bool),
}

pub fn show(
    ui: &mut Ui,
    v: &HostView,
    hu: &mut HostUi,
    mode: ServiceMode,
    poll_secs: u32,
) -> Action {
    let mut action = Action::None;
    super::panel_header(ui, "WATCH", |ui| {
        if w::icon_button(ui, ph::ARROWS_CLOCKWISE, "Refresh services now (F5)", false).clicked() {
            action = Action::RefreshServices;
        }
    });
    ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        services(ui, v, hu, mode, poll_secs, &mut action);
        firewall(ui, v, hu);
        security(ui, v, hu);
        scheduled(ui, v, hu);
    });
    action
}

fn open(hu: &mut HostUi, key: &'static str) -> bool {
    hu.is_open(key)
}

fn needs(ui: &mut Ui, v: &HostView, s: Section) -> bool {
    match v.section_errors.get(&s).map(String::as_str) {
        Some("needs-sudo") => {
            ui.label(w::faint(
                "Needs sudo — click \"no sudo\" in the status bar to enter the password.",
            ));
            true
        }
        Some("unavailable") => {
            ui.label(w::faint(
                "Not available: the tool is missing or sudo refused.",
            ));
            true
        }
        Some("missing") => {
            ui.label(w::faint("Not installed on this host."));
            true
        }
        _ => false,
    }
}

fn services(
    ui: &mut Ui,
    v: &HostView,
    hu: &mut HostUi,
    mode: ServiceMode,
    poll_secs: u32,
    action: &mut Action,
) {
    let mut is_open = open(hu, "services");
    let mut live = mode == ServiceMode::Live;
    let was_live = live;
    let failed = v
        .services
        .iter()
        .filter(|s| s.active == ActiveState::Failed)
        .count();
    // Both closures below can request these; resolved after `section` returns.
    let (pick, refresh) = (std::cell::Cell::new(false), std::cell::Cell::new(false));
    section(
        ui,
        &mut is_open,
        ph::GEAR_FINE,
        "Services",
        |ui| {
            if w::icon_button(ui, ph::PLUS, "Choose services…", false).clicked() {
                pick.set(true);
            }
            w::switch(ui, &mut live, if was_live { "Live" } else { "Off" })
                .on_hover_text("Live: systemd pushes state changes over the same connection");
            if failed > 0 {
                w::badge(ui, &format!("{failed} failed"), ERR, ERR_DIM);
            }
        },
        |ui| {
            if v.services.is_empty() {
                ui.horizontal(|ui| {
                    ui.label(w::faint("No services watched ·"));
                    if ui
                        .link(RichText::new("choose services").size(11.0))
                        .clicked()
                    {
                        pick.set(true);
                    }
                });
            }
            for s in &v.services {
                service_row(ui, s);
            }
            ui.add_space(6.0);
            if v.services.is_empty() {
                return; // nothing watched → no mode footer
            }
            ui.horizontal(|ui| match mode {
                ServiceMode::Live if v.live_watching => {
                    w::dot(ui, OK);
                    ui.label(w::faint(
                        "Live · state changes pushed by systemd · resources every 10s",
                    ));
                }
                ServiceMode::Live => {
                    w::dot(ui, WARN);
                    ui.label(w::faint(
                        "Live · polling every 5s (journal not readable without sudo)",
                    ));
                }
                ServiceMode::Poll => {
                    ui.label(RichText::new(ph::CLOCK_COUNTDOWN).color(TX3));
                    ui.label(w::faint(format!("Polling every {poll_secs}s")));
                }
                ServiceMode::Manual => {
                    ui.label(RichText::new(ph::CLOCK_COUNTDOWN).color(TX3));
                    let age = v
                        .age_s(Section::Svc)
                        .map_or("never".into(), |a| format!("{a:.0}s ago"));
                    ui.label(w::faint(format!("Checked {age}")));
                    if ui.link(RichText::new("refresh").size(11.0)).clicked() {
                        refresh.set(true);
                    }
                }
            });
        },
    );
    hu.open.insert("services", is_open);
    if live != was_live {
        *action = Action::SetLive(live);
    } else if pick.get() {
        *action = Action::OpenPicker;
    } else if refresh.get() {
        *action = Action::RefreshServices;
    }
}

fn service_row(ui: &mut Ui, s: &ServiceInfo) {
    let failed = s.active == ActiveState::Failed;
    let (color, state) = match s.active {
        ActiveState::Active | ActiveState::Reloading if s.sub == "running" => {
            (OK, "running".to_owned())
        }
        ActiveState::Active => (TX3, s.sub.clone()),
        ActiveState::Failed => (ERR, format!("failed · {}", s.result)),
        ActiveState::Activating | ActiveState::Deactivating => (WARN, s.sub.clone()),
        _ => (TX3, s.sub.clone()),
    };
    let age = s.state_age_s.map(format::duration).unwrap_or_default();
    let sub = match (failed, age.is_empty()) {
        (_, true) => state,
        (true, false) => format!("{state} · {age} ago"),
        (false, false) => format!("{state} · {age}"),
    };
    let width = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(vec2(width, 38.0), Sense::hover());
    let bg = match (failed, resp.hovered()) {
        (true, _) => Some(ERR_DIM),
        (false, true) => Some(BG2),
        _ => None,
    };
    if let Some(bg) = bg {
        ui.painter()
            .rect_filled(rect.expand2(vec2(6.0, 0.0)), 3, bg);
    }
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(rect)
            .layout(Layout::left_to_right(Align::Center)),
    );
    w::dot(&mut child, color);
    child.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        ui.add_space(3.0);
        ui.label(w::mono(s.short_name(), TX0));
        ui.label(
            RichText::new(sub)
                .size(11.0)
                .color(if failed { ERR } else { TX2 }),
        );
    });
    child.with_layout(Layout::right_to_left(Align::Center), |ui| {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.add_space(3.0);
            ui.with_layout(Layout::top_down(Align::Max), |ui| {
                ui.label(w::meta(s.memory.map(format::bytes).unwrap_or_default()));
                let pid = if s.main_pid > 0 {
                    format!("pid {}", s.main_pid)
                } else if s.id.ends_with(".timer") {
                    "timer".into()
                } else {
                    String::new()
                };
                ui.label(w::meta(pid));
            });
        });
    });
}

fn policy_color(p: &str) -> egui::Color32 {
    match p {
        "deny" | "drop" | "reject" => ERR,
        "allow" | "accept" => OK,
        _ => TX2,
    }
}

fn firewall(ui: &mut Ui, v: &HostView, hu: &mut HostUi) {
    let mut is_open = open(hu, "firewall");
    section(
        ui,
        &mut is_open,
        ph::WALL,
        "Firewall",
        |ui| match (&v.firewall, v.section_errors.get(&Section::Fw)) {
            (Some(f), _) if f.active => {
                w::badge(ui, &format!("{} active", f.backend), OK, OK_DIM);
            }
            (Some(f), _) => {
                w::badge(ui, &format!("{} inactive", f.backend), WARN, WARN_DIM);
            }
            (None, Some(c)) if c == "needs-sudo" => {
                w::badge(ui, "needs sudo", WARN, WARN_DIM);
            }
            _ => {
                ui.label(w::meta("—"));
            }
        },
        |ui| {
            if needs(ui, v, Section::Fw) && v.firewall.is_none() {
                return;
            }
            let Some(f) = &v.firewall else {
                ui.label(w::faint("Waiting for the first read…"));
                return;
            };
            ui.spacing_mut().item_spacing.y = 3.0;
            for (k, val) in [
                ("Incoming", &f.incoming),
                ("Outgoing", &f.outgoing),
                ("Routed", &f.routed),
            ] {
                if val.is_empty() {
                    continue;
                }
                ui.horizontal(|ui| {
                    ui.label(w::dim(k));
                    right(ui, |ui| {
                        ui.label(RichText::new(val.as_str()).color(policy_color(val)))
                    });
                });
            }
            ui.add_space(4.0);
            if f.rules.is_empty() {
                ui.label(w::faint("No rules."));
            } else {
                egui::Grid::new("fw-rules")
                    .num_columns(3)
                    .spacing(vec2(10.0, 2.0))
                    .show(ui, |ui| {
                        for h in ["To", "Action", "From"] {
                            ui.label(w::faint(h));
                        }
                        ui.end_row();
                        for r in f.rules.iter().take(40) {
                            ui.label(w::mono(&r.to, TX1));
                            let c = if r.action.to_ascii_uppercase().contains("ALLOW")
                                || r.action == "ACCEPT"
                                || r.action == "accept"
                            {
                                OK
                            } else {
                                ERR
                            };
                            ui.label(w::mono(&r.action, c));
                            ui.label(w::mono(&r.from, TX2));
                            ui.end_row();
                        }
                    });
                if f.rules.len() > 40 {
                    ui.label(w::faint(format!("… {} more rules", f.rules.len() - 40)));
                }
            }
            ui.add_space(4.0);
            let age = v
                .age_s(Section::Fw)
                .map_or(String::new(), |a| format!(" · read {a:.0}s ago"));
            ui.label(w::faint(format!("Read via sudo · every 60s{age}")));
        },
    );
    hu.open.insert("firewall", is_open);
}

fn security(ui: &mut Ui, v: &HostView, hu: &mut HostUi) {
    let mut is_open = open(hu, "security");
    let banned: u32 = v.jails.iter().map(|j| j.currently_banned).sum();
    section(
        ui,
        &mut is_open,
        ph::SHIELD_WARNING,
        "Security",
        |ui| {
            if !v.jails.is_empty() {
                w::badge(ui, &format!("{banned} banned"), TX1, BG4);
            }
        },
        |ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            if v.jails.is_empty() && !needs(ui, v, Section::F2b) {
                ui.label(w::faint("fail2ban: no jails reported yet."));
            }
            for j in &v.jails {
                ui.horizontal(|ui| {
                    ui.label(w::mono(&j.name, TX0));
                    ui.label(w::dim("jail"));
                    right(ui, |ui| {
                        ui.label(
                            RichText::new(format!("{} banned", j.currently_banned)).color(TX1),
                        );
                        if j.currently_failed > 0 {
                            ui.label(w::faint(format!("{} failing ·", j.currently_failed)));
                        }
                    });
                });
            }
            ui.add_space(6.0);
            ui.label(w::faint("FAILED SSH LOGINS · 24H"));
            match &v.auth {
                None => {
                    ui.label(w::faint("Waiting for the journal read (every 5 min)…"));
                }
                Some(a) => {
                    let mut rb = RingBuffer::new(48);
                    a.buckets.iter().for_each(|&b| rb.push(b as f32));
                    w::sparkline(ui, 34.0, 48, &[(&rb, WARN, true)], None);
                    ui.label(w::meta(format!("{} in 24 h", a.total())));
                    for (ip, n) in a.top.iter().take(6) {
                        let banned = v.jails.iter().any(|j| j.banned_ips.iter().any(|b| b == ip));
                        ui.horizontal(|ui| {
                            ui.label(w::mono(ip, TX1));
                            right(ui, |ui| {
                                if banned {
                                    w::badge(ui, "banned", ERR, ERR_DIM);
                                }
                                ui.label(w::meta(n.to_string()));
                            });
                        });
                    }
                }
            }
        },
    );
    hu.open.insert("security", is_open);
}

fn scheduled(ui: &mut Ui, v: &HostView, hu: &mut HostUi) {
    let mut is_open = open(hu, "scheduled");
    let summary = v
        .scheduled
        .as_ref()
        .map(|s| format!("{} timers · {} cron", s.timers.len(), s.cron_jobs.len()))
        .unwrap_or_default();
    section(
        ui,
        &mut is_open,
        ph::CLOCK_COUNTDOWN,
        "Scheduled",
        |ui| {
            ui.label(w::meta(summary));
        },
        |ui| {
            let Some(s) = &v.scheduled else {
                ui.label(w::faint("Collected only while this section is open."));
                return;
            };
            ui.spacing_mut().item_spacing.y = 3.0;
            for t in s.timers.iter().take(30) {
                ui.horizontal(|ui| {
                    ui.label(w::mono(t.unit.trim_end_matches(".timer"), TX0));
                    right(ui, |ui| {
                        let next = t
                            .next_in_s
                            .map_or("—".into(), |n| format!("in {}", format::duration(n)));
                        ui.label(w::meta(next));
                    });
                });
            }
            if !s.cron_jobs.is_empty() {
                ui.add_space(4.0);
                ui.label(w::faint("CRONTAB"));
                for c in s.cron_jobs.iter().take(10) {
                    let short: String = c.chars().take(48).collect();
                    ui.label(w::mono(short, TX2)).on_hover_text(c);
                }
            }
        },
    );
    hu.open.insert("scheduled", is_open);
}
