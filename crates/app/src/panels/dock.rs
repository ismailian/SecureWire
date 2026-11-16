//! Bottom dock — LOGS · ALERTS · PROCESSES · CONNECTIONS (ui-spec §3.4).

use egui::{Align, Align2, Layout, RichText, ScrollArea, Sense, TextEdit, Ui, pos2, vec2};
use egui_phosphor::regular as ph;
use sw_core::alerts::{AlertAction, Severity};
use sw_core::format;
use sw_core::logs::Level;

use sw_core::actions::Action as SrvAction;
use sw_core::shell::shell_quote;

use crate::state::{DockTab, HostUi, HostView, Request};
use crate::theme::{self, tok::*};
use crate::widgets as w;

const ROW_H: f32 = 20.0;

pub fn show(ui: &mut Ui, v: &mut HostView, hu: &mut HostUi, hide: &mut bool) {
    tabs(ui, v, hu, hide);
    match hu.dock_tab {
        DockTab::Logs => logs(ui, v, hu),
        DockTab::Alerts => alerts(ui, v, &mut hu.requests),
        DockTab::Processes => processes(ui, v, &mut hu.requests),
        DockTab::Connections => connections(ui, v, &mut hu.requests),
        DockTab::Traffic => traffic(ui, v, hu),
    }
}

fn tabs(ui: &mut Ui, v: &mut HostView, hu: &mut HostUi, hide: &mut bool) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 32.0), Sense::hover());
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(rect.shrink2(vec2(4.0, 0.0)))
            .layout(Layout::left_to_right(Align::Center)),
    );
    let ui2 = &mut child;
    let err_badge = (v.unseen_errors > 0).then(|| (v.unseen_errors.to_string(), ERR, ERR_DIM));
    let alert_badge = (!v.alerts.is_empty()).then(|| {
        let worst = v
            .alerts
            .iter()
            .map(|a| a.severity)
            .min()
            .unwrap_or(Severity::Info);
        let (fg, bg) = if worst == Severity::Error {
            (ERR, ERR_DIM)
        } else {
            (WARN, WARN_DIM)
        };
        (v.alerts.len().to_string(), fg, bg)
    });
    for (tab, icon, label, badge) in [
        (DockTab::Logs, ph::SCROLL, "LOGS", err_badge),
        (DockTab::Alerts, ph::BELL_RINGING, "ALERTS", alert_badge),
        (DockTab::Processes, ph::LIST_NUMBERS, "PROCESSES", None),
        (DockTab::Connections, ph::PLUGS, "CONNECTIONS", None),
        (DockTab::Traffic, ph::GLOBE, "TRAFFIC", None),
    ] {
        if tab == DockTab::Traffic && !has_traffic(v) {
            continue;
        }
        let on = hu.dock_tab == tab;
        let text_color = if on { TX0 } else { TX2 };
        let g =
            ui2.painter()
                .layout_no_wrap(format!("{icon}  {label}"), theme::prop(11.0), text_color);
        let bw = badge
            .as_ref()
            .map_or(0.0, |(t, ..)| 10.0 + t.len() as f32 * 7.0);
        let (r, resp) = ui2.allocate_exact_size(vec2(g.size().x + 20.0 + bw, 32.0), Sense::click());
        let p = ui2.painter();
        p.galley(
            pos2(r.left() + 10.0, r.center().y - g.size().y / 2.0),
            g.clone(),
            text_color,
        );
        if let Some((t, fg, bg)) = badge {
            let br = egui::Rect::from_min_size(
                pos2(r.left() + 14.0 + g.size().x, r.center().y - 8.0),
                vec2(bw - 4.0, 16.0),
            );
            p.rect_filled(br, 3, bg);
            p.text(br.center(), Align2::CENTER_CENTER, t, theme::prop(10.0), fg);
        }
        if on {
            p.rect_filled(
                egui::Rect::from_min_max(pos2(r.left(), r.bottom() - 1.0), r.max),
                0,
                ACC,
            );
        }
        if resp.clicked() {
            hu.dock_tab = tab;
            if tab == DockTab::Logs {
                v.unseen_errors = 0;
                v.sources.iter_mut().for_each(|s| s.unseen_errors = 0);
            }
        }
    }
    ui2.with_layout(Layout::right_to_left(Align::Center), |ui| {
        if w::icon_button(ui, ph::X, "Hide panel (Ctrl+J)", false).clicked() {
            *hide = true;
        }
    });
    w::hline(ui);
}

fn logs(ui: &mut Ui, v: &mut HostView, hu: &mut HostUi) {
    if v.sources.is_empty() {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(w::faint("No log sources yet ·"));
            if ui
                .link(RichText::new("choose log sources").size(11.0))
                .clicked()
            {
                hu.filter.dirty = true;
                hu.want_log_dialog = true;
            }
        });
        return;
    }
    // ---- toolbar ----
    egui::Frame::NONE
        .inner_margin(egui::Margin::symmetric(8, 5))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = vec2(4.0, 4.0);
                let all = v.sources.iter().all(|s| s.visible);
                if w::toggle_chip(ui, "all", all, TX0, BG3, None).clicked() {
                    v.sources.iter_mut().for_each(|s| s.visible = true);
                    hu.filter.dirty = true;
                }
                for s in v.sources.iter_mut() {
                    let label = if s.unseen_errors > 0 {
                        format!("{} ●", s.name)
                    } else {
                        s.name.clone()
                    };
                    if w::toggle_chip(ui, &label, s.visible, TX0, BG3, Some(s.color))
                        .on_hover_text(format!("{:?}: {}", s.kind, s.target))
                        .clicked()
                    {
                        s.visible = !s.visible;
                        hu.filter.dirty = true;
                    }
                }
                if w::icon_button(ui, ph::SLIDERS_HORIZONTAL, "Choose log sources…", false)
                    .clicked()
                {
                    hu.want_log_dialog = true;
                }
                ui.add_space(4.0);
                for lvl in Level::ALL {
                    let (fg, bg) = level_colors(lvl);
                    let on = hu.filter.levels[lvl.index()];
                    if w::toggle_chip(ui, lvl.label(), on, fg, bg, None).clicked() {
                        hu.filter.levels[lvl.index()] = !on;
                        hu.filter.dirty = true;
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if w::icon_button(
                        ui,
                        ph::ARROW_LINE_DOWN,
                        "Follow tail (End)",
                        hu.filter.follow,
                    )
                    .clicked()
                    {
                        hu.filter.follow = !hu.filter.follow;
                    }
                    let mut q = hu.filter.query.clone();
                    let stroke = if hu.filter.regex_invalid { WARN } else { LINE2 };
                    let resp = egui::Frame::NONE
                        .fill(BG0)
                        .stroke(egui::Stroke::new(1.0, stroke))
                        .corner_radius(3)
                        .inner_margin(egui::Margin::symmetric(6, 1))
                        .show(ui, |ui| {
                            ui.add(
                                TextEdit::singleline(&mut q)
                                    .id_salt("log-filter")
                                    .hint_text(format!("{} Filter (regex)…", ph::MAGNIFYING_GLASS))
                                    .frame(egui::Frame::NONE)
                                    .desired_width(200.0)
                                    .font(theme::mono(12.0)),
                            )
                        })
                        .inner;
                    if resp.changed() {
                        hu.filter.set_query(q);
                    }
                    if ui.input_mut(|i| {
                        i.consume_shortcut(&egui::KeyboardShortcut::new(
                            egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
                            egui::Key::L,
                        ))
                    }) {
                        resp.request_focus();
                    }
                });
            });
        });
    w::hline(ui);

    // ---- rows (virtualized) ----
    hu.filter.sync(v);
    let n = hu.filter.matches.len();
    if ui.input(|i| i.key_pressed(egui::Key::End)) {
        hu.filter.follow = true;
    }
    let mut log_reqs = Vec::new();
    let mut log_act = None;
    let view: &HostView = v;
    let out = ScrollArea::vertical()
        .id_salt("log-rows")
        .auto_shrink(false)
        .stick_to_bottom(hu.filter.follow)
        .show_rows(ui, ROW_H, n, |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for i in range {
                let Some(line) = hu.filter.matches.get(i).and_then(|&s| v.logs.get(s)) else {
                    continue;
                };
                let (r, resp) =
                    ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::click());
                let p = ui.painter();
                if line.level == Level::Error {
                    p.rect_filled(r, 0, ERR_TINT);
                }
                if resp.hovered() {
                    p.rect_filled(r, 0, BG2);
                }
                let y = r.center().y;
                let f = theme::mono(12.0);
                p.text(
                    pos2(r.left() + 10.0, y),
                    Align2::LEFT_CENTER,
                    clock(line.ts_ms),
                    f.clone(),
                    TX3,
                );
                let src = v.sources.get(line.source as usize);
                let (sname, scol) = src.map_or(("?", TX2), |s| (s.name.as_str(), s.color));
                // Clipped to its column: long source names must not run into the level.
                let src_rect = egui::Rect::from_min_max(
                    pos2(r.left() + 110.0, r.top()),
                    pos2(r.left() + 206.0, r.bottom()),
                );
                ui.painter_at(src_rect).text(
                    pos2(src_rect.left(), y),
                    Align2::LEFT_CENTER,
                    sname,
                    f.clone(),
                    scol,
                );
                let (lc, _) = level_colors(line.level);
                p.text(
                    pos2(r.left() + 212.0, y),
                    Align2::LEFT_CENTER,
                    line.level.label(),
                    theme::mono(10.5),
                    lc,
                );
                let mc = if line.level == Level::Error {
                    ERR_SOFT
                } else {
                    TX1
                };
                let msg_rect = egui::Rect::from_min_max(pos2(r.left() + 256.0, r.top()), r.max);
                ui.painter_at(msg_rect).text(
                    pos2(msg_rect.left(), y),
                    Align2::LEFT_CENTER,
                    &line.msg,
                    f,
                    mc,
                );
                // Click: copy, or act on an IP the line mentions (ban, its traffic, its logs).
                w::row_menu(&resp, |ui| {
                    if ui.button(format!("{}  Copy line", ph::COPY)).clicked() {
                        ui.ctx().copy_text(line.msg.clone());
                        ui.close();
                    }
                    for ip in sw_core::logs::extract_ips(&line.msg).into_iter().take(4) {
                        let ip = ip.to_string();
                        ui.menu_button(format!("{}  {ip}", ph::GLOBE), |ui| {
                            ip_items(ui, &ip, view, &mut log_reqs, &mut log_act);
                        });
                    }
                });
                if resp.hovered() {
                    resp.on_hover_text(&line.msg);
                }
            }
        });
    apply_ip_act(log_act, hu);
    hu.requests.extend(log_reqs);
    // Scrolling up turns follow off (ui-spec §3.4).
    let at_bottom = out.state.offset.y + out.inner_rect.height() >= out.content_size.y - ROW_H;
    if hu.filter.follow && !at_bottom && ui.input(|i| i.smooth_scroll_delta.y > 0.0) {
        hu.filter.follow = false;
    }
}

fn level_colors(l: Level) -> (egui::Color32, egui::Color32) {
    match l {
        Level::Error => (ERR, ERR_DIM),
        Level::Warn => (WARN, WARN_DIM),
        Level::Info => (INFO, INFO_DIM),
        Level::Debug => (TX1, BG3),
    }
}

/// Local wall-clock `HH:MM:SS.mmm` without a time-zone crate: UTC offset is
/// applied once at startup by the platform layer later (M5); UTC for now.
fn clock(ts_ms: i64) -> String {
    let ms = ts_ms.rem_euclid(1000);
    let s = ts_ms.div_euclid(1000).rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        s / 3600,
        (s % 3600) / 60,
        s % 60,
        ms
    )
}

fn alerts(ui: &mut Ui, v: &HostView, reqs: &mut Vec<Request>) {
    ScrollArea::vertical()
        .id_salt("alerts")
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            if v.alerts.is_empty() {
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new(format!("{} No active alerts", ph::SEAL_CHECK)).color(OK),
                    );
                });
            }
            for a in &v.alerts {
                egui::Frame::NONE
                    .inner_margin(egui::Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            let (icon, c) = match a.severity {
                                Severity::Error => (ph::X_CIRCLE, ERR),
                                Severity::Warn => (ph::WARNING, WARN),
                                Severity::Info => (ph::INFO, INFO),
                            };
                            ui.label(RichText::new(icon).size(15.0).color(c));
                            // Bounded text: a long detail truncates instead of widening the dock.
                            let text_w =
                                (ui.available_width() - 96.0 * a.actions.len() as f32 - 24.0)
                                    .max(120.0);
                            ui.allocate_ui(vec2(text_w, 36.0), |ui| {
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 1.0;
                                    ui.add(egui::Label::new(w::strong(&a.title)).truncate());
                                    ui.add(egui::Label::new(w::meta(&a.detail)).truncate())
                                        .on_hover_text(&a.detail);
                                });
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                for act in a.actions.iter().rev() {
                                    let label = match act {
                                        AlertAction::RestartService(_) => "Restart",
                                        AlertAction::ServiceLogs(_) => "Logs",
                                        AlertAction::LargestDirs(_) => "Largest dirs",
                                    };
                                    if ui.small_button(label).clicked() {
                                        reqs.push(match act {
                                            AlertAction::RestartService(u) => {
                                                Request::Run(SrvAction::ServiceRestart(u.clone()))
                                            }
                                            AlertAction::ServiceLogs(u) => {
                                                Request::NewTerminal(format!(
                                                    "journalctl -n 200 -f -u {}",
                                                    shell_quote(u)
                                                ))
                                            }
                                            AlertAction::LargestDirs(p) => {
                                                Request::Run(SrvAction::LargestDirs(p.clone()))
                                            }
                                        });
                                    }
                                }
                            });
                        });
                    });
                w::hline(ui);
            }
        });
}

fn processes(ui: &mut Ui, v: &HostView, reqs: &mut Vec<Request>) {
    // Fixed columns; COMMAND takes what is left and truncates (full text on hover), so a
    // long command line can never widen the dock past the right panel.
    ScrollArea::vertical()
        .id_salt("procs")
        .auto_shrink(false)
        .show_rows(ui, 20.0, v.processes.len() + 1, |ui, range| {
            egui::Frame::NONE
                .inner_margin(egui::Margin::symmetric(10, 0))
                .show(ui, |ui| {
                    for i in range {
                        ui.horizontal(|ui| {
                            let col = |ui: &mut Ui, w_: f32, t: RichText| {
                                w::cell(ui, w_, egui::Label::new(t).truncate())
                            };
                            if i == 0 {
                                for (h, w_) in [
                                    ("PID", 64.0),
                                    ("USER", 96.0),
                                    ("CPU%", 52.0),
                                    ("MEM", 76.0),
                                    ("UPTIME", 70.0),
                                ] {
                                    col(ui, w_, w::faint(h));
                                }
                                ui.label(w::faint("COMMAND"));
                                return;
                            }
                            let p = &v.processes[i - 1];
                            let r = w::cell(
                                ui,
                                64.0,
                                egui::Label::new(w::mono(p.pid.to_string(), ACC))
                                    .sense(Sense::click()),
                            )
                            .on_hover_text("Click for actions");
                            process_menu(&r, p.pid, reqs);
                            col(ui, 96.0, w::mono(&p.user, TX2));
                            col(
                                ui,
                                52.0,
                                w::mono(
                                    format!("{:.1}", p.cpu),
                                    if p.cpu > 50.0 { WARN } else { TX1 },
                                ),
                            );
                            col(ui, 76.0, w::mono(format::bytes(p.rss), TX1));
                            col(ui, 70.0, w::mono(format::duration(p.elapsed_s), TX2));
                            let rest = ui.available_width().max(40.0);
                            col(ui, rest, w::mono(&p.command, TX0)).on_hover_text(&p.command);
                        });
                    }
                });
        });
}

fn connections(ui: &mut Ui, v: &HostView, reqs: &mut Vec<Request>) {
    if v.conns.is_empty() {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(w::faint("No established TCP connections reported yet (refreshed every 60 s while this tab is open)."));
        });
        return;
    }
    ScrollArea::vertical()
        .id_salt("conns")
        .auto_shrink(false)
        .show_rows(ui, 20.0, v.conns.len() + 1, |ui, range| {
            egui::Frame::NONE
                .inner_margin(egui::Margin::symmetric(10, 0))
                .show(ui, |ui| {
                    for i in range {
                        ui.horizontal(|ui| {
                            let col = |ui: &mut Ui, w_: f32, t: RichText| {
                                ui.add_sized(vec2(w_, 18.0), egui::Label::new(t).truncate());
                            };
                            if i == 0 {
                                col(ui, 220.0, w::faint("LOCAL"));
                                col(ui, 240.0, w::faint("PEER"));
                                col(ui, 160.0, w::faint("PROCESS"));
                            } else {
                                let c = &v.conns[i - 1];
                                col(ui, 220.0, w::mono(&c.local, TX1));
                                let r = ui
                                    .add_sized(
                                        vec2(240.0, 18.0),
                                        egui::Label::new(w::mono(&c.peer, TX0))
                                            .truncate()
                                            .sense(Sense::click()),
                                    )
                                    .on_hover_text("Click for actions");
                                peer_menu(&r, &c.peer, &c.local, v.default_jail(), reqs);
                                col(ui, 160.0, w::mono(&c.process, TX2));
                            }
                        });
                    }
                });
        });
}

fn process_menu(r: &egui::Response, pid: u32, reqs: &mut Vec<Request>) {
    w::row_menu(r, |ui| {
        if ui.button(format!("{}  Copy PID", ph::COPY)).clicked() {
            ui.ctx().copy_text(pid.to_string());
            ui.close();
        }
        if ui
            .button(format!("{}  Terminate (TERM)", ph::STOP))
            .clicked()
        {
            reqs.push(Request::Run(SrvAction::Kill { pid, force: false }));
            ui.close();
        }
        if ui
            .button(RichText::new(format!("{}  Kill (KILL)", ph::SKULL)).color(ERR))
            .clicked()
        {
            reqs.push(Request::Run(SrvAction::Kill { pid, force: true }));
            ui.close();
        }
        if ui
            .button(format!("{}  top -p {pid} in a new tab", ph::TERMINAL))
            .clicked()
        {
            reqs.push(Request::NewTerminal(format!("top -p {pid}")));
            ui.close();
        }
    });
}

/// `203.0.113.7:443`, `[2001:db8::1]:22` → (address, port).
fn split_addr(s: &str) -> Option<(&str, u16)> {
    let (a, p) = s.rsplit_once(':')?;
    Some((
        a.trim_start_matches('[').trim_end_matches(']'),
        p.parse().ok()?,
    ))
}

fn peer_menu(
    r: &egui::Response,
    peer: &str,
    local: &str,
    jail: Option<&str>,
    reqs: &mut Vec<Request>,
) {
    w::row_menu(r, |ui| {
        let ip = split_addr(peer).map(|(a, _)| a.to_owned());
        if let (Some(ip), Some(j)) = (&ip, jail)
            && ui
                .button(RichText::new(format!("{}  Ban {ip} ({j})", ph::PROHIBIT)).color(ERR))
                .clicked()
        {
            reqs.push(Request::Run(SrvAction::Ban {
                jail: j.to_owned(),
                ip: ip.clone(),
            }));
            ui.close();
        }
        if let Some((_, port)) = split_addr(local)
            && ui
                .button(format!("{}  Who's on port {port}", ph::PLUGS))
                .clicked()
        {
            reqs.push(Request::Run(SrvAction::WhoOnPort(port)));
            ui.close();
        }
        if ui.button(format!("{}  Copy peer", ph::COPY)).clicked() {
            ui.ctx().copy_text(peer.to_owned());
            ui.close();
        }
    });
}

// ───────────────────────── Traffic (access logs) ─────────────────────────

fn has_traffic(v: &HostView) -> bool {
    v.traffic.total > 0
        || v.sources
            .iter()
            .any(|s| sw_core::logs::is_access_log(&s.target))
}

/// What an IP menu asks of the dock (besides server actions).
enum IpAct {
    OnlyClient(String),
    LogsFor(String),
}

/// Menu items for one IP: shared by the Traffic tab, log lines and connections.
fn ip_items(ui: &mut Ui, ip: &str, v: &HostView, reqs: &mut Vec<Request>, act: &mut Option<IpAct>) {
    if ui
        .button(format!("{}  Only this client's requests", ph::FUNNEL))
        .clicked()
    {
        *act = Some(IpAct::OnlyClient(ip.to_owned()));
        ui.close();
    }
    if ui
        .button(format!("{}  Log lines mentioning {ip}", ph::SCROLL))
        .clicked()
    {
        *act = Some(IpAct::LogsFor(ip.to_owned()));
        ui.close();
    }
    let banned_in = v
        .jails
        .iter()
        .find(|j| j.banned_ips.iter().any(|b| b == ip));
    match (banned_in, v.default_jail()) {
        (Some(j), _) => {
            if ui
                .button(format!("{}  Unban {ip} ({})", ph::CHECK_CIRCLE, j.name))
                .clicked()
            {
                reqs.push(Request::Run(SrvAction::Unban {
                    jail: j.name.clone(),
                    ip: ip.to_owned(),
                }));
                ui.close();
            }
        }
        (None, Some(j)) => {
            if ui
                .button(RichText::new(format!("{}  Ban {ip} ({j})", ph::PROHIBIT)).color(ERR))
                .clicked()
            {
                reqs.push(Request::Run(SrvAction::Ban {
                    jail: j.to_owned(),
                    ip: ip.to_owned(),
                }));
                ui.close();
            }
        }
        (None, None) => {
            ui.label(w::faint("Ban needs fail2ban (and sudo)"));
        }
    }
    if ui.button(format!("{}  Copy {ip}", ph::COPY)).clicked() {
        ui.ctx().copy_text(ip.to_owned());
        ui.close();
    }
}

fn apply_ip_act(act: Option<IpAct>, hu: &mut HostUi) {
    match act {
        Some(IpAct::OnlyClient(ip)) => {
            hu.traffic_ip = Some(ip);
            hu.dock_tab = DockTab::Traffic;
        }
        Some(IpAct::LogsFor(ip)) => {
            // The log filter is a regex: escape the dots.
            hu.filter.set_query(ip.replace('.', r"\."));
            hu.dock_tab = DockTab::Logs;
        }
        None => {}
    }
}

fn status_color(s: u16) -> egui::Color32 {
    match s {
        500.. => ERR,
        400..=499 => WARN,
        300..=399 => INFO,
        _ => OK,
    }
}

fn traffic(ui: &mut Ui, v: &HostView, hu: &mut HostUi) {
    let t = &v.traffic;
    if t.total == 0 {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.add_space(12.0);
            ui.label(w::faint("No requests yet. Traffic comes from access-log sources (nginx/apache access.log) ·"));
            if ui.link(RichText::new("log sources").size(11.0)).clicked() {
                hu.want_log_dialog = true;
            }
        });
        return;
    }
    let mut reqs = Vec::new();
    let mut act = None;
    let mut clear_ip = false;
    ui.horizontal(|ui| {
        ui.add_space(10.0);
        ui.label(w::meta(format!("{} requests", t.total)));
        for (i, (label, c)) in [("2xx", OK), ("3xx", INFO), ("4xx", WARN), ("5xx", ERR)]
            .into_iter()
            .enumerate()
        {
            w::chip(ui, &format!("{label} {}", t.status[i + 1]), c);
        }
        if let Some(ip) = &hu.traffic_ip {
            ui.add_space(8.0);
            if w::chip(ui, &format!("{ip}  ×"), ACC)
                .on_hover_text("Show all clients")
                .clicked()
            {
                clear_ip = true;
            }
        }
    });
    ui.columns(2, |c| {
        // ---- top clients ----
        c[0].horizontal(|ui| {
            ui.add_space(10.0);
            ui.label(w::faint("TOP CLIENTS · click for actions"));
        });
        ScrollArea::vertical()
            .id_salt("traffic-top")
            .auto_shrink(false)
            .show_rows(&mut c[0], 20.0, t.top.len(), |ui, range| {
                for ip in &t.top[range] {
                    let Some(s) = t.by_ip.get(ip) else { continue };
                    ui.horizontal(|ui| {
                        ui.add_space(10.0);
                        let banned = v.jails.iter().any(|j| j.banned_ips.iter().any(|b| b == ip));
                        let r = w::cell(
                            ui,
                            150.0,
                            egui::Label::new(w::mono(ip, if banned { TX3 } else { ACC }))
                                .truncate()
                                .sense(Sense::click()),
                        )
                        .on_hover_text(if banned {
                            "banned by fail2ban"
                        } else {
                            "click for actions"
                        });
                        w::row_menu(&r, |ui| ip_items(ui, ip, v, &mut reqs, &mut act));
                        w::cell(
                            ui,
                            56.0,
                            egui::Label::new(w::mono(s.requests.to_string(), TX1)),
                        );
                        w::cell(
                            ui,
                            48.0,
                            egui::Label::new(w::mono(
                                s.errors.to_string(),
                                if s.errors > 0 { WARN } else { TX3 },
                            )),
                        )
                        .on_hover_text("4xx/5xx answers");
                        let rest = ui.available_width().max(40.0);
                        w::cell(
                            ui,
                            rest,
                            egui::Label::new(w::mono(&s.last_path, TX2)).truncate(),
                        )
                        .on_hover_text(&s.last_path);
                    });
                }
            });
        // ---- recent requests (newest first) ----
        c[1].label(w::faint(match &hu.traffic_ip {
            Some(ip) => format!("RECENT REQUESTS · {ip}"),
            None => "RECENT REQUESTS".to_owned(),
        }));
        let rows: Vec<usize> = match &hu.traffic_ip {
            Some(ip) => (0..t.recent.len())
                .rev()
                .filter(|&i| t.recent[i].1.ip == *ip)
                .collect(),
            None => (0..t.recent.len()).rev().collect(),
        };
        ScrollArea::vertical()
            .id_salt("traffic-recent")
            .auto_shrink(false)
            .show_rows(&mut c[1], 20.0, rows.len(), |ui, range| {
                for &i in &rows[range] {
                    let (ts, h) = &t.recent[i];
                    ui.horizontal(|ui| {
                        w::cell(ui, 84.0, egui::Label::new(w::mono(clock(*ts), TX3)));
                        let r = w::cell(
                            ui,
                            120.0,
                            egui::Label::new(w::mono(&h.ip, TX1))
                                .truncate()
                                .sense(Sense::click()),
                        );
                        w::row_menu(&r, |ui| ip_items(ui, &h.ip, v, &mut reqs, &mut act));
                        w::cell(
                            ui,
                            36.0,
                            egui::Label::new(w::mono(h.status.to_string(), status_color(h.status))),
                        );
                        let rest = ui.available_width().max(40.0);
                        w::cell(
                            ui,
                            rest,
                            egui::Label::new(w::mono(format!("{} {}", h.method, h.path), TX0))
                                .truncate(),
                        )
                        .on_hover_text(format!(
                            "{} {}\n{} bytes\nreferrer: {}\nagent: {}",
                            h.method, h.path, h.bytes, h.referrer, h.agent
                        ));
                    });
                }
            });
    });
    if clear_ip {
        hu.traffic_ip = None;
    }
    apply_ip_act(act, hu);
    hu.requests.extend(reqs);
}
