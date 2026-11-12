//! Bottom dock — LOGS · ALERTS · PROCESSES · CONNECTIONS (ui-spec §3.4).

use egui::{Align, Align2, Layout, RichText, ScrollArea, Sense, TextEdit, Ui, pos2, vec2};
use egui_phosphor::regular as ph;
use sw_core::alerts::{AlertAction, Severity};
use sw_core::format;
use sw_core::logs::Level;

use crate::state::{DockTab, HostUi, HostView};
use crate::theme::{self, tok::*};
use crate::widgets as w;

const ROW_H: f32 = 20.0;

pub fn show(ui: &mut Ui, v: &mut HostView, hu: &mut HostUi, hide: &mut bool) {
    tabs(ui, v, hu, hide);
    match hu.dock_tab {
        DockTab::Logs => logs(ui, v, hu),
        DockTab::Alerts => alerts(ui, v),
        DockTab::Processes => processes(ui, v),
        DockTab::Connections => {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add_space(12.0);
                ui.label(w::faint(
                    "Established connections (`ss -Htn`) arrive with the `conns` section in M3.",
                ));
            });
        }
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
    ] {
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
            ui.label(w::faint(
                "No log sources yet — choosing and tailing logs arrives in M4.",
            ));
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
                let _ = w::icon_button(
                    ui,
                    ph::SLIDERS_HORIZONTAL,
                    "Choose log sources… (M4)",
                    false,
                );
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
                    ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::hover());
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
                p.text(
                    pos2(r.left() + 110.0, y),
                    Align2::LEFT_CENTER,
                    sname,
                    f.clone(),
                    scol,
                );
                let (lc, _) = level_colors(line.level);
                p.text(
                    pos2(r.left() + 196.0, y),
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
                let msg_rect = egui::Rect::from_min_max(pos2(r.left() + 240.0, r.top()), r.max);
                ui.painter_at(msg_rect).text(
                    pos2(msg_rect.left(), y),
                    Align2::LEFT_CENTER,
                    &line.msg,
                    f,
                    mc,
                );
                if resp.hovered() {
                    resp.on_hover_text(&line.msg);
                }
            }
        });
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

fn alerts(ui: &mut Ui, v: &HostView) {
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
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 1.0;
                                ui.label(w::strong(&a.title));
                                ui.label(w::meta(&a.detail));
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                for act in a.actions.iter().rev() {
                                    let label = match act {
                                        AlertAction::RestartService(_) => "Restart",
                                        AlertAction::ServiceLogs(_) => "Logs",
                                        AlertAction::LargestDirs(_) => "Largest dirs",
                                    };
                                    let _ = ui
                                        .small_button(label)
                                        .on_hover_text("Actions arrive in M5");
                                }
                            });
                        });
                    });
                w::hline(ui);
            }
        });
}

fn processes(ui: &mut Ui, v: &HostView) {
    ScrollArea::vertical()
        .id_salt("procs")
        .auto_shrink(false)
        .show(ui, |ui| {
            egui::Frame::NONE
                .inner_margin(egui::Margin::symmetric(10, 4))
                .show(ui, |ui| {
                    egui::Grid::new("proc-grid")
                        .striped(false)
                        .spacing(vec2(18.0, 3.0))
                        .show(ui, |ui| {
                            for h in ["PID", "USER", "CPU%", "MEM", "UPTIME", "COMMAND"] {
                                ui.label(w::faint(h));
                            }
                            ui.end_row();
                            for p in &v.processes {
                                ui.label(w::mono(p.pid.to_string(), TX1));
                                ui.label(w::mono(&p.user, TX2));
                                ui.label(w::mono(
                                    format!("{:.1}", p.cpu),
                                    if p.cpu > 50.0 { WARN } else { TX1 },
                                ));
                                ui.label(w::mono(format::bytes(p.rss), TX1));
                                ui.label(w::mono(format::duration(p.elapsed_s), TX2));
                                ui.label(w::mono(&p.command, TX0));
                                ui.end_row();
                            }
                        });
                });
        });
}
