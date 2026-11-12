//! Right panel — WATCH (ui-spec §3.5). M0: services live; firewall/security
//! sections are placeholders until their collectors land in M3.

use egui::{Align, Layout, RichText, ScrollArea, Sense, Ui, vec2};
use egui_phosphor::regular as ph;
use sw_core::Section;
use sw_core::format;
use sw_core::model::{ActiveState, ServiceInfo};

use crate::state::{HostUi, HostView};
use crate::theme::tok::*;
use crate::widgets::{self as w, section};

pub enum Action {
    None,
    RefreshServices,
}

pub fn show(ui: &mut Ui, v: &HostView, hu: &mut HostUi) -> Action {
    let mut action = Action::None;
    super::panel_header(ui, "WATCH", |ui| {
        if w::icon_button(ui, ph::ARROWS_CLOCKWISE, "Refresh all now (F5)", false).clicked() {
            action = Action::RefreshServices;
        }
    });
    ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        let mut live = hu.services_live;
        let live_now = live;
        let live_label = if live { "Live" } else { "Off" };
        let mut open = hu.is_open("services");
        section(
            ui,
            &mut open,
            ph::GEAR_FINE,
            "Services",
            |ui| {
                let _ = w::icon_button(ui, ph::PLUS, "Choose services… (M3)", false);
                w::switch(ui, &mut live, live_label)
                    .on_hover_text("Live: state changes pushed by systemd on the same connection");
            },
            |ui| {
                if v.services.is_empty() {
                    ui.label(w::faint("No services watched"));
                }
                for s in &v.services {
                    service_row(ui, s);
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if live_now {
                        w::dot(ui, OK);
                        ui.label(w::faint(
                            "Live · state changes pushed by systemd · resources every 10s",
                        ));
                    } else {
                        ui.label(RichText::new(ph::CLOCK_COUNTDOWN).color(TX3));
                        let age = v
                            .age_s(Section::Svc)
                            .map_or("never".into(), |a| format!("{a:.0}s ago"));
                        ui.label(w::faint(format!("Checked {age}")));
                        if ui.link(RichText::new("refresh").size(11.0)).clicked() {
                            action = Action::RefreshServices;
                        }
                    }
                });
            },
        );
        hu.open.insert("services", open);
        hu.services_live = live;

        let mut open = hu.is_open("firewall");
        section(
            ui,
            &mut open,
            ph::WALL,
            "Firewall",
            |ui| {
                ui.label(w::meta("M3"));
            },
            |ui| {
                ui.label(w::faint(
                    "ufw / nftables rules via $SUDO — collector section `fw` arrives in M3.",
                ));
            },
        );
        hu.open.insert("firewall", open);

        let mut open = hu.is_open("security");
        section(
            ui,
            &mut open,
            ph::SHIELD_WARNING,
            "Security",
            |ui| {
                ui.label(w::meta("M3"));
            },
            |ui| {
                ui.label(w::faint(
                    "fail2ban jails and failed logins — sections `f2b`, `auth` arrive in M3.",
                ));
            },
        );
        hu.open.insert("security", open);

        let mut open = hu.is_open("scheduled");
        section(
            ui,
            &mut open,
            ph::CLOCK_COUNTDOWN,
            "Scheduled",
            |ui| {
                ui.label(w::meta("M3"));
            },
            |ui| {
                ui.label(w::faint(
                    "Collapsed sections are not collected. Expanding triggers one fetch.",
                ));
            },
        );
        hu.open.insert("scheduled", open);
    });
    action
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
    let sub = if failed {
        format!("{state} · {age} ago")
    } else {
        format!("{state} · {age}")
    };

    let width = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(vec2(width, 38.0), Sense::hover());
    let p = ui.painter();
    let bg = match (failed, resp.hovered()) {
        (true, _) => Some(ERR_DIM),
        (false, true) => Some(BG2),
        _ => None,
    };
    if let Some(bg) = bg {
        p.rect_filled(rect.expand2(vec2(6.0, 0.0)), 3, bg);
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
        if resp.hovered() {
            ui.spacing_mut().item_spacing.x = 0.0;
            let _ = w::icon_button(ui, ph::TERMINAL, "systemctl status in terminal", false);
            let _ = w::icon_button(ui, ph::SCROLL, "Logs", false);
            let _ = w::icon_button(ui, ph::ARROW_CLOCKWISE, "Restart (asks first)", false);
        } else {
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
        }
    });
}
