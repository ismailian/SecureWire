//! Top bar (ui-spec §3.1).

use egui::{Align, Align2, Layout, RichText, Sense, Ui, pos2, vec2};
use egui_phosphor::regular as ph;
use sw_ssh::api::ConnState;

use crate::theme::{self, tok::*};
use crate::widgets as w;

pub struct Layout3 {
    pub left: bool,
    pub bottom: bool,
    pub right: bool,
}

pub struct HostTab<'a> {
    pub name: &'a str,
    pub state: ConnState,
    pub has_error: bool,
    pub has_warn: bool,
    pub tooltip: String,
}

#[derive(Default)]
pub struct TopAction {
    pub select: Option<usize>,
    pub close: Option<usize>,
    pub connect: bool,
    pub palette: bool,
}

pub fn show(ui: &mut Ui, hosts: &[HostTab<'_>], active: usize, layout: &mut Layout3) -> TopAction {
    let mut act = TopAction::default();
    ui.horizontal_centered(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        // Brand
        let (r, _) = ui.allocate_exact_size(vec2(18.0, 18.0), Sense::hover());
        ui.painter().rect_filled(r, 4, ACC);
        ui.painter().text(
            r.center(),
            Align2::CENTER_CENTER,
            ph::PLUGS_CONNECTED,
            theme::prop(12.0),
            BG0,
        );
        ui.add_space(7.0);
        ui.label(RichText::new("SecureWire").color(TX0).strong());
        ui.add_space(16.0);

        for (i, h) in hosts.iter().enumerate() {
            let on = i == active;
            let g = ui.painter().layout_no_wrap(
                h.name.to_owned(),
                theme::prop(12.5),
                if on { TX0 } else { TX2 },
            );
            let (r, resp) = ui.allocate_exact_size(vec2(g.size().x + 50.0, 38.0), Sense::click());
            let p = ui.painter();
            if on {
                p.rect_filled(r, 0, BG1);
                p.rect_filled(
                    egui::Rect::from_min_max(pos2(r.left(), r.bottom() - 2.0), r.max),
                    0,
                    ACC,
                );
            } else if resp.hovered() {
                p.rect_filled(r, 0, BG3);
            }
            let dot = match h.state {
                ConnState::Connected if h.has_error => ERR,
                ConnState::Connected if h.has_warn => WARN,
                ConnState::Connected => OK,
                ConnState::Reconnecting { .. } => WARN,
                ConnState::Connecting | ConnState::Authenticating => INFO,
                ConnState::Disconnected => TX3,
            };
            p.circle_filled(pos2(r.left() + 14.0, r.center().y), 3.5, dot);
            p.galley(
                pos2(r.left() + 24.0, r.center().y - g.size().y / 2.0),
                g,
                TX0,
            );
            let xr = egui::Rect::from_center_size(
                pos2(r.right() - 14.0, r.center().y),
                vec2(18.0, 18.0),
            );
            let x = ui.interact(xr, ui.id().with(("host-close", i)), Sense::click());
            if resp.hovered() || x.hovered() || on {
                if x.hovered() {
                    ui.painter().rect_filled(xr, 3, BG3);
                }
                ui.painter().text(
                    xr.center(),
                    Align2::CENTER_CENTER,
                    ph::X,
                    theme::prop(11.0),
                    if x.hovered() { TX0 } else { TX3 },
                );
            }
            if x.clicked() || resp.middle_clicked() {
                act.close = Some(i);
            } else if resp.clicked() {
                act.select = Some(i);
            }
            resp.on_hover_text(&h.tooltip);
        }
        ui.add_space(4.0);
        if w::icon_button(ui, ph::PLUS, "Connect to host…", false).clicked() {
            act.connect = true;
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            let _ = w::icon_button(ui, ph::GEAR_SIX, "Settings (M5)", false);
            ui.add_space(6.0);
            if w::icon_button(
                ui,
                ph::SIDEBAR_SIMPLE,
                "Toggle right panel (Ctrl+Shift+R)",
                layout.right,
            )
            .clicked()
            {
                layout.right = !layout.right;
            }
            if w::icon_button(
                ui,
                ph::ROWS,
                "Toggle bottom panel (Ctrl+Shift+J)",
                layout.bottom,
            )
            .clicked()
            {
                layout.bottom = !layout.bottom;
            }
            if w::icon_button(
                ui,
                ph::SIDEBAR_SIMPLE,
                "Toggle left panel (Ctrl+Shift+B)",
                layout.left,
            )
            .clicked()
            {
                layout.left = !layout.left;
            }
            ui.add_space(12.0);
            let width = (ui.available_width() - 40.0).clamp(160.0, 420.0);
            let (r, resp) = ui.allocate_exact_size(vec2(width, 24.0), Sense::click());
            let p = ui.painter();
            p.rect_filled(r, 3, BG1);
            p.rect_stroke(
                r,
                3,
                egui::Stroke::new(1.0, if resp.hovered() { TX3 } else { LINE2 }),
                egui::StrokeKind::Inside,
            );
            p.text(
                pos2(r.left() + 8.0, r.center().y),
                Align2::LEFT_CENTER,
                format!(
                    "{}  Run action, open log, jump to service…",
                    ph::MAGNIFYING_GLASS
                ),
                theme::prop(12.0),
                TX3,
            );
            p.text(
                pos2(r.right() - 8.0, r.center().y),
                Align2::RIGHT_CENTER,
                "Ctrl Shift P",
                theme::mono(10.5),
                TX2,
            );
            if resp.clicked() {
                act.palette = true;
            }
        });
    });
    act
}
