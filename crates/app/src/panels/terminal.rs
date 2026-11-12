//! Central terminal area. M0 renders a static placeholder screen; the real
//! PTY channel + `alacritty_terminal` renderer arrive in M1 (crate `term`).

use egui::text::LayoutJob;
use egui::{Align, Align2, Color32, Layout, Sense, TextFormat, Ui, pos2, vec2};
use egui_phosphor::regular as ph;

use crate::theme::{self, tok::*};
use crate::widgets as w;

pub fn show(ui: &mut Ui, host: &str, user: &str) {
    // Tab strip.
    let (strip, _) = ui.allocate_exact_size(vec2(ui.available_width(), 32.0), Sense::hover());
    ui.painter().rect_filled(strip, 0, BG1);
    let title = format!("{}  {user}@{host}", ph::TERMINAL_WINDOW);
    let g = ui.painter().layout_no_wrap(title, theme::prop(12.5), TX0);
    let tab = egui::Rect::from_min_size(strip.min, vec2(g.size().x + 28.0, 32.0));
    ui.painter().rect_filled(tab, 0, BG0);
    ui.painter().rect_filled(egui::Rect::from_min_size(tab.min, vec2(tab.width(), 2.0)), 0, ACC);
    ui.painter().galley(pos2(tab.left() + 14.0, tab.center().y - g.size().y / 2.0), g, TX0);
    ui.painter().text(
        pos2(strip.right() - 10.0, strip.center().y),
        Align2::RIGHT_CENTER,
        "PTY 132×34   channel #1   xterm-256color",
        theme::prop(11.0),
        TX3,
    );
    ui.painter().rect_filled(egui::Rect::from_min_max(pos2(strip.left(), strip.bottom() - 1.0), strip.max), 0, LINE);
    let mut c = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(egui::Rect::from_min_max(pos2(tab.right() + 4.0, strip.top()), pos2(strip.right(), strip.bottom())))
            .layout(Layout::left_to_right(Align::Center)),
    );
    let _ = w::icon_button(&mut c, ph::PLUS, "New terminal — another PTY channel on the same connection (M1)", false);

    // Screen.
    egui::Frame::NONE.inner_margin(egui::Margin::symmetric(12, 8)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let font = theme::mono(13.0);
        let mut job = LayoutJob::default();
        let mut put = |t: &str, c: Color32| job.append(t, 0.0, TextFormat { font_id: font.clone(), color: c, line_height: Some(19.5), ..Default::default() });
        let prompt = |put: &mut dyn FnMut(&str, Color32)| {
            put(&format!("{user}@{host}"), OK);
            put(":", TERM_FG);
            put("~", INFO);
            put("# ", TERM_FG);
        };
        put("Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-49-generic x86_64)\n\n", TERM_FG);
        put("Last login: Thu Nov 12 09:12:44 2026 from 198.51.100.24\n", TERM_FG);
        prompt(&mut put);
        put("systemctl status redis-server --no-pager\n", TERM_FG);
        put("×", ERR);
        put(" redis-server.service", TX0);
        put(" - Advanced key-value store\n     Loaded: loaded (/usr/lib/systemd/system/redis-server.service; ", TERM_FG);
        put("enabled", OK);
        put(")\n     Active: ", TERM_FG);
        put("failed", ERR);
        put(" (Result: exit-code) since Thu 2026-11-12 13:02:11 UTC; 3min ago\n", TERM_FG);
        put("   Main PID: 88213 (code=exited, status=1/FAILURE)\n\n", TERM_FG);
        prompt(&mut put);
        put("█\n\n", ACC);
        put("── M0 demo: this is a static screen. The live PTY terminal (alacritty_terminal renderer) arrives in M1. ──", TX3);
        ui.label(job);
    });
}
