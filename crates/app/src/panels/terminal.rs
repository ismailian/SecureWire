//! Central terminal area (ui-spec §3.3): tab strip, connection banner, and the
//! live `sw_term` view per PTY channel. The demo host keeps a static screen.

use std::sync::Arc;

use egui::text::LayoutJob;
use egui::{Align, Align2, Color32, Layout, RichText, Sense, TextFormat, Ui, pos2, vec2};
use egui_phosphor::regular as ph;
use parking_lot::Mutex;
use sw_ssh::api::{ConnState, PtyId};
use sw_term::{Size, Terminal, TerminalView};

use crate::theme::{self, tok::*};
use crate::widgets as w;

pub struct TermTab {
    pub id: PtyId,
    pub term: Terminal,
    pub view: TerminalView,
    pub title: Arc<Mutex<Option<String>>>,
}

#[derive(Default)]
pub struct TermUiOut {
    pub new_tab: bool,
    pub close: Option<usize>,
    pub select: Option<usize>,
    pub input: Option<(PtyId, Vec<u8>)>,
    pub resize: Option<(PtyId, Size)>,
    pub reconnect: bool,
    pub focused: bool,
    /// Files tab: clicked / closed / "open" button.
    pub files_select: bool,
    pub files_close: bool,
    pub files_open: bool,
}

pub struct Banner<'a> {
    pub state: ConnState,
    pub error: Option<&'a str>,
}

#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut Ui,
    tabs: &mut [TermTab],
    active: usize,
    fallback_title: &str,
    banner: Banner<'_>,
    pal: &sw_term::Palette,
    interactive: bool,
    // `Some(active)` when the host has a Files tab.
    files: Option<bool>,
) -> TermUiOut {
    let mut out = TermUiOut::default();
    let files_active = files == Some(true);

    // ---- tab strip ----
    let (strip, _) = ui.allocate_exact_size(vec2(ui.available_width(), 32.0), Sense::hover());
    ui.painter().rect_filled(strip, 0, BG1);
    ui.painter().rect_filled(
        egui::Rect::from_min_max(pos2(strip.left(), strip.bottom() - 1.0), strip.max),
        0,
        LINE,
    );
    let mut x = strip.left();
    if files.is_some() {
        let color = if files_active { TX0 } else { TX2 };
        let g = ui.painter().layout_no_wrap(
            format!("{}  Files", ph::FOLDERS),
            theme::prop(12.5),
            color,
        );
        let rect = egui::Rect::from_min_size(pos2(x, strip.top()), vec2(g.size().x + 46.0, 32.0));
        let resp = ui.interact(rect, ui.id().with("files-tab"), Sense::click());
        let p = ui.painter();
        if files_active {
            p.rect_filled(rect, 0, BG0);
            p.rect_filled(
                egui::Rect::from_min_size(rect.min, vec2(rect.width(), 2.0)),
                0,
                ACC,
            );
        } else if resp.hovered() {
            p.rect_filled(rect, 0, BG2);
        }
        p.rect_filled(
            egui::Rect::from_min_max(pos2(rect.right() - 1.0, rect.top()), rect.max),
            0,
            LINE,
        );
        p.galley(
            pos2(rect.left() + 12.0, rect.center().y - g.size().y / 2.0),
            g,
            color,
        );
        let close_r = egui::Rect::from_center_size(
            pos2(rect.right() - 16.0, rect.center().y),
            vec2(18.0, 18.0),
        );
        let close = ui.interact(close_r, ui.id().with("files-close"), Sense::click());
        if close.hovered() {
            ui.painter().rect_filled(close_r, 3, BG3);
        }
        ui.painter().text(
            close_r.center(),
            Align2::CENTER_CENTER,
            ph::X,
            theme::prop(11.0),
            if close.hovered() { TX0 } else { TX3 },
        );
        if close.clicked() || resp.middle_clicked() {
            out.files_close = true;
        } else if resp.clicked() {
            out.files_select = true;
        }
        x = rect.right();
    }
    for (i, t) in tabs.iter().enumerate() {
        let on = i == active && !files_active;
        let title = t
            .title
            .lock()
            .clone()
            .unwrap_or_else(|| fallback_title.to_owned());
        let title: String = title.chars().take(40).collect();
        let color = if on { TX0 } else { TX2 };
        let g = ui.painter().layout_no_wrap(
            format!("{}  {title}", ph::TERMINAL_WINDOW),
            theme::prop(12.5),
            color,
        );
        let rect = egui::Rect::from_min_size(pos2(x, strip.top()), vec2(g.size().x + 46.0, 32.0));
        let resp = ui.interact(rect, ui.id().with(("tab", t.id)), Sense::click());
        let p = ui.painter();
        if on {
            p.rect_filled(rect, 0, BG0);
            p.rect_filled(
                egui::Rect::from_min_size(rect.min, vec2(rect.width(), 2.0)),
                0,
                ACC,
            );
        } else if resp.hovered() {
            p.rect_filled(rect, 0, BG2);
        }
        p.rect_filled(
            egui::Rect::from_min_max(pos2(rect.right() - 1.0, rect.top()), rect.max),
            0,
            LINE,
        );
        p.galley(
            pos2(rect.left() + 12.0, rect.center().y - g.size().y / 2.0),
            g,
            color,
        );
        let close_r = egui::Rect::from_center_size(
            pos2(rect.right() - 16.0, rect.center().y),
            vec2(18.0, 18.0),
        );
        let close = ui.interact(close_r, ui.id().with(("close", t.id)), Sense::click());
        if close.hovered() {
            ui.painter().rect_filled(close_r, 3, BG3);
        }
        ui.painter().text(
            close_r.center(),
            Align2::CENTER_CENTER,
            ph::X,
            theme::prop(11.0),
            if close.hovered() { TX0 } else { TX3 },
        );
        if close.clicked() {
            out.close = Some(i);
        } else if resp.clicked() || resp.middle_clicked() {
            if resp.middle_clicked() {
                out.close = Some(i);
            } else {
                out.select = Some(i);
            }
        }
        x = rect.right();
    }
    let mut c = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(egui::Rect::from_min_max(
                pos2(x + 4.0, strip.top()),
                strip.max,
            ))
            .layout(Layout::left_to_right(Align::Center)),
    );
    if w::icon_button(
        &mut c,
        ph::PLUS,
        "New terminal (Ctrl+Shift+T) — another PTY channel on the same connection",
        false,
    )
    .clicked()
    {
        out.new_tab = true;
    }
    if files.is_none()
        && w::icon_button(
            &mut c,
            ph::FOLDERS,
            "Files (Ctrl+Shift+E): browse the server, transfer over SCP",
            false,
        )
        .clicked()
    {
        out.files_open = true;
    }
    if files_active {
        // The Files tab draws itself below the banner.
    } else if let Some(t) = tabs.get(active) {
        let s = t.term.size();
        c.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.add_space(6.0);
            ui.label(w::faint(format!(
                "PTY {}×{}   channel #{}   xterm-256color",
                s.cols, s.rows, t.id
            )));
        });
    }

    // ---- connection banner ----
    let connected = banner.state == ConnState::Connected;
    if !connected || banner.error.is_some() {
        let (text, color, button) = match banner.state {
            ConnState::Connecting => ("Connecting…".to_owned(), INFO, false),
            ConnState::Authenticating => ("Authenticating…".to_owned(), INFO, false),
            ConnState::Reconnecting { in_secs } => (
                format!("Connection lost — reconnecting in {in_secs}s"),
                WARN,
                true,
            ),
            ConnState::Disconnected => ("Disconnected".to_owned(), WARN, true),
            ConnState::Connected => (String::new(), WARN, false),
        };
        let text = match (banner.error, text.is_empty()) {
            (Some(e), true) => e.to_owned(),
            (Some(e), false) => format!("{text} · {e}"),
            (None, _) => text,
        };
        egui::Frame::NONE
            .fill(BG2)
            .inner_margin(egui::Margin::symmetric(12, 6))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(text).color(color));
                    if button {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.button("Reconnect now").clicked() {
                                out.reconnect = true;
                            }
                        });
                    }
                });
            });
    }

    // ---- terminal ----
    if files_active {
        return out;
    }
    let Some(tab) = tabs.get_mut(active) else {
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            ui.label(w::dim("No terminal open"));
            ui.label(w::faint("Ctrl Shift T opens one"));
            if ui
                .button(format!("{} New terminal", ph::TERMINAL_WINDOW))
                .clicked()
            {
                out.new_tab = true;
            }
        });
        return out;
    };
    let v = tab.view.show(ui, &tab.term, pal, !connected, interactive);
    out.focused = v.focused;
    if let Some(s) = v.resized {
        out.resize = Some((tab.id, s));
    }
    if !v.input.is_empty() {
        out.input = Some((tab.id, v.input));
    }
    out
}

/// Demo host: static screen (no PTY exists without a real connection).
pub fn demo_screen(ui: &mut Ui, host: &str, user: &str) {
    let (strip, _) = ui.allocate_exact_size(vec2(ui.available_width(), 32.0), Sense::hover());
    ui.painter().rect_filled(strip, 0, BG1);
    let g = ui.painter().layout_no_wrap(
        format!("{}  {user}@{host}", ph::TERMINAL_WINDOW),
        theme::prop(12.5),
        TX0,
    );
    let tab = egui::Rect::from_min_size(strip.min, vec2(g.size().x + 28.0, 32.0));
    ui.painter().rect_filled(tab, 0, BG0);
    ui.painter().rect_filled(
        egui::Rect::from_min_size(tab.min, vec2(tab.width(), 2.0)),
        0,
        ACC,
    );
    ui.painter().galley(
        pos2(tab.left() + 14.0, tab.center().y - g.size().y / 2.0),
        g,
        TX0,
    );

    // A recorded session (it matches the demo data: redis-server has failed), so the demo looks
    // like real use. Nothing here runs anything.
    let host = host.trim_end_matches(" (demo)");
    let prompt = format!("{user}@{host}");
    egui::Frame::NONE.inner_margin(egui::Margin::symmetric(12, 8)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let font = theme::mono(13.0);
        let mut job = LayoutJob::default();
        let mut put = |t: &str, c: Color32| {
            job.append(
                t,
                0.0,
                TextFormat {
                    font_id: font.clone(),
                    color: c,
                    line_height: Some(19.5),
                    ..Default::default()
                },
            )
        };
        let cmd = |put: &mut dyn FnMut(&str, Color32), c: &str| {
            put(&prompt, OK);
            put(":~# ", TERM_FG);
            put(c, TX0);
            put("
", TERM_FG);
        };
        cmd(&mut put, "systemctl status redis-server --no-pager -n 3");
        put("× ", ERR);
        put("redis-server.service - Advanced key-value store
", TX0);
        put("     Loaded: loaded (/usr/lib/systemd/system/redis-server.service; enabled; preset: enabled)
", TERM_FG);
        put("     Active: ", TERM_FG);
        put("failed", ERR);
        put(" (Result: exit-code) since Mon 2026-11-16 18:44:09 UTC; 3min ago
", TERM_FG);
        put("    Process: 1874 ExecStart=/usr/bin/redis-server /etc/redis/redis.conf (code=exited, status=1/FAILURE)
", TERM_FG);
        put("   Main PID: 1874 (code=exited, status=1/FAILURE)

", TERM_FG);
        put("Nov 16 18:44:09 prod-web-01 redis-server[1874]: # Can't open the log file: Permission denied
", TERM_FG);
        put("Nov 16 18:44:09 prod-web-01 systemd[1]: redis-server.service: Main process exited, code=exited, status=1/FAILURE
", TERM_FG);
        put("Nov 16 18:44:09 prod-web-01 systemd[1]: redis-server.service: Failed with result 'exit-code'.
", TERM_FG);
        cmd(&mut put, "ls -l /var/log/redis");
        put("total 2140
", TERM_FG);
        put("-rw-r----- 1 root adm 2187264 Nov 16 18:44 redis-server.log
", TERM_FG);
        cmd(&mut put, "chown redis:redis /var/log/redis/redis-server.log");
        put(&prompt, OK);
        put(":~# ", TERM_FG);
        put("█

", ACC);
        put(
            "Demo host: this terminal is a recording. Connect to a real server with + for a live shell.",
            TX3,
        );
        ui.label(job);
    });
}
