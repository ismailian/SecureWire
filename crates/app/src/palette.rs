//! Command palette (ui-spec §3.1, `Ctrl Shift P`): fuzzy search over actions,
//! hosts, services and log sources. Actions that need input ask for it in the
//! palette itself (a one-line parameter prompt) and are validated before they
//! become a request; destructive ones still go through the confirm dialog.

use egui::{Align2, Key, Modifiers, RichText, TextEdit, vec2};
use egui_phosphor::regular as ph;
use sw_core::actions::Action;
use sw_core::fuzzy;
use sw_core::shell::{is_valid_path, shell_quote};

use crate::state::Request;
use crate::theme::tok::*;
use crate::widgets as w;

/// What the palette knows about the app when it is drawn.
pub struct PaletteCtx {
    pub hosts: Vec<String>,
    pub active: usize,
    /// Saved hosts that are not open.
    pub saved: Vec<String>,
    pub services: Vec<String>,
    pub log_sources: Vec<String>,
    pub default_jail: Option<String>,
    pub connected: bool,
}

#[derive(Debug, Clone)]
pub enum Pick {
    /// For the active host.
    Host(Request),
    NewTerminal,
    Files,
    ToggleLeft,
    ToggleRight,
    ToggleBottom,
    SwitchHost(usize),
    ConnectSaved(String),
    NewHost,
    ChooseServices,
    LogSources,
    /// Show the logs tab filtered to this text (a source name).
    FilterLogs(String),
    RefreshAll,
    EnterSudo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Param {
    Restart,
    Stop,
    Start,
    Reload,
    Status,
    Ban,
    Unban,
    LargestDirs,
    WhoOnPort,
    TailFile,
    Tunnel,
}

impl Param {
    fn prompt(self) -> &'static str {
        match self {
            Param::Restart | Param::Stop | Param::Start | Param::Reload | Param::Status => {
                "Unit name (nginx.service)"
            }
            Param::Ban | Param::Unban => "IP address, optionally followed by the jail",
            Param::LargestDirs => "Directory (absolute path)",
            Param::WhoOnPort => "Port number",
            Param::TailFile => "File to follow (absolute path)",
            Param::Tunnel => "Server port to forward to 127.0.0.1 on this computer",
        }
    }

    fn wants_unit(self) -> bool {
        matches!(
            self,
            Param::Restart | Param::Stop | Param::Start | Param::Reload | Param::Status
        )
    }

    /// Turn the typed parameter into a request, or say what is wrong with it.
    fn build(self, input: &str, jail: Option<&str>) -> Result<Pick, String> {
        let s = input.trim();
        if s.is_empty() {
            return Err(self.prompt().into());
        }
        let unit = || {
            let u = if s.contains('.') {
                s.to_owned()
            } else {
                format!("{s}.service")
            };
            if sw_core::shell::is_valid_unit(&u) {
                Ok(u)
            } else {
                Err(format!("Not a valid unit name: {s}"))
            }
        };
        let run = |a: Action| a.command().map(|_| Pick::Host(Request::Run(a)));
        match self {
            Param::Restart => run(Action::ServiceRestart(unit()?)),
            Param::Stop => run(Action::ServiceStop(unit()?)),
            Param::Start => run(Action::ServiceStart(unit()?)),
            Param::Reload => run(Action::ServiceReload(unit()?)),
            Param::Status => Ok(Pick::Host(Request::Type(format!(
                "systemctl status --no-pager -- {}",
                shell_quote(&unit()?)
            )))),
            Param::Ban | Param::Unban => {
                let mut parts = s.split_whitespace();
                let ip = parts.next().unwrap_or_default().to_owned();
                let jail = parts
                    .next()
                    .map(str::to_owned)
                    .or(jail.map(str::to_owned))
                    .ok_or("No fail2ban jail known — add the jail name after the IP")?;
                run(if self == Param::Ban {
                    Action::Ban { jail, ip }
                } else {
                    Action::Unban { jail, ip }
                })
            }
            Param::LargestDirs => run(Action::LargestDirs(s.to_owned())),
            Param::WhoOnPort => {
                let p: u16 = s.parse().map_err(|_| format!("Not a port number: {s}"))?;
                run(Action::WhoOnPort(p))
            }
            Param::Tunnel => {
                let port: u16 = s
                    .parse()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| format!("Not a port number: {s}"))?;
                Ok(Pick::Host(Request::Tunnel {
                    host: "127.0.0.1".into(),
                    port,
                    label: format!("port {port}"),
                }))
            }
            Param::TailFile => {
                if !is_valid_path(s) {
                    return Err(format!("Not an absolute path: {s}"));
                }
                Ok(Pick::Host(Request::NewTerminal(format!(
                    "tail -F -n 200 -- {}",
                    shell_quote(s)
                ))))
            }
        }
    }
}

enum Run {
    Now(Pick),
    Ask(Param, String),
}

struct Item {
    icon: &'static str,
    label: String,
    hint: &'static str,
    run: Run,
}

#[derive(Default)]
pub struct Palette {
    pub open: bool,
    query: String,
    sel: usize,
    /// Parameter prompt: which action, typed text, last validation error.
    param: Option<(Param, String, Option<String>)>,
    focus: bool,
}

fn items(c: &PaletteCtx) -> Vec<Item> {
    let mut v = Vec::new();
    let now = |icon, label: String, hint, p: Pick| Item {
        icon,
        label,
        hint,
        run: Run::Now(p),
    };
    let ask = |icon, label: &str, hint, p: Param, pre: &str| Item {
        icon,
        label: label.to_owned(),
        hint,
        run: Run::Ask(p, pre.to_owned()),
    };
    if c.connected {
        v.push(ask(
            ph::ARROWS_CLOCKWISE,
            "Restart service…",
            "action",
            Param::Restart,
            "",
        ));
        v.push(ask(ph::STOP, "Stop service…", "action", Param::Stop, ""));
        v.push(ask(ph::PLAY, "Start service…", "action", Param::Start, ""));
        v.push(ask(
            ph::ARROW_CLOCKWISE,
            "Reload service…",
            "action",
            Param::Reload,
            "",
        ));
        v.push(ask(
            ph::TERMINAL,
            "Service status in terminal…",
            "terminal",
            Param::Status,
            "",
        ));
        v.push(ask(
            ph::FOLDER_OPEN,
            "Largest directories under…",
            "action",
            Param::LargestDirs,
            "/",
        ));
        v.push(ask(
            ph::PLUGS,
            "Who's on port…",
            "action",
            Param::WhoOnPort,
            "",
        ));
        v.push(ask(ph::PROHIBIT, "Ban IP…", "fail2ban", Param::Ban, ""));
        v.push(ask(
            ph::CHECK_CIRCLE,
            "Unban IP…",
            "fail2ban",
            Param::Unban,
            "",
        ));
        v.push(ask(
            ph::SCROLL,
            "Tail file in a new terminal…",
            "terminal",
            Param::TailFile,
            "/var/log/",
        ));
        v.push(ask(
            ph::ARROWS_LEFT_RIGHT,
            "Tunnel a server port to this computer…",
            "tunnel",
            Param::Tunnel,
            "",
        ));
        v.push(now(
            ph::PLUGS,
            "All listening sockets…".into(),
            "network",
            Pick::Host(Request::OpenPorts),
        ));
        v.push(now(
            ph::TERMINAL_WINDOW,
            "New terminal".into(),
            "Ctrl Shift T",
            Pick::NewTerminal,
        ));
        v.push(now(
            ph::FOLDERS,
            "Files: browse, upload, download".into(),
            "Ctrl Shift E",
            Pick::Files,
        ));
        for s in &c.services {
            let short = s.strip_suffix(".service").unwrap_or(s);
            v.push(now(
                ph::ARROWS_CLOCKWISE,
                format!("Restart {short}"),
                "service",
                Pick::Host(Request::Run(Action::ServiceRestart(s.clone()))),
            ));
            v.push(now(
                ph::TERMINAL,
                format!("Status of {short}"),
                "service",
                Pick::Host(Request::Type(format!(
                    "systemctl status --no-pager -- {}",
                    shell_quote(s)
                ))),
            ));
            v.push(now(
                ph::SCROLL,
                format!("Follow {short} journal in a new tab"),
                "service",
                Pick::Host(Request::NewTerminal(format!(
                    "journalctl -f -n 100 -u {}",
                    shell_quote(s)
                ))),
            ));
        }
        for l in &c.log_sources {
            v.push(now(
                ph::FUNNEL,
                format!("Logs: {l}"),
                "log source",
                Pick::FilterLogs(l.clone()),
            ));
        }
        v.push(now(
            ph::GEAR_FINE,
            "Choose watched services…".into(),
            "dialog",
            Pick::ChooseServices,
        ));
        v.push(now(
            ph::SCROLL,
            "Log sources…".into(),
            "dialog",
            Pick::LogSources,
        ));
        v.push(now(
            ph::ARROWS_CLOCKWISE,
            "Refresh all sections".into(),
            "F5",
            Pick::RefreshAll,
        ));
        v.push(now(
            ph::KEY,
            "Enter sudo password…".into(),
            "privileges",
            Pick::EnterSudo,
        ));
    }
    for (i, h) in c.hosts.iter().enumerate() {
        if i != c.active {
            v.push(now(
                ph::HARD_DRIVES,
                format!("Switch to {h}"),
                "host",
                Pick::SwitchHost(i),
            ));
        }
    }
    for h in &c.saved {
        v.push(now(
            ph::PLUGS_CONNECTED,
            format!("Connect to {h}"),
            "saved host",
            Pick::ConnectSaved(h.clone()),
        ));
    }
    v.push(now(ph::PLUS, "New host…".into(), "connect", Pick::NewHost));
    v.push(now(
        ph::SIDEBAR_SIMPLE,
        "Toggle left panel".into(),
        "Ctrl Shift B",
        Pick::ToggleLeft,
    ));
    v.push(now(
        ph::SIDEBAR_SIMPLE,
        "Toggle right panel".into(),
        "Ctrl Shift R",
        Pick::ToggleRight,
    ));
    v.push(now(
        ph::SQUARE_HALF_BOTTOM,
        "Toggle bottom dock".into(),
        "Ctrl Shift J",
        Pick::ToggleBottom,
    ));
    v
}

impl Palette {
    pub fn toggle(&mut self) {
        if self.open {
            self.open = false;
        } else {
            *self = Self {
                open: true,
                focus: true,
                ..Self::default()
            };
        }
    }

    pub fn show(&mut self, ctx: &egui::Context, c: &PaletteCtx) -> Option<Pick> {
        if !self.open {
            return None;
        }
        let (up, down, enter, esc) = ctx.input_mut(|i| {
            (
                i.consume_key(Modifiers::NONE, Key::ArrowUp),
                i.consume_key(Modifiers::NONE, Key::ArrowDown),
                i.consume_key(Modifiers::NONE, Key::Enter),
                i.consume_key(Modifiers::NONE, Key::Escape),
            )
        });
        if esc {
            if self.param.is_some() {
                self.param = None;
                self.focus = true;
            } else {
                self.open = false;
            }
            return None;
        }
        let mut picked = None;
        let width = 560.0_f32.min(ctx.content_rect().width() - 32.0);
        egui::Area::new(egui::Id::new("palette"))
            .order(egui::Order::Foreground)
            .anchor(Align2::CENTER_TOP, vec2(0.0, 48.0))
            .show(ctx, |ui| {
                egui::Frame::NONE
                    .fill(BG2)
                    .stroke(egui::Stroke::new(1.0, LINE2))
                    .corner_radius(4)
                    .inner_margin(egui::Margin::same(8))
                    .show(ui, |ui| {
                        ui.set_width(width);
                        ui.spacing_mut().item_spacing.y = 2.0;
                        if let Some((p, input, err)) = &mut self.param {
                            ui.label(w::faint(p.prompt()));
                            let r = ui.add(
                                TextEdit::singleline(input)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace),
                            );
                            if std::mem::take(&mut self.focus) {
                                r.request_focus();
                            }
                            if let Some(e) = err {
                                ui.label(RichText::new(format!("{} {e}", ph::WARNING)).color(WARN));
                            }
                            // Unit suggestions from the watched services.
                            let mut fill = None;
                            if p.wants_unit() {
                                let mut sugg: Vec<(i32, &String)> = c
                                    .services
                                    .iter()
                                    .filter_map(|s| fuzzy::score(input, s).map(|sc| (sc, s)))
                                    .collect();
                                sugg.sort_by_key(|s| std::cmp::Reverse(s.0));
                                for (_, s) in sugg.iter().take(6) {
                                    if ui
                                        .selectable_label(false, w::mono(s.as_str(), TX1))
                                        .clicked()
                                    {
                                        fill = Some((*s).clone());
                                    }
                                }
                            }
                            if let Some(f) = fill {
                                *input = f;
                                self.focus = true;
                            }
                            if enter {
                                match p.build(input, c.default_jail.as_deref()) {
                                    Ok(pick) => picked = Some(pick),
                                    Err(e) => *err = Some(e),
                                }
                            }
                            return;
                        }
                        let r = ui.add(
                            TextEdit::singleline(&mut self.query)
                                .hint_text(format!(
                                    "{}  Type a command, host or service…",
                                    ph::MAGNIFYING_GLASS
                                ))
                                .desired_width(f32::INFINITY),
                        );
                        if std::mem::take(&mut self.focus) {
                            r.request_focus();
                        }
                        if r.changed() {
                            self.sel = 0;
                        }
                        let all = items(c);
                        let mut ranked: Vec<(i32, usize)> = all
                            .iter()
                            .enumerate()
                            .filter_map(|(i, it)| {
                                fuzzy::score(&self.query, &it.label).map(|s| (s, i))
                            })
                            .collect();
                        // Stable: equal scores keep the list's own order.
                        ranked.sort_by_key(|r| std::cmp::Reverse(r.0));
                        ranked.truncate(12);
                        if ranked.is_empty() {
                            ui.label(w::faint("No matches"));
                            return;
                        }
                        if down {
                            self.sel = (self.sel + 1) % ranked.len();
                        }
                        if up {
                            self.sel = (self.sel + ranked.len() - 1) % ranked.len();
                        }
                        self.sel = self.sel.min(ranked.len() - 1);
                        let mut chosen = enter.then_some(self.sel);
                        for (row, (_, i)) in ranked.iter().enumerate() {
                            let it = &all[*i];
                            let on = row == self.sel;
                            let resp = ui
                                .horizontal(|ui| {
                                    let (rect, resp) = ui.allocate_exact_size(
                                        vec2(ui.available_width(), 24.0),
                                        egui::Sense::click(),
                                    );
                                    if on || resp.hovered() {
                                        ui.painter().rect_filled(
                                            rect,
                                            3,
                                            if on { ACC_DIM } else { BG3 },
                                        );
                                    }
                                    let p = ui.painter();
                                    let y = rect.center().y;
                                    p.text(
                                        egui::pos2(rect.left() + 8.0, y),
                                        Align2::LEFT_CENTER,
                                        it.icon,
                                        crate::theme::prop(13.0),
                                        TX2,
                                    );
                                    p.text(
                                        egui::pos2(rect.left() + 30.0, y),
                                        Align2::LEFT_CENTER,
                                        &it.label,
                                        crate::theme::prop(12.5),
                                        if on { TX0 } else { TX1 },
                                    );
                                    p.text(
                                        egui::pos2(rect.right() - 8.0, y),
                                        Align2::RIGHT_CENTER,
                                        it.hint,
                                        crate::theme::prop(11.0),
                                        TX3,
                                    );
                                    resp
                                })
                                .inner;
                            if resp.clicked() {
                                chosen = Some(row);
                            }
                        }
                        if let Some(row) = chosen {
                            match &all[ranked[row].1].run {
                                Run::Now(p) => picked = Some(p.clone()),
                                Run::Ask(p, pre) => {
                                    self.param = Some((*p, pre.clone(), None));
                                    self.focus = true;
                                }
                            }
                        }
                    });
            });
        if picked.is_some() {
            self.open = false;
        }
        picked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_validate_before_becoming_requests() {
        let unit = Param::Restart.build("nginx", None).unwrap();
        assert!(
            matches!(unit, Pick::Host(Request::Run(Action::ServiceRestart(ref u))) if u == "nginx.service")
        );
        assert!(Param::Stop.build("x; reboot", None).is_err());
        assert!(
            Param::Ban.build("198.51.100.7", None).is_err(),
            "no jail known"
        );
        assert!(matches!(
            Param::Ban.build("198.51.100.7", Some("sshd")).unwrap(),
            Pick::Host(Request::Run(Action::Ban { .. }))
        ));
        assert!(Param::Ban.build("not-an-ip", Some("sshd")).is_err());
        assert!(Param::WhoOnPort.build("70000", None).is_err());
        assert!(Param::TailFile.build("relative/path", None).is_err());
        let Pick::Host(Request::NewTerminal(cmd)) =
            Param::TailFile.build("/var/log/a b.log", None).unwrap()
        else {
            panic!()
        };
        assert_eq!(cmd, "tail -F -n 200 -- '/var/log/a b.log'");
    }
}
