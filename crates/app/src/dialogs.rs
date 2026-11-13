//! Modal windows (ui-spec §4): Connect, Host key, Authentication.

use egui::{Align, Align2, Color32, Layout, RichText, TextEdit, Ui, vec2};
use egui_phosphor::regular as ph;
use secrecy::SecretString;
use sw_core::config::{AuthMethod, HostConfig, HostsFile};
use sw_ssh::api::{AuthSpec, HostKeyStatus, KeyDecision};

use crate::store;
use crate::theme::tok::*;
use crate::widgets as w;

/// Shared look: dimmed backdrop + centered window.
fn modal<R>(
    ctx: &egui::Context,
    id: &str,
    title: &str,
    icon: &str,
    width: f32,
    body: impl FnOnce(&mut Ui) -> R,
) -> Option<R> {
    let screen = ctx.content_rect();
    // Dim everything behind the dialog (panels live on the background layer).
    ctx.layer_painter(egui::LayerId::new(
        egui::Order::Middle,
        egui::Id::new((id, "scrim")),
    ))
    .rect_filled(screen, 0, Color32::from_black_alpha(150));
    egui::Window::new(format!("{icon}  {title}"))
        .id(egui::Id::new(id))
        .order(egui::Order::Foreground)
        .collapsible(false)
        .resizable(false)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -40.0))
        // Width fixed, height follows content (lists fill in after the first frame).
        .min_width(width)
        .max_width(width)
        .show(ctx, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            body(ui)
        })
        .and_then(|r| r.inner)
}

fn field(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.add_sized(vec2(110.0, 24.0), egui::Label::new(w::dim(label)));
        add(ui);
    });
}

fn segmented<T: PartialEq + Copy>(ui: &mut Ui, value: &mut T, options: &[(T, &str)]) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for &(v, label) in options {
            let on = *value == v;
            let text = RichText::new(label).color(if on { ACC } else { TX2 });
            let b = egui::Button::new(text)
                .fill(if on { ACC_DIM } else { BG2 })
                .corner_radius(0);
            if ui.add(b).clicked() {
                *value = v;
            }
        }
    });
}

// ─────────────────────────────── Connect ───────────────────────────────

pub struct ConnectDialog {
    pub open: bool,
    form: HostConfig,
    port_text: String,
    password: String,
    passphrase: String,
    error: Option<String>,
    focus_secret: bool,
}

pub enum ConnectOutcome {
    None,
    Connect {
        config: Box<HostConfig>,
        auth: AuthSpec,
    },
    Delete(String),
}

impl Default for ConnectDialog {
    fn default() -> Self {
        Self {
            open: false,
            form: HostConfig::new("", "", "root"),
            port_text: "22".into(),
            password: String::new(),
            passphrase: String::new(),
            error: None,
            focus_secret: false,
        }
    }
}

impl ConnectDialog {
    pub fn open_new(&mut self) {
        *self = Self {
            open: true,
            ..Self::default()
        };
    }

    pub fn open_for(&mut self, h: &HostConfig) {
        *self = Self {
            open: true,
            form: h.clone(),
            port_text: h.port.to_string(),
            focus_secret: h.auth == AuthMethod::Password,
            ..Self::default()
        };
    }

    pub fn show(
        &mut self,
        ctx: &egui::Context,
        saved: &HostsFile,
        connected: &[String],
    ) -> ConnectOutcome {
        if !self.open {
            return ConnectOutcome::None;
        }
        let mut outcome = ConnectOutcome::None;
        let mut close = false;
        modal(
            ctx,
            "connect",
            "Connect",
            ph::PLUGS_CONNECTED,
            560.0,
            |ui| {
                if !saved.hosts.is_empty() {
                    ui.label(w::faint("SAVED HOSTS"));
                    for h in &saved.hosts {
                        let is_conn = connected.contains(&h.name);
                        egui::Frame::NONE
                            .fill(BG2)
                            .corner_radius(3)
                            .inner_margin(egui::Margin::symmetric(10, 6))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    w::dot(ui, if is_conn { OK } else { TX3 });
                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = 0.0;
                                        ui.label(w::mono(&h.name, TX0));
                                        let auth = match h.auth {
                                            AuthMethod::Agent => "agent".to_owned(),
                                            AuthMethod::Password => "password".to_owned(),
                                            AuthMethod::Key if h.key_path.is_empty() => {
                                                "~/.ssh/id_ed25519".to_owned()
                                            }
                                            AuthMethod::Key => h.key_path.clone(),
                                        };
                                        ui.label(w::faint(format!(
                                            "{}@{}:{} · {auth}",
                                            h.user, h.address, h.port
                                        )));
                                    });
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if w::icon_button(ui, ph::TRASH, "Remove saved host", false)
                                            .clicked()
                                        {
                                            outcome = ConnectOutcome::Delete(h.name.clone());
                                        }
                                        if !is_conn && ui.button("Use").clicked() {
                                            self.open_for(h);
                                        }
                                    });
                                });
                            });
                    }
                    ui.add_space(6.0);
                    ui.label(w::faint(if self.form.name.is_empty() {
                        "NEW HOST"
                    } else {
                        "CONNECTION"
                    }));
                }

                let f = &mut self.form;
                field(ui, "Name", |ui| {
                    ui.add(
                        TextEdit::singleline(&mut f.name)
                            .hint_text("my-vps")
                            .desired_width(f32::INFINITY),
                    );
                });
                field(ui, "Host / port", |ui| {
                    ui.add(
                        TextEdit::singleline(&mut f.address)
                            .hint_text("203.0.113.10")
                            .desired_width(300.0)
                            .font(egui::TextStyle::Monospace),
                    );
                    ui.add(
                        TextEdit::singleline(&mut self.port_text)
                            .desired_width(60.0)
                            .font(egui::TextStyle::Monospace),
                    );
                });
                field(ui, "User", |ui| {
                    ui.add(
                        TextEdit::singleline(&mut f.user)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace),
                    );
                });
                field(ui, "Auth", |ui| {
                    segmented(
                        ui,
                        &mut f.auth,
                        &[
                            (AuthMethod::Key, "Key file"),
                            (AuthMethod::Password, "Password"),
                            (AuthMethod::Agent, "ssh-agent"),
                        ],
                    );
                });
                match f.auth {
                    AuthMethod::Key => {
                        let hint = store::default_key_path().display().to_string();
                        field(ui, "Key file", |ui| {
                            ui.add(
                                TextEdit::singleline(&mut f.key_path)
                                    .hint_text(hint)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace),
                            );
                        });
                        field(ui, "Passphrase", |ui| {
                            let r = ui.add(
                                TextEdit::singleline(&mut self.passphrase)
                                    .password(true)
                                    .hint_text("only if the key is encrypted")
                                    .desired_width(f32::INFINITY),
                            );
                            if self.focus_secret {
                                r.request_focus();
                                self.focus_secret = false;
                            }
                        });
                    }
                    AuthMethod::Password => {
                        field(ui, "Password", |ui| {
                            let r = ui.add(
                                TextEdit::singleline(&mut self.password)
                                    .password(true)
                                    .desired_width(f32::INFINITY),
                            );
                            if self.focus_secret {
                                r.request_focus();
                                self.focus_secret = false;
                            }
                        });
                    }
                    AuthMethod::Agent => {
                        ui.label(w::faint("Uses the Windows OpenSSH agent or Pageant (SSH_AUTH_SOCK on Linux/macOS)."));
                    }
                }
                if let Some(e) = &self.error {
                    ui.label(RichText::new(format!("{} {e}", ph::WARNING)).color(WARN));
                }
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(w::faint("Saved to hosts.toml · passwords are never saved"));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                        let go = ui
                            .add(
                                egui::Button::new(RichText::new("Save & connect").color(BG0))
                                    .fill(ACC),
                            )
                            .clicked()
                            || enter;
                        if ui.button("Cancel").clicked()
                            || ui.input(|i| i.key_pressed(egui::Key::Escape))
                        {
                            close = true;
                        }
                        if go {
                            match self.build() {
                                Ok((config, auth)) => {
                                    outcome = ConnectOutcome::Connect {
                                        config: Box::new(config),
                                        auth,
                                    };
                                    close = true;
                                }
                                Err(e) => self.error = Some(e),
                            }
                        }
                    });
                });
            },
        );
        if close {
            *self = Self::default();
        }
        outcome
    }

    fn build(&mut self) -> Result<(HostConfig, AuthSpec), String> {
        let mut c = self.form.clone();
        c.name = c.name.trim().to_owned();
        c.address = c.address.trim().to_owned();
        c.user = c.user.trim().to_owned();
        c.key_path = c.key_path.trim().to_owned();
        c.port = self
            .port_text
            .trim()
            .parse()
            .map_err(|_| "Port must be a number 1–65535".to_owned())?;
        c.validate()?;
        let auth = match c.auth {
            AuthMethod::Agent => AuthSpec::Agent,
            AuthMethod::Password => {
                if self.password.is_empty() {
                    return Err("Enter the password".into());
                }
                AuthSpec::Password(SecretString::from(std::mem::take(&mut self.password)))
            }
            AuthMethod::Key => {
                let path = if c.key_path.is_empty() {
                    store::default_key_path()
                } else {
                    c.key_path.clone().into()
                };
                if !path.exists() {
                    return Err(format!("Key file not found: {}", path.display()));
                }
                let passphrase = (!self.passphrase.is_empty())
                    .then(|| SecretString::from(std::mem::take(&mut self.passphrase)));
                AuthSpec::KeyFile { path, passphrase }
            }
        };
        Ok((c, auth))
    }
}

// ─────────────────────────────── Host key ───────────────────────────────

pub struct HostKeyPrompt {
    pub host: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub status: HostKeyStatus,
    confirm_text: String,
}

impl HostKeyPrompt {
    pub fn new(
        host: String,
        algorithm: String,
        fingerprint: String,
        status: HostKeyStatus,
    ) -> Self {
        Self {
            host,
            algorithm,
            fingerprint,
            status,
            confirm_text: String::new(),
        }
    }

    pub fn show(&mut self, ctx: &egui::Context) -> Option<KeyDecision> {
        let changed = matches!(self.status, HostKeyStatus::Changed { .. });
        let (title, icon) = if changed {
            ("HOST KEY CHANGED", ph::WARNING)
        } else {
            ("Unknown host key", ph::KEY)
        };
        modal(ctx, "hostkey", title, icon, 540.0, |ui| {
            let mut out = None;
            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                out = Some(KeyDecision::Reject);
            }
            if let HostKeyStatus::Changed { file, line } = &self.status {
                ui.label(RichText::new(format!(
                    "The key presented by {} differs from the one recorded in {file} (line {line}). \
                     Someone may be intercepting the connection, or the server was reinstalled.",
                    self.host
                )).color(ERR));
            } else {
                ui.label(format!("{} has not been seen before. Compare the fingerprint with the one on the server:", self.host));
                ui.label(w::faint("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"));
            }
            egui::Frame::NONE.fill(BG0).corner_radius(3).inner_margin(egui::Margin::symmetric(10, 8)).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(w::mono(&self.algorithm, TX2));
                ui.label(w::mono(&self.fingerprint, TX0));
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if changed {
                        let ok = self.confirm_text.trim() == self.host;
                        if ui.add_enabled(ok, egui::Button::new(RichText::new("Connect once anyway").color(ERR))).clicked() {
                            out = Some(KeyDecision::Once);
                        }
                        ui.add(TextEdit::singleline(&mut self.confirm_text).hint_text(format!("type {} to enable", self.host)).desired_width(180.0));
                        if ui.add(egui::Button::new(RichText::new("Cancel").color(BG0)).fill(ACC)).clicked() {
                            out = Some(KeyDecision::Reject);
                        }
                    } else {
                        if ui.add(egui::Button::new(RichText::new("Trust and remember").color(BG0)).fill(ACC)).clicked() {
                            out = Some(KeyDecision::Trust);
                        }
                        if ui.button("Connect once").clicked() {
                            out = Some(KeyDecision::Once);
                        }
                        if ui.button("Cancel").clicked() {
                            out = Some(KeyDecision::Reject);
                        }
                    }
                });
            });
            out
        })
        .flatten()
    }
}

// ─────────────────────────────── Auth retry ───────────────────────────────

pub struct AuthPrompt {
    pub host: String,
    pub message: String,
    pub method: AuthMethod,
    pub key_path: String,
    secret: String,
    focus: bool,
}

pub enum AuthOutcome {
    None,
    Retry(AuthSpec),
    Cancel,
}

impl AuthPrompt {
    pub fn new(host: String, message: String, method: AuthMethod, key_path: String) -> Self {
        Self {
            host,
            message,
            method,
            key_path,
            secret: String::new(),
            focus: true,
        }
    }

    pub fn show(&mut self, ctx: &egui::Context) -> AuthOutcome {
        modal(
            ctx,
            "auth",
            "Authentication failed",
            ph::LOCK_KEY,
            480.0,
            |ui| {
                ui.label(RichText::new(&self.message).color(WARN));
                let label = match self.method {
                    AuthMethod::Password => "Password",
                    AuthMethod::Key => "Key passphrase",
                    AuthMethod::Agent => "",
                };
                if self.method != AuthMethod::Agent {
                    field(ui, label, |ui| {
                        let r = ui.add(
                            TextEdit::singleline(&mut self.secret)
                                .password(true)
                                .desired_width(f32::INFINITY),
                        );
                        if self.focus {
                            r.request_focus();
                            self.focus = false;
                        }
                    });
                }
                let mut out = AuthOutcome::None;
                ui.horizontal(|ui| {
                    ui.label(w::faint(format!("Host: {}", self.host)));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if ui
                            .add(egui::Button::new(RichText::new("Retry").color(BG0)).fill(ACC))
                            .clicked()
                            || enter
                        {
                            let s = SecretString::from(std::mem::take(&mut self.secret));
                            out = AuthOutcome::Retry(match self.method {
                                AuthMethod::Password => AuthSpec::Password(s),
                                AuthMethod::Agent => AuthSpec::Agent,
                                AuthMethod::Key => {
                                    let path = if self.key_path.is_empty() {
                                        store::default_key_path()
                                    } else {
                                        self.key_path.clone().into()
                                    };
                                    let passphrase = if crate::dialogs::is_empty_secret(&s) {
                                        None
                                    } else {
                                        Some(s)
                                    };
                                    AuthSpec::KeyFile { path, passphrase }
                                }
                            });
                        }
                        if ui.button("Close host").clicked() {
                            out = AuthOutcome::Cancel;
                        }
                    });
                });
                out
            },
        )
        .unwrap_or(AuthOutcome::None)
    }
}

fn is_empty_secret(s: &SecretString) -> bool {
    use secrecy::ExposeSecret;
    s.expose_secret().is_empty()
}

// ─────────────────────────────── Sudo password ───────────────────────────────

pub struct SudoPrompt {
    pub host: String,
    message: Option<String>,
    attempts_left: u8,
    secret: String,
    focus: bool,
}

pub enum SudoOutcome {
    None,
    Submit(SecretString),
    Skip,
}

impl SudoPrompt {
    pub fn new(host: String, message: Option<String>, attempts_left: u8) -> Self {
        Self {
            host,
            message,
            attempts_left,
            secret: String::new(),
            focus: true,
        }
    }

    pub fn show(&mut self, ctx: &egui::Context) -> SudoOutcome {
        modal(ctx, "sudo", "Sudo password", ph::SHIELD_WARNING, 480.0, |ui| {
            ui.label(format!(
                "Some panels (firewall, fail2ban, root-only logs) and service actions need sudo on {}.",
                self.host
            ));
            if let Some(m) = &self.message {
                ui.label(RichText::new(format!("{} {m} — {} attempt(s) left", ph::WARNING, self.attempts_left)).color(WARN));
            }
            field(ui, "Password", |ui| {
                let r = ui.add(TextEdit::singleline(&mut self.secret).password(true).desired_width(f32::INFINITY));
                if self.focus {
                    r.request_focus();
                    self.focus = false;
                }
            });
            let mut out = SudoOutcome::None;
            ui.horizontal(|ui| {
                ui.label(w::faint("Kept in memory for this session only — never saved."));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter)) && !self.secret.is_empty();
                    let ok = ui.add_enabled(!self.secret.is_empty(), egui::Button::new(RichText::new("Verify").color(BG0)).fill(ACC));
                    if ok.clicked() || enter {
                        out = SudoOutcome::Submit(SecretString::from(std::mem::take(&mut self.secret)));
                    }
                    if ui.button("Skip").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                        out = SudoOutcome::Skip;
                    }
                });
            });
            out
        })
        .unwrap_or(SudoOutcome::None)
    }
}

// ─────────────────────────────── Watched services ───────────────────────────────

#[derive(Default)]
pub struct ServicePicker {
    pub open: bool,
    filter: String,
    selected: std::collections::BTreeSet<String>,
    mode: sw_core::config::ServiceMode,
    poll: String,
}

pub enum PickerOutcome {
    None,
    Apply {
        units: Vec<String>,
        mode: sw_core::config::ServiceMode,
        poll_secs: u32,
    },
}

impl ServicePicker {
    pub fn open_with(
        &mut self,
        current: &[String],
        mode: sw_core::config::ServiceMode,
        poll_secs: u32,
    ) {
        *self = Self {
            open: true,
            filter: String::new(),
            selected: current.iter().cloned().collect(),
            mode,
            poll: poll_secs.to_string(),
        };
    }

    pub fn show(
        &mut self,
        ctx: &egui::Context,
        units: &[sw_core::model::UnitInfo],
        host: &str,
    ) -> PickerOutcome {
        use sw_core::config::ServiceMode;
        if !self.open {
            return PickerOutcome::None;
        }
        let mut out = PickerOutcome::None;
        let mut close = false;
        modal(
            ctx,
            "services",
            &format!("Watched services — {host}"),
            ph::GEAR_FINE,
            600.0,
            |ui| {
                ui.add(
                    TextEdit::singleline(&mut self.filter)
                        .hint_text(format!(
                            "{} Filter {} units…",
                            ph::MAGNIFYING_GLASS,
                            units.len()
                        ))
                        .desired_width(f32::INFINITY),
                );
                let q = self.filter.to_ascii_lowercase();
                // Units from the host, plus watched ones the host didn't list (e.g. not loaded right now).
                let mut rows: Vec<(String, String, String)> = units
                    .iter()
                    .map(|u| (u.name.clone(), u.active.clone(), u.description.clone()))
                    .collect();
                for s in &self.selected {
                    if !rows.iter().any(|r| &r.0 == s) {
                        rows.push((s.clone(), "unknown".into(), String::new()));
                    }
                }
                // Watched first, then failed, then by name.
                rows.sort_by_key(|r| (!self.selected.contains(&r.0), r.1 != "failed", r.0.clone()));
                rows.retain(|r| {
                    q.is_empty()
                        || r.0.to_ascii_lowercase().contains(&q)
                        || r.2.to_ascii_lowercase().contains(&q)
                });
                if units.is_empty() {
                    ui.label(w::faint("Loading the unit list from the host…"));
                }
                egui::ScrollArea::vertical()
                    .max_height(300.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        for (name, active, desc) in &rows {
                            let on = self.selected.contains(name);
                            let (r, resp) = ui.allocate_exact_size(
                                vec2(ui.available_width(), 28.0),
                                egui::Sense::click(),
                            );
                            let p = ui.painter();
                            if on {
                                p.rect_filled(r, 3, ACC_DIM);
                            } else if resp.hovered() {
                                p.rect_filled(r, 3, BG2);
                            }
                            let cb = egui::Rect::from_center_size(
                                egui::pos2(r.left() + 14.0, r.center().y),
                                vec2(13.0, 13.0),
                            );
                            p.rect_stroke(
                                cb,
                                3,
                                egui::Stroke::new(1.0, if on { ACC } else { LINE2 }),
                                egui::StrokeKind::Inside,
                            );
                            if on {
                                p.text(
                                    cb.center(),
                                    Align2::CENTER_CENTER,
                                    ph::CHECK,
                                    crate::theme::prop(11.0),
                                    ACC,
                                );
                            }
                            p.text(
                                egui::pos2(r.left() + 30.0, r.center().y),
                                Align2::LEFT_CENTER,
                                name,
                                crate::theme::mono(12.0),
                                TX0,
                            );
                            let (fg, label) = match active.as_str() {
                                "active" => (OK, "active"),
                                "failed" => (ERR, "failed"),
                                "inactive" => (TX3, "inactive"),
                                _ => (TX3, active.as_str()),
                            };
                            p.text(
                                egui::pos2(r.right() - 8.0, r.center().y),
                                Align2::RIGHT_CENTER,
                                label,
                                crate::theme::prop(10.5),
                                fg,
                            );
                            if !desc.is_empty() {
                                let d: String = desc.chars().take(40).collect();
                                p.text(
                                    egui::pos2(r.left() + 250.0, r.center().y),
                                    Align2::LEFT_CENTER,
                                    d,
                                    crate::theme::prop(11.0),
                                    TX3,
                                );
                            }
                            if resp.clicked() {
                                if on {
                                    self.selected.remove(name);
                                } else {
                                    self.selected.insert(name.clone());
                                }
                            }
                        }
                    });
                ui.add_space(6.0);
                field(ui, "Status updates", |ui| {
                    segmented(
                        ui,
                        &mut self.mode,
                        &[
                            (ServiceMode::Live, "Live (event-driven)"),
                            (ServiceMode::Poll, "Poll"),
                            (ServiceMode::Manual, "Manual"),
                        ],
                    );
                    if self.mode == ServiceMode::Poll {
                        ui.add(TextEdit::singleline(&mut self.poll).desired_width(40.0));
                        ui.label(w::dim("s"));
                    }
                });
                let cost = match self.mode {
                    ServiceMode::Live => {
                        "Follows systemd's own journal messages about these units on the same connection — near-zero cost while nothing changes. Memory/CPU per service still refresh every 10 s."
                    }
                    ServiceMode::Poll => {
                        "One batched `systemctl show` for all watched units per interval."
                    }
                    ServiceMode::Manual => {
                        "Status only when you open the section or press refresh. Zero background cost."
                    }
                };
                ui.label(w::faint(cost));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(w::faint(format!(
                        "{} watched · saved per host in hosts.toml",
                        self.selected.len()
                    )));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(egui::Button::new(RichText::new("Apply").color(BG0)).fill(ACC))
                            .clicked()
                        {
                            out = PickerOutcome::Apply {
                                units: self.selected.iter().cloned().collect(),
                                mode: self.mode,
                                poll_secs: self.poll.trim().parse().unwrap_or(30).clamp(5, 3600),
                            };
                            close = true;
                        }
                        if ui.button("Cancel").clicked()
                            || ui.input(|i| i.key_pressed(egui::Key::Escape))
                        {
                            close = true;
                        }
                    });
                });
            },
        );
        if close {
            self.open = false;
        }
        out
    }
}

// ─────────────────────────────── Log sources ───────────────────────────────

#[derive(Default)]
pub struct LogSourcesDialog {
    pub open: bool,
    selected: Vec<sw_core::config::LogSourceConfig>,
    custom: String,
    custom_sudo: bool,
    backlog: u32,
    cap: u32,
    error: Option<String>,
}

pub enum LogsOutcome {
    None,
    Apply {
        sources: Vec<sw_core::config::LogSourceConfig>,
        backlog: u32,
        cap: u32,
    },
}

impl LogSourcesDialog {
    pub fn open_with(
        &mut self,
        current: &[sw_core::config::LogSourceConfig],
        backlog: u32,
        cap: u32,
    ) {
        *self = Self {
            open: true,
            selected: current.to_vec(),
            backlog,
            cap,
            ..Default::default()
        };
    }

    fn toggle(&mut self, kind: &str, target: &str, id: &str, preset: sw_core::logs::Preset) {
        if let Some(i) = self.selected.iter().position(|s| s.target == target) {
            self.selected.remove(i);
        } else {
            let color = (0..u8::MAX)
                .find(|c| !self.selected.iter().any(|s| s.color == *c))
                .unwrap_or(0);
            self.selected.push(sw_core::config::LogSourceConfig {
                id: id.to_owned(),
                kind: kind.to_owned(),
                target: target.to_owned(),
                preset: (kind != "journal").then(|| preset.name().to_owned()),
                color,
            });
        }
    }

    pub fn show(
        &mut self,
        ctx: &egui::Context,
        candidates: &[sw_core::logs::LogCandidate],
        host: &str,
    ) -> LogsOutcome {
        if !self.open {
            return LogsOutcome::None;
        }
        let mut out = LogsOutcome::None;
        let mut close = false;
        modal(
            ctx,
            "logsrc",
            &format!("Log sources — {host}"),
            ph::SCROLL,
            620.0,
            |ui| {
                ui.label(w::faint(
                "Discovered on the host: running services (journal) and log files under /var/log. \
                 All selected sources stream over at most three channels of this connection.",
            ));
                // Candidates + selected sources the host didn't list.
                let mut rows: Vec<(String, String, String, sw_core::logs::Preset)> = candidates
                    .iter()
                    .map(|c| (c.kind.clone(), c.target.clone(), c.id.clone(), c.preset))
                    .collect();
                for s in &self.selected {
                    if !rows.iter().any(|r| r.1 == s.target) {
                        let p = sw_core::logs::Preset::from_name(s.preset.as_deref().unwrap_or(""));
                        rows.push((s.kind.clone(), s.target.clone(), s.id.clone(), p));
                    }
                }
                rows.sort_by_key(|r| {
                    (
                        !self.selected.iter().any(|s| s.target == r.1),
                        r.0 != "journal",
                        r.1.clone(),
                    )
                });
                if candidates.is_empty() {
                    ui.label(w::faint("Discovering sources on the host…"));
                } else {
                    ui.label(w::faint(format!(
                        "{} sources found on the host",
                        candidates.len()
                    )));
                }
                let mut toggled = None;
                egui::ScrollArea::vertical()
                    .max_height(300.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        for (kind, target, id, preset) in &rows {
                            let on = self.selected.iter().any(|s| &s.target == target);
                            let (r, resp) = ui.allocate_exact_size(
                                vec2(ui.available_width(), 28.0),
                                egui::Sense::click(),
                            );
                            let p = ui.painter();
                            if on {
                                p.rect_filled(r, 3, ACC_DIM);
                            } else if resp.hovered() {
                                p.rect_filled(r, 3, BG2);
                            }
                            let cb = egui::Rect::from_center_size(
                                egui::pos2(r.left() + 14.0, r.center().y),
                                vec2(13.0, 13.0),
                            );
                            p.rect_stroke(
                                cb,
                                3,
                                egui::Stroke::new(1.0, if on { ACC } else { LINE2 }),
                                egui::StrokeKind::Inside,
                            );
                            if on {
                                p.text(
                                    cb.center(),
                                    Align2::CENTER_CENTER,
                                    ph::CHECK,
                                    crate::theme::prop(11.0),
                                    ACC,
                                );
                            }
                            p.text(
                                egui::pos2(r.left() + 30.0, r.center().y),
                                Align2::LEFT_CENTER,
                                id,
                                crate::theme::mono(12.0),
                                TX0,
                            );
                            let t: String = target
                                .chars()
                                .rev()
                                .take(46)
                                .collect::<Vec<_>>()
                                .into_iter()
                                .rev()
                                .collect();
                            p.text(
                                egui::pos2(r.left() + 170.0, r.center().y),
                                Align2::LEFT_CENTER,
                                t,
                                crate::theme::mono(11.0),
                                TX3,
                            );
                            let (badge, fg) = match kind.as_str() {
                                "journal" => ("JOURNAL", INFO),
                                "sudo-file" => ("SUDO", WARN),
                                _ => ("FILE", TX2),
                            };
                            p.text(
                                egui::pos2(r.right() - 8.0, r.center().y),
                                Align2::RIGHT_CENTER,
                                badge,
                                crate::theme::prop(10.0),
                                fg,
                            );
                            if resp.clicked() {
                                toggled = Some((kind.clone(), target.clone(), id.clone(), *preset));
                            }
                        }
                    });
                if let Some((k, t, i, p)) = toggled {
                    self.toggle(&k, &t, &i, p);
                }
                ui.add_space(6.0);
                field(ui, "Custom file", |ui| {
                    ui.add(
                        TextEdit::singleline(&mut self.custom)
                            .hint_text("/opt/app/logs/app.log")
                            .desired_width(300.0)
                            .font(egui::TextStyle::Monospace),
                    );
                    ui.checkbox(&mut self.custom_sudo, "needs sudo");
                    if ui.button("Add").clicked() {
                        let path = self.custom.trim().to_owned();
                        if sw_core::shell::is_valid_path(&path)
                            && !self.selected.iter().any(|s| s.target == path)
                        {
                            let id = path
                                .rsplit('/')
                                .next()
                                .unwrap_or(&path)
                                .trim_end_matches(".log")
                                .to_owned();
                            let kind = if self.custom_sudo {
                                "sudo-file"
                            } else {
                                "file"
                            };
                            self.toggle(kind, &path, &id, sw_core::logs::Preset::Generic);
                            self.custom.clear();
                            self.error = None;
                        } else {
                            self.error = Some("Enter an absolute path (starting with /)".into());
                        }
                    }
                });
                if let Some(e) = &self.error {
                    ui.label(RichText::new(e).color(WARN));
                }
                field(ui, "Initial backlog", |ui| {
                    segmented(
                        ui,
                        &mut self.backlog,
                        &[(50, "50"), (200, "200"), (1000, "1000 lines")],
                    );
                });
                field(ui, "Keep in memory", |ui| {
                    segmented(
                        ui,
                        &mut self.cap,
                        &[(2_000, "2k"), (10_000, "10k"), (50_000, "50k lines")],
                    );
                });
                ui.horizontal(|ui| {
                    ui.label(w::faint(format!(
                        "{} selected · saved per host in hosts.toml",
                        self.selected.len()
                    )));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(egui::Button::new(RichText::new("Apply").color(BG0)).fill(ACC))
                            .clicked()
                        {
                            out = LogsOutcome::Apply {
                                sources: self.selected.clone(),
                                backlog: self.backlog,
                                cap: self.cap,
                            };
                            close = true;
                        }
                        if ui.button("Cancel").clicked()
                            || ui.input(|i| i.key_pressed(egui::Key::Escape))
                        {
                            close = true;
                        }
                    });
                });
            },
        );
        if close {
            self.open = false;
        }
        out
    }
}
