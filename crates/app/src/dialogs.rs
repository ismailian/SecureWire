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
        .fixed_size(vec2(width, 0.0))
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
