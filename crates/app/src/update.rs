//! Update checker (D-037). On start, one HTTPS GET of the website's
//! `releases/latest.json` on a short-lived thread; if it names a newer version
//! with an asset for this platform, the user gets Download / Close. Download
//! streams to the cache dir, checks size and SHA-256, then hands over to the
//! installer and exits. Leftover downloads are deleted on the next start.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use egui::{Align, Layout, RichText, Ui};
use egui_phosphor::regular as ph;
use serde::Deserialize;
use sha2::Digest as _;

use crate::theme::{self, tok::*};
use crate::widgets as w;

/// Published with the website (site/releases/latest.json); `SW_UPDATE_URL` overrides.
pub const LATEST_URL: &str = "https://securewire-app.pages.dev/releases/latest.json";
const MAX_JSON: u64 = 256 * 1024;
const MAX_DOWNLOAD: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
pub struct Latest {
    pub version: String,
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub notes: Vec<String>,
    /// Release page (fallback when this install can't update itself).
    #[serde(default)]
    pub page: String,
    pub assets: HashMap<String, Asset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Asset {
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

/// `latest.json` asset key for this build.
pub fn platform_key() -> &'static str {
    if cfg!(windows) {
        "windows-x86_64"
    } else if cfg!(target_os = "macos") {
        "macos-aarch64"
    } else {
        "linux-x86_64"
    }
}

fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim().trim_start_matches('v');
    let core = v.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((
        it.next()??,
        it.next().flatten().unwrap_or(0),
        it.next().flatten().unwrap_or(0),
    ))
}

pub fn is_newer(remote: &str, local: &str) -> bool {
    matches!((parse_version(remote), parse_version(local)), (Some(r), Some(l)) if r > l)
}

/// How this copy gets updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    /// Run the downloaded installer (silent when installed by it), then exit.
    Installer { silent: bool },
    /// Replace the running AppImage file, start it, exit.
    AppImage,
    /// Open the downloaded disk image, exit (the user drags the app over).
    Dmg,
    /// .deb / tar.gz / anything else: open the release page.
    Browser,
}

fn method() -> Method {
    if cfg!(windows) {
        let installed = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join("unins000.exe").exists()))
            .unwrap_or(false);
        Method::Installer { silent: installed }
    } else if cfg!(target_os = "macos") {
        Method::Dmg
    } else if std::env::var_os("APPIMAGE").is_some() {
        Method::AppImage
    } else {
        Method::Browser
    }
}

fn updates_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("dev", "SecureWire", "SecureWire")
        .map(|d| d.cache_dir().join("updates"))
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_recv_response(Some(Duration::from_secs(20)))
        .user_agent(format!("SecureWire/{}", theme::VERSION))
        .https_only(true)
        .build()
        .into()
}

enum Msg {
    Available(Latest),
    Downloaded(PathBuf),
    Failed(String),
}

enum State {
    Idle,
    Offer,
    Downloading,
    Ready(PathBuf),
    Failed(String),
    Closed,
}

pub struct Updater {
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    latest: Option<Latest>,
    state: State,
    got: Arc<AtomicU64>,
    cancel: Arc<AtomicBool>,
    ctx: egui::Context,
    /// When the dialog first appeared: keys pressed before then (the Esc that closed
    /// another dialog, say) must not answer it.
    shown: Option<std::time::Instant>,
}

impl Updater {
    /// Start the check (and the cleanup of earlier downloads) unless disabled.
    pub fn start(ctx: &egui::Context, enabled: bool) -> Self {
        let (tx, rx) = channel();
        let u = Self {
            tx,
            rx,
            latest: None,
            state: State::Idle,
            got: Arc::default(),
            cancel: Arc::default(),
            ctx: ctx.clone(),
            shown: None,
        };
        let url = std::env::var("SW_UPDATE_URL").ok();
        // Debug builds only check when pointed at a test feed.
        let enabled = enabled
            && std::env::var_os("SW_NO_UPDATE_CHECK").is_none()
            && (url.is_some() || !cfg!(debug_assertions));
        let (tx, ctx) = (u.tx.clone(), ctx.clone());
        let _ = std::thread::Builder::new()
            .name("update-check".into())
            .spawn(move || {
                if enabled {
                    match check(url.as_deref().unwrap_or(LATEST_URL)) {
                        Ok(Some(l)) => {
                            let _ = tx.send(Msg::Available(l));
                            ctx.request_repaint();
                        }
                        Ok(None) => {}
                        Err(e) => eprintln!("update check: {e}"),
                    }
                }
                sweep();
            });
        u
    }

    fn asset(&self) -> Option<&Asset> {
        self.latest.as_ref()?.assets.get(platform_key())
    }

    fn download(&mut self) {
        let Some(asset) = self.asset().cloned() else {
            return;
        };
        if method() == Method::Browser {
            let page = self
                .latest
                .as_ref()
                .map(|l| l.page.clone())
                .unwrap_or_default();
            open_url(if page.is_empty() { &asset.url } else { &page });
            self.state = State::Closed;
            return;
        }
        self.state = State::Downloading;
        self.got.store(0, Ordering::Relaxed);
        self.cancel.store(false, Ordering::Relaxed);
        let (tx, ctx, got, cancel) = (
            self.tx.clone(),
            self.ctx.clone(),
            self.got.clone(),
            self.cancel.clone(),
        );
        let _ = std::thread::Builder::new()
            .name("update-download".into())
            .spawn(move || {
                let r = fetch(&asset, &got, &cancel, &ctx);
                let _ = tx.send(match r {
                    Ok(p) => Msg::Downloaded(p),
                    Err(e) => Msg::Failed(e),
                });
                ctx.request_repaint();
            });
    }

    /// Hand over to the new version. `true` = the app should close now.
    fn install(&mut self, path: &Path) -> bool {
        match run_installer(path, method()) {
            Ok(close) => close,
            Err(e) => {
                self.state = State::Failed(e);
                false
            }
        }
    }

    /// Draw the dialog when there is something to show. Returns true when the app must exit
    /// so the installer can replace it. `busy`: another dialog is open; a new offer waits.
    pub fn show(&mut self, ctx: &egui::Context, busy: bool) -> bool {
        for m in self.rx.try_iter() {
            match m {
                Msg::Available(l) => {
                    self.latest = Some(l);
                    self.state = State::Offer;
                }
                Msg::Downloaded(p) => self.state = State::Ready(p),
                Msg::Failed(e) => {
                    if !matches!(self.state, State::Closed) {
                        self.state = State::Failed(e);
                    }
                }
            }
        }
        if matches!(self.state, State::Idle | State::Closed)
            || (busy && matches!(self.state, State::Offer))
        {
            return false;
        }
        let Some(latest) = self.latest.clone() else {
            return false;
        };
        let size = self.asset().map_or(0, |a| a.size);
        let mut act = None;
        crate::dialogs::modal(
            ctx,
            "update",
            "Update available",
            ph::ARROW_CIRCLE_UP,
            520.0,
            |ui| {
                ui.horizontal(|ui| {
                    ui.label(w::strong(format!("SecureWire {}", latest.version)).size(15.0));
                    if !latest.date.is_empty() {
                        ui.label(w::faint(sw_core::logs::sanitize(&latest.date)));
                    }
                });
                ui.label(w::dim(format!("You have version {}.", theme::VERSION)));
                if !latest.notes.is_empty() {
                    ui.add_space(4.0);
                    ui.label(w::meta("What's new"));
                    egui::Frame::NONE
                        .fill(BG0)
                        .stroke(egui::Stroke::new(1.0, LINE2))
                        .corner_radius(3)
                        .inner_margin(egui::Margin::symmetric(10, 8))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            egui::ScrollArea::vertical()
                                .max_height(180.0)
                                .show(ui, |ui| {
                                    for n in latest.notes.iter().take(20) {
                                        ui.horizontal_wrapped(|ui| {
                                            ui.label(RichText::new("•").color(ACC));
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(sw_core::logs::sanitize(n))
                                                        .color(TX1),
                                                )
                                                .wrap(),
                                            );
                                        });
                                    }
                                });
                        });
                }
                ui.add_space(4.0);
                act = self.body(ui, size);
            },
        );
        match act {
            Some(Act::Download) => self.download(),
            Some(Act::Close) => {
                self.cancel.store(true, Ordering::Relaxed);
                self.state = State::Closed;
            }
            Some(Act::Install(p)) => return self.install(&p),
            None => {}
        }
        if matches!(self.state, State::Downloading) {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
        false
    }

    fn body(&mut self, ui: &mut Ui, size: u64) -> Option<Act> {
        let mut act = None;
        let shown = *self.shown.get_or_insert_with(std::time::Instant::now);
        let settled = shown.elapsed() > Duration::from_millis(300);
        if !settled {
            ui.ctx().request_repaint_after(Duration::from_millis(320));
        }
        let mb = |b: u64| format!("{:.1} MB", b as f64 / 1e6);
        match &self.state {
            State::Offer => {
                let how = match method() {
                    Method::Installer { silent: true } => {
                        "SecureWire closes, installs the update and starts again."
                    }
                    Method::Installer { silent: false } => {
                        "The installer opens once the download is verified."
                    }
                    Method::AppImage => "The AppImage is replaced and restarted.",
                    Method::Dmg => "The disk image opens; drag SecureWire to Applications.",
                    Method::Browser => "Opens the release page to download the package you use.",
                };
                ui.label(w::faint(if method() == Method::Browser {
                    how.to_owned()
                } else {
                    format!(
                        "{} download · SHA-256 checked before install. {how}",
                        mb(size)
                    )
                }));
                buttons(ui, |ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new(format!("{}  Download", ph::DOWNLOAD_SIMPLE))
                                    .color(BG0),
                            )
                            .fill(ACC),
                        )
                        .clicked()
                    {
                        act = Some(Act::Download);
                    }
                    if ui.button("Close").clicked() || esc(ui, settled) {
                        act = Some(Act::Close);
                    }
                });
            }
            State::Downloading => {
                let got = self.got.load(Ordering::Relaxed);
                let f = if size > 0 {
                    got as f32 / size as f32
                } else {
                    0.0
                };
                w::bar(ui, ui.available_width(), 6.0, &[(f, ACC)]);
                ui.label(w::mono(
                    format!("{} / {} · {:.0} %", mb(got), mb(size), f * 100.0),
                    TX2,
                ));
                buttons(ui, |ui| {
                    if ui.button("Cancel").clicked() || esc(ui, settled) {
                        act = Some(Act::Close);
                    }
                });
            }
            State::Ready(p) => {
                ui.label(RichText::new(format!("{}  Download verified", ph::CHECK)).color(OK));
                let p = p.clone();
                buttons(ui, |ui| {
                    let label = if matches!(
                        method(),
                        Method::Installer { silent: true } | Method::AppImage
                    ) {
                        "Install and restart"
                    } else {
                        "Open installer"
                    };
                    if ui
                        .add(egui::Button::new(RichText::new(label).color(BG0)).fill(ACC))
                        .clicked()
                    {
                        act = Some(Act::Install(p));
                    }
                    if ui.button("Later").clicked() || esc(ui, settled) {
                        act = Some(Act::Close);
                    }
                });
            }
            State::Failed(e) => {
                ui.add(egui::Label::new(RichText::new(e).color(ERR)).wrap());
                let page = self
                    .latest
                    .as_ref()
                    .map(|l| l.page.clone())
                    .unwrap_or_default();
                buttons(ui, |ui| {
                    if ui.button("Retry").clicked() {
                        act = Some(Act::Download);
                    }
                    if !page.is_empty() && ui.button("Release page").clicked() {
                        open_url(&page);
                    }
                    if ui.button("Close").clicked() || esc(ui, settled) {
                        act = Some(Act::Close);
                    }
                });
            }
            State::Idle | State::Closed => {}
        }
        act
    }
}

enum Act {
    Download,
    Close,
    Install(PathBuf),
}

fn esc(ui: &Ui, settled: bool) -> bool {
    settled && ui.input(|i| i.key_pressed(egui::Key::Escape))
}

fn buttons(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    ui.add_space(4.0);
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), 28.0),
        Layout::right_to_left(Align::Center),
        add,
    );
}

/// Fetch and parse the feed; `Some` only for a newer version with an asset for this platform.
fn check(url: &str) -> Result<Option<Latest>, String> {
    // `SW_UPDATE_URL=file:<path>`: a local feed, for testing the dialog (downloads stay HTTPS).
    let text = if let Some(path) = url.strip_prefix("file:") {
        std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?
    } else {
        let mut resp = agent().get(url).call().map_err(|e| e.to_string())?;
        resp.body_mut()
            .with_config()
            .limit(MAX_JSON)
            .read_to_string()
            .map_err(|e| e.to_string())?
    };
    let l: Latest = serde_json::from_str(&text).map_err(|e| format!("latest.json: {e}"))?;
    let ok = is_newer(&l.version, theme::VERSION)
        && l.assets.get(platform_key()).is_some_and(|a| {
            a.url.starts_with("https://") && a.sha256.len() == 64 && a.size <= MAX_DOWNLOAD
        });
    Ok(ok.then_some(l))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Download `asset` into the updates dir, checking size and SHA-256 on the way.
fn fetch(
    asset: &Asset,
    got: &AtomicU64,
    cancel: &AtomicBool,
    ctx: &egui::Context,
) -> Result<PathBuf, String> {
    let dir = updates_dir().ok_or("No cache directory")?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let name = asset
        .url
        .rsplit('/')
        .next()
        .filter(|n| sw_core::files::is_valid_name(n) && !n.contains(['\\', ':']))
        .unwrap_or("securewire-update");
    let path = dir.join(name);
    let part = dir.join(format!("{name}.part"));
    let r = (|| {
        let mut resp = agent()
            .get(&asset.url)
            .call()
            .map_err(|e| format!("Download failed: {e}"))?;
        let mut body = resp.body_mut().with_config().limit(asset.size + 1).reader();
        let mut f = std::fs::File::create(&part).map_err(|e| e.to_string())?;
        let mut sha = sha2::Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut n_total = 0u64;
        let mut last = std::time::Instant::now();
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err("Cancelled".to_owned());
            }
            let n = body
                .read(&mut buf)
                .map_err(|e| format!("Download failed: {e}"))?;
            if n == 0 {
                break;
            }
            sha.update(&buf[..n]);
            f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            n_total += n as u64;
            got.store(n_total, Ordering::Relaxed);
            if last.elapsed() > Duration::from_millis(200) {
                last = std::time::Instant::now();
                ctx.request_repaint();
            }
        }
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        if n_total != asset.size {
            return Err(format!(
                "Download is {n_total} bytes, expected {} — not installed",
                asset.size
            ));
        }
        if !hex(&sha.finalize()).eq_ignore_ascii_case(asset.sha256.trim()) {
            return Err("SHA-256 does not match the published hash — not installed".into());
        }
        std::fs::rename(&part, &path).map_err(|e| e.to_string())?;
        Ok(path.clone())
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    r
}

/// Start the new version's installer. Ok(true) = exit now.
fn run_installer(path: &Path, m: Method) -> Result<bool, String> {
    use std::process::Command;
    let fail = |e: std::io::Error| format!("Could not start the installer: {e}");
    match m {
        Method::Installer { silent } => {
            // `/RELAUNCH=1` makes the installer start SecureWire again when it is done
            // (packaging/windows/securewire.iss); that start removes the downloaded file.
            let mut c = Command::new(path);
            if silent {
                c.args([
                    "/SILENT",
                    "/SUPPRESSMSGBOXES",
                    "/NORESTART",
                    "/CLOSEAPPLICATIONS",
                    "/SP-",
                ]);
            }
            c.arg("/RELAUNCH=1").spawn().map_err(fail)?;
            Ok(true)
        }
        Method::AppImage => {
            let target = PathBuf::from(std::env::var_os("APPIMAGE").ok_or("Not an AppImage")?);
            let new = target.with_extension("new");
            std::fs::copy(path, &new).map_err(|e| format!("{}: {e}", new.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755));
            }
            std::fs::rename(&new, &target).map_err(|e| format!("{}: {e}", target.display()))?;
            let _ = std::fs::remove_file(path);
            Command::new(&target).spawn().map_err(fail)?;
            Ok(true)
        }
        Method::Dmg => {
            Command::new("open").arg(path).spawn().map_err(fail)?;
            Ok(true)
        }
        Method::Browser => Ok(false),
    }
}

/// Remove downloads from earlier updates. The installer that started this process may
/// still be finishing, so locked files are retried for a while.
fn sweep() {
    let Some(dir) = updates_dir() else { return };
    for _ in 0..20 {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return;
        };
        let mut left = 0;
        for e in rd.flatten() {
            if std::fs::remove_file(e.path()).is_err() {
                left += 1;
            }
        }
        if left == 0 {
            let _ = std::fs::remove_dir(&dir);
            return;
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// Open an https URL in the default browser (not through a shell).
pub fn open_url(url: &str) {
    if !url.starts_with("https://") {
        return;
    }
    let r = if cfg!(windows) {
        std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .spawn()
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("open").arg(url).spawn()
    } else {
        std::process::Command::new("xdg-open").arg(url).spawn()
    };
    let _ = r;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(is_newer("1.1.0", "1.0.0"));
        assert!(is_newer("v2.0", "1.9.9"));
        assert!(is_newer("1.0.10", "1.0.9"));
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("0.9.0", "1.0.0"));
        assert!(!is_newer("garbage", "1.0.0"));
        assert!(!is_newer("1.0.0-rc1", "1.0.0"));
    }

    #[test]
    fn feed_parses() {
        let l: Latest =
            serde_json::from_str(include_str!("../../../site/releases/latest.json")).unwrap();
        assert!(parse_version(&l.version).is_some());
        for k in ["windows-x86_64", "linux-x86_64", "macos-aarch64"] {
            let a = &l.assets[k];
            assert!(a.url.starts_with("https://github.com/") && a.url.contains(&l.version));
            assert_eq!(a.sha256.len(), 64);
            assert!(a.size > 0);
        }
    }
}
