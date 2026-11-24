//! Files tab (ui-spec §3.7): a browser for the server's file system.
//!
//! - Copy / cut / paste between server folders runs plain `cp` / `mv` on the server.
//! - Upload (a native file picker, files pasted from Explorer, or a drop from the
//!   desktop) and Download (a native folder picker) are SCP transfers on the same
//!   SSH connection (protocol §15).
//!
//! The UI thread never touches the disk or blocks: native dialogs and the local
//! name-clash checks run on short-lived helper threads.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Instant;

use egui::{Align, Align2, Layout, RichText, Sense, Ui, pos2, vec2};
use egui_phosphor::regular as ph;
use sw_core::actions::Action;
use sw_core::files::{self as rfs, FsOp, Pair};
use sw_core::format;
use sw_ssh::api::{Command, DownloadItem, TransferProgress, TransferSpec, TransferState};

use crate::state::Request;
use crate::theme::{self, tok::*};
use crate::widgets as w;

const ROW_H: f32 = 24.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Col {
    Name,
    Size,
    Modified,
}

#[derive(Debug, Clone)]
struct Row {
    name: String,
    display: String,
    is_dir: bool,
    link: bool,
    size: u64,
    mtime: i64,
    mode: u32,
    owner: String,
}

/// The server folder on screen.
struct Pane {
    path: String,
    rows: Vec<Row>,
    /// Indices into `rows` that are drawn (hidden files filtered), in sort order.
    view: Vec<usize>,
    sel: HashSet<String>,
    anchor: Option<usize>,
    loading: bool,
    error: Option<String>,
    sort: (Col, bool),
    show_hidden: bool,
    editing: Option<String>,
    back: Vec<String>,
    pending: u64,
}

impl Pane {
    fn new() -> Self {
        Self {
            path: String::new(),
            rows: vec![],
            view: vec![],
            sel: HashSet::new(),
            anchor: None,
            loading: false,
            error: None,
            sort: (Col::Name, true),
            show_hidden: true,
            editing: None,
            back: vec![],
            pending: 0,
        }
    }

    fn resort(&mut self) {
        let (col, asc) = self.sort;
        let rows = &self.rows;
        let mut v: Vec<usize> = (0..rows.len())
            .filter(|&i| self.show_hidden || !rows[i].name.starts_with('.'))
            .collect();
        v.sort_by(|&a, &b| {
            let (x, y) = (&rows[a], &rows[b]);
            // Folders first, whatever the column.
            y.is_dir.cmp(&x.is_dir).then_with(|| {
                let o = match col {
                    Col::Name => x.name.to_lowercase().cmp(&y.name.to_lowercase()),
                    Col::Size => x.size.cmp(&y.size),
                    Col::Modified => x.mtime.cmp(&y.mtime),
                };
                if asc { o } else { o.reverse() }
            })
        });
        self.view = v;
    }

    fn set_rows(&mut self, rows: Vec<Row>) {
        self.rows = rows;
        let names: HashSet<&str> = self.rows.iter().map(|r| r.name.as_str()).collect();
        self.sel.retain(|n| names.contains(n.as_str()));
        self.anchor = None;
        self.loading = false;
        self.error = None;
        self.resort();
    }

    fn selected(&self) -> Vec<&Row> {
        self.view
            .iter()
            .map(|&i| &self.rows[i])
            .filter(|r| self.sel.contains(&r.name))
            .collect()
    }

    fn has(&self, name: &str) -> bool {
        self.rows.iter().any(|r| r.name == name)
    }
}

/// What Copy / Cut put on the browser's clipboard (server files).
#[derive(Clone)]
struct Clip {
    dir: String,
    items: Vec<Row>,
    cut: bool,
}

struct TransferRow {
    id: u64,
    upload: bool,
    label: String,
    target: String,
    p: TransferProgress,
    rate: f64,
    last: (Instant, u64),
}

enum PromptKind {
    Mkdir,
    Rename(String),
}

struct Prompt {
    kind: PromptKind,
    text: String,
    error: Option<String>,
    opened: Instant,
}

/// A transfer or server copy, resolved to what it will do.
#[derive(Clone)]
enum Plan {
    RemoteCopy {
        items: Vec<Row>,
        from: String,
        to: String,
        cut: bool,
    },
    /// Local paths → server folder `to`.
    Upload {
        items: Vec<(PathBuf, String)>,
        to: String,
    },
    /// Server files in `from` → local folder `to` (`existing`: names already there).
    Download {
        items: Vec<Row>,
        from: String,
        to: PathBuf,
        existing: HashSet<String>,
    },
}

/// A plan whose names already exist at the destination.
struct Conflict {
    plan: Plan,
    names: Vec<String>,
}

/// Results from the helper threads (native dialogs, local checks).
enum Picked {
    Upload {
        paths: Vec<PathBuf>,
        to: String,
    },
    Download {
        items: Vec<Row>,
        from: String,
        to: PathBuf,
        existing: HashSet<String>,
    },
}

/// What the tab asks the app to do.
pub enum Out {
    Cmd(Command),
    Req(Request),
    Toast(String),
}

pub struct FilesTab {
    pane: Pane,
    clip: Option<Clip>,
    transfers: Vec<TransferRow>,
    prompt: Option<Prompt>,
    conflict: Option<Conflict>,
    next_id: u64,
    pick_tx: Sender<Picked>,
    pick_rx: Receiver<Picked>,
    /// A native dialog is open (one at a time).
    picking: bool,
    /// Last local folder used, where the pickers start.
    last_local: Option<PathBuf>,
    ctx: egui::Context,
    paste_key_down: bool,
    started: bool,
}

impl FilesTab {
    pub fn new(ctx: &egui::Context) -> Self {
        let (pick_tx, pick_rx) = channel();
        Self {
            pane: Pane::new(),
            clip: None,
            transfers: vec![],
            prompt: None,
            conflict: None,
            next_id: 1,
            pick_tx,
            pick_rx,
            picking: false,
            last_local: directories::UserDirs::new()
                .and_then(|u| u.download_dir().map(Path::to_path_buf)),
            ctx: ctx.clone(),
            paste_key_down: false,
            started: false,
        }
    }

    fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    pub fn has_modal(&self) -> bool {
        self.prompt.is_some() || self.conflict.is_some()
    }

    pub fn running_transfers(&self) -> usize {
        self.transfers
            .iter()
            .filter(|t| t.p.state == TransferState::Running)
            .count()
    }

    // ───────────────────────── listing ─────────────────────────

    fn list(&mut self, path: String, out: &mut Vec<Out>) {
        let id = self.id();
        self.pane.pending = id;
        self.pane.loading = true;
        out.push(Out::Cmd(Command::FsList { id, path }));
    }

    fn go(&mut self, path: String, out: &mut Vec<Out>) {
        if self.pane.path != path {
            let old = std::mem::replace(&mut self.pane.path, path.clone());
            self.pane.back.push(old);
            self.pane.sel.clear();
        }
        self.list(path, out);
    }

    pub fn refresh_remote(&mut self, out: &mut Vec<Out>) {
        let p = self.pane.path.clone();
        self.list(p, out);
    }

    pub fn on_listing(&mut self, id: u64, result: Result<rfs::Listing, String>) {
        if id != self.pane.pending {
            return;
        }
        match result {
            Ok(l) => {
                self.pane.path = l.path;
                let rows = l
                    .entries
                    .into_iter()
                    .map(|e| Row {
                        link: e.kind == rfs::Kind::Link,
                        name: e.name,
                        display: e.display,
                        is_dir: e.is_dir,
                        size: e.size,
                        mtime: e.mtime,
                        mode: e.mode,
                        owner: e.owner,
                    })
                    .collect();
                self.pane.set_rows(rows);
            }
            Err(e) => {
                self.pane.loading = false;
                self.pane.error = Some(e);
                // Stay where we were if the new folder can't be opened.
                if !self.pane.rows.is_empty()
                    && let Some(prev) = self.pane.back.pop()
                {
                    self.pane.path = prev;
                }
            }
        }
    }

    pub fn on_transfer(&mut self, id: u64, p: TransferProgress, out: &mut Vec<Out>) {
        let Some(t) = self.transfers.iter_mut().find(|t| t.id == id) else {
            return;
        };
        let now = Instant::now();
        let dt = now.duration_since(t.last.0).as_secs_f64();
        if dt > 0.5 {
            t.rate = p.bytes.saturating_sub(t.last.1) as f64 / dt;
            t.last = (now, p.bytes);
        }
        let ended = t.p.state == TransferState::Running && p.state != TransferState::Running;
        if let TransferState::Failed(e) = &p.state {
            out.push(Out::Toast(format!("{}  {}: {e}", ph::WARNING, t.label)));
        }
        let refresh = ended && t.upload && t.target == self.pane.path;
        t.p = p;
        if refresh {
            self.refresh_remote(out);
        }
    }

    // ───────────────────────── clipboard, upload, download ─────────────────────────

    fn copy(&mut self, cut: bool) {
        let items: Vec<Row> = self.pane.selected().into_iter().cloned().collect();
        if items.is_empty() {
            return;
        }
        // The paths also go on the system clipboard as text (handy in a terminal). That
        // clears any file list copied in Explorer, so a later paste knows which is newer.
        let text: Vec<String> = items
            .iter()
            .map(|r| rfs::join(&self.pane.path, &r.name))
            .collect();
        self.ctx.copy_text(text.join("\n"));
        self.clip = Some(Clip {
            dir: self.pane.path.clone(),
            items,
            cut,
        });
    }

    fn paste(&mut self, out: &mut Vec<Out>) {
        // Files copied in the system file manager (Windows) are newer than our own copy.
        let os = os_clipboard_files();
        if !os.is_empty() {
            let to = self.pane.path.clone();
            return self.upload_paths(os, to, out);
        }
        let Some(c) = self.clip.clone() else {
            return out.push(Out::Toast("Nothing to paste — copy files first".into()));
        };
        if c.cut {
            self.clip = None; // a cut pastes once
        }
        let to = self.pane.path.clone();
        self.start(
            Plan::RemoteCopy {
                items: c.items,
                from: c.dir,
                to,
                cut: c.cut,
            },
            vec![],
            out,
        );
    }

    fn upload_paths(&mut self, paths: Vec<PathBuf>, to: String, out: &mut Vec<Out>) {
        let items: Vec<(PathBuf, String)> = paths
            .into_iter()
            .filter_map(|p| {
                let name = p.file_name()?.to_str()?.to_owned();
                Some((p, name))
            })
            .collect();
        if items.is_empty() {
            return;
        }
        if let Some(d) = items.first().and_then(|(p, _)| p.parent()) {
            self.last_local = Some(d.to_path_buf());
        }
        // Clashes are known only for the folder on screen.
        let clash = if to == self.pane.path {
            items
                .iter()
                .filter(|(_, n)| self.pane.has(n))
                .map(|(_, n)| n.clone())
                .collect()
        } else {
            vec![]
        };
        self.start(Plan::Upload { items, to }, clash, out);
    }

    /// Native file picker (helper thread) → upload into `to`.
    fn pick_upload(&mut self, to: String, folders: bool) {
        if self.picking {
            return;
        }
        self.picking = true;
        let (tx, ctx, start) = (
            self.pick_tx.clone(),
            self.ctx.clone(),
            self.last_local.clone(),
        );
        let _ = std::thread::Builder::new()
            .name("files-pick".into())
            .spawn(move || {
                let mut d = rfd::FileDialog::new().set_title(if folders {
                    "Upload folders to the server"
                } else {
                    "Upload files to the server"
                });
                if let Some(s) = start {
                    d = d.set_directory(s);
                }
                let paths = if folders {
                    d.pick_folders()
                } else {
                    d.pick_files()
                };
                let _ = tx.send(Picked::Upload {
                    paths: paths.unwrap_or_default(),
                    to,
                });
                ctx.request_repaint();
            });
    }

    /// Native folder picker (helper thread) → download the selection there.
    fn pick_download(&mut self, out: &mut Vec<Out>) {
        let items: Vec<Row> = self.pane.selected().into_iter().cloned().collect();
        if items.is_empty() {
            return out.push(Out::Toast("Select files or folders to download".into()));
        }
        if self.picking {
            return;
        }
        self.picking = true;
        let from = self.pane.path.clone();
        let (tx, ctx, start) = (
            self.pick_tx.clone(),
            self.ctx.clone(),
            self.last_local.clone(),
        );
        let _ = std::thread::Builder::new()
            .name("files-pick".into())
            .spawn(move || {
                let mut d = rfd::FileDialog::new().set_title("Download to this folder");
                if let Some(s) = start {
                    d = d.set_directory(s);
                }
                let to = d.pick_folder().unwrap_or_default();
                // Names already in the folder, read here so the UI thread does no I/O.
                let existing = std::fs::read_dir(&to)
                    .map(|rd| {
                        rd.flatten()
                            .filter_map(|e| e.file_name().into_string().ok())
                            .collect()
                    })
                    .unwrap_or_default();
                let _ = tx.send(Picked::Download {
                    items,
                    from,
                    to,
                    existing,
                });
                ctx.request_repaint();
            });
    }

    /// Run, or ask about clashing names first.
    fn start(&mut self, plan: Plan, clash: Vec<String>, out: &mut Vec<Out>) {
        let clash = match &plan {
            Plan::RemoteCopy {
                items, from, to, ..
            } => {
                if from == to {
                    // Pasting into the same folder makes copies ("x (copy)"), never a clash.
                    return self.run(plan, false, out);
                }
                items
                    .iter()
                    .filter(|r| self.pane.has(&r.name))
                    .map(|r| r.name.clone())
                    .collect()
            }
            _ => clash,
        };
        if clash.is_empty() {
            self.run(plan, false, out);
        } else {
            self.conflict = Some(Conflict { plan, names: clash });
        }
    }

    /// `replace`: clashing names are replaced; otherwise they get "(copy)" names.
    fn run(&mut self, plan: Plan, replace: bool, out: &mut Vec<Out>) {
        match plan {
            Plan::RemoteCopy {
                items,
                from,
                to,
                cut,
            } => {
                let mut taken: HashSet<String> =
                    self.pane.rows.iter().map(|r| r.name.clone()).collect();
                let same = from == to;
                let pairs: Vec<Pair> = items
                    .iter()
                    .map(|r| {
                        let name = if replace && !same {
                            r.name.clone()
                        } else {
                            rfs::unique_name(&r.name, |n| taken.contains(n))
                        };
                        let clash = !same && self.pane.has(&name);
                        taken.insert(name.clone());
                        Pair {
                            src: rfs::join(&from, &r.name),
                            dst: rfs::join(&to, &name),
                            replace: replace && clash,
                        }
                    })
                    .collect();
                let op = if cut && !same {
                    FsOp::Move(pairs)
                } else {
                    FsOp::Copy(pairs)
                };
                out.push(Out::Req(Request::Run(Action::Files(op))));
            }
            Plan::Upload { items, to } => {
                let mut taken: HashSet<String> = if to == self.pane.path {
                    self.pane.rows.iter().map(|r| r.name.clone()).collect()
                } else {
                    HashSet::new()
                };
                let n = items.len();
                let first = items.first().map(|i| i.1.clone()).unwrap_or_default();
                let items: Vec<(PathBuf, String)> = items
                    .into_iter()
                    .map(|(p, name)| {
                        let name = if replace {
                            name
                        } else {
                            rfs::unique_name(&name, |n| taken.contains(n))
                        };
                        taken.insert(name.clone());
                        (p, name)
                    })
                    .collect();
                let id = self.id();
                self.push_transfer(id, true, n, &first, &to);
                out.push(Out::Cmd(Command::Transfer {
                    id,
                    spec: TransferSpec::Upload {
                        items,
                        remote_dir: to,
                    },
                }));
            }
            Plan::Download {
                items,
                from,
                to,
                existing,
            } => {
                let n = items.len();
                let first = items.first().map(|r| r.name.clone()).unwrap_or_default();
                let mut taken = existing;
                let items: Vec<DownloadItem> = items
                    .iter()
                    .map(|r| {
                        let name = if replace {
                            r.name.clone()
                        } else {
                            rfs::unique_name(&r.name, |n| taken.contains(n))
                        };
                        taken.insert(name.clone());
                        DownloadItem {
                            remote: rfs::join(&from, &r.name),
                            local_name: name,
                            is_dir: r.is_dir,
                            size: r.size,
                        }
                    })
                    .collect();
                self.last_local = Some(to.clone());
                let id = self.id();
                self.push_transfer(id, false, n, &first, &to.display().to_string());
                out.push(Out::Cmd(Command::Transfer {
                    id,
                    spec: TransferSpec::Download {
                        items,
                        local_dir: to,
                    },
                }));
            }
        }
    }

    fn push_transfer(&mut self, id: u64, upload: bool, n: usize, first: &str, target: &str) {
        let what = if n == 1 {
            sw_core::logs::sanitize(first)
        } else {
            format!("{n} items")
        };
        self.transfers.insert(
            0,
            TransferRow {
                id,
                upload,
                label: format!("{} {what}", if upload { "Upload" } else { "Download" }),
                target: target.to_owned(),
                p: TransferProgress {
                    bytes: 0,
                    total: None,
                    files: 0,
                    current: String::new(),
                    state: TransferState::Running,
                },
                rate: 0.0,
                last: (Instant::now(), 0),
            },
        );
        // Keep the strip short: drop finished transfers beyond the newest few.
        let mut finished = 0;
        self.transfers.retain(|t| {
            if t.p.state == TransferState::Running {
                return true;
            }
            finished += 1;
            finished <= 4
        });
    }

    fn delete(&mut self, out: &mut Vec<Out>) {
        let paths: Vec<String> = self
            .pane
            .selected()
            .iter()
            .map(|r| rfs::join(&self.pane.path, &r.name))
            .collect();
        if !paths.is_empty() {
            out.push(Out::Req(Request::Run(Action::Files(FsOp::Delete(paths)))));
        }
    }

    fn open_row(&mut self, i: usize, out: &mut Vec<Out>) {
        let Some(r) = self.pane.rows.get(i).cloned() else {
            return;
        };
        if r.is_dir {
            let p = rfs::join(&self.pane.path, &r.name);
            self.go(p, out);
        } else {
            self.pane.sel = HashSet::from([r.name]);
            self.pick_download(out);
        }
    }

    // ───────────────────────── drawing ─────────────────────────

    pub fn show(&mut self, ui: &mut Ui, connected: bool, interactive: bool) -> Vec<Out> {
        let mut out = Vec::new();
        if !self.started && connected {
            self.started = true;
            self.list(String::new(), &mut out);
        }
        for p in self.pick_rx.try_iter().collect::<Vec<_>>() {
            self.picking = false;
            match p {
                Picked::Upload { paths, to } => self.upload_paths(paths, to, &mut out),
                Picked::Download {
                    items,
                    from,
                    to,
                    existing,
                } => {
                    if !to.as_os_str().is_empty() {
                        let clash = items
                            .iter()
                            .filter(|r| existing.contains(&r.name))
                            .map(|r| r.name.clone())
                            .collect();
                        let plan = Plan::Download {
                            items,
                            from,
                            to,
                            existing,
                        };
                        self.start(plan, clash, &mut out);
                    }
                }
            }
        }

        let full = ui.available_rect_before_wrap();
        let strip_h = if self.transfers.is_empty() {
            0.0
        } else {
            (self.transfers.len().min(4) as f32) * 40.0 + 30.0
        };
        let pane = egui::Rect::from_min_max(full.min, pos2(full.right(), full.bottom() - strip_h));
        let mut c = ui.new_child(egui::UiBuilder::new().max_rect(pane).id_salt("files-pane"));
        c.set_clip_rect(pane);
        let drop_dir = self.pane_ui(&mut c, connected, &mut out);

        // Drops from the desktop upload into the open folder, or the folder row under them.
        let (hovering, dropped) = ui.input(|i| {
            (
                !i.raw.hovered_files.is_empty(),
                i.raw
                    .dropped_files
                    .iter()
                    .map(|f| f.path().to_path_buf())
                    .filter(|p| !p.as_os_str().is_empty())
                    .collect::<Vec<_>>(),
            )
        });
        if connected && hovering {
            let target = drop_dir.clone().unwrap_or_else(|| self.pane.path.clone());
            drop_hint(ui, pane, &target);
        }
        if connected && !dropped.is_empty() {
            let to = drop_dir.unwrap_or_else(|| self.pane.path.clone());
            self.upload_paths(dropped, to, &mut out);
        }
        if strip_h > 0.0 {
            let srect = egui::Rect::from_min_max(pos2(full.left(), pane.bottom()), full.max);
            let mut c = ui.new_child(egui::UiBuilder::new().max_rect(srect));
            self.transfers_ui(&mut c, &mut out);
        }
        ui.allocate_rect(full, Sense::hover());

        if interactive && !self.has_modal() && connected {
            self.keys(ui, &mut out);
        }
        self.dialogs(ui.ctx(), &mut out);
        out
    }

    fn keys(&mut self, ui: &Ui, out: &mut Vec<Out>) {
        if ui.ctx().egui_wants_keyboard_input() {
            return;
        }
        let (copy, cut, paste_ev, mods) = ui.input(|i| {
            let mut c = (false, false, false);
            for e in &i.events {
                match e {
                    egui::Event::Copy => c.0 = true,
                    egui::Event::Cut => c.1 = true,
                    egui::Event::Paste(_) => c.2 = true,
                    _ => {}
                }
            }
            (c.0, c.1, c.2, i.modifiers)
        });
        // A file-only clipboard produces no Paste event; watch the key itself on Windows.
        let paste = if cfg!(windows) {
            let v_down = mods.command && paste_key_pressed();
            let edge = v_down && !self.paste_key_down;
            self.paste_key_down = v_down;
            edge
        } else {
            paste_ev
        };
        if copy || cut {
            self.copy(cut);
        }
        if paste {
            self.paste(out);
        }
        let key = |k| ui.input_mut(|i| i.consume_key(egui::Modifiers::NONE, k));
        if key(egui::Key::F5) {
            self.refresh_remote(out);
        }
        if key(egui::Key::Backspace)
            && let Some(p) = rfs::parent(&self.pane.path)
        {
            self.go(p, out);
        }
        if key(egui::Key::Delete) {
            self.delete(out);
        }
        if key(egui::Key::F2)
            && let Some(r) = self.pane.selected().first()
        {
            self.prompt = Some(Prompt::new(PromptKind::Rename(r.name.clone()), &r.name));
        }
        if ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::A)) {
            let p = &mut self.pane;
            p.sel = p.view.iter().map(|&i| p.rows[i].name.clone()).collect();
        }
        let len = self.pane.view.len();
        if len == 0 {
            return;
        }
        let up = key(egui::Key::ArrowUp);
        let down = key(egui::Key::ArrowDown);
        if up || down {
            let p = &mut self.pane;
            let cur = p.anchor.unwrap_or(0);
            let n = if up {
                cur.saturating_sub(1)
            } else {
                (cur + 1).min(len - 1)
            };
            p.anchor = Some(n);
            p.sel = HashSet::from([p.rows[p.view[n]].name.clone()]);
        }
        if key(egui::Key::Enter)
            && let Some(a) = self.pane.anchor
        {
            let i = self.pane.view[a];
            self.open_row(i, out);
        }
    }

    /// Draw the folder; returns the folder row the pointer is over (a drop target).
    fn pane_ui(&mut self, ui: &mut Ui, connected: bool, out: &mut Vec<Out>) -> Option<String> {
        // ---- one bar: navigation · breadcrumbs · actions (icons only) ----
        self.bar(ui, connected, out);
        w::hline(ui);

        if !connected {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| ui.label(w::dim("Not connected")));
            return None;
        }

        // ---- column header ----
        let (cr, _) = ui.allocate_exact_size(vec2(ui.available_width(), 22.0), Sense::hover());
        let cols = columns(cr);
        let sort = self.pane.sort;
        for (col, label, x, right) in [
            (Some(Col::Name), "NAME", cols.name, false),
            (Some(Col::Size), "SIZE", cols.size, true),
            (Some(Col::Modified), "MODIFIED (UTC)", cols.modified, false),
            (None, "PERMISSIONS", cols.perms, false),
            (None, "OWNER", cols.owner, false),
        ] {
            if x.is_nan() {
                continue;
            }
            let text = match col {
                Some(c) if c == sort.0 => {
                    format!(
                        "{label} {}",
                        if sort.1 { ph::CARET_UP } else { ph::CARET_DOWN }
                    )
                }
                _ => label.to_owned(),
            };
            let anchor = if right {
                Align2::RIGHT_CENTER
            } else {
                Align2::LEFT_CENTER
            };
            let r = ui
                .painter()
                .text(pos2(x, cr.center().y), anchor, text, theme::prop(10.5), TX3);
            if let Some(c) = col {
                let resp =
                    ui.interact(r.expand(4.0), ui.id().with(("sort", label)), Sense::click());
                if resp.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                if resp.clicked() {
                    let p = &mut self.pane;
                    p.sort = if p.sort.0 == c {
                        (c, !p.sort.1)
                    } else {
                        (c, true)
                    };
                    p.resort();
                }
            }
        }
        w::hline(ui);

        // ---- rows ----
        let status_h = 22.0;
        if let Some(e) = &self.pane.error {
            egui::Frame::NONE
                .fill(ERR_TINT)
                .inner_margin(egui::Margin::symmetric(12, 6))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(format!("{}  {e}", ph::WARNING)).color(ERR_SOFT));
                });
        }
        let list_h = (ui.available_height() - status_h).max(ROW_H);
        let n = self.pane.view.len();
        let mut clicked: Option<(usize, egui::Modifiers)> = None;
        let mut opened: Option<usize> = None;
        let mut menu: Option<MenuAct> = None;
        let mut drop_dir = None;
        let hovering_files = ui.input(|i| !i.raw.hovered_files.is_empty());
        let list_rect =
            egui::Rect::from_min_size(ui.cursor().min, vec2(ui.available_width(), list_h));
        let list_resp = ui.interact(list_rect, ui.id().with("files-bg"), Sense::click());
        ui.allocate_ui(vec2(ui.available_width(), list_h), |ui| {
            egui::ScrollArea::vertical()
                .id_salt("files-rows")
                .auto_shrink(false)
                .max_height(list_h)
                .show_rows(ui, ROW_H, n, |ui, range| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    let p = &self.pane;
                    for vi in range {
                        let i = p.view[vi];
                        let r = &p.rows[i];
                        let (rect, resp) = ui
                            .allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::click());
                        let sel = p.sel.contains(&r.name);
                        let over = ui.rect_contains_pointer(rect);
                        let painter = ui.painter();
                        if hovering_files && r.is_dir && over {
                            painter.rect_filled(rect, 0, ACC_MID);
                            drop_dir = Some(rfs::join(&p.path, &r.name));
                        } else if sel {
                            painter.rect_filled(rect, 0, ACC_DIM);
                        } else if resp.hovered() {
                            painter.rect_filled(rect, 0, BG2);
                        }
                        draw_row(ui, rect, r, sel);
                        if resp.double_clicked() {
                            opened = Some(i);
                        } else if resp.clicked() || (resp.secondary_clicked() && !sel) {
                            clicked = Some((vi, ui.input(|i| i.modifiers)));
                        }
                        resp.context_menu(|ui| menu = row_menu(ui, r));
                    }
                });
        });
        // Empty space: clears the selection; its menu offers upload / new folder / paste.
        if list_resp.clicked() && clicked.is_none() && opened.is_none() {
            self.pane.sel.clear();
        }
        list_resp.context_menu(|ui| menu = folder_menu(ui, self.clip.is_some()));
        if let Some((vi, m)) = clicked {
            let p = &mut self.pane;
            let name = p.rows[p.view[vi]].name.clone();
            if m.shift
                && let Some(a) = p.anchor
            {
                let (lo, hi) = (a.min(vi), a.max(vi));
                p.sel = (lo..=hi).map(|k| p.rows[p.view[k]].name.clone()).collect();
            } else if m.command {
                if !p.sel.remove(&name) {
                    p.sel.insert(name);
                }
                p.anchor = Some(vi);
            } else {
                p.sel = HashSet::from([name]);
                p.anchor = Some(vi);
            }
        }
        if let Some(i) = opened {
            self.open_row(i, out);
        }
        if let Some(m) = menu {
            self.menu_act(m, out);
        }

        // ---- status line ----
        let p = &self.pane;
        let sel = p.selected();
        let bytes: u64 = sel.iter().filter(|r| !r.is_dir).map(|r| r.size).sum();
        let text = if p.loading {
            "Loading…".to_owned()
        } else if sel.is_empty() {
            format!("{} items", p.view.len())
        } else {
            format!(
                "{} items · {} selected · {}",
                p.view.len(),
                sel.len(),
                format::bytes(bytes)
            )
        };
        let (sr, _) = ui.allocate_exact_size(vec2(ui.available_width(), status_h), Sense::hover());
        ui.painter().rect_filled(sr, 0, BG1);
        ui.painter().text(
            pos2(sr.left() + 12.0, sr.center().y),
            Align2::LEFT_CENTER,
            text,
            theme::prop(11.0),
            TX2,
        );
        let hint = match &self.clip {
            Some(c) => format!(
                "{} {} {} — Ctrl V pastes into the open folder",
                ph::CLIPBOARD,
                c.items.len(),
                if c.cut { "cut" } else { "copied" }
            ),
            None => "Drop files here to upload · Ctrl V pastes files copied in Explorer".into(),
        };
        ui.painter().text(
            pos2(sr.right() - 10.0, sr.center().y),
            Align2::RIGHT_CENTER,
            hint,
            theme::prop(11.0),
            TX3,
        );
        drop_dir
    }

    /// The single 40 px bar: Back · Up · Refresh | path field | Upload · Upload folders ·
    /// Download · New folder · Delete | Show hidden. Icons only, tooltips name them.
    fn bar(&mut self, ui: &mut Ui, connected: bool, out: &mut Vec<Out>) {
        const H: f32 = 40.0;
        const B: f32 = 30.0; // button size
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), H), Sense::hover());
        ui.painter().rect_filled(rect, 0, BG1);
        let y = rect.center().y;
        let has_sel = !self.pane.sel.is_empty();
        let in_dir = connected && !self.pane.path.is_empty();
        let back = self.pane.back.last().cloned();
        let parent = rfs::parent(&self.pane.path);

        // Left: navigation.
        let mut x = rect.left() + 8.0;
        let slot = |x: &mut f32| {
            let r = egui::Rect::from_center_size(pos2(*x + B / 2.0, y), vec2(B, B));
            *x += B + 2.0;
            r
        };
        let r_back = slot(&mut x);
        let r_up = slot(&mut x);
        let r_ref = slot(&mut x);
        let nav_end = x + 6.0;

        // Right: actions, laid out from the right edge.
        let mut rx = rect.right() - 8.0;
        let rslot = |rx: &mut f32| {
            let r = egui::Rect::from_center_size(pos2(*rx - B / 2.0, y), vec2(B, B));
            *rx -= B + 2.0;
            r
        };
        let r_hidden = rslot(&mut rx);
        rx -= 9.0; // group gap (divider drawn in it)
        let div2 = rx + 4.5;
        let r_del = rslot(&mut rx);
        let r_mkdir = rslot(&mut rx);
        rx -= 9.0;
        let div1 = rx + 4.5;
        let r_down = rslot(&mut rx);
        let r_upd = rslot(&mut rx);
        let r_up_files = rslot(&mut rx);
        let act_start = rx - 6.0;

        let p = ui.painter();
        for dx in [nav_end - 3.0, div1, div2] {
            p.line_segment(
                [pos2(dx, y - 9.0), pos2(dx, y + 9.0)],
                egui::Stroke::new(1.0, LINE2),
            );
        }

        if tool(
            ui,
            r_back,
            ph::ARROW_LEFT,
            "Back",
            back.is_some() && connected,
            None,
        ) && let Some(b) = back
        {
            self.pane.back.pop();
            self.pane.path = b.clone();
            self.pane.sel.clear();
            self.list(b, out);
        }
        if tool(
            ui,
            r_up,
            ph::ARROW_UP,
            "Up one folder (Backspace)",
            parent.is_some() && connected,
            None,
        ) && let Some(p) = parent
        {
            self.go(p, out);
        }
        if tool(
            ui,
            r_ref,
            ph::ARROW_CLOCKWISE,
            "Refresh (F5)",
            connected,
            None,
        ) {
            self.refresh_remote(out);
        }
        let path = self.pane.path.clone();
        if tool(
            ui,
            r_up_files,
            ph::UPLOAD_SIMPLE,
            "Upload files here (SCP)",
            in_dir,
            Some(ACC),
        ) {
            self.pick_upload(path.clone(), false);
        }
        if tool(
            ui,
            r_upd,
            ph::FOLDER_SIMPLE_PLUS,
            "Upload folders here (SCP)",
            in_dir,
            None,
        ) {
            self.pick_upload(path.clone(), true);
        }
        if tool(
            ui,
            r_down,
            ph::DOWNLOAD_SIMPLE,
            "Download the selection to a folder you choose (SCP)",
            connected && has_sel,
            None,
        ) {
            self.pick_download(out);
        }
        if tool(ui, r_mkdir, ph::FOLDER_PLUS, "New folder", in_dir, None) {
            self.prompt = Some(Prompt::new(PromptKind::Mkdir, ""));
        }
        if tool(
            ui,
            r_del,
            ph::TRASH,
            "Delete the selection (Del)",
            connected && has_sel,
            None,
        ) {
            self.delete(out);
        }
        let hidden = self.pane.show_hidden;
        let tip = if hidden {
            "Hide hidden files"
        } else {
            "Show hidden files"
        };
        if tool(
            ui,
            r_hidden,
            if hidden { ph::EYE } else { ph::EYE_SLASH },
            tip,
            true,
            hidden.then_some(ACC),
        ) {
            self.pane.show_hidden = !hidden;
            self.pane.resort();
        }

        // Middle: the path field.
        let field =
            egui::Rect::from_min_max(pos2(nav_end + 4.0, y - 14.0), pos2(act_start, y + 14.0));
        if field.width() > 60.0 {
            self.path_field(ui, field, connected, out);
        }
    }

    /// Breadcrumbs in a field; click empty space (or the pencil) to type a path.
    fn path_field(&mut self, ui: &mut Ui, field: egui::Rect, enabled: bool, out: &mut Vec<Out>) {
        let editing = self.pane.editing.is_some();
        let p = ui.painter();
        p.rect_filled(field, 4, BG0);
        p.rect_stroke(
            field,
            4,
            egui::Stroke::new(1.0, if editing { ACC_MID } else { LINE }),
            egui::StrokeKind::Inside,
        );
        let inner = field.shrink2(vec2(10.0, 0.0));
        if let Some(text) = &mut self.pane.editing {
            let mut c = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(inner)
                    .layout(Layout::left_to_right(Align::Center)),
            );
            let r = c.add(
                egui::TextEdit::singleline(text)
                    .font(theme::mono(12.5))
                    .frame(egui::Frame::NONE)
                    .desired_width(f32::INFINITY),
            );
            r.request_focus();
            if c.input(|i| i.key_pressed(egui::Key::Escape)) {
                self.pane.editing = None;
            } else if r.lost_focus() || c.input(|i| i.key_pressed(egui::Key::Enter)) {
                let t = self.pane.editing.take().unwrap_or_default();
                let t = t.trim().to_owned();
                if !t.is_empty() && enabled {
                    self.go(t, out);
                }
            }
            return;
        }
        // Background click → edit. Drawn first so the crumbs on top take their own clicks.
        let bg = ui.interact(field, ui.id().with("path-field"), Sense::click());
        if bg.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Text);
        }
        let path = self.pane.path.clone();
        let crumbs = crumbs(&path);
        let font = theme::prop(13.0);
        let sep_font = theme::prop(10.0);
        const GAP: f32 = 8.0; // space each side of a separator
        let sep_w = ui
            .painter()
            .layout_no_wrap(ph::CARET_RIGHT.into(), sep_font.clone(), TX3)
            .size()
            .x;
        let pencil_w = 22.0;
        let avail = inner.width() - pencil_w;
        let widths: Vec<f32> = crumbs
            .iter()
            .map(|(l, _)| {
                ui.painter()
                    .layout_no_wrap(sw_core::logs::sanitize(l), font.clone(), TX0)
                    .size()
                    .x
                    + 8.0
            })
            .collect();
        // Keep the root and as many trailing segments as fit; "…" replaces the middle.
        let step = sep_w + 2.0 * GAP;
        let total = |from: usize| -> f32 {
            widths[0] + widths[from..].iter().map(|w| w + step).sum::<f32>()
        };
        let mut from = 1.min(crumbs.len());
        while from + 1 < crumbs.len()
            && total(from) + (if from > 1 { 20.0 + step } else { 0.0 }) > avail
        {
            from += 1;
        }
        let mut shown: Vec<(String, Option<String>)> = vec![];
        if let Some(first) = crumbs.first() {
            shown.push((first.0.clone(), Some(first.1.clone())));
        }
        if from > 1 {
            shown.push(("…".into(), None));
        }
        for c in crumbs.iter().skip(from) {
            shown.push((c.0.clone(), Some(c.1.clone())));
        }
        let last = shown.len().saturating_sub(1);
        let mut x = inner.left();
        let y = field.center().y;
        let clip =
            egui::Rect::from_min_max(field.min, pos2(inner.right() - pencil_w, field.bottom()));
        let mut target = None;
        for (k, (label, full)) in shown.into_iter().enumerate() {
            if k > 0 {
                ui.painter_at(clip).text(
                    pos2(x + GAP, y),
                    Align2::LEFT_CENTER,
                    ph::CARET_RIGHT,
                    sep_font.clone(),
                    TX3,
                );
                x += step;
            }
            let color = if k == last { TX0 } else { TX2 };
            let g =
                ui.painter()
                    .layout_no_wrap(sw_core::logs::sanitize(&label), font.clone(), color);
            let r = egui::Rect::from_min_size(pos2(x, y - 11.0), vec2(g.size().x + 8.0, 22.0));
            if let Some(full) = full {
                let resp = ui.interact(r, ui.id().with(("crumb", k)), Sense::click());
                if resp.hovered() && k != last {
                    ui.painter_at(clip).rect_filled(r, 3, BG3);
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                if resp.on_hover_text(&full).clicked() && enabled && k != last {
                    target = Some(full);
                }
            }
            ui.painter_at(clip)
                .galley(pos2(r.left() + 4.0, y - g.size().y / 2.0), g, color);
            x = r.right();
        }
        let pr = egui::Rect::from_center_size(
            pos2(inner.right() - pencil_w / 2.0 + 4.0, y),
            vec2(22.0, 22.0),
        );
        let pencil = tool(ui, pr, ph::PENCIL_SIMPLE, "Type a path", enabled, None);
        if (bg.clicked() || pencil) && enabled {
            self.pane.editing = Some(path);
        }
        if let Some(t) = target {
            self.go(t, out);
        }
    }

    fn menu_act(&mut self, m: MenuAct, out: &mut Vec<Out>) {
        let dir = self.pane.path.clone();
        match m {
            MenuAct::Open(name) => {
                if let Some(i) = self.pane.rows.iter().position(|r| r.name == name) {
                    self.open_row(i, out);
                }
            }
            MenuAct::Download => self.pick_download(out),
            MenuAct::UploadInto(name, folders) => {
                let to = name.map_or(dir, |n| rfs::join(&self.pane.path, &n));
                self.pick_upload(to, folders);
            }
            MenuAct::Copy => self.copy(false),
            MenuAct::Cut => self.copy(true),
            MenuAct::Paste => self.paste(out),
            MenuAct::Delete => self.delete(out),
            MenuAct::Rename(name) => {
                self.prompt = Some(Prompt::new(PromptKind::Rename(name.clone()), &name))
            }
            MenuAct::Mkdir => self.prompt = Some(Prompt::new(PromptKind::Mkdir, "")),
            MenuAct::CopyPath(name) => self.ctx.copy_text(rfs::join(&dir, &name)),
            MenuAct::Terminal(name) => {
                let p = name.map_or(dir, |n| rfs::join(&self.pane.path, &n));
                out.push(Out::Req(Request::NewTerminal(format!(
                    "cd -- {}",
                    sw_core::shell::shell_quote(&p)
                ))));
            }
        }
    }

    fn transfers_ui(&mut self, ui: &mut Ui, out: &mut Vec<Out>) {
        w::hline(ui);
        let (hr, _) = ui.allocate_exact_size(vec2(ui.available_width(), 28.0), Sense::hover());
        ui.painter().rect_filled(hr, 0, BG1);
        let running = self.running_transfers();
        ui.painter().text(
            pos2(hr.left() + 12.0, hr.center().y),
            Align2::LEFT_CENTER,
            if running > 0 {
                format!("TRANSFERS · {running} running")
            } else {
                "TRANSFERS".to_owned()
            },
            theme::prop(11.0),
            TX2,
        );
        let mut c = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(hr.shrink2(vec2(8.0, 0.0)))
                .layout(Layout::right_to_left(Align::Center)),
        );
        if running < self.transfers.len() && c.button("Clear finished").clicked() {
            self.transfers
                .retain(|t| t.p.state == TransferState::Running);
        }
        let mut cancel = None;
        for t in self.transfers.iter().take(4) {
            let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 40.0), Sense::hover());
            let p = ui.painter();
            let (icon, ic) = match &t.p.state {
                TransferState::Running => (
                    if t.upload {
                        ph::UPLOAD_SIMPLE
                    } else {
                        ph::DOWNLOAD_SIMPLE
                    },
                    ACC,
                ),
                TransferState::Done => (ph::CHECK_CIRCLE, OK),
                TransferState::Failed(_) => (ph::WARNING_CIRCLE, ERR),
                TransferState::Cancelled => (ph::X_CIRCLE, TX3),
            };
            p.text(
                pos2(r.left() + 14.0, r.top() + 14.0),
                Align2::LEFT_CENTER,
                icon,
                theme::prop(14.0),
                ic,
            );
            let text_clip = egui::Rect::from_min_max(r.min, pos2(r.right() - 220.0, r.bottom()));
            ui.painter_at(text_clip).text(
                pos2(r.left() + 34.0, r.top() + 14.0),
                Align2::LEFT_CENTER,
                format!("{}  → {}", t.label, sw_core::logs::sanitize(&t.target)),
                theme::prop(12.5),
                TX0,
            );
            let total = t.p.total.unwrap_or(0);
            let f = if total > 0 {
                t.p.bytes as f32 / total as f32
            } else {
                0.0
            };
            let detail = match &t.p.state {
                TransferState::Running => {
                    let cur = if t.p.current.is_empty() {
                        String::new()
                    } else {
                        format!(" · {}", sw_core::logs::sanitize(&t.p.current))
                    };
                    format!(
                        "{} / {} · {}{cur}",
                        format::bytes(t.p.bytes),
                        if total > 0 {
                            format::bytes(total)
                        } else {
                            "…".into()
                        },
                        format::rate(t.rate),
                    )
                }
                TransferState::Done => format!(
                    "{} · {} file{}",
                    format::bytes(t.p.bytes),
                    t.p.files,
                    if t.p.files == 1 { "" } else { "s" }
                ),
                TransferState::Failed(e) => sw_core::logs::sanitize(e),
                TransferState::Cancelled => "Cancelled".into(),
            };
            let dc = if matches!(t.p.state, TransferState::Failed(_)) {
                ERR_SOFT
            } else {
                TX2
            };
            ui.painter_at(text_clip).text(
                pos2(r.left() + 34.0, r.top() + 30.0),
                Align2::LEFT_CENTER,
                detail,
                theme::prop(11.0),
                dc,
            );
            if t.p.state == TransferState::Running {
                let bar = egui::Rect::from_min_size(
                    pos2(r.right() - 210.0, r.center().y - 3.0),
                    vec2(160.0, 6.0),
                );
                p.rect_filled(bar, 2, BG3);
                if f > 0.0 {
                    p.rect_filled(
                        egui::Rect::from_min_size(
                            bar.min,
                            vec2(bar.width() * f.min(1.0), bar.height()),
                        ),
                        2,
                        ACC,
                    );
                }
                let xr = egui::Rect::from_center_size(
                    pos2(r.right() - 24.0, r.center().y),
                    vec2(22.0, 22.0),
                );
                let x = ui.interact(xr, ui.id().with(("cancel", t.id)), Sense::click());
                if x.hovered() {
                    ui.painter().rect_filled(xr, 3, BG3);
                }
                ui.painter().text(
                    xr.center(),
                    Align2::CENTER_CENTER,
                    ph::X,
                    theme::prop(12.0),
                    if x.hovered() { TX0 } else { TX2 },
                );
                if x.on_hover_text("Cancel").clicked() {
                    cancel = Some(t.id);
                }
            }
        }
        if let Some(id) = cancel {
            out.push(Out::Cmd(Command::CancelTransfer(id)));
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context, out: &mut Vec<Out>) {
        if let Some(c) = &self.conflict {
            let mut act = None;
            let n = c.names.len();
            let title = if n == 1 {
                "Name already exists".to_owned()
            } else {
                format!("{n} names already exist")
            };
            let listed: Vec<String> = c
                .names
                .iter()
                .take(6)
                .map(|s| sw_core::logs::sanitize(s))
                .collect();
            crate::dialogs::modal(ctx, "files-conflict", &title, ph::COPY, 480.0, |ui| {
                ui.label(w::dim("The destination folder already has:"));
                for s in &listed {
                    ui.label(w::mono(s, TX0));
                }
                if n > listed.len() {
                    ui.label(w::faint(format!("… and {} more", n - listed.len())));
                }
                ui.label(w::faint(
                    "Replace overwrites files and merges folders. Keep both adds \"(copy)\" to the new names.",
                ));
                ui.add_space(4.0);
                ui.allocate_ui_with_layout(
                    vec2(ui.available_width(), 28.0),
                    Layout::right_to_left(Align::Center),
                    |ui| {
                        if ui
                            .add(egui::Button::new(RichText::new("Replace").color(BG0)).fill(ERR))
                            .clicked()
                        {
                            act = Some(Some(true));
                        }
                        if ui
                            .add(egui::Button::new(RichText::new("Keep both").color(BG0)).fill(ACC))
                            .clicked()
                            || ui.input(|i| i.key_pressed(egui::Key::Enter))
                        {
                            act = Some(Some(false));
                        }
                        if ui.button("Cancel").clicked()
                            || ui.input(|i| i.key_pressed(egui::Key::Escape))
                        {
                            act = Some(None);
                        }
                    },
                );
            });
            if let Some(a) = act
                && let Some(c) = self.conflict.take()
                && let Some(replace) = a
            {
                self.run(c.plan, replace, out);
            }
            return;
        }
        let Some(pr) = &mut self.prompt else { return };
        let (title, verb) = match &pr.kind {
            PromptKind::Mkdir => ("New folder".to_owned(), "Create"),
            PromptKind::Rename(n) => (format!("Rename {}", sw_core::logs::sanitize(n)), "Rename"),
        };
        let mut act = None;
        let dir = self.pane.path.clone();
        crate::dialogs::modal(
            ctx,
            "files-prompt",
            &title,
            ph::FOLDER_SIMPLE,
            440.0,
            |ui| {
                ui.label(w::dim(format!("In {}", sw_core::logs::sanitize(&dir))));
                let r =
                    ui.add(egui::TextEdit::singleline(&mut pr.text).desired_width(f32::INFINITY));
                if pr.opened.elapsed().as_millis() < 300 {
                    r.request_focus();
                }
                if let Some(e) = &pr.error {
                    ui.label(RichText::new(e).color(ERR));
                }
                ui.allocate_ui_with_layout(
                    vec2(ui.available_width(), 28.0),
                    Layout::right_to_left(Align::Center),
                    |ui| {
                        if ui
                            .add(egui::Button::new(RichText::new(verb).color(BG0)).fill(ACC))
                            .clicked()
                            || ui.input(|i| i.key_pressed(egui::Key::Enter))
                        {
                            act = Some(true);
                        }
                        if ui.button("Cancel").clicked()
                            || ui.input(|i| i.key_pressed(egui::Key::Escape))
                        {
                            act = Some(false);
                        }
                    },
                );
            },
        );
        match act {
            Some(false) => self.prompt = None,
            Some(true) => {
                let name = pr.text.trim().to_owned();
                if !rfs::is_valid_name(&name) {
                    pr.error = Some("Not a valid name (no \"/\", not \".\" or \"..\")".into());
                } else if self.pane.has(&name)
                    && !matches!(&pr.kind, PromptKind::Rename(n) if *n == name)
                {
                    pr.error = Some("That name is already taken here".into());
                } else {
                    let op = match &pr.kind {
                        PromptKind::Mkdir => Some(FsOp::Mkdir(rfs::join(&dir, &name))),
                        PromptKind::Rename(old) if *old == name => None,
                        PromptKind::Rename(old) => Some(FsOp::Rename {
                            from: rfs::join(&dir, old),
                            to: rfs::join(&dir, &name),
                        }),
                    };
                    self.prompt = None;
                    if let Some(op) = op {
                        out.push(Out::Req(Request::Run(Action::Files(op))));
                    }
                }
            }
            None => {}
        }
    }
}

impl Prompt {
    fn new(kind: PromptKind, text: &str) -> Self {
        Self {
            kind,
            text: text.to_owned(),
            error: None,
            opened: Instant::now(),
        }
    }
}

enum MenuAct {
    Open(String),
    Download,
    /// Upload into the open folder (`None`) or into this subfolder; `true` = pick folders.
    UploadInto(Option<String>, bool),
    Copy,
    Cut,
    Paste,
    Delete,
    Rename(String),
    Mkdir,
    CopyPath(String),
    Terminal(Option<String>),
}

fn menu_item(ui: &mut Ui, act: &mut Option<MenuAct>, icon: &str, label: &str, a: MenuAct) {
    if ui.button(format!("{icon}  {label}")).clicked() {
        *act = Some(a);
        ui.close();
    }
}

fn row_menu(ui: &mut Ui, r: &Row) -> Option<MenuAct> {
    let mut act = None;
    let a = &mut act;
    if r.is_dir {
        menu_item(
            ui,
            a,
            ph::FOLDER_OPEN,
            "Open",
            MenuAct::Open(r.name.clone()),
        );
    }
    menu_item(ui, a, ph::DOWNLOAD_SIMPLE, "Download…", MenuAct::Download);
    if r.is_dir {
        menu_item(
            ui,
            a,
            ph::UPLOAD_SIMPLE,
            "Upload files into this folder…",
            MenuAct::UploadInto(Some(r.name.clone()), false),
        );
    }
    ui.separator();
    menu_item(ui, a, ph::COPY, "Copy  (Ctrl C)", MenuAct::Copy);
    menu_item(ui, a, ph::SCISSORS, "Cut  (Ctrl X)", MenuAct::Cut);
    menu_item(ui, a, ph::CLIPBOARD, "Paste  (Ctrl V)", MenuAct::Paste);
    ui.separator();
    menu_item(
        ui,
        a,
        ph::PENCIL_SIMPLE,
        "Rename…  (F2)",
        MenuAct::Rename(r.name.clone()),
    );
    menu_item(
        ui,
        a,
        ph::LINK,
        "Copy path",
        MenuAct::CopyPath(r.name.clone()),
    );
    if r.is_dir {
        menu_item(
            ui,
            a,
            ph::TERMINAL_WINDOW,
            "Open a terminal here",
            MenuAct::Terminal(Some(r.name.clone())),
        );
    }
    ui.separator();
    menu_item(ui, a, ph::TRASH, "Delete…  (Del)", MenuAct::Delete);
    act
}

/// Right-click on empty space in the list.
fn folder_menu(ui: &mut Ui, can_paste: bool) -> Option<MenuAct> {
    let mut act = None;
    let a = &mut act;
    menu_item(
        ui,
        a,
        ph::UPLOAD_SIMPLE,
        "Upload files…",
        MenuAct::UploadInto(None, false),
    );
    menu_item(
        ui,
        a,
        ph::FOLDER_SIMPLE_PLUS,
        "Upload folders…",
        MenuAct::UploadInto(None, true),
    );
    menu_item(ui, a, ph::FOLDER_PLUS, "New folder…", MenuAct::Mkdir);
    if can_paste || cfg!(windows) {
        menu_item(ui, a, ph::CLIPBOARD, "Paste  (Ctrl V)", MenuAct::Paste);
    }
    menu_item(
        ui,
        a,
        ph::TERMINAL_WINDOW,
        "Open a terminal here",
        MenuAct::Terminal(None),
    );
    act
}

/// Icon-only toolbar button in `r`. `accent`: icon color when enabled (default TX1).
fn tool(
    ui: &Ui,
    r: egui::Rect,
    icon: &str,
    tip: &str,
    enabled: bool,
    accent: Option<egui::Color32>,
) -> bool {
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let resp = ui.interact(r, ui.id().with(("tool", icon)), sense);
    let p = ui.painter();
    if enabled && resp.hovered() {
        p.rect_filled(r, 4, BG3);
    }
    let color = if !enabled {
        TX3
    } else if resp.hovered() {
        accent.unwrap_or(TX0)
    } else {
        accent.unwrap_or(TX1)
    };
    p.text(
        r.center(),
        Align2::CENTER_CENTER,
        icon,
        theme::prop(16.0),
        color,
    );
    resp.on_hover_text(tip).clicked()
}

struct Cols {
    name: f32,
    size: f32,
    modified: f32,
    perms: f32,
    owner: f32,
}

/// Column x positions; NaN = column hidden (narrow window).
fn columns(r: egui::Rect) -> Cols {
    let right = r.right() - 12.0;
    let (owner, perms) = if r.width() > 640.0 {
        (right - 90.0, right - 190.0)
    } else {
        (f32::NAN, f32::NAN)
    };
    let modified_end = if perms.is_nan() { right } else { perms - 20.0 };
    let modified = if r.width() > 420.0 {
        modified_end - 112.0
    } else {
        f32::NAN
    };
    let size = if modified.is_nan() {
        right
    } else {
        modified - 24.0
    };
    Cols {
        name: r.left() + 34.0,
        size,
        modified,
        perms,
        owner,
    }
}

fn draw_row(ui: &Ui, rect: egui::Rect, r: &Row, sel: bool) {
    let c = columns(rect);
    let p = ui.painter();
    let y = rect.center().y;
    let (icon, ic) = if r.is_dir {
        (
            if r.link {
                ph::FOLDER_SIMPLE_DASHED
            } else {
                ph::FOLDER_SIMPLE
            },
            ACC,
        )
    } else if r.link {
        (ph::LINK_SIMPLE, INFO)
    } else {
        (ph::FILE, TX2)
    };
    p.text(
        pos2(rect.left() + 12.0, y),
        Align2::LEFT_CENTER,
        icon,
        theme::prop(14.0),
        ic,
    );
    let name_end = c.size - 80.0;
    ui.painter_at(egui::Rect::from_min_max(
        rect.min,
        pos2(name_end, rect.bottom()),
    ))
    .text(
        pos2(c.name, y),
        Align2::LEFT_CENTER,
        &r.display,
        theme::prop(12.5),
        if sel { TX0 } else { TX1 },
    );
    let mono = theme::mono(11.5);
    if !r.is_dir {
        p.text(
            pos2(c.size, y),
            Align2::RIGHT_CENTER,
            format::bytes(r.size),
            mono.clone(),
            TX2,
        );
    }
    if !c.modified.is_nan() && r.mtime > 0 {
        p.text(
            pos2(c.modified, y),
            Align2::LEFT_CENTER,
            format::datetime(r.mtime),
            mono.clone(),
            TX3,
        );
    }
    if !c.perms.is_nan() {
        p.text(
            pos2(c.perms, y),
            Align2::LEFT_CENTER,
            format::perms(r.mode),
            mono.clone(),
            TX3,
        );
        ui.painter_at(egui::Rect::from_min_max(
            pos2(c.owner, rect.top()),
            rect.max,
        ))
        .text(pos2(c.owner, y), Align2::LEFT_CENTER, &r.owner, mono, TX3);
    }
}

fn drop_hint(ui: &Ui, rect: egui::Rect, target: &str) {
    let p = ui.ctx().layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        egui::Id::new("files-drop-hint"),
    ));
    let r = rect.shrink(6.0);
    p.rect_stroke(r, 4, egui::Stroke::new(1.5, ACC), egui::StrokeKind::Inside);
    let label = format!(
        "{}  Drop to upload to {} (SCP)",
        ph::UPLOAD_SIMPLE,
        sw_core::logs::sanitize(target)
    );
    let g = p.layout_no_wrap(label, theme::prop(13.5), TX0);
    let chip = egui::Rect::from_center_size(
        pos2(r.center().x, r.bottom() - 28.0),
        g.size() + vec2(28.0, 14.0),
    );
    p.rect_filled(chip, 4, ACC_DIM);
    p.rect_stroke(
        chip,
        4,
        egui::Stroke::new(1.0, ACC),
        egui::StrokeKind::Inside,
    );
    p.galley(chip.center() - g.size() / 2.0, g, TX0);
}

/// Path → clickable segments (label, full path).
fn crumbs(path: &str) -> Vec<(String, String)> {
    if path.is_empty() {
        return vec![("~".into(), String::new())];
    }
    let mut v = vec![("/".to_owned(), "/".to_owned())];
    let mut acc = String::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        acc.push('/');
        acc.push_str(seg);
        v.push((seg.to_owned(), acc.clone()));
    }
    v
}

/// Files on the system clipboard (copied in Explorer). Windows only; empty elsewhere.
fn os_clipboard_files() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let Ok(_clip) = clipboard_win::Clipboard::new_attempts(5) else {
            return vec![];
        };
        let mut v: Vec<String> = Vec::new();
        if clipboard_win::raw::get_file_list(&mut v).is_ok() {
            return v.into_iter().map(PathBuf::from).collect();
        }
        vec![]
    }
    #[cfg(not(windows))]
    {
        vec![]
    }
}

/// Is V held right now? (egui gets no event for Ctrl V when the clipboard holds only files.)
fn paste_key_pressed() -> bool {
    #[cfg(windows)]
    {
        // SAFETY: plain Win32 call with a constant virtual-key code.
        unsafe {
            (windows_sys::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState(0x56) as u16
                & 0x8000)
                != 0
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_crumbs() {
        assert_eq!(
            crumbs("/var/www"),
            vec![
                ("/".into(), "/".into()),
                ("var".into(), "/var".into()),
                ("www".into(), "/var/www".into())
            ]
        );
        assert_eq!(crumbs(""), vec![("~".into(), String::new())]);
    }

    #[test]
    fn sort_keeps_folders_first() {
        let row = |n: &str, d: bool, s: u64| Row {
            name: n.into(),
            display: n.into(),
            is_dir: d,
            link: false,
            size: s,
            mtime: 0,
            mode: 0,
            owner: String::new(),
        };
        let mut p = Pane::new();
        p.set_rows(vec![
            row("b.txt", false, 5),
            row("A", true, 0),
            row(".h", false, 9),
            row("a.txt", false, 50),
        ]);
        let names: Vec<&str> = p.view.iter().map(|&i| p.rows[i].name.as_str()).collect();
        assert_eq!(names, ["A", ".h", "a.txt", "b.txt"]);
        p.sort = (Col::Size, false);
        p.show_hidden = false;
        p.resort();
        let names: Vec<&str> = p.view.iter().map(|&i| p.rows[i].name.as_str()).collect();
        assert_eq!(names, ["A", "a.txt", "b.txt"]);
    }
}
