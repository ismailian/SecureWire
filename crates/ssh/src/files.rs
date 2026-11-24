//! File browser channels (protocol §15): directory listings (`ls.sh` on an exec
//! channel) and transfers over SCP (`scp -t` / `scp -f` on an exec channel).
//! All of it runs on the host's one SSH connection.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::ChannelMsg;
use russh::client::{self, Handle};
use sw_core::files::{self as fs, ScpRecord};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

use crate::api::{EventKind, TransferProgress, TransferSpec, TransferState};
use crate::collector;
use crate::remote::{self, Writer};

const LIST_TIMEOUT: Duration = Duration::from_secs(30);
/// Listing output larger than this is cut (a directory with ~200k entries).
const LIST_MAX: usize = 32 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
/// Progress events at most this often per transfer.
const PROGRESS_EVERY: Duration = Duration::from_millis(150);

/// List one directory (empty path = home).
pub(crate) async fn list<H: client::Handler>(
    h: &Handle<H>,
    path: &str,
) -> Result<fs::Listing, String> {
    let cmd = fs::listing_command(path)?;
    let fut = async {
        let mut ch = h.channel_open_session().await.map_err(|e| e.to_string())?;
        ch.exec(false, cmd).await.map_err(|e| e.to_string())?;
        ch.data(collector::LS.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        ch.eof().await.map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::Data { data } if out.len() < LIST_MAX => out.extend_from_slice(&data),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        fs::parse_listing(&out)
    };
    tokio::time::timeout(LIST_TIMEOUT, fut)
        .await
        .map_err(|_| "Listing timed out".to_owned())?
}

/// Reports progress for one transfer (throttled) through the actor's event channel.
pub(crate) struct Reporter {
    pub emit: Box<dyn Fn(EventKind) + Send>,
    pub id: u64,
    pub p: TransferProgress,
    last: Instant,
}

impl Reporter {
    pub fn new(id: u64, emit: Box<dyn Fn(EventKind) + Send>) -> Self {
        Self {
            emit,
            id,
            p: TransferProgress {
                bytes: 0,
                total: None,
                files: 0,
                current: String::new(),
                state: TransferState::Running,
            },
            last: Instant::now() - PROGRESS_EVERY,
        }
    }

    fn tick(&mut self, force: bool) {
        if force || self.last.elapsed() >= PROGRESS_EVERY {
            self.last = Instant::now();
            (self.emit)(EventKind::Transfer {
                id: self.id,
                progress: self.p.clone(),
            });
        }
    }

    fn finish(&mut self, state: TransferState) {
        self.p.state = state;
        self.tick(true);
    }
}

/// Buffered reader/writer over an SCP exec channel.
struct Io {
    rd: russh::ChannelReadHalf,
    wr: Writer,
    buf: Vec<u8>,
    pos: usize,
    closed: bool,
    stderr: Vec<u8>,
    exit: Option<u32>,
}

impl Io {
    async fn open<H: client::Handler>(h: &Handle<H>, cmd: String) -> Result<Self, String> {
        let ch = h.channel_open_session().await.map_err(|e| e.to_string())?;
        ch.exec(false, cmd).await.map_err(|e| e.to_string())?;
        let (rd, wr) = ch.split();
        Ok(Self {
            rd,
            wr,
            buf: Vec::new(),
            pos: 0,
            closed: false,
            stderr: Vec::new(),
            exit: None,
        })
    }

    /// Wait for more data; false once the channel has ended.
    async fn fill(&mut self) -> bool {
        if self.closed {
            return false;
        }
        loop {
            match self.rd.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    if self.pos == self.buf.len() {
                        self.buf.clear();
                        self.pos = 0;
                    }
                    self.buf.extend_from_slice(&data);
                    return true;
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if self.stderr.len() < 4096 {
                        self.stderr.extend_from_slice(&data);
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => self.exit = Some(exit_status),
                Some(ChannelMsg::Eof) => {
                    // The exit status usually follows the EOF; collect it for the error text.
                    let _ = tokio::time::timeout(Duration::from_secs(2), async {
                        while let Some(m) = self.rd.wait().await {
                            match m {
                                ChannelMsg::ExitStatus { exit_status } => {
                                    self.exit = Some(exit_status)
                                }
                                ChannelMsg::ExtendedData { data, .. }
                                    if self.stderr.len() < 4096 =>
                                {
                                    self.stderr.extend_from_slice(&data)
                                }
                                ChannelMsg::Close => break,
                                _ => {}
                            }
                        }
                    })
                    .await;
                    self.closed = true;
                    return false;
                }
                Some(ChannelMsg::Close) | None => {
                    self.closed = true;
                    return false;
                }
                _ => {}
            }
        }
    }

    fn ended(&self) -> String {
        let err = sw_core::logs::sanitize(String::from_utf8_lossy(&self.stderr).trim());
        if !err.is_empty() {
            return err;
        }
        match self.exit {
            Some(127) => {
                "scp is not installed on the server (the openssh-client package provides it)".into()
            }
            Some(c) => format!("The server's scp exited with status {c}"),
            None => "The server closed the transfer channel".into(),
        }
    }

    async fn byte(&mut self) -> Result<u8, String> {
        while self.pos == self.buf.len() {
            if !self.fill().await {
                return Err(self.ended());
            }
        }
        self.pos += 1;
        Ok(self.buf[self.pos - 1])
    }

    async fn line(&mut self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        loop {
            match self.byte().await? {
                b'\n' => return Ok(out),
                b => out.push(b),
            }
            if out.len() > 8192 {
                return Err("SCP: control line too long".into());
            }
        }
    }

    /// The server's answer to our last message: 0 = OK, 1/2 + text = warning/error.
    async fn ack(&mut self) -> Result<(), String> {
        match self.byte().await? {
            0 => Ok(()),
            1 | 2 => Err(self.message().await),
            b => Err(format!("SCP: unexpected reply byte {b}")),
        }
    }

    async fn message(&mut self) -> String {
        let l = self.line().await.unwrap_or_default();
        let s = sw_core::logs::sanitize(String::from_utf8_lossy(&l).trim());
        s.strip_prefix("scp: ").unwrap_or(&s).to_owned()
    }

    async fn send(&mut self, b: &[u8]) -> Result<(), String> {
        self.wr.data(b).await.map_err(|e| e.to_string())
    }

    /// Up to `max` buffered bytes (waits for some).
    async fn chunk(&mut self, max: usize) -> Result<&[u8], String> {
        while self.pos == self.buf.len() {
            if !self.fill().await {
                return Err(self.ended());
            }
        }
        let n = (self.buf.len() - self.pos).min(max);
        let s = self.pos;
        self.pos += n;
        Ok(&self.buf[s..s + n])
    }
}

/// Run one transfer to the end; cancellation via `cancel`.
pub(crate) async fn run<H: client::Handler>(
    h: Arc<Handle<H>>,
    spec: TransferSpec,
    cancel: Arc<Notify>,
    mut rep: Reporter,
) {
    // A partly written local file is removed when the download fails or is cancelled.
    let mut partial: Option<PathBuf> = None;
    let result = match spec {
        TransferSpec::Upload { items, remote_dir } => {
            upload(&h, items, &remote_dir, &cancel, &mut rep).await
        }
        TransferSpec::Download { items, local_dir } => {
            download(&h, items, &local_dir, &cancel, &mut rep, &mut partial).await
        }
    };
    let state = match result {
        Ok(warnings) if warnings.is_empty() => TransferState::Done,
        Ok(w) => TransferState::Failed(format!(
            "{} item(s) skipped — {}",
            w.len(),
            w.first().cloned().unwrap_or_default()
        )),
        Err(e) => {
            if let Some(p) = partial.take() {
                let _ = tokio::fs::remove_file(&p).await;
            }
            if e == CANCELLED {
                TransferState::Cancelled
            } else {
                TransferState::Failed(e)
            }
        }
    };
    rep.finish(state);
}

const CANCELLED: &str = "\0cancelled";

/// One step of an upload, planned from the local tree before anything is sent.
enum Step {
    Enter {
        name: String,
        mode: u32,
    },
    File {
        path: PathBuf,
        name: String,
        size: u64,
        mode: u32,
    },
    Leave,
}

#[cfg(unix)]
fn mode_of(m: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_of(m: &std::fs::Metadata) -> u32 {
    if m.is_dir() { 0o755 } else { 0o644 }
}

/// Walk the local items (blocking; runs on tokio's blocking pool).
fn plan(items: Vec<(PathBuf, String)>) -> Result<(Vec<Step>, u64, Vec<String>), String> {
    fn walk(
        p: &Path,
        name: String,
        out: &mut Vec<Step>,
        total: &mut u64,
        skipped: &mut Vec<String>,
    ) {
        let Ok(m) = std::fs::metadata(p) else {
            skipped.push(format!("{}: cannot read", p.display()));
            return;
        };
        if !fs::is_valid_name(&name) {
            skipped.push(format!("{}: name not allowed on the server", p.display()));
            return;
        }
        if m.is_dir() {
            out.push(Step::Enter {
                name,
                mode: mode_of(&m),
            });
            match std::fs::read_dir(p) {
                Ok(rd) => {
                    let mut kids: Vec<_> = rd.flatten().collect();
                    kids.sort_by_key(|e| e.file_name());
                    for e in kids {
                        match e.file_name().into_string() {
                            Ok(n) => walk(&e.path(), n, out, total, skipped),
                            Err(_) => {
                                skipped.push(format!("{}: name is not UTF-8", e.path().display()))
                            }
                        }
                    }
                }
                Err(e) => skipped.push(format!("{}: {e}", p.display())),
            }
            out.push(Step::Leave);
        } else if m.is_file() {
            *total += m.len();
            out.push(Step::File {
                path: p.to_owned(),
                name,
                size: m.len(),
                mode: mode_of(&m),
            });
        } else {
            skipped.push(format!("{}: not a regular file", p.display()));
        }
    }
    let (mut out, mut total, mut skipped) = (Vec::new(), 0, Vec::new());
    for (p, name) in items {
        walk(&p, name, &mut out, &mut total, &mut skipped);
    }
    Ok((out, total, skipped))
}

async fn upload<H: client::Handler>(
    h: &Handle<H>,
    items: Vec<(PathBuf, String)>,
    remote_dir: &str,
    cancel: &Notify,
    rep: &mut Reporter,
) -> Result<Vec<String>, String> {
    let cmd = fs::scp_sink_command(remote_dir)?;
    let (steps, total, skipped) = tokio::task::spawn_blocking(move || plan(items))
        .await
        .map_err(|e| e.to_string())??;
    rep.p.total = Some(total);
    rep.tick(true);
    let mut io = Io::open(h, cmd).await?;
    let r = tokio::select! {
        r = send_steps(&mut io, &steps, rep) => r,
        _ = cancel.notified() => Err(CANCELLED.to_owned()),
    };
    let _ = io.wr.eof().await;
    if r.is_err() {
        let _ = io.wr.close().await;
    }
    r.map(|()| skipped)
}

async fn send_steps(io: &mut Io, steps: &[Step], rep: &mut Reporter) -> Result<(), String> {
    io.ack().await?;
    let mut buf = vec![0u8; CHUNK];
    for s in steps {
        match s {
            Step::Enter { name, mode } => {
                io.send(fs::scp_dir_header(*mode, name).as_bytes()).await?;
                io.ack().await?;
            }
            Step::Leave => {
                io.send(b"E\n").await?;
                io.ack().await?;
            }
            Step::File {
                path,
                name,
                size,
                mode,
            } => {
                rep.p.current = name.clone();
                rep.tick(true);
                let mut f = tokio::fs::File::open(path)
                    .await
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                io.send(fs::scp_file_header(*mode, *size, name).as_bytes())
                    .await?;
                io.ack().await?;
                let mut left = *size;
                while left > 0 {
                    let want = (left as usize).min(CHUNK);
                    let n = f
                        .read(&mut buf[..want])
                        .await
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                    if n == 0 {
                        return Err(format!("{}: file shrank while uploading", path.display()));
                    }
                    io.send(&buf[..n]).await?;
                    left -= n as u64;
                    rep.p.bytes += n as u64;
                    rep.tick(false);
                }
                io.send(&[0]).await?;
                io.ack().await?;
                rep.p.files += 1;
            }
        }
    }
    Ok(())
}

async fn download<H: client::Handler>(
    h: &Handle<H>,
    items: Vec<crate::api::DownloadItem>,
    local_dir: &Path,
    cancel: &Notify,
    rep: &mut Reporter,
    partial: &mut Option<PathBuf>,
) -> Result<Vec<String>, String> {
    // Folder sizes come from `du` so the progress bar has a total.
    let mut total: u64 = items.iter().filter(|i| !i.is_dir).map(|i| i.size).sum();
    let dirs: Vec<&str> = items
        .iter()
        .filter(|i| i.is_dir && fs::is_plain_path(&i.remote))
        .map(|i| i.remote.as_str())
        .collect();
    if !dirs.is_empty() {
        let q: Vec<String> = dirs
            .iter()
            .map(|d| sw_core::shell::shell_quote(d))
            .collect();
        let cmd = format!("du -sk -- {} 2>/dev/null", q.join(" "));
        if let Ok((out, _)) =
            remote::run_exec(h, &cmd, None, None, Duration::from_secs(30), 64 * 1024).await
        {
            total += out
                .lines()
                .filter_map(|l| l.split_whitespace().next()?.parse::<u64>().ok())
                .sum::<u64>()
                * 1024;
        }
    }
    rep.p.total = Some(total);
    rep.tick(true);
    let mut warnings = Vec::new();
    for item in items {
        let cmd = fs::scp_source_command(&item.remote)?;
        let mut io = Io::open(h, cmd).await?;
        let r = tokio::select! {
            r = receive(&mut io, local_dir, &item.local_name, rep, partial, &mut warnings) => r,
            _ = cancel.notified() => Err(CANCELLED.to_owned()),
        };
        if r.is_err() {
            let _ = io.wr.close().await;
        }
        r?;
    }
    Ok(warnings)
}

/// Receive one SCP source stream into `dir`, the top-level entry named `top`.
async fn receive(
    io: &mut Io,
    dir: &Path,
    top: &str,
    rep: &mut Reporter,
    partial: &mut Option<PathBuf>,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    if !fs::is_valid_name(top) {
        return Err(format!("Not a valid file name: {top:?}"));
    }
    let local_err = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    let mut stack: Vec<PathBuf> = vec![dir.to_owned()];
    let mut seen_top = false;
    io.send(&[0]).await?;
    loop {
        let first = match io.byte().await {
            Ok(b) => b,
            // The source ends the channel after the last record.
            Err(e) if !seen_top => return Err(e),
            Err(_) => return Ok(()),
        };
        if first == 1 || first == 2 {
            let m = io.message().await;
            if !seen_top || first == 2 {
                return Err(m);
            }
            warnings.push(m);
            continue;
        }
        let mut line = vec![first];
        line.extend(io.line().await?);
        let rec = fs::parse_scp_record(&line)?;
        // The first record is renamed to the name the user chose (e.g. "x (copy)").
        let name_for = |n: String, seen: &mut bool, depth: usize| {
            if !*seen && depth == 1 {
                *seen = true;
                top.to_owned()
            } else {
                n
            }
        };
        match rec {
            ScpRecord::Time => io.send(&[0]).await?,
            ScpRecord::End => {
                if stack.len() > 1 {
                    stack.pop();
                }
                io.send(&[0]).await?;
            }
            ScpRecord::Dir { name, .. } => {
                let depth = stack.len();
                let name = name_for(name, &mut seen_top, depth);
                let p = stack[depth - 1].join(&name);
                tokio::fs::create_dir_all(&p)
                    .await
                    .map_err(|e| local_err(&p, e))?;
                stack.push(p);
                io.send(&[0]).await?;
            }
            ScpRecord::File { size, name, .. } => {
                let depth = stack.len();
                let name = name_for(name, &mut seen_top, depth);
                let p = stack[depth - 1].join(&name);
                rep.p.current = name;
                rep.tick(true);
                let mut f = tokio::fs::File::create(&p)
                    .await
                    .map_err(|e| local_err(&p, e))?;
                *partial = Some(p.clone());
                io.send(&[0]).await?;
                let mut left = size;
                while left > 0 {
                    let c = io.chunk(left.min(CHUNK as u64) as usize).await?;
                    let n = c.len() as u64;
                    f.write_all(c).await.map_err(|e| local_err(&p, e))?;
                    left -= n;
                    rep.p.bytes += n;
                    rep.tick(false);
                }
                f.flush().await.map_err(|e| local_err(&p, e))?;
                drop(f);
                io.ack().await?;
                *partial = None;
                io.send(&[0]).await?;
                rep.p.files += 1;
            }
        }
    }
}
