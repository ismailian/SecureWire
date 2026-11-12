//! The real host actor: one russh connection per host, one task on the net
//! runtime. M1 scope: connect, host-key verification (TOFU), auth (agent /
//! key file / password), PTY channels, keepalive, reconnect with backoff.
//! Collector and log channels join in M2/M4 on the same connection.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use russh::ChannelMsg;
use russh::client::{self, Handle};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use secrecy::ExposeSecret;
use sw_term::Terminal;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::Waker;
use crate::api::{
    AuthSpec, Command, ConnInfo, ConnState, ConnectSpec, Event, EventKind, HostId, HostKeyStatus,
    KeyDecision, PtyId, SudoMode,
};

const BACKOFF: [u32; 6] = [1, 2, 4, 8, 16, 30];
const TERM_NAME: &str = "xterm-256color";

pub(crate) struct Shared {
    id: HostId,
    events: std::sync::mpsc::Sender<Event>,
    wake: Waker,
}

impl Shared {
    fn emit(&self, kind: EventKind) {
        let _ = self.events.send(Event {
            host: self.id,
            kind,
        });
        (self.wake)();
    }
}

// ───────────────────────── host key verification ─────────────────────────

#[derive(Default)]
struct KeyState {
    /// Key accepted during this host session ("once" or trusted). Reconnects
    /// accept exactly this key without asking again.
    accepted: Option<PublicKey>,
    /// Last key seen + whether it came from a known_hosts file.
    seen: Option<(String, String, bool)>,
}

struct Client {
    shared: Arc<Shared>,
    host: String,
    port: u16,
    known_hosts: crate::api::KnownHosts,
    decisions: Arc<tokio::sync::Mutex<UnboundedReceiver<KeyDecision>>>,
    keys: Arc<parking_lot::Mutex<KeyState>>,
    /// Set when the key was rejected or changed, so the caller doesn't retry.
    key_refused: Arc<AtomicBool>,
    /// Host-key prompt timing, so the handshake timeout ignores the user's reading time.
    prompt: Arc<parking_lot::Mutex<PromptClock>>,
}

#[derive(Default)]
struct PromptClock {
    active: bool,
    ended: Option<std::time::Instant>,
}

enum Known {
    Match,
    Unknown,
    Changed { file: String, line: usize },
}

fn check_file(path: &std::path::Path, host: &str, port: u16, key: &PublicKey) -> Known {
    match russh::keys::check_known_hosts_path(host, port, key, path) {
        Ok(true) => Known::Match,
        Ok(false) => Known::Unknown,
        Err(russh::keys::Error::KeyChanged { line }) => Known::Changed {
            file: path.display().to_string(),
            line,
        },
        // Missing/unreadable file = nothing known.
        Err(_) => Known::Unknown,
    }
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_key else {
            self.shared.emit(EventKind::Error(
                "Host certificates are not supported yet".into(),
            ));
            self.key_refused.store(true, Ordering::SeqCst);
            return Ok(false);
        };
        let algorithm = key.algorithm().as_str().to_owned();
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();

        if self.keys.lock().accepted.as_ref() == Some(key) {
            return Ok(true);
        }

        let mut status = HostKeyStatus::Unknown;
        let files = self
            .known_hosts
            .user_file
            .iter()
            .chain(std::iter::once(&self.known_hosts.app_file));
        for f in files {
            match check_file(f, &self.host, self.port, key) {
                Known::Match => {
                    let mut k = self.keys.lock();
                    k.accepted = Some(key.clone());
                    k.seen = Some((algorithm, fingerprint, true));
                    return Ok(true);
                }
                Known::Changed { file, line } => {
                    status = HostKeyStatus::Changed { file, line };
                    break;
                }
                Known::Unknown => {}
            }
        }

        let mut decisions = self.decisions.lock().await;
        // An answer to an earlier, abandoned prompt must never approve this key.
        while decisions.try_recv().is_ok() {}
        self.prompt.lock().active = true;
        self.shared.emit(EventKind::HostKeyPrompt {
            algorithm: algorithm.clone(),
            fingerprint: fingerprint.clone(),
            status: status.clone(),
        });
        let decision = decisions.recv().await.unwrap_or(KeyDecision::Reject);
        drop(decisions);
        {
            let mut p = self.prompt.lock();
            p.active = false;
            p.ended = Some(std::time::Instant::now());
        }
        // A changed key can only be accepted for this session; never written to disk silently.
        let decision = match (&status, decision) {
            (HostKeyStatus::Changed { .. }, KeyDecision::Trust) => KeyDecision::Once,
            (_, d) => d,
        };
        match decision {
            KeyDecision::Reject => {
                self.key_refused.store(true, Ordering::SeqCst);
                Ok(false)
            }
            KeyDecision::Trust | KeyDecision::Once => {
                if decision == KeyDecision::Trust
                    && let Err(e) = russh::keys::known_hosts::learn_known_hosts_path(
                        &self.host,
                        self.port,
                        key,
                        &self.known_hosts.app_file,
                    )
                {
                    self.shared
                        .emit(EventKind::Error(format!("Could not save host key: {e}")));
                }
                let mut k = self.keys.lock();
                k.accepted = Some(key.clone());
                k.seen = Some((algorithm, fingerprint, decision == KeyDecision::Trust));
                Ok(true)
            }
        }
    }
}

// ───────────────────────────── authentication ─────────────────────────────

async fn authenticate(h: &mut Handle<Client>, user: &str, auth: &AuthSpec) -> Result<(), String> {
    match auth {
        AuthSpec::Password(p) => {
            let r = h
                .authenticate_password(user, p.expose_secret())
                .await
                .map_err(|e| e.to_string())?;
            if r.success() {
                Ok(())
            } else {
                Err("Password rejected by the server".into())
            }
        }
        AuthSpec::KeyFile { path, passphrase } => {
            let key =
                russh::keys::load_secret_key(path, passphrase.as_ref().map(|p| p.expose_secret()))
                    .map_err(|e| match e {
                        russh::keys::Error::KeyIsEncrypted => {
                            format!("{} is encrypted — enter its passphrase", path.display())
                        }
                        russh::keys::Error::IO(e) => format!("Cannot read {}: {e}", path.display()),
                        e if passphrase.is_some() => {
                            format!("Cannot load {} (wrong passphrase?): {e}", path.display())
                        }
                        e => format!("Cannot load {}: {e}", path.display()),
                    })?;
            // Only RSA needs a hash choice; asking waits for server-sig-algs, which some servers never send.
            let hash = if key.algorithm().is_rsa() {
                rsa_hash(h).await
            } else {
                None
            };
            let r = h
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
                .map_err(|e| e.to_string())?;
            if r.success() {
                Ok(())
            } else {
                Err(format!(
                    "Key {} was not accepted for {user}",
                    path.display()
                ))
            }
        }
        AuthSpec::Agent => agent_auth(h, user).await,
    }
}

async fn rsa_hash(h: &Handle<Client>) -> Option<HashAlg> {
    tokio::time::timeout(Duration::from_secs(3), h.best_supported_rsa_hash())
        .await
        .ok()?
        .ok()
        .flatten()
        .flatten()
}

async fn agent_auth(h: &mut Handle<Client>, user: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        if let Ok(a) = russh::keys::agent::client::AgentClient::connect_named_pipe(
            r"\\.\pipe\openssh-ssh-agent",
        )
        .await
        {
            return try_agent(h, user, a).await;
        }
        if let Ok(a) = russh::keys::agent::client::AgentClient::connect_pageant().await {
            return try_agent(h, user, a).await;
        }
        Err(
            "No SSH agent found (Windows OpenSSH agent service not running, Pageant not open)"
                .into(),
        )
    }
    #[cfg(not(windows))]
    {
        match russh::keys::agent::client::AgentClient::connect_env().await {
            Ok(a) => try_agent(h, user, a).await,
            Err(_) => Err("No SSH agent found (SSH_AUTH_SOCK not set or unreachable)".into()),
        }
    }
}

async fn try_agent<S>(
    h: &mut Handle<Client>,
    user: &str,
    mut agent: russh::keys::agent::client::AgentClient<S>,
) -> Result<(), String>
where
    S: russh::keys::agent::client::AgentStream + Unpin + Send + 'static,
{
    let ids = agent
        .request_identities()
        .await
        .map_err(|e| format!("SSH agent error: {e}"))?;
    if ids.is_empty() {
        return Err("The SSH agent has no keys loaded".into());
    }
    for id in ids {
        let russh::keys::agent::AgentIdentity::PublicKey { key, .. } = id else {
            continue;
        };
        let hash = if key.algorithm().is_rsa() {
            rsa_hash(h).await
        } else {
            None
        };
        if let Ok(r) = h
            .authenticate_publickey_with(user, key, hash, &mut agent)
            .await
            && r.success()
        {
            return Ok(());
        }
    }
    Err(format!("None of the agent's keys were accepted for {user}"))
}

// ────────────────────────────────── actor ──────────────────────────────────

enum Internal {
    /// `generation` identifies which channel ended: a reader from a previous
    /// connection may report late, after the PTY was reopened on a new one.
    PtyEnded {
        pty: PtyId,
        generation: u64,
        exit: Option<u32>,
    },
}

struct Pty {
    term: Terminal,
    writer: Option<russh::ChannelWriteHalf<client::Msg>>,
    generation: u64,
}

enum End {
    Shutdown,
    UserDisconnect,
    Lost,
}

pub(crate) struct Actor {
    shared: Arc<Shared>,
    spec: ConnectSpec,
    rx: UnboundedReceiver<Command>,
    decisions_tx: UnboundedSender<KeyDecision>,
    decisions: Arc<tokio::sync::Mutex<UnboundedReceiver<KeyDecision>>>,
    keys: Arc<parking_lot::Mutex<KeyState>>,
    ptys: HashMap<PtyId, Pty>,
    internal_tx: UnboundedSender<Internal>,
    internal_rx: UnboundedReceiver<Internal>,
    next_generation: u64,
}

impl Actor {
    pub(crate) fn new(
        id: HostId,
        spec: ConnectSpec,
        rx: UnboundedReceiver<Command>,
        events: std::sync::mpsc::Sender<Event>,
        wake: Waker,
    ) -> Self {
        let (decisions_tx, decisions_rx) = unbounded_channel();
        let (internal_tx, internal_rx) = unbounded_channel();
        Self {
            shared: Arc::new(Shared { id, events, wake }),
            spec,
            rx,
            decisions_tx,
            decisions: Arc::new(tokio::sync::Mutex::new(decisions_rx)),
            keys: Arc::default(),
            ptys: HashMap::new(),
            internal_tx,
            internal_rx,
            next_generation: 1,
        }
    }

    fn emit(&self, k: EventKind) {
        self.shared.emit(k);
    }

    /// Handle commands that mean the same in every state; returns the rest.
    fn absorb(&mut self, c: Command) -> Option<Command> {
        match c {
            Command::OpenPty { pty, term } => {
                self.ptys.insert(
                    pty,
                    Pty {
                        term,
                        writer: None,
                        generation: 0,
                    },
                );
                None
            }
            Command::ClosePty(pty) => {
                self.ptys.remove(&pty);
                None
            }
            Command::HostKey(d) => {
                let _ = self.decisions_tx.send(d);
                None
            }
            // Collector commands arrive with M2; input while offline is dropped.
            Command::SetSection { .. }
            | Command::Now(_)
            | Command::Throttle(_)
            | Command::SetServices(_)
            | Command::PtyInput { .. }
            | Command::PtyResize { .. } => None,
            other => Some(other),
        }
    }

    pub(crate) async fn run(mut self) {
        let mut ever_connected = false;
        let mut attempt = 0usize;
        loop {
            self.emit(EventKind::State(ConnState::Connecting));
            let refused = Arc::new(AtomicBool::new(false));
            match self.connect(refused.clone()).await {
                Ok(Some(handle)) => {
                    ever_connected = true;
                    attempt = 0;
                    match self.session(handle).await {
                        End::Shutdown => return,
                        End::UserDisconnect => {
                            self.emit(EventKind::State(ConnState::Disconnected));
                            if !self.wait_for_retry().await {
                                return;
                            }
                            continue;
                        }
                        End::Lost => {
                            self.banner("\r\n\x1b[33m[connection lost — reconnecting…]\x1b[0m\r\n");
                        }
                    }
                }
                Ok(None) => return, // shutdown during connect
                Err(ConnectError::Auth(msg)) => {
                    self.emit(EventKind::AuthFailed(msg));
                    self.emit(EventKind::State(ConnState::Disconnected));
                    if !self.wait_for_retry().await {
                        return;
                    }
                    continue;
                }
                Err(ConnectError::Other(msg)) => {
                    // Host key refusals and first-connect failures need the user; drops after a
                    // working session reconnect on their own.
                    if refused.load(Ordering::SeqCst) || !ever_connected {
                        self.emit(EventKind::Error(msg));
                        self.emit(EventKind::State(ConnState::Disconnected));
                        if !self.wait_for_retry().await {
                            return;
                        }
                        continue;
                    }
                    self.emit(EventKind::Error(msg));
                }
            }
            // Backoff with a visible countdown; Retry skips the wait.
            let delay = BACKOFF[attempt.min(BACKOFF.len() - 1)];
            attempt += 1;
            if !self.countdown(delay).await {
                return;
            }
        }
    }

    fn banner(&self, text: &str) {
        for p in self.ptys.values() {
            p.term.advance(text.as_bytes());
        }
        (self.shared.wake)();
    }

    /// Wait (Disconnected) until Retry; false on Shutdown.
    async fn wait_for_retry(&mut self) -> bool {
        while let Some(c) = self.rx.recv().await {
            match self.absorb(c) {
                Some(Command::Retry(auth)) => {
                    if let Some(a) = auth {
                        self.spec.auth = a;
                    }
                    return true;
                }
                Some(Command::Shutdown) => return false,
                _ => {}
            }
        }
        false
    }

    async fn countdown(&mut self, secs: u32) -> bool {
        for left in (1..=secs).rev() {
            self.emit(EventKind::State(ConnState::Reconnecting { in_secs: left }));
            let sleep = tokio::time::sleep(Duration::from_secs(1));
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    _ = &mut sleep => break,
                    c = self.rx.recv() => match c.and_then(|c| self.absorb(c)) {
                        Some(Command::Retry(auth)) => {
                            if let Some(a) = auth { self.spec.auth = a; }
                            return true;
                        }
                        Some(Command::Shutdown) => return false,
                        Some(Command::Disconnect) => {
                            self.emit(EventKind::State(ConnState::Disconnected));
                            return self.wait_for_retry().await;
                        }
                        _ => {}
                    },
                }
            }
        }
        true
    }

    async fn connect(
        &mut self,
        refused: Arc<AtomicBool>,
    ) -> Result<Option<Handle<Client>>, ConnectError> {
        let config = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_max: 3,
            nodelay: true,
            ..Default::default()
        });
        let timeout = self.spec.connect_timeout;
        let prompt = Arc::new(parking_lot::Mutex::new(PromptClock::default()));
        let handler = Client {
            shared: self.shared.clone(),
            host: self.spec.address.clone(),
            port: self.spec.port,
            known_hosts: self.spec.known_hosts.clone(),
            decisions: self.decisions.clone(),
            keys: self.keys.clone(),
            key_refused: refused.clone(),
            prompt: prompt.clone(),
        };
        let addr = (self.spec.address.clone(), self.spec.port);

        // 1. TCP connect, bounded.
        let tcp = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr));
        tokio::pin!(tcp);
        let sock = loop {
            tokio::select! {
                r = &mut tcp => break r,
                c = self.rx.recv() => match c.and_then(|c| self.absorb(c)) {
                    Some(Command::Shutdown) => return Ok(None),
                    Some(Command::Disconnect) => return Err(ConnectError::Other("Cancelled".into())),
                    _ => {}
                },
            }
        };
        let sock = match sock {
            Err(_) => {
                return Err(ConnectError::Other(format!(
                    "Timed out after {}s",
                    timeout.as_secs()
                )));
            }
            Ok(Err(e)) => return Err(ConnectError::Other(format!("Network error: {e}"))),
            Ok(Ok(s)) => s,
        };
        let _ = sock.set_nodelay(true);

        // 2. SSH handshake. The idle deadline never counts time the user spends
        //    reading a host-key prompt (it re-arms while one is open or just closed).
        let hs = client::connect_stream(config, sock, handler);
        tokio::pin!(hs);
        let mut deadline = tokio::time::Instant::now() + timeout;
        let result = loop {
            tokio::select! {
                r = &mut hs => break r,
                _ = tokio::time::sleep_until(deadline) => {
                    let p = prompt.lock();
                    if p.active {
                        deadline = tokio::time::Instant::now() + timeout;
                    } else if let Some(t) = p.ended.filter(|t| t.elapsed() < timeout) {
                        deadline = tokio::time::Instant::from_std(t + timeout);
                    } else {
                        return Err(ConnectError::Other("Timed out during the SSH handshake".into()));
                    }
                }
                c = self.rx.recv() => match c.and_then(|c| self.absorb(c)) {
                    Some(Command::Shutdown) => return Ok(None),
                    Some(Command::Disconnect) => return Err(ConnectError::Other("Cancelled".into())),
                    _ => {}
                },
            }
        };
        let mut handle = match result {
            Ok(h) => h,
            Err(e) if refused.load(Ordering::SeqCst) => {
                return Err(ConnectError::Other(format!("Host key not accepted ({e})")));
            }
            Err(russh::Error::IO(e)) => {
                return Err(ConnectError::Other(format!("Network error: {e}")));
            }
            Err(e) => return Err(ConnectError::Other(e.to_string())),
        };

        self.emit(EventKind::State(ConnState::Authenticating));
        let user = self.spec.user.clone();
        let auth = self.spec.auth.clone();
        authenticate(&mut handle, &user, &auth)
            .await
            .map_err(ConnectError::Auth)?;
        Ok(Some(handle))
    }

    async fn open_pty(&mut self, handle: &Handle<Client>, pty: PtyId) -> Result<(), String> {
        let Some(p) = self.ptys.get_mut(&pty) else {
            return Ok(());
        };
        let size = p.term.size();
        let ch = handle
            .channel_open_session()
            .await
            .map_err(|e| e.to_string())?;
        ch.request_pty(
            false,
            TERM_NAME,
            size.cols as u32,
            size.rows as u32,
            0,
            0,
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
        ch.request_shell(false).await.map_err(|e| e.to_string())?;
        let (mut read, write) = ch.split();
        p.writer = Some(write);
        let generation = self.next_generation;
        self.next_generation += 1;
        p.generation = generation;
        let term = p.term.clone();
        let wake = self.shared.wake.clone();
        let internal = self.internal_tx.clone();
        tokio::spawn(async move {
            let mut exit = None;
            while let Some(msg) = read.wait().await {
                match msg {
                    ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => {
                        term.advance(&data);
                        wake();
                    }
                    ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
            let _ = internal.send(Internal::PtyEnded {
                pty,
                generation,
                exit,
            });
        });
        Ok(())
    }

    async fn session(&mut self, handle: Handle<Client>) -> End {
        let (algorithm, fingerprint, key_known) = self.keys.lock().seen.clone().unwrap_or_default();
        self.emit(EventKind::Connected(ConnInfo {
            user: self.spec.user.clone(),
            address: self.spec.address.clone(),
            port: self.spec.port,
            host_key: algorithm,
            fingerprint,
            key_known,
            sudo: SudoMode::Unknown, // probed in M2
        }));
        self.emit(EventKind::State(ConnState::Connected));

        let ids: Vec<PtyId> = self.ptys.keys().copied().collect();
        for pty in ids {
            if let Err(e) = self.open_pty(&handle, pty).await {
                self.emit(EventKind::Error(format!("Could not open terminal: {e}")));
            }
        }
        self.emit_link();

        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                c = self.rx.recv() => {
                    let Some(c) = c else { return End::Shutdown };
                    match c {
                        Command::OpenPty { pty, term } => {
                            self.ptys.insert(pty, Pty { term, writer: None, generation: 0 });
                            if let Err(e) = self.open_pty(&handle, pty).await {
                                self.emit(EventKind::Error(format!("Could not open terminal: {e}")));
                            }
                            self.emit_link();
                        }
                        Command::PtyInput { pty, bytes } => {
                            if let Some(w) = self.ptys.get(&pty).and_then(|p| p.writer.as_ref()) {
                                let _ = w.data_bytes(bytes).await;
                            }
                        }
                        Command::PtyResize { pty, cols, rows } => {
                            if let Some(w) = self.ptys.get(&pty).and_then(|p| p.writer.as_ref()) {
                                let _ = w.window_change(cols as u32, rows as u32, 0, 0).await;
                            }
                        }
                        Command::ClosePty(pty) => {
                            if let Some(w) = self.ptys.remove(&pty).and_then(|p| p.writer) {
                                let _ = w.close().await;
                            }
                            self.emit_link();
                        }
                        Command::Disconnect => {
                            let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
                            self.drop_writers();
                            return End::UserDisconnect;
                        }
                        Command::Shutdown => {
                            let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
                            return End::Shutdown;
                        }
                        other => { let _ = self.absorb(other); }
                    }
                }
                i = self.internal_rx.recv() => {
                    if let Some(Internal::PtyEnded { pty, generation, exit }) = i {
                        // Only the channel currently serving this tab counts.
                        let current = self.ptys.get(&pty).is_some_and(|p| p.generation == generation && p.writer.is_some());
                        if current && handle.is_closed() {
                            self.drop_writers();
                            return End::Lost;
                        }
                        if let Some(p) = self.ptys.get_mut(&pty).filter(|_| current) {
                            p.writer = None;
                            self.emit(EventKind::PtyClosed { pty, exit });
                            self.emit_link();
                        }
                    }
                }
                _ = tick.tick() => {
                    if handle.is_closed() {
                        self.drop_writers();
                        return End::Lost;
                    }
                }
            }
        }
    }

    fn drop_writers(&mut self) {
        for p in self.ptys.values_mut() {
            p.writer = None;
        }
        self.emit_link();
    }

    /// Status-bar channel count (open PTY channels; collector/log channels join in M2/M4).
    fn emit_link(&self) {
        let channels = self.ptys.values().filter(|p| p.writer.is_some()).count() as u32;
        self.emit(EventKind::Link(sw_core::model::LinkStats {
            rtt_ms: None,
            overhead_bps: 0.0,
            channels,
        }));
    }
}

enum ConnectError {
    Auth(String),
    Other(String),
}
