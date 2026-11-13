//! The real host actor: one russh connection per host, one task on the net
//! runtime. M1 scope: connect, host-key verification (TOFU), auth (agent /
//! key file / password), PTY channels, keepalive, reconnect with backoff.
//! Collector and log channels join in M2/M4 on the same connection.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use russh::ChannelMsg;
use russh::client::{self, Handle};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use secrecy::{ExposeSecret, SecretString};
use sw_core::Section;
use sw_core::model::LinkStats;
use sw_core::parse::Probe;
use sw_term::Terminal;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::Waker;
use crate::api::{
    AuthSpec, Command, ConnInfo, ConnState, ConnectSpec, Event, EventKind, HostId, HostKeyStatus,
    KeyDecision, LogKind, LogSourceInfo, PtyId, SudoMode, Throttle,
};
use crate::collector::{self, Priv};
use crate::remote::{self, CollectorMsg};
use sw_core::config::ServiceMode;
use sw_core::logs::Preset;

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

    /// Several events, one UI wake-up.
    fn emit_batch(&self, kinds: Vec<EventKind>) {
        for kind in kinds {
            let _ = self.events.send(Event {
                host: self.id,
                kind,
            });
        }
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
    Probed(Result<Probe, String>),
    SudoChecked {
        password: SecretString,
        result: Result<bool, String>,
    },
    CollectorStarted {
        generation: u64,
        result: Result<remote::Writer, String>,
    },
    WatcherStarted {
        generation: u64,
        result: Result<remote::Writer, String>,
    },
    Units(Result<Vec<sw_core::model::UnitInfo>, String>),
    LogStarted {
        generation: u64,
        result: Result<remote::Writer, String>,
    },
    Discovered(Result<Vec<sw_core::logs::LogCandidate>, String>),
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

const SUDO_ATTEMPTS: u8 = 3;

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
    // ---- collector (protocol §2), replayed onto every new collector ----
    sections: HashMap<Section, bool>,
    throttle: Throttle,
    services: Vec<String>,
    collector: Option<remote::Writer>,
    /// Bumped per session so messages from an old collector are ignored.
    collector_gen: u64,
    coll_tx: UnboundedSender<CollectorMsg>,
    coll_rx: UnboundedReceiver<CollectorMsg>,
    clock: Instant,
    link: LinkStats,
    // ---- privilege (protocol §9) ----
    probe: Option<Probe>,
    sudo_mode: SudoMode,
    /// Held in memory for the host session (survives reconnects), never persisted.
    sudo_password: Option<SecretString>,
    sudo_attempts: u8,
    sudo_checking: bool,
    sudo_skipped: bool,
    // ---- M3: privilege the collector runs with, service status mode ----
    handle: Option<Arc<Handle<Client>>>,
    collector_priv: Priv,
    service_mode: ServiceMode,
    poll_secs: u32,
    watcher: Option<remote::Writer>,
    watcher_gen: u64,
    last_unit_now: Option<Instant>,
    // ---- M4: log channels (protocol §6) ----
    log_sources: Vec<sw_core::config::LogSourceConfig>,
    log_backlog: u32,
    log_writers: Vec<remote::Writer>,
    log_gen: u64,
    journal_cursor: Option<String>,
    /// Logs ran in an earlier session → resume (cursor, no file backlog) after reconnect.
    logs_ran: bool,
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
        let (coll_tx, coll_rx) = unbounded_channel();
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
            sections: HashMap::new(),
            throttle: Throttle::Normal,
            services: Vec::new(),
            collector: None,
            collector_gen: 0,
            coll_tx,
            coll_rx,
            clock: Instant::now(),
            link: LinkStats::default(),
            probe: None,
            sudo_mode: SudoMode::Unknown,
            sudo_password: None,
            sudo_attempts: 0,
            sudo_checking: false,
            sudo_skipped: false,
            handle: None,
            collector_priv: Priv::None,
            service_mode: ServiceMode::Live,
            poll_secs: 30,
            watcher: None,
            watcher_gen: 0,
            last_unit_now: None,
            log_sources: Vec::new(),
            log_backlog: 200,
            log_writers: Vec::new(),
            log_gen: 0,
            journal_cursor: None,
            logs_ran: false,
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
            // Remembered while offline, replayed onto the next collector.
            Command::SetSection { section, on } => {
                self.sections.insert(section, on);
                None
            }
            Command::Throttle(t) => {
                self.throttle = t;
                None
            }
            Command::SetServices(u) => {
                self.services = u;
                None
            }
            Command::SetServiceMode { mode, poll_secs } => {
                self.service_mode = mode;
                self.poll_secs = poll_secs.max(5);
                None
            }
            // Meaningless without a connection.
            Command::ListUnits => None,
            Command::SetLogSources { sources, backlog } => {
                self.log_sources = sources;
                self.log_backlog = backlog;
                self.emit_log_sources();
                None
            }
            Command::DiscoverLogs => None,
            Command::Now(_)
            | Command::PtyInput { .. }
            | Command::PtyResize { .. }
            | Command::SudoPassword(_)
            | Command::SudoAsk => None,
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
        let handle = Arc::new(handle);
        self.handle = Some(handle.clone());
        let (algorithm, fingerprint, key_known) = self.keys.lock().seen.clone().unwrap_or_default();
        self.emit(EventKind::Connected(ConnInfo {
            user: self.spec.user.clone(),
            address: self.spec.address.clone(),
            port: self.spec.port,
            host_key: algorithm,
            fingerprint,
            key_known,
            sudo: self.sudo_mode,
        }));
        self.emit(EventKind::State(ConnState::Connected));

        let ids: Vec<PtyId> = self.ptys.keys().copied().collect();
        for pty in ids {
            if let Err(e) = self.open_pty(&handle, pty).await {
                self.emit(EventKind::Error(format!("Could not open terminal: {e}")));
            }
        }
        self.emit_link();

        // Probe → sudo → collector run off this loop so the terminal stays responsive.
        self.collector_gen += 1;
        {
            let (h, tx) = (handle.clone(), self.internal_tx.clone());
            tokio::spawn(async move {
                let _ = tx.send(Internal::Probed(remote::run_probe(&h).await));
            });
        }

        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut ping = tokio::time::interval(Duration::from_secs(10));
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
                        Command::SetSection { section, on } => {
                            self.sections.insert(section, on);
                            self.coll_line(&collector::on_off(section, on)).await;
                        }
                        Command::Now(s) => self.coll_line(&collector::now(s)).await,
                        Command::Throttle(t) => {
                            self.throttle = t;
                            for l in collector::tiers(t) {
                                self.coll_line(&l).await;
                            }
                        }
                        Command::SetServices(u) => {
                            self.services = u;
                            let l = collector::svc(&self.services);
                            self.coll_line(&l).await;
                            self.apply_service_mode().await;
                        }
                        Command::SetServiceMode { mode, poll_secs } => {
                            self.service_mode = mode;
                            self.poll_secs = poll_secs.max(5);
                            self.apply_service_mode().await;
                        }
                        Command::ListUnits => self.list_units(),
                        Command::SetLogSources { sources, backlog } => {
                            self.log_sources = sources;
                            self.log_backlog = backlog;
                            self.emit_log_sources();
                            self.start_logs(false).await;
                        }
                        Command::DiscoverLogs => self.discover_logs(),
                        Command::SudoPassword(Some(pw)) => self.check_sudo(&handle, pw),
                        Command::SudoPassword(None) => {
                            self.sudo_skipped = true;
                            self.set_sudo(SudoMode::None).await;
                        }
                        Command::SudoAsk => {
                            self.sudo_skipped = false;
                            self.sudo_attempts = 0;
                            self.ask_sudo(true);
                        }
                        Command::Disconnect => {
                            let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
                            self.end_session();
                            return End::UserDisconnect;
                        }
                        Command::Shutdown => {
                            if let Some(w) = &self.collector {
                                remote::send_line(w, "QUIT").await;
                            }
                            let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
                            return End::Shutdown;
                        }
                        other => { let _ = self.absorb(other); }
                    }
                }
                i = self.internal_rx.recv() => match i {
                    Some(Internal::PtyEnded { pty, generation, exit }) => {
                        // Only the channel currently serving this tab counts.
                        let current = self.ptys.get(&pty).is_some_and(|p| p.generation == generation && p.writer.is_some());
                        if current && handle.is_closed() {
                            self.end_session();
                            return End::Lost;
                        }
                        if let Some(p) = self.ptys.get_mut(&pty).filter(|_| current) {
                            p.writer = None;
                            self.emit(EventKind::PtyClosed { pty, exit });
                            self.emit_link();
                        }
                    }
                    Some(Internal::Probed(Ok(p))) => self.on_probe(p).await,
                    Some(Internal::Probed(Err(e))) => {
                        self.emit(EventKind::Error(format!("Host probe failed ({e}) — live metrics are off")));
                    }
                    Some(Internal::SudoChecked { password, result }) => self.on_sudo_checked(password, result).await,
                    Some(Internal::WatcherStarted { generation, result }) => {
                        if generation == self.watcher_gen {
                            match result {
                                Ok(w) => {
                                    self.watcher = Some(w);
                                    self.emit(EventKind::ServiceMode { live_watching: true });
                                    self.emit_link();
                                }
                                Err(_) => self.watch_fallback().await,
                            }
                        }
                    }
                    Some(Internal::Units(Ok(u))) => self.emit(EventKind::Units(u)),
                    Some(Internal::LogStarted { generation, result }) => {
                        if generation == self.log_gen {
                            match result {
                                Ok(w) => {
                                    self.log_writers.push(w);
                                    self.emit_link();
                                }
                                Err(e) => self.emit(EventKind::Error(format!("Could not start a log channel: {e}"))),
                            }
                        }
                    }
                    Some(Internal::Discovered(Ok(c))) => self.emit(EventKind::LogCandidates(c)),
                    Some(Internal::Discovered(Err(e))) => self.emit(EventKind::Error(format!("Log discovery failed: {e}"))),
                    Some(Internal::Units(Err(e))) => self.emit(EventKind::Error(format!("Could not list units: {e}"))),
                    Some(Internal::CollectorStarted { generation, result }) => {
                        if generation == self.collector_gen {
                            match result {
                                Ok(w) => {
                                    let sections: Vec<(Section, bool)> =
                                        self.sections.iter().map(|(&s, &on)| (s, on)).collect();
                                    let lines = collector::tiers(self.throttle)
                                        .into_iter()
                                        .chain(collector::replay(&sections, &self.services));
                                    for l in lines {
                                        remote::send_line(&w, &l).await;
                                    }
                                    // First RTT sample right away instead of after the 10 s ping tick.
                                    remote::send_line(&w, &collector::ping(self.clock.elapsed().as_millis() as u64)).await;
                                    self.collector = Some(w);
                                    self.emit_link();
                                    // sudo became available while this collector was starting → relaunch with it.
                                    if Priv::from_sudo(self.sudo_mode) != self.collector_priv {
                                        self.spawn_collector().await;
                                    } else {
                                        self.apply_service_mode().await;
                                    }
                                }
                                Err(e) => self.emit(EventKind::Error(format!("Could not start the collector: {e}"))),
                            }
                        }
                    }
                    None => return End::Shutdown,
                },
                m = self.coll_rx.recv() => match m {
                    Some(CollectorMsg::Rtt(ms)) => {
                        self.link.rtt_ms = Some(ms);
                        self.emit_link();
                    }
                    Some(CollectorMsg::Overhead(bps)) => {
                        self.link.overhead_bps = bps;
                        self.emit_link();
                    }
                    Some(CollectorMsg::Ended { generation })
                        if generation == self.collector_gen && self.collector.is_some() =>
                    {
                        self.collector = None;
                        self.emit_link();
                        if !handle.is_closed() {
                            self.emit(EventKind::Error("Live metrics stopped: the collector exited".into()));
                        }
                    }
                    Some(CollectorMsg::JournalCursor(c)) => self.journal_cursor = Some(c),
                    Some(CollectorMsg::LogEnded { generation, reason }) => {
                        if generation == self.log_gen && !handle.is_closed()
                            && let Some(r) = reason {
                                self.emit(EventKind::Error(format!("A log source stopped: {r}")));
                            }
                    }
                    Some(CollectorMsg::UnitEvent) => {
                        // A watched unit changed: refresh now, at most once a second.
                        if self.last_unit_now.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                            self.last_unit_now = Some(Instant::now());
                            self.coll_line(&collector::now(Section::Svc)).await;
                        }
                    }
                    Some(CollectorMsg::WatcherEnded { generation }) => {
                        if generation == self.watcher_gen && self.watcher.take().is_some() && !handle.is_closed() {
                            self.watch_fallback().await;
                        }
                    }
                    // A collector from an earlier session, or already gone.
                    Some(CollectorMsg::Ended { .. }) | None => {}
                },
                _ = ping.tick() => {
                    if let Some(w) = &self.collector {
                        remote::send_line(w, &collector::ping(self.clock.elapsed().as_millis() as u64)).await;
                    }
                }
                _ = tick.tick() => {
                    if handle.is_closed() {
                        self.end_session();
                        return End::Lost;
                    }
                }
            }
        }
    }

    async fn coll_line(&self, line: &str) {
        if let Some(w) = &self.collector {
            remote::send_line(w, line).await;
        }
    }

    async fn on_probe(&mut self, p: Probe) {
        self.emit(EventKind::Probe(p.clone()));
        let mode = if p.is_root() {
            SudoMode::Root
        } else if p.sudo_n {
            SudoMode::NoPasswd
        } else if self.sudo_password.is_some() {
            SudoMode::Password // entered earlier this host session (reconnect)
        } else {
            SudoMode::None
        };
        let has_bash = p.bash.is_some();
        self.probe = Some(p);
        self.sudo_mode = mode;
        self.emit(EventKind::Sudo(mode));
        self.ask_sudo(false);
        if !has_bash {
            self.emit(EventKind::Error(
                "bash is not installed on this host — live metrics need bash".into(),
            ));
            return;
        }
        self.spawn_collector().await;
    }

    /// (Re)start the collector with the current privilege. An older collector is told to quit.
    async fn spawn_collector(&mut self) {
        let Some(h) = self.handle.clone() else { return };
        if !self.probe.as_ref().is_some_and(|p| p.bash.is_some()) {
            return;
        }
        if let Some(old) = self.collector.take() {
            remote::send_line(&old, "QUIT").await;
            let _ = old.close().await;
        }
        self.collector_gen += 1;
        let generation = self.collector_gen;
        let privilege = Priv::from_sudo(self.sudo_mode);
        self.collector_priv = privilege;
        let password = if privilege == Priv::Password {
            self.sudo_password.clone()
        } else {
            None
        };
        let (tx, msgs) = (self.internal_tx.clone(), self.coll_tx.clone());
        let (throttle, clock, shared) = (self.throttle, self.clock, self.shared.clone());
        tokio::spawn(async move {
            let emit = move |evs: Vec<EventKind>| shared.emit_batch(evs);
            let launch = remote::Launch {
                throttle,
                privilege,
                password,
                generation,
                clock,
            };
            let result = remote::start_collector(&h, launch, emit, msgs).await;
            let _ = tx.send(Internal::CollectorStarted { generation, result });
        });
    }

    /// Apply Live / Poll / Manual to the collector and the unit watcher (protocol §3).
    async fn apply_service_mode(&mut self) {
        if let Some(w) = self.watcher.take() {
            let _ = w.close().await;
        }
        self.watcher_gen += 1;
        self.emit_link();
        match self.service_mode {
            ServiceMode::Poll => {
                self.coll_line(&collector::every(Section::Svc, self.poll_secs))
                    .await;
                self.emit(EventKind::ServiceMode {
                    live_watching: false,
                });
            }
            ServiceMode::Manual => {
                self.coll_line(&collector::every(Section::Svc, 0)).await;
                self.emit(EventKind::ServiceMode {
                    live_watching: false,
                });
            }
            ServiceMode::Live => {
                self.coll_line(&collector::every(Section::Svc, 0)).await;
                let Some(h) = self.handle.clone() else { return };
                let journal_ok = self.probe.as_ref().is_some_and(|p| p.journal_read);
                let (prefix, secret) = match (journal_ok, self.sudo_mode) {
                    (true, _) | (false, SudoMode::Root) => ("", None),
                    (false, SudoMode::NoPasswd) => ("sudo -n ", None),
                    (false, SudoMode::Password) => ("sudo -S -p \"\" ", self.sudo_password.clone()),
                    _ => return self.watch_fallback().await,
                };
                let Some(cmd) = collector::unit_watch_command(&self.services, prefix) else {
                    return; // nothing watched yet
                };
                let (generation, tx, msgs) = (
                    self.watcher_gen,
                    self.internal_tx.clone(),
                    self.coll_tx.clone(),
                );
                tokio::spawn(async move {
                    let result =
                        remote::start_unit_watcher(&h, cmd, secret, generation, msgs).await;
                    let _ = tx.send(Internal::WatcherStarted { generation, result });
                });
            }
        }
    }

    /// Live mode without journal access: poll quickly instead (shown as "LIVE · POLLING").
    async fn watch_fallback(&mut self) {
        self.coll_line(&collector::every(Section::Svc, 5)).await;
        self.emit(EventKind::ServiceMode {
            live_watching: false,
        });
        self.emit_link();
    }

    fn list_units(&self) {
        let Some(h) = self.handle.clone() else { return };
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let r = remote::run_exec(
                &h,
                collector::LIST_UNITS_COMMAND,
                None,
                None,
                Duration::from_secs(20),
                1 << 20,
            )
            .await
            .map(|(out, _)| sw_core::parse::parse_units(&out));
            let _ = tx.send(Internal::Units(r));
        });
    }

    /// (Re)start the log channels (protocol §6): one for journal units, one for
    /// readable files, one for root-only files. `resume`: after a reconnect, the
    /// journal continues from its cursor and files start with no backlog.
    async fn start_logs(&mut self, resume: bool) {
        for w in self.log_writers.drain(..) {
            let _ = w.close().await;
        }
        self.log_gen += 1;
        self.emit_link();
        let (Some(h), Some(probe)) = (self.handle.clone(), self.probe.clone()) else {
            return;
        };
        if self.log_sources.is_empty() {
            return;
        }
        self.logs_ran = true;
        let generation = self.log_gen;
        let privilege = Priv::from_sudo(self.sudo_mode);
        let secret = |p: Priv| {
            if p == Priv::Password {
                self.sudo_password.clone()
            } else {
                None
            }
        };
        let mut channels: Vec<(String, Option<SecretString>, remote::LogBackend)> = Vec::new();

        let journal: Vec<(String, u16)> = self
            .log_sources
            .iter()
            .enumerate()
            .filter(|(_, s)| s.kind == "journal")
            .map(|(i, s)| (s.target.clone(), i as u16))
            .collect();
        if !journal.is_empty() {
            let jp = if probe.journal_read {
                Priv::None
            } else {
                privilege
            };
            if !probe.journal_read && jp == Priv::None {
                self.emit(EventKind::Error(
                    "Journal log sources need sudo on this host (click \"no sudo\" in the status bar)".into(),
                ));
            } else {
                let units: Vec<String> = journal.iter().map(|j| j.0.clone()).collect();
                let cursor = if resume {
                    self.journal_cursor.as_deref()
                } else {
                    None
                };
                if let Some(cmd) = collector::journal_command(
                    &units,
                    self.log_backlog,
                    cursor,
                    collector::sudo_prefix(jp),
                ) {
                    channels.push((
                        cmd,
                        secret(jp),
                        remote::LogBackend::Journal(journal.into_iter().collect()),
                    ));
                }
            }
        }
        for (kind, p) in [("file", Priv::None), ("sudo-file", privilege)] {
            let files: Vec<(String, u16, Preset)> = self
                .log_sources
                .iter()
                .enumerate()
                .filter(|(_, s)| s.kind == kind)
                .map(|(i, s)| {
                    (
                        s.target.clone(),
                        i as u16,
                        Preset::from_name(s.preset.as_deref().unwrap_or("")),
                    )
                })
                .collect();
            if files.is_empty() {
                continue;
            }
            if kind == "sudo-file" && p == Priv::None {
                self.emit(EventKind::Error(format!(
                    "{} log file(s) need sudo (click \"no sudo\" in the status bar)",
                    files.len()
                )));
                continue;
            }
            let paths: Vec<String> = files.iter().map(|f| f.0.clone()).collect();
            let backlog = if resume { 0 } else { self.log_backlog };
            if let Some(cmd) = collector::tail_command(&paths, backlog, collector::sudo_prefix(p)) {
                channels.push((cmd, secret(p), remote::LogBackend::Files(files)));
            }
        }
        for (cmd, secret, backend) in channels {
            let (h, tx, msgs, shared) = (
                h.clone(),
                self.internal_tx.clone(),
                self.coll_tx.clone(),
                self.shared.clone(),
            );
            tokio::spawn(async move {
                let emit = move |evs: Vec<EventKind>| shared.emit_batch(evs);
                let result =
                    remote::start_log_channel(&h, cmd, secret, backend, generation, emit, msgs)
                        .await;
                let _ = tx.send(Internal::LogStarted { generation, result });
            });
        }
    }

    fn emit_log_sources(&self) {
        let infos = self
            .log_sources
            .iter()
            .map(|s| LogSourceInfo {
                name: s.id.clone(),
                kind: match s.kind.as_str() {
                    "journal" => LogKind::Journal,
                    "sudo-file" => LogKind::SudoFile,
                    _ => LogKind::File,
                },
                target: s.target.clone(),
            })
            .collect();
        self.emit(EventKind::LogSources(infos));
    }

    fn discover_logs(&self) {
        let Some(h) = self.handle.clone() else { return };
        let p = Priv::from_sudo(self.sudo_mode);
        let secret = if p == Priv::Password {
            self.sudo_password.clone()
        } else {
            None
        };
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let r = remote::run_exec(
                &h,
                &collector::discover_command(p),
                Some(collector::DISCOVER),
                secret.as_ref(),
                Duration::from_secs(30),
                1 << 20,
            )
            .await
            .map(|(out, _)| sw_core::logs::parse_discovery(&out));
            let _ = tx.send(Internal::Discovered(r));
        });
    }

    /// Prompt for the sudo password when privileged access needs one (protocol §9).
    fn ask_sudo(&self, explicit: bool) {
        let Some(p) = &self.probe else { return };
        if p.is_root() || p.sudo_n || self.sudo_password.is_some() || self.sudo_checking {
            return;
        }
        if !p.sudo {
            if explicit {
                self.emit(EventKind::Error(
                    "sudo is not installed on this host".into(),
                ));
            }
            return;
        }
        if self.sudo_skipped || self.sudo_attempts >= SUDO_ATTEMPTS {
            return;
        }
        self.emit(EventKind::SudoPrompt {
            message: None,
            attempts_left: SUDO_ATTEMPTS - self.sudo_attempts,
        });
    }

    fn check_sudo(&mut self, handle: &Arc<Handle<Client>>, password: SecretString) {
        if self.sudo_checking {
            return;
        }
        self.sudo_checking = true;
        let (h, tx) = (handle.clone(), self.internal_tx.clone());
        tokio::spawn(async move {
            let result = remote::verify_sudo(&h, &password).await;
            let _ = tx.send(Internal::SudoChecked { password, result });
        });
    }

    async fn on_sudo_checked(&mut self, password: SecretString, result: Result<bool, String>) {
        self.sudo_checking = false;
        match result {
            Ok(true) => {
                self.sudo_password = Some(password);
                self.sudo_attempts = 0;
                self.set_sudo(SudoMode::Password).await;
            }
            Ok(false) => {
                self.sudo_attempts += 1;
                if self.sudo_attempts >= SUDO_ATTEMPTS {
                    self.set_sudo(SudoMode::None).await;
                    self.emit(EventKind::Error(
                        "sudo rejected the password 3 times — privileged panels stay off (retry from the status bar)".into(),
                    ));
                } else {
                    self.emit(EventKind::SudoPrompt {
                        message: Some("Wrong password".into()),
                        attempts_left: SUDO_ATTEMPTS - self.sudo_attempts,
                    });
                }
            }
            Err(e) => {
                self.set_sudo(SudoMode::None).await;
                self.emit(EventKind::Error(format!(
                    "Could not check the sudo password: {e}"
                )));
            }
        }
    }

    /// New privilege → relaunch the collector (root-only sections) and the unit watcher.
    async fn set_sudo(&mut self, mode: SudoMode) {
        let before = Priv::from_sudo(self.sudo_mode);
        self.sudo_mode = mode;
        self.emit(EventKind::Sudo(mode));
        if self.collector.is_some() && Priv::from_sudo(mode) != self.collector_priv {
            self.spawn_collector().await;
        }
        // sudo-only log sources (and a privileged journal) can start now.
        if before != Priv::from_sudo(mode) && !self.log_sources.is_empty() && self.probe.is_some() {
            self.start_logs(self.logs_ran).await;
        }
    }

    /// Connection gone: drop channel writers; stale reader messages are ignored by generation.
    fn end_session(&mut self) {
        for p in self.ptys.values_mut() {
            p.writer = None;
        }
        self.collector = None;
        self.collector_gen += 1;
        self.watcher = None;
        self.watcher_gen += 1;
        self.log_writers.clear();
        self.log_gen += 1;
        self.handle = None;
        self.link.rtt_ms = None;
        self.link.overhead_bps = 0.0;
        self.emit_link();
    }

    /// Status-bar link numbers: open PTY channels + collector.
    fn emit_link(&self) {
        let ptys = self.ptys.values().filter(|p| p.writer.is_some()).count() as u32;
        self.emit(EventKind::Link(LinkStats {
            channels: ptys
                + u32::from(self.collector.is_some())
                + u32::from(self.watcher.is_some()),
            ..self.link
        }));
    }
}

enum ConnectError {
    Auth(String),
    Other(String),
}
