//! The contract between the UI thread and the net side. The UI only ever sees
//! these types; whether the russh actor or the demo source produces them is
//! invisible to it.

use std::path::PathBuf;

use secrecy::SecretString;
use sw_core::Section;
use sw_core::alerts::Alert;
use sw_core::logs::LogLine;
use sw_core::model::{
    CpuSample, DiskIo, HostStatic, LinkStats, MemSample, Mount, NetSample, Process, ServiceInfo,
    Session,
};
use sw_term::Terminal;

pub type HostId = u32;
pub type PtyId = u32;

/// How privileged commands are run on this host (protocol §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudoMode {
    Root,
    NoPasswd,
    /// Password entered this session and held in memory.
    Password,
    /// No privileged access (skipped or failed).
    None,
    /// Not probed yet (probe arrives in M2).
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Connecting,
    Authenticating,
    Connected,
    Reconnecting { in_secs: u32 },
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnInfo {
    pub user: String,
    pub address: String,
    pub port: u16,
    /// Host key algorithm, e.g. `ssh-ed25519`.
    pub host_key: String,
    pub fingerprint: String,
    /// Found in a known_hosts file (vs. accepted once / just trusted).
    pub key_known: bool,
    pub sudo: SudoMode,
}

/// Credentials. Secrets live only in memory and are zeroized on drop.
#[derive(Debug, Clone)]
pub enum AuthSpec {
    Agent,
    KeyFile {
        path: PathBuf,
        passphrase: Option<SecretString>,
    },
    Password(SecretString),
}

#[derive(Debug, Clone)]
pub struct KnownHosts {
    /// The user's OpenSSH file (`~/.ssh/known_hosts`); read-only for us.
    pub user_file: Option<PathBuf>,
    /// SecureWire's own file; keys the user trusts are appended here.
    pub app_file: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ConnectSpec {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthSpec,
    pub known_hosts: KnownHosts,
    /// TCP connect and SSH-handshake idle limit (host-key prompt time excluded).
    pub connect_timeout: std::time::Duration,
}

impl ConnectSpec {
    pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDecision {
    /// Remember in SecureWire's known_hosts.
    Trust,
    /// Accept for this session only.
    Once,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKeyStatus {
    Unknown,
    /// A different key is recorded for this host — possible MITM.
    Changed {
        file: String,
        line: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogKind {
    Journal,
    File,
    SudoFile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSourceInfo {
    pub name: String,
    pub kind: LogKind,
    pub target: String,
}

/// Collection speed, driven by window focus/visibility (protocol §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Throttle {
    /// Window focused, host tab active: default tiers.
    Normal,
    /// Window unfocused.
    Background,
    /// Minimized or host tab inactive.
    Hidden,
}

impl Throttle {
    /// (fast, medium, slow) tier intervals in seconds.
    pub fn tiers(self) -> (u64, u64, u64) {
        match self {
            Throttle::Normal => (2, 10, 60),
            Throttle::Background => (10, 30, 60),
            Throttle::Hidden => (30, 120, 0), // 0 = slow sections off
        }
    }
}

#[derive(Debug)]
pub enum Command {
    /// Section visible (`ON`) or collapsed/hidden (`OFF`).
    SetSection {
        section: Section,
        on: bool,
    },
    /// Emit a section immediately (`NOW`).
    Now(Section),
    Throttle(Throttle),
    /// Replace the watched unit list (`SVC`).
    SetServices(Vec<String>),
    /// Open (or re-open after exit) a PTY shell feeding `term`.
    OpenPty {
        pty: PtyId,
        term: Terminal,
    },
    PtyInput {
        pty: PtyId,
        bytes: Vec<u8>,
    },
    PtyResize {
        pty: PtyId,
        cols: u16,
        rows: u16,
    },
    ClosePty(PtyId),
    /// Answer to [`EventKind::HostKeyPrompt`].
    HostKey(KeyDecision),
    /// Live / Poll / Manual service status (protocol §3).
    SetServiceMode {
        mode: sw_core::config::ServiceMode,
        poll_secs: u32,
    },
    /// Fetch the unit list for the "Watched services" picker → [`EventKind::Units`].
    ListUnits,
    /// Answer to [`EventKind::SudoPrompt`]: `None` = skip (no privileged features).
    SudoPassword(Option<SecretString>),
    /// Ask for the sudo password again (status bar → "no sudo").
    SudoAsk,
    /// Reconnect now, optionally with new credentials.
    Retry(Option<AuthSpec>),
    Disconnect,
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum EventKind {
    State(ConnState),
    Connected(ConnInfo),
    HostKeyPrompt {
        algorithm: String,
        fingerprint: String,
        status: HostKeyStatus,
    },
    /// Authentication failed; the actor waits for `Retry(Some(..))`.
    AuthFailed(String),
    /// Connection-level error shown to the user.
    Error(String),
    PtyClosed {
        pty: PtyId,
        exit: Option<u32>,
    },
    /// Capabilities from the probe (protocol §4).
    Probe(sw_core::parse::Probe),
    /// Privileged features need a sudo password (protocol §9).
    SudoPrompt {
        message: Option<String>,
        attempts_left: u8,
    },
    Sudo(SudoMode),
    Listeners(Vec<sw_core::model::Listener>),
    Conns(Vec<sw_core::model::Conn>),
    Firewall(sw_core::model::Firewall),
    Jails(Vec<sw_core::model::Jail>),
    Auth(sw_core::model::AuthStats),
    Scheduled(sw_core::model::Scheduled),
    Units(Vec<sw_core::model::UnitInfo>),
    /// Effective service-status mode (Live degrades to polling without journal access).
    ServiceMode {
        live_watching: bool,
    },
    Static(HostStatic),
    Cpu(CpuSample),
    Mem(MemSample),
    Net(NetSample),
    DiskIo(DiskIo),
    Mounts(Vec<Mount>),
    Sessions(Vec<Session>),
    Services(Vec<ServiceInfo>),
    Processes(Vec<Process>),
    LogSources(Vec<LogSourceInfo>),
    Logs(Vec<LogLine>),
    Alerts(Vec<Alert>),
    Link(LinkStats),
    SectionError {
        section: Section,
        code: String,
    },
}

#[derive(Debug, Clone)]
pub struct Event {
    pub host: HostId,
    pub kind: EventKind,
}
