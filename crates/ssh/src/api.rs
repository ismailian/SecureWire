//! The contract between the UI thread and the net side. The UI only ever sees
//! these types; whether a real SSH actor or the demo source produces them is
//! invisible to it.

use sw_core::Section;
use sw_core::alerts::Alert;
use sw_core::logs::LogLine;
use sw_core::model::{
    CpuSample, DiskIo, HostStatic, LinkStats, MemSample, Mount, NetSample, Process, ServiceInfo, Session,
};

pub type HostId = u32;

/// How privileged commands are run on this host (protocol §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudoMode {
    Root,
    NoPasswd,
    /// Password entered this session and held in memory.
    Password,
    /// No privileged access (skipped or failed).
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Connecting,
    Connected,
    Reconnecting { in_secs: u32 },
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnInfo {
    pub user: String,
    pub address: String,
    pub port: u16,
    pub host_key: String,
    pub key_known: bool,
    pub sudo: SudoMode,
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

#[derive(Debug, Clone)]
pub enum Command {
    /// Section visible (`ON`) or collapsed/hidden (`OFF`).
    SetSection { section: Section, on: bool },
    /// Emit a section immediately (`NOW`).
    Now(Section),
    Throttle(Throttle),
    /// Replace the watched unit list (`SVC`).
    SetServices(Vec<String>),
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum EventKind {
    State(ConnState),
    Connected(ConnInfo),
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
    SectionError { section: Section, code: String },
}

#[derive(Debug, Clone)]
pub struct Event {
    pub host: HostId,
    pub kind: EventKind,
}
