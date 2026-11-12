//! Ready-to-draw types the UI receives. Produced by `parse` + `metrics`.

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostStatic {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub cpus: u32,
    pub virt: String,
    pub mem_total: u64,
}

/// CPU utilisation over the last sample interval, in percent (0–100).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CpuSample {
    pub total: f32,
    pub user: f32,
    pub system: f32,
    pub iowait: f32,
    pub steal: f32,
    pub cores: Vec<f32>,
    pub load: [f32; 3],
    pub uptime_s: f64,
}

/// Memory in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemSample {
    pub total: u64,
    /// total − available (what applications actually hold).
    pub used: u64,
    /// Reclaimable page cache + buffers (part of "available").
    pub cache: u64,
    pub swap_total: u64,
    pub swap_used: u64,
}

impl MemSample {
    pub fn used_frac(&self) -> f32 {
        ratio(self.used, self.total)
    }
    pub fn cache_frac(&self) -> f32 {
        ratio(self.cache, self.total)
    }
    pub fn swap_frac(&self) -> f32 {
        ratio(self.swap_used, self.swap_total)
    }
    pub fn available(&self) -> u64 {
        self.total.saturating_sub(self.used)
    }
}

/// Throughput of the primary interface, bytes per second.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NetSample {
    pub iface: String,
    pub rx_bps: f64,
    pub tx_bps: f64,
}

/// Disk throughput summed over whole disks, bytes per second.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct DiskIo {
    pub read_bps: f64,
    pub write_bps: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mount {
    pub fs: String,
    pub mount: String,
    pub size: u64,
    pub used: u64,
    pub avail: u64,
}

impl Mount {
    /// Usage as `df` reports it: used / (used + avail), ignoring reserved blocks.
    pub fn frac(&self) -> f32 {
        ratio(self.used, self.used + self.avail)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub tty: String,
    pub from: String,
    /// `"."` = active now, `"old"`, or `HH:MM`.
    pub idle: String,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ActiveState {
    Active,
    Reloading,
    Inactive,
    Failed,
    Activating,
    Deactivating,
    #[default]
    Unknown,
}

impl ActiveState {
    pub fn parse(s: &str) -> Self {
        match s {
            "active" => Self::Active,
            "reloading" => Self::Reloading,
            "inactive" => Self::Inactive,
            "failed" => Self::Failed,
            "activating" => Self::Activating,
            "deactivating" => Self::Deactivating,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceInfo {
    /// Full unit name, e.g. `nginx.service`.
    pub id: String,
    pub active: ActiveState,
    /// `running`, `exited`, `waiting`, `dead`, `failed` …
    pub sub: String,
    pub main_pid: u32,
    pub memory: Option<u64>,
    pub cpu_ns: Option<u64>,
    pub tasks: Option<u32>,
    pub nrestarts: u32,
    /// `success`, `exit-code`, `signal`, `timeout` …
    pub result: String,
    /// Seconds since the unit entered its current active state, when known.
    pub state_age_s: Option<u64>,
}

impl ServiceInfo {
    /// Unit name without the `.service` suffix (timers etc. keep theirs).
    pub fn short_name(&self) -> &str {
        self.id.strip_suffix(".service").unwrap_or(&self.id)
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Process {
    pub pid: u32,
    pub user: String,
    pub cpu: f32,
    pub rss: u64,
    pub elapsed_s: u64,
    pub command: String,
}

/// Link-level numbers for the status bar.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LinkStats {
    pub rtt_ms: Option<u32>,
    /// Monitoring bytes per second (excludes terminal traffic).
    pub overhead_bps: f64,
    pub channels: u32,
}

pub(crate) fn ratio(a: u64, b: u64) -> f32 {
    if b == 0 {
        0.0
    } else {
        (a as f64 / b as f64) as f32
    }
}

// ───────────────────────── M3: watch sections ─────────────────────────

/// A listening socket (`ss -Htlnu`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listener {
    pub proto: String,
    pub addr: String,
    pub port: u16,
    /// Only known when the collector can see other users' processes (root).
    pub process: String,
}

impl Listener {
    /// Bound to a non-loopback address.
    pub fn is_public(&self) -> bool {
        let a = self.addr.trim_matches(['[', ']']);
        !(a.starts_with("127.") || a == "::1" || a.starts_with("::ffff:127.") || a == "localhost")
    }
}

/// An established TCP connection (`ss -Htn state established`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conn {
    pub local: String,
    pub peer: String,
    pub process: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FwRule {
    pub to: String,
    pub action: String,
    pub from: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Firewall {
    /// `ufw`, `nftables` or `iptables`.
    pub backend: String,
    pub active: bool,
    pub incoming: String,
    pub outgoing: String,
    pub routed: String,
    pub rules: Vec<FwRule>,
}

impl Firewall {
    /// Whether an ALLOW rule mentions this port (best effort; used for alerts only).
    pub fn allows_port(&self, port: u16) -> bool {
        let p = port.to_string();
        self.rules
            .iter()
            .filter(|r| r.action.to_ascii_uppercase().starts_with("ALLOW") || r.action == "ACCEPT")
            .any(|r| {
                r.to.split(['/', ' ', ',', ':']).any(|t| t == p)
                    || r.to.split(['/', ' ']).any(|t| {
                        t.split_once(':').is_some_and(|(a, b)| {
                            a.parse::<u16>().is_ok_and(|a| {
                                b.parse::<u16>().is_ok_and(|b| (a..=b).contains(&port))
                            })
                        })
                    })
            })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Jail {
    pub name: String,
    pub currently_failed: u32,
    pub total_failed: u32,
    pub currently_banned: u32,
    pub total_banned: u32,
    pub banned_ips: Vec<String>,
}

/// Failed SSH logins over the last 24 h.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthStats {
    /// 48 half-hour buckets, oldest first.
    pub buckets: Vec<u32>,
    /// Top offending addresses, most attempts first.
    pub top: Vec<(String, u32)>,
}

impl AuthStats {
    pub fn total(&self) -> u32 {
        self.buckets.iter().sum()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Timer {
    pub unit: String,
    pub activates: String,
    /// Seconds until the next run (None = not scheduled).
    pub next_in_s: Option<u64>,
    /// Seconds since the last run (None = never).
    pub last_ago_s: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scheduled {
    pub timers: Vec<Timer>,
    /// Non-comment lines in the user's crontab.
    pub cron_jobs: Vec<String>,
}

/// A unit offered in the "Watched services" picker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitInfo {
    pub name: String,
    pub active: String,
    pub sub: String,
    pub description: String,
}
