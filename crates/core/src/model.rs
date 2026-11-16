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
    /// Owning processes (`ss -p`), to match a service's MainPID.
    pub pids: Vec<u32>,
}

impl Listener {
    /// Bound to a non-loopback address.
    pub fn is_public(&self) -> bool {
        let a = self.addr.trim_matches(['[', ']']);
        !(a.starts_with("127.") || a == "::1" || a.starts_with("::ffff:127.") || a == "localhost")
    }

    /// Address to reach this socket from the server itself (tunnel target):
    /// wildcards become loopback, a specific address stays as it is.
    pub fn reach_addr(&self) -> String {
        match self.addr.trim_matches(['[', ']']) {
            "0.0.0.0" | "*" | "" => "127.0.0.1".into(),
            "::" => "::1".into(),
            a => a.split('%').next().unwrap_or(a).to_owned(),
        }
    }
}

/// Listening sockets grouped by port, for chips (one per port, not per address).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortGroup {
    pub port: u16,
    /// Any of its sockets is bound to a non-loopback address.
    pub public: bool,
    /// e.g. "tcp", "tcp+udp".
    pub protos: String,
    /// Distinct process names, comma-separated.
    pub processes: String,
}

/// Public ports first, then local-only, each by port number.
pub fn group_ports(ls: &[Listener]) -> Vec<PortGroup> {
    let mut out: Vec<PortGroup> = Vec::new();
    for l in ls {
        let g = match out.iter_mut().position(|g| g.port == l.port) {
            Some(i) => &mut out[i],
            None => {
                out.push(PortGroup {
                    port: l.port,
                    ..Default::default()
                });
                out.last_mut().expect("just pushed")
            }
        };
        g.public |= l.is_public();
        if !g.protos.split('+').any(|p| p == l.proto) {
            if !g.protos.is_empty() {
                g.protos.push('+');
            }
            g.protos.push_str(&l.proto);
        }
        if !l.process.is_empty() && !g.processes.split(", ").any(|p| p == l.process) {
            if !g.processes.is_empty() {
                g.processes.push_str(", ");
            }
            g.processes.push_str(&l.process);
        }
    }
    out.sort_by_key(|g| (!g.public, g.port));
    out
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

/// What the firewall does to new connections on a port (best effort: rules we can read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortFirewall {
    /// Inactive, or the default incoming policy accepts everything.
    Open,
    /// An allow rule mentions the port.
    Allowed,
    /// Default deny and no allow rule for it.
    Blocked,
}

impl Firewall {
    /// Active, but the default incoming policy accepts: rules aren't what protects ports.
    pub fn accepts_all(&self) -> bool {
        matches!(
            self.incoming.to_ascii_lowercase().as_str(),
            "accept" | "allow"
        )
    }

    pub fn port_status(&self, port: u16) -> PortFirewall {
        if !self.active || self.accepts_all() {
            PortFirewall::Open
        } else if self.allows_port(port) {
            PortFirewall::Allowed
        } else {
            PortFirewall::Blocked
        }
    }

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
