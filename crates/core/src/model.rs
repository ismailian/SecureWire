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
    if b == 0 { 0.0 } else { (a as f64 / b as f64) as f32 }
}
