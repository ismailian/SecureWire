//! `/proc` based sections: cpu (stat + loadavg + uptime), mem, net, dio.

use super::num;
use crate::model::MemSample;

/// Jiffies from one `cpu` line of `/proc/stat`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTimes {
    /// Sum of all states (guest time is already included in user/nice).
    pub fn total(&self) -> u64 {
        self.user + self.nice + self.system + self.idle + self.iowait + self.irq + self.softirq + self.steal
    }

    fn parse(fields: &[&str]) -> Option<Self> {
        let f = |i: usize| fields.get(i).and_then(|s| num::<u64>(s)).unwrap_or(0);
        if fields.len() < 4 {
            return None;
        }
        Some(Self {
            user: f(0),
            nice: f(1),
            system: f(2),
            idle: f(3),
            iowait: f(4),
            irq: f(5),
            softirq: f(6),
            steal: f(7),
        })
    }
}

/// Payload of the `cpu` section.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CpuFrame {
    /// Remote `/proc/uptime` first field — the clock used for all rate math.
    pub uptime_s: f64,
    pub total: CpuTimes,
    pub cores: Vec<CpuTimes>,
    pub load: [f32; 3],
    pub procs_running: u32,
}

pub fn parse_cpu_frame(payload: &str) -> Option<CpuFrame> {
    let mut f = CpuFrame::default();
    let mut have_total = false;
    for line in payload.lines() {
        let mut it = line.split_ascii_whitespace();
        let Some(key) = it.next() else { continue };
        let rest: Vec<&str> = it.collect();
        match key {
            "uptime" => f.uptime_s = rest.first().and_then(|s| num(s)).unwrap_or(0.0),
            "cpu" => {
                if let Some(t) = CpuTimes::parse(&rest) {
                    f.total = t;
                    have_total = true;
                }
            }
            "loadavg" => {
                for (i, v) in rest.iter().take(3).enumerate() {
                    f.load[i] = num(v).unwrap_or(0.0);
                }
            }
            "procs_running" => f.procs_running = rest.first().and_then(|s| num(s)).unwrap_or(0),
            k if k.starts_with("cpu") && k[3..].bytes().all(|b| b.is_ascii_digit()) => {
                if let Some(t) = CpuTimes::parse(&rest) {
                    f.cores.push(t);
                }
            }
            _ => {}
        }
    }
    have_total.then_some(f)
}

/// `/proc/meminfo` → bytes. Missing keys count as 0.
pub fn parse_meminfo(payload: &str) -> MemSample {
    let (mut total, mut avail, mut free, mut buffers, mut cached, mut srecl, mut shmem, mut st, mut sf) =
        (0u64, None, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for line in payload.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let kib: u64 = v.split_ascii_whitespace().next().and_then(num).unwrap_or(0);
        let b = kib * 1024;
        match k {
            "MemTotal" => total = b,
            "MemAvailable" => avail = Some(b),
            "MemFree" => free = b,
            "Buffers" => buffers = b,
            "Cached" => cached = b,
            "SReclaimable" => srecl = b,
            "Shmem" => shmem = b,
            "SwapTotal" => st = b,
            "SwapFree" => sf = b,
            _ => {}
        }
    }
    let cache = (buffers + cached + srecl).saturating_sub(shmem);
    // Kernels < 3.14 lack MemAvailable: approximate like `free` does.
    let available = avail.unwrap_or(free + cache).min(total);
    MemSample {
        total,
        used: total - available,
        cache: cache.min(available),
        swap_total: st,
        swap_used: st.saturating_sub(sf),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetDev {
    pub name: String,
    pub rx: u64,
    pub tx: u64,
}

impl NetDev {
    /// Interfaces that never represent "the server's traffic".
    pub fn is_virtual(&self) -> bool {
        self.name == "lo" || ["docker", "veth", "br-", "virbr", "cni", "flannel", "tun", "wg"]
            .iter()
            .any(|p| self.name.starts_with(p))
    }
}

/// `/proc/net/dev`: two header lines, then `iface: rx_bytes … (8 fields) tx_bytes …`.
pub fn parse_net_dev(payload: &str) -> Vec<NetDev> {
    payload
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let fields: Vec<&str> = rest.split_ascii_whitespace().collect();
            if fields.len() < 9 {
                return None;
            }
            Some(NetDev { name: name.trim().to_owned(), rx: num(fields[0])?, tx: num(fields[8])? })
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskStat {
    pub name: String,
    pub sectors_read: u64,
    pub sectors_written: u64,
}

/// `/proc/diskstats`, whole disks only (partitions, loop and ram devices skipped).
pub fn parse_diskstats(payload: &str) -> Vec<DiskStat> {
    payload
        .lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_ascii_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            let name = f[2];
            if !is_whole_disk(name) {
                return None;
            }
            Some(DiskStat { name: name.to_owned(), sectors_read: num(f[5])?, sectors_written: num(f[9])? })
        })
        .collect()
}

fn is_whole_disk(name: &str) -> bool {
    if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram") || name.starts_with("dm-") {
        return false;
    }
    if name.starts_with("nvme") || name.starts_with("mmcblk") {
        return !name.contains('p') || !name.rsplit('p').next().is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit()));
    }
    // sda, vda, xvda: whole disk has no trailing digit.
    !name.ends_with(|c: char| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CPU: &str = "uptime 3562110.25 13800000.10
cpu  4705 150 1120 1600000 2000 0 300 50 0 0
cpu0 1200 40 300 400000 500 0 80 10 0 0
cpu1 1100 30 280 400000 500 0 70 15 0 0
ctxt 123456
procs_running 2
loadavg 0.42 0.51 0.48 2/345 6789";

    #[test]
    fn cpu_frame() {
        let f = parse_cpu_frame(CPU).unwrap();
        assert_eq!(f.cores.len(), 2);
        assert_eq!(f.total.user, 4705);
        assert_eq!(f.total.steal, 50);
        assert_eq!(f.load, [0.42, 0.51, 0.48]);
        assert_eq!(f.procs_running, 2);
        assert!((f.uptime_s - 3562110.25).abs() < 1e-6);
    }

    #[test]
    fn cpu_frame_without_total_is_none() {
        assert!(parse_cpu_frame("uptime 1 1\nloadavg 0 0 0").is_none());
    }

    #[test]
    fn meminfo() {
        let m = parse_meminfo(
            "MemTotal:        8000000 kB
MemFree:          500000 kB
MemAvailable:    3000000 kB
Buffers:          100000 kB
Cached:          1200000 kB
SwapCached:            0 kB
Shmem:            100000 kB
SReclaimable:     200000 kB
SwapTotal:       2000000 kB
SwapFree:        1500000 kB",
        );
        assert_eq!(m.total, 8_000_000 * 1024);
        assert_eq!(m.used, 5_000_000 * 1024);
        assert_eq!(m.cache, 1_400_000 * 1024);
        assert_eq!(m.swap_used, 500_000 * 1024);
    }

    #[test]
    fn meminfo_without_available() {
        let m = parse_meminfo("MemTotal: 1000 kB\nMemFree: 200 kB\nCached: 300 kB");
        assert_eq!(m.available(), 500 * 1024);
    }

    #[test]
    fn net_dev() {
        let v = parse_net_dev(
            "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 98765 500 0 0 0 0 0 0 43210 400 0 0 0 0 0 0
docker0: 5 1 0 0 0 0 0 0 6 1 0 0 0 0 0 0",
        );
        assert_eq!(v.len(), 3);
        assert_eq!(v[1], NetDev { name: "eth0".into(), rx: 98765, tx: 43210 });
        assert!(v[0].is_virtual() && v[2].is_virtual() && !v[1].is_virtual());
    }

    #[test]
    fn diskstats_whole_disks_only() {
        let v = parse_diskstats(
            "   8       0 sda 100 0 2000 0 50 0 4000 0 0 0 0
   8       1 sda1 90 0 1800 0 40 0 3000 0 0 0 0
 259       0 nvme0n1 10 0 300 0 5 0 700 0 0 0 0
 259       1 nvme0n1p1 9 0 200 0 4 0 600 0 0 0 0
   7       0 loop0 1 0 2 0 0 0 0 0 0 0 0",
        );
        let names: Vec<_> = v.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["sda", "nvme0n1"]);
        assert_eq!(v[0].sectors_read, 2000);
        assert_eq!(v[0].sectors_written, 4000);
    }
}
