//! Turning consecutive raw snapshots into rates and percentages.
//!
//! All rate math uses the *remote* uptime delta carried in the cpu frame, so
//! network jitter between the server and the client never distorts numbers.

use crate::model::{CpuSample, DiskIo, NetSample};
use crate::parse::{CpuFrame, CpuTimes, DiskStat, NetDev};

/// Fixed-capacity ring of `f32` samples for sparklines. Oldest values drop off.
#[derive(Debug, Clone)]
pub struct RingBuffer {
    buf: Vec<f32>,
    head: usize,
    len: usize,
}

impl RingBuffer {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            buf: vec![0.0; capacity],
            head: 0,
            len: 0,
        }
    }

    pub fn push(&mut self, v: f32) {
        self.buf[self.head] = v;
        self.head = (self.head + 1) % self.buf.len();
        self.len = (self.len + 1).min(self.buf.len());
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    pub fn last(&self) -> Option<f32> {
        (self.len > 0).then(|| self.buf[(self.head + self.buf.len() - 1) % self.buf.len()])
    }

    /// Oldest → newest.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = f32> + '_ {
        let cap = self.buf.len();
        let start = (self.head + cap - self.len) % cap;
        (0..self.len).map(move |i| self.buf[(start + i) % cap])
    }

    /// Iterate only the newest `n` values (oldest → newest).
    pub fn tail(&self, n: usize) -> impl Iterator<Item = f32> + '_ {
        self.iter().skip(self.len.saturating_sub(n))
    }

    pub fn max(&self) -> f32 {
        self.iter().fold(0.0, f32::max)
    }
}

fn pct(part: u64, whole: u64) -> f32 {
    if whole == 0 {
        0.0
    } else {
        (part as f64 * 100.0 / whole as f64) as f32
    }
}

fn delta(a: &CpuTimes, b: &CpuTimes) -> CpuTimes {
    CpuTimes {
        user: b.user.saturating_sub(a.user) + b.nice.saturating_sub(a.nice),
        nice: 0,
        system: (b.system + b.irq + b.softirq).saturating_sub(a.system + a.irq + a.softirq),
        idle: b.idle.saturating_sub(a.idle),
        iowait: b.iowait.saturating_sub(a.iowait),
        irq: 0,
        softirq: 0,
        steal: b.steal.saturating_sub(a.steal),
    }
}

fn busy_pct(d: &CpuTimes) -> f32 {
    let total = d.total();
    pct(total - d.idle - d.iowait, total)
}

/// Keeps the previous cpu frame; yields a sample from the second frame on.
#[derive(Debug, Default)]
pub struct CpuTracker {
    prev: Option<CpuFrame>,
}

impl CpuTracker {
    pub fn update(&mut self, f: CpuFrame) -> Option<CpuSample> {
        let out = self.prev.as_ref().and_then(|p| {
            // Counter reset (reboot) or duplicate frame → skip one sample.
            if f.uptime_s <= p.uptime_s {
                return None;
            }
            let d = delta(&p.total, &f.total);
            let total = d.total();
            let cores = p
                .cores
                .iter()
                .zip(&f.cores)
                .map(|(a, b)| busy_pct(&delta(a, b)))
                .collect();
            Some(CpuSample {
                total: busy_pct(&d),
                user: pct(d.user, total),
                system: pct(d.system, total),
                iowait: pct(d.iowait, total),
                steal: pct(d.steal, total),
                cores,
                load: f.load,
                uptime_s: f.uptime_s,
            })
        });
        self.prev = Some(f);
        out
    }

    pub fn uptime_s(&self) -> f64 {
        self.prev.as_ref().map_or(0.0, |p| p.uptime_s)
    }
}

/// Picks the busiest non-virtual interface and reports its rx/tx rate.
#[derive(Debug, Default)]
pub struct NetTracker {
    prev: Option<(f64, Vec<NetDev>)>,
}

impl NetTracker {
    pub fn update(&mut self, uptime_s: f64, devs: Vec<NetDev>) -> Option<NetSample> {
        let out = self.prev.as_ref().and_then(|(t0, prev)| {
            let dt = uptime_s - t0;
            if dt <= 0.0 {
                return None;
            }
            devs.iter()
                .filter(|d| !d.is_virtual())
                .filter_map(|d| {
                    let p = prev.iter().find(|p| p.name == d.name)?;
                    let rx = d.rx.saturating_sub(p.rx) as f64 / dt;
                    let tx = d.tx.saturating_sub(p.tx) as f64 / dt;
                    Some(NetSample {
                        iface: d.name.clone(),
                        rx_bps: rx,
                        tx_bps: tx,
                    })
                })
                .max_by(|a, b| (a.rx_bps + a.tx_bps).total_cmp(&(b.rx_bps + b.tx_bps)))
        });
        self.prev = Some((uptime_s, devs));
        out
    }
}

/// Sums whole-disk read/write throughput.
#[derive(Debug, Default)]
pub struct DiskIoTracker {
    prev: Option<(f64, u64, u64)>,
}

impl DiskIoTracker {
    pub fn update(&mut self, uptime_s: f64, disks: &[DiskStat]) -> Option<DiskIo> {
        // /proc/diskstats always counts 512-byte sectors, regardless of device sector size.
        let r: u64 = disks.iter().map(|d| d.sectors_read * 512).sum();
        let w: u64 = disks.iter().map(|d| d.sectors_written * 512).sum();
        let out = self.prev.and_then(|(t0, r0, w0)| {
            let dt = uptime_s - t0;
            (dt > 0.0).then(|| DiskIo {
                read_bps: r.saturating_sub(r0) as f64 / dt,
                write_bps: w.saturating_sub(w0) as f64 / dt,
            })
        });
        self.prev = Some((uptime_s, r, w));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_cpu_frame;

    #[test]
    fn ring_buffer_wraps() {
        let mut r = RingBuffer::new(3);
        assert_eq!(r.last(), None);
        for v in 1..=5 {
            r.push(v as f32);
        }
        assert_eq!(r.iter().collect::<Vec<_>>(), [3.0, 4.0, 5.0]);
        assert_eq!(r.tail(2).collect::<Vec<_>>(), [4.0, 5.0]);
        assert_eq!(r.last(), Some(5.0));
        assert_eq!(r.max(), 5.0);
    }

    #[test]
    fn cpu_percentages() {
        let a =
            parse_cpu_frame("uptime 100 0\ncpu 100 0 100 800 0 0 0 0\ncpu0 100 0 100 800 0 0 0 0")
                .unwrap();
        let b = parse_cpu_frame(
            "uptime 102 0\ncpu 150 0 130 900 20 0 0 0\ncpu0 150 0 130 900 20 0 0 0",
        )
        .unwrap();
        let mut t = CpuTracker::default();
        assert!(t.update(a).is_none());
        let s = t.update(b).unwrap();
        // delta: user 50, sys 30, idle 100, iowait 20 → total 200, busy 80
        assert_eq!(s.total, 40.0);
        assert_eq!(s.user, 25.0);
        assert_eq!(s.iowait, 10.0);
        assert_eq!(s.cores, vec![40.0]);
    }

    #[test]
    fn cpu_reset_skips_sample() {
        let a = parse_cpu_frame("uptime 100 0\ncpu 100 0 100 800").unwrap();
        let b = parse_cpu_frame("uptime 5 0\ncpu 1 0 1 8").unwrap();
        let mut t = CpuTracker::default();
        t.update(a);
        assert!(t.update(b).is_none());
    }

    #[test]
    fn net_rates_pick_busiest_physical() {
        let mut t = NetTracker::default();
        let d = |n: &str, rx, tx| NetDev {
            name: n.into(),
            rx,
            tx,
        };
        t.update(10.0, vec![d("lo", 0, 0), d("eth0", 0, 0), d("eth1", 0, 0)]);
        let s = t
            .update(
                12.0,
                vec![
                    d("lo", 1_000_000, 1_000_000),
                    d("eth0", 4000, 2000),
                    d("eth1", 10, 10),
                ],
            )
            .unwrap();
        assert_eq!(s.iface, "eth0");
        assert_eq!(s.rx_bps, 2000.0);
        assert_eq!(s.tx_bps, 1000.0);
    }
}
