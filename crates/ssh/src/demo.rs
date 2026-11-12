//! Demo host: a fake server that produces byte-exact collector output and log
//! lines, pushed through the real [`FrameDecoder`] and [`Pipeline`]. Used by
//! `securewire --demo` for UI work without a VPS.
//!
//! The loop mirrors the collector's main loop (protocol §2.3): tiers, ON/OFF,
//! NOW, and a timed wait on the command channel instead of `read -t`.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sw_core::frame::encode;
use sw_core::logs::{Level, LogLine, Preset, detect_level};
use sw_core::model::LinkStats;
use sw_core::{FrameDecoder, Section};

use crate::Waker;
use crate::api::{
    Command, ConnInfo, ConnState, Event, EventKind, HostId, LogKind, LogSourceInfo, SudoMode,
};
use crate::handle::{CmdTx, HostHandle};
use crate::pipeline::Pipeline;

const CORES: usize = 4;

pub fn spawn_demo_host(id: HostId, events: Sender<Event>, wake: Waker) -> HostHandle {
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name(format!("demo-host-{id}"))
        .spawn(move || DemoHost::new(id, events, wake).run(rx))
        .expect("spawn demo thread");
    HostHandle::new(id, CmdTx::Std(tx))
}

/// xorshift64* — deterministic, dependency-free noise.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    /// Uniform in [0, 1).
    fn f(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.f()
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[(self.next() % v.len() as u64) as usize]
    }
}

/// Fake kernel counters that evolve plausibly.
struct FakeServer {
    rng: Rng,
    uptime: f64,
    util: [f64; CORES],
    cores: [[u64; 8]; CORES],
    mem_used_kib: f64,
    rx: u64,
    tx: u64,
    rx_rate: f64,
    tx_rate: f64,
    sect_r: u64,
    sect_w: u64,
    mysql_used: u64,
    redis_failed_at: f64,
}

impl FakeServer {
    fn new() -> Self {
        let uptime = 41.0 * 86_400.0 + 6.0 * 3600.0;
        Self {
            rng: Rng(0x9e37_79b9_7f4a_7c15),
            uptime,
            util: [0.2; CORES],
            cores: [[
                1_000_000, 5_000, 300_000, 20_000_000, 40_000, 0, 9_000, 1_000,
            ]; CORES],
            mem_used_kib: 4_200_000.0,
            rx: 9_876_543_210,
            tx: 1_234_567_890,
            rx_rate: 1_500_000.0,
            tx_rate: 400_000.0,
            sect_r: 50_000_000,
            sect_w: 80_000_000,
            mysql_used: 86_973_087_744,
            redis_failed_at: uptime - 180.0,
        }
    }

    fn tick(&mut self, dt: f64) {
        self.uptime += dt;
        let hz = 100.0 * dt;
        for c in 0..CORES {
            let u = (self.util[c] + self.rng.range(-0.12, 0.12)).clamp(0.03, 0.97);
            self.util[c] = u;
            let busy = u * hz;
            let io = self.rng.range(0.0, 0.03) * hz;
            let t = &mut self.cores[c];
            t[0] += (busy * 0.72) as u64; // user
            t[1] += (busy * 0.03) as u64; // nice
            t[2] += (busy * 0.20) as u64; // system
            t[3] += (hz - busy - io).max(0.0) as u64; // idle
            t[4] += io as u64; // iowait
            t[6] += (busy * 0.05) as u64; // softirq
            t[7] += self.rng.range(0.0, 0.3) as u64; // steal
        }
        self.mem_used_kib = (self.mem_used_kib + self.rng.range(-60_000.0, 60_000.0))
            .clamp(3_600_000.0, 5_600_000.0);
        self.rx_rate = (self.rx_rate * self.rng.range(0.75, 1.3)).clamp(80_000.0, 6_000_000.0);
        self.tx_rate = (self.tx_rate * self.rng.range(0.75, 1.3)).clamp(20_000.0, 1_500_000.0);
        self.rx += (self.rx_rate * dt) as u64;
        self.tx += (self.tx_rate * dt) as u64;
        self.sect_r += (self.rng.range(500.0, 4000.0) * dt) as u64;
        self.sect_w += (self.rng.range(200.0, 1500.0) * dt) as u64;
        self.mysql_used += (self.rng.range(0.0, 40_000.0) * dt) as u64;
    }

    fn payload(&mut self, s: Section, units: &[String]) -> String {
        let mut o = String::new();
        match s {
            Section::Static => {
                o.push_str("hostname=prod-web-01\nos=Ubuntu 24.04.1 LTS\nkernel=6.8.0-49-generic\narch=x86_64\n");
                let _ = write!(o, "cpus={CORES}\nvirt=kvm\nmem_total_kib=8130000");
            }
            Section::Cpu => {
                let _ = writeln!(o, "uptime {:.2} {:.2}", self.uptime, self.uptime * 3.5);
                let mut total = [0u64; 8];
                for c in &self.cores {
                    for (t, v) in total.iter_mut().zip(c) {
                        *t += v;
                    }
                }
                let line = |o: &mut String, name: &str, t: &[u64; 8]| {
                    let _ = writeln!(
                        o,
                        "{name} {} {} {} {} {} {} {} {} 0 0",
                        t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]
                    );
                };
                line(&mut o, "cpu ", &total);
                for (i, c) in self.cores.iter().enumerate() {
                    line(&mut o, &format!("cpu{i}"), c);
                }
                let avg = self.util.iter().sum::<f64>();
                let _ = write!(
                    o,
                    "ctxt 99887766\nprocs_running 2\nloadavg {:.2} {:.2} {:.2} 2/345 6789",
                    avg,
                    avg * 0.9 + 0.1,
                    0.48
                );
            }
            Section::Mem => {
                let total = 8_130_000.0;
                let avail = total - self.mem_used_kib;
                let _ = write!(
                    o,
                    "MemTotal: {total:.0} kB\nMemFree: {:.0} kB\nMemAvailable: {avail:.0} kB\nBuffers: 120000 kB\nCached: 1050000 kB\nShmem: 41000 kB\nSReclaimable: 90000 kB\nSwapTotal: 2097148 kB\nSwapFree: 1908000 kB",
                    avail - 1_100_000.0
                );
            }
            Section::Net => {
                let _ = write!(
                    o,
                    "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets\n    lo: 1234567 9000 0 0 0 0 0 0 1234567 9000 0 0 0 0 0 0\n  eth0: {} 8000000 0 0 0 0 0 0 {} 6000000 0 0 0 0 0 0\ndocker0: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
                    self.rx, self.tx
                );
            }
            Section::Dio => {
                let _ = write!(
                    o,
                    " 252 0 vda 900000 0 {} 0 400000 0 {} 0 0 0 0\n 252 1 vda1 1 0 2 0 3 0 4 0 0 0 0",
                    self.sect_r, self.sect_w
                );
            }
            Section::Df => {
                let _ = write!(
                    o,
                    "Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/vda1 66437775360 41231917056 25205858304 62% /\n/dev/vdb1 107374182400 {} {} 81% /var/lib/mysql\n/dev/vda16 958435328 297795584 593727488 34% /boot",
                    self.mysql_used,
                    107_374_182_400u64.saturating_sub(self.mysql_used)
                );
            }
            Section::Who => {
                o.push_str(
                    "root     pts/0        2026-11-12 09:12   .          88123 (198.51.100.24)\n",
                );
                o.push_str(
                    "deploy   pts/1        2026-11-12 11:02 02:01        88200 (203.0.113.50)",
                );
            }
            Section::Ps => {
                let j = |r: &mut Rng, b: f64| (b * r.range(0.6, 1.4) * 10.0).round() / 10.0;
                let rows = [
                    (1342, "mysql", 12.4, 1_268_000, "/usr/sbin/mysqld"),
                    (2211, "www-data", 6.1, 90_112, "php-fpm: pool www"),
                    (2212, "www-data", 5.8, 88_000, "php-fpm: pool www"),
                    (1123, "www-data", 1.2, 38_900, "nginx: worker process"),
                    (
                        988,
                        "root",
                        0.6,
                        72_000,
                        "/usr/bin/python3 /usr/bin/fail2ban-server -xf start",
                    ),
                    (
                        612,
                        "root",
                        0.2,
                        22_000,
                        "/usr/lib/systemd/systemd-journald",
                    ),
                    (1, "root", 0.0, 12_800, "/sbin/init"),
                ];
                for (pid, user, cpu, rss, cmd) in rows {
                    let _ = writeln!(
                        o,
                        "{pid:>7} {user:<8} {:>4} {rss:>8} 3562000 {cmd}",
                        j(&mut self.rng, cpu)
                    );
                }
            }
            Section::Svc => {
                let mono = |age: f64, up: f64| ((up - age).max(0.0) * 1e6) as u64;
                for (i, u) in units.iter().enumerate() {
                    if i > 0 {
                        o.push('\n');
                    }
                    let (state, sub, pid, mem, result, age, restarts) = match u.as_str() {
                        "nginx.service" => (
                            "active",
                            "running",
                            1123,
                            Some(39_845_888u64),
                            "success",
                            41.0 * 86_400.0,
                            0,
                        ),
                        "mysql.service" => (
                            "active",
                            "running",
                            1342,
                            Some(1_288_490_189),
                            "success",
                            41.0 * 86_400.0,
                            0,
                        ),
                        "php8.3-fpm.service" => (
                            "active",
                            "running",
                            2201,
                            Some(432_013_312),
                            "success",
                            2.0 * 86_400.0 + 4.0 * 3600.0,
                            1,
                        ),
                        "fail2ban.service" => (
                            "active",
                            "running",
                            988,
                            Some(73_728_000),
                            "success",
                            41.0 * 86_400.0,
                            0,
                        ),
                        "redis-server.service" if self.redis_failed_at > 0.0 => (
                            "failed",
                            "failed",
                            0,
                            None,
                            "exit-code",
                            self.uptime - self.redis_failed_at,
                            3,
                        ),
                        "redis-server.service" => (
                            "active",
                            "running",
                            99001,
                            Some(8_388_608),
                            "success",
                            2.0,
                            3,
                        ),
                        "certbot.timer" => {
                            ("active", "waiting", 0, None, "success", 6.0 * 3600.0, 0)
                        }
                        _ => ("inactive", "dead", 0, None, "success", 0.0, 0),
                    };
                    let _ = writeln!(
                        o,
                        "Id={u}\nActiveState={state}\nSubState={sub}\nMainPID={pid}"
                    );
                    let _ = writeln!(
                        o,
                        "MemoryCurrent={}",
                        mem.map_or("[not set]".into(), |m| m.to_string())
                    );
                    let _ = writeln!(
                        o,
                        "TasksCurrent={}\nNRestarts={restarts}\nResult={result}",
                        if pid > 0 { 5 } else { 0 }
                    );
                    let _ = writeln!(
                        o,
                        "ActiveEnterTimestampMonotonic={}",
                        mono(age, self.uptime)
                    );
                    let _ = writeln!(
                        o,
                        "InactiveEnterTimestampMonotonic={}",
                        mono(age, self.uptime)
                    );
                }
            }
            Section::Ports => {
                o.push_str(
                    "tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=812,fd=3))
",
                );
                o.push_str(
                    "tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1123,fd=6))
",
                );
                o.push_str(
                    "tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=1123,fd=7))
",
                );
                o.push_str(
                    "tcp LISTEN 0 80 127.0.0.1:3306 0.0.0.0:* users:((\"mysqld\",pid=1342,fd=21))
",
                );
                o.push_str("tcp LISTEN 0 511 127.0.0.1:9000 0.0.0.0:* users:((\"php-fpm8.3\",pid=2201,fd=8))
");
                o.push_str("tcp LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:((\"redis-server\",pid=99001,fd=6))");
            }
            Section::Conns => {
                o.push_str(
                    "0 0 203.0.113.10:22 198.51.100.24:50412 users:((\"sshd\",pid=88123,fd=4))
",
                );
                o.push_str(
                    "0 0 203.0.113.10:443 192.0.2.77:61022 users:((\"nginx\",pid=1123,fd=12))
",
                );
                o.push_str(
                    "0 0 127.0.0.1:3306 127.0.0.1:44120 users:((\"mysqld\",pid=1342,fd=40))",
                );
            }
            Section::Fw => {
                o.push_str(
                    "backend ufw
Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)

To                         Action      From
--                         ------      ----
",
                );
                o.push_str(
                    "22/tcp                     ALLOW IN    Anywhere
80,443/tcp                 ALLOW IN    Anywhere
3306                       ALLOW IN    10.0.0.0/24
22/tcp (v6)                ALLOW IN    Anywhere (v6)",
                );
            }
            Section::F2b => {
                o.push_str(
                    "Status
`- Jail list:	nginx-http-auth, sshd
@@jail sshd
|  |- Currently failed:	3
|  |- Total failed:	1284
   |- Currently banned:	14
   |- Total banned:	102
   `- Banned IP list:	198.51.100.203 192.0.2.155
",
                );
                o.push_str(
                    "@@jail nginx-http-auth
   |- Currently banned:	3
   `- Banned IP list:	203.0.113.199",
                );
            }
            Section::Auth => {
                let b: Vec<String> = (0..48)
                    .map(|i| {
                        (20.0
                            + 30.0 * ((i as f64) / 4.0).sin().max(0.0)
                            + self.rng.range(0.0, 25.0))
                        .round()
                        .to_string()
                    })
                    .collect();
                o.push_str(&b.join(" "));
                o.push_str(
                    "
412 198.51.100.203
288 192.0.2.155
97 203.0.113.199
41 198.51.100.88",
                );
            }
            Section::Timers => {
                o.push_str("now 1000000
[{\"next\":1021600000000,\"last\":979400000000,\"unit\":\"certbot.timer\",\"activates\":\"certbot.service\"},{\"next\":1003000000000,\"last\":999000000000,\"unit\":\"logrotate.timer\",\"activates\":\"logrotate.service\"},{\"next\":1086400000000,\"last\":0,\"unit\":\"apt-daily.timer\",\"activates\":\"apt-daily.service\"}]
@@cron
*/5 * * * * /usr/local/bin/backup.sh
0 3 * * 0 /usr/bin/certbot renew --quiet");
            }
        }
        o
    }
}

struct Tier {
    sections: &'static [Section],
    every: u64,
    next: Instant,
}

const LOG_SOURCES: [(&str, LogKind, &str, Preset); 6] = [
    (
        "nginx",
        LogKind::File,
        "/var/log/nginx/error.log",
        Preset::Nginx,
    ),
    (
        "mysql",
        LogKind::SudoFile,
        "/var/log/mysql/error.log",
        Preset::Mysql,
    ),
    (
        "fail2ban",
        LogKind::SudoFile,
        "/var/log/fail2ban.log",
        Preset::Fail2ban,
    ),
    ("sshd", LogKind::Journal, "ssh.service", Preset::Generic),
    (
        "redis",
        LogKind::Journal,
        "redis-server.service",
        Preset::Generic,
    ),
    (
        "php-fpm",
        LogKind::Journal,
        "php8.3-fpm.service",
        Preset::Generic,
    ),
];

const LOG_LINES: [&[&str]; 6] = [
    &[
        "2026/11/12 13:05:01 [error] 1123#1123: *88412 connect() failed (111: Connection refused) while connecting to upstream, client: 198.51.100.77, server: api.example.com, upstream: \"http://127.0.0.1:6379\"",
        "2026/11/12 13:05:02 [warn] 1123#1123: *88413 an upstream response is buffered to a temporary file /var/cache/nginx/proxy_temp/4/02/0000000024",
        "2026/11/12 13:05:03 [notice] 1123#1123: signal process started",
    ],
    &[
        "2026-11-12T13:05:11.120Z 0 [Warning] [MY-010055] [Server] IP address '10.0.0.14' could not be resolved: Name or service not known",
        "2026-11-12T13:05:12.002Z 4412 [Note] [MY-010914] [Server] Aborted connection 4412 to db: 'app' user: 'app' host: '10.0.0.12' (Got timeout reading communication packets).",
    ],
    &[
        "2026-11-12 13:05:41,201 fail2ban.filter [988]: INFO [sshd] Found 198.51.100.203 - 2026-11-12 13:05:41",
        "2026-11-12 13:05:42,880 fail2ban.actions [988]: NOTICE [sshd] Ban 203.0.113.199",
        "2026-11-12 13:05:44,012 fail2ban.actions [988]: NOTICE [sshd] Unban 192.0.2.10",
    ],
    &[
        "Failed password for invalid user admin from 198.51.100.203 port 51122 ssh2",
        "Accepted publickey for deploy from 203.0.113.50 port 50022 ssh2: ED25519 SHA256:q3xUe0d9",
        "Connection closed by authenticating user root 192.0.2.155 port 40118 [preauth]",
        "Invalid user oracle from 198.51.100.88 port 33190",
    ],
    &[
        "Can't open the log file: Permission denied",
        "redis-server.service: Main process exited, code=exited, status=1/FAILURE",
    ],
    &[
        "WARNING: [pool www] server reached pm.max_children setting (20), consider raising it",
        "NOTICE: [pool www] child 2290 started",
    ],
];

struct DemoHost {
    id: HostId,
    events: Sender<Event>,
    wake: Waker,
    server: FakeServer,
    decoder: FrameDecoder,
    pipeline: Pipeline,
    seq: u64,
    off: HashSet<Section>,
    units: Vec<String>,
    tiers: [Tier; 2],
    next_log: Instant,
    bytes_window: (Instant, usize),
    overhead_bps: f64,
    last_tick: Instant,
    pending: Vec<EventKind>,
}

impl DemoHost {
    fn new(id: HostId, events: Sender<Event>, wake: Waker) -> Self {
        let now = Instant::now();
        Self {
            id,
            events,
            wake,
            server: FakeServer::new(),
            decoder: FrameDecoder::new(),
            pipeline: Pipeline::new(),
            seq: 0,
            off: HashSet::new(),
            units: [
                "nginx.service",
                "mysql.service",
                "php8.3-fpm.service",
                "fail2ban.service",
                "redis-server.service",
                "certbot.timer",
            ]
            .map(String::from)
            .to_vec(),
            tiers: [
                Tier {
                    sections: &[Section::Cpu, Section::Mem, Section::Net, Section::Dio],
                    every: 2,
                    next: now,
                },
                Tier {
                    sections: &[
                        Section::Df,
                        Section::Who,
                        Section::Ps,
                        Section::Svc,
                        Section::Ports,
                        Section::Conns,
                        Section::Fw,
                        Section::F2b,
                        Section::Auth,
                        Section::Timers,
                    ],
                    every: 10,
                    next: now,
                },
            ],
            next_log: now,
            bytes_window: (now, 0),
            overhead_bps: 0.0,
            last_tick: now,
            pending: Vec::new(),
        }
    }

    /// Queue events; they go out together on the next [`Self::flush`].
    fn send(&mut self, kinds: impl IntoIterator<Item = EventKind>) {
        self.pending.extend(kinds);
    }

    /// Deliver queued events with a single UI wake-up (one repaint per loop turn, not per event).
    fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        for kind in self.pending.drain(..) {
            if self
                .events
                .send(Event {
                    host: self.id,
                    kind,
                })
                .is_err()
            {
                return;
            }
        }
        (self.wake)();
    }

    /// Produce one section exactly as the collector would and run it through the real decoder.
    fn emit(&mut self, s: Section) {
        if self.off.contains(&s) {
            return;
        }
        self.seq += 1;
        let bytes = encode(s, self.seq, &self.server.payload(s, &self.units));
        self.bytes_window.1 += bytes.len();
        let mut frames = Vec::new();
        self.decoder.push(&bytes, &mut frames);
        let mut out = Vec::new();
        for f in frames {
            self.pipeline.on_frame(f, &mut out);
        }
        self.send(out);
    }

    fn run(mut self, rx: Receiver<Command>) {
        self.send([
            EventKind::State(ConnState::Connecting),
            EventKind::Connected(ConnInfo {
                user: "root".into(),
                address: "203.0.113.10".into(),
                port: 22,
                host_key: "ed25519".into(),
                key_known: true,
                fingerprint: "SHA256:demo-host-key-not-real".into(),
                sudo: SudoMode::Root,
            }),
            EventKind::State(ConnState::Connected),
            EventKind::ServiceMode { live_watching: true },
            EventKind::LogSources(
                LOG_SOURCES
                    .iter()
                    .map(|(n, k, t, _)| LogSourceInfo {
                        name: (*n).into(),
                        kind: k.clone(),
                        target: (*t).into(),
                    })
                    .collect(),
            ),
        ]);
        self.emit(Section::Static);
        self.backlog();

        loop {
            let now = Instant::now();
            // Fast-tier ticks advance the fake kernel clock.
            for t in 0..self.tiers.len() {
                if now >= self.tiers[t].next {
                    if t == 0 {
                        let dt = now.duration_since(self.last_tick).as_secs_f64().max(0.5);
                        self.last_tick = now;
                        self.server.tick(dt);
                    }
                    for &s in self.tiers[t].sections {
                        self.emit(s);
                    }
                    self.tiers[t].next = now + Duration::from_secs(self.tiers[t].every);
                }
            }
            if now >= self.next_log {
                let n = self.log_line();
                self.send([EventKind::Logs(vec![n])]);
                self.next_log =
                    now + Duration::from_millis(400 + (self.server.rng.f() * 2200.0) as u64);
            }
            if now.duration_since(self.bytes_window.0) >= Duration::from_secs(5) {
                self.overhead_bps = self.bytes_window.1 as f64
                    / now.duration_since(self.bytes_window.0).as_secs_f64();
                self.bytes_window = (now, 0);
                let rtt = 34 + (self.server.rng.f() * 9.0) as u32;
                self.send([EventKind::Link(LinkStats {
                    rtt_ms: Some(rtt),
                    overhead_bps: self.overhead_bps,
                    channels: 5,
                })]);
            }

            self.flush();
            let next = self
                .tiers
                .iter()
                .map(|t| t.next)
                .chain([self.next_log])
                .min()
                .unwrap_or(now);
            match rx.recv_timeout(next.saturating_duration_since(Instant::now())) {
                Ok(Command::Shutdown) | Err(RecvTimeoutError::Disconnected) => return,
                Ok(c) => {
                    self.handle(c);
                    self.flush();
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }

    fn handle(&mut self, c: Command) {
        match c {
            Command::SetSection { section, on } => {
                if on {
                    if self.off.remove(&section) {
                        self.emit(section);
                    }
                } else {
                    self.off.insert(section);
                }
            }
            Command::Now(s) => {
                if s == Section::Cpu {
                    self.server.tick(
                        Instant::now()
                            .duration_since(self.last_tick)
                            .as_secs_f64()
                            .max(0.5),
                    );
                    self.last_tick = Instant::now();
                }
                self.emit(s);
            }
            Command::Throttle(t) => {
                let (fast, medium, _) = t.tiers();
                let now = Instant::now();
                for (tier, every) in self.tiers.iter_mut().zip([fast, medium]) {
                    tier.every = every;
                    tier.next = tier.next.min(now + Duration::from_secs(every));
                }
            }
            Command::SetServices(u) => {
                self.units = u;
                self.emit(Section::Svc);
            }
            // Terminal, host-key and connection commands have no meaning for the demo host.
            _ => {}
        }
    }

    fn log_line(&mut self) -> LogLine {
        let rng = &mut self.server.rng;
        // redis has stopped logging (it's dead); weight the rest.
        let src = *rng.pick(&[0usize, 0, 0, 1, 2, 2, 3, 3, 3, 5]);
        let msg = *rng.pick(LOG_LINES[src]);
        let level = match LOG_SOURCES[src].1 {
            LogKind::Journal
                if msg.starts_with("WARNING")
                    || msg.starts_with("Failed")
                    || msg.starts_with("Invalid") =>
            {
                Level::Warn
            }
            LogKind::Journal => Level::Info,
            _ => detect_level(LOG_SOURCES[src].3, msg),
        };
        LogLine {
            ts_ms: now_ms(),
            source: src as u16,
            level,
            msg: msg.to_owned(),
        }
    }

    fn backlog(&mut self) {
        let base = now_ms() - 60_000;
        let order = [0, 3, 2, 1, 0, 5, 3, 0, 4, 4, 0, 2, 3, 1, 0];
        let lines = order
            .iter()
            .enumerate()
            .map(|(i, &src)| {
                let msg = LOG_LINES[src][i % LOG_LINES[src].len()];
                let level = match (LOG_SOURCES[src].1.clone(), src) {
                    (_, 4) => Level::Error,
                    (LogKind::Journal, _)
                        if msg.starts_with("Failed") || msg.starts_with("WARNING") =>
                    {
                        Level::Warn
                    }
                    (LogKind::Journal, _) => Level::Info,
                    _ => detect_level(LOG_SOURCES[src].3, msg),
                };
                LogLine {
                    ts_ms: base + i as i64 * 3900,
                    source: src as u16,
                    level,
                    msg: msg.into(),
                }
            })
            .collect();
        self.send([EventKind::Logs(lines)]);
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every fake payload must survive the real decoder + parsers.
    #[test]
    fn fake_payloads_parse() {
        let mut srv = FakeServer::new();
        let mut dec = FrameDecoder::new();
        let mut pipe = Pipeline::new();
        let units: Vec<String> = ["nginx.service", "redis-server.service"]
            .map(String::from)
            .to_vec();
        let mut out = Vec::new();
        for round in 0..2 {
            srv.tick(2.0);
            for s in [
                Section::Static,
                Section::Cpu,
                Section::Mem,
                Section::Net,
                Section::Dio,
                Section::Df,
                Section::Who,
                Section::Ps,
                Section::Svc,
                Section::Ports,
                Section::Conns,
                Section::Fw,
                Section::F2b,
                Section::Auth,
                Section::Timers,
            ] {
                let mut frames = Vec::new();
                dec.push(
                    &encode(s, round * 100 + s as u64, &srv.payload(s, &units)),
                    &mut frames,
                );
                assert_eq!(frames.len(), 1, "{s:?}");
                for f in frames {
                    pipe.on_frame(f, &mut out);
                }
            }
        }
        assert_eq!(dec.dropped, 0);
        let has = |p: fn(&EventKind) -> bool| out.iter().any(p);
        assert!(has(
            |e| matches!(e, EventKind::Cpu(c) if c.cores.len() == CORES && c.total > 0.0)
        ));
        assert!(has(
            |e| matches!(e, EventKind::Net(n) if n.iface == "eth0" && n.rx_bps > 0.0)
        ));
        assert!(has(
            |e| matches!(e, EventKind::DiskIo(d) if d.read_bps > 0.0)
        ));
        assert!(has(|e| matches!(e, EventKind::Mounts(m) if m.len() == 3)));
        assert!(has(|e| matches!(e, EventKind::Sessions(s) if s.len() == 2)));
        assert!(has(
            |e| matches!(e, EventKind::Processes(p) if p.len() == 7)
        ));
        assert!(has(|e| matches!(e, EventKind::Services(s) if s.len() == 2)));
        assert!(has(
            |e| matches!(e, EventKind::Static(h) if h.cpus == CORES as u32)
        ));
        assert!(has(
            |e| matches!(e, EventKind::Firewall(f) if f.active && f.rules.len() == 4)
        ));
        assert!(has(|e| matches!(e, EventKind::Jails(j) if j.len() == 2)));
        assert!(has(
            |e| matches!(e, EventKind::Auth(a) if a.buckets.len() == 48)
        ));
        assert!(has(
            |e| matches!(e, EventKind::Scheduled(s) if s.timers.len() == 3)
        ));
        assert!(has(
            |e| matches!(e, EventKind::Listeners(l) if l.len() == 6)
        ));
        // disk 85 %, failed redis, and redis on a public port without a ufw rule.
        assert!(has(|e| matches!(e, EventKind::Alerts(a) if a.len() == 3)));
    }
}
