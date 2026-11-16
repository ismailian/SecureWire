//! Drive the real actor against a real server and print what every part returns:
//! probe, sudo, every collector section, services (Live), log discovery + streaming,
//! actions, and full-screen programs (vim, htop, tmux) in a PTY.
//!
//! Credentials come from the environment only (nothing is written anywhere):
//!   SW_REAL=user@host[:port]  SW_REAL_PASS=…  [SW_REAL_SUDO=… (defaults to SW_REAL_PASS)]
//!   cargo run -p securewire-ssh --example real_host
//! Host keys are accepted for this run only (never saved).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use sw_core::Section;
use sw_core::actions::Action;
use sw_ssh::api::{AuthSpec, Command, ConnectSpec, EventKind, KeyDecision, KnownHosts};
use sw_ssh::{Event, HostHandle, Net};
use sw_term::{Size, Terminal};

struct Run {
    host: HostHandle,
    rx: Receiver<Event>,
    sudo: SecretString,
    counts: BTreeMap<String, usize>,
    log: Vec<String>,
    results: BTreeMap<u64, (bool, Option<u32>, String)>,
    candidates: Vec<sw_core::logs::LogCandidate>,
    connected: bool,
    last: BTreeMap<String, String>,
}

fn kind_name(e: &EventKind) -> String {
    let s = format!("{e:?}");
    s.split(['(', ' ', '{']).next().unwrap_or("?").to_owned()
}

impl Run {
    /// Pump events for `d`, answering prompts; stop early when `until` matches.
    fn pump(&mut self, d: Duration, mut until: impl FnMut(&EventKind) -> bool) -> bool {
        let end = Instant::now() + d;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            let Ok(ev) = self.rx.recv_timeout(left) else {
                return false;
            };
            let k = ev.kind;
            let name = kind_name(&k);
            let first = !self.counts.contains_key(&name);
            self.last.insert(name.clone(), format!("{k:?}"));
            *self.counts.entry(name.clone()).or_default() += 1;
            match &k {
                EventKind::HostKeyPrompt {
                    host,
                    algorithm,
                    fingerprint,
                    status,
                } => {
                    println!(
                        "host key {host}: {algorithm} {fingerprint} ({status:?}) → accept once"
                    );
                    self.host.send(Command::HostKey(KeyDecision::Once));
                }
                EventKind::SudoPrompt {
                    attempts_left,
                    message,
                } => {
                    println!(
                        "sudo prompt (attempts left {attempts_left}, {message:?}) → sending password"
                    );
                    self.host
                        .send(Command::SudoPassword(Some(self.sudo.clone())));
                }
                EventKind::Connected(_) => self.connected = true,
                EventKind::ActionResult {
                    id,
                    ok,
                    exit,
                    output,
                } => {
                    self.results.insert(*id, (*ok, *exit, output.clone()));
                }
                EventKind::LogCandidates(c) => self.candidates = c.clone(),
                EventKind::Error(e) | EventKind::AuthFailed(e) => println!("!! {name}: {e}"),
                EventKind::SectionError { section, code } => {
                    println!("!! section {section:?}: {code}")
                }
                _ => {}
            }
            if first {
                let s = format!("{k:?}");
                let short: String = s.chars().take(300).collect();
                self.log.push(format!("{name}: {short}"));
                println!("first {short}");
            }
            if until(&k) {
                return true;
            }
        }
    }
}

fn screen_wait(run: &mut Run, term: &Terminal, needle: &[&str], d: Duration) -> Option<String> {
    let end = Instant::now() + d;
    while Instant::now() < end {
        let s = term.screen_text();
        if let Some(n) = needle.iter().find(|n| s.contains(**n)) {
            return Some((*n).to_owned());
        }
        run.pump(Duration::from_millis(100), |_| false);
    }
    None
}

fn typ(run: &Run, s: &str) {
    run.host.send(Command::PtyInput {
        pty: 1,
        bytes: s.as_bytes().to_vec(),
    });
}

fn main() {
    let target = std::env::var("SW_REAL").expect("set SW_REAL=user@host[:port]");
    let pass = std::env::var("SW_REAL_PASS").expect("set SW_REAL_PASS");
    let sudo = std::env::var("SW_REAL_SUDO").unwrap_or_else(|_| pass.clone());
    let (user, rest) = target.split_once('@').expect("user@host");
    let (address, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), p.parse().expect("port")),
        None => (rest.to_owned(), 22),
    };
    let kh = std::env::temp_dir().join(format!("sw-real-{}", std::process::id()));
    let spec = ConnectSpec {
        name: "real".into(),
        address,
        port,
        user: user.into(),
        auth: AuthSpec::Password(SecretString::from(pass)),
        known_hosts: KnownHosts {
            user_file: None,
            app_file: kh.join("known_hosts"),
        },
        connect_timeout: ConnectSpec::DEFAULT_TIMEOUT,
        jump: None,
    };
    let net = Net::start().unwrap();
    let (tx, rx) = channel();
    let host = net.connect(1, spec, tx, Arc::new(|| {}));
    let mut run = Run {
        host,
        rx,
        sudo: SecretString::from(sudo),
        counts: BTreeMap::new(),
        log: vec![],
        results: BTreeMap::new(),
        candidates: vec![],
        connected: false,
        last: BTreeMap::new(),
    };
    let t0 = Instant::now();
    assert!(
        run.pump(Duration::from_secs(30), |e| matches!(
            e,
            EventKind::Connected(_)
        )),
        "did not connect"
    );
    println!("connected in {} ms", t0.elapsed().as_millis());
    if std::env::var_os("SW_REAL_PROFILE").is_some() {
        profile(&mut run);
        return;
    }
    if std::env::var_os("SW_REAL_STEADY").is_some() {
        steady(&mut run);
        return;
    }

    // Everything visible, services Live.
    for s in [
        Section::Mem,
        Section::Net,
        Section::Df,
        Section::Dio,
        Section::Who,
        Section::Svc,
        Section::Ports,
        Section::Conns,
        Section::Fw,
        Section::F2b,
        Section::Auth,
        Section::Timers,
        Section::Ps,
        Section::Cpu,
    ] {
        run.host.send(Command::SetSection {
            section: s,
            on: true,
        });
    }
    run.host.send(Command::SetServices(
        [
            "ssh.service",
            "sshd.service",
            "cron.service",
            "systemd-journald.service",
            "nonexistent-x.service",
        ]
        .map(String::from)
        .to_vec(),
    ));
    run.host.send(Command::SetServiceMode {
        mode: sw_core::config::ServiceMode::Live,
        poll_secs: 30,
    });

    let term = Terminal::new(
        Size {
            cols: 120,
            rows: 36,
        },
        2000,
        Arc::new(|_| {}),
    );
    run.host.send(Command::OpenPty {
        pty: 1,
        term: term.clone(),
    });
    run.pump(Duration::from_secs(6), |_| false);
    typ(&run, "echo SW-MARK-$((40+2)); stty size\r");
    let echo = screen_wait(&mut run, &term, &["SW-MARK-42"], Duration::from_secs(5));
    println!("pty echo: {echo:?}");
    let stty = screen_wait(&mut run, &term, &["36 120"], Duration::from_secs(3));
    println!("stty: {stty:?}");

    typ(
        &run,
        "clear; for c in vim vi vim.tiny nano htop top tmux screen; do printf '%s=%s ' $c $(command -v $c >/dev/null && echo y || echo n); done; echo END-CMDS\r",
    );
    screen_wait(
        &mut run,
        &term,
        &["y END-CMDS", "n END-CMDS"],
        Duration::from_secs(4),
    );
    run.pump(Duration::from_millis(300), |_| false);
    println!(
        "programs: {}",
        term.screen_text()
            .lines()
            .find(|l| l.contains("vim="))
            .unwrap_or("?")
    );

    // Full-screen programs: each starts from a cleared screen with a fresh marker, runs,
    // is checked by what it draws, quits, and the shell must come back.
    let programs: [(&str, &str, &[&str], &str); 4] = [
        (
            "vim",
            "vim -u NONE -N || vi",
            &["~                ", "VIM"],
            "\x1b:q!\r",
        ),
        (
            "vi",
            "vi -u NONE",
            &["~                ", "VIM"],
            "\x1b:q!\r",
        ),
        ("htop", "htop", &["Load average", "Tasks:"], "q"),
        (
            "tmux/screen",
            "tmux new -s swcheck || screen -S swcheck",
            &["[swcheck]", "swcheck", "Screen version"],
            "exit\r",
        ),
    ];
    for (n, (name, cmd, needles, quit)) in programs.iter().enumerate() {
        let ready = format!("READY-{n}-OK");
        typ(&run, &format!("clear; echo READY-{n}-$((0))K | tr 0 O\r"));
        screen_wait(&mut run, &term, &[ready.as_str()], Duration::from_secs(4));
        typ(&run, &format!("clear; {cmd}\r"));
        let got = screen_wait(&mut run, &term, needles, Duration::from_secs(6));
        println!("{name}: {got:?}");
        if got.is_some() {
            println!(
                "--- {name} screen (top) ---\n{}\n---",
                term.screen_text()
                    .lines()
                    .take(4)
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        typ(&run, quit);
        run.pump(Duration::from_millis(1200), |_| false);
    }
    typ(&run, "clear; echo BACK-$((1+1))\r");
    println!(
        "shell back: {:?}",
        screen_wait(&mut run, &term, &["BACK-2"], Duration::from_secs(4))
    );

    // Logs: discovery, then stream the first journal unit + first file.
    run.host.send(Command::DiscoverLogs);
    run.pump(Duration::from_secs(15), |e| {
        matches!(e, EventKind::LogCandidates(_))
    });
    println!("log candidates: {}", run.candidates.len());
    for c in run.candidates.iter().take(12) {
        println!("  {c:?}");
    }
    let mut sources = vec![];
    if let Some(u) = run
        .candidates
        .iter()
        .find(|c| format!("{c:?}").contains("ssh"))
    {
        let s = format!("{u:?}");
        println!("pick {s}");
    }
    sources.push(sw_core::config::LogSourceConfig {
        id: "journal".into(),
        kind: "journal".into(),
        target: "ssh.service".into(),
        preset: None,
        color: 0,
    });
    sources.push(sw_core::config::LogSourceConfig {
        id: "syslog".into(),
        kind: "sudo-file".into(),
        target: "/var/log/syslog".into(),
        preset: None,
        color: 1,
    });
    run.host.send(Command::SetLogSources {
        sources,
        backlog: 50,
    });
    let got = run.pump(
        Duration::from_secs(10),
        |e| matches!(e, EventKind::Logs(l) if !l.is_empty()),
    );
    println!("log lines arrived: {got}");

    // Actions (read-only ones; nothing is changed on the server).
    run.host.send(Command::RunAction {
        id: 1,
        action: Action::WhoOnPort(22),
    });
    run.host.send(Command::RunAction {
        id: 2,
        action: Action::LargestDirs("/var".into()),
    });
    run.pump(Duration::from_secs(30), |_| false);
    for (id, (ok, exit, out)) in &run.results {
        let head: String = out.lines().take(8).collect::<Vec<_>>().join("\n    ");
        println!("action {id}: ok={ok} exit={exit:?}\n    {head}");
    }

    for k in [
        "Services",
        "ServiceMode",
        "Sudo",
        "Link",
        "Firewall",
        "Sessions",
    ] {
        println!("last {k}: {}", run.last.get(k).map_or("-", |s| s.as_str()));
    }
    // Default UI visibility: Processes, Connections and Scheduled are not shown.
    for s in [Section::Conns, Section::Ps, Section::Timers] {
        run.host.send(Command::SetSection {
            section: s,
            on: false,
        });
    }
    // Every collector process (sudo parent + bash), own + reaped children's CPU, over 60 s.
    // Skipped in strict mode (CI): it only checks that everything works, and this is a 60 s sleep.
    let measure = std::env::var_os("SW_REAL_STRICT").is_none();
    if measure {
        typ(
            &run,
            "clear; T=$(getconf CLK_TCK); t() { s=0; for p in $(pgrep -f securewire-collector); do v=$(awk '{print $14+$15+$16+$17}' /proc/$p/stat 2>/dev/null); s=$((s+${v:-0})); done; echo $s; }; ps -o pid,user,args -p \"$(pgrep -d, -f securewire-collector)\"; a=$(t); sleep 60; b=$(t); echo CPU-RESULT ticks=$((b-a)) hz=$T over=60s\r",
        );
        screen_wait(
            &mut run,
            &term,
            &["CPU-RESULT ticks"],
            Duration::from_secs(75),
        );
        println!(
            "{}",
            term.screen_text()
                .lines()
                .filter(|l| l.contains("CPU-RESULT ticks") || l.contains("securewire-collector"))
                .collect::<Vec<_>>()
                .join(
                    "
"
                )
        );
    }
    println!(
        "last Link: {}",
        run.last.get("Link").map_or("-", |s| s.as_str())
    );

    // Collector cost on the server, measured from the PTY.
    typ(
        &run,
        "clear; ps -eo pid,pcpu,cputime,etime,args | grep -F securewire- | grep -v grep\r",
    );
    run.pump(Duration::from_secs(2), |_| false);
    println!(
        "--- server processes ---\n{}\n---",
        term.screen_text().trim_end()
    );

    println!("\nevent counts after {} s:", t0.elapsed().as_secs());
    for (k, n) in &run.counts {
        println!("  {k:<16} {n}");
    }
    // SW_REAL_STRICT=1 (CI against a real sshd): every part must have worked.
    if std::env::var_os("SW_REAL_STRICT").is_some() {
        let mut missing = Vec::new();
        for k in [
            "Probe",
            "Static",
            "Cpu",
            "Mem",
            "Net",
            "DiskIo",
            "Mounts",
            "Processes",
            "Listeners",
            "Services",
            "LogCandidates",
            "LogSources",
        ] {
            if !run.counts.contains_key(k) {
                missing.push(k.to_owned());
            }
        }
        if echo.is_none() || stty.is_none() {
            missing.push("PTY echo / resize".into());
        }
        if run.last.get("Sudo").map(String::as_str) != Some("Sudo(Password)") {
            missing.push(format!(
                "sudo password mode (got {:?})",
                run.last.get("Sudo")
            ));
        }
        for id in [1, 2] {
            if !run.results.get(&id).is_some_and(|r| r.0) {
                missing.push(format!("action {id}"));
            }
        }
        if !got {
            missing.push("log lines".into());
        }
        assert!(missing.is_empty(), "real-host check failed: {missing:?}");
        println!("STRICT: all parts worked");
    }
    let _ = std::fs::remove_dir_all(&kh);
    drop(run);
    drop(net);
}

/// `SW_REAL_PROFILE=1`: server CPU per collector section. Everything OFF, then each
/// section is emitted N times with `NOW`; the collector processes' CPU ticks (own +
/// reaped children, /proc/<pid>/stat) are read from a PTY shell before and after.
fn profile(run: &mut Run) {
    const N: u32 = 5;
    let all = [
        Section::Cpu,
        Section::Mem,
        Section::Net,
        Section::Dio,
        Section::Df,
        Section::Who,
        Section::Svc,
        Section::Ports,
        Section::Conns,
        Section::Ps,
        Section::Fw,
        Section::F2b,
        Section::Auth,
        Section::Timers,
    ];
    run.host.send(Command::SetServices(
        ["ssh.service", "cron.service", "fail2ban.service"]
            .map(String::from)
            .to_vec(),
    ));
    run.host.send(Command::SetServiceMode {
        mode: sw_core::config::ServiceMode::Manual,
        poll_secs: 30,
    });
    for s in all {
        run.host.send(Command::SetSection {
            section: s,
            on: false,
        });
    }
    let term = Terminal::new(
        Size {
            cols: 160,
            rows: 40,
        },
        500,
        Arc::new(|_| {}),
    );
    run.host.send(Command::OpenPty {
        pty: 1,
        term: term.clone(),
    });
    run.pump(Duration::from_secs(8), |_| false); // sudo + collector restart settle
    typ(
        run,
        " t() { s=0; for p in $(pgrep -f securewire-collector); do v=$(awk '{print $14+$15+$16+$17}' /proc/$p/stat 2>/dev/null); s=$((s+${v:-0})); done; echo $s; }\r",
    );
    let read = |run: &mut Run, tag: &str| -> Option<i64> {
        typ(run, &format!("clear; echo TK-{tag}=$(t)=\r"));
        let needle = format!("TK-{tag}=");
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            run.pump(Duration::from_millis(100), |_| false);
            let s = term.screen_text();
            if let Some(l) = s
                .lines()
                .find(|l| l.starts_with(&needle) && l.ends_with('='))
            {
                return l.trim_end_matches('=').rsplit('=').next()?.parse().ok();
            }
        }
        None
    };
    let base_a = read(run, "base0");
    run.pump(Duration::from_secs(10), |_| false);
    let base_b = read(run, "base1");
    println!(
        "idle (all OFF) 10 s: {:?} ticks",
        base_b.zip(base_a).map(|(b, a)| b - a)
    );
    for s in all {
        let a = read(run, &format!("{s:?}a"));
        for _ in 0..N {
            run.host.send(Command::Now(s));
            run.pump(Duration::from_millis(1500), |_| false);
        }
        let b = read(run, &format!("{s:?}b"));
        let per = b.zip(a).map(|(b, a)| (b - a) as f64 * 10.0 / N as f64);
        println!(
            "{s:?}: {} ms CPU per emission",
            per.map_or("?".into(), |v| format!("{v:.0}"))
        );
    }
}

/// `SW_REAL_STEADY=1`: steady-state server CPU per group of sections, each ON alone for
/// 40 s at the default tiers (what a real session costs, gates and dedupe included).
fn steady(run: &mut Run) {
    let all = [
        Section::Cpu,
        Section::Mem,
        Section::Net,
        Section::Dio,
        Section::Df,
        Section::Who,
        Section::Svc,
        Section::Ports,
        Section::Conns,
        Section::Ps,
        Section::Fw,
        Section::F2b,
        Section::Auth,
        Section::Timers,
    ];
    run.host.send(Command::SetServices(
        ["ssh.service", "cron.service", "fail2ban.service"]
            .map(String::from)
            .to_vec(),
    ));
    let mode = if std::env::var_os("SW_REAL_STEADY_LIVE").is_some() {
        sw_core::config::ServiceMode::Live
    } else {
        sw_core::config::ServiceMode::Poll
    };
    run.host.send(Command::SetServiceMode {
        mode,
        poll_secs: 10,
    });
    let term = Terminal::new(
        Size {
            cols: 160,
            rows: 40,
        },
        500,
        Arc::new(|_| {}),
    );
    run.host.send(Command::OpenPty {
        pty: 1,
        term: term.clone(),
    });
    run.pump(Duration::from_secs(8), |_| false);
    typ(
        run,
        " t() { s=0; for p in $(pgrep -f securewire-collector); do v=$(awk '{print $14+$15+$16+$17}' /proc/$p/stat 2>/dev/null); s=$((s+${v:-0})); done; echo $s; }\r",
    );
    let read = |run: &mut Run, tag: &str| -> Option<i64> {
        typ(run, &format!("clear; echo TK-{tag}=$(t)=\r"));
        let needle = format!("TK-{tag}=");
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            run.pump(Duration::from_millis(100), |_| false);
            if let Some(l) = term
                .screen_text()
                .lines()
                .find(|l| l.starts_with(&needle) && l.ends_with('='))
            {
                return l.trim_end_matches('=').rsplit('=').next()?.parse().ok();
            }
        }
        None
    };
    let groups: [(&str, &[Section]); 7] = [
        (
            "all default-visible",
            &[
                Section::Cpu,
                Section::Mem,
                Section::Net,
                Section::Dio,
                Section::Df,
                Section::Who,
                Section::Svc,
                Section::Ports,
                Section::Fw,
                Section::F2b,
                Section::Auth,
            ],
        ),
        ("none", &[]),
        (
            "fast cpu+mem+net+dio",
            &[Section::Cpu, Section::Mem, Section::Net, Section::Dio],
        ),
        ("svc (poll 10 s)", &[Section::Svc]),
        ("who", &[Section::Who]),
        ("df+ports+fw", &[Section::Df, Section::Ports, Section::Fw]),
        ("f2b", &[Section::F2b]),
    ];
    // SW_REAL_STEADY_ONLY=f2b  SW_REAL_STEADY_SECS=130: one group, a longer window.
    let only = std::env::var("SW_REAL_STEADY_ONLY").ok();
    let secs: u64 = std::env::var("SW_REAL_STEADY_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    for (name, on) in groups {
        if only.as_deref().is_some_and(|o| !name.contains(o)) {
            continue;
        }
        for s in all {
            run.host.send(Command::SetSection {
                section: s,
                on: on.contains(&s),
            });
        }
        run.pump(Duration::from_secs(3), |_| false);
        let a = read(run, &format!("{}a", name.len()));
        run.pump(Duration::from_secs(secs), |_| false);
        let b = read(run, &format!("{}b", name.len()));
        let ms_per_s = b.zip(a).map(|(b, a)| (b - a) as f64 * 10.0 / secs as f64);
        println!(
            "STEADY {name}: {} ms CPU per second ({}% of a core)",
            ms_per_s.map_or("?".into(), |v| format!("{v:.2}")),
            ms_per_s.map_or("?".into(), |v| format!("{:.2}", v / 10.0))
        );
    }
}
