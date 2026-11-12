//! The real `collector/collector.sh` under a real bash, fed through the real
//! frame decoder and pipeline. Skips (with a note) when no bash is available.

#[path = "support/fakehost.rs"]
mod fakehost;

use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use fakehost::FakeHost;
use sw_core::{Frame, FrameDecoder, Section};
use sw_ssh::api::EventKind;
use sw_ssh::collector::SCRIPT;
use sw_ssh::pipeline::Pipeline;

struct Run {
    child: Child,
    stdin: ChildStdin,
    out: Receiver<Vec<u8>>,
    dec: FrameDecoder,
    pipe: Pipeline,
    _host: FakeHost,
}

impl Run {
    /// `tiers`: fast/medium/slow seconds.
    fn start(tag: &str, tiers: (u32, u32, u32)) -> Option<Run> {
        Self::start_priv(tag, tiers, "none", None)
    }

    /// `privilege`: none | root | nopasswd | password; `password` is written after the script.
    fn start_priv(
        tag: &str,
        tiers: (u32, u32, u32),
        privilege: &str,
        password: Option<&str>,
    ) -> Option<Run> {
        let Some(host) = FakeHost::new(tag) else {
            eprintln!("SKIP: no bash found (set SW_TEST_BASH)");
            return None;
        };
        let mut child = Command::new(host.bash())
            .args([
                "-s",
                "securewire-collector",
                &tiers.0.to_string(),
                &tiers.1.to_string(),
                &tiers.2.to_string(),
                privilege,
            ])
            .envs(host.env())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bash");
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(SCRIPT.as_bytes()).unwrap();
        if let Some(pw) = password {
            writeln!(stdin, "{pw}").unwrap();
        }
        let mut stdout = child.stdout.take().unwrap();
        let (tx, out) = channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Some(Run {
            child,
            stdin,
            out,
            dec: FrameDecoder::new(),
            pipe: Pipeline::new(),
            _host: host,
        })
    }

    fn host(&self) -> &FakeHost {
        &self._host
    }

    fn send(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
    }

    /// Collect frames until `pred` matches one (or time out).
    fn until(&mut self, secs: u64, mut pred: impl FnMut(&Frame) -> bool) -> Vec<Frame> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut seen = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let chunk = self
                .out
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("timed out; frames so far: {seen:#?}"));
            let mut frames = Vec::new();
            self.dec.push(&chunk, &mut frames);
            for f in frames {
                let hit = pred(&f);
                seen.push(f);
                if hit {
                    return seen;
                }
            }
        }
    }

    fn events(&mut self, frames: Vec<Frame>) -> Vec<EventKind> {
        let mut out = Vec::new();
        for f in frames {
            self.pipe.on_frame(f, &mut out);
        }
        out
    }
}

fn is_data(f: &Frame, s: Section) -> bool {
    matches!(f, Frame::Data { section, .. } if *section == s)
}

#[test]
fn every_m2_section_parses_and_controls_work() {
    let Some(mut r) = Run::start("all", (1, 1, 0)) else {
        return;
    };

    // HELLO + static first, then every section on its tier.
    let frames = r.until(10, |f| is_data(f, Section::Ps));
    assert!(
        matches!(frames[0], Frame::Hello { proto: 1, .. }),
        "{:?}",
        frames[0]
    );
    for s in [
        Section::Static,
        Section::Cpu,
        Section::Mem,
        Section::Net,
        Section::Dio,
        Section::Df,
        Section::Who,
    ] {
        assert!(
            frames.iter().any(|f| is_data(f, s)),
            "missing {s:?} in {frames:#?}"
        );
    }
    let ev = r.events(frames);
    assert!(ev.iter().any(|e| matches!(e, EventKind::Static(h) if h.hostname == "fake-vps" && h.cpus == 2 && h.os == "Ubuntu 24.04.1 LTS")));
    assert!(
        ev.iter()
            .any(|e| matches!(e, EventKind::Mem(m) if m.total == 8_000_000 * 1024))
    );
    assert!(
        ev.iter()
            .any(|e| matches!(e, EventKind::Mounts(m) if m.len() == 2))
    );
    assert!(
        ev.iter()
            .any(|e| matches!(e, EventKind::Sessions(s) if s[0].user == "deploy"))
    );
    assert!(
        ev.iter()
            .any(|e| matches!(e, EventKind::Processes(p) if p[0].command == "/usr/sbin/mysqld"))
    );
    // /var/lib/mysql at 85 % → disk alert from the pipeline.
    assert!(ev.iter().any(
        |e| matches!(e, EventKind::Alerts(a) if a.iter().any(|x| x.key == "disk:/var/lib/mysql"))
    ));

    // Counters advance → the next cpu/net frames give real rates.
    r.host().tick();
    r.send("NOW cpu");
    r.send("NOW net");
    let frames = r.until(5, |f| is_data(f, Section::Net));
    let ev = r.events(frames);
    let cpu = ev
        .iter()
        .find_map(|e| {
            if let EventKind::Cpu(c) = e {
                Some(c.clone())
            } else {
                None
            }
        })
        .expect("cpu sample");
    assert!((cpu.total - 33.3).abs() < 1.0, "cpu {cpu:?}");
    assert_eq!(cpu.cores.len(), 2);
    let net = ev
        .iter()
        .find_map(|e| {
            if let EventKind::Net(n) = e {
                Some(n.clone())
            } else {
                None
            }
        })
        .expect("net sample");
    assert_eq!(net.iface, "eth0");
    assert!((net.rx_bps - 1_000_000.0).abs() < 1.0, "net {net:?}");

    // Unchanged medium sections are deduplicated.
    r.send("NOW df");
    let frames = r.until(5, |f| {
        matches!(
            f,
            Frame::Same {
                section: Section::Df,
                ..
            }
        )
    });
    assert!(frames.iter().all(|f| !is_data(f, Section::Df)));

    // Services: invalid names dropped by the script, failed unit → alert.
    r.send("SVC nginx.service redis-server.service $(touch_pwned) ../etc -bad");
    let frames = r.until(5, |f| is_data(f, Section::Svc));
    let ev = r.events(frames);
    let svcs = ev
        .iter()
        .find_map(|e| {
            if let EventKind::Services(s) = e {
                Some(s.clone())
            } else {
                None
            }
        })
        .unwrap();
    let ids: Vec<_> = svcs.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, ["nginx.service", "redis-server.service"]);
    assert!(ev.iter().any(|e| matches!(e, EventKind::Alerts(a) if a.iter().any(|x| x.key == "svc-failed:redis-server.service"))));

    // OFF stops a section; garbage is ignored; PING answers.
    r.send("OFF ps");
    r.send("NOW ../../etc/passwd");
    r.send("TIER fast notanumber");
    r.send("PING 4242");
    let frames = r.until(5, |f| matches!(f, Frame::Pong(4242)));
    let _ = frames;
    let frames = r.until(4, |f| is_data(f, Section::Mem)); // a couple of ticks later
    let frames2 = r.until(4, |f| is_data(f, Section::Mem));
    assert!(
        frames
            .iter()
            .chain(&frames2)
            .all(|f| !is_data(f, Section::Ps)),
        "ps still sent after OFF"
    );

    // QUIT ends it cleanly.
    r.send("QUIT");
    let status = r.child.wait().unwrap();
    assert!(status.success());
}

#[test]
fn eof_on_stdin_ends_the_collector() {
    let Some(mut r) = Run::start("eof", (1, 1, 0)) else {
        return;
    };
    r.until(10, |f| is_data(f, Section::Cpu));
    let Run {
        mut child, stdin, ..
    } = r;
    drop(stdin); // the SSH channel closing looks like this to the script
    let t = Instant::now();
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            assert!(s.success());
            break;
        }
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "collector kept running after EOF"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn missing_proc_files_report_err_not_crash() {
    let Some(mut r) = Run::start("missing", (1, 1, 0)) else {
        return;
    };
    std::fs::remove_file(r.host().dir.join("proc/net/dev")).unwrap();
    std::fs::remove_file(r.host().dir.join("proc/diskstats")).unwrap();
    let frames = r.until(10, |f| {
        matches!(
            f,
            Frame::Err {
                section: Section::Dio,
                ..
            }
        )
    });
    assert!(
        frames.iter().any(
            |f| matches!(f, Frame::Err { section: Section::Net, code, .. } if code == "missing")
        )
    );
    // Still alive and answering.
    r.send("PING 7");
    r.until(5, |f| matches!(f, Frame::Pong(7)));
}

fn data_of(frames: &[Frame], s: Section) -> bool {
    frames.iter().any(|f| is_data(f, s))
}

#[test]
fn m3_sections_with_sudo_password() {
    // Slow tier 1 s so every M3 section shows up quickly; auth has its own 300 s
    // interval, so ask for it explicitly.
    let Some(mut r) = Run::start_priv("m3", (1, 1, 1), "password", Some(fakehost::SUDO_PASSWORD))
    else {
        return;
    };
    r.send("NOW auth");
    let mut frames = Vec::new();
    for s in [
        Section::Ports,
        Section::Conns,
        Section::Fw,
        Section::F2b,
        Section::Auth,
        Section::Timers,
    ] {
        if !data_of(&frames, s) {
            frames.extend(r.until(10, |f| is_data(f, s)));
        }
    }
    let ev = r.events(frames);
    let find = |pred: &dyn Fn(&EventKind) -> bool| ev.iter().any(pred);
    assert!(find(
        &|e| matches!(e, EventKind::Listeners(l) if l.len() == 4 && l.iter().any(|x| x.port == 6379))
    ));
    assert!(find(&|e| matches!(e, EventKind::Conns(c) if c.len() == 2)));
    assert!(find(
        &|e| matches!(e, EventKind::Firewall(f) if f.backend == "ufw" && f.active && f.rules.len() == 2)
    ));
    assert!(find(
        &|e| matches!(e, EventKind::Jails(j) if j.len() == 1 && j[0].currently_banned == 2)
    ));
    assert!(find(
        &|e| matches!(e, EventKind::Auth(a) if a.total() == 3 && a.top[0] == ("198.51.100.203".to_string(), 2))
    ));
    assert!(find(
        &|e| matches!(e, EventKind::Scheduled(s) if s.timers[0].unit == "certbot.timer" && s.cron_jobs.len() == 1)
    ));
    // redis on 0.0.0.0:6379 with ufw denying incoming and no rule for it.
    assert!(find(
        &|e| matches!(e, EventKind::Alerts(a) if a.iter().any(|x| x.key == "listener:6379"))
    ));
}

#[test]
fn privileged_sections_need_sudo() {
    // No privilege → fw/f2b report needs-sudo; a wrong password behaves the same way.
    for (tag, privilege, pw) in [
        ("nopriv", "none", None),
        ("badpw", "password", Some("wrong")),
    ] {
        let Some(mut r) = Run::start_priv(tag, (1, 1, 1), privilege, pw) else {
            return;
        };
        let frames = r.until(10, |f| {
            matches!(
                f,
                Frame::Err {
                    section: Section::F2b,
                    ..
                }
            )
        });
        let code = |s: Section| {
            frames.iter().find_map(|f| match f {
                Frame::Err { section, code, .. } if *section == s => Some(code.clone()),
                _ => None,
            })
        };
        let fw = code(Section::Fw);
        if privilege == "none" {
            assert_eq!(fw.as_deref(), Some("needs-sudo"), "{tag}");
            assert_eq!(code(Section::F2b).as_deref(), Some("needs-sudo"), "{tag}");
        } else {
            // sudo refuses the wrong password → both sections report an error, never empty data.
            assert_eq!(fw.as_deref(), Some("unavailable"), "{tag}");
            assert_eq!(code(Section::F2b).as_deref(), Some("unavailable"), "{tag}");
            assert!(
                !data_of(&frames, Section::Fw) && !data_of(&frames, Section::F2b),
                "{tag}"
            );
        }
    }
}

#[test]
fn every_overrides_a_section_interval() {
    let Some(mut r) = Run::start("every", (1, 60, 0)) else {
        return;
    };
    r.send("SVC nginx.service");
    r.until(5, |f| {
        is_data(f, Section::Svc)
            || matches!(
                f,
                Frame::Same {
                    section: Section::Svc,
                    ..
                }
            )
    });
    // Medium tier is 60 s; EVERY svc 1 makes it poll every second.
    r.send("EVERY svc 1");
    for _ in 0..2 {
        r.until(5, |f| {
            matches!(
                f,
                Frame::Same {
                    section: Section::Svc,
                    ..
                } | Frame::Data {
                    section: Section::Svc,
                    ..
                }
            )
        });
    }
}
