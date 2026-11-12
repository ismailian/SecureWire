//! End-to-end: the real russh actor against the in-process test server.

mod support;

use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use sw_ssh::api::{
    AuthSpec, Command, ConnState, ConnectSpec, EventKind, HostKeyStatus, KeyDecision, KnownHosts,
};
use sw_ssh::{Event, HostHandle, Net};
use sw_term::{Size, Terminal};

struct Fixture {
    _net: Net,
    host: HostHandle,
    rx: Receiver<Event>,
    _dir: TempDir,
    /// Every event received so far (for order-independent checks).
    seen: std::cell::RefCell<Vec<EventKind>>,
}

/// Like [`wait_for`], but also succeeds on an event that already went by.
fn seen_or_wait(f: &Fixture, mut pred: impl FnMut(&EventKind) -> bool) -> EventKind {
    if let Some(e) = f.seen.borrow().iter().find(|e| pred(e)) {
        return e.clone();
    }
    wait_for(f, KeyDecision::Once, pred)
}

/// Minimal temp dir (no extra dependency).
struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "sw-test-{tag}-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn spec(port: u16, auth: AuthSpec, dir: &TempDir) -> ConnectSpec {
    ConnectSpec {
        name: "test".into(),
        address: "127.0.0.1".into(),
        port,
        user: support::USER.into(),
        auth,
        known_hosts: KnownHosts {
            user_file: None,
            app_file: dir.0.join("known_hosts"),
        },
        connect_timeout: Duration::from_secs(1),
    }
}

fn password() -> AuthSpec {
    AuthSpec::Password(SecretString::from(support::PASSWORD))
}

fn connect(port: u16, auth: AuthSpec, dir: TempDir) -> Fixture {
    let net = Net::start().unwrap();
    let (tx, rx) = channel();
    let host = net.connect(1, spec(port, auth, &dir), tx, Arc::new(|| {}));
    Fixture {
        _net: net,
        host,
        rx,
        _dir: dir,
        seen: Default::default(),
    }
}

/// Wait for the first event matching `pred`, answering host-key prompts with `decision`.
fn wait_for(
    f: &Fixture,
    decision: KeyDecision,
    mut pred: impl FnMut(&EventKind) -> bool,
) -> EventKind {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let ev =
            f.rx.recv_timeout(left)
                .expect("timed out waiting for event")
                .kind;
        if std::env::var_os("SW_TRACE").is_some() {
            eprintln!("event: {ev:?}");
        }
        f.seen.borrow_mut().push(ev.clone());
        if let EventKind::HostKeyPrompt { .. } = ev {
            if pred(&ev) {
                return ev;
            }
            f.host.send(Command::HostKey(decision));
            continue;
        }
        if pred(&ev) {
            return ev;
        }
    }
}

fn wait_screen(term: &Terminal, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if term.screen_text().contains(needle) {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("screen never contained {needle:?}:\n{}", term.screen_text());
}

fn open_term(f: &Fixture) -> Terminal {
    let term = Terminal::new(
        Size {
            cols: 100,
            rows: 30,
        },
        1000,
        Arc::new(|_| {}),
    );
    f.host.send(Command::OpenPty {
        pty: 1,
        term: term.clone(),
    });
    term
}

fn type_line(f: &Fixture, s: &str) {
    f.host.send(Command::PtyInput {
        pty: 1,
        bytes: format!("{s}\r").into_bytes(),
    });
}

#[test]
fn password_tofu_pty_resize_and_exit() {
    let srv = support::start();
    let f = connect(srv.port, password(), TempDir::new("tofu"));

    let prompt = wait_for(&f, KeyDecision::Trust, |e| {
        matches!(e, EventKind::HostKeyPrompt { .. })
    });
    let EventKind::HostKeyPrompt {
        algorithm,
        fingerprint,
        status,
    } = prompt
    else {
        unreachable!()
    };
    assert_eq!(algorithm, "ssh-ed25519");
    assert!(fingerprint.starts_with("SHA256:"));
    assert_eq!(status, HostKeyStatus::Unknown);
    f.host.send(Command::HostKey(KeyDecision::Trust));

    let EventKind::Connected(info) = wait_for(&f, KeyDecision::Trust, |e| {
        matches!(e, EventKind::Connected(_))
    }) else {
        unreachable!()
    };
    assert_eq!(info.fingerprint, fingerprint);
    let kh = std::fs::read_to_string(f._dir.0.join("known_hosts")).unwrap();
    assert!(
        kh.contains(&format!("[127.0.0.1]:{}", srv.port)),
        "trusted key saved: {kh}"
    );

    let term = open_term(&f);
    wait_screen(&term, "tester@sw-test");
    assert_eq!(srv.observed.lock().unwrap().sizes.first(), Some(&(100, 30)));

    type_line(&f, "whoami");
    wait_screen(&term, "\ntester\n");

    term.resize(Size {
        cols: 120,
        rows: 40,
    });
    f.host.send(Command::PtyResize {
        pty: 1,
        cols: 120,
        rows: 40,
    });
    type_line(&f, "stty size");
    wait_screen(&term, "40 120");

    type_line(&f, "exit");
    let closed = wait_for(&f, KeyDecision::Reject, |e| {
        matches!(e, EventKind::PtyClosed { .. })
    });
    assert!(matches!(
        closed,
        EventKind::PtyClosed {
            pty: 1,
            exit: Some(0)
        }
    ));
}

#[test]
fn trusted_key_is_not_asked_again() {
    let srv = support::start();
    let dir = TempDir::new("known");
    russh::keys::known_hosts::learn_known_hosts_path(
        "127.0.0.1",
        srv.port,
        &srv.host_key,
        dir.0.join("known_hosts"),
    )
    .unwrap();
    let f = connect(srv.port, password(), dir);
    let ev = wait_for(&f, KeyDecision::Reject, |e| {
        matches!(e, EventKind::Connected(_) | EventKind::HostKeyPrompt { .. })
    });
    let EventKind::Connected(info) = ev else {
        panic!("asked about a known key: {ev:?}")
    };
    assert!(info.key_known);
}

#[test]
fn changed_key_is_flagged_and_rejection_stops() {
    let srv = support::start();
    let dir = TempDir::new("changed");
    // Record a *different* ed25519 key for this host.
    let other = russh::keys::load_public_key(support::fixture("test_client_ed25519.pub")).unwrap();
    russh::keys::known_hosts::learn_known_hosts_path(
        "127.0.0.1",
        srv.port,
        &other,
        dir.0.join("known_hosts"),
    )
    .unwrap();
    let f = connect(srv.port, password(), dir);
    let ev = wait_for(&f, KeyDecision::Reject, |e| {
        matches!(e, EventKind::HostKeyPrompt { .. })
    });
    assert!(matches!(
        ev,
        EventKind::HostKeyPrompt {
            status: HostKeyStatus::Changed { .. },
            ..
        }
    ));
    f.host.send(Command::HostKey(KeyDecision::Reject));
    wait_for(
        &f,
        KeyDecision::Reject,
        |e| matches!(e, EventKind::Error(m) if m.contains("Host key not accepted")),
    );
    wait_for(&f, KeyDecision::Reject, |e| {
        matches!(e, EventKind::State(ConnState::Disconnected))
    });
}

#[test]
fn wrong_password_reports_auth_failure_then_retry_works() {
    let srv = support::start();
    let f = connect(
        srv.port,
        AuthSpec::Password(SecretString::from("nope")),
        TempDir::new("badpw"),
    );
    wait_for(&f, KeyDecision::Once, |e| {
        matches!(e, EventKind::AuthFailed(_))
    });
    f.host.send(Command::Retry(Some(password())));
    wait_for(&f, KeyDecision::Once, |e| {
        matches!(e, EventKind::Connected(_))
    });
}

#[test]
fn key_file_auth_plain_and_encrypted() {
    let srv = support::start();
    let plain = AuthSpec::KeyFile {
        path: support::fixture("test_client_ed25519"),
        passphrase: None,
    };
    let f = connect(srv.port, plain, TempDir::new("key"));
    wait_for(&f, KeyDecision::Once, |e| {
        matches!(e, EventKind::Connected(_))
    });

    let enc_no_pass = AuthSpec::KeyFile {
        path: support::fixture("test_client_ed25519_enc"),
        passphrase: None,
    };
    let f = connect(srv.port, enc_no_pass, TempDir::new("key-enc"));
    let ev = wait_for(&f, KeyDecision::Once, |e| {
        matches!(e, EventKind::AuthFailed(_))
    });
    assert!(
        matches!(&ev, EventKind::AuthFailed(m) if m.contains("encrypted")),
        "{ev:?}"
    );
    f.host.send(Command::Retry(Some(AuthSpec::KeyFile {
        path: support::fixture("test_client_ed25519_enc"),
        passphrase: Some(SecretString::from(support::PASSPHRASE)),
    })));
    wait_for(&f, KeyDecision::Once, |e| {
        matches!(e, EventKind::Connected(_))
    });
}

#[test]
fn reconnects_after_connection_loss_without_asking_again() {
    let srv = support::start();
    let f = connect(srv.port, password(), TempDir::new("lost"));
    wait_for(&f, KeyDecision::Once, |e| {
        matches!(e, EventKind::Connected(_))
    });
    let term = open_term(&f);
    // A second tab: both channels must come back after the reconnect.
    let term2 = Terminal::new(Size { cols: 80, rows: 24 }, 1000, Arc::new(|_| {}));
    f.host.send(Command::OpenPty {
        pty: 2,
        term: term2.clone(),
    });
    wait_screen(&term, "tester@sw-test");
    wait_screen(&term2, "tester@sw-test");

    type_line(&f, "crash");
    wait_for(&f, KeyDecision::Reject, |e| {
        matches!(e, EventKind::State(ConnState::Reconnecting { .. }))
    });
    // "Once" keys stay accepted for the host session: no second prompt (Reject would fail the test).
    wait_for(&f, KeyDecision::Reject, |e| {
        matches!(e, EventKind::Connected(_))
    });
    // Readers of the dead connection may report late; that must not close the new shells.
    let quiet_until = Instant::now() + Duration::from_millis(1500);
    while let Some(left) = quiet_until.checked_duration_since(Instant::now()) {
        if let Ok(ev) = f.rx.recv_timeout(left) {
            assert!(
                !matches!(ev.kind, EventKind::PtyClosed { .. }),
                "new shell reported closed after reconnect: {:?}",
                ev.kind
            );
        }
    }
    wait_screen(&term, "connection lost");
    assert!(srv.observed.lock().unwrap().sessions >= 2);
    // Both reopened shells work.
    type_line(&f, "echo back-again");
    wait_screen(&term, "back-again\n");
    f.host.send(Command::PtyInput {
        pty: 2,
        bytes: b"echo tab-two\r".to_vec(),
    });
    wait_screen(&term2, "tab-two\n");
}

#[test]
fn slow_host_key_answer_does_not_time_out() {
    // connect_timeout is 1 s in these tests; the user takes 2.5 s to decide.
    let srv = support::start();
    let f = connect(srv.port, password(), TempDir::new("slow"));
    wait_for(&f, KeyDecision::Reject, |e| {
        matches!(e, EventKind::HostKeyPrompt { .. })
    });
    std::thread::sleep(Duration::from_millis(2500));
    f.host.send(Command::HostKey(KeyDecision::Once));
    wait_for(&f, KeyDecision::Reject, |e| {
        matches!(e, EventKind::Connected(_))
    });
}

#[test]
fn probe_sudo_and_live_collector_over_ssh() {
    use support::fakehost::{FakeHost, SUDO_PASSWORD};
    let Some(host) = FakeHost::new("e2e") else {
        eprintln!("SKIP: no bash found (set SW_TEST_BASH)");
        return;
    };
    let srv = support::start_with_exec(support::ExecEnv {
        bash: host.bash().into(),
        env: host.env(),
    });
    let f = connect(srv.port, password(), TempDir::new("m2"));

    // Probe: non-root user with sudo that needs a password.
    let EventKind::Probe(p) = wait_for(&f, KeyDecision::Once, |e| matches!(e, EventKind::Probe(_)))
    else {
        unreachable!()
    };
    assert_eq!(p.uid, Some(1000));
    assert!(
        p.bash.is_some() && p.sudo && !p.sudo_n && p.complete,
        "{p:?}"
    );

    // Sudo flow (protocol §9): wrong password → retry prompt, right one → Password mode.
    wait_for(&f, KeyDecision::Once, |e| {
        matches!(
            e,
            EventKind::SudoPrompt {
                attempts_left: 3,
                ..
            }
        )
    });
    f.host
        .send(Command::SudoPassword(Some(SecretString::from("wrong"))));
    let ev = wait_for(&f, KeyDecision::Once, |e| {
        matches!(
            e,
            EventKind::SudoPrompt {
                message: Some(_),
                ..
            }
        )
    });
    assert!(
        matches!(
            ev,
            EventKind::SudoPrompt {
                attempts_left: 2,
                ..
            }
        ),
        "{ev:?}"
    );
    f.host.send(Command::SudoPassword(Some(SecretString::from(
        SUDO_PASSWORD,
    ))));
    wait_for(&f, KeyDecision::Once, |e| {
        matches!(e, EventKind::Sudo(sw_ssh::api::SudoMode::Password))
    });

    // Collector frames arrive as ready-to-draw events.
    wait_for(
        &f,
        KeyDecision::Once,
        |e| matches!(e, EventKind::Static(h) if h.hostname == "fake-vps"),
    );
    wait_for(
        &f,
        KeyDecision::Once,
        |e| matches!(e, EventKind::Mounts(m) if m.len() == 2),
    );
    wait_for(&f, KeyDecision::Once, |e| {
        matches!(e, EventKind::Processes(_))
    });
    host.tick();
    f.host.send(Command::Now(sw_core::Section::Cpu));
    let EventKind::Cpu(c) = wait_for(&f, KeyDecision::Once, |e| matches!(e, EventKind::Cpu(_)))
    else {
        unreachable!()
    };
    assert!((c.total - 33.3).abs() < 1.0, "{c:?}");
    // Status bar numbers: the collector counts as a channel and PONG gives an RTT.
    wait_for(
        &f,
        KeyDecision::Once,
        |e| matches!(e, EventKind::Link(l) if l.rtt_ms.is_some() && l.channels >= 1),
    );

    // Visibility: OFF stops a section at the collector.
    f.host.send(Command::SetSection {
        section: sw_core::Section::Who,
        on: false,
    });
    f.host
        .send(Command::SetServices(vec!["redis-server.service".into()]));
    let EventKind::Services(s) = wait_for(&f, KeyDecision::Once, |e| {
        matches!(e, EventKind::Services(_))
    }) else {
        unreachable!()
    };
    assert_eq!(s[0].id, "redis-server.service");

    // M3: once sudo works the collector restarts with privilege → root-only sections arrive.
    seen_or_wait(
        &f,
        |e| matches!(e, EventKind::Firewall(fw) if fw.backend == "ufw"),
    );
    seen_or_wait(&f, |e| matches!(e, EventKind::Jails(j) if !j.is_empty()));

    // Live service mode: the journal isn't readable as this user, so the watcher runs via
    // `sudo -S` with the held password, on its own channel.
    f.host.send(Command::SetServiceMode {
        mode: sw_core::config::ServiceMode::Live,
        poll_secs: 30,
    });
    wait_for(&f, KeyDecision::Once, |e| {
        matches!(
            e,
            EventKind::ServiceMode {
                live_watching: true
            }
        )
    });
    f.host.send(Command::SetServiceMode {
        mode: sw_core::config::ServiceMode::Poll,
        poll_secs: 30,
    });
    wait_for(&f, KeyDecision::Once, |e| {
        matches!(
            e,
            EventKind::ServiceMode {
                live_watching: false
            }
        )
    });

    // Unit picker list.
    f.host.send(Command::ListUnits);
    let EventKind::Units(u) = wait_for(&f, KeyDecision::Once, |e| matches!(e, EventKind::Units(_)))
    else {
        unreachable!()
    };
    assert_eq!(u.len(), 3);
    assert!(
        u.iter()
            .any(|x| x.name == "redis-server.service" && x.active == "failed")
    );
}
