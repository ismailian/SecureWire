//! Check the Files tab's channels (protocol §15) against a real server:
//!
//!   SW_REAL=user@host[:port]  [SW_REAL_KEY=~/.ssh/id_ed25519 | SW_REAL_PASS=…]
//!   cargo run -p securewire-ssh --example files_real
//!
//! Lists the home folder, uploads a small tree plus a 32 MiB file over SCP, downloads it
//! back and compares byte for byte, then copies, renames and deletes on the server.
//! Everything happens in `~/securewire-files-test-<pid>`, removed at the end.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use secrecy::SecretString;
use sw_core::actions::Action;
use sw_core::files::{FsOp, Pair};
use sw_ssh::api::{
    AuthSpec, Command, ConnectSpec, DownloadItem, EventKind, KeyDecision, KnownHosts, TransferSpec,
    TransferState,
};
use sw_ssh::{Event, Net};

fn wait(
    rx: &Receiver<Event>,
    h: &sw_ssh::HostHandle,
    mut pred: impl FnMut(&EventKind) -> bool,
) -> EventKind {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let ev = rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("timed out")
            .kind;
        match &ev {
            EventKind::HostKeyPrompt { .. } => h.send(Command::HostKey(KeyDecision::Once)),
            EventKind::SudoPrompt { .. } => h.send(Command::SudoPassword(None)),
            EventKind::AuthFailed(m) | EventKind::Error(m) => eprintln!("! {m}"),
            _ => {}
        }
        if pred(&ev) {
            return ev;
        }
    }
}

fn main() {
    let target = std::env::var("SW_REAL").expect("set SW_REAL=user@host[:port]");
    let (user, rest) = target.split_once('@').expect("user@host");
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), p.parse().unwrap()),
        None => (rest.to_owned(), 22),
    };
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap();
    let auth = match std::env::var("SW_REAL_PASS") {
        Ok(p) => AuthSpec::Password(SecretString::from(p)),
        Err(_) => AuthSpec::KeyFile {
            path: std::env::var("SW_REAL_KEY")
                .map(Into::into)
                .unwrap_or_else(|_| std::path::Path::new(&home).join(".ssh").join("id_ed25519")),
            passphrase: None,
        },
    };
    let tmp = std::env::temp_dir().join(format!("sw-files-real-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let net = Net::start().unwrap();
    let (tx, rx) = channel();
    let h = net.connect(
        1,
        ConnectSpec {
            name: "real".into(),
            address: host,
            port,
            user: user.into(),
            auth,
            known_hosts: KnownHosts {
                user_file: Some(std::path::Path::new(&home).join(".ssh").join("known_hosts")),
                app_file: tmp.join("known_hosts"),
            },
            jump: None,
            connect_timeout: ConnectSpec::DEFAULT_TIMEOUT,
        },
        tx,
        Arc::new(|| {}),
    );
    wait(&rx, &h, |e| matches!(e, EventKind::Connected(_)));
    println!("connected");

    let list = |id: u64, path: &str| {
        h.send(Command::FsList {
            id,
            path: path.into(),
        });
        let EventKind::FsListing { result, .. } = wait(
            &rx,
            &h,
            |e| matches!(e, EventKind::FsListing { id: i, .. } if *i == id),
        ) else {
            unreachable!()
        };
        result
    };
    let t = Instant::now();
    let home_l = list(1, "").expect("home listing");
    println!(
        "home {} — {} entries in {:?} (e.g. {:?})",
        home_l.path,
        home_l.entries.len(),
        t.elapsed(),
        home_l
            .entries
            .iter()
            .take(4)
            .map(|e| &e.name)
            .collect::<Vec<_>>()
    );
    let root = list(2, "/").expect("/ listing");
    println!(
        "/ — {} entries, dirs: {}",
        root.entries.len(),
        root.entries.iter().filter(|e| e.is_dir).count()
    );
    println!("/root as user → {:?}", list(3, "/root").err());

    let dir = format!(
        "{}/securewire-files-test-{}",
        home_l.path,
        std::process::id()
    );
    let run = |id: u64, op: FsOp| {
        h.send(Command::RunAction {
            id,
            action: Action::Files(op),
        });
        let EventKind::ActionResult { ok, output, .. } = wait(
            &rx,
            &h,
            |e| matches!(e, EventKind::ActionResult { id: i, .. } if *i == id),
        ) else {
            unreachable!()
        };
        assert!(ok, "{output}");
    };
    run(10, FsOp::Mkdir(dir.clone()));

    // Local tree: odd-sized file, a 32 MiB file, a folder with a quote and a space in its name.
    let up = tmp.join("up");
    std::fs::create_dir_all(up.join("it's a dir")).unwrap();
    let small: Vec<u8> = (0..70_001u32).map(|i| (i % 253) as u8).collect();
    let big: Vec<u8> = (0..32u32 * 1024 * 1024)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    std::fs::write(up.join("small.bin"), &small).unwrap();
    std::fs::write(up.join("big.bin"), &big).unwrap();
    std::fs::write(up.join("it's a dir").join("$(touch x).txt"), b"not run\n").unwrap();

    let transfer = |id: u64, spec: TransferSpec| {
        let t = Instant::now();
        h.send(Command::Transfer { id, spec });
        let ev = wait(
            &rx,
            &h,
            |e| matches!(e, EventKind::Transfer { id: i, progress } if *i == id && progress.state != TransferState::Running),
        );
        let EventKind::Transfer { progress, .. } = ev else {
            unreachable!()
        };
        let secs = t.elapsed().as_secs_f64();
        println!(
            "transfer {id}: {:?} — {} files, {} bytes in {secs:.2}s ({:.1} MB/s)",
            progress.state,
            progress.files,
            progress.bytes,
            progress.bytes as f64 / secs / 1e6
        );
        assert_eq!(progress.state, TransferState::Done);
    };
    transfer(
        20,
        TransferSpec::Upload {
            items: vec![
                (up.join("small.bin"), "small.bin".into()),
                (up.join("big.bin"), "big.bin".into()),
                (up.join("it's a dir"), "it's a dir".into()),
            ],
            remote_dir: dir.clone(),
        },
    );
    let l = list(21, &dir).unwrap();
    println!(
        "uploaded: {:?}",
        l.entries
            .iter()
            .map(|e| (&e.name, e.size))
            .collect::<Vec<_>>()
    );

    run(
        30,
        FsOp::Copy(vec![Pair {
            src: format!("{dir}/it's a dir"),
            dst: format!("{dir}/copy"),
            replace: false,
        }]),
    );
    run(
        31,
        FsOp::Rename {
            from: format!("{dir}/small.bin"),
            to: format!("{dir}/small2.bin"),
        },
    );

    let down = tmp.join("down");
    std::fs::create_dir_all(&down).unwrap();
    transfer(
        40,
        TransferSpec::Download {
            items: vec![
                DownloadItem {
                    remote: format!("{dir}/small2.bin"),
                    local_name: "small.bin".into(),
                    is_dir: false,
                    size: 70_001,
                },
                DownloadItem {
                    remote: format!("{dir}/big.bin"),
                    local_name: "big.bin".into(),
                    is_dir: false,
                    size: big.len() as u64,
                },
                DownloadItem {
                    remote: format!("{dir}/copy"),
                    local_name: "copy (copy)".into(),
                    is_dir: true,
                    size: 0,
                },
            ],
            local_dir: down.clone(),
        },
    );
    assert_eq!(std::fs::read(down.join("small.bin")).unwrap(), small);
    assert_eq!(std::fs::read(down.join("big.bin")).unwrap(), big);
    assert_eq!(
        std::fs::read(down.join("copy (copy)").join("$(touch x).txt")).unwrap(),
        b"not run\n"
    );
    println!("downloads match byte for byte");

    // Cancel mid-way: the partial local file is removed.
    h.send(Command::Transfer {
        id: 50,
        spec: TransferSpec::Download {
            items: vec![DownloadItem {
                remote: format!("{dir}/big.bin"),
                local_name: "partial.bin".into(),
                is_dir: false,
                size: big.len() as u64,
            }],
            local_dir: down.clone(),
        },
    });
    wait(
        &rx,
        &h,
        |e| matches!(e, EventKind::Transfer { id: 50, progress } if progress.bytes > 0),
    );
    h.send(Command::CancelTransfer(50));
    let ev = wait(
        &rx,
        &h,
        |e| matches!(e, EventKind::Transfer { id: 50, progress } if progress.state != TransferState::Running),
    );
    println!("cancel → {ev:?}");
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !down.join("partial.bin").exists(),
        "partial file left behind"
    );

    run(60, FsOp::Delete(vec![dir.clone()]));
    assert!(list(61, &dir).is_err());
    println!("cleaned up {dir}");
    let _ = std::fs::remove_dir_all(&tmp);
    println!("ALL OK");
}
