//! In-process SSH server for tests and `examples/dev_sshd.rs`.
//!
//! A fake shell with a handful of commands — enough to exercise connect,
//! host keys, auth, PTY sizing, input echo, exit status and dropped
//! connections without a real Linux box. Keys are generated fresh per process
//! into a temp dir (no private keys live in the repo); credentials below are test-only.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use russh::keys::PublicKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub mod fakehost;

pub const USER: &str = "tester";
pub const PASSWORD: &str = "securewire-test";
pub const PASSPHRASE: &str = "test-passphrase";

/// Path of a generated test key: `test_host_ed25519`, `test_client_ed25519`,
/// `test_client_ed25519_enc` (passphrase [`PASSPHRASE`]), each with a `.pub`.
pub fn fixture(name: &str) -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(generate_keys).join(name)
}

fn generate_keys() -> PathBuf {
    use russh::keys::ssh_key::{Algorithm, LineEnding, PrivateKey};
    // dev_sshd sets SW_TEST_KEY_DIR to a stable dir so its host key survives restarts.
    let dir = std::env::var_os("SW_TEST_KEY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("securewire-test-keys-{}", std::process::id()))
        });
    std::fs::create_dir_all(&dir).expect("key dir");
    if dir.join("test_client_ed25519_enc.pub").exists() {
        return dir;
    }
    let mut rng = rand::rng();
    let write = |name: &str, key: &PrivateKey| {
        std::fs::write(
            dir.join(name),
            key.to_openssh(LineEnding::LF).expect("encode").as_bytes(),
        )
        .expect("write key");
        std::fs::write(
            dir.join(format!("{name}.pub")),
            key.public_key().to_openssh().expect("encode pub"),
        )
        .expect("write pub");
    };
    for name in ["test_host_ed25519", "test_client_ed25519"] {
        write(
            name,
            &PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("keygen"),
        );
    }
    let enc = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("keygen");
    let enc_pub = enc.public_key().clone();
    let enc = enc.encrypt(&mut rng, PASSPHRASE).expect("encrypt");
    std::fs::write(
        dir.join("test_client_ed25519_enc"),
        enc.to_openssh(LineEnding::LF).expect("encode").as_bytes(),
    )
    .expect("write key");
    std::fs::write(
        dir.join("test_client_ed25519_enc.pub"),
        enc_pub.to_openssh().expect("encode pub"),
    )
    .expect("write pub");
    dir
}

#[derive(Default)]
pub struct Observed {
    /// (cols, rows) from pty-req and window-change, in order.
    pub sizes: Vec<(u32, u32)>,
    pub sessions: usize,
}

pub struct TestServer {
    pub port: u16,
    pub observed: Arc<Mutex<Observed>>,
    pub host_key: PublicKey,
    /// Every process started by exec requests, killed (with descendants) on drop.
    all_pids: Arc<Mutex<Vec<u32>>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        for pid in self.all_pids.lock().unwrap().drain(..) {
            kill_tree(pid);
        }
    }
}

pub fn start() -> TestServer {
    start_with_host_key(&fixture("test_host_ed25519"))
}

pub fn start_with_host_key(path: &Path) -> TestServer {
    start_on(0, path)
}

/// Listen on 127.0.0.1:`port` (0 = any free port).
pub fn start_on(port: u16, path: &Path) -> TestServer {
    start_on_with(port, path, None)
}

/// Like [`start`], but `exec` requests run through a local bash in `env` (a [`fakehost::FakeHost`]).
pub fn start_with_exec(env: ExecEnv) -> TestServer {
    start_on_with(0, &fixture("test_host_ed25519"), Some(env))
}

#[derive(Clone)]
pub struct ExecEnv {
    pub bash: PathBuf,
    pub env: Vec<(String, String)>,
}

pub fn start_on_with(port: u16, path: &Path, exec: Option<ExecEnv>) -> TestServer {
    let exec = exec.map(Arc::new);
    let all_pids: Arc<Mutex<Vec<u32>>> = Arc::default();
    let all = all_pids.clone();
    let host = russh::keys::load_secret_key(path, None).expect("host key");
    let host_pub = host.public_key().clone();
    let client_keys: Vec<PublicKey> = ["test_client_ed25519.pub", "test_client_ed25519_enc.pub"]
        .iter()
        .map(|f| russh::keys::load_public_key(fixture(f)).expect("client pub"))
        .collect();
    let observed = Arc::new(Mutex::new(Observed::default()));
    let obs = observed.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let config = Arc::new(server::Config {
                keys: vec![host],
                auth_rejection_time: std::time::Duration::from_millis(10),
                auth_rejection_time_initial: Some(std::time::Duration::ZERO),
                ..Default::default()
            });
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .unwrap();
            tx.send(listener.local_addr().unwrap().port()).unwrap();
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                obs.lock().unwrap().sessions += 1;
                let pids = Arc::new(Mutex::new(Vec::new()));
                let h = Shell {
                    client_keys: client_keys.clone(),
                    obs: obs.clone(),
                    lines: HashMap::new(),
                    exec: exec.clone(),
                    stdins: HashMap::new(),
                    pids: pids.clone(),
                    all_pids: all.clone(),
                };
                let cfg = config.clone();
                tokio::spawn(async move {
                    if let Ok(s) = server::run_stream(cfg, sock, h).await {
                        let _ = s.await;
                    }
                    // Connection gone: kill everything it started (tail -F, journalctl -f, …),
                    // grandchildren included, so test processes never outlive the session.
                    for pid in pids.lock().unwrap().drain(..) {
                        kill_tree(pid);
                    }
                });
            }
        });
    });
    TestServer {
        port: rx.recv().unwrap(),
        observed,
        host_key: host_pub,
        all_pids,
    }
}

struct Shell {
    client_keys: Vec<PublicKey>,
    obs: Arc<Mutex<Observed>>,
    lines: HashMap<ChannelId, String>,
    exec: Option<Arc<ExecEnv>>,
    /// Exec channels: client data goes to the local process.
    stdins: HashMap<ChannelId, tokio::process::ChildStdin>,
    /// Processes started by exec requests on this connection.
    pids: Arc<Mutex<Vec<u32>>>,
    all_pids: Arc<Mutex<Vec<u32>>>,
}

const PROMPT: &[u8] = b"\x1b[32mtester@sw-test\x1b[0m:~$ ";

impl server::Handler for Shell {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == USER && password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(
            if user == USER
                && self
                    .client_keys
                    .iter()
                    .any(|k| k.key_data() == key.public_key.key_data())
            {
                Auth::Accept
            } else {
                Auth::reject()
            },
        )
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        _term: &str,
        cols: u32,
        rows: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.obs.lock().unwrap().sizes.push((cols, rows));
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        cols: u32,
        rows: u32,
        _pw: u32,
        _ph: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.obs.lock().unwrap().sizes.push((cols, rows));
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.lines.insert(channel, String::new());
        session.data(
            channel,
            b"Welcome to the SecureWire test server\r\n".to_vec(),
        )?;
        session.data(channel, PROMPT.to_vec())?;
        Ok(())
    }

    /// Run the command through a local bash in the fake-host environment, relaying
    /// stdin/stdout and the exit status — enough for probe, sudo check and collector.
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(exec) = self.exec.clone() else {
            session.close(channel)?;
            return Ok(());
        };
        let cmd = String::from_utf8_lossy(data).into_owned();
        let mut command = tokio::process::Command::new(&exec.bash);
        command
            .arg("-c")
            .arg(&cmd)
            .envs(exec.env.iter().cloned())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0); // so kill_tree can take the whole group
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(_) => {
                session.close(channel)?;
                return Ok(());
            }
        };
        if let Some(pid) = child.id() {
            self.pids.lock().unwrap().push(pid);
            self.all_pids.lock().unwrap().push(pid);
        }
        if let Some(stdin) = child.stdin.take() {
            self.stdins.insert(channel, stdin);
        }
        let mut stdout = child.stdout.take().expect("stdout");
        let handle = session.handle();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(n) = stdout.read(&mut buf).await {
                if n == 0 || handle.data(channel, buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
            let code = child
                .wait()
                .await
                .ok()
                .and_then(|s| s.code())
                .unwrap_or(255) as u32;
            let _ = handle.exit_status_request(channel, code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.stdins.remove(&channel); // dropping stdin = EOF for the process
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(stdin) = self.stdins.get_mut(&channel) {
            if stdin.write_all(data).await.is_err() {
                self.stdins.remove(&channel);
            }
            return Ok(());
        }
        for &b in data {
            let line = self.lines.entry(channel).or_default();
            match b {
                b'\r' | b'\n' => {
                    let cmd = std::mem::take(line);
                    session.data(channel, b"\r\n".to_vec())?;
                    let cmd = cmd.trim();
                    let out: String = match cmd {
                        "" => String::new(),
                        "whoami" => format!("{USER}\r\n"),
                        "stty size" => {
                            let (c, r) = self.obs.lock().unwrap().sizes.last().copied().unwrap_or((80, 24));
                            format!("{r} {c}\r\n")
                        }
                        "colors" => "\x1b[31mred\x1b[0m \x1b[1;32mbold-green\x1b[0m \x1b[7minverse\x1b[0m\r\n".into(),
                        "exit" => {
                            session.exit_status_request(channel, 0)?;
                            session.eof(channel)?;
                            session.close(channel)?;
                            return Ok(());
                        }
                        // Simulate the server dying: ending the session drops the TCP connection.
                        "crash" => return Err(russh::Error::Disconnect),
                        c if c.starts_with("echo ") => format!("{}\r\n", &c[5..]),
                        c => format!("sh: {c}: command not found\r\n"),
                    };
                    session.data(channel, out.into_bytes())?;
                    session.data(channel, PROMPT.to_vec())?;
                }
                0x7f => {
                    if line.pop().is_some() {
                        session.data(channel, b"\x08 \x08".to_vec())?;
                    }
                }
                0x03 => {
                    line.clear();
                    session.data(channel, b"^C\r\n".to_vec())?;
                    session.data(channel, PROMPT.to_vec())?;
                }
                0x20..=0x7e => {
                    line.push(b as char);
                    session.data(channel, vec![b])?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Kill a process and its descendants.
fn kill_tree(pid: u32) {
    #[cfg(windows)]
    let _ = std::process::Command::new("taskkill")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    #[cfg(not(windows))]
    {
        // Children were started in their own process group (see exec_request).
        let _ = std::process::Command::new("kill")
            .args(["-KILL", "--", &format!("-{pid}")])
            .status();
    }
}
