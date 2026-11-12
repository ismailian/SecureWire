//! Local SSH server with a fake shell, for trying the app without a VPS.
//!
//!     cargo run -p securewire-ssh --example dev_sshd [port]
//!
//! Connect SecureWire to 127.0.0.1:2222 as `tester` with password
//! `securewire-test`, or with the client key path printed at startup.
//! Shell commands: whoami, echo …, stty size, colors, exit, crash (drops the connection).
//! With a local bash available, exec requests (probe, sudo check, collector) run
//! against a fake host whose counters advance every 2 s, so the panels go live.
//! Sudo password: `sudo-pass`. Keys are test-only, kept in target/dev-sshd-keys.

#[path = "../tests/support/mod.rs"]
mod support;

use support::fakehost::{FakeHost, SUDO_PASSWORD};

fn main() {
    let port = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(2222);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/dev-sshd-keys");
    // SAFETY: set before any other thread exists.
    unsafe { std::env::set_var("SW_TEST_KEY_DIR", &dir) };
    let host = FakeHost::new("dev");
    let exec = host.as_ref().map(|h| support::ExecEnv {
        bash: h.bash().into(),
        env: h.env(),
    });
    let srv = support::start_on_with(port, &support::fixture("test_host_ed25519"), exec);
    println!("dev sshd listening on 127.0.0.1:{}", srv.port);
    println!("  user {} / password {}", support::USER, support::PASSWORD);
    println!(
        "  key  {}",
        support::fixture("test_client_ed25519").display()
    );
    match &host {
        Some(_) => println!("  live metrics: on (fake host) · sudo password {SUDO_PASSWORD}"),
        None => println!("  live metrics: off (no local bash found; set SW_TEST_BASH)"),
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
        if let Some(h) = &host {
            h.tick();
        }
    }
}
