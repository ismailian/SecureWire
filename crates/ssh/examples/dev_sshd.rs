//! Local SSH server with a fake shell, for trying the app without a VPS.
//!
//!     cargo run -p securewire-ssh --example dev_sshd [port]
//!
//! Connect SecureWire to 127.0.0.1:2222 as `tester` with password
//! `securewire-test`, or with the client key path printed at startup.
//! Commands: whoami, echo …, stty size, colors, exit, crash (drops the connection).
//! Keys are test-only and kept in target/dev-sshd-keys (git-ignored).

#[path = "../tests/support/mod.rs"]
mod support;

fn main() {
    let port = std::env::args()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(2222);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/dev-sshd-keys");
    // SAFETY: set before any other thread exists.
    unsafe { std::env::set_var("SW_TEST_KEY_DIR", &dir) };
    let srv = support::start_on(port, &support::fixture("test_host_ed25519"));
    println!("dev sshd listening on 127.0.0.1:{}", srv.port);
    println!("  user {} / password {}", support::USER, support::PASSWORD);
    println!(
        "  key  {}",
        support::fixture("test_client_ed25519").display()
    );
    loop {
        std::thread::park();
    }
}
