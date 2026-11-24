<p align="center"><img src="packaging/icons/securewire-128.png" width="96" alt="SecureWire logo"></p>

# SecureWire

A desktop SSH workstation for people who look after their own Linux servers. It puts an interactive terminal in the middle, with live panels around it for the things you would otherwise type every time: `free -h`, `df -h`, `who`, `systemctl status`, `journalctl -u`, `ufw status`, `fail2ban-client status`…

Rust · egui · russh · alacritty_terminal. Windows, Linux and macOS clients; Linux servers.

**Website and docs:** https://securewire-app.pages.dev/

## What you get

- **Terminal tabs** (vi, htop, tmux…), each a channel on the host's single SSH connection.
- **System**: CPU, memory, disks (click a mount for its largest directories), network rates, listening ports, sessions.
- **Watch**:
  - services you choose, live (systemd pushes state changes) or polled;
  - firewall (ufw / nftables / iptables);
  - fail2ban jails and failed logins over 24 h;
  - timers and cron.
- **Logs**:
  - journal units and log files, found for you;
  - level and regex filters, follow;
  - resumes where it left off after a reconnect.
- **Traffic**: requests from nginx/apache access logs, top clients, status codes. Ban or unban an IP in one click.
- **Actions with confirmation**: restart / stop / reload services, kill processes, ban and unban IPs. The dialog shows the exact command first.
- **One-click tunnels**: right-click a service or a port to reach it from your computer (MySQL, Redis, a web dashboard). It listens on `127.0.0.1` only and uses the same SSH connection.
- **Command palette** (`Ctrl Shift P`), `~/.ssh/config` import, jump hosts (ProxyJump).
- **Files** (`Ctrl Shift E`): browse the server; copy, cut, paste, rename, delete and create folders there (plain `cp`/`mv`/`rm` as your login user). Upload by picking files, dropping them on the window or pasting files copied in Explorer; download the selection to a folder you pick. Transfers use SCP on the same SSH connection (the server needs the `scp` binary, which OpenSSH provides).
- **Updates**: on start SecureWire checks the website for a newer version. Download verifies the SHA-256 before the installer runs; set `SW_NO_UPDATE_CHECK=1` to turn the check off.

## What it does on your server

**Nothing is installed or written there.** On connect, a short probe and a small bash script are streamed over SSH and run from memory (`bash -s`). The script sends back plain text that the app parses. Everything runs over **one SSH connection per host**: terminal tabs, metrics, log tails, actions, file transfers and tunnels are channels on it.

Collection follows what you can see. Closed sections stop collecting, and an unfocused or minimized window slows collection down. On a small 2-vCPU VM the script costs about 0.3 % of one core with the default panels open, and monitoring traffic is under 1 KB/s.

## Security model

- **Host keys** are verified against `~/.ssh/known_hosts` and SecureWire's own known_hosts. A new key is shown for you to approve; a changed key is a hard stop.
- **Passwords are never stored.** The sudo password is asked once per session, kept only in memory, and reaches `sudo -S` only through a channel's stdin: never argv, the environment, logs or your terminal. With sudo, the monitoring script runs under a single `sudo` for the session, so your auth log isn't flooded.
- **Every remote command** is a fixed template with validated, quoted arguments. Anything that changes the server is confirmed first.
- **Remote text** (log lines, unit names, window titles) is treated as untrusted and stripped of control characters before it is drawn outside the terminal.

Details: [`design/collector-protocol.md`](design/collector-protocol.md) and [`design/decisions.md`](design/decisions.md).

### Sudo

Firewall, fail2ban, root-only logs and the service actions need root. SecureWire asks for your sudo password once per session and never stores it. Clicking "no sudo" in the status bar asks again.

You *can* let it in without a password by granting `NOPASSWD`. Be aware what that means: with sudo, the monitoring script runs as `sudo -n -- bash -s …`, so the rule has to allow `bash`, which amounts to full root without a password:

```
# /etc/sudoers.d/securewire — only if you accept passwordless root for this user
deploy ALL=(root) NOPASSWD: /usr/bin/bash
```

Entering the password per session is the safer default. Hosts where you log in as `root` need neither.

## Install

Download a package from the [releases](../../releases):

| System | Package |
|---|---|
| Windows 10/11 (x64) | `…-windows-x86_64-setup.exe` installer (per-user, no admin needed) or `…-portable.zip` |
| Linux (x86_64) | `.deb`, `.AppImage` or `.tar.gz` |
| macOS (Apple silicon) | `.dmg` (drag SecureWire to Applications) or `.tar.gz` |

The packages aren't code-signed yet. On Windows, SmartScreen may ask you to confirm ("More info" → "Run anyway"). On macOS, open the app the first time with right-click → Open. `SHA256SUMS` on the release page lets you check each download.

`securewire --version` prints the version; it is also in the window's top-left tooltip.

Or build from source with a stable Rust toolchain (1.90 or later):

```bash
cargo run --release -p securewire
```

On Linux, building needs `libxkbcommon-dev libwayland-dev libgl1-mesa-dev`.

Try it without a server: `cargo run -p securewire -- --demo`.

## Configuration

Saved hosts, watched services and log sources live in `hosts.toml`:
- Windows: `%APPDATA%\SecureWire\SecureWire\config`
- Linux: `~/.config/securewire`

Passwords never go into that file.

## License

MIT or Apache-2.0, at your option ([`LICENSE-MIT`](LICENSE-MIT), [`LICENSE-APACHE`](LICENSE-APACHE)). The bundled JetBrains Mono font is under the SIL Open Font License ([`crates/app/assets/fonts/OFL.txt`](crates/app/assets/fonts/OFL.txt)).

## Development

See [`CLAUDE.md`](CLAUDE.md) for the architecture, rules, commands and test strategy, and [`design/`](design/) for the UI spec, tokens and protocol. CI runs shellcheck, clippy and the tests on Linux and Windows, plus an end-to-end check against a real OpenSSH server with sudo.
