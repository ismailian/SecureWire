# SecureWire

A desktop SSH workstation for people who look after their own Linux servers (VPS, small fleets). IDE-style window: an interactive terminal in the middle, surrounded by live panels for resources, network, sessions, services, firewall, security and logs — the things you would otherwise type `free -h`, `df -h`, `who`, `systemctl status`, `journalctl -u`, `ufw status` … for, every single time.

**Stack:** Rust · egui/eframe · russh · tokio · alacritty_terminal
**Status:** **v1.0.0** — M0–M6 done (2026-11-16). M6 added the logo, version info, bundled JetBrains Mono, CI (Linux, Windows, real sshd + sudo) and release packages: Windows Inno Setup installer + portable zip, Linux .deb / AppImage / tar.gz, macOS .dmg / tar.gz (D-035). The collector CPU budget is now 0.5 % of one core (D-034). M5 brought actions with confirmation, the command palette, `~/.ssh/config` import, ProxyJump, tunnels, the sockets table, the Traffic tab and IP menus; the collector runs under one sudo per session (D-029).

Measurements (release, Windows, window focused): M0 demo host — idle CPU 0.3 % of one core, private memory 36 MB, binary 7.3 MB. M1 live SSH connection + 1 terminal — idle CPU 0.26 %, private memory 66 MB, binary 10.6 MB. M2 live collector at 2 s tiers — idle CPU 0.78 %, private memory 48 MB, monitoring traffic ~330 B/s, binary 10.7 MB. M5 real host (2-vCPU VM): collector 0.28 % of one core in steady state with Live services, 0.47 % with 10 s polling (within the revised 0.5 % budget, D-034; the 2 s fast tier alone is 0.23 %, protocol §14), monitoring traffic ~640 B/s, RTT 1–2 ms. Client (release, M6 pass): idle CPU 0.70 % focused on that host (~1 repaint/s), private memory 50 MB, first window 151 ms, `--bench-ui` p99 1.92 ms, binary 11.5 MB.

---

## 1. Read these first

| Need to… | Read |
|---|---|
| See what the app looks like | `design/prototype/index.html` (open in a browser) |
| Build or change any UI | `design/ui-spec.md`, `design/design-tokens.md` |
| Touch SSH, the collector, logs or actions | `design/collector-protocol.md` |
| Understand why something is the way it is | `design/decisions.md` |

`design/ui-spec.md` is authoritative over the prototype. `design/collector-protocol.md` is authoritative over the code for anything on the wire. Update the design doc in the same change as the code.

## 2. Non-negotiables

1. **One SSH connection per host.** Terminal tabs, collector, log tails and one-shot actions are *channels* on that connection. Never open a second TCP connection or shell out to `ssh`.
2. **Nothing installed or written on the server.** The collector is a bash script streamed on the stdin of `exec bash -s …`; after the script's last line, the same stdin is the control channel (D-022).
3. **Pay only for what is visible.** Collapsed sections, hidden panels, unfocused/minimized windows and inactive host tabs reduce or stop collection (protocol §5). Every new section must support `ON`/`OFF`/`NOW`.
4. **The UI thread never blocks and never parses.** No I/O, no locks held across await points, no regex compilation, no allocation-heavy work in `update()`. Data arrives as ready-to-draw structs.
5. **No continuous repaint.** eframe runs reactive. Repaints come from input, from the net thread (`request_repaint`, throttled), and from a 1 s `request_repaint_after` only while collector data is stale. The terminal cursor does not blink (D-019).
6. **Security:** verify host keys (TOFU dialog, hard stop on mismatch); never store passwords on disk; the sudo password is asked once per host session, held only in memory (`secrecy`), and reaches `sudo -S` only via channel stdin — never argv, env, logs or the user's terminal (protocol §9, D-017); validate every identifier and quote every argument that goes into a remote command; treat all remote text (logs, unit names, window titles) as untrusted data — strip control characters before drawing outside the terminal.
7. **Destructive actions show the exact command and ask first.** Restart/stop service, kill, ban IP, anything that writes.

## 3. Architecture

```
┌──────────────────────── UI thread (eframe, glow) ────────────────────────┐
│ App ─ HostTabs ─ per host: HostView { panels, ring buffers, log store }   │
│   ▲ drain Event channel each frame          │ Command (connect, ON/OFF,  │
│   │                                         ▼ NOW, SVC, action, input)    │
├───┴────────────── net thread: tokio current_thread runtime ───────────────┤
│ HostActor (one per host)                                                  │
│   ├─ russh client::Handle  ── one TCP connection                          │
│   ├─ PtyChannel ×n   bytes → alacritty_terminal::Term (Arc<FairMutex>)   │
│   ├─ CollectorChannel  frames → core::parse → Snapshot events            │
│   ├─ LogChannel ×≤3    lines  → core::logs::LogLine events               │
│   └─ ActionRunner      transient exec channels                            │
└───────────────────────────────────────────────────────────────────────────┘
```

- **Threads:** we create two — main (UI) and one net thread running a current-thread tokio runtime for every host (D-016). The process shows ~15 OS threads, the rest belonging to winit, the GL driver and Windows.
- **UI → net:** `tokio::sync::mpsc::UnboundedSender<Command>` (tagged with `HostId`).
- **net → UI:** `std::sync::mpsc::Sender<Event>`; after sending, the actor calls a throttled repaint (≤ 1 per 50 ms for metrics/logs; immediate for terminal output and user-initiated results).
- **Terminal grid** is the only shared state: the net thread feeds bytes into `Term`, the UI locks it briefly to render. Everything else is message passing.
- **Rates and percentages** are computed in the actor from consecutive raw snapshots (using the remote `/proc/uptime` delta) so the UI receives final numbers.
- **Alerts** are evaluated in the actor after each snapshot (pure function in `core::alerts`), sent as `Event::Alerts(Vec<Alert>)` only when they change.

### Connection lifecycle
`Probe` (one exec, capabilities) → open PTY #1 → open collector → open log channels → steady state. Keepalive 15 s; on loss: dim UI, backoff reconnect (1→30 s), reopen channels, resume journal by `__CURSOR`. Details: protocol §1, §4.

## 4. Workspace layout

```
Cargo.toml                 # workspace, shared deps + profiles (see §8)
.cargo/config.toml         # rust-lld on Windows MSVC
crates/
  core/  securewire-core (lib sw_core) — pure logic, no I/O, no egui; most tests live here
    src/frame.rs           # collector frame decoder (RS-delimited, incremental) + encode() for demo/tests
    src/parse/             # proc (cpu/meminfo/net_dev/diskstats), df, who, ps, systemctl   [M3: ss, ufw, nft, fail2ban]
    src/metrics.rs         # RingBuffer, Cpu/Net/DiskIo trackers (rates from the remote uptime delta)
    src/model.rs           # ready-to-draw types: CpuSample, MemSample, Mount, ServiceInfo, Process …
    src/logs.rs            # Level, LogLine, presets, detect_level(), sanitize()
    src/alerts.rs          # threshold rules → Vec<Alert>
    src/shell.rs           # shell_quote(), is_valid_unit(), is_valid_path()
    src/actions.rs         # server actions (protocol §7): fixed templates + validated args → exact command
    src/fuzzy.rs           # palette fuzzy match
    src/format.rs          # bytes / rate / duration formatting rules
    src/parse/probe.rs     # probe.sh key=value output → Probe
    src/config.rs          # hosts.toml types (HostConfig, HostsFile) — no I/O; ~/.ssh/config import, ProxyJump parsing
  ssh/   securewire-ssh (lib sw_ssh) — net side
    src/api.rs             # Command / Event / EventKind / SudoMode / Throttle: the UI↔net contract
    src/pipeline.rs        # Frame → EventKind (trackers, alerts); shared by the demo and the real actor
    src/demo.rs            # fake server: byte-exact collector output through the real decoder + pipeline
    src/collector.rs       # embedded collector.sh / probe.sh, launch command, control-line builders
    src/remote.rs          # exec channels: run_probe, verify_sudo, start_collector (reader + 30 ms packet coalescing), log channels (+ access-log parsing), run_exec
    src/tunnel.rs          # one-click tunnels: 127.0.0.1 listener → direct-tcpip on the same connection (protocol §13)
    src/actor.rs           # russh HostActor: connect, host-key TOFU, auth, PTY channels, keepalive, reconnect
    src/handle.rs          # HostHandle / CmdTx (same handle for demo and real hosts)
    src/lib.rs             # Net: the net thread + Net::connect()
    tests/connect.rs       # end-to-end tests of the real actor against tests/support (in-process russh server)
    tests/collector.rs     # the real collector.sh under local bash vs a fake host (fake /proc + stub commands)
    tests/support/fakehost.rs  # that fake host; the test SSH server runs exec requests inside it
                           # test keys are generated per run (temp dir); no private keys in the repo
    examples/dev_sshd.rs   # the same fake server on 127.0.0.1:2222 for manual GUI testing
    examples/real_host.rs  # drive the real actor against a real server (SW_REAL=user@host SW_REAL_PASS=…; SW_REAL_PROFILE / SW_REAL_STEADY = server CPU per section)
  app/   securewire (bin) — eframe App
    src/main.rs, app.rs    # NativeOptions (glow), event drain, panel order, section ON/OFF diffing, focus throttle
    src/theme.rs           # tokens + Visuals + fonts — the only place colors are constructed
    src/state.rs           # HostView (data, ring buffers, LogStore), HostUi (open sections, LogFilter)
    src/store.rs           # config dir: hosts.toml load/save (atomic), SecureWire known_hosts path
    src/dialogs.rs         # Connect, Host key (TOFU / changed), Auth retry, Sudo, service picker, log sources, Confirm action, action output, Listening sockets
    src/palette.rs         # command palette (Ctrl Shift P): fuzzy items, parameter prompts → Request
    src/widgets.rs         # section, sparkline, bar, badge, dot, switch, icon_button, toggle_chip
    src/panels/            # topbar, status, system (left), watch (right), dock (bottom), terminal (central)
  term/  securewire-term (lib sw_term) — Terminal (alacritty_terminal + VT parser behind a FairMutex),
                           # TerminalView egui widget (renderer, keys, mouse, selection, clipboard), input.rs (xterm key encoding)
collector/             # collector.sh (bash), probe.sh (POSIX sh) — embedded with include_str!; collector ends with `main "$@"`
packaging/                 # icons/ (securewire.svg + small variant → PNGs + .ico, committed), securewire.desktop, windows/ (Inno Setup .iss + build-installer.ps1), macos/Info.plist
LICENSE-MIT, LICENSE-APACHE
design/                    # see §1
```

Never name a package `core` (it shadows Rust's `core`): packages are `securewire-*`, libs are `sw_*`.

Dependency direction: `app → ssh → core`, `app → term`, `ssh → term` (feeds `Term`). `core` depends only on `memchr`, `serde` and `toml`; keep it that light (`serde_json` joins for journal JSON).

### Pinned crates
| Crate | Version | Notes |
|---|---|---|
| `eframe` / `egui` | **0.36** | Held at 0.36 because `egui-phosphor 0.14` depends on egui 0.36. Never allow two egui versions (`cargo tree -i egui`). eframe features: `glow`, `default_fonts`, `persistence`, `x11`, `wayland`, `accesskit` — no wgpu. |
| `egui-phosphor` | 0.14 | `regular` variant only |
| `regex-lite` | 0.1 | log filter |
| `memchr` | 2 | frame decoder |
| `russh` | 0.65 | default features off, `ring` + `flate2` + `rsa` — the default `aws-lc-rs` backend needs cmake/NASM on Windows |
| `tokio` | 1 | `rt`, `net`, `sync`, `time`, `macros`, `io-util` — current-thread runtime only |
| `alacritty_terminal` | 0.26 | emulator + `vte` parser |
| `parking_lot` | **0.12** | must match alacritty_terminal (its `FairMutex` hands out parking_lot 0.12 guards) |
| `secrecy` | 0.10 | passwords / passphrases in memory |
| `directories` | 6 | config dir |
| `serde` + `toml` | 1 / 1 | hosts.toml |

egui 0.36 API (differs from most examples online): `eframe::App::ui(&mut self, ui: &mut Ui, frame)` instead of `update(ctx, …)`; panels are `egui::Panel::{top,bottom,left,right}(id)` with `.exact_size / .default_size / .size_range` and `.show(ui, …)`; `CentralPanel::no_frame()`; `Margin` fields are `i8`; `rect_stroke` takes a `StrokeKind`; `NativeOptions` has no `vsync` field.

Planned, added in their milestone: `serde_json` (journal), `ssh2-config` (import `~/.ssh/config`), `tracing` + `tracing-subscriber`, `anyhow` (app) / `thiserror` (libs), `keyring` (optional, off by default).

Add a dependency only when it removes real code; prefer std. Check `cargo tree -d` for duplicates after adding one.

## 5. UI implementation rules

- Panel construction order and sizes: `design/ui-spec.md §2` (top → status → left → right → bottom dock → central).
- Colors only from `theme.rs` (`tok::*`), which mirrors `design/design-tokens.md`. No `Color32::from_rgb` outside it.
- Long lists (logs, processes, connections, unit picker) use `ScrollArea::show_rows` — never lay out invisible rows.
- Sparklines and bars: draw with `Painter` (`line_segment`/`Shape::line`/`rect_filled`) from `RingBuffer<f32>`; no plotting crate.
- Cache text layout: terminal rows and log rows keep their `Galley` until content or width changes.
- Every section reports visibility changes (expanded/collapsed, panel shown/hidden) to its `HostActor` → `ON`/`OFF`.
- Every displayed value carries its sample time; headers show age in amber when older than 3 × tier.
- Numbers: binary units for sizes (KiB/MiB/GiB), decimal per second for rates (KB/s, MB/s), one decimal max, mono font where columns must align.
- Keyboard: app shortcuts are only those in `ui-spec.md §6`; everything else goes to the focused terminal.

## 6. Performance budgets (check before merging anything in the hot path)

| Metric | Budget |
|---|---|
| Idle CPU, 1 host, focused, default tiers | < 1 % of one core |
| Idle CPU, unfocused | < 0.2 % |
| RSS, 1 host, 10k log lines, 1 terminal | < 80 MB |
| Frame time (UI) with log stream at 50 lines/s | < 4 ms |
| Cold start to first frame | < 300 ms |
| Monitoring traffic | < 1 KB/s per host |
| Server-side collector CPU | < 0.5 % of one core, steady state, default sections (D-034) |
| Release binary | < 15 MB |

Memory caps: log store per host bounded (default 10k lines, configurable 2k–50k); metric history 30 min per series (`RingBuffer<f32>`, 900 points); terminal scrollback 10k lines.

## 7. Configuration & persistence

Location via `directories::ProjectDirs::from("dev", "SecureWire", "SecureWire")` (Windows: `%APPDATA%\SecureWire\SecureWire\config`, Linux: `~/.config/securewire`).

- `settings.toml` — theme/scale, fonts, default tiers, alert thresholds, terminal options, keybindings.
- `hosts.toml` — saved hosts and per-host watch config:

```toml
[[host]]
name = "prod-web-01"
address = "203.0.113.10"
port = 22
user = "root"
auth = "agent"            # agent | key | password (password is prompted, never stored)
key_path = ""             # for auth = "key"
jump = ""                 # optional host name from this file or ~/.ssh/config

[host.services]
mode = "live"             # live | poll | manual
poll_secs = 30
units = ["nginx.service", "mysql.service", "php8.3-fpm.service", "fail2ban.service", "redis-server.service", "certbot.timer"]

[[host.logs]]
id = "nginx"
kind = "journal"          # journal | file | sudo-file
target = "nginx.service"
color = 0                 # index into the categorical palette

[[host.logs]]
id = "nginx-error"
kind = "file"
target = "/var/log/nginx/error.log"
preset = "nginx"          # level-detection preset
```
- UI layout state (panel sizes/visibility, collapsed sections, active tabs, log filters) — eframe persistence, keyed per host name.
- Known hosts: read `~/.ssh/known_hosts`; write new trusted keys to our own `known_hosts` in the config dir (never modify the user's OpenSSH file).

## 8. Build & tooling

Required build settings (user preference — keep them):

```toml
# Cargo.toml (workspace)
[profile.dev]
debug = "line-tables-only"

[profile.dev.package."*"]
debug = false
opt-level = 2          # deps optimized: egui/alacritty are slow unoptimized; keep our own crates at 0

[profile.dev.build-override]
debug = false

[profile.release]
lto = "thin"
codegen-units = 1
strip = true
panic = "abort"
```
- Each library crate: `[lib] doctest = false` unless it has doc examples meant as tests.
- `.cargo/config.toml`:
  ```toml
  [target.x86_64-pc-windows-msvc]
  linker = "rust-lld"
  ```
- Use `debug = true` locally only when a debugger is needed; don't commit it.
- After changing build settings, confirm a build still links and say so.

Commands
```bash
cargo run -p securewire                       # app
cargo run -p securewire -- --demo             # app fed by recorded collector frames, no server needed
cargo test --workspace                        # unit + fixture tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
shellcheck -s bash collector/collector.sh collector/discover.sh && shellcheck -s sh collector/probe.sh   # runs in CI (not installed on the dev machine)
cargo test -p securewire-ssh --test collector  # collector.sh under local bash (Git Bash on Windows; SW_TEST_BASH overrides)
SW_FRAME_STATS=frames.txt cargo run --release -p securewire   # append repaints-per-10s to a file (perf checks)
cargo run -p securewire -- --connect user@host[:port] [--key PATH]   # pre-filled Connect dialog
cargo run -p securewire-ssh --example dev_sshd # local fake SSH server: 127.0.0.1:2222, tester / securewire-test
cargo test -p securewire-ssh --test connect   # real actor vs in-process server (no Docker, no VPS)
SW_REAL=user@host SW_REAL_PASS=… cargo run -p securewire-ssh --example real_host   # check against a real server (add SW_REAL_STEADY=1 for per-section server CPU)
```

## 9. Testing strategy

- **Parsers (`core`)**: table-driven tests over `tests/fixtures/<distro>/` captured from real machines, including edge cases (many cores, no swap, IPv6-only, `ufw inactive`, `fail2ban` not installed, unit names with `@`, non-UTF-8 log bytes).
- **Frame decoder**: fuzz-style tests for partial reads, frames split across packets, missing `END`, `SAME`, `ERR`.
- **Collector script**: runs for real under a local bash against a fake host (`tests/collector.rs`): every section parses, rates are right, OFF/NOW/TIER/SVC/PING/QUIT, garbage and injection attempts ignored, EOF ends it, missing `/proc` files give `ERR`. A unit test asserts the script ends with the `main` call. shellcheck runs in CI.
- **CI** (`.github/workflows/ci.yml`): Linux (shellcheck, fmt, clippy, tests with real bash + /proc), Windows (tests under Git Bash), and **real-sshd**: OpenSSH + a password user in the sudo group on the runner, then `examples/real_host.rs` with `SW_REAL_STRICT=1` (probe, sudo, every section, logs, actions, PTY must all work).
- **Release** (`.github/workflows/release.yml`): tag `v*` (must equal the Cargo.toml version) → Windows Inno Setup installer + portable zip, Linux tar.gz + .deb (`cargo deb`) + AppImage, macOS .dmg (ad-hoc signed `SecureWire.app`) + tar.gz, SHA256SUMS, attached to a **draft** release. "Run workflow" builds the same packages as artifacts without a release. Locally: `cargo build --release -p securewire` then `packaging/windows/build-installer.ps1` → `dist/`.
- **Command building**: every action template tested with hostile inputs (spaces, quotes, `;`, `$()`, newlines) — must be rejected or safely quoted.
- **Demo mode** (`--demo`) replays recorded frames and log lines; use it for UI work and screenshots instead of a live server.
- **Perf**: `securewire --bench-ui[=report.txt]` runs the demo host at 50 log lines/s for 20 s, writes frame-time percentiles and exits (window must be visible). `SW_FRAME_STATS=<file>` logs repaints per 10 s.

## 10. Conventions

- Rust 2024 edition, stable toolchain. `clippy -D warnings` clean.
- Errors: `thiserror` enums in libraries, `anyhow` only in `app`. User-facing errors are short and say what to do ("needs sudo — see Settings › Privileges").
- Logging: `tracing`; never log secrets, key material or full command output at info level.
- No `unwrap()`/`expect()` on anything derived from remote data.
- Remote command strings are built only through `core::shell` helpers (`shell_quote`, validators); grep for `format!(` near `exec` in review.
- Keep the collector script small and readable; any new section adds: script function, frame parser, fixture, UI section, visibility wiring, design-doc row.

## 11. Milestones

| | Scope | Done when |
|---|---|---|
| **M0** ✅ | Workspace scaffold, build settings, theme + icons, full panel layout with demo data through the real decoder/parsers | Done 2026-11-12. JetBrains Mono embedded in M6; Inter still open (egui default proportional font in use) |
| **M1** ✅ | Connect dialog, known_hosts/TOFU, agent + key + password auth, PTY tabs with `alacritty_terminal` renderer, resize, copy/paste, reconnect | Done 2026-11-12 against the in-process test server (7 end-to-end tests + GUI check). **Open:** tmux on a real host (vi + htop verified on a VM in M5); ssh-agent path untested (agent service disabled on dev machine) |
| **M2** ✅ | Probe + sudo password flow (protocol §9) + collector (static, cpu, mem, net, dio, df, who, ps), SYSTEM panel live, focus/visibility throttling (inactive host tabs run Hidden), status bar | Done 2026-11-12 against a fake host (3 collector tests + full SSH e2e test + GUI check). **Open:** real-VPS check of §8 targets; sh fallback for hosts without bash; shellcheck |
| **M3** ✅ | WATCH panel: services (picker dialog, Live/Poll/Manual), firewall, security, scheduled | Done 2026-11-12: 6 collector tests (incl. sudo password / wrong password / no sudo), SSH e2e covers collector restart with privilege, Live watcher via `sudo -S`, unit list. **Open:** "failure within 1 s" needs a real systemd host to measure |
| **M4** ✅ | Logs: discovery dialog, journal + file + sudo-file channels, filters, regex, follow, Alerts tab | Done 2026-11-13: `--bench-ui` p99 1.82 ms at 50 lines/s; SSH e2e test streams journal + file lines and discovers sources; discovery tested in both privilege modes |
| **M5** ✅ | Multi-host tabs, command palette with parameter prompts, actions with confirmation, Processes/Connections tabs, `~/.ssh/config` import, jump hosts; added on request: tunnels, sockets table, Traffic tab, IP actions | Done 2026-11-16: 11 SSH e2e tests (jump host, actions via sudo, tunnel), real-VM check (`examples/real_host.rs`) + GUI check. **Open:** "daily driver for 3 hosts" needs the user's own use; collector CPU above budget (M6) |
| **M6** ✅ | Perf pass, packaging, sudoers snippet docs, logo, versioning | Done 2026-11-16 as **v1.0.0**: budgets in §6 verified on a real host (collector 0.28–0.47 % under the revised 0.5 % budget, D-034; client idle 0.70 %, 50 MB, first window 151 ms, frame p99 1.92 ms); CI (Linux, Windows, real sshd + sudo); release workflow with Inno Setup installer, .deb, AppImage, .dmg (D-035); README with sudo notes; logo + exe icon + version (`--version`, top-bar tooltip, welcome screen); JetBrains Mono bundled. **Open:** Inter not embedded (needs the font files); packages not code-signed; ssh-agent auth and tmux untested on a real host |

Out of scope for v1: editing firewall rules, file manager/SFTP, port forwarding UI, Windows/BSD servers, light theme, user-arranged docking.
