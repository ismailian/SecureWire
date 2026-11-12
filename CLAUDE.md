# SecureWire

A desktop SSH workstation for people who look after their own Linux servers (VPS, small fleets). IDE-style window: an interactive terminal in the middle, surrounded by live panels for resources, network, sessions, services, firewall, security and logs — the things you would otherwise type `free -h`, `df -h`, `who`, `systemctl status`, `journalctl -u`, `ufw status` … for, every single time.

**Stack:** Rust · egui/eframe · russh · tokio · alacritty_terminal
**Status:** M0 done (2026-11-12) — workspace, theme, full panel layout driven by the demo source through the real frame decoder and parsers. No SSH yet. Next: M1 (connect + terminal).

M0 measurements (release, Windows, demo host, window focused): idle CPU 0.3 % of one core · private memory 36 MB · binary 7.3 MB.

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
2. **Nothing installed or written on the server.** The collector is a bash script passed as the exec command. Its stdin is the control channel.
3. **Pay only for what is visible.** Collapsed sections, hidden panels, unfocused/minimized windows and inactive host tabs reduce or stop collection (protocol §5). Every new section must support `ON`/`OFF`/`NOW`.
4. **The UI thread never blocks and never parses.** No I/O, no locks held across await points, no regex compilation, no allocation-heavy work in `update()`. Data arrives as ready-to-draw structs.
5. **No continuous repaint.** eframe runs reactive. Repaints come from input, from the net thread (`request_repaint`, throttled), and from timed `request_repaint_after` for the cursor blink only while the terminal is focused.
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

- **Threads:** main (UI) + one net thread. That's it at idle (D-016).
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
    src/format.rs          # bytes / rate / duration formatting rules
  ssh/   securewire-ssh (lib sw_ssh) — net side
    src/api.rs             # Command / Event / EventKind / SudoMode / Throttle: the UI↔net contract
    src/pipeline.rs        # Frame → EventKind (trackers, alerts); shared by the demo and the real actor
    src/demo.rs            # fake server: byte-exact collector output through the real decoder + pipeline
                           # [M1: actor.rs (russh HostActor), known_hosts.rs, probe.rs, sudo.rs]
  app/   securewire (bin) — eframe App
    src/main.rs, app.rs    # NativeOptions (glow), event drain, panel order, section ON/OFF diffing, focus throttle
    src/theme.rs           # tokens + Visuals + fonts — the only place colors are constructed
    src/state.rs           # HostView (data, ring buffers, LogStore), HostUi (open sections, LogFilter)
    src/widgets.rs         # section, sparkline, bar, badge, dot, switch, icon_button, toggle_chip
    src/panels/            # topbar, status, system (left), watch (right), dock (bottom), terminal (central)
  [M1] term/               # alacritty_terminal glue + egui terminal widget
[M2] collector/            # collector.sh, probe.sh — include_str!, no single quotes, shellcheck-clean
design/                    # see §1
```

Never name a package `core` (it shadows Rust's `core`): packages are `securewire-*`, libs are `sw_*`.

Dependency direction: `app → ssh → core`, `app → term`, `ssh → term` (feeds `Term`). `core` depends only on `memchr` today; keep it that light (`serde`/`serde_json` join for config and journal JSON).

### Pinned crates
| Crate | Version | Notes |
|---|---|---|
| `eframe` / `egui` | **0.36** | Held at 0.36 because `egui-phosphor 0.14` depends on egui 0.36. Never allow two egui versions (`cargo tree -i egui`). eframe features: `glow`, `default_fonts`, `persistence`, `x11`, `wayland`, `accesskit` — no wgpu. |
| `egui-phosphor` | 0.14 | `regular` variant only |
| `regex-lite` | 0.1 | log filter |
| `memchr` | 2 | frame decoder |

egui 0.36 API (differs from most examples online): `eframe::App::ui(&mut self, ui: &mut Ui, frame)` instead of `update(ctx, …)`; panels are `egui::Panel::{top,bottom,left,right}(id)` with `.exact_size / .default_size / .size_range` and `.show(ui, …)`; `CentralPanel::no_frame()`; `Margin` fields are `i8`; `rect_stroke` takes a `StrokeKind`; `NativeOptions` has no `vsync` field.

Planned, added in their milestone: `russh`, `tokio` (`rt`, `net`, `sync`, `time`, `macros`), `alacritty_terminal`, `secrecy`/`zeroize`, `serde` + `toml` + `serde_json`, `directories`, `ssh2-config`, `parking_lot`, `tracing` + `tracing-subscriber`, `anyhow` (app) / `thiserror` (libs), `keyring` (optional, off by default).

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
| Server-side collector CPU | < 0.1 % of one core |
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
shellcheck -s bash collector/collector.sh collector/probe.sh
cargo test -p ssh -- --ignored                # integration: needs Docker (spins up an sshd container)
```

## 9. Testing strategy

- **Parsers (`core`)**: table-driven tests over `tests/fixtures/<distro>/` captured from real machines, including edge cases (many cores, no swap, IPv6-only, `ufw inactive`, `fail2ban` not installed, unit names with `@`, non-UTF-8 log bytes).
- **Frame decoder**: fuzz-style tests for partial reads, frames split across packets, missing `END`, `SAME`, `ERR`.
- **Collector script**: shellcheck; a test asserts it contains no `'`; integration test runs it in a container and checks every section emits a parseable frame.
- **Command building**: every action template tested with hostile inputs (spaces, quotes, `;`, `$()`, newlines) — must be rejected or safely quoted.
- **Demo mode** (`--demo`) replays recorded frames and log lines; use it for UI work and screenshots instead of a live server.
- **Perf**: a `--bench-ui` flag that runs the demo at 50 log lines/s and prints frame-time percentiles.

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
| **M0** ✅ | Workspace scaffold, build settings, theme + icons, full panel layout with demo data through the real decoder/parsers | Done 2026-11-12. Open: Inter + JetBrains Mono not embedded yet (egui default fonts in use) |
| **M1** | Connect dialog, known_hosts/TOFU, agent + key + password auth, one PTY tab with `alacritty_terminal` renderer, resize, copy/paste, reconnect | vim, htop, tmux usable |
| **M2** | Probe + sudo password flow (protocol §9) + collector (static, cpu, mem, net, dio, df, who, ps), SYSTEM panel live, focus/visibility throttling, status bar | Matches protocol §8 targets on a real VPS |
| **M3** | WATCH panel: services (picker dialog, Live/Poll/Manual), firewall, security, scheduled | Service failure shows within 1 s in Live mode |
| **M4** | Logs: discovery dialog, journal + file + sudo-file channels, filters, regex, follow, Alerts tab | 50 lines/s stays < 4 ms/frame |
| **M5** | Multi-host tabs, command palette with parameter prompts, actions with confirmation, Processes/Connections tabs, `~/.ssh/config` import, jump hosts | Daily-driver for 3 hosts |
| **M6** | Perf pass, packaging (Windows MSI / Linux AppImage + .deb / macOS dmg), sudoers snippet docs | Budgets in §6 verified and recorded |

Out of scope for v1: editing firewall rules, file manager/SFTP, port forwarding UI, Windows/BSD servers, light theme, user-arranged docking.
