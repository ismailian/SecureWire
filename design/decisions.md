# Decision Log

Short records of choices that shape the code. Add a new entry instead of editing an accepted one; mark superseded entries.

Format: **context → decision → consequences**.

---

### D-001 · UI toolkit: egui via eframe, `glow` renderer
- **Context:** Requirement is Rust + egui, low resource use, fast startup.
- **Decision:** `eframe` with the `glow` (OpenGL) backend, not `wgpu`. Reactive repaint mode (no continuous redraw).
- **Consequences:** Smaller binary and lower idle GPU/RAM than wgpu. All repaint must be requested explicitly when data arrives (`ctx.request_repaint()` from the net thread, throttled). If a platform lacks GL, revisit.

### D-002 · One SSH connection, many channels
- **Context:** The user wants "a stream of all this info from a single connection".
- **Decision:** Exactly one transport per host. Terminal tabs, collector, log tails and actions are separate SSH channels on it (`russh`).
- **Consequences:** One handshake, one auth, one `who` entry; channels are cheap (1 RTT to open). Must respect `MaxSessions` (default 10) — see protocol §1.

### D-003 · Agentless shell collector, not a deployed binary agent
- **Context:** A Rust agent on the server would be most efficient but requires upload, arch matching, updates, and trust.
- **Decision:** A small bash script sent as the exec command; it streams framed raw text. Nothing is written to the server.
- **Consequences:** Works on any Linux with bash + procfs. Slight per-sample overhead (bash builtins, ~zero forks on the fast tier). A binary agent can be added later behind the same frame protocol if needed.

### D-004 · Raw data over the wire, parsing in Rust
- **Decision:** The collector sends unprocessed `/proc` and command output; rates, percentages and deltas are computed client-side.
- **Consequences:** Remote script stays tiny and dumb; parsers are pure functions in `crates/core`, tested against captured fixtures from real distros. Bandwidth is slightly higher than pre-computed numbers (still < 1 KB/s).

### D-005 · Tiered, visibility-driven sampling
- **Decision:** Three tiers (fast 2 s / medium 10 s / slow 60 s) plus per-section on/off. Collapsed sections, hidden panels, unfocused or minimized windows reduce or stop collection via control commands on the collector's stdin.
- **Consequences:** The UI must report section visibility to the net layer every time it changes. "Data age" must be visible because some data is intentionally old.

### D-006 · Service status: Live (event) / Poll / Manual
- **Context:** The user called constant live status "overkill" but wants the option.
- **Decision:** Per-host mode. *Live* is event-driven (systemd's own journal messages about the watched units trigger one `systemctl show`), not a fast poll. *Poll* = batched `systemctl show` every 30 s. *Manual* = only on refresh/expand.
- **Consequences:** Live costs almost nothing when nothing changes. Requires journal read access; otherwise degrades to Poll 5 s with a visible badge.

### D-007 · Logs: one channel per backend
- **Decision:** All journal units in one `journalctl -f -o json` channel; all readable files in one `tail -F` channel; root-only files in one `sudo -n tail -F` channel.
- **Consequences:** At most 3 log channels regardless of source count. Changing sources restarts the affected channel. Journal resume by cursor makes reconnects lossless.

### D-008 · Fixed IDE layout with built-in egui panels (no docking crate in v1)
- **Context:** `egui_dock` / `egui_tiles` allow arbitrary docking but add weight and complexity.
- **Decision:** Fixed regions (left, right, bottom-under-terminal, central) using `SidePanel` / `TopBottomPanel`, resizable and toggleable. Sections inside panels are collapsible.
- **Consequences:** Users can't drag sections between panels in v1. Revisit with `egui_tiles` if users ask for custom arrangements.

### D-009 · Dark theme only in v1
- **Decision:** Ship one dark theme from tokens; all colors go through `theme.rs`.
- **Consequences:** Light theme later is a token table, not a refactor.

### D-010 · Icons: Phosphor
- **Decision:** `egui-phosphor` (regular weight; fill for status icons). The prototype uses the same set via `@phosphor-icons/web`, so names map 1:1.

### D-011 · Fonts: Inter + JetBrains Mono, embedded and subsetted
- **Decision:** Inter for UI, JetBrains Mono for terminal, logs, tables and anything numeric that must align.
- **Consequences:** ~300–400 KB added to the binary after subsetting. Both are OFL-licensed; include license files.

### D-012 · Terminal emulation: `alacritty_terminal`
- **Context:** Options: `vt100` (simple), `alacritty_terminal` (complete, maintained), `wezterm-term` (heavy).
- **Decision:** `alacritty_terminal::Term` for parsing and grid state; our own egui renderer (row-run galleys, damage-tracked). `egui_term` is a useful reference implementation.
- **Consequences:** Full xterm compatibility (htop, vim, tmux work). Parsing runs on the net thread; the UI locks the grid briefly per frame.

### D-013 · No secrets at rest
- **Decision:** Never store passwords or key passphrases. Prefer ssh-agent (Windows OpenSSH agent pipe, Pageant, `SSH_AUTH_SOCK`), then key files with passphrase prompt. Optional OS keyring (`keyring` crate) for key passphrases only, opt-in, off by default.
- **Consequences:** Password hosts prompt on every connect.

### D-014 · Privilege: `sudo -n` only — **superseded by D-017**
- **Decision:** Root-only reads (firewall, fail2ban, some logs, process names in `ss`) use `sudo -n`. The app never asks for or forwards a sudo password in v1.
- **Consequences:** Users wanting these features configure NOPASSWD for specific read commands (docs will give a minimal sudoers snippet) or connect as root. Unavailable features show "needs sudo" rather than failing silently.

### D-015 · Host key verification is mandatory
- **Decision:** Check against `~/.ssh/known_hosts` (and our own known-hosts file). Unknown → TOFU dialog with SHA256 fingerprint. Mismatch → hard stop, no one-click override.

### D-016 · Threading: UI thread + one current-thread tokio runtime
- **Decision:** egui on the main thread; one background thread running a `current_thread` tokio runtime for all hosts' SSH I/O and parsing. Message passing both ways; no shared mutable app state except the terminal grid (`Arc<FairMutex<Term>>`).
- **Consequences:** Two OS threads total at idle. If parsing ever shows up in profiles, move it to a small blocking pool, not the UI thread.

### D-017 · Privilege: sudo password asked once per session, kept in memory
- **Context:** Requiring NOPASSWD sudoers entries is friction; the user wants to type the sudo password once when the session starts and have it apply to every privileged command the app runs.
- **Decision:** After login, the probe checks `id -u` and `sudo -n true`. Root → no sudo. NOPASSWD works → use `sudo -n`. Otherwise show the **Sudo password** prompt (skippable). The password is verified once (`sudo -S -k -p "" true`), then held in client memory for the lifetime of the host session (survives reconnects, cleared when the host tab closes or on "Forget sudo password"). Every privileged command the app runs uses `sudo -S -p ""` and receives the password as the **first line of its stdin** — never in argv, never in an environment variable, never in a file. Details: `collector-protocol.md §9`.
- **Consequences:** Firewall, fail2ban, root-only logs and service actions work without sudoers changes. The password lives in memory as a `secrecy`/`zeroize` type, is never logged or persisted, and is never typed into the user's terminal tabs (the terminal stays the user's; their own `sudo` there prompts as usual). Wrong password: up to 3 attempts, then privileged features show "sudo not authorised" until retried from the status bar (avoids PAM faillock lockouts). Hosts with `Defaults requiretty` need a PTY for sudo — detected in the probe and handled by running privileged commands on a PTY channel.

### D-018 · App shortcuts use Ctrl+Shift
- **Context:** The mock used `Ctrl B` / `Ctrl J` / `Ctrl K`. In a terminal those belong to the shell: `Ctrl B` is the tmux prefix, `Ctrl K`/`Ctrl J` are readline keys.
- **Decision:** App shortcuts are `Ctrl Shift P` (palette), `Ctrl Shift B/R/J` (panels), `Ctrl Shift T/W` (tabs), `Ctrl Tab`. `F5` refreshes only when the terminal is not focused. Everything else goes to the shell.
- **Consequences:** ui-spec §6 updated; the HTML prototype keeps the old labels.

### D-019 · Terminal: steady cursor, no remote clipboard, paste is sanitised
- **Decision:** No cursor blink (zero repaints while idle). OSC 52 clipboard reads/writes from the remote are ignored. Pasted text has ESC stripped and is wrapped in bracketed-paste markers when the app asked for them. Plain `Ctrl C` copies only while a selection exists, otherwise sends SIGINT; `Ctrl V` pastes.
- **Consequences:** `Ctrl V` (literal-next) can't be sent to the shell. Bold renders as bright color (no bold monospace font loaded yet).

### D-020 · SSH tested against an in-process server
- **Context:** No local sshd, Docker or WSL on the dev machine; tests must not need a VPS.
- **Decision:** `crates/ssh/tests/support` runs a russh server with a fake shell; its host and client keys are generated per test run (no private keys in the repo; `dev_sshd` keeps a stable set in `target/dev-sshd-keys`). The integration tests drive the real actor through it: TOFU, known/changed keys, password, key file (plain + encrypted), slow host-key answer, PTY sizing, exit status, dropped connection + reconnect. `examples/dev_sshd.rs` exposes the same server on 127.0.0.1:2222 for manual GUI testing.
- **Consequences:** Real-shell behaviour (vim, htop, tmux) still needs a manual check on a real Linux host.

### D-021 · Host-key prompts don't count against the connect timeout
- **Decision:** The TCP connect is bounded by `connect_timeout` (15 s). The SSH handshake uses an idle deadline that re-arms while a host-key prompt is open and for `connect_timeout` after it closes. A late answer to an abandoned prompt is discarded and can never approve a later key. Each PTY channel has a generation number, so a reader from a dropped connection can't close the tab's new shell.

### D-022 · Collector travels on stdin (`bash -s`), not as a quoted argument
- **Context:** D-003 planned `exec bash -c '<script>'`, which depends on the remote login shell's quoting rules (fish and csh differ) and puts the whole script in `ps`.
- **Decision:** `exec bash -s securewire-collector F M S`, script streamed on stdin. bash executes it command by command, so lines written after its final `main "$@"` arrive in `main` as control commands. The probe uses `exec sh -s` the same way.
- **Consequences:** The script must end with the `main` call (unit test). The "no single quotes" rule is gone. Supersedes the transport detail of D-003.

### D-023 · The collector doesn't get the sudo password until a section needs it
- **Decision:** M2's sections need no privilege, so the password is verified and held by the actor but never sent to the collector. M3 (firewall, fail2ban) will pass it as the first stdin line (protocol §9).

### D-024 · Coalesce collector packets before waking the UI
- **Context:** Measured ~2.5 repaints/s with a 2 s tier — bash writes each section as a separate SSH packet, one wake each. Client CPU 1.15 %.
- **Decision:** The reader collects packets arriving within 30 ms and emits them as one batch. Result: ~1.3 repaints/s, client CPU 0.78 % with live metrics (budget < 1 %).

### D-025 · Privileged reads accept sudo's log lines, but keep them few
- **Context:** Every `sudo` call is logged on the server. Reading the firewall and fail2ban every 60 s therefore adds log lines.
- **Decision:** One sudo call per section per tick (fail2ban jails batched into one `sudo sh -c`), only while the section is open; `ports` never uses sudo (process names only as root); `auth` uses sudo only when the journal isn't readable, every 5 minutes.
- **Consequences:** ≈ 2 sudo log lines per minute with Firewall and Security open. Documented in the protocol (§11).

### D-026 · Live service status = journal match on PID 1's messages about the units
- **Decision:** `journalctl -f -n 0 _PID=1 UNIT=…` on its own channel; output only triggers `NOW svc`, it isn't parsed. Without journal access and without sudo it degrades to a 5 s poll, shown in the UI.
