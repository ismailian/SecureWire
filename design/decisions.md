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
