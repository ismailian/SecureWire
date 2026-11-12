# UI Specification

Companion to the clickable prototype in [`prototype/index.html`](prototype/index.html) (open it in a browser). When the prototype and this file disagree, **this file wins**; update both.

---

## 1. Principles

1. **The terminal is the hero.** It gets the largest area and keyboard focus by default. Everything else supports it — information you would otherwise type commands to get.
2. **Glanceable, then drillable.** Each section shows a one-line summary in its header (`5.1 / 7.8 GiB`, `1 > 80%`, `17 banned`) so the panel is useful even fully collapsed. Expand for detail; click for action.
3. **Calm by default, loud on problems.** Neutral grays everywhere; color is reserved for state (ok / warn / error / info) and the single teal accent for focus and selection. A failed service is the reddest thing on screen.
4. **Pay only for what you look at.** Collapsed sections and hidden panels stop collecting (see `collector-protocol.md §5`). The UI must make this visible: a collapsed section's header still shows its last summary with its age.
5. **Every number has a unit and an age.** Units: binary (KiB, MiB, GiB) for memory/disk sizes, decimal per second (KB/s, MB/s) for rates, `%` for utilisation. Tabular figures everywhere numbers update.
6. **Show the command.** Anything the app runs on the user's behalf can be revealed ("Read via `sudo -n ufw status verbose`"), and any action that changes the server shows the exact command before running it.
7. **Cheap to draw.** Flat fills, 1 px strokes, radius ≤ 4 px, no gradients, no blur, no animation except the live-dot pulse and a 1 s highlight on new log lines. Everything here maps to plain `egui::Painter` calls.

## 2. Layout

```
┌──────────────────────────── Top bar (38) ──────────────────────────────────┐
│ ◆ SecureWire │ host tabs … [+] │   [ ⌕ Command palette  Ctrl⇧P ]   │ ▯ ▭ ▯ ⚙ │
├───────────┬────────────────────────────────────────────────┬───────────────┤
│           │ terminal tabs                       PTY · ch #  │               │
│  SYSTEM   │                                                 │    WATCH      │
│  (left)   │               TERMINAL (central)                │   (right)     │
│  288 px   │                                                 │   312 px      │
│ 200–480   ├──────────────────── splitter ───────────────────┤  220–520      │
│           │ LOGS · ALERTS · PROCESSES · CONNECTIONS (bottom)│               │
│           │ 248 px, 120 … (window − 200)                    │               │
├───────────┴────────────────────────────────────────────────┴───────────────┤
│ Status bar (24): connection · address · host key · RTT … channels · tiers · overhead · sample age │
└─────────────────────────────────────────────────────────────────────────────┘
```

This follows the original sketch: side panels run full height, the bottom panel lives **only under the terminal**.

### egui construction order (it determines which panel owns the corners)
```rust
// egui 0.36 API — see crates/app/src/app.rs
Panel::top("topbar").exact_size(38.0)                     // 1
Panel::bottom("status").exact_size(24.0)                  // 2
Panel::left("system").resizable(true)
    .default_size(288.0).size_range(200.0..=480.0)        // 3
Panel::right("watch").resizable(true)
    .default_size(312.0).size_range(220.0..=520.0)        // 4
Panel::bottom("dock").resizable(true)
    .default_size(248.0).size_range(120.0..=max)          // 5  (max = window − 200, recomputed each frame)
CentralPanel::no_frame()                                  // 6  terminal
```
Panel visibility, sizes, collapsed sections, active bottom tab and log filters persist per host via eframe persistence.

### Minimum window
1024 × 640. Below 1280 px wide the right panel starts hidden (toggle still works). Below 800 px tall the bottom panel starts hidden.

## 3. Regions

### 3.1 Top bar
| Element | Behaviour |
|---|---|
| Brand | Glyph + "SecureWire". Not interactive. |
| Host tabs | One per open host. Status dot = worst current state (green ok · amber warning · red error · gray disconnected). Hover shows `user@host:port` and the reason for the color. Middle-click / × closes (asks if terminals are running). Drag to reorder. |
| `+` | Opens **Connect** dialog. |
| Command palette | `Ctrl Shift P`. Fuzzy over: actions (restart service, tail file, largest dirs, who's on port, ban IP, new terminal), hosts, services, log sources. Actions that need input open a small parameter prompt in the palette itself. |
| Layout toggles | Left (`Ctrl Shift B`), bottom (`Ctrl Shift J`), right (`Ctrl Shift R`). Teal when visible. |
| Settings | Opens settings window (theme, fonts, tier intervals, thresholds, keybindings). |

### 3.2 Left panel — SYSTEM
Header: title, age of last fast sample, pause sampling, collapse all.

| Section | Header summary | Body |
|---|---|---|
| Host | `up 41d 6h` | OS, kernel, hardware (vCPU · RAM · virt), address, privilege badge (`SUDO -n OK` / `NO SUDO` / `ROOT`). Static — fetched once. |
| CPU | `load 0.42 0.51 0.48` | Big % (user/sys/iowait/steal breakdown), 2-min sparkline (60 × 2 s), per-core mini bars (grid of 4 columns; > 16 cores → show top 8 busiest + "all cores" toggle). |
| Memory | `5.1 / 7.8 GiB` | RAM bar segmented used / cache, swap bar, legend with values. |
| Disk | `1 > 80%` badge or `ok` | One row per real mount: path, used/total, bar (amber > 80 %, red > 90 %), I/O read/write rates. Click mount → palette action "Largest directories under …". |
| Network | primary interface name | ↓/↑ rates, dual sparkline (rx filled info-blue, tx teal line), established count, listening ports as chips (public = normal, loopback = dim, unexpected public bind = amber). |
| Sessions | `2 users` | `who` rows: user, tty, from, idle; your own session tagged `YOU`. Footer note linking failed-login count to Security. |

### 3.3 Center — TERMINAL
- Tab strip: one tab per PTY channel on the current host; title = remote window title (OSC 0/2) or `user@host`. `+` opens another PTY **on the same connection**; `Ctrl Shift T` new tab, `Ctrl Shift W` close, `Ctrl Tab` cycle.
- Right of tabs (dim): `PTY cols×rows`, `channel #n`, `TERM`.
- Rendering: monospace grid from `alacritty_terminal`; 256-color + truecolor; bold/italic/underline/inverse; mouse reporting; bracketed paste; selection with copy on `Ctrl Shift C`, paste `Ctrl Shift V` (and right-click menu). Scrollback 10 000 lines (configurable).
- Focus: terminal has focus on launch and after closing any dialog. Focused cursor = teal block; unfocused = hollow gray.
- Disconnect: dim the grid, show an inline banner "Connection lost — reconnecting in 4 s · [Reconnect now]". Scrollback is preserved; a new shell starts after reconnect (we do not pretend the old shell survived).

### 3.4 Bottom dock — LOGS · ALERTS · PROCESSES · CONNECTIONS
Tab headers are uppercase labels with count badges (Logs: error count since last viewed; Alerts: active alerts).

**Logs**
- Toolbar: source chips (`all` + one per enabled source, colored swatch; red dot if the source has unseen errors) · sliders button → **Log sources** dialog · level toggles `ERR WARN INFO DEBUG` · regex filter (invalid regex → plain substring, input border turns amber) · follow toggle · clear view.
- Rows: `HH:MM:SS.mmm` · source (colored) · level · message (single line, ellipsized; full text on hover; click row to expand multi-line). Error rows get a faint red tint. New rows highlight for 1 s.
- Scrolling up turns follow off; pressing End or the follow button turns it on.
- Must be virtualized (`ScrollArea::show_rows`) — only visible rows are laid out.

**Alerts** — derived client-side, never from a server agent:
| Rule (defaults, per host overridable) | Severity |
|---|---|
| Watched service `failed` or `inactive` when it should run | error |
| Disk mount > 80 % / > 90 % | warn / error |
| Memory available < 15 % / < 5 % | warn / error |
| CPU > 90 % sustained 60 s | warn |
| Service restarted (`NRestarts` increased) | warn |
| Public listener not covered by a firewall allow rule | warn |
| fail2ban ban rate > N/h | info |
Each alert has contextual buttons (Logs, Restart, Largest dirs, Show rule). Alerts clear automatically when the condition clears; a cleared alert stays greyed in the list for 10 min.

**Processes** — top 25 by CPU (sortable: CPU, MEM, PID). Row context menu: copy PID, `kill -TERM` (confirm), open `top -p` in a new terminal tab.

**Connections** — established TCP (proto, local, peer, state, process). Fetched on tab open + slow tier.

### 3.5 Right panel — WATCH
Header: refresh all now, collapse all.

| Section | Header summary | Body |
|---|---|---|
| Services | Live switch + `+` | One row per watched unit: status dot, name (mono), sub-line `running · 41d` / `failed · exit 1 · 3m ago`, right column memory + pid/tasks. Failed rows have a red-tinted background and sort first. Hover reveals actions: restart/reload, logs (filters Logs tab to that unit), status in terminal (types `systemctl status <unit> --no-pager` into the active terminal **without pressing Enter**), stop. Footer: current mode ("Live · state changes pushed by systemd", or "Checked 12s ago · refresh"). |
| Firewall | `UFW ACTIVE` / `NFT` / `INACTIVE` / `NO ACCESS` badge | Default policies, rule table (To, Action, From). Footer shows the command used and its interval. Read-only in v1. |
| Security | `17 banned` | fail2ban jails with ban counts and rate badges; 24 h failed-login sparkline (48 × 30 min); top offending IPs with `BANNED` badge or a Ban button (confirm). |
| Scheduled | `4 cron · 9 timers` | systemd timers (next/last run) + user crontab. Collapsed by default; collected only when expanded. |

### 3.6 Status bar (left → right)
`🔒 user@host` (teal block, click → host menu: disconnect, reconnect, copy address) · `ip:port` · host-key state (`ed25519 · known host` / amber `new key` / red `KEY MISMATCH`) · `RTT n ms` (from collector `PING`) · sudo mode (`root` / `sudo (nopasswd)` / `sudo ✓` / amber `no sudo` → click to enter password, menu has "Forget sudo password") · spacer · `1 connection · n channels` (hover lists channels) · `tiers 2s · 10s · 60s` (click → settings) · `overhead ↓ x KB/s` (monitoring bytes only) · `sample n.ns ago` (turns amber if > 3 × fast tier).

## 4. Dialogs (egui `Window`, modal, centered, 640 px wide)

All dialogs: title bar with icon + title + host name, × close, body, footer with "Saved per host in hosts.toml" hint left, Cancel + primary right. `Esc` cancels, `Enter` confirms when focus isn't in a multiline field.

1. **Connect / Hosts** — list of saved hosts (status, `user@host`, auth method, Connect button); "New host" form: name, host, port, user, auth (`ssh-agent` · `Key file` · `Password` — prompted each time, never saved), jump host; footer button "Import ~/.ssh/config".
2. **Log sources** — discovered sources (journal units + readable files), each a toggle row with path and badges `JOURNAL` / `FILE` / `SUDO`; custom file path field; initial backlog (50/200/1000); memory cap (2k/10k/50k lines).
3. **Watched services** — filterable unit list with checkbox + current state badge; mode segmented control `Live (event-driven)` · `Poll every 30s` · `Manual`, with a cost explanation that changes with the selection.
4. **Host key** (blocking, first connect or mismatch) — fingerprint `SHA256:…`, key type, "Trust and remember" / "Connect once" / "Cancel". On mismatch: red, no trust option unless the user types the host name to confirm.
5. **Sudo password** (after login, only when the user isn't root and `sudo -n` fails) — "Some panels (firewall, fail2ban, root-only logs) and service actions need sudo on *host*." Masked field, Enter = verify, "Skip" = continue without. Wrong password: inline error, attempts left. Footer note: "Kept in memory for this session only — never saved." Re-open later by clicking the sudo item in the status bar.
6. **Confirm action** — exact command in a mono block, target host name in the title, primary button labelled with the verb ("Restart nginx"), destructive ones in error color.
7. **Settings** — tabs: General (theme, UI scale, fonts), Collection (tier intervals, focus throttling on/off), Alerts (thresholds), Terminal (scrollback, font size, cursor style, copy-on-select), Keys.

## 5. States

| State | Treatment |
|---|---|
| Connecting | Host tab dot pulses gray; panels show skeleton rows (flat `bg-3` bars, no shimmer); terminal shows "Connecting to host… / Authenticating… / Opening channels…" lines. |
| Auth failure | Inline error in terminal area with the server's method list and a "Change auth" button. |
| Reconnecting | All values stay but dim to 60 % opacity; status bar shows countdown; host dot amber. |
| Section unavailable | Body replaced by one dim line: "ufw not installed" / "needs sudo · [Enter password]" + "Why?" tooltip. Header summary shows `—`. |
| Stale data | Any value older than 3 × its tier shows its age in amber in the section header. |
| Empty | Services with nothing watched: "No services watched · [Choose services]". Logs with no sources: same pattern. |

## 6. Keyboard map

| Keys | Action |
|---|---|
| `Ctrl Shift P` | Command palette |
| `Ctrl Shift B` / `Ctrl Shift R` / `Ctrl Shift J` | Toggle left / right / bottom panel |
| `Ctrl Shift T` / `Ctrl Shift W` | New / close terminal tab |
| `Ctrl Tab` / `Ctrl Shift Tab` | Next / previous terminal tab |
| `Ctrl 1…9` | Switch host tab |
| `Ctrl Shift L` | Focus logs filter |
| `Ctrl Shift C` / `Ctrl V` or `Ctrl Shift V` | Copy / paste in terminal. Plain `Ctrl C` copies only while a selection exists, otherwise it sends SIGINT. |
| `Shift PageUp` / `Shift PageDown` | Scroll terminal history |
| `F5` | Refresh all sections now — only when the terminal does **not** have focus (htop and mc use F5) |
| `Esc` | Close dialog / palette; return focus to terminal |

The terminal swallows all other keys while focused (so `Ctrl B` for tmux, `Ctrl C`, `Ctrl D`, `Ctrl R`, `Ctrl K` etc. reach the shell). App shortcuts use `Ctrl Shift` for that reason (D-018) and are the only ones intercepted. The prototype still shows the older single-Ctrl shortcuts; this table wins.

## 7. Prototype coverage

| Feature | In prototype |
|---|---|
| Full layout, resizable splitters, panel toggles + shortcuts | ✓ |
| Live-updating sparklines, per-core bars, status bar ticking | ✓ (fake data) |
| Services list, live switch, hover actions, failed state | ✓ |
| Logs: source chips, level filters, regex filter, follow | ✓ (fake stream) |
| Alerts / Processes / Connections tabs | ✓ static |
| Log sources, Watched services, Connect dialogs | ✓ |
| Command palette | ✓ (no parameter prompts) |
| Mock terminal (try `help`, `free -h`, `systemctl restart redis-server`) | ✓ |
| Host key dialog, Confirm dialog, Settings, connecting/reconnecting states | spec only |
