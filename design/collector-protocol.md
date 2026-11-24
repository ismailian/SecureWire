# Collector & Channel Protocol

How SecureWire gets all of its monitoring data over **one SSH connection** with no agent installed on the server.

Status: design v0.1 — the source of truth for `crates/ssh` and `collector/collector.sh`. Change this file first when the protocol changes.

---

## 1. Connection model

```
                       ┌──────────────── one TCP socket, one key exchange, one auth ───────────────┐
 SecureWire (client) ══╡                                                                           ╞══ sshd (server)
                       │  ch #1  session+pty   "shell"                 ← terminal tab 1            │
                       │  ch #2  session+pty   "shell"                 ← terminal tab 2 (optional) │
                       │  ch #3  exec  bash -c '<collector>'           ← metrics, services, fw …   │
                       │  ch #4  exec  journalctl -f -o json …         ← journal log sources       │
                       │  ch #5  exec  tail -F …                       ← file log sources          │
                       │  ch #6  exec  $SUDO tail -F …               ← root-only files (optional)│
                       │  ch #n  exec  <one-shot action>               ← restart, du, ban …        │
                       └───────────────────────────────────────────────────────────────────────────┘
```

- SSH multiplexes many **channels** over one transport (RFC 4254). Opening a channel costs one round-trip and no new handshake, so it is the unit we use for every independent stream.
- Library: `russh` client (`client::Handle::channel_open_session()` per channel). Never open a second TCP connection to the same host.
- Default server limits: OpenSSH `MaxSessions 10` caps channels per connection. Budget: ≤ 4 long-lived non-PTY channels + PTY tabs + 1–2 transient action channels. When we would exceed 10, queue actions on a single reusable "action" channel and warn when a user opens more terminal tabs than fit.
- Keepalive: `russh` keepalive every 15 s, disconnect after 3 missed. Auto-reconnect with backoff 1, 2, 4, 8, 16, 30 s (cap). On reconnect: re-open collector + log channels; log channels resume from the last journal `__CURSOR` / last file line count so nothing is duplicated or lost.

## 2. Collector channel (ch #3)

### 2.1 Launch

The collector is a bash script embedded in the binary (`include_str!("../../../collector/collector.sh")`). It is **streamed on the stdin** of the exec command, never written to disk:

```
exec bash -s securewire-collector <fast_s> <medium_s> <slow_s>
```

- bash reads a script from stdin one command at a time, so everything the client writes after the script's last line (`main "$@"`) is read by `main` as control input. Rule: the script is all function definitions and its **last line calls `main`** (unit-tested); anything after it would be swallowed as input.
- No quoting of the script through the user's login shell (works the same under bash, zsh, fish, csh), no script text in `ps` (it shows `bash -s securewire-collector 2 10 60`).
- Nothing is installed or written on the server. The script avoids here-strings (older bash backs them with temp files) and uses builtins on the fast tier.
- Test hooks: `SW_PROC` (fake `/proc` root) and `SW_OS_RELEASE`; unset in production.
- `bash` is required for `read -t` (timed reads → control commands without polling) and associative arrays. Detected during the probe step (§4). **Fallback for hosts without bash** (e.g. Alpine): run the same logic with `/bin/sh` in *restart mode* — no stdin control; any config change closes and reopens the channel.

### 2.2 Output framing (server → client)

Line-oriented UTF-8 text. Frames start with ASCII RS (`0x1E`), which never appears in `/proc` text or in the commands' normal output.

```
␞SW1 <section> <seq>\n
<raw payload lines…>\n
␞END <section> <seq>\n

␞SAME <section> <seq>\n            # payload identical to the previous emit → client keeps old data
␞ERR <section> <seq> <code>\n      # command missing / permission denied / timed out
␞HELLO <proto_version> <bash_version>\n   # first line after start
```

- `seq` is a monotonically increasing u64 per channel; the client drops frames whose `END` never arrived (truncated by disconnect).
- **Payloads are raw** (`/proc/stat` lines, `df -P` output, `systemctl show` output). All parsing happens in Rust (`crates/core::parse::*`), which keeps the remote script tiny, makes parsers unit-testable with captured fixtures, and costs the server nothing.
- `SAME`: the script keeps the previous payload of every medium/slow section in a bash variable and compares strings — no fork, no hashing. Fast sections are always sent (they always change).

### 2.3 Control (client → server, via the channel's stdin)

One command per line. Unknown commands are ignored (forward compatible).

| Command | Effect |
|---|---|
| `TIER <fast\|medium\|slow> <seconds>` | Change a tier interval (used for focus-aware throttling, §5). |
| `ON <section>` / `OFF <section>` | Enable/disable a section. Collapsed or hidden UI sections are `OFF`. |
| `NOW <section>` | Emit a section immediately (refresh button, section expanded). |
| `SVC <unit> <unit> …` | Replace the watched-unit list. |
| `PING <n>` | Script replies `␞PONG <n>` — used for the RTT shown in the status bar. |
| `QUIT` | Clean exit. |

The main loop sleeps with `read -t <time_to_next_due> line`, so a control command is handled immediately and an idle collector burns no CPU between ticks.

### 2.4 Sections

| Section | Tier (default) | Source on the server | Forks per emit | Needs |
|---|---|---|---|---|
| `static` | once on connect | `/etc/os-release`, `uname -srm`, `nproc`, `hostname`, `systemd-detect-virt`, `/proc/meminfo` MemTotal | ~4 (once) | — |
| `cpu` | fast 2 s | `/proc/stat` (`cpu*`, `ctxt`, `procs_*` lines only, filtered with bash builtins), `/proc/loadavg`, `/proc/uptime` | 0 | — |
| `mem` | fast 2 s | `/proc/meminfo` (MemTotal, MemAvailable, Buffers, Cached, SReclaimable, Shmem, SwapTotal, SwapFree) | 0 | — |
| `net` | fast 2 s | `/proc/net/dev` | 0 | — |
| `dio` | fast 2 s | `/proc/diskstats` (whole-disk rows only) | 0 | — |
| `df` | medium 10 s | `df -P -B1 -x tmpfs -x devtmpfs -x squashfs -x overlay` | 1 | — |
| `who` | medium 10 s | `who -u` | 1 | — |
| `ps` | medium 10 s | `ps -eo pid,user,pcpu,rss,etimes,args --sort=-pcpu --no-headers \| head -n 25` | 2 | — |
| `svc` | medium 10 s (mode-dependent, §3) | `systemctl show -p Id,ActiveState,SubState,MainPID,MemoryCurrent,CPUUsageNSec,ActiveEnterTimestampMonotonic,NRestarts,Result <units…>` — **one call for all units** | 1 | — |
| `ports` | slow 60 s | `ss -Htlnup` | 1 | root for process names (via `$SUDO`, §9) |
| `conns` | slow 60 s / `NOW` | `ss -Htn state established` (counts + top peers) | 1 | — |
| `fw` | slow 60 s | `$SUDO ufw status verbose` → else `$SUDO nft -j list ruleset` → else `$SUDO iptables -S` | 1 | sudo |
| `f2b` | slow 60 s | `$SUDO fail2ban-client status` + `status <jail>` per jail | 1 + jails | sudo |
| `auth` | 300 s | failed-login count buckets (see below) | 2 | journal read access |
| `timers` | slow, only when expanded | `systemctl list-timers --all --no-pager --output=json` (fallback: plain) + `crontab -l` | 2 | — |

Notes
- CPU %, network/disk rates, and per-service CPU % are computed **client-side** from counter deltas over the remote `/proc/uptime` delta (immune to network jitter).
- `auth`: on connect, `journalctl _COMM=sshd --since -24h -o short-unix --no-pager | grep -E 'Failed|Invalid user'` bucketed per 30 min in awk → 48 numbers. Afterwards, if the `sshd` log source is enabled, the client increments buckets from the live log stream and the section is turned `OFF`.
- A section whose tool is missing emits `␞ERR <section> <seq> missing` once and is auto-disabled; the UI shows an inline "not available on this host" state.

### 2.5 Script skeleton (illustrative and pre-implementation — `collector/collector.sh` is authoritative)

```bash
# securewire collector — no single quotes allowed in this file
RS=$'\x1e'; F=${1:-2}; M=${2:-10}; S=${3:-60}; seq=0
declare -A ON=([cpu]=1 [mem]=1 [net]=1 [dio]=1 [df]=1 [who]=1 [ps]=1 [svc]=1 [ports]=1 [fw]=1 [f2b]=1)
declare -A PREV DUE
SVC=()

frame() {  # $1=section $2=payload $3=dedupe(0/1)
  seq=$((seq+1))
  if [[ $3 == 1 && ${PREV[$1]+x} && ${PREV[$1]} == "$2" ]]; then printf "%sSAME %s %d\n" "$RS" "$1" "$seq"; return; fi
  PREV[$1]=$2
  printf "%sSW1 %s %d\n%s\n%sEND %s %d\n" "$RS" "$1" "$seq" "$2" "$RS" "$1" "$seq"
}

s_cpu() { local l o; read -r l < /proc/uptime; o="uptime $l"
  while IFS= read -r l; do case $l in cpu*|ctxt*|procs_*) o+=$'\n'"$l";; esac; done < /proc/stat
  read -r l < /proc/loadavg; o+=$'\n'"loadavg $l"; frame cpu "$o" 0; }
# s_mem, s_net, s_dio … same pattern (builtins only)
s_df()  { frame df "$(df -P -B1 -x tmpfs -x devtmpfs -x squashfs -x overlay 2>&1)" 1; }
s_svc() { ((${#SVC[@]})) || return; frame svc "$(systemctl show -p Id,ActiveState,SubState,MainPID,MemoryCurrent,CPUUsageNSec,NRestarts,Result "${SVC[@]}" 2>&1)" 1; }

handle() { set -- $1; case $1 in
  TIER) case $2 in fast) F=$3;; medium) M=$3;; slow) S=$3;; esac;;
  ON) ON[$2]=1; DUE[$2]=0;;  OFF) ON[$2]=0;;  NOW) "s_$2";;
  SVC) shift; SVC=("$@"); s_svc;;  PING) printf "%sPONG %s\n" "$RS" "$2";;  QUIT) exit 0;; esac; }

printf "%sHELLO 1 %s\n" "$RS" "$BASH_VERSION"
while :; do
  now=$SECONDS
  # run every enabled section whose DUE[name] <= now, then set DUE[name]=now+tier
  # compute wait = min(DUE) - now (>= 1)
  if read -r -t "$wait" line; then handle "$line"; elif (( $? < 128 )); then exit 0; fi   # EOF → client gone
done
```

## 3. Service status modes

Per host, chosen in the *Watched services* dialog.

| Mode | How | Cost while nothing changes |
|---|---|---|
| **Live** (event-driven) | Log channel ch #4 additionally matches systemd's own messages about watched units: `_PID=1 UNIT=<u1> + _PID=1 UNIT=<u2> …` (journal). Any such line → client sends `NOW svc` on the collector. Resource numbers (memory, CPU) still refresh on the medium tier. | ~0 (one blocked `journalctl`) |
| **Poll** | `svc` section on its own interval (default 30 s). | 1 fork / interval |
| **Manual** | `svc` is `OFF`; `NOW svc` on section expand, window focus, or refresh button. | 0 |

If the user cannot read the system journal (not root, not in `systemd-journal`/`adm`), *Live* degrades to *Poll 5 s* and the UI says so (badge "LIVE · POLLING").

## 4. Probe (on connect, one exec channel, then closed)

One script that prints `key=value` lines:

```
bash=5.2.21  uid=1000  sudo_n=0  requiretty=0  systemd=255  journal_read=1  ufw=1  nft=0  iptables=1
fail2ban=1  ss=1  docker=0  os=ubuntu:24.04  init=systemd
```

The client uses this to pick collector mode (bash vs restart), enable/disable sections, decide which firewall backend to read, and label sudo-only features. Results are cached in memory per connection only.

## 5. Visibility- and focus-driven collection

The cheapest sample is the one never taken.

| UI state | Client sends |
|---|---|
| Section collapsed / panel hidden | `OFF <section>` (re-`ON` + `NOW` when shown) |
| Window unfocused | `TIER fast 10`, `TIER medium 30` |
| Window minimized / host tab not active | `TIER fast 30`, `TIER medium 120`, slow sections `OFF` (alerts still evaluated on what arrives) |
| Focus regained | restore tiers + `NOW cpu` so numbers are fresh instantly |

## 6. Log channels (ch #4–#6)

### Journal sources — one channel for all units
```
journalctl -f -n <backlog> -o json \
  --output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,__REALTIME_TIMESTAMP,__CURSOR \
  -u nginx.service -u ssh.service …  [+ _PID=1 UNIT=… matches for Live services]
```
- One JSON object per line → `serde_json` into a borrowed struct; `PRIORITY` (0–7) gives the level directly. `MESSAGE` may be a byte array for binary data → lossy UTF-8.
- On reconnect: `--after-cursor=<last __CURSOR>` instead of `-n`.

### File sources — one channel for all readable files
```
tail -n <backlog> -F -- /var/log/nginx/error.log /var/log/fail2ban.log …
```
- `tail` prints `==> <path> <==` headers when switching files; the client tracks the current file from them (paths are known, so the header cannot be spoofed by log content: only exact matches of configured paths are accepted).
- Files only root can read go to a separate `$SUDO tail -F` channel (ch #6). Without privileged access (§9) the source is shown as "needs sudo".
- Level detection for files: per-source preset regex (nginx `[error]`/`[warn]`, MySQL `[ERROR]`/`[Warning]`, fail2ban `ERROR`/`WARNING`/`NOTICE`, generic `(?i)\b(fatal|crit|error|err|fail(ed|ure)?)\b` → ERR, `(?i)\bwarn(ing)?\b` → WARN).

Changing sources = close that channel and reopen it with the new argument list (cheap: one round-trip).

### Discovery (log sources dialog)
On dialog open, one exec: `systemctl list-units --type=service --state=loaded --no-legend --plain` + `find /var/log -maxdepth 2 -type f -name "*.log" -size +0 -readable 2>/dev/null` (+ the same under `$SUDO` when privileged access is available, marked SUDO). Known units are mapped to friendly presets (nginx → journal + `/var/log/nginx/error.log`).

## 7. One-shot actions

Every action is a fixed template filled with **validated** arguments, run on a fresh exec channel, output shown in a toast or streamed into the bottom panel. Nothing user-typed is concatenated into a shell string without quoting via `shell_quote()` (single-quote escaping), and identifiers are validated first:

| Arg kind | Validation |
|---|---|
| systemd unit | `^[A-Za-z0-9@._:\\-]{1,255}$` and must exist in the last unit list |
| IP address | parse with `std::net::IpAddr` |
| path | absolute, no NUL; always passed quoted |
| fail2ban jail | must be in the last `f2b` jail list |

Examples: `$SUDO systemctl restart <unit>`, `$SUDO fail2ban-client set <jail> banip <ip>`, `du -xh --max-depth=1 <path> 2>/dev/null | sort -rh | head -n 20`.
Destructive actions (stop, restart, ban, firewall change) always show a confirmation with the exact command.

## 8. Bandwidth & cost targets (per host, steady state, window focused)

| | Target |
|---|---|
| Collector traffic | < 1 KB/s (fast tier dominates: ~1.5 KB per 2 s on a 4-core box before SSH compression) |
| Server CPU for the collector | < 0.5 % of one core in steady state with the default sections (D-034; the original 0.1 % guess was not reachable at a 2 s fast tier) |
| *Measured (M5, 2-vCPU VirtualBox VM, Ubuntu 26.04)* | fast tier 2.25 ms/s; svc 18 ms per poll; who 12 ms; ports 26 ms; fail2ban-client ~400 ms per refresh (see §14) |
| Server processes added | 1 `bash` + 1 `journalctl` + 1 `tail` (+ 1 `sudo tail` when privileged logs are enabled) |
| Client parse cost | < 50 µs per fast frame |

Enable SSH compression (`zlib@openssh.com`) when RTT > 80 ms; leave it off on fast links (CPU > bytes).

## 9. Privilege (sudo)

`$SUDO` in this document means "run this privileged", resolved per host from the probe (§4):

| Probe result | Mode | `$SUDO cmd` becomes |
|---|---|---|
| `uid=0` | `root` | `cmd` |
| `sudo_n=1` (NOPASSWD) | `nopasswd` | `sudo -n cmd` |
| otherwise, user entered a password | `password` | `sudo -S -p "" cmd` with the password as the first stdin line |
| otherwise, user skipped the prompt | `none` | section disabled, UI shows "needs sudo" |

### Session flow
1. Probe reports `uid`, `sudo_n`, `requiretty`.
2. Mode `password` needed → **Sudo password** dialog (masked field, "Skip", "Remember for this session" is implicit — there is no on-disk option).
3. Verify on a transient exec channel: `sudo -S -k -p "" true`, password written to stdin. Exit 0 → keep it; non-zero → re-prompt (max 3 attempts, then mode `none` until the user retries from the status bar).
4. The password is stored in client memory only (`secrecy::SecretString`, zeroized on drop) for the host session; reconnects reuse it; closing the host tab or "Forget sudo password" drops it.

### How each channel gets the password
- **One-shot actions & `$SUDO tail -F` log channel:** exec `sudo -S -p "" <cmd>`, then write `password\n` to the channel's stdin. The command itself never reads stdin, so nothing else is needed.
- **Collector (D-029, M5):** the whole collector runs under **one** sudo for the session: `exec sudo -S -p "" -- bash -s securewire-collector F M S root`. The client writes the password line first (read by `sudo -S`, unbuffered in both sudo and sudo-rs), then the script (read by bash). Privileged sections then run as root without calling sudo again — one auth-log entry per session instead of one per section per tick, and no PAM cost per tick. NOPASSWD hosts use `exec sudo -n -- bash -s … root`. Verified on Ubuntu 26.04 with sudo-rs 0.2.13.
- **`requiretty=1` hosts:** privileged commands run on a dedicated PTY channel (no echo, prompt `-p ""`), driven by the actor; the collector delegates privileged sections to the actor (`␞NEED <section>`) instead of running them itself.

### Rules
- The password is never logged (not even at trace), never written to disk, never placed in argv, env, or a here-doc file, and never sent to a terminal tab.
- Status bar shows the mode: `root`, `sudo (nopasswd)`, `sudo ✓` (password held), or `no sudo` (click → re-enter password).
- A failed privileged command with `sudo: a password is required` / `incorrect password` drops the stored password and sets mode `none` (the password changed on the server).

## 10. Implementation notes (M2)

- **Probe** runs as `exec sh -s` with `collector/probe.sh` on stdin, then EOF. Output is parsed by `sw_core::parse::parse_probe`.
- **Sudo check** is `sudo -S -k -p "" true` with the password as the only stdin line, then EOF — one attempt per submission, max 3 per host session.
- **RTT** in the status bar is `PING`→`PONG` through the collector, so it includes the collector's loop latency (a few ms on Linux; much more on a Windows test bash, where forks are slow). The first sample is sent right after the collector starts.
- **Wake-ups:** bash writes each section as its own SSH packet; the reader gathers packets that arrive within 30 ms and hands them to the UI as one batch (one repaint per tick, not per section).
- **Tests:** `crates/ssh/tests/collector.rs` runs the real script under a local bash against a fake host (`tests/support/fakehost.rs`: fake `/proc` + stub `df`/`who`/`ps`/`systemctl`/`id`/`sudo`); `tests/connect.rs` runs probe → sudo → collector end to end through the in-process SSH server, whose exec requests execute in that fake host.

## 11. Implementation notes (M3)

- *(Superseded in M5 by D-029 — see §9: the collector now runs under one sudo and gets `root`.)*
- **Launch:** `exec bash -s securewire-collector F M S PRIV` — `PRIV` is `none|root|nopasswd|password`. With `password`, the first stdin line after the script is the sudo password; `main` reads it before anything else. `sudo_run` pipes it from a builtin `printf` into `sudo -S -p ""`. The actor relaunches the collector whenever the privilege changes (e.g. the user enters the sudo password after connecting).
- **`EVERY <section> <secs>`** sets a per-section interval (0 = back to its tier). Used for the service status modes: Live = medium tier (10 s, resources) + unit watcher; Poll = `EVERY svc <poll_secs>`; Manual = the app turns `svc` OFF and sends `NOW svc` on demand.
- **ERR codes:** `needs-sudo` (no privilege), `unavailable` (tool missing or sudo refused), `missing` (tool not installed), `unreadable`.
- **Sections:** `ports` = `ss -Htlnu` (`-p` only as root — no sudo, to avoid a log line per tick); `conns` = `ss -Htnp state established | head -300`; `fw` tries ufw (if active) → `nft list ruleset` → `iptables -S`, payload starts with `backend <name>`; `f2b` is ONE `sudo sh -c` per tick for all jails (`@@jail <name>` markers); `auth` = sshd journal for 24 h bucketed by awk into 48 half-hours + top 10 source IPs, every 300 s, via sudo only if the journal isn't readable; `timers` = `now <epoch>`, `systemctl list-timers -o json` (plain fallback), `@@cron`, `crontab -l`.
- **Sudo noise:** every privileged read is logged by sudo on the server (fw + f2b ≈ 2 lines/min while those sections are open; auth 1 per 5 min if needed). Collapsing the sections stops it.
- **Unit watcher (Live mode):** its own channel running `journalctl -f -n 0 -q -o cat _PID=1 'UNIT=a' 'UNIT=b' …` (units validated + quoted), via `sudo -n`/`sudo -S` when the journal needs privilege. Any output → `NOW svc` (≤ 1/s). If it can't run, the actor falls back to `EVERY svc 5` and the UI says "polling".
- **Unit picker list:** one-shot `systemctl list-units --type=service,timer --all --no-legend --plain --no-pager`.
- **Alert:** a listener on a public address whose port no ALLOW rule mentions, when the firewall is active and denies incoming by default.

## 12. Implementation notes (M4 — logs)

- **Discovery:** `collector/discover.sh` on stdin of `exec bash -s securewire-discover <priv>` (password = first line after the script). Lists running services (`unit <name> <desc>`) and files under `/var/log` (depth 3, `*.log`, syslog, messages, secure, kern.log; `find` runs via sudo when available so 0750 directories are visible), each marked `r` (readable) or `sudo`. Test hook `SW_LOG_ROOT`.
- **Channels** (at most three per host): `journalctl -f -n <backlog> -q -o json --output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,UNIT,SYSLOG_IDENTIFIER,__REALTIME_TIMESTAMP -u <unit>…` (via sudo when the journal isn't readable); `tail -n <backlog> -F -- <files>`; `sudo tail …` for root-only files. Units and paths are validated and single-quoted.
- **Parsing** happens on the net thread: journal JSON → level from PRIORITY, source by `_SYSTEMD_UNIT` (or `UNIT` for PID 1's messages about the unit); `tail` headers (`==> path <==`) switch files only on exact configured paths; file levels come from the source's preset. Packets within 30 ms become one UI batch.
- **Reconnect:** the journal resumes with `--after-cursor=<last cursor>`; files restart with `-n 0` (lines written while disconnected are not replayed).
- **Settings per host** (`hosts.toml`): `[[host.logs]]` sources, `log_backlog` (50/200/1000), `log_cap` (2k/10k/50k lines kept in memory).
- **Measured:** `securewire --bench-ui` (demo host, 50 lines/s, 20 s, release build on Windows): p50 1.00 ms, p95 1.48 ms, p99 1.82 ms, max 3.92 ms per frame — budget < 4 ms.

## 13. Tunnels (one-click port forwarding, M5)

"Tunnel" on a listening socket (sockets table, service menu, palette) forwards a port of the server to this computer:

- The client binds **127.0.0.1** only — never a wildcard address. It tries the same port number first (unprivileged, or any on Windows), then port + 10000, then any free port.
- Each accepted local connection opens a `direct-tcpip` channel on the host's **existing** SSH connection to the socket's address as seen from the server (`0.0.0.0` → `127.0.0.1`, `::` → `::1`, else the bound address). No second TCP connection; nothing runs on the server.
- The target must be an IP literal from `ss` output; anything else is refused before binding.
- Tunnels survive reconnects: every new local connection uses the current session; while offline, local connections are closed at once. Closing the tunnel releases the local port.
- UDP sockets can't be tunnelled (`direct-tcpip` is TCP only).

## 14. Implementation notes (M5 — measured on a real host)

Per-emission server CPU, then steady state per group, on a 2-vCPU VirtualBox VM (Ubuntu 26.04, bash 5.3, sudo-rs):

| Section | ms CPU per emission | Tier / interval (after M5) |
|---|---|---|
| cpu, mem, net, dio | ~2 each (8 per fast tick before `mapfile`) | fast, 2 s — 2.25 ms/s together |
| svc | 12–18 | 10 s in Poll mode; **30 s** in Live mode (state changes are pushed) |
| who | ~12 | **every 30 s** |
| df | 2–6 | **slow** (60 s) |
| ports (`ss -p` as root) | 20–26 | slow |
| fw | 4–10 | slow |
| f2b (`fail2ban-client`, Python) | ~400 | slow, but only re-run when `/var/lib/fail2ban/fail2ban.sqlite3` changed (`find -newermt`), on `NOW`, or every 10 min; otherwise `SAME` |
| auth | ~30 | every 300 s |

- Fast-tier readers use `mapfile` (a few syscalls per file) instead of `while read` (a read+lseek pair per line); `/proc/stat` is read only up to the last `cpuN` line (the `intr` line is huge). `procs_running` now comes from `/proc/loadavg`'s 4th field.
- `svc` asks for `LoadState`: a watched unit that doesn't exist shows "unit not found" instead of "dead"; an alias (`sshd.service` → `ssh.service`) is shown once.
- Before M5 the collector called `sudo` per privileged section per tick: on a real host each call wrote 3 auth-log lines (command + PAM open/close). D-029 removed that.
- Result, steady state with the default visible sections (120 s windows): **0.28 % of one core** with services in Live mode, **0.47 %** in Poll-every-10 s mode — down from ~1.4 % before M5. The original < 0.1 % target was not reachable at a 2 s fast tier on this VM (the fast tier alone is ~0.23 %), so §8 now says < 0.5 % (D-034). Release binary 11.5 MB.

## 15. File browser (Files tab, v1.1)

Everything runs as the **login user** (never sudo) on channels of the host's one connection. Nothing is installed on the server.

**Listing** — one exec channel per folder opened: `LC_ALL=C exec sh -s -- '<dir>'` (no argument = home) with `collector/ls.sh` on stdin. Output is NUL-separated: `P\0<resolved path>\0`, then 8 fields per entry — `%y%Y` (type, and target type for symlinks), size, mtime, octal mode, user, group, name, link target — or `E\0<noent|notdir|perm>\0`. GNU `find -printf` does it in one process; BusyBox/BSD fall back to one `stat` per entry. Names that are not UTF-8 are skipped (they can't be named back safely); names are drawn with control characters stripped. Output is capped at 32 MiB, 30 s.

**Operations on the server** — copy, move, rename, new folder, delete are server actions (§7, `Action::Files`) built from fixed templates in `core::files` (`cp -a --`, `mv [-n] --`, `mkdir --`, `rm -rf --`). Every path must be absolute with plain components (no `.`/`..`/empty, no NUL/newline) and is single-quoted. Delete, move, rename and anything that replaces an existing name show the exact command and ask first (non-negotiable 7); copies into free names and new folders run directly. Pasting into the same folder makes `name (copy).ext`. A move or copy into itself is refused.

**Transfers (SCP)** — Upload / Download (native pickers), a drop from the desktop, or files copied in Explorer and pasted:
- Upload: one exec channel `scp -r -t -- '<remote dir>'`. The client walks the local items first (tokio blocking pool) for the total, then sends `D<mode> 0 <name>` / `C<mode> <size> <name>` / data / `\0` / `E`, waiting for the sink's `\0` after each record. A clash the user chose to keep gets a "(copy)" name in the `C`/`D` record.
- Download: one exec channel per item, `scp -r -f -- '<path>'`. Records from the server are parsed by `core::files::parse_scp_record`, which refuses names with `/`, `.` or `..` (a hostile server can't write outside the chosen folder). The top-level record is renamed to the name the user chose. Folder totals come from one `du -sk` first. A partly written file is deleted on failure or cancel.
- `\1`/`\2` replies are warnings/errors from the server's scp; warnings inside a folder skip that file and are reported at the end. Exit 127 → "scp is not installed on the server".
- Progress events at most every 150 ms per transfer; cancel closes the channel. Transfers end with the session (no resume after a reconnect).
