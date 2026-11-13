#![allow(dead_code)]

//! A fake Linux host for running the real collector/probe scripts under a local
//! bash: a fake `/proc` (via the scripts' `SW_PROC` hook) and stub commands
//! (`df`, `who`, `ps`, `systemctl`, `id`, `sudo`, …) first on `PATH`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The stub `sudo` accepts exactly this password.
pub const SUDO_PASSWORD: &str = "sudo-pass";

/// A real bash (not the WSL launcher in System32). `SW_TEST_BASH` overrides.
pub fn local_bash() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SW_TEST_BASH") {
        return Some(PathBuf::from(p));
    }
    let candidates: &[&str] = if cfg!(windows) {
        &[
            r"C:\Program Files\Git\usr\bin\bash.exe",
            r"C:\Program Files\Git\bin\bash.exe",
        ]
    } else {
        &["/bin/bash", "/usr/bin/bash", "/usr/local/bin/bash"]
    };
    candidates.iter().map(PathBuf::from).find(|p| p.exists())
}

fn slash(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

/// Absolute POSIX path as the remote shell sees it: `C:\x\y` → `/c/x/y` under Git Bash.
pub fn posix(p: &Path) -> String {
    let s = slash(p);
    match s.as_bytes() {
        [d, b':', b'/', ..] if cfg!(windows) => {
            format!("/{}{}", (*d as char).to_ascii_lowercase(), &s[2..])
        }
        _ => s,
    }
}

pub struct FakeHost {
    pub dir: PathBuf,
    bash: PathBuf,
    ticks: AtomicU64,
}

impl FakeHost {
    pub fn new(tag: &str) -> Option<Self> {
        let bash = local_bash()?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("sw-fakehost-{tag}-{}-{nanos}", std::process::id()));
        for d in ["proc/net", "proc/sys/kernel", "bin", "log/nginx"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        let h = Self {
            dir,
            bash,
            ticks: AtomicU64::new(0),
        };
        h.write_static();
        h.tick();
        h.write_stubs();
        Some(h)
    }

    pub fn bash(&self) -> &Path {
        &self.bash
    }

    /// Environment that points the scripts at this fake host.
    pub fn env(&self) -> Vec<(String, String)> {
        let sep = if cfg!(windows) { ";" } else { ":" };
        let bash_dir = self
            .bash
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let path = format!(
            "{}{sep}{bash_dir}{sep}{}",
            self.dir.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        vec![
            ("SW_PROC".into(), slash(&self.dir.join("proc"))),
            ("SW_OS_RELEASE".into(), slash(&self.dir.join("os-release"))),
            ("SW_LOG_ROOT".into(), posix(&self.dir.join("log"))),
            ("PATH".into(), path),
        ]
    }

    fn write(&self, rel: &str, s: &str) {
        std::fs::write(self.dir.join(rel), s).unwrap();
    }

    fn write_static(&self) {
        self.write(
            "log/app.log",
            "boot ok
worker started
",
        );
        self.write(
            "log/nginx/error.log",
            "2026/11/12 13:05:01 [error] 1123#1123: upstream timed out
",
        );
        self.write("proc/sys/kernel/hostname", "fake-vps\n");
        self.write("proc/sys/kernel/osrelease", "6.8.0-49-generic\n");
        self.write(
            "os-release",
            "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n",
        );
        self.write("proc/loadavg", "0.42 0.51 0.48 2/345 6789\n");
        self.write(
            "proc/meminfo",
            "MemTotal:        8000000 kB\nMemFree:          500000 kB\nMemAvailable:    3000000 kB\nBuffers:          100000 kB\n\
             Cached:          1200000 kB\nShmem:            100000 kB\nSReclaimable:     200000 kB\nSwapTotal:       2000000 kB\n\
             SwapFree:        1500000 kB\nHugePages_Total:       0\n",
        );
    }

    /// Advance the kernel counters: 2 s of 25 % CPU, 1 MB/s rx, 512 KiB/s disk read.
    pub fn tick(&self) {
        let t = self.ticks.fetch_add(1, Ordering::SeqCst) + 1;
        let (busy, idle) = (50 * t, 150 * t); // per core, jiffies
        let up = 1000.0 + 2.0 * t as f64;
        self.write("proc/uptime", &format!("{up:.2} {:.2}\n", up * 1.5));
        self.write(
            "proc/stat",
            &format!(
                "cpu  {} 0 {} {} 0 0 0 0 0 0\ncpu0 {} 0 {} {} 0 0 0 0 0 0\ncpu1 {} 0 {} {} 0 0 0 0 0 0\nintr 1 2 3\nctxt 999\nprocs_running 1\n",
                busy * 2, busy, idle * 2, busy, busy / 2, idle, busy, busy / 2, idle
            ),
        );
        self.write(
            "proc/net/dev",
            &format!(
                "Inter-|   Receive |  Transmit\n face |bytes packets|bytes packets\n    lo: 5 0 0 0 0 0 0 0 5 0 0 0 0 0 0 0\n  eth0: {} 10 0 0 0 0 0 0 {} 20 0 0 0 0 0 0\n",
                2_000_000 * t,
                1_000_000 * t
            ),
        );
        self.write(
            "proc/diskstats",
            &format!(
                "   8 0 sda 100 0 {} 0 50 0 {} 0 0 0 0\n   7 0 loop0 1 0 2 0 0 0 0 0 0 0 0\n",
                2048 * t,
                1024 * t
            ),
        );
    }

    fn write_stubs(&self) {
        let stub = |name: &str, body: &str| {
            let p = self.dir.join("bin").join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        };
        stub(
            "df",
            r#"echo "Filesystem 1-blocks Used Available Capacity Mounted on"
echo "/dev/vda1 66437775360 41231917056 25205858304 62% /"
echo "/dev/vdb1 107374182400 91268055040 16106127360 85% /var/lib/mysql""#,
        );
        stub(
            "who",
            r#"echo "deploy   pts/0        2026-11-12 09:12   .          88123 (198.51.100.24)""#,
        );
        stub(
            "ps",
            r#"echo "   1342 mysql    12.4 1268000 3562000 /usr/sbin/mysqld"
echo "   1123 www-data  1.2   38900 3562000 nginx: worker process""#,
        );
        stub(
            "systemctl",
            r#"case $1 in
  show)
    seen=0
    for u in "$@"; do
      [ "$seen" = 1 ] || { [ "$u" = -- ] && seen=1; continue; }
      case $u in
        redis*) printf "Id=%s\nActiveState=failed\nSubState=failed\nMainPID=0\nNRestarts=3\nResult=exit-code\n\n" "$u" ;;
        *) printf "Id=%s\nActiveState=active\nSubState=running\nMainPID=1123\nMemoryCurrent=39845888\nNRestarts=0\nResult=success\n\n" "$u" ;;
      esac
    done ;;
  list-units)
    echo "nginx.service loaded active running A high performance web server"
    echo "redis-server.service loaded failed failed Advanced key-value store"
    echo "certbot.timer loaded active waiting Run certbot twice daily" ;;
  list-timers)
    now=$(date +%s)
    echo "[{\"next\":$(( (now + 3600) * 1000000 )),\"left\":0,\"last\":$(( (now - 600) * 1000000 )),\"passed\":0,\"unit\":\"certbot.timer\",\"activates\":\"certbot.service\"}]" ;;
  *) echo "systemd 255" ;;
esac"#,
        );
        stub("uname", "echo x86_64");
        stub("systemd-detect-virt", "echo kvm");
        stub(
            "journalctl",
            r#"case "$*" in
  *"-o json"*)
    # Log channel: two nginx entries (one error), or just the newest after a cursor.
    case "$*" in
      *--after-cursor*) ;;
      *)
        echo '{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1731416531000000","PRIORITY":"6","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"nginx started"}'
        echo '{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1731416532000000","PRIORITY":"3","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"upstream connect() failed"}' ;;
    esac
    echo '{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"1731416533000000","PRIORITY":"4","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"after cursor"}'
    sleep 300 ;;
  *_COMM=sshd*)
    now=$(date +%s)
    echo "$((now - 100)).000000 fake-vps sshd[1]: Failed password for root from 198.51.100.203 port 1 ssh2"
    echo "$((now - 200)).000000 fake-vps sshd[1]: Failed password for root from 198.51.100.203 port 2 ssh2"
    echo "$((now - 4000)).000000 fake-vps sshd[1]: Invalid user admin from 192.0.2.155 port 3"
    echo "$((now - 50)).000000 fake-vps sshd[1]: Accepted publickey for deploy from 203.0.113.50 port 4 ssh2" ;;
  *" -f "*)
    # Unit watcher: report a state change, then keep following.
    sleep 1
    echo "Started nginx.service - A high performance web server."
    sleep 300 ;;
  *) exit 1 ;;   # the plain user cannot read the system journal
esac"#,
        );
        stub(
            "id",
            r#"case $1 in -u) echo 1000 ;; -un) echo deploy ;; *) echo "uid=1000(deploy)" ;; esac"#,
        );
        stub(
            "sudo",
            &format!(
                r#"n=0; s=0
while [ $# -gt 0 ]; do
  case $1 in
    -n) n=1; shift ;;
    -S) s=1; shift ;;
    -k) shift ;;
    -p) shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
if [ "$s" = 1 ]; then
  IFS= read -r pw || exit 1
  [ "$pw" = "{SUDO_PASSWORD}" ] || exit 1
elif [ "$n" = 1 ]; then
  exit 1
fi
[ $# -gt 0 ] || exit 0
exec "$@""#
            ),
        );
        stub(
            "ss",
            r#"case "$*" in
  *established*)
    echo "0      0      203.0.113.10:22      198.51.100.24:50412"
    echo "0      0      203.0.113.10:443     192.0.2.77:61022" ;;
  *)
    echo "tcp   LISTEN 0      4096       0.0.0.0:22        0.0.0.0:*"
    echo "tcp   LISTEN 0      511        0.0.0.0:443       0.0.0.0:*"
    echo "tcp   LISTEN 0      80       127.0.0.1:3306      0.0.0.0:*"
    echo "tcp   LISTEN 0      511        0.0.0.0:6379      0.0.0.0:*" ;;
esac"#,
        );
        stub(
            "ufw",
            r#"[ "$1 $2" = "status verbose" ] || exit 1
cat <<'X'
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80,443/tcp                 ALLOW IN    Anywhere
X"#,
        );
        stub(
            "fail2ban-client",
            r#"if [ "$1" = status ] && [ -z "$2" ]; then
  printf "Status\n|- Number of jail:\t1\n\`- Jail list:\tsshd\n"
elif [ "$1" = status ] && [ "$2" = sshd ]; then
  printf "Status for the jail: sshd\n|- Filter\n|  |- Currently failed:\t3\n|  |- Total failed:\t1284\n|  \`- File list:\t/var/log/auth.log\n\`- Actions\n   |- Currently banned:\t2\n   |- Total banned:\t102\n   \`- Banned IP list:\t198.51.100.203 192.0.2.155\n"
fi"#,
        );
        stub(
            "crontab",
            r#"[ "$1" = -l ] && echo "*/5 * * * * /usr/local/bin/backup.sh""#,
        );
    }
}

impl Drop for FakeHost {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl FakeHost {
    /// Append a line to a fake log file (as an application would).
    pub fn append_log(&self, rel: &str, line: &str) {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join("log").join(rel))
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    /// The path the remote shell uses for a fake log file.
    pub fn log_path(&self, rel: &str) -> String {
        posix(&self.dir.join("log").join(rel))
    }
}
