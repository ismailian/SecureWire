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
        for d in ["proc/net", "proc/sys/kernel", "bin"] {
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
            ("PATH".into(), path),
        ]
    }

    fn write(&self, rel: &str, s: &str) {
        std::fs::write(self.dir.join(rel), s).unwrap();
    }

    fn write_static(&self) {
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
            "echo \"Filesystem 1-blocks Used Available Capacity Mounted on\"\n\
             echo \"/dev/vda1 66437775360 41231917056 25205858304 62% /\"\n\
             echo \"/dev/vdb1 107374182400 91268055040 16106127360 85% /var/lib/mysql\"",
        );
        stub(
            "who",
            "echo \"deploy   pts/0        2026-11-12 09:12   .          88123 (198.51.100.24)\"",
        );
        stub(
            "ps",
            "echo \"   1342 mysql    12.4 1268000 3562000 /usr/sbin/mysqld\"\n\
             echo \"   1123 www-data  1.2   38900 3562000 nginx: worker process\"",
        );
        stub(
            "systemctl",
            "[ \"$1\" = show ] || { echo \"systemd 255\"; exit 0; }\n\
             seen=0\n\
             for u in \"$@\"; do\n\
               [ \"$seen\" = 1 ] || { [ \"$u\" = -- ] && seen=1; continue; }\n\
               case $u in\n\
                 redis*) printf \"Id=%s\\nActiveState=failed\\nSubState=failed\\nMainPID=0\\nNRestarts=3\\nResult=exit-code\\n\\n\" \"$u\" ;;\n\
                 *) printf \"Id=%s\\nActiveState=active\\nSubState=running\\nMainPID=1123\\nMemoryCurrent=39845888\\nNRestarts=0\\nResult=success\\n\\n\" \"$u\" ;;\n\
               esac\n\
             done",
        );
        stub("uname", "echo x86_64");
        stub("systemd-detect-virt", "echo kvm");
        stub("journalctl", "exit 1");
        stub(
            "id",
            "case $1 in -u) echo 1000 ;; -un) echo deploy ;; *) echo \"uid=1000(deploy)\" ;; esac",
        );
        stub(
            "sudo",
            &format!(
                "case $1 in\n\
                   -n) exit 1 ;;\n\
                   -S) IFS= read -r pw; [ \"$pw\" = \"{SUDO_PASSWORD}\" ] && exit 0; exit 1 ;;\n\
                 esac\n\
                 exit 1"
            ),
        );
    }
}

impl Drop for FakeHost {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
