//! On-disk locations (CLAUDE.md §7): hosts.toml and SecureWire's own known_hosts.

use std::path::PathBuf;

use sw_core::config::HostsFile;

pub struct Store {
    pub dir: PathBuf,
}

impl Store {
    pub fn open() -> Self {
        let dir = directories::ProjectDirs::from("dev", "SecureWire", "SecureWire")
            .map(|d| d.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Self { dir }
    }

    pub fn hosts_path(&self) -> PathBuf {
        self.dir.join("hosts.toml")
    }

    pub fn known_hosts_path(&self) -> PathBuf {
        self.dir.join("known_hosts")
    }

    /// Missing file → empty list. A corrupt file is reported, never overwritten silently.
    pub fn load_hosts(&self) -> Result<HostsFile, String> {
        match std::fs::read_to_string(self.hosts_path()) {
            Ok(s) => {
                HostsFile::parse(&s).map_err(|e| format!("{}: {e}", self.hosts_path().display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HostsFile::default()),
            Err(e) => Err(format!("{}: {e}", self.hosts_path().display())),
        }
    }

    pub fn save_hosts(&self, f: &HostsFile) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        // Write-then-rename so a crash never leaves a half-written file.
        let tmp = self.dir.join("hosts.toml.tmp");
        std::fs::write(&tmp, f.to_toml()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, self.hosts_path()).map_err(|e| e.to_string())
    }
}

/// `~/.ssh/<name>` — the default key path shown in the connect dialog.
pub fn default_key_path() -> PathBuf {
    home().join(".ssh").join("id_ed25519")
}

/// The user's OpenSSH known_hosts (read-only for SecureWire).
pub fn user_known_hosts() -> Option<PathBuf> {
    let p = home().join(".ssh").join("known_hosts");
    p.exists().then_some(p)
}

fn home() -> PathBuf {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .unwrap_or_default()
}
