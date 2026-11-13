//! `hosts.toml` types (CLAUDE.md §7). Pure (de)serialization; file I/O lives in the app.
//! Secrets are never part of this file: passwords and passphrases are prompted.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Agent,
    #[default]
    Key,
    Password,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServiceMode {
    #[default]
    Live,
    Poll,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Services {
    pub mode: ServiceMode,
    pub poll_secs: u32,
    pub units: Vec<String>,
}

impl Default for Services {
    fn default() -> Self {
        Self {
            mode: ServiceMode::Live,
            poll_secs: 30,
            units: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogSourceConfig {
    pub id: String,
    /// `journal` | `file` | `sudo-file`
    pub kind: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    #[serde(default)]
    pub color: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostConfig {
    pub name: String,
    pub address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub auth: AuthMethod,
    /// For `auth = "key"`. Empty → `~/.ssh/id_ed25519`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub jump: String,
    #[serde(default)]
    pub services: Services,
    #[serde(default, rename = "logs", skip_serializing_if = "Vec::is_empty")]
    pub logs: Vec<LogSourceConfig>,
    /// Lines of history each log channel starts with.
    #[serde(default = "default_backlog")]
    pub log_backlog: u32,
    /// Log lines kept in memory for this host.
    #[serde(default = "default_log_cap")]
    pub log_cap: u32,
}

fn default_port() -> u16 {
    22
}

fn default_backlog() -> u32 {
    200
}

fn default_log_cap() -> u32 {
    10_000
}

impl HostConfig {
    pub fn new(name: &str, address: &str, user: &str) -> Self {
        Self {
            name: name.into(),
            address: address.into(),
            port: 22,
            user: user.into(),
            auth: AuthMethod::Key,
            key_path: String::new(),
            jump: String::new(),
            services: Services::default(),
            logs: vec![],
            log_backlog: default_backlog(),
            log_cap: default_log_cap(),
        }
    }

    /// Basic validation for the connect dialog. Returns a user-facing message.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("Name is required".into());
        }
        if self.address.trim().is_empty() || self.address.contains(char::is_whitespace) {
            return Err("Host must be a hostname or IP address".into());
        }
        if self.port == 0 {
            return Err("Port must be 1–65535".into());
        }
        if self.user.trim().is_empty() || self.user.contains(char::is_whitespace) {
            return Err("User is required".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostsFile {
    #[serde(default, rename = "host")]
    pub hosts: Vec<HostConfig>,
}

impl HostsFile {
    pub fn parse(s: &str) -> Result<Self, String> {
        toml::from_str(s).map_err(|e| e.to_string())
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    pub fn upsert(&mut self, h: HostConfig) {
        match self.hosts.iter_mut().find(|x| x.name == h.name) {
            Some(x) => *x = h,
            None => self.hosts.push(h),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let f = HostsFile::parse(
            r#"
[[host]]
name = "prod-web-01"
address = "203.0.113.10"
user = "root"
auth = "agent"

[host.services]
mode = "poll"
units = ["nginx.service"]

[[host.logs]]
id = "nginx"
kind = "journal"
target = "nginx.service"
"#,
        )
        .unwrap();
        let h = &f.hosts[0];
        assert_eq!(h.port, 22);
        assert_eq!(h.auth, AuthMethod::Agent);
        assert_eq!(h.services.mode, ServiceMode::Poll);
        assert_eq!(h.services.poll_secs, 30);
        assert_eq!(h.logs[0].target, "nginx.service");
        assert_eq!(HostsFile::parse(&f.to_toml()).unwrap(), f);
    }

    #[test]
    fn validation() {
        assert!(
            HostConfig::new("a", "203.0.113.10", "root")
                .validate()
                .is_ok()
        );
        assert!(HostConfig::new("", "h", "u").validate().is_err());
        assert!(HostConfig::new("a", "bad host", "u").validate().is_err());
    }
}
