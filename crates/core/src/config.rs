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

/// Import hosts from an OpenSSH client config (`~/.ssh/config`).
///
/// Concrete `Host` aliases become hosts; wildcard patterns (`*`, `?`, `!`) are
/// not hosts, but `Host *` supplies defaults. Supported keys: HostName, User,
/// Port, IdentityFile, ProxyJump (first hop). `Match` blocks and `Include` are
/// skipped. `default_user` fills hosts with no User anywhere.
pub fn parse_ssh_config(text: &str, default_user: &str) -> Vec<HostConfig> {
    #[derive(Default, Clone)]
    struct Block {
        patterns: Vec<String>,
        host_name: Option<String>,
        user: Option<String>,
        port: Option<u16>,
        identity: Option<String>,
        jump: Option<String>,
    }
    let mut blocks: Vec<Block> = Vec::new();
    let mut in_match = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // "Key value" or "Key=value"
        let (key, value) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (
                k.to_ascii_lowercase(),
                v.trim()
                    .trim_start_matches('=')
                    .trim()
                    .trim_matches('"')
                    .to_owned(),
            ),
            None => continue,
        };
        match key.as_str() {
            "host" => {
                in_match = false;
                blocks.push(Block {
                    patterns: value.split_whitespace().map(str::to_owned).collect(),
                    ..Default::default()
                });
            }
            "match" => in_match = true,
            _ if in_match => {}
            _ => {
                let Some(b) = blocks.last_mut() else { continue };
                match key.as_str() {
                    "hostname" => b.host_name = b.host_name.clone().or(Some(value)),
                    "user" => b.user = b.user.clone().or(Some(value)),
                    "port" => b.port = b.port.or(value.parse().ok()),
                    "identityfile" => b.identity = b.identity.clone().or(Some(value)),
                    "proxyjump" if value != "none" => {
                        b.jump = b
                            .jump
                            .clone()
                            .or(value.split(',').next().map(|s| s.trim().to_owned()))
                    }
                    _ => {}
                }
            }
        }
    }
    let wildcard = |p: &str| p.contains(['*', '?', '!']);
    let defaults = blocks
        .iter()
        .find(|b| b.patterns.iter().any(|p| p == "*"))
        .cloned()
        .unwrap_or_default();
    let mut out: Vec<HostConfig> = Vec::new();
    for b in &blocks {
        for alias in b.patterns.iter().filter(|p| !wildcard(p)) {
            if out.iter().any(|h| &h.name == alias) {
                continue; // first match wins, as in OpenSSH
            }
            let mut h = HostConfig::new(
                alias,
                b.host_name.as_deref().unwrap_or(alias),
                b.user
                    .as_deref()
                    .or(defaults.user.as_deref())
                    .unwrap_or(default_user),
            );
            h.port = b.port.or(defaults.port).unwrap_or(22);
            match b.identity.as_ref().or(defaults.identity.as_ref()) {
                Some(k) => {
                    h.auth = AuthMethod::Key;
                    h.key_path = k.clone();
                }
                None => h.auth = AuthMethod::Agent,
            }
            h.jump = b.jump.clone().unwrap_or_default();
            out.push(h);
        }
    }
    out
}

/// A jump host given as `[user@]host[:port]` (ProxyJump syntax).
pub fn parse_jump(s: &str) -> Option<(Option<String>, String, u16)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (user, rest) = match s.split_once('@') {
        Some((u, r)) => (Some(u.to_owned()), r),
        None => (None, s),
    };
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        // [v6] or [v6]:port
        let (h, after) = inner.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => 22,
        };
        (h, port)
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, p.parse().ok()?),
            _ => (rest, 22),
        }
    };
    (!host.is_empty()).then(|| (user, host.trim_matches(['[', ']']).to_owned(), port))
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

#[cfg(test)]
mod ssh_config_tests {
    use super::*;

    #[test]
    fn import() {
        let hosts = parse_ssh_config(
            "# comment
Host *
    User admin
    IdentityFile ~/.ssh/id_ed25519

Host prod web1
    HostName 203.0.113.10
    Port 2222

Host db-02
    HostName=198.51.100.20
    User deploy
    ProxyJump bastion,other

Host bastion
    HostName bastion.example.com
    IdentityFile ~/.ssh/bastion

Host *.internal !secret
    User nobody

Match host foo
    User ignored
",
            "me",
        );
        let names: Vec<_> = hosts.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["prod", "web1", "db-02", "bastion"]);
        let prod = &hosts[0];
        assert_eq!(
            (prod.address.as_str(), prod.port, prod.user.as_str()),
            ("203.0.113.10", 2222, "admin")
        );
        assert_eq!(
            (prod.auth, prod.key_path.as_str()),
            (AuthMethod::Key, "~/.ssh/id_ed25519")
        );
        assert_eq!(hosts[2].user, "deploy");
        assert_eq!(hosts[2].jump, "bastion");
        assert_eq!(hosts[3].key_path, "~/.ssh/bastion");
        assert!(
            parse_ssh_config("Host x\n  HostName 1.2.3.4\n", "me")[0].auth == AuthMethod::Agent
        );
    }

    #[test]
    fn jump_syntax() {
        assert_eq!(
            parse_jump("deploy@bastion:2200"),
            Some((Some("deploy".into()), "bastion".into(), 2200))
        );
        assert_eq!(parse_jump("bastion"), Some((None, "bastion".into(), 22)));
        assert_eq!(
            parse_jump("[2001:db8::1]:22").map(|j| j.1),
            Some("2001:db8::1".into())
        );
        assert_eq!(parse_jump(""), None);
    }
}
