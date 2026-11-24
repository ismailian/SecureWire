//! Server actions (protocol §7): every command is a fixed template filled with
//! validated, quoted arguments. Nothing user- or server-supplied is ever
//! concatenated into a shell string unchecked.

use std::net::IpAddr;

use crate::shell::{is_valid_path, is_valid_unit, shell_quote};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    ServiceStart(String),
    ServiceStop(String),
    ServiceRestart(String),
    ServiceReload(String),
    Ban {
        jail: String,
        ip: String,
    },
    Unban {
        jail: String,
        ip: String,
    },
    Kill {
        pid: u32,
        force: bool,
    },
    LargestDirs(String),
    /// Sockets on a local or remote port, with their processes.
    WhoOnPort(u16),
    /// File browser operation (protocol §15); always runs as the login user.
    Files(crate::files::FsOp),
}

/// fail2ban jail names: letters, digits, `.`, `_`, `-` (1–64).
pub fn is_valid_jail(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl Action {
    /// The exact command (without the sudo prefix) or why the arguments are refused.
    pub fn command(&self) -> Result<String, String> {
        let unit = |u: &str| {
            if is_valid_unit(u) {
                Ok(shell_quote(u))
            } else {
                Err(format!("Not a valid unit name: {u:?}"))
            }
        };
        let ip = |s: &str| {
            s.trim()
                .parse::<IpAddr>()
                .map(|a| shell_quote(&a.to_string()))
                .map_err(|_| format!("Not an IP address: {s:?}"))
        };
        let jail = |j: &str| {
            if is_valid_jail(j) {
                Ok(shell_quote(j))
            } else {
                Err(format!("Not a valid jail name: {j:?}"))
            }
        };
        Ok(match self {
            Action::Files(op) => op.command()?,
            Action::ServiceStart(u) => format!("systemctl start -- {}", unit(u)?),
            Action::ServiceStop(u) => format!("systemctl stop -- {}", unit(u)?),
            Action::ServiceRestart(u) => format!("systemctl restart -- {}", unit(u)?),
            Action::ServiceReload(u) => format!("systemctl reload -- {}", unit(u)?),
            Action::Ban { jail: j, ip: a } => {
                format!("fail2ban-client set {} banip {}", jail(j)?, ip(a)?)
            }
            Action::Unban { jail: j, ip: a } => {
                format!("fail2ban-client set {} unbanip {}", jail(j)?, ip(a)?)
            }
            Action::Kill { pid, force } => {
                if *pid <= 1 {
                    return Err("Refusing to signal PID 0/1".into());
                }
                format!("kill -{} {pid}", if *force { "KILL" } else { "TERM" })
            }
            Action::WhoOnPort(0) => return Err("Port must be 1–65535".into()),
            Action::WhoOnPort(port) => {
                format!("ss -tunap '( sport = :{port} or dport = :{port} )'")
            }
            Action::LargestDirs(p) => {
                if !is_valid_path(p) {
                    return Err(format!("Not an absolute path: {p:?}"));
                }
                format!(
                    "du -xh --max-depth=1 -- {} 2>/dev/null | sort -rh | head -n 25",
                    shell_quote(p)
                )
            }
        })
    }

    /// Changes the server (asks for confirmation, shown in red).
    pub fn destructive(&self) -> bool {
        match self {
            Action::Files(op) => op.destructive(),
            _ => !matches!(self, Action::LargestDirs(_) | Action::WhoOnPort(_)),
        }
    }

    /// Never prefixed with sudo, even when the session has it (file browser operations
    /// act with the login user's own permissions, like the terminal).
    pub fn as_user(&self) -> bool {
        matches!(self, Action::Files(_))
    }

    /// Still useful without sudo (sees less): runs plain when the session has no privilege.
    /// Everything else needs root and is refused up front instead.
    pub fn works_unprivileged(&self) -> bool {
        matches!(
            self,
            Action::LargestDirs(_) | Action::WhoOnPort(_) | Action::Files(_)
        )
    }

    /// Button / title text: "Restart nginx".
    pub fn verb(&self) -> String {
        let short = |u: &str| u.strip_suffix(".service").unwrap_or(u).to_owned();
        match self {
            Action::Files(op) => op.verb(),
            Action::ServiceStart(u) => format!("Start {}", short(u)),
            Action::ServiceStop(u) => format!("Stop {}", short(u)),
            Action::ServiceRestart(u) => format!("Restart {}", short(u)),
            Action::ServiceReload(u) => format!("Reload {}", short(u)),
            Action::Ban { ip, jail } => format!("Ban {ip} ({jail})"),
            Action::Unban { ip, jail } => format!("Unban {ip} ({jail})"),
            Action::Kill { pid, force } => format!(
                "{} process {pid}",
                if *force { "Kill" } else { "Terminate" }
            ),
            Action::LargestDirs(p) => format!("Largest directories under {p}"),
            Action::WhoOnPort(p) => format!("Who's on port {p}"),
        }
    }

    /// Which collector section to refresh after it ran.
    pub fn refreshes(&self) -> Option<crate::Section> {
        use crate::Section;
        match self {
            Action::ServiceStart(_)
            | Action::ServiceStop(_)
            | Action::ServiceRestart(_)
            | Action::ServiceReload(_) => Some(Section::Svc),
            Action::Ban { .. } | Action::Unban { .. } => Some(Section::F2b),
            Action::Kill { .. } => Some(Section::Ps),
            Action::LargestDirs(_) | Action::WhoOnPort(_) | Action::Files(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates() {
        assert_eq!(
            Action::ServiceRestart("nginx.service".into())
                .command()
                .unwrap(),
            "systemctl restart -- 'nginx.service'"
        );
        assert_eq!(
            Action::Ban {
                jail: "sshd".into(),
                ip: " 198.51.100.7 ".into()
            }
            .command()
            .unwrap(),
            "fail2ban-client set 'sshd' banip '198.51.100.7'"
        );
        assert_eq!(
            Action::Unban {
                jail: "sshd".into(),
                ip: "2001:db8::1".into()
            }
            .command()
            .unwrap(),
            "fail2ban-client set 'sshd' unbanip '2001:db8::1'"
        );
        assert_eq!(
            Action::Kill {
                pid: 4242,
                force: false
            }
            .command()
            .unwrap(),
            "kill -TERM 4242"
        );
        assert!(
            Action::LargestDirs("/var/lib/mysql".into())
                .command()
                .unwrap()
                .contains("-- '/var/lib/mysql'")
        );
        assert_eq!(
            Action::ServiceRestart("redis-server.service".into()).verb(),
            "Restart redis-server"
        );
        assert_eq!(
            Action::WhoOnPort(443).command().unwrap(),
            "ss -tunap '( sport = :443 or dport = :443 )'"
        );
        assert!(Action::WhoOnPort(0).command().is_err());
        assert!(
            !Action::WhoOnPort(22).destructive()
                && Action::Kill {
                    pid: 9,
                    force: false
                }
                .destructive()
        );
    }

    #[test]
    fn hostile_inputs_are_refused_or_quoted() {
        for bad in [
            "nginx; rm -rf /",
            "$(reboot)",
            "`id`",
            "a b",
            "-help",
            "x\ny",
            "a'b",
            "",
        ] {
            assert!(
                Action::ServiceStop(bad.into()).command().is_err(),
                "{bad:?}"
            );
            assert!(
                Action::Ban {
                    jail: bad.into(),
                    ip: "1.2.3.4".into()
                }
                .command()
                .is_err(),
                "{bad:?}"
            );
            assert!(
                Action::Ban {
                    jail: "sshd".into(),
                    ip: bad.into()
                }
                .command()
                .is_err(),
                "{bad:?}"
            );
        }
        assert!(
            Action::Kill {
                pid: 1,
                force: true
            }
            .command()
            .is_err()
        );
        assert!(Action::LargestDirs("relative".into()).command().is_err());
        // Paths are quoted, never interpreted.
        let c = Action::LargestDirs("/tmp/$(reboot) x".into())
            .command()
            .unwrap();
        assert!(c.contains("'/tmp/$(reboot) x'"));
    }
}
