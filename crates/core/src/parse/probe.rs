//! Output of `collector/probe.sh`: `key=value` lines (protocol §4).

use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Probe {
    pub uid: Option<u32>,
    pub user: String,
    /// `BASH_VERSION`, `None` when bash is not installed.
    pub bash: Option<String>,
    pub sudo: bool,
    /// `sudo -n true` succeeded (NOPASSWD or cached).
    pub sudo_n: bool,
    pub systemd: bool,
    pub journal_read: bool,
    /// ufw, nft, iptables, fail2ban-client, ss, docker → installed?
    pub tools: BTreeMap<String, bool>,
    /// `ID:VERSION_ID` from os-release, e.g. `ubuntu:24.04`.
    pub os: String,
    /// The probe ran to the end (`probe=done`).
    pub complete: bool,
}

impl Probe {
    pub fn is_root(&self) -> bool {
        self.uid == Some(0)
    }

    pub fn has(&self, tool: &str) -> bool {
        self.tools.get(tool).copied().unwrap_or(false)
    }
}

pub fn parse_probe(out: &str) -> Probe {
    let mut p = Probe::default();
    for line in out.lines() {
        let Some((k, v)) = line.trim().split_once('=') else {
            continue;
        };
        let flag = v == "1";
        match k {
            "uid" => p.uid = v.parse().ok(),
            "user" => p.user = v.to_owned(),
            "bash" => p.bash = (!v.is_empty()).then(|| v.to_owned()),
            "sudo" => p.sudo = flag,
            "sudo_n" => p.sudo_n = flag,
            "systemd" => p.systemd = flag,
            "journal_read" => p.journal_read = flag,
            "os" => p.os = v.to_owned(),
            "probe" => p.complete = v == "done",
            "ufw" | "nft" | "iptables" | "fail2ban-client" | "ss" | "docker" => {
                p.tools.insert(k.to_owned(), flag);
            }
            _ => {}
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe() {
        let p = parse_probe(
            "uid=1000\nuser=deploy\nbash=5.2.21(1)-release\nsudo=1\nsudo_n=0\nsystemd=1\njournal_read=0\n\
             ufw=1\nnft=0\niptables=1\nfail2ban-client=1\nss=1\ndocker=0\nos=ubuntu:24.04\nprobe=done\n",
        );
        assert_eq!(p.uid, Some(1000));
        assert!(!p.is_root());
        assert_eq!(p.bash.as_deref(), Some("5.2.21(1)-release"));
        assert!(p.sudo && !p.sudo_n && p.systemd && !p.journal_read);
        assert!(p.has("ufw") && !p.has("docker") && !p.has("unknown"));
        assert_eq!(p.os, "ubuntu:24.04");
        assert!(p.complete);
    }

    #[test]
    fn missing_bash_and_truncated() {
        let p = parse_probe("uid=0\nbash=\n");
        assert!(p.is_root());
        assert_eq!(p.bash, None);
        assert!(!p.complete);
    }
}
