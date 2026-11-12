//! Client-side alert rules (ui-spec §3.4). Pure: same inputs → same alerts.

use crate::format;
use crate::model::{ActiveState, Firewall, Listener, MemSample, Mount, ServiceInfo};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Error,
    Warn,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertAction {
    ServiceLogs(String),
    RestartService(String),
    LargestDirs(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// Stable identity so the UI can track "new" vs "still active".
    pub key: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub actions: Vec<AlertAction>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub disk_warn: f32,
    pub disk_err: f32,
    pub mem_avail_warn: f32,
    pub mem_avail_err: f32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            disk_warn: 0.80,
            disk_err: 0.90,
            mem_avail_warn: 0.15,
            mem_avail_err: 0.05,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Inputs<'a> {
    pub services: &'a [ServiceInfo],
    pub mounts: &'a [Mount],
    pub mem: Option<&'a MemSample>,
    pub listeners: &'a [Listener],
    pub firewall: Option<&'a Firewall>,
}

/// Evaluate all rules. Output is sorted by severity, then key.
pub fn evaluate(i: Inputs<'_>, t: &Thresholds) -> Vec<Alert> {
    let mut out = Vec::new();

    for s in i.services {
        if s.active == ActiveState::Failed {
            let name = s.short_name().to_owned();
            let ago = s
                .state_age_s
                .map(|a| format!(" · {} ago", format::duration(a)))
                .unwrap_or_default();
            out.push(Alert {
                key: format!("svc-failed:{}", s.id),
                severity: Severity::Error,
                title: format!("{} failed", s.id),
                detail: format!("result {}{ago}", s.result),
                actions: vec![
                    AlertAction::ServiceLogs(name.clone()),
                    AlertAction::RestartService(name),
                ],
            });
        }
    }

    for m in i.mounts {
        let f = m.frac();
        let sev = if f >= t.disk_err {
            Severity::Error
        } else if f >= t.disk_warn {
            Severity::Warn
        } else {
            continue;
        };
        out.push(Alert {
            key: format!("disk:{}", m.mount),
            severity: sev,
            title: format!(
                "{} above {:.0}%",
                m.mount,
                (if sev == Severity::Error {
                    t.disk_err
                } else {
                    t.disk_warn
                }) * 100.0
            ),
            detail: format!(
                "{} of {} used ({:.0}%)",
                format::bytes(m.used),
                format::bytes(m.size),
                f * 100.0
            ),
            actions: vec![AlertAction::LargestDirs(m.mount.clone())],
        });
    }

    if let Some(mem) = i.mem.filter(|m| m.total > 0) {
        let avail = mem.available() as f32 / mem.total as f32;
        let sev = if avail <= t.mem_avail_err {
            Some(Severity::Error)
        } else if avail <= t.mem_avail_warn {
            Some(Severity::Warn)
        } else {
            None
        };
        if let Some(severity) = sev {
            out.push(Alert {
                key: "mem".into(),
                severity,
                title: "Memory running low".into(),
                detail: format!(
                    "{} available of {}",
                    format::bytes(mem.available()),
                    format::bytes(mem.total)
                ),
                actions: vec![],
            });
        }
    }

    // A public listener the firewall doesn't mention (only when the firewall is active and
    // denies incoming by default, i.e. when the rules are the source of truth).
    if let Some(fw) = i
        .firewall
        .filter(|f| f.active && matches!(f.incoming.as_str(), "deny" | "drop" | "reject"))
    {
        let mut seen = std::collections::BTreeSet::new();
        for l in i
            .listeners
            .iter()
            .filter(|l| l.is_public() && !fw.allows_port(l.port))
        {
            if seen.insert(l.port) {
                out.push(Alert {
                    key: format!("listener:{}", l.port),
                    severity: Severity::Warn,
                    title: format!("{} listening on {}:{} without a firewall rule", if l.process.is_empty() { "A service" } else { &l.process }, l.addr, l.port),
                    detail: format!("{} is bound to a public address but no {} rule allows it (default: {} incoming)", l.proto, fw.backend, fw.incoming),
                    actions: vec![],
                });
            }
        }
    }

    out.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.key.cmp(&b.key)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        let services = [
            ServiceInfo {
                id: "nginx.service".into(),
                active: ActiveState::Active,
                ..Default::default()
            },
            ServiceInfo {
                id: "redis-server.service".into(),
                active: ActiveState::Failed,
                result: "exit-code".into(),
                state_age_s: Some(180),
                ..Default::default()
            },
        ];
        let mounts = [
            Mount {
                mount: "/".into(),
                size: 100,
                used: 62,
                avail: 38,
                ..Default::default()
            },
            Mount {
                mount: "/var/lib/mysql".into(),
                size: 100,
                used: 81,
                avail: 19,
                ..Default::default()
            },
        ];
        let mem = MemSample {
            total: 100,
            used: 50,
            ..Default::default()
        };
        let a = evaluate(
            Inputs {
                services: &services,
                mounts: &mounts,
                mem: Some(&mem),
                ..Default::default()
            },
            &Thresholds::default(),
        );
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].severity, Severity::Error);
        assert_eq!(a[0].detail, "result exit-code · 3m ago");
        assert_eq!(a[1].key, "disk:/var/lib/mysql");
    }
}

#[cfg(test)]
mod m3_tests {
    use super::*;
    use crate::model::FwRule;

    #[test]
    fn unexpected_public_listener() {
        let listeners = [
            Listener {
                proto: "tcp".into(),
                addr: "0.0.0.0".into(),
                port: 22,
                process: "sshd".into(),
            },
            Listener {
                proto: "tcp".into(),
                addr: "0.0.0.0".into(),
                port: 6379,
                process: "redis-server".into(),
            },
            Listener {
                proto: "tcp".into(),
                addr: "127.0.0.1".into(),
                port: 3306,
                process: String::new(),
            },
        ];
        let fw = Firewall {
            backend: "ufw".into(),
            active: true,
            incoming: "deny".into(),
            rules: vec![FwRule {
                to: "22/tcp".into(),
                action: "ALLOW IN".into(),
                from: "Anywhere".into(),
            }],
            ..Default::default()
        };
        let a = evaluate(
            Inputs {
                listeners: &listeners,
                firewall: Some(&fw),
                ..Default::default()
            },
            &Thresholds::default(),
        );
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].key, "listener:6379");
        // Inactive firewall → no opinion.
        let off = Firewall {
            active: false,
            ..fw
        };
        assert!(
            evaluate(
                Inputs {
                    listeners: &listeners,
                    firewall: Some(&off),
                    ..Default::default()
                },
                &Thresholds::default()
            )
            .is_empty()
        );
    }
}
