//! Client-side alert rules (ui-spec §3.4). Pure: same inputs → same alerts.

use crate::format;
use crate::model::{ActiveState, MemSample, Mount, ServiceInfo};

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
        Self { disk_warn: 0.80, disk_err: 0.90, mem_avail_warn: 0.15, mem_avail_err: 0.05 }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Inputs<'a> {
    pub services: &'a [ServiceInfo],
    pub mounts: &'a [Mount],
    pub mem: Option<&'a MemSample>,
}

/// Evaluate all rules. Output is sorted by severity, then key.
pub fn evaluate(i: Inputs<'_>, t: &Thresholds) -> Vec<Alert> {
    let mut out = Vec::new();

    for s in i.services {
        if s.active == ActiveState::Failed {
            let name = s.short_name().to_owned();
            let ago = s.state_age_s.map(|a| format!(" · {} ago", format::duration(a))).unwrap_or_default();
            out.push(Alert {
                key: format!("svc-failed:{}", s.id),
                severity: Severity::Error,
                title: format!("{} failed", s.id),
                detail: format!("result {}{ago}", s.result),
                actions: vec![AlertAction::ServiceLogs(name.clone()), AlertAction::RestartService(name)],
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
            title: format!("{} above {:.0}%", m.mount, (if sev == Severity::Error { t.disk_err } else { t.disk_warn }) * 100.0),
            detail: format!("{} of {} used ({:.0}%)", format::bytes(m.used), format::bytes(m.size), f * 100.0),
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
                detail: format!("{} available of {}", format::bytes(mem.available()), format::bytes(mem.total)),
                actions: vec![],
            });
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
            ServiceInfo { id: "nginx.service".into(), active: ActiveState::Active, ..Default::default() },
            ServiceInfo {
                id: "redis-server.service".into(),
                active: ActiveState::Failed,
                result: "exit-code".into(),
                state_age_s: Some(180),
                ..Default::default()
            },
        ];
        let mounts = [
            Mount { mount: "/".into(), size: 100, used: 62, avail: 38, ..Default::default() },
            Mount { mount: "/var/lib/mysql".into(), size: 100, used: 81, avail: 19, ..Default::default() },
        ];
        let mem = MemSample { total: 100, used: 50, ..Default::default() };
        let a = evaluate(Inputs { services: &services, mounts: &mounts, mem: Some(&mem) }, &Thresholds::default());
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].severity, Severity::Error);
        assert_eq!(a[0].detail, "result exit-code · 3m ago");
        assert_eq!(a[1].key, "disk:/var/lib/mysql");
    }
}
