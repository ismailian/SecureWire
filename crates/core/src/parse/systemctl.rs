use super::num;
use crate::model::{ActiveState, ServiceInfo};

/// `systemctl show -p Id,LoadState,ActiveState,SubState,MainPID,MemoryCurrent,CPUUsageNSec,TasksCurrent,
/// NRestarts,Result,ActiveEnterTimestampMonotonic,InactiveEnterTimestampMonotonic <units…>`
///
/// Units are separated by blank lines. `uptime_s` (remote) turns monotonic
/// timestamps into "time in current state".
pub fn parse_systemctl_show(payload: &str, uptime_s: f64) -> Vec<ServiceInfo> {
    let mut out = Vec::new();
    let mut cur = ServiceInfo::default();
    let (mut active_enter, mut inactive_enter) = (0u64, 0u64);
    let mut not_found = false;
    let mut flush = |cur: &mut ServiceInfo, ae: &mut u64, ie: &mut u64, nf: &mut bool| {
        if std::mem::take(nf) {
            cur.sub = "not-found".into();
        }
        // An alias (sshd.service → ssh.service) reports its canonical Id: show it once.
        if !cur.id.is_empty() && out.iter().any(|s: &ServiceInfo| s.id == cur.id) {
            *cur = ServiceInfo::default();
        }
        if !cur.id.is_empty() {
            let mono = if matches!(cur.active, ActiveState::Active | ActiveState::Reloading) {
                *ae
            } else {
                *ie
            };
            if mono > 0 && uptime_s > 0.0 {
                cur.state_age_s = Some((uptime_s - mono as f64 / 1e6).max(0.0) as u64);
            }
            out.push(std::mem::take(cur));
        }
        *ae = 0;
        *ie = 0;
    };
    for line in payload.lines() {
        if line.trim().is_empty() {
            flush(
                &mut cur,
                &mut active_enter,
                &mut inactive_enter,
                &mut not_found,
            );
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "Id" => cur.id = v.to_owned(),
            "LoadState" => not_found = v == "not-found",
            "ActiveState" => cur.active = ActiveState::parse(v),
            "SubState" => cur.sub = v.to_owned(),
            "MainPID" => cur.main_pid = num(v).unwrap_or(0),
            "MemoryCurrent" => cur.memory = set(v),
            "CPUUsageNSec" => cur.cpu_ns = set(v),
            "TasksCurrent" => cur.tasks = set::<u64>(v).and_then(|t| u32::try_from(t).ok()),
            "NRestarts" => cur.nrestarts = num(v).unwrap_or(0),
            "Result" => cur.result = v.to_owned(),
            "ActiveEnterTimestampMonotonic" => active_enter = num(v).unwrap_or(0),
            "InactiveEnterTimestampMonotonic" => inactive_enter = num(v).unwrap_or(0),
            _ => {}
        }
    }
    flush(
        &mut cur,
        &mut active_enter,
        &mut inactive_enter,
        &mut not_found,
    );
    out
}

/// systemd prints `[not set]` or u64::MAX for unavailable accounting values.
fn set<T: std::str::FromStr + PartialEq + TryFrom<u64>>(v: &str) -> Option<T> {
    let n: u64 = num(v)?;
    if n == u64::MAX {
        return None;
    }
    T::try_from(n).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn show_two_units() {
        let v = parse_systemctl_show(
            "Id=nginx.service
ActiveState=active
SubState=running
MainPID=1123
MemoryCurrent=39845888
CPUUsageNSec=123456789
TasksCurrent=5
NRestarts=0
Result=success
ActiveEnterTimestampMonotonic=1000000

Id=redis-server.service
ActiveState=failed
SubState=failed
MainPID=0
MemoryCurrent=[not set]
CPUUsageNSec=18446744073709551615
NRestarts=3
Result=exit-code
ActiveEnterTimestampMonotonic=0
InactiveEnterTimestampMonotonic=99000000
",
            100.0,
        );
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].short_name(), "nginx");
        assert_eq!(v[0].memory, Some(39845888));
        assert_eq!(v[0].tasks, Some(5));
        assert_eq!(v[0].state_age_s, Some(99));
        assert_eq!(v[1].active, ActiveState::Failed);
        assert_eq!(v[1].memory, None);
        assert_eq!(v[1].cpu_ns, None);
        assert_eq!(v[1].nrestarts, 3);
        assert_eq!(v[1].state_age_s, Some(1));
    }

    // Seen on Ubuntu 26.04: watching both names of an alias, plus a unit that does not exist.
    #[test]
    fn aliases_once_and_not_found_flagged() {
        let v = parse_systemctl_show(
            "Id=ssh.service
LoadState=loaded
ActiveState=active
SubState=running

Id=ssh.service
LoadState=loaded
ActiveState=active
SubState=running

Id=nope.service
LoadState=not-found
ActiveState=inactive
SubState=dead
",
            100.0,
        );
        assert_eq!(v.len(), 2, "{v:?}");
        assert_eq!(v[0].id, "ssh.service");
        assert_eq!(v[1].sub, "not-found");
    }
}
