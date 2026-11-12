//! M3 sections: ports, conns, fw, f2b, auth, timers, and the unit picker list.

use super::num;
use crate::model::{AuthStats, Conn, Firewall, FwRule, Jail, Listener, Scheduled, Timer, UnitInfo};

/// Split `host:port` / `[v6]:port` / `*:port`; interface suffixes (`%lo`) dropped.
fn split_addr(s: &str) -> Option<(String, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.split('%').next().unwrap_or(host);
    Some((host.trim_matches(['[', ']']).to_owned(), port))
}

fn process_name(tok: &str) -> String {
    // users:(("sshd",pid=812,fd=3),("sshd",pid=813,fd=3))
    tok.split('"').nth(1).unwrap_or("").to_owned()
}

fn is_addr(tok: &str) -> bool {
    !tok.starts_with("users:")
        && tok.contains(':')
        && tok
            .rsplit(':')
            .next()
            .is_some_and(|p| p == "*" || p.parse::<u16>().is_ok())
}

/// `ss -Htlnu[p]`: tokens are located by shape, so it works with or without
/// the Netid/State columns and the process column.
pub fn parse_listeners(payload: &str) -> Vec<Listener> {
    let mut out: Vec<Listener> = payload
        .lines()
        .filter_map(|line| {
            let toks: Vec<&str> = line.split_whitespace().collect();
            let proto = match toks.first() {
                Some(&p @ ("tcp" | "udp" | "tcp6" | "udp6")) => p.trim_end_matches('6').to_owned(),
                _ => "tcp".to_owned(),
            };
            let local = toks.iter().find(|t| is_addr(t))?;
            let (addr, port) = split_addr(local)?;
            let process = toks
                .iter()
                .find(|t| t.starts_with("users:"))
                .map(|t| process_name(t))
                .unwrap_or_default();
            Some(Listener {
                proto,
                addr,
                port,
                process,
            })
        })
        .collect();
    out.sort_by(|a, b| (a.port, &a.proto, &a.addr).cmp(&(b.port, &b.proto, &b.addr)));
    out.dedup();
    out
}

/// `ss -Htn[p] state established` (no State column with a state filter).
pub fn parse_conns(payload: &str) -> Vec<Conn> {
    payload
        .lines()
        .filter_map(|line| {
            let toks: Vec<&str> = line.split_whitespace().collect();
            let mut addrs = toks.iter().filter(|t| is_addr(t));
            let local = addrs.next()?.to_string();
            let peer = addrs.next()?.to_string();
            let process = toks
                .iter()
                .find(|t| t.starts_with("users:"))
                .map(|t| process_name(t))
                .unwrap_or_default();
            Some(Conn {
                local,
                peer,
                process,
            })
        })
        .collect()
}

/// Split a table row on runs of 2+ spaces (ufw, systemctl plain output).
fn columns(line: &str) -> Vec<String> {
    line.split("  ")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// `fw` payload: first line `backend <ufw|nftables|iptables>`, then that tool's output.
pub fn parse_firewall(payload: &str) -> Firewall {
    let mut lines = payload.lines();
    let backend = lines
        .next()
        .and_then(|l| l.strip_prefix("backend "))
        .unwrap_or("")
        .trim()
        .to_owned();
    let body: Vec<&str> = lines.collect();
    let mut fw = Firewall {
        backend: backend.clone(),
        ..Default::default()
    };
    match backend.as_str() {
        "ufw" => {
            let mut in_table = false;
            for l in &body {
                if let Some(s) = l.strip_prefix("Status:") {
                    fw.active = s.trim() == "active";
                } else if let Some(d) = l.strip_prefix("Default:") {
                    // deny (incoming), allow (outgoing), disabled (routed)
                    for part in d.split(',') {
                        let mut it = part.split_whitespace();
                        let (Some(policy), Some(dir)) = (it.next(), it.next()) else {
                            continue;
                        };
                        match dir.trim_matches(['(', ')']) {
                            "incoming" => fw.incoming = policy.into(),
                            "outgoing" => fw.outgoing = policy.into(),
                            "routed" => fw.routed = policy.into(),
                            _ => {}
                        }
                    }
                } else if l.starts_with("--") {
                    in_table = true;
                } else if in_table && !l.trim().is_empty() {
                    let c = columns(l);
                    if c.len() >= 3 {
                        fw.rules.push(FwRule {
                            to: c[0].clone(),
                            action: c[1].clone(),
                            from: c[2].clone(),
                        });
                    }
                }
            }
        }
        "iptables" => {
            fw.active = true;
            for l in &body {
                let t: Vec<&str> = l.split_whitespace().collect();
                match t.as_slice() {
                    ["-P", chain, policy, ..] => match *chain {
                        "INPUT" => fw.incoming = policy.to_ascii_lowercase(),
                        "OUTPUT" => fw.outgoing = policy.to_ascii_lowercase(),
                        "FORWARD" => fw.routed = policy.to_ascii_lowercase(),
                        _ => {}
                    },
                    ["-A", "INPUT", rest @ ..] => {
                        let val = |flag: &str| {
                            rest.iter()
                                .position(|x| *x == flag)
                                .and_then(|i| rest.get(i + 1))
                                .copied()
                        };
                        let target = val("-j").unwrap_or("?").to_owned();
                        let proto = val("-p").unwrap_or("");
                        let to = match (val("--dport").or(val("--dports")), proto) {
                            (Some(p), "") => p.to_owned(),
                            (Some(p), pr) => format!("{p}/{pr}"),
                            (None, _) => rest.join(" "),
                        };
                        let from = val("-s").unwrap_or("Anywhere").to_owned();
                        fw.rules.push(FwRule {
                            to,
                            action: target,
                            from,
                        });
                    }
                    _ => {}
                }
            }
        }
        "nftables" => {
            fw.active = body.iter().any(|l| l.contains("chain "));
            for l in &body {
                let l = l.trim();
                if l.contains("hook input") {
                    if let Some(p) = l.split("policy").nth(1) {
                        fw.incoming = p.trim().trim_end_matches(';').trim().to_owned();
                    }
                } else if l.contains("hook output") {
                    if let Some(p) = l.split("policy").nth(1) {
                        fw.outgoing = p.trim().trim_end_matches(';').trim().to_owned();
                    }
                } else if l.contains(" dport ")
                    && (l.ends_with("accept") || l.ends_with("drop") || l.ends_with("reject"))
                {
                    let t: Vec<&str> = l.split_whitespace().collect();
                    let after = |k: &str| {
                        t.iter()
                            .position(|x| *x == k)
                            .and_then(|i| t.get(i + 1))
                            .copied()
                    };
                    let proto = t
                        .first()
                        .copied()
                        .filter(|p| *p == "tcp" || *p == "udp")
                        .unwrap_or("");
                    let port = after("dport").unwrap_or("?");
                    let to = if proto.is_empty() {
                        port.to_owned()
                    } else {
                        format!("{port}/{proto}")
                    };
                    let from = after("saddr").unwrap_or("Anywhere").to_owned();
                    fw.rules.push(FwRule {
                        to,
                        action: t.last().unwrap_or(&"").to_string(),
                        from,
                    });
                }
            }
        }
        _ => {}
    }
    fw
}

/// `f2b` payload: `fail2ban-client status`, then for each jail a `@@jail <name>`
/// marker followed by `fail2ban-client status <name>`.
pub fn parse_f2b(payload: &str) -> Vec<Jail> {
    let mut jails: Vec<Jail> = Vec::new();
    for line in payload.lines() {
        if let Some(name) = line.strip_prefix("@@jail ") {
            jails.push(Jail {
                name: name.trim().to_owned(),
                ..Default::default()
            });
            continue;
        }
        let Some(j) = jails.last_mut() else { continue };
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k = k.trim_start_matches(['|', '`', '-', ' ']).trim();
        match k {
            "Currently failed" => j.currently_failed = num(v).unwrap_or(0),
            "Total failed" => j.total_failed = num(v).unwrap_or(0),
            "Currently banned" => j.currently_banned = num(v).unwrap_or(0),
            "Total banned" => j.total_banned = num(v).unwrap_or(0),
            "Banned IP list" => j.banned_ips = v.split_whitespace().map(str::to_owned).collect(),
            _ => {}
        }
    }
    jails
}

/// `auth` payload: line 1 = 48 counts (oldest first); then `count ip` lines.
pub fn parse_auth(payload: &str) -> AuthStats {
    let mut lines = payload.lines();
    let buckets = lines
        .next()
        .map(|l| l.split_whitespace().filter_map(num).collect())
        .unwrap_or_default();
    let top = lines
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let n = num(it.next()?)?;
            Some((it.next()?.to_owned(), n))
        })
        .collect();
    AuthStats { buckets, top }
}

/// `timers` payload: `now <epoch_s>`, then `systemctl list-timers -o json`
/// (or the plain table on older systemd), then `@@cron` and `crontab -l`.
pub fn parse_timers(payload: &str) -> Scheduled {
    let mut now_s: u64 = 0;
    let mut body = String::new();
    let mut cron = Vec::new();
    let mut in_cron = false;
    for line in payload.lines() {
        if let Some(n) = line.strip_prefix("now ") {
            now_s = num(n).unwrap_or(0);
        } else if line == "@@cron" {
            in_cron = true;
        } else if in_cron {
            let t = line.trim();
            if !t.is_empty() && !t.starts_with('#') && !t.contains("no crontab") {
                cron.push(t.to_owned());
            }
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }
    let timers = if body.trim_start().starts_with('[') {
        timers_json(&body, now_s)
    } else {
        body.lines()
            .filter_map(|l| {
                let c = columns(l);
                // NEXT LEFT LAST PASSED UNIT ACTIVATES (missing values are "-" or "n/a")
                let (unit, activates) = (c.get(c.len().checked_sub(2)?)?, c.last()?);
                unit.ends_with(".timer").then(|| Timer {
                    unit: unit.clone(),
                    activates: activates.clone(),
                    next_in_s: None,
                    last_ago_s: None,
                })
            })
            .collect()
    };
    Scheduled {
        timers,
        cron_jobs: cron,
    }
}

fn timers_json(body: &str, now_s: u64) -> Vec<Timer> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return vec![];
    };
    let now_us = now_s.saturating_mul(1_000_000);
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| {
                    let us = |k: &str| t.get(k).and_then(|x| x.as_u64()).filter(|&x| x > 0);
                    Some(Timer {
                        unit: t.get("unit")?.as_str()?.to_owned(),
                        activates: t
                            .get("activates")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_owned(),
                        next_in_s: us("next").map(|n| n.saturating_sub(now_us) / 1_000_000),
                        last_ago_s: us("last").map(|l| now_us.saturating_sub(l) / 1_000_000),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `systemctl list-units --type=service,timer --all --no-legend --plain --no-pager`
pub fn parse_units(payload: &str) -> Vec<UnitInfo> {
    payload
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace().skip_while(|t| *t == "●" || *t == "*");
            let name = it.next()?.trim_start_matches('●').to_owned();
            if !(name.ends_with(".service") || name.ends_with(".timer"))
                || !crate::shell::is_valid_unit(&name)
            {
                return None;
            }
            let _load = it.next()?;
            let active = it.next()?.to_owned();
            let sub = it.next()?.to_owned();
            let description = it.collect::<Vec<_>>().join(" ");
            Some(UnitInfo {
                name,
                active,
                sub,
                description,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listeners() {
        let v = parse_listeners(
            "tcp   LISTEN 0      4096       0.0.0.0:22        0.0.0.0:*    users:((\"sshd\",pid=812,fd=3))
tcp   LISTEN 0      511           [::]:443          [::]:*
tcp   LISTEN 0      80       127.0.0.1:3306      0.0.0.0:*
udp   UNCONN 0      0    127.0.0.53%lo:53        0.0.0.0:*
tcp   LISTEN 0      511              *:6379             *:*",
        );
        assert_eq!(v.len(), 5);
        assert_eq!(
            v[0],
            Listener {
                proto: "tcp".into(),
                addr: "0.0.0.0".into(),
                port: 22,
                process: "sshd".into()
            }
        );
        let mysql = v.iter().find(|l| l.port == 3306).unwrap();
        assert!(!mysql.is_public());
        let dns = v.iter().find(|l| l.port == 53).unwrap();
        assert_eq!(
            (dns.proto.as_str(), dns.addr.as_str()),
            ("udp", "127.0.0.53")
        );
        assert!(v.iter().find(|l| l.port == 6379).unwrap().is_public());
    }

    #[test]
    fn conns_without_state_column() {
        let v = parse_conns(
            "0      0      203.0.113.10:22      198.51.100.24:50412 users:((\"sshd\",pid=1,fd=4))
0      36     [::ffff:203.0.113.10]:443 [::ffff:192.0.2.77]:61022",
        );
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].peer, "198.51.100.24:50412");
        assert_eq!(v[0].process, "sshd");
    }

    #[test]
    fn ufw() {
        let fw = parse_firewall(
            "backend ufw
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80,443/tcp                 ALLOW IN    Anywhere
3306                       ALLOW IN    10.0.0.0/24
22/tcp (v6)                ALLOW IN    Anywhere (v6)",
        );
        assert!(fw.active);
        assert_eq!(
            (
                fw.incoming.as_str(),
                fw.outgoing.as_str(),
                fw.routed.as_str()
            ),
            ("deny", "allow", "disabled")
        );
        assert_eq!(fw.rules.len(), 4);
        assert_eq!(
            fw.rules[1],
            FwRule {
                to: "80,443/tcp".into(),
                action: "ALLOW IN".into(),
                from: "Anywhere".into()
            }
        );
        assert!(fw.allows_port(443) && fw.allows_port(22) && !fw.allows_port(6379));
    }

    #[test]
    fn iptables_and_nft() {
        let fw = parse_firewall(
            "backend iptables\n-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -s 10.0.0.0/24 -p tcp --dport 3306 -j ACCEPT",
        );
        assert_eq!(fw.incoming, "drop");
        assert_eq!(
            fw.rules[1],
            FwRule {
                to: "3306/tcp".into(),
                action: "ACCEPT".into(),
                from: "10.0.0.0/24".into()
            }
        );
        assert!(fw.allows_port(22));
        let nft = parse_firewall(
            "backend nftables\ntable inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept\n\t\tip saddr 10.0.0.0/24 tcp dport 3306 accept\n\t}\n}",
        );
        assert!(nft.active);
        assert_eq!(nft.incoming, "drop");
        assert_eq!(nft.rules.len(), 2);
        assert_eq!(nft.rules[0].to, "22/tcp");
    }

    #[test]
    fn fail2ban() {
        let j = parse_f2b(
            "Status
|- Number of jail:\t2
`- Jail list:\tnginx-http-auth, sshd
@@jail sshd
Status for the jail: sshd
|- Filter
|  |- Currently failed:\t3
|  |- Total failed:\t1284
|  `- File list:\t/var/log/auth.log
`- Actions
   |- Currently banned:\t2
   |- Total banned:\t102
   `- Banned IP list:\t198.51.100.203 192.0.2.155",
        );
        assert_eq!(j.len(), 1);
        assert_eq!(
            (
                j[0].currently_failed,
                j[0].total_failed,
                j[0].currently_banned,
                j[0].total_banned
            ),
            (3, 1284, 2, 102)
        );
        assert_eq!(j[0].banned_ips, ["198.51.100.203", "192.0.2.155"]);
    }

    #[test]
    fn auth() {
        let a = parse_auth(&format!(
            "{}\n412 198.51.100.203\n288 192.0.2.155\n",
            "1 ".repeat(48)
        ));
        assert_eq!(a.buckets.len(), 48);
        assert_eq!(a.total(), 48);
        assert_eq!(a.top[0], ("198.51.100.203".into(), 412));
    }

    #[test]
    fn timers_json_and_plain() {
        let s = parse_timers(
            "now 1000\n[{\"next\":4600000000,\"left\":0,\"last\":400000000,\"passed\":0,\"unit\":\"certbot.timer\",\"activates\":\"certbot.service\"},{\"next\":0,\"left\":0,\"last\":0,\"passed\":0,\"unit\":\"idle.timer\",\"activates\":\"idle.service\"}]\n@@cron\n# m h dom mon dow command\n*/5 * * * * /usr/local/bin/backup.sh\n",
        );
        assert_eq!(s.timers.len(), 2);
        assert_eq!(s.timers[0].next_in_s, Some(3600));
        assert_eq!(s.timers[0].last_ago_s, Some(600));
        assert_eq!(s.timers[1].next_in_s, None);
        assert_eq!(s.cron_jobs, ["*/5 * * * * /usr/local/bin/backup.sh"]);
        let p = parse_timers(
            "now 1\nThu 2026-11-12 20:00:00 UTC  6h left  Thu 2026-11-12 08:00:00 UTC  5h ago  certbot.timer  certbot.service\n@@cron\n",
        );
        assert_eq!(p.timers[0].unit, "certbot.timer");
        assert_eq!(p.timers[0].activates, "certbot.service");
    }

    #[test]
    fn units() {
        let u = parse_units(
            "nginx.service loaded active running A high performance web server\n● redis-server.service loaded failed failed Advanced key-value store\ncertbot.timer loaded active waiting Run certbot twice daily\nsys-kernel.mount loaded active mounted Kernel\n",
        );
        assert_eq!(u.len(), 3);
        assert_eq!(u[1].name, "redis-server.service");
        assert_eq!(u[1].active, "failed");
        assert_eq!(u[0].description, "A high performance web server");
    }
}
