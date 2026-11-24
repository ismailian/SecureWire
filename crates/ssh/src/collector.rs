//! The embedded remote scripts and the control-line vocabulary (protocol §2.3).

use sw_core::Section;
use sw_core::shell::is_valid_unit;

use crate::api::Throttle;

/// Streamed on stdin of [`launch_command`]; its last line calls `main`, so every
/// line written after it is a control command.
pub const SCRIPT: &str = include_str!("../../../collector/collector.sh");

/// POSIX sh, streamed on stdin of [`PROBE_COMMAND`]; stdin is closed after it.
pub const PROBE: &str = include_str!("../../../collector/probe.sh");

pub const PROBE_COMMAND: &str = "exec sh -s";

/// Directory listing for the file browser (protocol §15), streamed on stdin of
/// [`sw_core::files::listing_command`].
pub const LS: &str = include_str!("../../../collector/ls.sh");

/// Verifies a sudo password read from stdin (protocol §9). `-k` ignores cached
/// credentials so a wrong password can't pass by accident.
pub const SUDO_VERIFY_COMMAND: &str = "sudo -S -k -p \"\" true";

/// The exec command for the collector channel. No secret and no script text in argv.
pub fn launch_command(t: Throttle, p: Priv) -> String {
    launch_with_tiers(t.tiers(), p)
}

/// With privilege the whole collector runs under ONE sudo for the session (D-029): one
/// auth-log entry instead of one per privileged section per tick, and no PAM cost per
/// tick. With `Priv::Password` the password is the first stdin line, read by `sudo -S`
/// (unbuffered in sudo and sudo-rs); the script follows on the same stdin, for bash.
pub fn launch_with_tiers((fast, medium, slow): (u64, u64, u64), p: Priv) -> String {
    let run = format!("bash -s securewire-collector {fast} {medium} {slow}");
    match p {
        Priv::None => format!("exec {run} none"),
        Priv::Root => format!("exec {run} root"),
        Priv::NoPasswd => format!("exec sudo -n -- {run} root"),
        Priv::Password => format!("exec sudo -S -p \"\" -- {run} root"),
    }
}

/// How the collector may run root-only commands (protocol §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priv {
    None,
    Root,
    NoPasswd,
    Password,
}

impl Priv {
    pub fn arg(self) -> &'static str {
        match self {
            Priv::None => "none",
            Priv::Root => "root",
            Priv::NoPasswd => "nopasswd",
            Priv::Password => "password",
        }
    }

    pub fn from_sudo(m: crate::api::SudoMode) -> Self {
        use crate::api::SudoMode;
        match m {
            SudoMode::Root => Priv::Root,
            SudoMode::NoPasswd => Priv::NoPasswd,
            SudoMode::Password => Priv::Password,
            SudoMode::None | SudoMode::Unknown => Priv::None,
        }
    }
}

/// `EVERY <section> <secs>`: per-section interval; 0 restores the tier.
pub fn every(s: Section, secs: u32) -> String {
    format!("EVERY {} {secs}", s.name())
}

/// Lists units for the "Watched services" picker.
pub const LIST_UNITS_COMMAND: &str =
    "systemctl list-units --type=service,timer --all --no-legend --plain --no-pager";

/// Follows systemd's own messages about the watched units (Live service mode,
/// protocol §3). Any line means "something changed" → `NOW svc`.
/// `sudo`: prefix for hosts where the journal needs privilege (`""`, `"sudo -n "`, `"sudo -S -p \"\" "`).
pub fn unit_watch_command(units: &[String], sudo: &str) -> Option<String> {
    let matches: Vec<String> = units
        .iter()
        .filter(|u| is_valid_unit(u))
        .map(|u| sw_core::shell::shell_quote(&format!("UNIT={u}")))
        .collect();
    (!matches.is_empty()).then(|| {
        format!(
            "exec {sudo}journalctl -f -n 0 -q -o cat _PID=1 {}",
            matches.join(" ")
        )
    })
}

/// Control lines to bring a fresh collector to the client's current state.
pub fn replay(sections: &[(Section, bool)], services: &[String]) -> Vec<String> {
    let mut out: Vec<String> = sections.iter().map(|&(s, on)| on_off(s, on)).collect();
    if !services.is_empty() {
        out.push(svc(services));
    }
    out
}

pub fn on_off(s: Section, on: bool) -> String {
    format!("{} {}", if on { "ON" } else { "OFF" }, s.name())
}

pub fn now(s: Section) -> String {
    format!("NOW {}", s.name())
}

pub fn tiers(t: Throttle) -> [String; 3] {
    let (fast, medium, slow) = t.tiers();
    [
        format!("TIER fast {fast}"),
        format!("TIER medium {medium}"),
        format!("TIER slow {slow}"),
    ]
}

/// `SVC` with only valid unit names (the script re-validates).
pub fn svc(units: &[String]) -> String {
    let mut s = String::from("SVC");
    for u in units.iter().filter(|u| is_valid_unit(u)) {
        s.push(' ');
        s.push_str(u);
    }
    s
}

pub fn ping(n: u64) -> String {
    format!("PING {n}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_shape() {
        // bash -s executes the stream command by command: main must be the last
        // line, or the remainder of the script would be read as control input.
        assert!(SCRIPT.trim_end().ends_with("main \"$@\""));
        // A CRLF checkout would break bash on the server (`$'\r': command not found`).
        assert!(
            !SCRIPT.contains('\r') && !PROBE.contains('\r'),
            "collector scripts must be LF-only"
        );
        assert!(SCRIPT.ends_with('\n'));
        assert!(PROBE.trim_end().ends_with("echo \"probe=done\""));
    }

    #[test]
    fn lines() {
        assert_eq!(
            launch_command(Throttle::Normal, Priv::Password),
            r#"exec sudo -S -p "" -- bash -s securewire-collector 2 10 60 root"#
        );
        assert_eq!(
            launch_command(Throttle::Normal, Priv::None),
            "exec bash -s securewire-collector 2 10 60 none"
        );
        assert_eq!(on_off(Section::Df, false), "OFF df");
        assert_eq!(
            svc(&["nginx.service".into(), "x; rm -rf /".into(), "-bad".into()]),
            "SVC nginx.service"
        );
        assert_eq!(tiers(Throttle::Hidden)[2], "TIER slow 0");
    }
}

#[cfg(test)]
mod m3_tests {
    use super::*;

    #[test]
    fn watch_command_quotes_and_validates() {
        let c = unit_watch_command(&["nginx.service".into(), "bad;rm".into()], "").unwrap();
        assert_eq!(
            c,
            "exec journalctl -f -n 0 -q -o cat _PID=1 'UNIT=nginx.service'"
        );
        assert!(unit_watch_command(&["$(x)".into()], "").is_none());
        assert_eq!(every(Section::Svc, 30), "EVERY svc 30");
    }
}

// ───────────────────────── M4: logs (protocol §6) ─────────────────────────

/// Log discovery, streamed on stdin of [`discover_command`].
pub const DISCOVER: &str = include_str!("../../../collector/discover.sh");

pub fn discover_command(p: Priv) -> String {
    format!("exec bash -s securewire-discover {}", p.arg())
}

/// Prefix + optional stdin secret for running a log reader with privilege.
pub fn sudo_prefix(p: Priv) -> &'static str {
    match p {
        Priv::None | Priv::Root => "",
        Priv::NoPasswd => "sudo -n -- ",
        Priv::Password => "sudo -S -p \"\" -- ",
    }
}

/// The exact command line a server action runs as (protocol §7), shown verbatim in the
/// confirm dialog. `sh -c` makes the `2>&1` and any pipes apply to the whole command under
/// sudo; the sudo password (Password mode) goes on the channel's stdin, never in this line.
pub fn action_line(
    action: &sw_core::actions::Action,
    sudo: crate::api::SudoMode,
) -> Result<String, String> {
    let cmd = action.command()?;
    let p = if action.as_user() {
        Priv::None
    } else {
        Priv::from_sudo(sudo)
    };
    if p == Priv::None && !action.works_unprivileged() {
        return Err("This action needs sudo — click \"no sudo\" in the status bar".into());
    }
    let quoted = sw_core::shell::shell_quote(&format!("{cmd} 2>&1"));
    Ok(format!("{}sh -c {quoted}", sudo_prefix(p)))
}

/// `journalctl -f -o json` for the given units. `resume_cursor` replaces the
/// backlog after a reconnect so nothing is lost or duplicated.
pub fn journal_command(
    units: &[String],
    backlog: u32,
    resume_cursor: Option<&str>,
    prefix: &str,
) -> Option<String> {
    let units: Vec<String> = units
        .iter()
        .filter(|u| is_valid_unit(u))
        .map(|u| format!("-u {}", sw_core::shell::shell_quote(u)))
        .collect();
    if units.is_empty() {
        return None;
    }
    let start = match resume_cursor {
        Some(c) => format!("--after-cursor={}", sw_core::shell::shell_quote(c)),
        None => format!("-n {backlog}"),
    };
    Some(format!(
        "exec {prefix}journalctl -f {start} -q -o json \
         --output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,UNIT,SYSLOG_IDENTIFIER,__REALTIME_TIMESTAMP {}",
        units.join(" ")
    ))
}

/// `tail -F` for files (absolute paths only, each quoted).
pub fn tail_command(paths: &[String], backlog: u32, prefix: &str) -> Option<String> {
    let files: Vec<String> = paths
        .iter()
        .filter(|p| sw_core::shell::is_valid_path(p))
        .map(|p| sw_core::shell::shell_quote(p))
        .collect();
    (!files.is_empty()).then(|| format!("exec {prefix}tail -n {backlog} -F -- {}", files.join(" ")))
}

#[cfg(test)]
mod m4_tests {
    use super::*;

    #[test]
    fn log_commands() {
        let j = journal_command(&["nginx.service".into(), "x;y".into()], 200, None, "").unwrap();
        assert!(j.starts_with("exec journalctl -f -n 200 -q -o json"));
        assert!(j.ends_with("-u 'nginx.service'"));
        let r = journal_command(
            &["nginx.service".into()],
            200,
            Some("s=1;i=2"),
            "sudo -n -- ",
        )
        .unwrap();
        assert!(r.contains("exec sudo -n -- journalctl -f --after-cursor='s=1;i=2'"));
        let t = tail_command(&["/var/log/a b.log".into(), "rel.log".into()], 50, "").unwrap();
        assert_eq!(t, "exec tail -n 50 -F -- '/var/log/a b.log'");
        assert!(tail_command(&["$(x)".into()], 1, "").is_none());
        assert!(DISCOVER.trim_end().ends_with("discover \"$@\""));
        assert!(!DISCOVER.contains('\r'));
    }
}

#[cfg(test)]
mod action_tests {
    use super::action_line;
    use crate::api::SudoMode;
    use sw_core::actions::Action;

    #[test]
    fn action_lines_per_privilege() {
        let a = Action::ServiceRestart("nginx.service".into());
        assert_eq!(
            action_line(&a, SudoMode::Root).unwrap(),
            r#"sh -c 'systemctl restart -- '"'"'nginx.service'"'"' 2>&1'"#
        );
        assert!(
            action_line(&a, SudoMode::Password)
                .unwrap()
                .starts_with(r#"sudo -S -p "" -- sh -c "#)
        );
        assert!(
            action_line(&a, SudoMode::NoPasswd)
                .unwrap()
                .starts_with("sudo -n -- sh -c ")
        );
        assert!(action_line(&a, SudoMode::None).is_err());
        // Read-only actions still run, unprivileged.
        assert!(
            action_line(&Action::WhoOnPort(22), SudoMode::None)
                .unwrap()
                .starts_with("sh -c ")
        );
    }
}
