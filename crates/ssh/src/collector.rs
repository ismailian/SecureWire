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

/// Verifies a sudo password read from stdin (protocol §9). `-k` ignores cached
/// credentials so a wrong password can't pass by accident.
pub const SUDO_VERIFY_COMMAND: &str = "sudo -S -k -p \"\" true";

/// The exec command for the collector channel. No secret and no script text in argv.
pub fn launch_command(t: Throttle) -> String {
    let (fast, medium, slow) = t.tiers();
    format!("exec bash -s securewire-collector {fast} {medium} {slow}")
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
            launch_command(Throttle::Normal),
            "exec bash -s securewire-collector 2 10 60"
        );
        assert_eq!(on_off(Section::Df, false), "OFF df");
        assert_eq!(
            svc(&["nginx.service".into(), "x; rm -rf /".into(), "-bad".into()]),
            "SVC nginx.service"
        );
        assert_eq!(tiers(Throttle::Hidden)[2], "TIER slow 0");
    }
}
