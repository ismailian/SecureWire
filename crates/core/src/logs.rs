//! Log lines and level detection (protocol §6).

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

impl Level {
    pub const ALL: [Level; 4] = [Level::Error, Level::Warn, Level::Info, Level::Debug];

    pub fn label(self) -> &'static str {
        match self {
            Level::Error => "ERR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DBG",
        }
    }

    /// syslog / journal PRIORITY (0 emerg … 7 debug).
    pub fn from_priority(p: u8) -> Self {
        match p {
            0..=3 => Level::Error,
            4 => Level::Warn,
            5 | 6 => Level::Info,
            _ => Level::Debug,
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }
}

/// Level-detection preset for file sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Preset {
    #[default]
    Generic,
    Nginx,
    Mysql,
    Fail2ban,
}

impl Preset {
    pub fn from_name(s: &str) -> Self {
        match s {
            "nginx" => Preset::Nginx,
            "mysql" => Preset::Mysql,
            "fail2ban" => Preset::Fail2ban,
            _ => Preset::Generic,
        }
    }
}

/// Classify a file log line. Cheap: ASCII case-insensitive substring checks, no regex.
pub fn detect_level(preset: Preset, msg: &str) -> Level {
    let has = |needle: &str| contains_ci(msg, needle);
    match preset {
        Preset::Nginx => {
            if has("[emerg]") || has("[alert]") || has("[crit]") || has("[error]") {
                Level::Error
            } else if has("[warn]") {
                Level::Warn
            } else if has("[debug]") {
                Level::Debug
            } else {
                Level::Info
            }
        }
        Preset::Mysql => {
            if has("[error]") || has("[fatal]") {
                Level::Error
            } else if has("[warning]") {
                Level::Warn
            } else {
                Level::Info
            }
        }
        Preset::Fail2ban => {
            if has(" error ") || has(" critical ") {
                Level::Error
            } else if has(" warning ") || has(" notice ") {
                Level::Warn
            } else if has(" debug ") {
                Level::Debug
            } else {
                Level::Info
            }
        }
        Preset::Generic => {
            if ["fatal", "crit", "error", "failed", "failure", "panic"].iter().any(|w| has_word_ci(msg, w)) {
                Level::Error
            } else if ["warn", "warning"].iter().any(|w| has_word_ci(msg, w)) {
                Level::Warn
            } else if has_word_ci(msg, "debug") {
                Level::Debug
            } else {
                Level::Info
            }
        }
    }
}

fn contains_ci(hay: &str, needle: &str) -> bool {
    let (h, n) = (hay.as_bytes(), needle.as_bytes());
    n.is_empty() || h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

fn has_word_ci(hay: &str, word: &str) -> bool {
    let (h, n) = (hay.as_bytes(), word.as_bytes());
    if n.len() > h.len() {
        return false;
    }
    (0..=h.len() - n.len()).any(|i| {
        h[i..i + n.len()].eq_ignore_ascii_case(n)
            && (i == 0 || !h[i - 1].is_ascii_alphanumeric())
            && h.get(i + n.len()).is_none_or(|c| !c.is_ascii_alphanumeric())
    })
}

/// Replace control characters (except tab) so remote text can't spoof the UI.
pub fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_control() && c != '\t' { '\u{fffd}' } else { c }).collect()
}

/// One log line as stored by the UI.
#[derive(Debug, Clone, PartialEq)]
pub struct LogLine {
    /// Unix time in milliseconds (journal `__REALTIME_TIMESTAMP` / arrival time for files).
    pub ts_ms: i64,
    /// Index into the host's log source list.
    pub source: u16,
    pub level: Level,
    pub msg: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets() {
        assert_eq!(
            detect_level(Preset::Nginx, "2026/11/12 13:02:11 [error] 1123#1123: *1 connect() failed"),
            Level::Error
        );
        assert_eq!(detect_level(Preset::Mysql, "2026-11-12T13:05Z 0 [Warning] [MY-010055] x"), Level::Warn);
        assert_eq!(detect_level(Preset::Fail2ban, "2026-11-12 13:05:41,1 fail2ban.actions [988]: NOTICE [sshd] Ban 1.2.3.4"), Level::Warn);
    }

    #[test]
    fn generic_uses_word_boundaries() {
        assert_eq!(detect_level(Preset::Generic, "terror alert"), Level::Info);
        assert_eq!(detect_level(Preset::Generic, "Job FAILED: exit 1"), Level::Error);
        assert_eq!(detect_level(Preset::Generic, "warning: disk"), Level::Warn);
    }

    #[test]
    fn priorities() {
        assert_eq!(Level::from_priority(3), Level::Error);
        assert_eq!(Level::from_priority(4), Level::Warn);
        assert_eq!(Level::from_priority(6), Level::Info);
        assert_eq!(Level::from_priority(7), Level::Debug);
    }

    #[test]
    fn sanitize_strips_escapes() {
        assert_eq!(sanitize("a\x1b[31mb\tc"), "a\u{fffd}[31mb\tc");
    }
}
