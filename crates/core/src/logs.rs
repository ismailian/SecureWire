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
    pub fn name(self) -> &'static str {
        match self {
            Preset::Generic => "generic",
            Preset::Nginx => "nginx",
            Preset::Mysql => "mysql",
            Preset::Fail2ban => "fail2ban",
        }
    }

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
            if ["fatal", "crit", "error", "failed", "failure", "panic"]
                .iter()
                .any(|w| has_word_ci(msg, w))
            {
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
            && h.get(i + n.len())
                .is_none_or(|c| !c.is_ascii_alphanumeric())
    })
}

/// Replace control characters (except tab) so remote text can't spoof the UI.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() && c != '\t' {
                '\u{fffd}'
            } else {
                c
            }
        })
        .collect()
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

// ───────────────────────── M4: log channels ─────────────────────────

/// One `journalctl -o json` record (the fields we ask for with `--output-fields`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    pub unit: String,
    /// `UNIT=` — set on PID 1's messages *about* a unit (started, failed, …).
    pub about_unit: String,
    pub identifier: String,
    pub message: String,
    pub priority: u8,
    pub ts_us: u64,
    pub cursor: String,
}

/// Parse one JSON line. MESSAGE may be a byte array (binary/invalid UTF-8) → lossy text.
pub fn parse_journal_line(line: &str) -> Option<JournalEntry> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_owned();
    let message = match v.get("MESSAGE")? {
        serde_json::Value::String(m) => m.clone(),
        serde_json::Value::Array(bytes) => {
            let b: Vec<u8> = bytes
                .iter()
                .filter_map(|x| x.as_u64().map(|n| n as u8))
                .collect();
            String::from_utf8_lossy(&b).into_owned()
        }
        _ => return None,
    };
    Some(JournalEntry {
        unit: s("_SYSTEMD_UNIT"),
        about_unit: s("UNIT"),
        identifier: s("SYSLOG_IDENTIFIER"),
        message,
        priority: s("PRIORITY").parse().unwrap_or(6),
        ts_us: s("__REALTIME_TIMESTAMP").parse().unwrap_or(0),
        cursor: s("__CURSOR"),
    })
}

/// Follows `tail -F a b c` output: `==> path <==` headers switch the current
/// file. Only exact matches of configured paths count, so log content can't
/// impersonate another source.
#[derive(Debug, Clone)]
pub struct TailParser {
    paths: Vec<String>,
    current: Option<usize>,
}

impl TailParser {
    pub fn new(paths: Vec<String>) -> Self {
        // With a single file tail prints no header.
        let current = (paths.len() == 1).then_some(0);
        Self { paths, current }
    }

    /// `Some((path index, text))` for a log line, `None` for headers/blank separators.
    pub fn line<'a>(&mut self, line: &'a str) -> Option<(usize, &'a str)> {
        if let Some(p) = line
            .strip_prefix("==> ")
            .and_then(|l| l.strip_suffix(" <=="))
            && let Some(i) = self.paths.iter().position(|x| x == p)
        {
            self.current = Some(i);
            return None;
        }
        if line.starts_with("tail: ") {
            return None; // "tail: 'x' has been replaced; following new file" etc.
        }
        let i = self.current?;
        (!line.is_empty()).then_some((i, line))
    }
}

/// A log source offered by discovery (`collector/discover.sh`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogCandidate {
    /// `journal` | `file` | `sudo-file`
    pub kind: String,
    pub target: String,
    pub id: String,
    pub preset: Preset,
    pub description: String,
}

/// Parse discovery output: `unit <name> <description…>` and `file <path> <r|sudo>`.
pub fn parse_discovery(out: &str) -> Vec<LogCandidate> {
    let mut v: Vec<LogCandidate> = out
        .lines()
        .filter_map(|l| {
            let mut it = l.splitn(3, ' ');
            match (it.next()?, it.next()?, it.next().unwrap_or("")) {
                ("unit", name, desc) if crate::shell::is_valid_unit(name) => {
                    let id = name.trim_end_matches(".service").to_owned();
                    Some(LogCandidate {
                        kind: "journal".into(),
                        target: name.to_owned(),
                        preset: Preset::from_name(&id),
                        id,
                        description: desc.to_owned(),
                    })
                }
                ("file", path, access) if crate::shell::is_valid_path(path) => {
                    let base = path.rsplit('/').next().unwrap_or(path);
                    let dir = path.rsplit('/').nth(1).unwrap_or("");
                    let id = if base.contains("error") || base.contains("access") || dir == "log" {
                        base.trim_end_matches(".log").to_owned()
                    } else {
                        format!("{dir}/{}", base.trim_end_matches(".log"))
                    };
                    let preset = if path.contains("nginx") {
                        Preset::Nginx
                    } else if path.contains("mysql") || path.contains("mariadb") {
                        Preset::Mysql
                    } else if path.contains("fail2ban") {
                        Preset::Fail2ban
                    } else {
                        Preset::Generic
                    };
                    let kind = if access.trim() == "r" {
                        "file"
                    } else {
                        "sudo-file"
                    };
                    Some(LogCandidate {
                        kind: kind.into(),
                        target: path.to_owned(),
                        id,
                        preset,
                        description: String::new(),
                    })
                }
                _ => None,
            }
        })
        .collect();
    v.sort_by(|a, b| (a.kind != "journal", &a.target).cmp(&(b.kind != "journal", &b.target)));
    v.dedup_by(|a, b| a.target == b.target);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets() {
        assert_eq!(
            detect_level(
                Preset::Nginx,
                "2026/11/12 13:02:11 [error] 1123#1123: *1 connect() failed"
            ),
            Level::Error
        );
        assert_eq!(
            detect_level(Preset::Mysql, "2026-11-12T13:05Z 0 [Warning] [MY-010055] x"),
            Level::Warn
        );
        assert_eq!(
            detect_level(
                Preset::Fail2ban,
                "2026-11-12 13:05:41,1 fail2ban.actions [988]: NOTICE [sshd] Ban 1.2.3.4"
            ),
            Level::Warn
        );
    }

    #[test]
    fn generic_uses_word_boundaries() {
        assert_eq!(detect_level(Preset::Generic, "terror alert"), Level::Info);
        assert_eq!(
            detect_level(Preset::Generic, "Job FAILED: exit 1"),
            Level::Error
        );
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

#[cfg(test)]
mod m4_tests {
    use super::*;

    #[test]
    fn journal_json() {
        let e = parse_journal_line(r#"{"__CURSOR":"s=abc;i=1","__REALTIME_TIMESTAMP":"1731416531123456","PRIORITY":"3","_SYSTEMD_UNIT":"nginx.service","SYSLOG_IDENTIFIER":"nginx","MESSAGE":"upstream failed"}"#).unwrap();
        assert_eq!(
            (e.unit.as_str(), e.priority, e.ts_us, e.cursor.as_str()),
            ("nginx.service", 3, 1731416531123456, "s=abc;i=1")
        );
        assert_eq!(Level::from_priority(e.priority), Level::Error);
        let bin = parse_journal_line(r#"{"MESSAGE":[104,105,255],"PRIORITY":"6"}"#).unwrap();
        assert_eq!(bin.message, "hi\u{fffd}");
        assert!(parse_journal_line("not json").is_none());
    }

    #[test]
    fn tail_headers() {
        let mut t = TailParser::new(vec!["/var/log/a.log".into(), "/var/log/b.log".into()]);
        assert_eq!(t.line("orphan before any header"), None);
        assert_eq!(t.line("==> /var/log/b.log <=="), None);
        assert_eq!(t.line("hello"), Some((1, "hello")));
        // A log line that looks like a header for an unknown file is just text.
        assert_eq!(
            t.line("==> /etc/shadow <=="),
            Some((1, "==> /etc/shadow <=="))
        );
        assert_eq!(t.line(""), None);
        let mut one = TailParser::new(vec!["/x.log".into()]);
        assert_eq!(one.line("a"), Some((0, "a")));
    }

    #[test]
    fn discovery() {
        let c = parse_discovery(
            "unit nginx.service A high performance web server\nunit bad;unit x\nfile /var/log/nginx/error.log r\nfile /var/log/mysql/error.log sudo\nfile /var/log/syslog r\nfile relative.log r\n",
        );
        assert_eq!(c.len(), 4);
        assert_eq!(
            (c[0].kind.as_str(), c[0].id.as_str(), c[0].preset),
            ("journal", "nginx", Preset::Nginx)
        );
        let my = c
            .iter()
            .find(|x| x.target == "/var/log/mysql/error.log")
            .unwrap();
        assert_eq!((my.kind.as_str(), my.preset), ("sudo-file", Preset::Mysql));
        assert_eq!(
            c.iter().find(|x| x.target == "/var/log/syslog").unwrap().id,
            "syslog"
        );
    }
}
