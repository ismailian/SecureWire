//! Remote file browser (protocol §15): the listing format, file operations as
//! fixed templates with validated, quoted paths, and the pieces of the SCP wire
//! protocol used for transfers. No I/O.

use crate::shell::shell_quote;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Link,
    Other,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoteEntry {
    /// The exact name on the server (only valid UTF-8 names are kept).
    pub name: String,
    /// `name` with control characters replaced, for drawing.
    pub display: String,
    pub kind: Kind,
    /// A directory, or a symlink that points at one.
    pub is_dir: bool,
    pub size: u64,
    /// Unix seconds.
    pub mtime: i64,
    /// Permission bits (`0o755`).
    pub mode: u32,
    pub owner: String,
    pub group: String,
    /// Symlink target (sanitized), empty otherwise.
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Listing {
    /// Absolute, symlink-resolved path of the listed directory.
    pub path: String,
    pub entries: Vec<RemoteEntry>,
    /// Entries left out because their name is not UTF-8 (they can't be named safely).
    pub skipped: usize,
}

/// `ls.sh` output → [`Listing`]. Fields are NUL-terminated: `P <path>` then
/// 8 fields per entry (`%y%Y size mtime mode user group name target`), or `E <code>`.
pub fn parse_listing(out: &[u8]) -> Result<Listing, String> {
    let mut f = out.split(|&b| b == 0);
    match f.next() {
        Some(b"P") => {}
        Some(b"E") => {
            return Err(match f.next() {
                Some(b"noent") => "No such directory".into(),
                Some(b"notdir") => "Not a directory".into(),
                Some(b"perm") => "Permission denied".into(),
                _ => "Cannot open this directory".into(),
            });
        }
        _ => {
            return Err("The server sent no listing (is `sh` available?)".into());
        }
    }
    let path = f
        .next()
        .and_then(|p| std::str::from_utf8(p).ok())
        .filter(|p| p.starts_with('/'))
        .ok_or("The directory path is not valid UTF-8")?
        .to_owned();
    let mut l = Listing {
        path,
        ..Default::default()
    };
    let fields: Vec<&[u8]> = f.collect();
    for e in fields.as_chunks::<8>().0 {
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let Ok(name) = std::str::from_utf8(e[6]) else {
            l.skipped += 1;
            continue;
        };
        if !is_valid_name(name) {
            l.skipped += 1;
            continue;
        }
        let t = e[0];
        let kind = match t.first() {
            Some(b'f') => Kind::File,
            Some(b'd') => Kind::Dir,
            Some(b'l') => Kind::Link,
            _ => Kind::Other,
        };
        let is_dir = kind == Kind::Dir || (kind == Kind::Link && t.get(1) == Some(&b'd'));
        let num = |b: &[u8]| {
            s(b).split('.')
                .next()
                .unwrap_or("0")
                .parse::<i64>()
                .unwrap_or(0)
        };
        l.entries.push(RemoteEntry {
            name: name.to_owned(),
            display: crate::logs::sanitize(name),
            kind,
            is_dir,
            size: s(e[1]).parse().unwrap_or(0),
            mtime: num(e[2]),
            mode: u32::from_str_radix(&s(e[3]), 8).unwrap_or(0),
            owner: crate::logs::sanitize(&s(e[4])),
            group: crate::logs::sanitize(&s(e[5])),
            target: crate::logs::sanitize(&s(e[7])),
        });
    }
    Ok(l)
}

/// One path component: not empty, `.` or `..`, no `/`, NUL or line breaks, ≤ 255 bytes.
pub fn is_valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 255 && n != "." && n != ".." && !n.contains(['/', '\0', '\n', '\r'])
}

/// Absolute path whose components are all valid names (so never `/`, `..` or `//`).
pub fn is_plain_path(p: &str) -> bool {
    p.len() > 1 && p.starts_with('/') && p[1..].split('/').all(is_valid_name)
}

pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// `/a/b` → `/a`, `/a` → `/`, `/` → None.
pub fn parent(path: &str) -> Option<String> {
    let p = path.trim_end_matches('/');
    if p.is_empty() {
        return None;
    }
    Some(match p.rfind('/') {
        Some(0) | None => "/".to_owned(),
        Some(i) => p[..i].to_owned(),
    })
}

pub fn file_name(path: &str) -> &str {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(path)
}

/// `report.pdf` → `report (copy).pdf`, then `report (copy 2).pdf` … until `taken` says no.
pub fn unique_name(name: &str, taken: impl Fn(&str) -> bool) -> String {
    if !taken(name) {
        return name.to_owned();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (1..)
        .map(|n| {
            if n == 1 {
                format!("{stem} (copy){ext}")
            } else {
                format!("{stem} (copy {n}){ext}")
            }
        })
        .find(|c| !taken(c))
        .unwrap_or_else(|| name.to_owned())
}

/// The listing channel: `ls.sh` on stdin, the directory (empty = home) as `$1`.
pub fn listing_command(path: &str) -> Result<String, String> {
    if path.is_empty() {
        return Ok("LC_ALL=C exec sh -s".into());
    }
    if path != "/" && !is_plain_path(path) {
        return Err(format!("Not an absolute path: {path:?}"));
    }
    Ok(format!("LC_ALL=C exec sh -s -- {}", shell_quote(path)))
}

/// One source → destination pair of a copy or move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pair {
    pub src: String,
    pub dst: String,
    /// `dst` exists and the user chose to replace it (removed first).
    pub replace: bool,
}

/// A file operation on the server, run as the login user (never sudo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsOp {
    Mkdir(String),
    Delete(Vec<String>),
    Rename { from: String, to: String },
    Copy(Vec<Pair>),
    Move(Vec<Pair>),
}

impl FsOp {
    pub fn command(&self) -> Result<String, String> {
        let q = |p: &str| {
            if is_plain_path(p) {
                Ok(shell_quote(p))
            } else {
                Err(format!("Not a safe absolute path: {p:?}"))
            }
        };
        let pairs = |v: &[Pair], verb: &str| -> Result<String, String> {
            if v.is_empty() {
                return Err("Nothing to do".into());
            }
            let mut parts = Vec::with_capacity(v.len());
            for p in v {
                let (s, d) = (q(&p.src)?, q(&p.dst)?);
                if p.src == p.dst || p.dst.starts_with(&format!("{}/", p.src)) {
                    return Err(format!("Cannot {verb} {:?} into itself", p.src));
                }
                let flag = match verb {
                    "copy" => "cp -a",
                    _ if p.replace => "mv",
                    _ => "mv -n",
                };
                parts.push(if p.replace {
                    format!("rm -rf -- {d} && {flag} -- {s} {d}")
                } else {
                    format!("{flag} -- {s} {d}")
                });
            }
            Ok(parts.join(" && "))
        };
        Ok(match self {
            FsOp::Mkdir(p) => format!("mkdir -- {}", q(p)?),
            FsOp::Delete(v) if v.is_empty() => return Err("Nothing to delete".into()),
            FsOp::Delete(v) => {
                let v: Result<Vec<_>, _> = v.iter().map(|p| q(p)).collect();
                format!("rm -rf -- {}", v?.join(" "))
            }
            FsOp::Rename { from, to } => format!("mv -n -- {} {}", q(from)?, q(to)?),
            FsOp::Copy(v) => pairs(v, "copy")?,
            FsOp::Move(v) => pairs(v, "move")?,
        })
    }

    /// Removes or replaces data: shown with the exact command and confirmed first.
    pub fn destructive(&self) -> bool {
        match self {
            FsOp::Mkdir(_) => false,
            FsOp::Copy(v) => v.iter().any(|p| p.replace),
            FsOp::Delete(_) | FsOp::Rename { .. } | FsOp::Move(_) => true,
        }
    }

    pub fn verb(&self) -> String {
        let n = |k: usize, one: &str| {
            if k == 1 {
                one.to_owned()
            } else {
                format!("{k} items")
            }
        };
        match self {
            FsOp::Mkdir(p) => format!("New folder {}", file_name(p)),
            FsOp::Delete(v) => format!(
                "Delete {}",
                n(v.len(), v.first().map_or("", |p| file_name(p)))
            ),
            FsOp::Rename { from, to } => {
                format!("Rename {} to {}", file_name(from), file_name(to))
            }
            FsOp::Copy(v) => format!(
                "Copy {}",
                n(v.len(), v.first().map_or("", |p| file_name(&p.src)))
            ),
            FsOp::Move(v) => format!(
                "Move {}",
                n(v.len(), v.first().map_or("", |p| file_name(&p.src)))
            ),
        }
    }
}

// ───────────────────────────── SCP ─────────────────────────────

/// Upload channel: an SCP sink that receives into `dir` (which must exist).
pub fn scp_sink_command(dir: &str) -> Result<String, String> {
    if dir != "/" && !is_plain_path(dir) {
        return Err(format!("Not an absolute path: {dir:?}"));
    }
    Ok(format!("scp -r -t -- {}", shell_quote(dir)))
}

/// Download channel: an SCP source sending `path` (file or directory tree).
pub fn scp_source_command(path: &str) -> Result<String, String> {
    if !is_plain_path(path) {
        return Err(format!("Not a safe absolute path: {path:?}"));
    }
    Ok(format!("scp -r -f -- {}", shell_quote(path)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScpRecord {
    File {
        mode: u32,
        size: u64,
        name: String,
    },
    Dir {
        mode: u32,
        name: String,
    },
    /// End of the current directory.
    End,
    /// Modification times (only sent with `-p`); ignored.
    Time,
}

/// Parse one control line from an SCP source (without the trailing newline). Names are
/// checked so a hostile server can't write outside the chosen folder (`..`, `/`).
pub fn parse_scp_record(line: &[u8]) -> Result<ScpRecord, String> {
    let s = std::str::from_utf8(line).map_err(|_| "SCP: file name is not UTF-8".to_owned())?;
    let bad = || format!("SCP: unexpected record {:?}", crate::logs::sanitize(s));
    match s.as_bytes().first() {
        Some(b'E') if s == "E" => Ok(ScpRecord::End),
        Some(b'T') => Ok(ScpRecord::Time),
        Some(c @ (b'C' | b'D')) => {
            let mut it = s[1..].splitn(3, ' ');
            let mode = it
                .next()
                .and_then(|m| u32::from_str_radix(m, 8).ok())
                .ok_or_else(bad)?;
            let size: u64 = it.next().and_then(|n| n.parse().ok()).ok_or_else(bad)?;
            let name = it.next().ok_or_else(bad)?;
            if !is_valid_name(name) {
                return Err(format!(
                    "SCP: refused unsafe file name {:?}",
                    crate::logs::sanitize(name)
                ));
            }
            let name = name.to_owned();
            Ok(if *c == b'C' {
                ScpRecord::File {
                    mode: mode & 0o7777,
                    size,
                    name,
                }
            } else {
                ScpRecord::Dir {
                    mode: mode & 0o7777,
                    name,
                }
            })
        }
        _ => Err(bad()),
    }
}

pub fn scp_file_header(mode: u32, size: u64, name: &str) -> String {
    format!("C{:04o} {size} {name}\n", mode & 0o7777)
}

pub fn scp_dir_header(mode: u32, name: &str) -> String {
    format!("D{:04o} 0 {name}\n", mode & 0o7777)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(f: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for s in f {
            v.extend_from_slice(s.as_bytes());
            v.push(0);
        }
        v
    }

    #[test]
    fn listing() {
        let mut out = rec(&["P", "/var/www"]);
        out.extend(rec(&[
            "dd",
            "4096",
            "1700000000.5",
            "755",
            "www",
            "www",
            "html",
            "",
        ]));
        out.extend(rec(&[
            "ff",
            "12",
            "1700000001.0",
            "644",
            "root",
            "root",
            "a\tb.txt",
            "",
        ]));
        out.extend(rec(&[
            "ld",
            "7",
            "1700000002",
            "777",
            "root",
            "root",
            "cur",
            "/srv/x",
        ]));
        out.extend(rec(&[
            "lN",
            "7",
            "1700000002",
            "777",
            "root",
            "root",
            "dead",
            "/nope",
        ]));
        out.extend(b"ff\x0012\x001\x00644\x00u\x00g\x00bad\xff\x00\x00");
        let l = parse_listing(&out).unwrap();
        assert_eq!(l.path, "/var/www");
        assert_eq!(l.entries.len(), 4);
        assert_eq!(l.skipped, 1);
        let e = &l.entries[0];
        assert!(e.is_dir && e.kind == Kind::Dir && e.mode == 0o755 && e.mtime == 1_700_000_000);
        assert_eq!(l.entries[1].name, "a\tb.txt");
        assert!(l.entries[2].is_dir && l.entries[2].kind == Kind::Link);
        assert!(!l.entries[3].is_dir);
        assert_eq!(
            parse_listing(&rec(&["E", "perm"])).unwrap_err(),
            "Permission denied"
        );
        assert!(parse_listing(b"").is_err());
    }

    #[test]
    fn paths() {
        assert!(is_plain_path("/a/b c/d"));
        for bad in ["/", "", "a/b", "/a/../b", "/a//b", "/a/./b", "/a\nb", "/a/"] {
            assert!(!is_plain_path(bad), "{bad:?}");
        }
        assert_eq!(parent("/a/b").as_deref(), Some("/a"));
        assert_eq!(parent("/a").as_deref(), Some("/"));
        assert_eq!(parent("/"), None);
        assert_eq!(join("/", "x"), "/x");
        assert_eq!(join("/a", "x"), "/a/x");
        assert_eq!(file_name("/a/b.txt"), "b.txt");
        let taken = ["r.pdf", "r (copy).pdf"];
        assert_eq!(
            unique_name("r.pdf", |n| taken.contains(&n)),
            "r (copy 2).pdf"
        );
        assert_eq!(unique_name(".bashrc", |n| n == ".bashrc"), ".bashrc (copy)");
        assert_eq!(unique_name("new", |_| false), "new");
    }

    #[test]
    fn ops_are_quoted_and_checked() {
        let p = |s: &str, d: &str, r: bool| Pair {
            src: s.into(),
            dst: d.into(),
            replace: r,
        };
        assert_eq!(
            FsOp::Copy(vec![p("/a/x y", "/b/x y", false)])
                .command()
                .unwrap(),
            "cp -a -- '/a/x y' '/b/x y'"
        );
        assert_eq!(
            FsOp::Move(vec![p("/a/x", "/b/x", true)]).command().unwrap(),
            "rm -rf -- '/b/x' && mv -- '/a/x' '/b/x'"
        );
        assert_eq!(
            FsOp::Delete(vec!["/tmp/$(reboot)".into(), "/tmp/it's".into()])
                .command()
                .unwrap(),
            "rm -rf -- '/tmp/$(reboot)' '/tmp/it'\"'\"'s'"
        );
        for bad in ["/", "/..", "relative", "/a/../../etc", "/x\nrm -rf /", ""] {
            assert!(FsOp::Delete(vec![bad.into()]).command().is_err(), "{bad:?}");
            assert!(FsOp::Mkdir(bad.into()).command().is_err(), "{bad:?}");
        }
        assert!(FsOp::Delete(vec![]).command().is_err());
        assert!(FsOp::Copy(vec![p("/a", "/a/b", false)]).command().is_err());
        assert!(FsOp::Move(vec![p("/a", "/a", false)]).command().is_err());
        assert!(!FsOp::Copy(vec![p("/a", "/b", false)]).destructive());
        assert!(FsOp::Copy(vec![p("/a", "/b", true)]).destructive());
        assert!(FsOp::Delete(vec!["/a".into()]).destructive());
        assert_eq!(listing_command("").unwrap(), "LC_ALL=C exec sh -s");
        assert_eq!(listing_command("/").unwrap(), "LC_ALL=C exec sh -s -- '/'");
        assert!(listing_command("/a;b").is_ok());
        assert!(listing_command("a").is_err());
    }

    #[test]
    fn scp_records() {
        assert_eq!(
            parse_scp_record(b"C0644 12 notes.txt").unwrap(),
            ScpRecord::File {
                mode: 0o644,
                size: 12,
                name: "notes.txt".into()
            }
        );
        assert_eq!(
            parse_scp_record(b"D0755 0 my dir").unwrap(),
            ScpRecord::Dir {
                mode: 0o755,
                name: "my dir".into()
            }
        );
        assert_eq!(parse_scp_record(b"E").unwrap(), ScpRecord::End);
        assert_eq!(parse_scp_record(b"T1 0 1 0").unwrap(), ScpRecord::Time);
        for bad in [
            &b"C0644 12 ../../etc/passwd"[..],
            b"C0644 12 a/b",
            b"D0755 0 ..",
            b"C0644 x name",
            b"C0644 12 ",
            b"X",
            b"C0644 1 \xff",
        ] {
            assert!(parse_scp_record(bad).is_err(), "{bad:?}");
        }
        assert_eq!(scp_file_header(0o100644, 5, "a b"), "C0644 5 a b\n");
        assert_eq!(scp_dir_header(0o755, "d"), "D0755 0 d\n");
        assert_eq!(
            scp_sink_command("/srv/up").unwrap(),
            "scp -r -t -- '/srv/up'"
        );
        assert_eq!(
            scp_source_command("/srv/x").unwrap(),
            "scp -r -f -- '/srv/x'"
        );
        assert!(scp_source_command("/").is_err());
    }
}
