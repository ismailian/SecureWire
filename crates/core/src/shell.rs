//! The only sanctioned way to put values into remote command strings
//! (protocol §7). Validate identifiers first, then quote everything.

/// POSIX single-quote quoting: `it's` → `'it'"'"'s'`. Safe for any byte except NUL.
pub fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\"'\"'");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// systemd unit name: `^[A-Za-z0-9@._:\-]{1,255}$`, must not start with `-`.
pub fn is_valid_unit(s: &str) -> bool {
    (1..=255).contains(&s.len())
        && !s.starts_with('-')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"@._:-".contains(&b))
}

/// Absolute path without NUL or newlines (it will still be quoted).
pub fn is_valid_path(s: &str) -> bool {
    s.starts_with('/') && !s.contains(['\0', '\n', '\r'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("nginx"), "'nginx'");
        assert_eq!(shell_quote("it's"), "'it'\"'\"'s'");
        assert_eq!(shell_quote("$(rm -rf /); `x`"), "'$(rm -rf /); `x`'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn units() {
        for ok in ["nginx.service", "getty@tty1.service", "php8.3-fpm", "sys-devices-x:1.device"] {
            assert!(is_valid_unit(ok), "{ok}");
        }
        for bad in ["", "-x", "a b", "a;b", "$(x)", "a\nb", "a'b", &"a".repeat(256)] {
            assert!(!is_valid_unit(bad), "{bad:?}");
        }
    }

    #[test]
    fn paths() {
        assert!(is_valid_path("/var/log/my app.log"));
        assert!(!is_valid_path("var/log"));
        assert!(!is_valid_path("/a\nb"));
    }
}
