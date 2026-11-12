use super::num;
use crate::model::Session;

/// `who -u`: `user tty date time idle pid (from)`. `(from)` is absent for local logins.
pub fn parse_who(payload: &str) -> Vec<Session> {
    payload
        .lines()
        .filter_map(|line| {
            let (head, from) = match line.rfind('(') {
                Some(i) if line.ends_with(')') => {
                    (&line[..i], line[i + 1..line.len() - 1].to_owned())
                }
                _ => (line, String::new()),
            };
            let f: Vec<&str> = head.split_ascii_whitespace().collect();
            if f.len() < 6 {
                return None;
            }
            Some(Session {
                user: f[0].to_owned(),
                tty: f[1].to_owned(),
                idle: f[4].to_owned(),
                pid: num(f[5]).unwrap_or(0),
                from,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who() {
        let v = parse_who(
            "root     pts/0        2026-11-12 09:12   .          88123 (198.51.100.24)
deploy   pts/1        2026-11-12 11:02 02:01        88200 (203.0.113.50)
admin    tty1         2026-11-10 08:00  old          900",
        );
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].from, "198.51.100.24");
        assert_eq!(v[1].idle, "02:01");
        assert_eq!(v[2].from, "");
        assert_eq!(v[2].pid, 900);
    }
}
