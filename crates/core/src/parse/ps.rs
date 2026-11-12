use super::num;
use crate::model::Process;

/// `ps -eo pid,user,pcpu,rss,etimes,args --sort=-pcpu --no-headers`
/// (`args` last so it may contain spaces).
pub fn parse_ps(payload: &str) -> Vec<Process> {
    payload
        .lines()
        .filter_map(|line| {
            let mut it = line.split_ascii_whitespace();
            let pid = num(it.next()?)?;
            let user = it.next()?.to_owned();
            let cpu = num(it.next()?)?;
            let rss_kib: u64 = num(it.next()?)?;
            let elapsed_s = num(it.next()?)?;
            let command = it.collect::<Vec<_>>().join(" ");
            Some(Process { pid, user, cpu, rss: rss_kib * 1024, elapsed_s, command })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps() {
        let v = parse_ps(
            "   1342 mysql    12.4 1268000 3562000 /usr/sbin/mysqld
   2211 www-data  6.1  90112   12000 php-fpm: pool www
garbage line",
        );
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].command, "php-fpm: pool www");
        assert_eq!(v[0].rss, 1268000 * 1024);
    }
}
