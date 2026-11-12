//! Number formatting rules from `design/ui-spec.md` §1.5:
//! binary units for sizes, decimal per second for rates, at most one decimal.

/// Bytes → `512 B`, `38 MiB`, `5.1 GiB`.
pub fn bytes(b: u64) -> String {
    const U: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 || v >= 100.0 { format!("{v:.0} {}", U[i]) } else { format!("{v:.1} {}", U[i]) }
}

/// Bytes as GiB with one decimal, no unit — for "5.1 / 7.8 GiB" pairs.
pub fn gib(b: u64) -> String {
    format!("{:.1}", b as f64 / (1024.0 * 1024.0 * 1024.0))
}

/// Bytes per second → `820 B/s`, `420 KB/s`, `1.8 MB/s`.
pub fn rate(bps: f64) -> String {
    const U: [&str; 4] = ["B/s", "KB/s", "MB/s", "GB/s"];
    let mut v = bps.max(0.0);
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 || v >= 100.0 { format!("{v:.0} {}", U[i]) } else { format!("{v:.1} {}", U[i]) }
}

/// Seconds → `45s`, `12m`, `3h 4m`, `41d 6h`.
pub fn duration(s: u64) -> String {
    let (d, h, m) = (s / 86_400, (s % 86_400) / 3600, (s % 3600) / 60);
    match (d, h, m) {
        (0, 0, 0) => format!("{s}s"),
        (0, 0, m) => format!("{m}m"),
        (0, h, m) => format!("{h}h {m}m"),
        (d, h, _) => format!("{d}d {h}h"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(39_845_888), "38.0 MiB");
        assert_eq!(bytes(1_288_490_189), "1.2 GiB");
        assert_eq!(bytes(200 * 1024 * 1024), "200 MiB");
        assert_eq!(rate(420_000.0), "420 KB/s");
        assert_eq!(rate(1_800_000.0), "1.8 MB/s");
        assert_eq!(rate(-3.0), "0 B/s");
        assert_eq!(duration(59), "59s");
        assert_eq!(duration(3 * 3600 + 240), "3h 4m");
        assert_eq!(duration(41 * 86_400 + 6 * 3600 + 5), "41d 6h");
    }
}
