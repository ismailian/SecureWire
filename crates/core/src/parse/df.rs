use super::num;
use crate::model::Mount;

/// `df -P -B1 …` output. Mount points may contain spaces (everything after the
/// capacity column is the mount point).
pub fn parse_df(payload: &str) -> Vec<Mount> {
    payload
        .lines()
        .filter_map(|line| {
            let mut it = line.split_ascii_whitespace();
            let fs = it.next()?;
            let size: u64 = num(it.next()?)?; // header line fails here and is skipped
            let used: u64 = num(it.next()?)?;
            let avail: u64 = num(it.next()?)?;
            let _cap = it.next()?;
            let mount = it.collect::<Vec<_>>().join(" ");
            if mount.is_empty() || size == 0 {
                return None;
            }
            Some(Mount { fs: fs.to_owned(), mount, size, used, avail })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn df() {
        let v = parse_df(
            "Filesystem        1-blocks        Used   Available Capacity Mounted on
/dev/vda1      66437775360 41231917056 25189081088      63% /
/dev/vdb1     107374182400 86973087744 20401094656      81% /var/lib/mysql
/dev/vda15        109422592     6334464   103088128       6% /boot/efi
/dev/sdc1       1000000000   100000000   900000000      10% /mnt/my disk",
        );
        assert_eq!(v.len(), 4);
        assert_eq!(v[1].mount, "/var/lib/mysql");
        assert!((v[1].frac() - 0.81).abs() < 0.01);
        assert_eq!(v[3].mount, "/mnt/my disk");
    }
}
