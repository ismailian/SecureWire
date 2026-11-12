//! Parsers for raw collector payloads. Every parser is total: malformed lines
//! are skipped, never panic. Fixtures live in `crates/core/tests/fixtures/`.

pub mod df;
pub mod probe;
pub mod proc;
pub mod ps;
pub mod systemctl;
pub mod who;

pub use df::parse_df;
pub use probe::{Probe, parse_probe};
pub use proc::{
    CpuFrame, CpuTimes, DiskStat, NetDev, parse_cpu_frame, parse_diskstats, parse_meminfo,
    parse_net_dev,
};
pub use ps::parse_ps;
pub use systemctl::parse_systemctl_show;
pub use who::parse_who;

/// Parse a decimal integer field, tolerating surrounding whitespace.
pub(crate) fn num<T: std::str::FromStr>(s: &str) -> Option<T> {
    s.trim().parse().ok()
}
