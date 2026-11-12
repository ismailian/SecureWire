//! Collector frames → UI events. Shared by the real SSH actor and the demo
//! source, so the demo exercises exactly the production parsing path.

use std::collections::HashMap;

use sw_core::alerts::{self, Alert, Thresholds};
use sw_core::metrics::{CpuTracker, DiskIoTracker, NetTracker};
use sw_core::model::{HostStatic, MemSample, Mount, ServiceInfo};
use sw_core::{Frame, Section, parse};

use crate::api::EventKind;

#[derive(Default)]
pub struct Pipeline {
    cpu: CpuTracker,
    net: NetTracker,
    dio: DiskIoTracker,
    mem: Option<MemSample>,
    mounts: Vec<Mount>,
    services: Vec<ServiceInfo>,
    alerts: Vec<Alert>,
    thresholds: Thresholds,
    errors: HashMap<Section, String>,
    pub protocol: Option<u32>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_frame(&mut self, frame: Frame, out: &mut Vec<EventKind>) {
        match frame {
            Frame::Hello { proto, .. } => self.protocol = Some(proto),
            Frame::Data { section, payload, .. } => {
                self.errors.remove(&section);
                self.on_data(section, &payload, out);
            }
            Frame::Same { .. } | Frame::Pong(_) => {}
            Frame::Err { section, code, .. } => {
                if self.errors.get(&section) != Some(&code) {
                    self.errors.insert(section, code.clone());
                    out.push(EventKind::SectionError { section, code });
                }
            }
        }
    }

    fn on_data(&mut self, section: Section, p: &str, out: &mut Vec<EventKind>) {
        let up = self.cpu.uptime_s();
        match section {
            Section::Static => out.push(EventKind::Static(parse_static(p))),
            Section::Cpu => {
                if let Some(s) = parse::parse_cpu_frame(p).and_then(|f| self.cpu.update(f)) {
                    out.push(EventKind::Cpu(s));
                }
            }
            Section::Mem => {
                let m = parse::parse_meminfo(p);
                self.mem = Some(m);
                out.push(EventKind::Mem(m));
                self.eval_alerts(out);
            }
            Section::Net => {
                if let Some(s) = self.net.update(up, parse::parse_net_dev(p)) {
                    out.push(EventKind::Net(s));
                }
            }
            Section::Dio => {
                if let Some(s) = self.dio.update(up, &parse::parse_diskstats(p)) {
                    out.push(EventKind::DiskIo(s));
                }
            }
            Section::Df => {
                self.mounts = parse::parse_df(p);
                out.push(EventKind::Mounts(self.mounts.clone()));
                self.eval_alerts(out);
            }
            Section::Who => out.push(EventKind::Sessions(parse::parse_who(p))),
            Section::Ps => out.push(EventKind::Processes(parse::parse_ps(p))),
            Section::Svc => {
                self.services = parse::parse_systemctl_show(p, up);
                out.push(EventKind::Services(self.services.clone()));
                self.eval_alerts(out);
            }
            // Parsers for these arrive with their milestones (M3).
            Section::Ports | Section::Conns | Section::Fw | Section::F2b | Section::Auth | Section::Timers => {}
        }
    }

    fn eval_alerts(&mut self, out: &mut Vec<EventKind>) {
        let a = alerts::evaluate(
            alerts::Inputs { services: &self.services, mounts: &self.mounts, mem: self.mem.as_ref() },
            &self.thresholds,
        );
        if a != self.alerts {
            self.alerts = a.clone();
            out.push(EventKind::Alerts(a));
        }
    }
}

/// `static` section: `key=value` lines from the probe-like static block.
fn parse_static(p: &str) -> HostStatic {
    let mut s = HostStatic::default();
    for line in p.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let v = v.trim().trim_matches('"');
        match k {
            "hostname" => s.hostname = v.into(),
            "PRETTY_NAME" | "os" => s.os = v.into(),
            "kernel" => s.kernel = v.into(),
            "arch" => s.arch = v.into(),
            "cpus" => s.cpus = v.parse().unwrap_or(0),
            "virt" => s.virt = v.into(),
            "mem_total_kib" => s.mem_total = v.parse::<u64>().unwrap_or(0) * 1024,
            _ => {}
        }
    }
    s
}
