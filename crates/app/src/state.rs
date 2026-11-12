//! Per-host data as the UI holds it, plus per-host UI state.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use egui::Color32;
use sw_core::Section;
use sw_core::alerts::Alert;
use sw_core::logs::{Level, LogLine, sanitize};
use sw_core::metrics::RingBuffer;
use sw_core::model::{
    CpuSample, DiskIo, HostStatic, LinkStats, MemSample, Mount, NetSample, Process, ServiceInfo,
    Session,
};
use sw_ssh::api::{ConnInfo, ConnState, EventKind, LogKind};

use crate::theme::tok;

/// 30 min of 2 s samples.
const HISTORY: usize = 900;

pub struct LogSource {
    pub name: String,
    pub kind: LogKind,
    pub target: String,
    pub color: Color32,
    pub visible: bool,
    pub unseen_errors: u32,
}

/// Bounded log store with a stable sequence number per line, so filtered
/// views can hold `seq`s that survive eviction from the front.
pub struct LogStore {
    lines: VecDeque<LogLine>,
    first_seq: u64,
    cap: usize,
}

impl LogStore {
    fn new(cap: usize) -> Self {
        Self {
            lines: VecDeque::with_capacity(cap.min(4096)),
            first_seq: 0,
            cap,
        }
    }

    fn push(&mut self, l: LogLine) -> u64 {
        if self.lines.len() == self.cap {
            self.lines.pop_front();
            self.first_seq += 1;
        }
        self.lines.push_back(l);
        self.first_seq + self.lines.len() as u64 - 1
    }

    pub fn get(&self, seq: u64) -> Option<&LogLine> {
        seq.checked_sub(self.first_seq)
            .and_then(|i| self.lines.get(i as usize))
    }

    pub fn first_seq(&self) -> u64 {
        self.first_seq
    }

    pub fn iter_seq(&self) -> impl Iterator<Item = (u64, &LogLine)> {
        self.lines
            .iter()
            .enumerate()
            .map(|(i, l)| (self.first_seq + i as u64, l))
    }
}

pub struct HostView {
    pub name: String,
    pub state: ConnState,
    pub info: Option<ConnInfo>,
    pub stat: HostStatic,
    pub cpu: Option<CpuSample>,
    pub cpu_hist: RingBuffer,
    pub mem: Option<MemSample>,
    pub net: Option<NetSample>,
    pub rx_hist: RingBuffer,
    pub tx_hist: RingBuffer,
    pub dio: Option<DiskIo>,
    pub mounts: Vec<Mount>,
    pub sessions: Vec<Session>,
    pub services: Vec<ServiceInfo>,
    pub processes: Vec<Process>,
    pub alerts: Vec<Alert>,
    pub link: LinkStats,
    pub last_sample: HashMap<Section, Instant>,
    pub section_errors: HashMap<Section, String>,
    pub sources: Vec<LogSource>,
    pub logs: LogStore,
    /// Seqs of new lines since the last frame (the log view filters them incrementally).
    pub new_log_seqs: Vec<u64>,
    pub unseen_errors: u32,
    pub probe: Option<sw_core::parse::Probe>,
    pub listeners: Vec<sw_core::model::Listener>,
    pub conns: Vec<sw_core::model::Conn>,
    pub firewall: Option<sw_core::model::Firewall>,
    pub jails: Vec<sw_core::model::Jail>,
    pub auth: Option<sw_core::model::AuthStats>,
    pub scheduled: Option<sw_core::model::Scheduled>,
    pub units: Vec<sw_core::model::UnitInfo>,
    /// Live service mode is actually following the journal (vs. polling fallback).
    pub live_watching: bool,
}

impl HostView {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            state: ConnState::Connecting,
            info: None,
            stat: HostStatic::default(),
            cpu: None,
            cpu_hist: RingBuffer::new(HISTORY),
            mem: None,
            net: None,
            rx_hist: RingBuffer::new(HISTORY),
            tx_hist: RingBuffer::new(HISTORY),
            dio: None,
            mounts: vec![],
            sessions: vec![],
            services: vec![],
            processes: vec![],
            alerts: vec![],
            link: LinkStats::default(),
            last_sample: HashMap::new(),
            section_errors: HashMap::new(),
            sources: vec![],
            logs: LogStore::new(10_000),
            new_log_seqs: vec![],
            unseen_errors: 0,
            probe: None,
            listeners: vec![],
            conns: vec![],
            firewall: None,
            jails: vec![],
            auth: None,
            scheduled: None,
            units: vec![],
            live_watching: false,
        }
    }

    pub fn age_s(&self, s: Section) -> Option<f32> {
        self.last_sample.get(&s).map(|t| t.elapsed().as_secs_f32())
    }

    pub fn apply(&mut self, ev: EventKind, logs_visible: bool) {
        let now = Instant::now();
        match ev {
            EventKind::State(s) => self.state = s,
            EventKind::Connected(i) => self.info = Some(i),
            EventKind::Static(s) => self.stat = s,
            EventKind::Cpu(c) => {
                self.cpu_hist.push(c.total);
                self.cpu = Some(c);
                self.last_sample.insert(Section::Cpu, now);
            }
            EventKind::Mem(m) => {
                self.mem = Some(m);
                self.last_sample.insert(Section::Mem, now);
            }
            EventKind::Net(n) => {
                self.rx_hist.push(n.rx_bps as f32);
                self.tx_hist.push(n.tx_bps as f32);
                self.net = Some(n);
                self.last_sample.insert(Section::Net, now);
            }
            EventKind::DiskIo(d) => self.dio = Some(d),
            EventKind::Mounts(m) => {
                self.mounts = m;
                self.last_sample.insert(Section::Df, now);
            }
            EventKind::Sessions(s) => {
                self.sessions = s;
                self.last_sample.insert(Section::Who, now);
            }
            EventKind::Services(mut s) => {
                // Failed first, then by name (ui-spec §3.5).
                s.sort_by_key(|x| {
                    (
                        x.active != sw_core::model::ActiveState::Failed,
                        x.id.clone(),
                    )
                });
                self.services = s;
                self.last_sample.insert(Section::Svc, now);
            }
            EventKind::Processes(p) => {
                self.processes = p;
                self.last_sample.insert(Section::Ps, now);
            }
            EventKind::LogSources(src) => {
                self.sources = src
                    .into_iter()
                    .enumerate()
                    .map(|(i, s)| LogSource {
                        name: s.name,
                        kind: s.kind,
                        target: s.target,
                        color: tok::cat(i),
                        visible: true,
                        unseen_errors: 0,
                    })
                    .collect();
            }
            EventKind::Logs(lines) => {
                for mut l in lines {
                    l.msg = sanitize(&l.msg);
                    if l.level == Level::Error && !logs_visible {
                        self.unseen_errors += 1;
                        if let Some(s) = self.sources.get_mut(l.source as usize) {
                            s.unseen_errors += 1;
                        }
                    }
                    let seq = self.logs.push(l);
                    self.new_log_seqs.push(seq);
                }
            }
            EventKind::Alerts(a) => self.alerts = a,
            EventKind::Link(l) => self.link = l,
            EventKind::SectionError { section, code } => {
                self.section_errors.insert(section, code);
            }
            EventKind::Probe(p) => self.probe = Some(p),
            EventKind::Listeners(l) => {
                self.listeners = l;
                self.last_sample.insert(Section::Ports, now);
            }
            EventKind::Conns(c) => {
                self.conns = c;
                self.last_sample.insert(Section::Conns, now);
            }
            EventKind::Firewall(f) => {
                self.firewall = Some(f);
                self.section_errors.remove(&Section::Fw);
                self.last_sample.insert(Section::Fw, now);
            }
            EventKind::Jails(j) => {
                self.jails = j;
                self.section_errors.remove(&Section::F2b);
                self.last_sample.insert(Section::F2b, now);
            }
            EventKind::Auth(a) => self.auth = Some(a),
            EventKind::Scheduled(s) => self.scheduled = Some(s),
            EventKind::Units(u) => self.units = u,
            EventKind::ServiceMode { live_watching } => self.live_watching = live_watching,
            EventKind::Sudo(mode) => {
                if let Some(i) = &mut self.info {
                    i.sudo = mode;
                }
            }
            // Handled by the app (dialogs, banners, terminal tabs).
            EventKind::HostKeyPrompt { .. }
            | EventKind::AuthFailed(_)
            | EventKind::Error(_)
            | EventKind::PtyClosed { .. }
            | EventKind::SudoPrompt { .. } => {}
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DockTab {
    Logs,
    Alerts,
    Processes,
    Connections,
}

pub struct LogFilter {
    pub levels: [bool; 4],
    pub query: String,
    pub regex: Option<regex_lite::Regex>,
    pub regex_invalid: bool,
    pub follow: bool,
    /// Seqs of lines passing the filter, oldest first.
    pub matches: VecDeque<u64>,
    pub dirty: bool,
}

impl Default for LogFilter {
    fn default() -> Self {
        Self {
            levels: [true, true, true, false],
            query: String::new(),
            regex: None,
            regex_invalid: false,
            follow: true,
            matches: VecDeque::new(),
            dirty: true,
        }
    }
}

impl LogFilter {
    pub fn set_query(&mut self, q: String) {
        self.regex_invalid = false;
        self.regex = None;
        if !q.is_empty() {
            match regex_lite::RegexBuilder::new(&q)
                .case_insensitive(true)
                .build()
            {
                Ok(r) => self.regex = Some(r),
                Err(_) => self.regex_invalid = true,
            }
        }
        self.query = q;
        self.dirty = true;
    }

    pub fn accepts(&self, l: &LogLine, sources: &[LogSource]) -> bool {
        if !self.levels[l.level.index()] {
            return false;
        }
        if !sources.get(l.source as usize).is_none_or(|s| s.visible) {
            return false;
        }
        if self.query.is_empty() {
            return true;
        }
        match &self.regex {
            Some(r) => r.is_match(&l.msg),
            None => l
                .msg
                .to_ascii_lowercase()
                .contains(&self.query.to_ascii_lowercase()),
        }
    }

    /// Bring `matches` up to date: full rebuild when the filter changed, else append new lines.
    pub fn sync(&mut self, view: &mut HostView) {
        let first = view.logs.first_seq();
        while self.matches.front().is_some_and(|&s| s < first) {
            self.matches.pop_front();
        }
        if self.dirty {
            self.matches = view
                .logs
                .iter_seq()
                .filter(|(_, l)| self.accepts(l, &view.sources))
                .map(|(s, _)| s)
                .collect();
            self.dirty = false;
        } else {
            for &seq in &view.new_log_seqs {
                if view
                    .logs
                    .get(seq)
                    .is_some_and(|l| self.accepts(l, &view.sources))
                {
                    self.matches.push_back(seq);
                }
            }
        }
        view.new_log_seqs.clear();
    }
}

pub struct HostUi {
    pub open: HashMap<&'static str, bool>,
    pub dock_tab: DockTab,
    pub filter: LogFilter,
    pub service_mode: sw_core::config::ServiceMode,
    pub poll_secs: u32,
    /// Sections currently ON at the collector, to diff against.
    pub sent_on: HashMap<Section, bool>,
    /// Last collection speed sent to this host (inactive host tabs run Hidden).
    pub sent_throttle: Option<sw_ssh::api::Throttle>,
}

impl Default for HostUi {
    fn default() -> Self {
        Self {
            open: HashMap::from([("scheduled", false)]),
            dock_tab: DockTab::Logs,
            filter: LogFilter::default(),
            service_mode: sw_core::config::ServiceMode::Live,
            poll_secs: 30,
            sent_on: HashMap::new(),
            sent_throttle: None,
        }
    }
}

impl HostUi {
    pub fn is_open(&self, key: &'static str) -> bool {
        self.open.get(key).copied().unwrap_or(true)
    }
}
