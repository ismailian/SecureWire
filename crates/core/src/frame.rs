//! Incremental decoder for the collector's framed output (protocol §2.2).
//!
//! ```text
//! ␞SW1 <section> <seq>      start of a frame
//! <payload lines>
//! ␞END <section> <seq>      end of that frame
//! ␞SAME <section> <seq>     payload unchanged since last emit
//! ␞ERR <section> <seq> <code>
//! ␞HELLO <proto> <bash_version>
//! ␞PONG <n>
//! ```
//! Bytes may arrive split anywhere (SSH packets don't respect lines). Partial
//! lines are buffered; a frame interrupted by another `SW1` is dropped.

use memchr::memchr;

/// Record separator that starts every control line.
pub const RS: u8 = 0x1e;

/// Highest protocol version this client understands.
pub const PROTOCOL_VERSION: u32 = 1;

/// Hard cap on a single frame's payload. Anything bigger is a bug or hostile.
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    Static,
    Cpu,
    Mem,
    Net,
    Dio,
    Df,
    Who,
    Ps,
    Svc,
    Ports,
    Conns,
    Fw,
    F2b,
    Auth,
    Timers,
}

impl Section {
    pub const ALL: [Section; 15] = [
        Section::Static,
        Section::Cpu,
        Section::Mem,
        Section::Net,
        Section::Dio,
        Section::Df,
        Section::Who,
        Section::Ps,
        Section::Svc,
        Section::Ports,
        Section::Conns,
        Section::Fw,
        Section::F2b,
        Section::Auth,
        Section::Timers,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Section::Static => "static",
            Section::Cpu => "cpu",
            Section::Mem => "mem",
            Section::Net => "net",
            Section::Dio => "dio",
            Section::Df => "df",
            Section::Who => "who",
            Section::Ps => "ps",
            Section::Svc => "svc",
            Section::Ports => "ports",
            Section::Conns => "conns",
            Section::Fw => "fw",
            Section::F2b => "f2b",
            Section::Auth => "auth",
            Section::Timers => "timers",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.name() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello {
        proto: u32,
        shell: String,
    },
    Data {
        section: Section,
        seq: u64,
        payload: String,
    },
    Same {
        section: Section,
        seq: u64,
    },
    Err {
        section: Section,
        seq: u64,
        code: String,
    },
    Pong(u64),
}

#[derive(Debug)]
struct Open {
    section: Section,
    seq: u64,
    payload: String,
}

/// Feed bytes with [`FrameDecoder::push`], collect complete frames.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    pending: Vec<u8>,
    open: Option<Open>,
    /// Frames dropped because they were interrupted, oversized, or malformed.
    pub dropped: u64,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append bytes and push every completed frame into `out`.
    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<Frame>) {
        self.pending.extend_from_slice(bytes);
        let mut start = 0;
        while let Some(nl) = memchr(b'\n', &self.pending[start..]) {
            let end = start + nl;
            // Take the line out by index to keep the borrow checker happy.
            let line = String::from_utf8_lossy(&self.pending[start..end]).into_owned();
            start = end + 1;
            self.line(line.trim_end_matches('\r'), out);
        }
        self.pending.drain(..start);
        if self.pending.len() > MAX_PAYLOAD {
            // A single line this long is never legitimate.
            self.pending.clear();
            self.open = None;
            self.dropped += 1;
        }
    }

    fn line(&mut self, line: &str, out: &mut Vec<Frame>) {
        let Some(ctrl) = line.strip_prefix(RS as char) else {
            if let Some(open) = &mut self.open {
                if open.payload.len() + line.len() + 1 > MAX_PAYLOAD {
                    self.open = None;
                    self.dropped += 1;
                    return;
                }
                if !open.payload.is_empty() {
                    open.payload.push('\n');
                }
                open.payload.push_str(line);
            }
            // Lines outside a frame (stray stderr, motd) are ignored.
            return;
        };

        let mut it = ctrl.split_ascii_whitespace();
        let kind = it.next().unwrap_or("");
        match kind {
            "SW1" => {
                if self.open.take().is_some() {
                    self.dropped += 1;
                }
                if let Some((section, seq)) = section_seq(&mut it) {
                    self.open = Some(Open {
                        section,
                        seq,
                        payload: String::new(),
                    });
                } else {
                    self.dropped += 1;
                }
            }
            "END" => match (self.open.take(), section_seq(&mut it)) {
                (Some(o), Some((section, seq))) if o.section == section && o.seq == seq => {
                    out.push(Frame::Data {
                        section,
                        seq,
                        payload: o.payload,
                    });
                }
                (Some(_), _) | (None, Some(_)) => self.dropped += 1,
                (None, None) => {}
            },
            "SAME" => {
                if let Some((section, seq)) = section_seq(&mut it) {
                    out.push(Frame::Same { section, seq });
                }
            }
            "ERR" => {
                if let Some((section, seq)) = section_seq(&mut it) {
                    let code = it.next().unwrap_or("unknown").to_owned();
                    out.push(Frame::Err { section, seq, code });
                }
            }
            "HELLO" => {
                let proto = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                let shell = it.next().unwrap_or("").to_owned();
                out.push(Frame::Hello { proto, shell });
            }
            "PONG" => {
                if let Some(n) = it.next().and_then(|s| s.parse().ok()) {
                    out.push(Frame::Pong(n));
                }
            }
            _ => {} // unknown control line: forward compatible
        }
    }
}

fn section_seq<'a>(it: &mut impl Iterator<Item = &'a str>) -> Option<(Section, u64)> {
    let section = Section::from_name(it.next()?)?;
    let seq = it.next()?.parse().ok()?;
    Some((section, seq))
}

/// Encode a data frame exactly like the collector does. Used by the demo source and tests.
pub fn encode(section: Section, seq: u64, payload: &str) -> Vec<u8> {
    let rs = RS as char;
    format!(
        "{rs}SW1 {n} {seq}\n{payload}\n{rs}END {n} {seq}\n",
        n = section.name()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(chunks: &[&[u8]]) -> (Vec<Frame>, u64) {
        let mut d = FrameDecoder::new();
        let mut out = Vec::new();
        for c in chunks {
            d.push(c, &mut out);
        }
        (out, d.dropped)
    }

    #[test]
    fn whole_frame() {
        let b = encode(Section::Cpu, 7, "cpu 1 2 3\ncpu0 1 2 3");
        let (f, dropped) = decode_all(&[&b]);
        assert_eq!(dropped, 0);
        assert_eq!(
            f,
            vec![Frame::Data {
                section: Section::Cpu,
                seq: 7,
                payload: "cpu 1 2 3\ncpu0 1 2 3".into()
            }]
        );
    }

    #[test]
    fn split_at_every_byte() {
        let mut b = b"\x1eHELLO 1 5.2.21\n".to_vec();
        b.extend(encode(Section::Mem, 1, "MemTotal: 10 kB"));
        b.extend(b"\x1eSAME df 2\n\x1ePONG 9\n");
        let chunks: Vec<&[u8]> = b.chunks(1).collect();
        let (f, dropped) = decode_all(&chunks);
        assert_eq!(dropped, 0);
        assert_eq!(f.len(), 4);
        assert_eq!(
            f[0],
            Frame::Hello {
                proto: 1,
                shell: "5.2.21".into()
            }
        );
        assert_eq!(
            f[2],
            Frame::Same {
                section: Section::Df,
                seq: 2
            }
        );
        assert_eq!(f[3], Frame::Pong(9));
    }

    #[test]
    fn interrupted_frame_is_dropped() {
        let (f, dropped) =
            decode_all(&[b"\x1eSW1 cpu 1\npartial\n", &encode(Section::Cpu, 2, "ok")]);
        assert_eq!(dropped, 1);
        assert_eq!(
            f,
            vec![Frame::Data {
                section: Section::Cpu,
                seq: 2,
                payload: "ok".into()
            }]
        );
    }

    #[test]
    fn mismatched_end_is_dropped() {
        let (f, dropped) = decode_all(&[b"\x1eSW1 cpu 1\nx\n\x1eEND cpu 2\n"]);
        assert!(f.is_empty());
        assert_eq!(dropped, 1);
    }

    #[test]
    fn noise_outside_frames_is_ignored_and_crlf_ok() {
        let (f, _) = decode_all(&[b"Welcome!\r\n\x1eERR fw 3 missing\r\n\x1eBOGUS x\n"]);
        assert_eq!(
            f,
            vec![Frame::Err {
                section: Section::Fw,
                seq: 3,
                code: "missing".into()
            }]
        );
    }

    #[test]
    fn unknown_section_is_dropped() {
        let (f, dropped) = decode_all(&[b"\x1eSW1 nope 1\nx\n\x1eEND nope 1\n"]);
        assert!(f.is_empty());
        assert_eq!(dropped, 1);
    }
}
