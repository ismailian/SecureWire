//! Terminal emulation for SecureWire.
//!
//! * [`Terminal`] wraps `alacritty_terminal::Term` + the VT parser behind a fair
//!   mutex. The net thread calls [`Terminal::advance`] with PTY bytes; the UI
//!   thread locks it briefly per frame to draw.
//! * [`view::TerminalView`] is the egui widget: renderer, keyboard/mouse input,
//!   selection, clipboard. It never touches the network — it returns the bytes
//!   to send and the new size, and the caller forwards them to the host actor.

pub mod input;
pub mod view;

use std::sync::Arc;

use alacritty_terminal::event::{Event as AtEvent, EventListener};
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::sync::FairMutex;
use alacritty_terminal::term::{Config, Term};
use alacritty_terminal::vte::ansi::{Processor, StdSyncHandler};

pub use view::{Palette, TerminalView, ViewOutput};

/// Events the emulator raises that the owner must act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermEvent {
    /// Bytes the terminal must send back to the remote (e.g. replies to
    /// device-attribute or cursor-position queries).
    PtyWrite(Vec<u8>),
    Title(String),
    ResetTitle,
    Bell,
}

pub type EventSink = Arc<dyn Fn(TermEvent) + Send + Sync>;

#[derive(Clone)]
pub struct Proxy(EventSink);

impl EventListener for Proxy {
    fn send_event(&self, ev: AtEvent) {
        let out = match ev {
            AtEvent::PtyWrite(s) => TermEvent::PtyWrite(s.into_bytes()),
            AtEvent::Title(t) => TermEvent::Title(t),
            AtEvent::ResetTitle => TermEvent::ResetTitle,
            AtEvent::Bell => TermEvent::Bell,
            // Clipboard access from the remote (OSC 52) and color queries are
            // deliberately not honoured: remote content must not read or write
            // the local clipboard.
            _ => return,
        };
        (self.0)(out);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub cols: u16,
    pub rows: u16,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.rows as usize
    }
    fn screen_lines(&self) -> usize {
        self.rows as usize
    }
    fn columns(&self) -> usize {
        self.cols as usize
    }
}

pub struct Inner {
    pub term: Term<Proxy>,
    parser: Processor<StdSyncHandler>,
}

/// Shared terminal state. Cheap to clone.
#[derive(Clone)]
pub struct Terminal {
    inner: Arc<FairMutex<Inner>>,
}

impl std::fmt::Debug for Terminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Terminal")
            .field("size", &self.size())
            .finish()
    }
}

impl Terminal {
    pub fn new(size: Size, scrollback: usize, sink: EventSink) -> Self {
        let config = Config {
            scrolling_history: scrollback,
            ..Config::default()
        };
        let term = Term::new(config, &size, Proxy(sink));
        Self {
            inner: Arc::new(FairMutex::new(Inner {
                term,
                parser: Processor::new(),
            })),
        }
    }

    /// Feed bytes received from the remote PTY.
    pub fn advance(&self, bytes: &[u8]) {
        let mut g = self.inner.lock();
        let Inner { term, parser } = &mut *g;
        parser.advance(term, bytes);
    }

    pub fn size(&self) -> Size {
        let g = self.inner.lock();
        Size {
            cols: g.term.columns() as u16,
            rows: g.term.screen_lines() as u16,
        }
    }

    pub fn resize(&self, size: Size) {
        self.inner.lock().term.resize(size);
    }

    pub fn lock(&self) -> parking_lot::MutexGuard<'_, Inner> {
        self.inner.lock()
    }

    /// Plain text of the visible screen (tests, "copy screen").
    pub fn screen_text(&self) -> String {
        let g = self.inner.lock();
        let mut out = String::new();
        let mut line = None;
        for cell in g.term.grid().display_iter() {
            if line.is_some_and(|l| l != cell.point.line) {
                out.truncate(out.trim_end_matches(' ').len());
                out.push('\n');
            }
            line = Some(cell.point.line);
            out.push(cell.c);
        }
        out.truncate(out.trim_end_matches(' ').len());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn term() -> (Terminal, Arc<Mutex<Vec<TermEvent>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let e2 = events.clone();
        let t = Terminal::new(
            Size { cols: 20, rows: 4 },
            100,
            Arc::new(move |e| e2.lock().unwrap().push(e)),
        );
        (t, events)
    }

    #[test]
    fn prints_and_wraps() {
        let (t, _) = term();
        t.advance(b"hello\r\nworld \x1b[31mred\x1b[0m");
        assert_eq!(
            t.screen_text().lines().take(2).collect::<Vec<_>>(),
            ["hello", "world red"]
        );
    }

    #[test]
    fn answers_device_attributes_and_sets_title() {
        let (t, ev) = term();
        t.advance(b"\x1b]0;my title\x07\x1b[c");
        let ev = ev.lock().unwrap();
        assert!(ev.contains(&TermEvent::Title("my title".into())));
        assert!(
            ev.iter()
                .any(|e| matches!(e, TermEvent::PtyWrite(b) if b.starts_with(b"\x1b[")))
        );
    }

    #[test]
    fn resize_changes_size() {
        let (t, _) = term();
        t.resize(Size { cols: 80, rows: 24 });
        assert_eq!(t.size(), Size { cols: 80, rows: 24 });
    }
}
