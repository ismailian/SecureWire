//! SecureWire core: pure logic shared by the SSH layer and the UI.
//!
//! No I/O, no threads, no UI. Everything here is deterministic and unit-tested
//! against captured fixtures (see `tests/`).
//!
//! Wire format: `design/collector-protocol.md`.

pub mod alerts;
pub mod config;
pub mod format;
pub mod frame;
pub mod logs;
pub mod metrics;
pub mod model;
pub mod parse;
pub mod shell;

pub use frame::{Frame, FrameDecoder, Section};
