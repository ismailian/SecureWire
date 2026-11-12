//! SecureWire net side.
//!
//! M0 ships only the [`demo`] source; the russh-based `HostActor` arrives in M1
//! and implements the same [`api`] contract.

use std::sync::Arc;

pub mod api;
pub mod demo;
pub mod pipeline;

pub use api::{Command, Event, EventKind, HostId};
pub use demo::{HostHandle, spawn_demo_host};

/// Called after events are sent so the UI repaints (wraps `egui::Context::request_repaint`).
pub type Waker = Arc<dyn Fn() + Send + Sync>;
