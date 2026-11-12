//! SecureWire net side: one tokio runtime thread, one actor task per host.
//!
//! * [`Net::connect`] starts a russh [`actor`] for a real host.
//! * [`spawn_demo_host`] starts the demo source (no network).
//!
//! Both implement the same [`api`] contract.

use std::sync::Arc;

mod actor;
pub mod api;
pub mod collector;
pub mod demo;
pub mod handle;
pub mod pipeline;
mod remote;

pub use api::{Command, Event, EventKind, HostId};
pub use demo::spawn_demo_host;
pub use handle::{CmdTx, HostHandle};

/// Called after events are sent so the UI repaints (wraps `egui::Context::request_repaint`).
pub type Waker = Arc<dyn Fn() + Send + Sync>;

/// The net thread: a current-thread tokio runtime driving every host actor.
pub struct Net {
    rt: tokio::runtime::Handle,
}

impl Net {
    pub fn start() -> std::io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("net".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                };
                let _ = tx.send(Ok(rt.handle().clone()));
                rt.block_on(std::future::pending::<()>());
            })?;
        let rt = rx
            .recv()
            .map_err(|_| std::io::Error::other("net thread died"))??;
        Ok(Self { rt })
    }

    pub fn connect(
        &self,
        id: HostId,
        spec: api::ConnectSpec,
        events: std::sync::mpsc::Sender<Event>,
        wake: Waker,
    ) -> HostHandle {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.rt
            .spawn(actor::Actor::new(id, spec, rx, events, wake).run());
        HostHandle::new(id, CmdTx::Tokio(tx))
    }
}
