//! Handle the UI holds per host. Works for both the demo source (std thread)
//! and the russh actor (tokio task).

use crate::api::{Command, HostId};

#[derive(Clone)]
pub enum CmdTx {
    Std(std::sync::mpsc::Sender<Command>),
    Tokio(tokio::sync::mpsc::UnboundedSender<Command>),
}

impl CmdTx {
    pub fn send(&self, c: Command) {
        let _ = match self {
            CmdTx::Std(t) => t.send(c).map_err(|_| ()),
            CmdTx::Tokio(t) => t.send(c).map_err(|_| ()),
        };
    }
}

/// Dropping the handle shuts the host down.
pub struct HostHandle {
    pub id: HostId,
    tx: CmdTx,
}

impl HostHandle {
    pub fn new(id: HostId, tx: CmdTx) -> Self {
        Self { id, tx }
    }

    pub fn send(&self, c: Command) {
        self.tx.send(c);
    }

    /// A cloneable sender, e.g. for a terminal's reply sink.
    pub fn sender(&self) -> CmdTx {
        self.tx.clone()
    }
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        self.tx.send(Command::Shutdown);
    }
}
