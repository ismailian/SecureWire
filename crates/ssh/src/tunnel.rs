//! One-click tunnels (protocol §13): a local listener on 127.0.0.1 whose connections are
//! carried as `direct-tcpip` channels on the host's existing SSH connection — no second
//! TCP connection to the server, nothing installed there (same mechanism as ProxyJump).
//!
//! A tunnel outlives reconnects: every accepted connection uses whatever session is
//! current; while offline, connections are dropped at once.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use russh::client::{self, Handle};

/// The current SSH session, shared with tunnel tasks (`None` while offline).
pub(crate) type Live<H> = Arc<parking_lot::Mutex<Option<Arc<Handle<H>>>>>;

pub(crate) struct Tunnel {
    pub local_port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Stops accepting and releases the local port; open connections end with their channel.
        self.task.abort();
    }
}

/// Local port to try first: the same number when it's unprivileged (or on Windows, where
/// low ports aren't reserved), else the number + 10000; any free port as the last resort.
fn candidates(remote_port: u16, wanted: u16) -> Vec<u16> {
    if wanted != 0 {
        return vec![wanted];
    }
    let mut v = Vec::new();
    if remote_port >= 1024 || cfg!(windows) {
        v.push(remote_port);
    }
    if let Some(p) = remote_port.checked_add(10_000) {
        v.push(p);
    }
    v.push(0);
    v
}

/// Bind on 127.0.0.1 and start forwarding to `host:port` as seen from the server.
/// `host` must be an IP literal (it comes from `ss`, see `Listener::reach_addr`).
pub(crate) fn open<H>(
    live: Live<H>,
    host: &str,
    port: u16,
    wanted_local: u16,
) -> Result<Tunnel, String>
where
    H: client::Handler + Send + 'static,
{
    let target: IpAddr = host
        .parse()
        .map_err(|_| format!("Not an IP address: {host:?}"))?;
    if port == 0 {
        return Err("Port must be 1–65535".into());
    }
    let mut last = String::new();
    let mut bound = None;
    for p in candidates(port, wanted_local) {
        match std::net::TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), p)) {
            Ok(l) => {
                bound = Some(l);
                break;
            }
            Err(e) => last = format!("127.0.0.1:{p}: {e}"),
        }
    }
    let std_listener = bound.ok_or(last)?;
    std_listener
        .set_nonblocking(true)
        .map_err(|e| e.to_string())?;
    let local_port = std_listener.local_addr().map_err(|e| e.to_string())?.port();
    let listener = tokio::net::TcpListener::from_std(std_listener).map_err(|e| e.to_string())?;
    let host = target.to_string();
    let task = tokio::spawn(async move {
        while let Ok((mut sock, peer)) = listener.accept().await {
            let session = live.lock().clone();
            let host = host.clone();
            tokio::spawn(async move {
                let Some(h) = session else { return }; // offline: refuse by closing
                let _ = sock.set_nodelay(true);
                if let Ok(ch) = h
                    .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", peer.port() as u32)
                    .await
                {
                    let mut stream = ch.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
                }
            });
        }
    });
    Ok(Tunnel { local_port, task })
}

#[cfg(test)]
mod tests {
    use super::candidates;

    #[test]
    fn local_port_choice() {
        assert_eq!(candidates(3306, 0), vec![3306, 13306, 0]);
        assert_eq!(candidates(6000, 7000), vec![7000]);
        assert_eq!(
            *candidates(60000, 0).last().unwrap(),
            0,
            "no overflow past 65535"
        );
        if !cfg!(windows) {
            assert_eq!(candidates(80, 0), vec![10080, 0]);
        }
    }
}
