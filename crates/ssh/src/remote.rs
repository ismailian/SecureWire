//! Exec channels on an established connection: probe (§4), sudo check (§9),
//! and the long-lived collector (§2). Each is one more channel on the same
//! SSH connection.

use std::time::{Duration, Instant};

use russh::ChannelMsg;
use russh::client::{self, Handle};
use secrecy::{ExposeSecret, SecretString};
use sw_core::FrameDecoder;
use sw_core::frame::Frame;
use sw_core::parse::{Probe, parse_probe};
use tokio::sync::mpsc::UnboundedSender;

use crate::api::{EventKind, Throttle};
use crate::collector;
use crate::pipeline::Pipeline;

const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
const SUDO_TIMEOUT: Duration = Duration::from_secs(20);
/// Probe output larger than this is not a probe.
const PROBE_MAX: usize = 16 * 1024;
/// Packets arriving this close together reach the UI as one batch (one repaint).
const COALESCE: Duration = Duration::from_millis(30);

pub(crate) type Writer = russh::ChannelWriteHalf<client::Msg>;

/// Run `probe.sh` and parse its `key=value` output.
pub(crate) async fn run_probe<H: client::Handler>(h: &Handle<H>) -> Result<Probe, String> {
    let fut = async {
        let mut ch = h.channel_open_session().await.map_err(|e| e.to_string())?;
        ch.exec(false, collector::PROBE_COMMAND)
            .await
            .map_err(|e| e.to_string())?;
        ch.data(collector::PROBE.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        ch.eof().await.map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    out.extend_from_slice(&data);
                    if out.len() > PROBE_MAX {
                        return Err("probe output too large".to_owned());
                    }
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(parse_probe(&String::from_utf8_lossy(&out)))
    };
    tokio::time::timeout(PROBE_TIMEOUT, fut)
        .await
        .map_err(|_| "probe timed out".to_owned())?
}

/// `sudo -S -k -p "" true` with the password as the only stdin line.
/// Ok(true) = accepted. The password never touches argv or the environment.
pub(crate) async fn verify_sudo<H: client::Handler>(
    h: &Handle<H>,
    password: &SecretString,
) -> Result<bool, String> {
    let fut = async {
        let mut ch = h.channel_open_session().await.map_err(|e| e.to_string())?;
        ch.exec(false, collector::SUDO_VERIFY_COMMAND)
            .await
            .map_err(|e| e.to_string())?;
        let mut line = Vec::with_capacity(password.expose_secret().len() + 1);
        line.extend_from_slice(password.expose_secret().as_bytes());
        line.push(b'\n');
        let sent = ch.data(&line[..]).await;
        line.iter_mut().for_each(|b| *b = 0);
        sent.map_err(|e| e.to_string())?;
        ch.eof().await.map_err(|e| e.to_string())?;
        let mut status = None;
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(status == Some(0))
    };
    tokio::time::timeout(SUDO_TIMEOUT, fut)
        .await
        .map_err(|_| "sudo check timed out".to_owned())?
}

pub(crate) enum CollectorMsg {
    Rtt(u32),
    /// Monitoring bytes per second over the last window.
    Overhead(f64),
    Ended {
        generation: u64,
    },
}

/// Start the collector channel. Frames are parsed on this (net) thread by the
/// reader task; the UI receives ready-to-draw events, one wake-up per chunk.
pub(crate) async fn start_collector<H: client::Handler>(
    h: &Handle<H>,
    throttle: Throttle,
    generation: u64,
    clock: Instant,
    emit: impl Fn(Vec<EventKind>) + Send + 'static,
    msgs: UnboundedSender<CollectorMsg>,
) -> Result<Writer, String> {
    let ch = h.channel_open_session().await.map_err(|e| e.to_string())?;
    ch.exec(false, collector::launch_command(throttle))
        .await
        .map_err(|e| e.to_string())?;
    ch.data(collector::SCRIPT.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let (mut read, write) = ch.split();
    tokio::spawn(async move {
        let mut dec = FrameDecoder::new();
        let mut pipe = Pipeline::new();
        let mut frames = Vec::new();
        let mut window = (Instant::now(), 0usize);
        let mut open = true;
        while open {
            // Block for the first packet, then gather whatever follows within
            // COALESCE: bash writes each section separately, and one tick should
            // cost the UI one wake-up, not one per packet.
            let mut msg = read.wait().await;
            let mut out = Vec::new();
            loop {
                match msg {
                    None | Some(ChannelMsg::Close) => {
                        open = false;
                        break;
                    }
                    Some(ChannelMsg::Data { data }) => {
                        window.1 += data.len();
                        dec.push(&data, &mut frames);
                        for f in frames.drain(..) {
                            if let Frame::Pong(n) = f {
                                let now = clock.elapsed().as_millis() as u64;
                                let rtt = now.saturating_sub(n).min(u32::MAX as u64) as u32;
                                let _ = msgs.send(CollectorMsg::Rtt(rtt));
                            } else {
                                pipe.on_frame(f, &mut out);
                            }
                        }
                    }
                    Some(_) => {}
                }
                match tokio::time::timeout(COALESCE, read.wait()).await {
                    Ok(next) => msg = next,
                    Err(_) => break,
                }
            }
            if let Some(proto) = pipe
                .protocol
                .take()
                .filter(|&p| p > sw_core::frame::PROTOCOL_VERSION)
            {
                out.push(EventKind::Error(format!(
                    "Collector protocol {proto} is newer than this app understands"
                )));
            }
            if !out.is_empty() {
                emit(out);
            }
            let elapsed = window.0.elapsed();
            if elapsed >= Duration::from_secs(5) {
                let _ = msgs.send(CollectorMsg::Overhead(
                    window.1 as f64 / elapsed.as_secs_f64(),
                ));
                window = (Instant::now(), 0);
            }
        }
        let _ = msgs.send(CollectorMsg::Ended { generation });
    });
    Ok(write)
}

/// Write one control line; errors mean the channel is gone (the reader reports it).
pub(crate) async fn send_line(w: &Writer, line: &str) {
    let mut b = Vec::with_capacity(line.len() + 1);
    b.extend_from_slice(line.as_bytes());
    b.push(b'\n');
    let _ = w.data_bytes(b).await;
}
