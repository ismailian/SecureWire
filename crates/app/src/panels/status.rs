//! Status bar (ui-spec §3.6).

use egui::{Align, Layout, RichText, Ui};
use egui_phosphor::regular as ph;
use sw_core::Section;
use sw_core::format;
use sw_ssh::api::{ConnState, SudoMode, Throttle};

use crate::state::HostView;
use crate::theme::tok::*;

fn item(ui: &mut Ui, text: impl Into<RichText>) {
    ui.add_space(10.0);
    ui.label(text.into());
    ui.add_space(10.0);
}

pub fn show(ui: &mut Ui, v: &HostView, throttle: Throttle) {
    ui.horizontal_centered(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        let small = |t: String, c| RichText::new(t).size(11.5).color(c);

        // Connection block.
        let (label, fg, bg) = match v.state {
            ConnState::Connected => (
                format!(
                    "{} {}@{}",
                    ph::LOCK_KEY,
                    v.info.as_ref().map_or("", |i| &i.user),
                    v.name
                ),
                ACC,
                ACC_DIM,
            ),
            ConnState::Connecting => (format!("{} connecting…", ph::PLUGS), TX2, BG3),
            ConnState::Authenticating => (format!("{} authenticating…", ph::LOCK_KEY), TX2, BG3),
            ConnState::Reconnecting { in_secs } => {
                (format!("reconnecting in {in_secs}s"), WARN, WARN_DIM)
            }
            ConnState::Disconnected => ("disconnected".into(), TX2, BG3),
        };
        egui::Frame::NONE
            .fill(bg)
            .inner_margin(egui::Margin::symmetric(10, 4))
            .show(ui, |ui| {
                ui.label(small(label, fg));
            });
        if let Some(i) = &v.info {
            item(
                ui,
                RichText::new(format!("{}:{}", i.address, i.port))
                    .monospace()
                    .size(11.5)
                    .color(TX2),
            );
            let (t, c) = if i.key_known {
                (
                    format!("{} {} · known host", ph::SEAL_CHECK, i.host_key),
                    TX2,
                )
            } else {
                (format!("{} {} · new key", ph::WARNING, i.host_key), WARN)
            };
            item(ui, small(t, c));
            let (t, c) = match i.sudo {
                SudoMode::Root => ("root", TX2),
                SudoMode::NoPasswd => ("sudo (nopasswd)", TX2),
                SudoMode::Password => ("sudo ✓", TX2),
                SudoMode::None => ("no sudo", WARN),
                SudoMode::Unknown => ("sudo ?", TX3),
            };
            item(ui, small(t.into(), c));
        }
        if let Some(rtt) = v.link.rtt_ms {
            item(ui, small(format!("RTT {rtt} ms"), TX2));
        }

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let age = v.age_s(Section::Cpu);
            let (fast, medium, slow) = throttle.tiers();
            let stale = age.is_some_and(|a| a > 3.0 * fast as f32);
            // Collector items only once a collector is actually sending (demo now, real hosts in M2).
            if age.is_some() {
                item(
                    ui,
                    small(
                        format!(
                            "sample {}s ago",
                            age.map_or("—".into(), |a| format!("{a:.0}"))
                        ),
                        if stale { WARN } else { TX2 },
                    ),
                );
                item(
                    ui,
                    small(
                        format!("overhead ↓ {}", format::rate(v.link.overhead_bps)),
                        TX2,
                    ),
                );
                let tiers = if slow == 0 {
                    format!("tiers {fast}s · {medium}s · off")
                } else {
                    format!("tiers {fast}s · {medium}s · {slow}s")
                };
                item(
                    ui,
                    small(
                        tiers,
                        if throttle == Throttle::Normal {
                            TX2
                        } else {
                            INFO
                        },
                    ),
                );
            }
            item(
                ui,
                small(
                    format!(
                        "{} 1 connection · {} channel{}",
                        ph::GIT_MERGE,
                        v.link.channels,
                        if v.link.channels == 1 { "" } else { "s" }
                    ),
                    TX2,
                ),
            );
        });
    });
}
