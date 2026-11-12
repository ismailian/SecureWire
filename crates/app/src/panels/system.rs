//! Left panel — SYSTEM (ui-spec §3.2).

use egui::{Align, Layout, RichText, ScrollArea, Ui, vec2};
use egui_phosphor::regular as ph;
use sw_core::Section;
use sw_core::format;
use sw_ssh::api::SudoMode;

use crate::state::{HostUi, HostView};
use crate::theme::tok::*;
use crate::widgets::{self as w, right, section};

const SPARK_POINTS: usize = 60;

pub fn show(ui: &mut Ui, v: &HostView, hu: &mut HostUi) {
    super::panel_header(ui, "SYSTEM", |ui| {
        let age = v
            .age_s(Section::Cpu)
            .map_or("—".into(), |a| format!("{a:.0}s"));
        ui.label(w::faint(age));
    });
    ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
        ui.spacing_mut().item_spacing.y = 0.0;
        host(ui, v, hu);
        cpu(ui, v, hu);
        memory(ui, v, hu);
        disk(ui, v, hu);
        network(ui, v, hu);
        sessions(ui, v, hu);
    });
}

fn open<'a>(hu: &'a mut HostUi, key: &'static str) -> &'a mut bool {
    hu.open.entry(key).or_insert(true)
}

fn kv(ui: &mut Ui, k: &str, val: impl Into<RichText>) {
    ui.horizontal(|ui| {
        ui.label(w::dim(k));
        right(ui, |ui| ui.label(val.into()));
    });
}

fn host(ui: &mut Ui, v: &HostView, hu: &mut HostUi) {
    let up = v
        .cpu
        .as_ref()
        .map(|c| format!("up {}", format::duration(c.uptime_s as u64)));
    section(
        ui,
        open(hu, "host"),
        ph::HARD_DRIVES,
        "Host",
        |ui| {
            ui.label(w::meta(up.unwrap_or_default()));
        },
        |ui| {
            ui.spacing_mut().item_spacing.y = 3.0;
            let s = &v.stat;
            kv(ui, "OS", s.os.as_str());
            kv(ui, "Kernel", w::mono(&s.kernel, TX1));
            kv(
                ui,
                "Hardware",
                format!(
                    "{} vCPU · {} GiB · {}",
                    s.cpus,
                    format::gib(s.mem_total),
                    s.virt.to_uppercase()
                ),
            );
            if let Some(i) = &v.info {
                kv(ui, "Address", w::mono(&i.address, TX1));
                ui.horizontal(|ui| {
                    ui.label(w::dim("Privileges"));
                    right(ui, |ui| match i.sudo {
                        SudoMode::Root => w::badge(ui, "root", OK, OK_DIM),
                        SudoMode::NoPasswd => w::badge(ui, "sudo nopasswd", OK, OK_DIM),
                        SudoMode::Password => w::badge(ui, "sudo ok", OK, OK_DIM),
                        SudoMode::None => w::badge(ui, "no sudo", WARN, WARN_DIM),
                        SudoMode::Unknown => w::badge(ui, "not probed", TX2, BG3),
                    });
                });
            }
        },
    );
}

fn cpu(ui: &mut Ui, v: &HostView, hu: &mut HostUi) {
    let load = v
        .cpu
        .as_ref()
        .map(|c| format!("load {:.2} {:.2} {:.2}", c.load[0], c.load[1], c.load[2]));
    section(
        ui,
        open(hu, "cpu"),
        ph::CPU,
        "CPU",
        |ui| {
            ui.label(w::meta(load.unwrap_or_default()));
        },
        |ui| {
            let Some(c) = &v.cpu else {
                ui.label(w::faint("waiting for second sample…"));
                return;
            };
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{:.0}%", c.total))
                        .size(22.0)
                        .color(TX0),
                );
                ui.label(w::meta(format!(
                    "user {:.0} · sys {:.0} · iowait {:.0} · steal {:.0}",
                    c.user, c.system, c.iowait, c.steal
                )));
            });
            ui.add_space(4.0);
            w::sparkline(
                ui,
                38.0,
                SPARK_POINTS,
                &[(&v.cpu_hist, ACC, true)],
                Some(100.0),
            );
            ui.add_space(6.0);
            // Per-core bars, 4 columns.
            let cols = 4;
            let gap = 6.0;
            let cw = (ui.available_width() - gap * (cols - 1) as f32) / cols as f32;
            for (ri, row) in c.cores.chunks(cols).enumerate() {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = gap;
                    for (i, &u) in row.iter().enumerate() {
                        ui.allocate_ui(vec2(cw, 22.0), |ui| {
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                let idx = ri * cols + i;
                                ui.label(w::faint(format!("cpu{idx} {u:.0}%")));
                                let col = if u > 85.0 {
                                    ERR
                                } else if u > 65.0 {
                                    WARN
                                } else {
                                    ACC
                                };
                                w::bar(ui, cw, 4.0, &[(u / 100.0, col)]);
                            });
                        });
                    }
                });
            }
        },
    );
}

fn memory(ui: &mut Ui, v: &HostView, hu: &mut HostUi) {
    let sum = v
        .mem
        .map(|m| format!("{} / {} GiB", format::gib(m.used), format::gib(m.total)));
    section(
        ui,
        open(hu, "mem"),
        ph::MEMORY,
        "Memory",
        |ui| {
            ui.label(w::meta(sum.unwrap_or_default()));
        },
        |ui| {
            let Some(m) = v.mem else { return };
            ui.spacing_mut().item_spacing.y = 4.0;
            let row = |ui: &mut Ui, label: &str, segs: &[(f32, egui::Color32)], pct: f32| {
                ui.horizontal(|ui| {
                    ui.add_sized(vec2(36.0, 16.0), egui::Label::new(w::dim(label)));
                    let bw = ui.available_width() - 42.0;
                    w::bar(ui, bw, 6.0, segs);
                    right(ui, |ui| {
                        ui.label(RichText::new(format!("{pct:.0}%")).color(TX1))
                    });
                });
            };
            row(
                ui,
                "RAM",
                &[(m.used_frac(), ACC), (m.cache_frac(), ACC_MID)],
                (m.used_frac() + m.cache_frac()) * 100.0,
            );
            row(ui, "Swap", &[(m.swap_frac(), ACC)], m.swap_frac() * 100.0);
            ui.horizontal(|ui| {
                legend(ui, ACC, &format!("used {}", format::gib(m.used)));
                legend(ui, ACC_MID, &format!("cache {}", format::gib(m.cache)));
                legend(
                    ui,
                    BG3,
                    &format!("free {} GiB", format::gib(m.total - m.used - m.cache)),
                );
            });
        },
    );
}

fn legend(ui: &mut Ui, c: egui::Color32, t: &str) {
    let (r, _) = ui.allocate_exact_size(vec2(8.0, 8.0), egui::Sense::hover());
    ui.painter().rect_filled(r, 2, c);
    ui.label(w::faint(t));
}

fn disk(ui: &mut Ui, v: &HostView, hu: &mut HostUi) {
    let over = v.mounts.iter().filter(|m| m.frac() >= 0.8).count();
    section(
        ui,
        open(hu, "disk"),
        ph::HARD_DRIVE,
        "Disk",
        |ui| {
            if over > 0 {
                w::badge(ui, &format!("{over} > 80%"), WARN, WARN_DIM);
            } else if !v.mounts.is_empty() {
                ui.label(w::meta("ok"));
            }
        },
        |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for m in &v.mounts {
                let f = m.frac();
                let col = if f >= 0.9 {
                    ERR
                } else if f >= 0.8 {
                    WARN
                } else {
                    ACC
                };
                ui.horizontal(|ui| {
                    ui.label(w::mono(&m.mount, TX1)).on_hover_text(&m.fs);
                    right(ui, |ui| {
                        ui.label(w::meta(format!(
                            "{} / {}",
                            format::bytes(m.used),
                            format::bytes(m.size)
                        )))
                    });
                });
                ui.horizontal(|ui| {
                    let bw = ui.available_width() - 42.0;
                    w::bar(ui, bw, 6.0, &[(f, col)]);
                    right(ui, |ui| {
                        ui.label(
                            RichText::new(format!("{:.0}%", f * 100.0)).color(if f >= 0.8 {
                                col
                            } else {
                                TX1
                            }),
                        )
                    });
                });
                ui.add_space(4.0);
            }
            if let Some(d) = v.dio {
                ui.horizontal(|ui| {
                    ui.label(w::dim("I/O"));
                    ui.label(format!(
                        "read {} · write {}",
                        format::rate(d.read_bps),
                        format::rate(d.write_bps)
                    ));
                });
            }
        },
    );
}

fn network(ui: &mut Ui, v: &HostView, hu: &mut HostUi) {
    let iface = v.net.as_ref().map(|n| n.iface.clone());
    section(
        ui,
        open(hu, "net"),
        ph::NETWORK,
        "Network",
        |ui| {
            ui.label(w::mono(iface.unwrap_or_default(), TX2));
        },
        |ui| {
            let Some(n) = &v.net else { return };
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{} {}", ph::ARROW_DOWN, format::rate(n.rx_bps)))
                        .color(INFO),
                );
                ui.label(
                    RichText::new(format!("{} {}", ph::ARROW_UP, format::rate(n.tx_bps)))
                        .color(ACC),
                );
            });
            ui.add_space(4.0);
            w::sparkline(
                ui,
                38.0,
                SPARK_POINTS,
                &[(&v.rx_hist, INFO, true), (&v.tx_hist, ACC, false)],
                None,
            );
            ui.add_space(6.0);
            ui.label(w::faint("LISTENING · arrives in M3"));
        },
    );
}

fn sessions(ui: &mut Ui, v: &HostView, hu: &mut HostUi) {
    let n = v
        .sessions
        .iter()
        .map(|s| s.user.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();
    section(
        ui,
        open(hu, "who"),
        ph::USERS,
        "Sessions",
        |ui| {
            ui.label(w::meta(format!(
                "{n} user{}",
                if n == 1 { "" } else { "s" }
            )));
        },
        |ui| {
            let me = v.info.as_ref().map(|i| i.user.as_str());
            let mut you_marked = false;
            for s in &v.sessions {
                ui.horizontal(|ui| {
                    let is_me = !you_marked && Some(s.user.as_str()) == me && s.idle == ".";
                    ui.label(RichText::new(ph::USER).color(if is_me { ACC } else { TX2 }));
                    ui.label(w::mono(&s.user, TX0));
                    ui.label(w::mono(&s.tty, TX2));
                    ui.label(w::mono(&s.from, TX2));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if is_me {
                            you_marked = true;
                            w::badge(ui, "you", INFO, INFO_DIM);
                        } else if s.idle != "." {
                            ui.label(w::faint(format!("idle {}", s.idle)));
                        }
                    });
                });
            }
        },
    );
}
