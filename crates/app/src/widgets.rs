//! Small, cheap widgets drawn with plain `Painter` calls (ui-spec §1.7).

use egui::{
    Align, Align2, Color32, CornerRadius, Layout, Mesh, Pos2, Rect, Response, RichText, Sense,
    Shape, Stroke, Ui, UiBuilder, Vec2, pos2, vec2,
};
use egui_phosphor::regular as ph;
use sw_core::metrics::RingBuffer;

use crate::theme::{self, R, tok::*};

pub const SECTION_H: f32 = 28.0;
pub const PAD_X: f32 = 12.0;

/// Collapsible section with a one-line summary in its header (ui-spec §1.2).
/// Returns whether the section is open.
pub fn section(
    ui: &mut Ui,
    open: &mut bool,
    icon: &str,
    title: &str,
    summary: impl FnOnce(&mut Ui),
    body: impl FnOnce(&mut Ui),
) {
    let (rect, resp) =
        ui.allocate_exact_size(vec2(ui.available_width(), SECTION_H), Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(rect, 0, BG2);
    }
    if resp.clicked() {
        *open = !*open;
    }
    let p = ui.painter();
    let y = rect.center().y;
    let chev = if *open {
        ph::CARET_DOWN
    } else {
        ph::CARET_RIGHT
    };
    p.text(
        pos2(rect.left() + 8.0, y),
        Align2::LEFT_CENTER,
        chev,
        theme::prop(10.5),
        TX3,
    );
    p.text(
        pos2(rect.left() + 24.0, y),
        Align2::LEFT_CENTER,
        icon,
        theme::prop(13.0),
        TX2,
    );
    p.text(
        pos2(rect.left() + 44.0, y),
        Align2::LEFT_CENTER,
        title,
        theme::prop(12.5),
        TX0,
    );
    let right = Rect::from_min_max(
        pos2(rect.left() + 120.0, rect.top()),
        pos2(rect.right() - 8.0, rect.bottom()),
    );
    ui.scope_builder(
        UiBuilder::new()
            .max_rect(right)
            .layout(Layout::right_to_left(Align::Center)),
        |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            summary(ui);
        },
    );
    if *open {
        egui::Frame::NONE
            .inner_margin(egui::Margin {
                left: PAD_X as i8,
                right: PAD_X as i8,
                top: 2,
                bottom: 12,
            })
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                body(ui);
            });
    }
    hline(ui);
}

/// Full-width 1 px hairline at the cursor.
pub fn hline(ui: &mut Ui) {
    let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().rect_filled(r, 0, LINE);
}

pub fn meta(text: impl Into<String>) -> RichText {
    RichText::new(text).color(TX2).size(11.5)
}

pub fn dim(text: impl Into<String>) -> RichText {
    RichText::new(text).color(TX2)
}

pub fn faint(text: impl Into<String>) -> RichText {
    RichText::new(text).color(TX3).size(11.0)
}

pub fn strong(text: impl Into<String>) -> RichText {
    RichText::new(text).color(TX0)
}

pub fn mono(text: impl Into<String>, color: Color32) -> RichText {
    RichText::new(text).monospace().color(color)
}

/// Colored status dot.
pub fn dot(ui: &mut Ui, color: Color32) -> Response {
    let (r, resp) = ui.allocate_exact_size(vec2(8.0, 8.0), Sense::hover());
    ui.painter().circle_filled(r.center(), 3.5, color);
    resp
}

/// Small uppercase pill: `SUDO -n OK`, `1 > 80%`, `BANNED`.
pub fn badge(ui: &mut Ui, text: &str, fg: Color32, bg: Color32) -> Response {
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_uppercase(), theme::prop(10.0), fg);
    let size = galley.size() + vec2(10.0, 3.0);
    let (r, resp) = ui.allocate_exact_size(vec2(size.x, 16.0), Sense::hover());
    ui.painter().rect_filled(r, R, bg);
    ui.painter()
        .galley(r.center() - galley.size() / 2.0, galley, fg);
    resp
}

/// Horizontal bar made of colored segments (fractions 0–1), on a `bg-3` track.
pub fn bar(ui: &mut Ui, width: f32, height: f32, segments: &[(f32, Color32)]) -> Response {
    let (r, resp) = ui.allocate_exact_size(vec2(width.max(10.0), height), Sense::hover());
    let p = ui.painter();
    p.rect_filled(r, 2, BG3);
    let mut x = r.left();
    for &(f, c) in segments {
        let w = r.width() * f.clamp(0.0, 1.0);
        if w > 0.5 {
            let seg =
                Rect::from_min_max(pos2(x, r.top()), pos2((x + w).min(r.right()), r.bottom()));
            p.rect_filled(seg, CornerRadius::same(2), c);
            x += w;
        }
    }
    resp
}

/// Sparkline over the newest `n` samples of each series. `max` = None → auto-scale.
pub fn sparkline(
    ui: &mut Ui,
    height: f32,
    n: usize,
    series: &[(&RingBuffer, Color32, bool)],
    max: Option<f32>,
) {
    let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::hover());
    let p = ui.painter_at(r);
    p.line_segment(
        [
            pos2(r.left(), r.bottom() - 0.5),
            pos2(r.right(), r.bottom() - 0.5),
        ],
        Stroke::new(1.0, LINE),
    );
    let max = max
        .unwrap_or_else(|| {
            series
                .iter()
                .map(|(b, ..)| b.tail(n).fold(0.0, f32::max))
                .fold(1.0, f32::max)
                * 1.15
        })
        .max(f32::EPSILON);
    let step = r.width() / (n.max(2) - 1) as f32;
    for &(buf, color, fill) in series {
        let len = buf.len().min(n);
        if len < 2 {
            continue;
        }
        let x0 = r.right() - (len - 1) as f32 * step;
        let pts: Vec<Pos2> = buf
            .tail(len)
            .enumerate()
            .map(|(i, v)| {
                pos2(
                    x0 + i as f32 * step,
                    r.bottom() - 1.0 - (v / max).clamp(0.0, 1.0) * (r.height() - 4.0),
                )
            })
            .collect();
        if fill {
            let mut m = Mesh::default();
            let c = crate::theme::tok::area(color);
            for w in pts.windows(2) {
                let i = m.vertices.len() as u32;
                m.colored_vertex(w[0], c);
                m.colored_vertex(w[1], c);
                m.colored_vertex(pos2(w[1].x, r.bottom()), c);
                m.colored_vertex(pos2(w[0].x, r.bottom()), c);
                m.add_triangle(i, i + 1, i + 2);
                m.add_triangle(i, i + 2, i + 3);
            }
            p.add(Shape::mesh(m));
        }
        p.add(Shape::line(pts, Stroke::new(1.5, color)));
    }
}

/// Toggle switch with label (Live / Off).
pub fn switch(ui: &mut Ui, on: &mut bool, label: &str) -> Response {
    let color = if *on { ACC } else { TX2 };
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), theme::prop(11.0), color);
    let (r, mut resp) = ui.allocate_exact_size(vec2(26.0 + galley.size().x, 16.0), Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let track = Rect::from_min_size(pos2(r.left(), r.center().y - 7.0), vec2(24.0, 14.0));
    let p = ui.painter();
    p.rect_filled(track, 7, if *on { ACC_DIM } else { BG4 });
    let knob_x = if *on {
        track.right() - 7.0
    } else {
        track.left() + 7.0
    };
    p.circle_filled(
        pos2(knob_x, track.center().y),
        5.0,
        if *on { ACC } else { TX2 },
    );
    p.galley(
        pos2(track.right() + 4.0, r.center().y - galley.size().y / 2.0),
        galley,
        color,
    );
    resp
}

/// Frameless icon button (24×22). `active` paints it teal.
pub fn icon_button(ui: &mut Ui, icon: &str, tooltip: &str, active: bool) -> Response {
    let (r, resp) = ui.allocate_exact_size(vec2(24.0, 22.0), Sense::click());
    let hovered = resp.hovered();
    if hovered {
        ui.painter().rect_filled(r, R, BG3);
    }
    let c = if active {
        ACC
    } else if hovered {
        TX0
    } else {
        TX2
    };
    ui.painter().text(
        r.center(),
        Align2::CENTER_CENTER,
        icon,
        theme::prop(14.0),
        c,
    );
    resp.on_hover_text(tooltip)
}

/// Toggle chip for log levels / sources. Returns clicked.
pub fn toggle_chip(
    ui: &mut Ui,
    text: &str,
    on: bool,
    fg: Color32,
    bg: Color32,
    swatch: Option<Color32>,
) -> Response {
    let font = theme::mono(11.5);
    let color = if on { fg } else { TX3 };
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, color);
    let extra = if swatch.is_some() { 14.0 } else { 0.0 };
    let (r, resp) =
        ui.allocate_exact_size(vec2(galley.size().x + 16.0 + extra, 22.0), Sense::click());
    let p = ui.painter();
    if on {
        p.rect_filled(r, R, bg);
    } else {
        p.rect_stroke(
            r,
            R,
            Stroke::new(1.0, if resp.hovered() { TX3 } else { LINE2 }),
            egui::StrokeKind::Inside,
        );
    }
    let mut x = r.left() + 8.0;
    if let Some(sw) = swatch {
        p.rect_filled(
            Rect::from_center_size(pos2(x + 4.0, r.center().y), Vec2::splat(8.0)),
            2,
            sw,
        );
        x += 14.0;
    }
    p.galley(pos2(x, r.center().y - galley.size().y / 2.0), galley, color);
    resp
}

/// Right-aligned remainder of a horizontal row.
pub fn right<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    ui.with_layout(Layout::right_to_left(Align::Center), add)
        .inner
}
