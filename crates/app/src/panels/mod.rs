pub mod dock;
pub mod status;
pub mod system;
pub mod terminal;
pub mod topbar;
pub mod watch;

use egui::{Align, Align2, Layout, Sense, Ui, UiBuilder, pos2, vec2};

use crate::theme::{self, tok::*};
use crate::widgets;

/// 30 px uppercase panel title row with right-aligned tools.
pub fn panel_header(ui: &mut Ui, title: &str, tools: impl FnOnce(&mut Ui)) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 30.0), Sense::hover());
    ui.painter().text(pos2(rect.left() + 12.0, rect.center().y), Align2::LEFT_CENTER, title, theme::prop(11.0), TX2);
    ui.scope_builder(
        UiBuilder::new().max_rect(rect.shrink2(vec2(6.0, 0.0))).layout(Layout::right_to_left(Align::Center)),
        tools,
    );
    widgets::hline(ui);
}
