//! Design tokens (`design/design-tokens.md`) mapped onto egui. The only file
//! allowed to construct colors.

use egui::style::{Selection, WidgetVisuals};
use egui::{Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Visuals};

pub mod tok {
    use egui::Color32 as C;
    pub const BG0: C = C::from_rgb(0x0c, 0x0f, 0x13);
    pub const BG1: C = C::from_rgb(0x12, 0x16, 0x1b);
    pub const BG2: C = C::from_rgb(0x18, 0x1d, 0x23);
    pub const BG3: C = C::from_rgb(0x20, 0x27, 0x31);
    pub const BG4: C = C::from_rgb(0x2a, 0x32, 0x3d);
    pub const LINE: C = C::from_rgb(0x23, 0x2a, 0x33);
    pub const LINE2: C = C::from_rgb(0x31, 0x3a, 0x46);
    pub const TX0: C = C::from_rgb(0xe8, 0xed, 0xf2);
    pub const TX1: C = C::from_rgb(0xb3, 0xbd, 0xc8);
    pub const TX2: C = C::from_rgb(0x7b, 0x86, 0x96);
    pub const TX3: C = C::from_rgb(0x54, 0x5e, 0x6b);
    pub const ACC: C = C::from_rgb(0x4f, 0xc3, 0xb4);
    pub const ACC_DIM: C = C::from_rgb(0x17, 0x37, 0x34);
    pub const ACC_MID: C = C::from_rgb(0x2f, 0x6a, 0x64);
    pub const OK: C = C::from_rgb(0x5c, 0xc2, 0x7a);
    pub const OK_DIM: C = C::from_rgb(0x16, 0x32, 0x22);
    pub const WARN: C = C::from_rgb(0xe3, 0xa9, 0x4b);
    pub const WARN_DIM: C = C::from_rgb(0x3a, 0x2c, 0x14);
    pub const ERR: C = C::from_rgb(0xec, 0x64, 0x50);
    pub const ERR_DIM: C = C::from_rgb(0x3d, 0x1a, 0x16);
    pub const ERR_TINT: C = C::from_rgb(0x24, 0x17, 0x17);
    pub const ERR_SOFT: C = C::from_rgb(0xf3, 0xb2, 0xa8);
    pub const INFO: C = C::from_rgb(0x6e, 0xa8, 0xea);
    pub const INFO_DIM: C = C::from_rgb(0x16, 0x27, 0x3b);
    pub const TERM_FG: C = C::from_rgb(0xc9, 0xd1, 0xd9);

    /// Categorical palette for log sources.
    pub const CAT: [C; 7] = [
        C::from_rgb(0x6e, 0xa8, 0xea),
        C::from_rgb(0xc7, 0x92, 0xea),
        C::from_rgb(0xe3, 0xa9, 0x4b),
        C::from_rgb(0x4f, 0xc3, 0xb4),
        C::from_rgb(0xf0, 0x7f, 0x9c),
        C::from_rgb(0x9c, 0xcc, 0x65),
        C::from_rgb(0xd4, 0xb4, 0x83),
    ];

    pub fn cat(i: usize) -> C {
        CAT[i % CAT.len()]
    }

    /// Translucent fill for sparkline areas.
    pub fn area(c: C) -> C {
        C::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 28)
    }
}

use tok::*;

pub const R: u8 = 3;

pub fn visuals() -> Visuals {
    let mut v = Visuals::dark();
    v.panel_fill = BG1;
    v.window_fill = BG1;
    v.extreme_bg_color = BG0;
    v.faint_bg_color = BG2;
    v.code_bg_color = BG2;
    v.window_stroke = Stroke::new(1.0, LINE2);
    v.window_corner_radius = CornerRadius::same(6);
    v.menu_corner_radius = CornerRadius::same(4);
    v.selection = Selection {
        bg_fill: ACC_DIM,
        stroke: Stroke::new(1.0, ACC),
    };
    v.hyperlink_color = ACC;
    v.warn_fg_color = WARN;
    v.error_fg_color = ERR;
    v.override_text_color = None;
    let w = |fill: Color32, stroke: Color32, fg: Color32| WidgetVisuals {
        bg_fill: fill,
        weak_bg_fill: fill,
        bg_stroke: Stroke::new(1.0, stroke),
        fg_stroke: Stroke::new(1.0, fg),
        corner_radius: CornerRadius::same(R),
        expansion: 0.0,
    };
    v.widgets.noninteractive = w(BG1, LINE, TX1);
    v.widgets.inactive = w(BG2, LINE2, TX1);
    v.widgets.hovered = w(BG3, TX3, TX0);
    v.widgets.active = w(BG4, ACC, TX0);
    v.widgets.open = w(BG3, LINE2, TX0);
    v
}

pub fn install(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    // Icons must also resolve inside monospace text (log toolbar, tables).
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .push("phosphor".into());
    ctx.set_fonts(fonts);

    ctx.set_theme(egui::ThemePreference::Dark);
    ctx.set_visuals_of(egui::Theme::Dark, visuals());
    ctx.style_mut_of(egui::Theme::Dark, |s| {
        s.text_styles = [
            (TextStyle::Small, FontId::proportional(11.0)),
            (TextStyle::Body, FontId::proportional(12.5)),
            (TextStyle::Button, FontId::proportional(12.5)),
            (TextStyle::Monospace, FontId::monospace(12.0)),
            (TextStyle::Heading, FontId::proportional(14.0)), // window titles
        ]
        .into();
        s.spacing.item_spacing = egui::vec2(8.0, 4.0);
        s.spacing.button_padding = egui::vec2(8.0, 3.0);
        s.spacing.interact_size.y = 22.0;
        s.spacing.scroll.bar_width = 6.0;
        s.spacing.scroll.floating = true;
        s.interaction.selectable_labels = false;
        s.animation_time = 0.08;
    });
}

pub fn mono(size: f32) -> FontId {
    FontId::monospace(size)
}

pub fn prop(size: f32) -> FontId {
    FontId::proportional(size)
}

/// Terminal colors (design-tokens.md "Terminal palette").
pub fn terminal_palette() -> sw_term::Palette {
    use egui::Color32 as C;
    sw_term::Palette {
        fg: TERM_FG,
        bg: BG0,
        cursor: ACC,
        selection: C::from_rgb(0x1f, 0x4a, 0x46),
        ansi: [
            C::from_rgb(0x1a, 0x1f, 0x26),
            ERR,
            OK,
            WARN,
            INFO,
            C::from_rgb(0xc7, 0x92, 0xea),
            ACC,
            TX1,
            C::from_rgb(0x54, 0x5e, 0x6b),
            C::from_rgb(0xf3, 0x8a, 0x7a),
            C::from_rgb(0x7f, 0xd8, 0x97),
            C::from_rgb(0xef, 0xc1, 0x72),
            C::from_rgb(0x93, 0xc0, 0xf2),
            C::from_rgb(0xd9, 0xb0, 0xf2),
            C::from_rgb(0x7a, 0xd6, 0xca),
            TX0,
        ],
    }
}
