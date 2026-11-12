# Design Tokens

Single source for colors, type, spacing, and shape. The prototype's `:root` CSS variables and `crates/app/src/theme.rs` must both match this file.

Theme: **dark only in v1** (see decisions D-009). Light theme is a later token swap — nothing outside `theme.rs` may hard-code a color.

## Color

### Surfaces
| Token | Hex | Use |
|---|---|---|
| `bg-0` | `#0c0f13` | Terminal background, text inputs, `extreme_bg_color` |
| `bg-1` | `#12161b` | Side/bottom panels, dialogs (`panel_fill`, `window_fill`) |
| `bg-2` | `#181d23` | Top bar, status bar, section-header hover, inactive widget fill |
| `bg-3` | `#202731` | Hover fill, bar track, chips |
| `bg-4` | `#2a323d` | Pressed / active fill, scrollbar thumb |
| `line` | `#232a33` | Hairlines between panels and sections |
| `line-2` | `#313a46` | Widget strokes (buttons, inputs, chips) |

### Text
| Token | Hex | Use |
|---|---|---|
| `tx-0` | `#e8edf2` | Strong: values, names, active tab |
| `tx-1` | `#b3bdc8` | Body |
| `tx-2` | `#7b8696` | Secondary labels, panel titles |
| `tx-3` | `#545e6b` | Hints, timestamps, disabled |

### Accent & semantic
| Token | Hex | Dim (bg) | Use |
|---|---|---|---|
| `acc` | `#4fc3b4` | `acc-dim #173734` | Focus, selection, active tab underline, primary button, CPU/tx series |
| `ok` | `#5cc27a` | `ok-dim #163222` | running, allow, healthy |
| `warn` | `#e3a94b` | `warn-dim #3a2c14` | thresholds crossed, WARN level |
| `err` | `#ec6450` | `err-dim #3d1a16` | failed, deny, ERR level |
| `info` | `#6ea8ea` | `info-dim #16273b` | INFO level, rx series, informational badges |

Text on `acc` fill uses `bg-0`.

### Categorical (log sources, max 7 then repeat)
`#6ea8ea` `#c792ea` `#e3a94b` `#4fc3b4` `#f07f9c` `#9ccc65` `#d4b483` — assigned in the order sources are enabled; stored per source in `hosts.toml` so a source keeps its color.

### Terminal palette (ANSI 16)
| | Normal | Bright |
|---|---|---|
| black | `#1a1f26` | `#545e6b` |
| red | `#ec6450` | `#f38a7a` |
| green | `#5cc27a` | `#7fd897` |
| yellow | `#e3a94b` | `#efc172` |
| blue | `#6ea8ea` | `#93c0f2` |
| magenta | `#c792ea` | `#d9b0f2` |
| cyan | `#4fc3b4` | `#7ad6ca` |
| white | `#b3bdc8` | `#e8edf2` |
Foreground `#c9d1d9`, background `bg-0`, cursor `acc`, selection `acc-dim`.

## Typography

| Role | Font | Size (pt @ 1.0 scale) | Weight |
|---|---|---|---|
| UI body | Inter | 12.5 | Regular |
| UI strong / section headers | Inter | 12.5 | Medium |
| Panel titles, bottom tabs | Inter | 11, uppercase, +0.8 letter spacing | SemiBold |
| Small / meta | Inter | 11 | Regular |
| Big metric | Inter | 22 | Medium, tabular |
| Mono (names, paths, IPs, logs, tables) | JetBrains Mono | 12 | Regular |
| Terminal | JetBrains Mono | 13 (user-configurable) | Regular / Bold |

- Both fonts are embedded (`include_bytes!`), subsetted to Latin + Latin-1 + box drawing + arrows to keep the binary small. egui's default emoji font stays as fallback.
- egui has no letter-spacing: uppercase titles get spacing by using `RichText::small().strong()` only — accept the difference from the mock.
- Numbers that update must use tabular figures: Inter's `tnum` is not selectable in egui, so updating numbers in the UI use **JetBrains Mono** when alignment matters (tables, status bar), Inter elsewhere.

## Spacing & shape

| Token | Value |
|---|---|
| Base unit | 4 px |
| Panel padding | 12 px horizontal, 4 / 12 px section body top/bottom |
| Section header height | 28 px |
| Panel header height | 30 px |
| Row height (lists) | 22 px |
| Log row height | 20 px |
| Item spacing | `egui::vec2(8.0, 4.0)` |
| Button padding | `egui::vec2(10.0, 4.0)` |
| Corner radius | 3 px widgets, 6 px windows, 2 px bars |
| Strokes | 1 px everywhere |
| Window shadow | offset (0, 12), blur 40, `#00000080` — the only shadow |

## egui mapping (sketch for `theme.rs`)

```rust
use egui::{Color32 as C, CornerRadius, Stroke, Visuals, style::{Selection, WidgetVisuals}};

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
    pub const OK: C = C::from_rgb(0x5c, 0xc2, 0x7a);
    pub const WARN: C = C::from_rgb(0xe3, 0xa9, 0x4b);
    pub const ERR: C = C::from_rgb(0xec, 0x64, 0x50);
    pub const INFO: C = C::from_rgb(0x6e, 0xa8, 0xea);
}

pub fn visuals() -> Visuals {
    use tok::*;
    let mut v = Visuals::dark();
    v.panel_fill = BG1;
    v.window_fill = BG1;
    v.extreme_bg_color = BG0;
    v.faint_bg_color = BG2;
    v.window_stroke = Stroke::new(1.0, LINE2);
    v.window_corner_radius = CornerRadius::same(6);
    v.selection = Selection { bg_fill: ACC_DIM, stroke: Stroke::new(1.0, ACC) };
    v.hyperlink_color = ACC;
    v.warn_fg_color = WARN;
    v.error_fg_color = ERR;
    let w = |fill: C, stroke: C, fg: C| WidgetVisuals {
        bg_fill: fill, weak_bg_fill: fill,
        bg_stroke: Stroke::new(1.0, stroke),
        fg_stroke: Stroke::new(1.0, fg),
        corner_radius: CornerRadius::same(3), expansion: 0.0,
    };
    v.widgets.noninteractive = w(BG1, LINE, TX1);
    v.widgets.inactive = w(BG2, LINE2, TX1);
    v.widgets.hovered = w(BG3, TX3, TX0);
    v.widgets.active = w(BG4, ACC, TX0);
    v.widgets.open = w(BG3, LINE2, TX0);
    v
}
```
Field names follow egui ≥ 0.31 (`CornerRadius`); adjust to the pinned egui version.
