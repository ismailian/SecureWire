//! egui key/mouse events → bytes for the remote PTY (xterm conventions).

use egui::{Key, Modifiers};

/// xterm modifier parameter: 1 + shift + 2·alt + 4·ctrl.
fn modifier_param(m: Modifiers) -> u8 {
    1 + m.shift as u8 + 2 * m.alt as u8 + 4 * m.ctrl as u8
}

/// Bytes for a non-text key press, or `None` if the key produces nothing
/// (plain printable keys arrive as `Event::Text` instead).
pub fn key_bytes(key: Key, m: Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    let plain = !m.shift && !m.alt && !m.ctrl;
    let csi_mod = |final_byte: u8| -> Vec<u8> {
        if plain {
            if app_cursor {
                vec![0x1b, b'O', final_byte]
            } else {
                vec![0x1b, b'[', final_byte]
            }
        } else {
            format!("\x1b[1;{}{}", modifier_param(m), final_byte as char).into_bytes()
        }
    };
    let tilde = |n: u8| -> Vec<u8> {
        if plain {
            format!("\x1b[{n}~").into_bytes()
        } else {
            format!("\x1b[{n};{}~", modifier_param(m)).into_bytes()
        }
    };
    let ss3_f = |final_byte: u8| -> Vec<u8> {
        if plain {
            vec![0x1b, b'O', final_byte]
        } else {
            format!("\x1b[1;{}{}", modifier_param(m), final_byte as char).into_bytes()
        }
    };

    let b = match key {
        Key::Enter => vec![b'\r'],
        Key::Tab if m.shift => b"\x1b[Z".to_vec(),
        Key::Tab => vec![b'\t'],
        Key::Backspace if m.ctrl => vec![0x08],
        Key::Backspace if m.alt => vec![0x1b, 0x7f],
        Key::Backspace => vec![0x7f],
        Key::Escape => vec![0x1b],
        Key::ArrowUp => csi_mod(b'A'),
        Key::ArrowDown => csi_mod(b'B'),
        Key::ArrowRight => csi_mod(b'C'),
        Key::ArrowLeft => csi_mod(b'D'),
        Key::Home => csi_mod(b'H'),
        Key::End => csi_mod(b'F'),
        Key::Insert => tilde(2),
        Key::Delete => tilde(3),
        Key::PageUp => tilde(5),
        Key::PageDown => tilde(6),
        Key::F1 => ss3_f(b'P'),
        Key::F2 => ss3_f(b'Q'),
        Key::F3 => ss3_f(b'R'),
        Key::F4 => ss3_f(b'S'),
        Key::F5 => tilde(15),
        Key::F6 => tilde(17),
        Key::F7 => tilde(18),
        Key::F8 => tilde(19),
        Key::F9 => tilde(20),
        Key::F10 => tilde(21),
        Key::F11 => tilde(23),
        Key::F12 => tilde(24),
        Key::Space if m.ctrl => vec![0],
        _ if m.ctrl && !m.alt => ctrl_byte(key)?,
        _ if m.alt && !m.ctrl => {
            // Meta: ESC prefix + the character (Text events are suppressed while Alt is held).
            let c = key_char(key, m.shift)?;
            vec![0x1b, c]
        }
        _ => return None,
    };
    Some(b)
}

/// Ctrl+<key> control characters (Ctrl+C/X/V arrive as Copy/Cut/Paste events instead).
fn ctrl_byte(key: Key) -> Option<Vec<u8>> {
    let c = key_char(key, false)?;
    let b = match c {
        b'a'..=b'z' => c - b'a' + 1,
        b'[' => 0x1b,
        b'\\' => 0x1c,
        b']' => 0x1d,
        b'/' => 0x1f,
        b'2' | b'@' => 0x00,
        b'6' => 0x1e,
        _ => return None,
    };
    Some(vec![b])
}

fn key_char(key: Key, shift: bool) -> Option<u8> {
    let name = key.symbol_or_name();
    let mut chars = name.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return match key {
            Key::OpenBracket => Some(b'['),
            Key::CloseBracket => Some(b']'),
            Key::Backslash => Some(b'\\'),
            Key::Slash => Some(b'/'),
            _ => None,
        };
    }
    if !c.is_ascii() {
        return None;
    }
    let c = c as u8;
    Some(if c.is_ascii_alphabetic() {
        if shift {
            c.to_ascii_uppercase()
        } else {
            c.to_ascii_lowercase()
        }
    } else {
        c
    })
}

/// Text for a paste: newlines → CR, ESC stripped (so pasted content can't end
/// bracketed-paste mode early or inject sequences), wrapped if the app asked for it.
pub fn paste_bytes(text: &str, bracketed: bool) -> Vec<u8> {
    let clean: String = text
        .replace("\r\n", "\r")
        .replace('\n', "\r")
        .chars()
        .filter(|&c| c != '\x1b')
        .collect();
    if bracketed {
        let mut v = b"\x1b[200~".to_vec();
        v.extend_from_slice(clean.as_bytes());
        v.extend_from_slice(b"\x1b[201~");
        v
    } else {
        clean.into_bytes()
    }
}

/// SGR (1006) mouse report. `button`: 0 left, 1 middle, 2 right, 64/65 wheel up/down.
pub fn sgr_mouse(button: u8, col: usize, row: usize, pressed: bool, m: Modifiers) -> Vec<u8> {
    let b = button + 4 * m.shift as u8 + 8 * m.alt as u8 + 16 * m.ctrl as u8;
    format!(
        "\x1b[<{b};{};{}{}",
        col + 1,
        row + 1,
        if pressed { 'M' } else { 'm' }
    )
    .into_bytes()
}

/// Legacy X10 mouse report (coordinates limited to 223).
pub fn x10_mouse(button: u8, col: usize, row: usize, pressed: bool) -> Option<Vec<u8>> {
    if col > 222 || row > 222 {
        return None;
    }
    let b = if pressed || button >= 64 { button } else { 3 };
    Some(vec![
        0x1b,
        b'[',
        b'M',
        32 + b,
        33 + col as u8,
        33 + row as u8,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Modifiers = Modifiers::NONE;

    #[test]
    fn basics() {
        assert_eq!(key_bytes(Key::Enter, NONE, false).unwrap(), b"\r");
        assert_eq!(key_bytes(Key::Backspace, NONE, false).unwrap(), b"\x7f");
        assert_eq!(key_bytes(Key::ArrowUp, NONE, false).unwrap(), b"\x1b[A");
        assert_eq!(key_bytes(Key::ArrowUp, NONE, true).unwrap(), b"\x1bOA");
        assert_eq!(
            key_bytes(Key::ArrowLeft, Modifiers::CTRL, false).unwrap(),
            b"\x1b[1;5D"
        );
        assert_eq!(key_bytes(Key::Delete, NONE, false).unwrap(), b"\x1b[3~");
        assert_eq!(key_bytes(Key::F5, NONE, false).unwrap(), b"\x1b[15~");
        assert_eq!(key_bytes(Key::F1, NONE, false).unwrap(), b"\x1bOP");
        assert_eq!(
            key_bytes(Key::Tab, Modifiers::SHIFT, false).unwrap(),
            b"\x1b[Z"
        );
    }

    #[test]
    fn ctrl_and_alt() {
        assert_eq!(key_bytes(Key::D, Modifiers::CTRL, false).unwrap(), [4]);
        assert_eq!(key_bytes(Key::R, Modifiers::CTRL, false).unwrap(), [18]);
        assert_eq!(
            key_bytes(Key::OpenBracket, Modifiers::CTRL, false).unwrap(),
            [0x1b]
        );
        assert_eq!(key_bytes(Key::B, Modifiers::ALT, false).unwrap(), b"\x1bb");
        assert_eq!(key_bytes(Key::A, NONE, false), None); // printable → Text event
    }

    #[test]
    fn paste() {
        assert_eq!(paste_bytes("a\nb", false), b"a\rb");
        assert_eq!(
            paste_bytes("x\x1b[201~y", true),
            b"\x1b[200~x[201~y\x1b[201~"
        );
    }

    #[test]
    fn mouse() {
        assert_eq!(sgr_mouse(0, 4, 9, true, NONE), b"\x1b[<0;5;10M");
        assert_eq!(sgr_mouse(64, 0, 0, true, NONE), b"\x1b[<64;1;1M");
        assert_eq!(
            x10_mouse(0, 0, 0, true).unwrap(),
            [0x1b, b'[', b'M', 32, 33, 33]
        );
    }
}
