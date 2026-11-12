//! SecureWire — IDE-style SSH workstation. See CLAUDE.md and design/.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod dialogs;
mod panels;
mod state;
mod store;
mod theme;
mod widgets;

fn main() -> eframe::Result {
    // `--demo`: a fake host fed through the real parsers, no network (UI work, screenshots).
    let args: Vec<String> = std::env::args().skip(1).collect();
    let demo = args.iter().any(|a| a == "--demo");
    let prefill = parse_connect_args(&args);

    let options = eframe::NativeOptions {
        renderer: eframe::Renderer::Glow,
        viewport: egui::ViewportBuilder::default()
            .with_title("SecureWire")
            // IDE-style: first launch maximized; eframe persistence restores the size afterwards.
            .with_inner_size([1280.0, 800.0])
            .with_maximized(true)
            .with_min_inner_size([1024.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "SecureWire",
        options,
        Box::new(|cc| Ok(Box::new(app::SecureWireApp::new(cc, demo, prefill)))),
    )
}

/// `--connect user@host[:port] [--key PATH]` → pre-filled Connect dialog.
fn parse_connect_args(args: &[String]) -> Option<sw_core::config::HostConfig> {
    let target = args
        .iter()
        .position(|a| a == "--connect")
        .and_then(|i| args.get(i + 1))?;
    let (user, rest) = target.split_once('@')?;
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse().ok()?),
        _ => (rest, 22),
    };
    let mut c = sw_core::config::HostConfig::new(host, host, user);
    c.port = port;
    if let Some(k) = args
        .iter()
        .position(|a| a == "--key")
        .and_then(|i| args.get(i + 1))
    {
        c.key_path = k.clone();
    }
    Some(c)
}

#[cfg(test)]
mod tests {
    use super::parse_connect_args;

    fn a(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }

    #[test]
    fn connect_args() {
        let c = parse_connect_args(&a("--connect root@203.0.113.10:2222 --key /k")).unwrap();
        assert_eq!(
            (
                c.user.as_str(),
                c.address.as_str(),
                c.port,
                c.key_path.as_str()
            ),
            ("root", "203.0.113.10", 2222, "/k")
        );
        assert_eq!(
            parse_connect_args(&a("--connect deploy@host"))
                .unwrap()
                .port,
            22
        );
        assert!(parse_connect_args(&a("--connect nohost")).is_none());
    }
}
