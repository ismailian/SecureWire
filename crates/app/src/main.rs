//! SecureWire — IDE-style SSH workstation. See CLAUDE.md and design/.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod panels;
mod state;
mod theme;
mod widgets;

fn main() -> eframe::Result {
    // M0: the demo source is the only data source; `--demo` is accepted for forward compatibility.
    let _demo = std::env::args().any(|a| a == "--demo");

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
    eframe::run_native("SecureWire", options, Box::new(|cc| Ok(Box::new(app::SecureWireApp::new(cc)))))
}
