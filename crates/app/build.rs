//! Windows: embeds the icon and version info into securewire.exe (Explorer, taskbar, installer).

fn main() {
    println!("cargo:rerun-if-changed=../../packaging/icons/securewire.ico");
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("../../packaging/icons/securewire.ico")
            .set("ProductName", "SecureWire")
            .set("FileDescription", "SecureWire")
            .set("CompanyName", "SecureWire")
            .set("OriginalFilename", "securewire.exe");
        res.compile()
            .expect("embedding the Windows icon needs rc.exe from the Windows SDK");
    }
}
