fn main() {
    // Emit Slint element debug info in debug builds so the headless
    // `i-slint-backend-testing` `ElementHandle` query API works under
    // `cargo test` with no extra env var (it otherwise needs
    // SLINT_EMIT_DEBUG_INFO=1). Release builds stay lean (no debug info).
    let debug = std::env::var("PROFILE").as_deref() != Ok("release");
    let config = slint_build::CompilerConfiguration::new().with_debug_info(debug);
    slint_build::compile_with_config("ui/app.slint", config).unwrap();

    // Embed the multi-resolution .ico into the .exe so Explorer/taskbar show the
    // icon for the raw binary, independent of any installer (ADR 0022). No-op
    // off Windows — `winresource` is a Windows-only build-dependency.
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icons/icon.ico");
        res.compile().expect("embed Windows .exe icon");
    }
}
