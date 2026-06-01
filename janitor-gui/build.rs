fn main() {
    // Emit Slint element debug info in debug builds so the headless
    // `i-slint-backend-testing` `ElementHandle` query API works under
    // `cargo test` with no extra env var (it otherwise needs
    // SLINT_EMIT_DEBUG_INFO=1). Release builds stay lean (no debug info).
    let debug = std::env::var("PROFILE").as_deref() != Ok("release");
    let config = slint_build::CompilerConfiguration::new().with_debug_info(debug);
    slint_build::compile_with_config("ui/app.slint", config).unwrap();
}
