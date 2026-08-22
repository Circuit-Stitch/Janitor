//! The Swift binding generator for `janitor-app`'s UniFFI boundary (ADR 0035).
//!
//! It reads the exported metadata out of a compiled `janitor-app` staticlib and
//! writes the Swift sources, the C header, and the modulemap that
//! `JanitorKit.xcframework` carries (#104).
//!
//! It is its own package, outside the workspace, for two reasons. The generator is
//! a build tool rather than part of the application. And `uniffi_bindgen` pulls a
//! template engine and a CLI parser that a workspace-wide `--all-features` lint or
//! test run would otherwise compile every time.
//!
//! Run it through `scripts/generate-swift-bindings.sh`, which also pins the
//! version match against `janitor-app`.

fn main() {
    uniffi::uniffi_bindgen_swift()
}
