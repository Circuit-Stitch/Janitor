#!/usr/bin/env bash
#
# Generate the Swift bindings for janitor-app's UniFFI boundary (ADR 0035, #95).
#
# It builds janitor-app as a staticlib, reads the exported metadata back out of
# that archive, and writes three things: the Swift sources, the C header, and the
# modulemap. #104 folds the same three into JanitorKit.xcframework.
#
# On macOS it then compiles the generated Swift, so a boundary that does not build
# fails here rather than inside Xcode Cloud. The compile matches how the framework
# is built: Swift 6 language mode, `nonisolated` default actor isolation, and
# library evolution. Library evolution is what catches a module and a public type
# sharing a name, because the emitted `.swiftinterface` is verified.
#
# Usage: scripts/generate-swift-bindings.sh [OUT_DIR]
#   OUT_DIR defaults to target/swift-bindings.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/target/swift-bindings}"

# The Swift module the bindings are compiled into. #104 publishes this name.
MODULE_NAME="JanitorKit"
# The low-level C module. UniFFI derives it from the crate's namespace, so the
# generated Swift already says `import janitorFFI`; the modulemap has to agree.
FFI_MODULE_NAME="janitorFFI"

# Resolve CARGO_HOME to its physical path. `uniffi_bindgen` builds its templates
# with askama, which computes a path from the source file to CARGO_MANIFEST_DIR.
# A symlinked cargo home makes that arithmetic wrong and the build fails on a
# missing askama.toml.
CARGO_HOME="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
export CARGO_HOME

echo "==> Building janitor-app as a staticlib"
# Produced on demand rather than declared in Cargo.toml, so Linux and Windows
# never link an archive they have no use for (ADR 0035).
cargo rustc -p janitor-app --features uniffi --lib --crate-type staticlib

LIB="$ROOT/target/debug/libjanitor_app.a"
[ -f "$LIB" ] || { echo "no staticlib at $LIB" >&2; exit 1; }

# The generator has to be built against the same UniFFI version as the
# scaffolding it reads. scripts/build-xcframework.sh runs the same check, so it
# lives in one file that both source.
TOOL="$ROOT/tools/uniffi-bindgen-swift"
# shellcheck source=scripts/uniffi-pin.sh
. "$ROOT/scripts/uniffi-pin.sh"
check_uniffi_pin "$ROOT"

echo "==> Generating Swift bindings into $OUT"
rm -rf "$OUT"
mkdir -p "$OUT"
cargo run -q --manifest-path "$TOOL/Cargo.toml" -- \
    --swift-sources --headers --modulemap \
    --module-name "$FFI_MODULE_NAME" \
    --modulemap-filename "$FFI_MODULE_NAME.modulemap" \
    "$LIB" "$OUT"

if ! command -v xcrun >/dev/null 2>&1; then
    echo "==> No Xcode toolchain; skipping the Swift compile"
    echo "Generated:"; ls -1 "$OUT"
    exit 0
fi

# Clang finds a module by looking for `module.modulemap` on the header search
# path. Copying the modulemap under that name puts the FFI module on the path.
# The `.swiftinterface` verification pass needs that: it re-parses the interface
# without the `-Xcc` flags this script would otherwise pass.
INC="$OUT/include"
mkdir -p "$INC"
cp "$OUT/$FFI_MODULE_NAME.h" "$INC/"
cp "$OUT/$FFI_MODULE_NAME.modulemap" "$INC/module.modulemap"

echo "==> Compiling the generated Swift as module $MODULE_NAME"
xcrun swiftc -emit-module \
    -swift-version 6 \
    -default-isolation nonisolated \
    -enable-library-evolution \
    -module-name "$MODULE_NAME" \
    -emit-module-path "$OUT/$MODULE_NAME.swiftmodule" \
    -emit-module-interface-path "$OUT/$MODULE_NAME.swiftinterface" \
    -I "$INC" \
    "$OUT"/*.swift

# No `async fn` is exported (ADR 0035): Swift gets a fire-and-forget call plus a
# stream, never a `try await`. Async bindings also inherit `@MainActor` under
# Xcode 26's `SWIFT_DEFAULT_ACTOR_ISOLATION`, which is the second reason.
if grep -q ' async ' "$OUT/$MODULE_NAME.swiftinterface"; then
    echo "the boundary exported an async function; ADR 0035 exports none" >&2
    exit 1
fi

echo "==> OK — interface verified, no async exported"
ls -1 "$OUT"
