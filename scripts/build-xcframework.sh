#!/usr/bin/env bash
#
# Builds JanitorKit.xcframework and zips it (ADR 0035, #104).
#
# One slice, macos-arm64_x86_64. A macOS Release archive is universal by default,
# so the slice carries arm64 and x86_64 and an app built for either links it.
# Gonger needs three slices because it ships to a phone as well; Janitor is
# macOS-only.
#
# The framework carries the core rather than pointing at it. Inside are the Rust
# archive, the UniFFI-generated Swift compiled over it, and the C header the
# generated Swift is written against, folded into one static library with
# `libtool`. An app resolves a single binary target and clones nothing.
#
# ONE MODULE, NOT TWO
#
# The generated Swift exports 48 `FfiConverterType*_lift`/`_lower` functions that
# take a `RustBuffer`. They are public, so the C module cannot be an internal
# import, so it cannot be hidden from the interface the way Gonger hides
# CWotSound. It is not hidden here. The framework is a mixed-language one: the C
# half is the framework's own clang module, the Swift half is compiled with
# `-import-underlying-module`, and both are called JanitorKit. `import JanitorKit`
# gets both. UniFFI's `--xcframework` flag emits exactly this modulemap.
#
# Nothing here is signed and nothing needs to be. A static library is linked into
# the app that carries it, and the app's own signature covers it.
#
# Usage:
#   scripts/build-xcframework.sh [output-directory]
#
# Needs full Xcode rather than the Command Line Tools, because xcodebuild is what
# assembles an XCFramework. Set DEVELOPER_DIR if xcode-select points elsewhere.

set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=${1:-$here/build/apple}

# shellcheck source=scripts/uniffi-pin.sh
. "$here/scripts/uniffi-pin.sh"

# The module, the framework, and the zip all carry this name. #105 publishes it
# under the depot's swift/janitor prefix.
module=JanitorKit

# The floor the slice is built against. It matches the macOS deployment target in
# Janitor-macos/project.yml. A consumer may set its own no lower.
export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-15.0}

# Resolve CARGO_HOME to its physical path. `uniffi_bindgen` builds its templates
# with askama, which computes a path from the source file to CARGO_MANIFEST_DIR.
# A symlinked cargo home makes that arithmetic wrong and the build fails on a
# missing askama.toml.
CARGO_HOME="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
export CARGO_HOME

if ! xcodebuild -version >/dev/null 2>&1; then
    echo "error: xcodebuild is not usable. Set DEVELOPER_DIR to an Xcode.app's Contents/Developer." >&2
    exit 1
fi

# `cargo pkgid` prints `path+file:///…/janitor-app#0.1.0` for a path package, and
# `…#janitor-app@0.1.0` when the directory and the crate disagree. The version is
# what follows the last `#` or `@` either way.
version=$(cargo pkgid -p janitor-app)
version=${version##*[#@]}

check_uniffi_pin "$here"

lib=libjanitor_app.a
staging=$out/staging
rm -rf "$staging" "$out/$module.xcframework" "$out/$module.xcframework.zip" \
    "$out/$module.xcframework.zip.sha256"
mkdir -p "$staging"

sdk=$(xcrun --sdk macosx --show-sdk-path)

echo "==> building $version for both Mac architectures"
# The staticlib crate type is produced on demand rather than declared in
# Cargo.toml, so Linux and Windows never link an archive they have no use for.
for target in aarch64-apple-darwin x86_64-apple-darwin; do
    cargo rustc -p janitor-app --features uniffi --lib --crate-type staticlib \
        --release --target "$target"
done

# The system libraries the Rust half calls into. rustc does not record these in a
# staticlib the way it does in an rlib, so the framework has to declare them or
# every consumer links them by hand. They go in the modulemap as autolink
# directives, which reach the objects that import the module.
#
# AppKit and AuthenticationServices are the browser Sign-in: janitor-aws-auth
# drives ASWebAuthenticationSession through objc2, and AppKit comes with it.
#
# Refresh the list from rustc rather than editing it by guess:
#
#   cargo rustc -p janitor-app --features uniffi --lib --crate-type staticlib \
#       --release --target aarch64-apple-darwin -- --print native-static-libs
#
# The link check at the end of this script is what catches a stale list.
link_frameworks=(
    Security CoreFoundation AuthenticationServices AppKit
    CoreVideo CoreData CoreText CoreImage CoreGraphics CloudKit
    QuartzCore Foundation
)
link_libraries=(objc iconv)

gen=$staging/gen
echo "==> generating the Swift, the header, and the modulemap"
# Read out of the arm64 archive. The exported metadata is the same in both, and
# this one is unstripped: `strip -S` runs below, after the generator has read it.
framework_flags=()
for framework in "${link_frameworks[@]}"; do
    framework_flags+=(--link-frameworks "$framework")
done
cargo run -q --manifest-path "$here/tools/uniffi-bindgen-swift/Cargo.toml" -- \
    --swift-sources --headers --modulemap --xcframework \
    --module-name "$module" \
    --modulemap-filename module.modulemap \
    "${framework_flags[@]}" \
    "$here/target/aarch64-apple-darwin/release/$lib" "$gen"

# The generator writes framework directives and no plain ones, so the two
# libraries are appended here. The closing brace is the last line it wrote.
python3 - "$gen/module.modulemap" "${link_libraries[@]}" <<'PYTHON'
import sys

path, libraries = sys.argv[1], sys.argv[2:]
text = open(path).read().rstrip()
assert text.endswith("}"), text
body = text[:-1].rstrip("\n")
for library in libraries:
    body += '\n    link "%s"' % library
open(path, "w").write(body + "\n}\n")
PYTHON

# Cargo's own `strip` setting does not reach a static library: it strips what the
# linker produced, and nobody linked this. strip -S is what reaches inside the
# archive. It takes the DWARF out and leaves the symbol table, so the library
# still links and a backtrace through it still names functions.
echo "==> stripping debug info out of the Rust archives"
cp "$here/target/aarch64-apple-darwin/release/$lib" "$staging/rust-arm64.a"
cp "$here/target/x86_64-apple-darwin/release/$lib" "$staging/rust-x86_64.a"
# The release profile already stripped some objects, and strip says so once per
# object. Real failures still reach the terminal and still fail the build.
if ! strip -S "$staging/rust-arm64.a" "$staging/rust-x86_64.a" 2> "$staging/strip.log"; then
    cat "$staging/strip.log" >&2
    exit 1
fi
grep -v 'input object file already stripped' "$staging/strip.log" >&2 || true

# A Mac framework is a versioned bundle, not a flat one. Xcode checks an app
# against the rule and refuses a Mac build carrying a flat framework:
#
#   Framework JanitorKit.framework contains Info.plist, expected
#   Versions/Current/Resources/Info.plist since the platform does not use shallow
#   bundles
#
# The symlinks at the top are the bundle: everything reads through
# Versions/Current, so the version in use is one link rather than a copy.
fw=$staging/frameworks/$module.framework
mkdir -p "$fw/Versions/A/Headers" "$fw/Versions/A/Modules" "$fw/Versions/A/Resources"
cp "$gen/janitorFFI.h" "$fw/Versions/A/Headers/"
cp "$gen/module.modulemap" "$fw/Versions/A/Modules/"
ln -s A "$fw/Versions/Current"
ln -s "Versions/Current/$module" "$fw/$module"
ln -s Versions/Current/Headers "$fw/Headers"
ln -s Versions/Current/Modules "$fw/Modules"
ln -s Versions/Current/Resources "$fw/Resources"

# The interface, the doc file, and the binary module all land here, named after
# the triple. The driver writes the doc beside the module without being asked.
#
# The Swift module goes in after both compiles. Emitting it into the framework
# would put a Swift module named JanitorKit beside the clang module named
# JanitorKit while the second architecture is still importing the underlying one.
modules=$staging/swiftmodule
mkdir -p "$modules"

merged=()
for pair in "arm64:arm64-apple-macos" "x86_64:x86_64-apple-macos"; do
    arch=${pair%%:*}
    triple=${pair##*:}

    echo "==> compiling the generated Swift for $arch"
    # -import-underlying-module is what makes this one module rather than two. The
    # generated Swift guards its own `import janitorFFI` with `#if
    # canImport(janitorFFI)`, and that module does not exist here, so the import
    # is skipped and the C declarations arrive through the framework instead.
    xcrun swiftc \
        -module-name "$module" \
        -target "$triple$MACOSX_DEPLOYMENT_TARGET" \
        -sdk "$sdk" \
        -swift-version 6 \
        -default-isolation nonisolated \
        -enable-library-evolution \
        -import-underlying-module \
        -F "$staging/frameworks" \
        -emit-module-path "$modules/$triple.swiftmodule" \
        -emit-module-interface-path "$modules/$triple.swiftinterface" \
        -emit-private-module-interface-path "$modules/$triple.private.swiftinterface" \
        -emit-library -static -o "$staging/swift-$arch.a" \
        "$gen"/*.swift

    # A static library holds objects and no link step has run, so folding the two
    # archives together is what puts the core inside the framework. An app links
    # the result and resolves both halves at once.
    libtool -static -o "$staging/merged-$arch.a" \
        "$staging/swift-$arch.a" "$staging/rust-$arch.a" 2>/dev/null

    merged+=("$staging/merged-$arch.a")
done

lipo -create "${merged[@]}" -output "$fw/Versions/A/$module"

# The interfaces and the doc file, and not the binary `.swiftmodule` beside them.
# `xcodebuild -create-xcframework` removes a binary module when an interface
# describes the same architecture, because a module built by one compiler cannot
# be read by another and the interface is what makes the framework portable.
mkdir -p "$fw/Versions/A/Modules/$module.swiftmodule"
cp "$modules"/*.swiftinterface "$modules"/*.swiftdoc \
    "$fw/Versions/A/Modules/$module.swiftmodule/"

cat > "$fw/Versions/A/Resources/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key><string>en</string>
	<key>CFBundleExecutable</key><string>$module</string>
	<key>CFBundleIdentifier</key><string>com.circuitstitch.$module</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundleName</key><string>$module</string>
	<key>CFBundlePackageType</key><string>FMWK</string>
	<key>CFBundleShortVersionString</key><string>$version</string>
	<key>CFBundleVersion</key><string>$version</string>
	<key>CFBundleSupportedPlatforms</key><array><string>MacOSX</string></array>
	<key>LSMinimumSystemVersion</key><string>$MACOSX_DEPLOYMENT_TARGET</string>
</dict>
</plist>
PLIST

# The interface is what a consumer on another Xcode reads, so it has to parse
# back into a module. This is the check ADR 0035 asks for: a module and a public
# type sharing one name compile here and fail there, because the interface prints
# every type fully qualified.
echo "==> verifying the emitted interfaces"
for pair in "arm64:arm64-apple-macos" "x86_64:x86_64-apple-macos"; do
    triple=${pair##*:}
    xcrun swiftc -frontend -compile-module-from-interface \
        -target "$triple$MACOSX_DEPLOYMENT_TARGET" \
        -sdk "$sdk" \
        -module-name "$module" \
        -F "$staging/frameworks" \
        -o "$staging/verified-$triple.swiftmodule" \
        "$fw/Versions/A/Modules/$module.swiftmodule/$triple.swiftinterface"
done

# No `async fn` is exported (ADR 0035): Swift gets a fire-and-forget call plus a
# stream, never a `try await`. Async bindings also inherit `@MainActor` under
# Xcode 26's SWIFT_DEFAULT_ACTOR_ISOLATION, which is the second reason.
if grep -q ' async ' "$fw/Versions/A/Modules/$module.swiftmodule"/*.swiftinterface; then
    echo "the boundary exported an async function; ADR 0035 exports none" >&2
    exit 1
fi

echo "==> assembling $module.xcframework"
xcodebuild -create-xcframework \
    -framework "$fw" \
    -output "$out/$module.xcframework"

# The framework is only finished if something can link it. A missing autolink
# directive builds an xcframework that resolves, imports, and then fails at the
# link step inside somebody's app, which is a long way from here. This links a
# consumer against the real slice and runs it.
echo "==> linking a consumer against the slice"
cat > "$staging/link-check.swift" <<'CHECK'
import JanitorKit

// Forces the scaffolding's own checksum check to run, so a Swift half compiled
// against a different Rust half aborts here rather than in an app.
uniffiEnsureJanitorAppInitialized()

// One exported function, called for its answer. The rule itself is tested in
// janitor-core; this is checking that the call reaches the Rust at all.
precondition(isRevealed(revealedRow: 1, revealedCol: 2, row: 1, col: 2))
precondition(!isRevealed(revealedRow: 1, revealedCol: 2, row: 0, col: 2))
print("JanitorKit links and runs")
CHECK
xcrun swiftc \
    -swift-version 6 \
    -default-isolation nonisolated \
    -sdk "$sdk" \
    -F "$out/$module.xcframework/macos-arm64_x86_64" \
    -framework "$module" \
    -o "$staging/link-check" \
    "$staging/link-check.swift"
"$staging/link-check"

echo "==> zipping"
# ditto rather than zip, because it is what Apple's own tooling produces and it
# keeps the enclosing directory, which is what SwiftPM unpacks and expects to
# find.
( cd "$out" && ditto -c -k --sequesterRsrc --keepParent \
    "$module.xcframework" "$module.xcframework.zip" )
shasum -a 256 "$out/$module.xcframework.zip" | cut -d' ' -f1 \
    > "$out/$module.xcframework.zip.sha256"

rm -rf "$staging"

echo
echo "version:   $version"
echo "$module: $out/$module.xcframework.zip"
echo "           $(cat "$out/$module.xcframework.zip.sha256")"
echo
echo "The binaryTarget in Janitor-macos/JanitorKit/Package.swift carries that"
echo "checksum. It is the same number \`swift package compute-checksum\` prints for"
echo "the file beside it."
