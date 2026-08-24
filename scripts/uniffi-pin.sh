# The UniFFI version check, shared by the two scripts that run the generator.
#
# `uniffi_bindgen` reads the scaffolding that `uniffi`'s macros wrote into the
# archive. The two have to be the same version. They are pinned in two lockfiles
# that Cargo resolves independently, because the generator is a package outside
# the workspace, so nothing but this check keeps them together.
#
# Source it, then call `check_uniffi_pin <repository root>`.

# Print the version Cargo resolved for the `uniffi` package in one lockfile.
locked_uniffi() {
    awk '/^name = "uniffi"$/ { found = 1; next }
         found && /^version = / { gsub(/"/, "", $3); print $3; exit }' "$1"
}

# Fail unless janitor-app and the generator resolved the same `uniffi`.
check_uniffi_pin() {
    local root=$1 app tool
    app="$(locked_uniffi "$root/Cargo.lock")"
    tool="$(locked_uniffi "$root/tools/uniffi-bindgen-swift/Cargo.lock")"
    if [ "$app" != "$tool" ]; then
        echo "uniffi version mismatch: janitor-app has $app, the generator has $tool" >&2
        echo "bump both pins together, or the bindings will link and then misbehave" >&2
        return 1
    fi
    echo "==> UniFFI $app on both sides"
}
