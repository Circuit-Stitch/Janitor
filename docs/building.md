# Build & test

Standard Cargo across a six-crate workspace (`janitor-core`, `janitor-app`,
`janitor-aws-auth`, `janitor-aws`, `janitor-ssm`, `janitor-mock`).

No crate here links a GUI toolkit, so a Linux build needs no extra system
packages. The Slint shell lives in
[`Circuit-Stitch/Janitor-slint`](https://github.com/Circuit-Stitch/Janitor-slint),
which builds against a checkout of this repository beside it and carries its own
system-dependency list.

## Commands

```bash
cargo build                          # build the workspace
cargo test --workspace               # all crates (logic tested against fakes/replay)
cargo test --workspace --all-features  # + janitor-app's UniFFI boundary tests (what CI runs)
cargo test -p janitor-core <name>    # a single core test (substring match)
cargo clippy --all-targets           # lint
cargo fmt                            # format

# Coverage (≥80% gate; janitor-app is exempt — see ADR 0016 and ADR 0035's
# 2026-08-21 amendment). Needs the cargo-llvm-cov subcommand:
#   cargo install cargo-llvm-cov
cargo llvm-cov -p janitor-core
cargo llvm-cov -p janitor-aws --ignore-filename-regex 'src/bin/'   # lib only (ADR 0016)

# Human-gated binaries (need a browser + a real Identity Center org):
# First run? docs/iam_setup.md sets up the Identity Center org + permission set.
cargo run -p janitor-aws --bin loopback-spike        # browser↔loopback shell, no AWS
cargo run -p janitor-aws --bin live-verify           # guided sign-in: log in, then pick (ADR 0011)
cargo run -p janitor-aws --bin live-verify-sm-write  # read-only-gated Secrets Manager write (ADR 0001)
cargo run -p janitor-ssm --bin live-verify-ssm       # read a remote .env over SSM (ADR 0025)
cargo run -p janitor-ssm --bin live-verify-ssm-write # write a remote .env over SSM (ADR 0029)
```

## The Apple artifact

`JanitorKit.xcframework` is the macOS slice of `janitor-app` with the
UniFFI-generated Swift compiled into it (ADR 0035).
[`Circuit-Stitch/Janitor-macos`](https://github.com/Circuit-Stitch/Janitor-macos)
resolves it as a checksum-pinned SwiftPM binary target.

```bash
# Generate the Swift bindings, then compile and verify them as module JanitorKit.
./scripts/generate-swift-bindings.sh

# Build the framework and its zip into build/apple. Needs full Xcode and both
# Darwin targets. It verifies the emitted interfaces, then links and runs a
# consumer against the finished slice.
rustup target add x86_64-apple-darwin      # aarch64-apple-darwin comes with the Mac
./scripts/build-xcframework.sh
```

Publishing it is [docs/RELEASING.md](RELEASING.md).

## Running the shells

```bash
# The Slint shell, from a checkout beside this one:
cd ../Janitor-slint && cargo run
JANITOR_MOCK=1 cargo run   # offline mock (bash); PowerShell: $env:JANITOR_MOCK=1; cargo run

# The SwiftUI shell: open Janitor.xcodeproj in ../Janitor-macos. Set
# JANITORKIT_LOCAL=1 to build it against this repository's
# build/apple/JanitorKit.xcframework instead of the published zip.
```
