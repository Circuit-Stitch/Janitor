# Build & test

Standard Cargo across a seven-crate workspace (`janitor-core`, `janitor-app`,
`janitor-gui`, `janitor-aws-auth`, `janitor-aws`, `janitor-ssm`,
`janitor-mock`).

## Linux system dependencies

`janitor-gui` uses [Slint](https://slint.dev), whose Linux backend links against
a few system libraries (`fontconfig`, `freetype`, `libxkbcommon`) via
`pkg-config`. Without their development packages the build fails in
`yeslogic-fontconfig-sys` with *"Package fontconfig was not found in the
pkg-config search path."* Install them before building:

```bash
# Fedora / RHEL
sudo dnf install -y fontconfig-devel freetype-devel libxkbcommon-devel

# Debian / Ubuntu
sudo apt install -y libfontconfig-dev libfreetype-dev libxkbcommon-dev
```

If a later `*-sys` crate still fails, you may also need the Wayland / X11 / GL
dev packages — on Fedora: `wayland-devel libxkbcommon-x11-devel
mesa-libGL-devel mesa-libEGL-devel`. macOS and Windows need no extra packages.

## Commands

```bash
cargo build                          # build the workspace
cargo test --workspace               # all crates (logic tested against fakes/replay)
cargo test -p janitor-core <name>    # a single core test (substring match)
cargo clippy --all-targets           # lint
cargo fmt                            # format

# Coverage (≥80% gate; janitor-gui and janitor-app are exempt — see ADR 0016 and
# ADR 0035's 2026-08-21 amendment). Needs the cargo-llvm-cov subcommand:
#   cargo install cargo-llvm-cov
cargo llvm-cov -p janitor-core
cargo llvm-cov -p janitor-aws --ignore-filename-regex 'src/bin/'   # lib only (ADR 0016)

cargo run -p janitor-gui             # real AWS via the worker bridge (browser sign-in; needs a configured org)
cargo run -p janitor-gui -- --ssm    # use the remote-.env-over-SSM Provider instead of Secrets Manager
JANITOR_MOCK=1 cargo run -p janitor-gui          # offline mock (bash); PowerShell: $env:JANITOR_MOCK=1; cargo run -p janitor-gui

# Human-gated binaries (need a browser + a real Identity Center org):
# First run? docs/iam_setup.md sets up the Identity Center org + permission set.
cargo run -p janitor-aws --bin loopback-spike        # browser↔loopback shell, no AWS
cargo run -p janitor-aws --bin live-verify           # guided sign-in: log in, then pick (ADR 0011)
cargo run -p janitor-aws --bin live-verify-sm-write  # read-only-gated Secrets Manager write (ADR 0001)
cargo run -p janitor-ssm --bin live-verify-ssm       # read a remote .env over SSM (ADR 0025)
cargo run -p janitor-ssm --bin live-verify-ssm-write # write a remote .env over SSM (ADR 0029)
```
