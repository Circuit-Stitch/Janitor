# Architecture Decision Records

Every hard-to-reverse, non-obvious choice gets an ADR here. The top-level
[README](../../README.md) and [CLAUDE.md](../../CLAUDE.md) summarize; the depth
lives in these files.

| # | Decision |
| --- | --- |
| [0001](0001-non-stomping-writes-via-staged-put-and-cas.md) | Non-stomping writes via staged `PutSecretValue` + atomic stage CAS |
| [0002](0002-identity-center-only-memory-only-auth.md) | Identity-Center-only, memory-only authentication |
| [0003](0003-core-gui-split-slint-and-secret-display.md) | Core/GUI split, Slint for the view, and the secret-display stance |
| [0004](0004-read-only-v1-scope-and-secret-shapes.md) | Read-only v1 scope, and how non-flat secret shapes are handled |
| [0005](0005-clipboard-and-read-model.md) | Clipboard handling and the matrix read model |
| [0006](0006-version-history-and-restore.md) | Version history and restore as a first-class feature |
| [0007](0007-ci-and-distribution.md) | CI and distribution: cargo-packager bundles, signed on macOS and Windows |
| [0008](0008-secret-shape-flattening-scheme.md) | Secret-shape flattening: leaf-type-preserving dotted paths with escaped dots |
| [0009](0009-comparison-engine-result-model.md) | Comparison engine result model (Aligned / Drift / Gap) |
| [0010](0010-aws-adapter-crate-and-auth-object-model.md) | `janitor-aws` adapter crate and the Identity Center auth object model |
| [0011](0011-guided-sign-in-and-discovery.md) | Guided sign-in: issuer-scoped registration, post-sign-in discovery, remembered picks |
| [0012](0012-gui-aws-bridge-worker-and-lazy-sign-in.md) | GUI↔AWS bridge: worker thread, a tested `Session`, and lazy sign-in |
| [0013](0013-guided-discovery-in-gui-step-machine-and-manage-window.md) | Guided Discovery in the GUI: step machine and Manage window |
| [0014](0014-drift-matrix-model-n-column-and-comparison-columns.md) | Drift-matrix model: N Environment columns and comparison columns |
| [0015](0015-region-picker-and-cross-region-discovery.md) | Region picker and cross-region Discovery |
| [0016](0016-per-crate-coverage-badges-and-aws-gate.md) | Per-crate coverage badges and the `janitor-aws` coverage gate |
| [0017](0017-in-app-diagnostic-log-panel-and-zero-terminal-output.md) | In-app diagnostic log panel and zero terminal output |
| [0018](0018-stale-role-auto-recovery-on-load.md) | Stale-role auto-recovery on load |
| [0019](0019-provider-port-in-core-and-janitor-mock-crate.md) | `Provider` port in `core` and the `janitor-mock` crate |
| [0020](0020-window-resize-floor-and-uncapped-matrix-width.md) | Window resize floor and uncapped matrix width |
| [0021](0021-gui-view-tests-via-slint-testing-backend.md) | GUI view tests via the Slint testing backend |
| [0022](0022-packaging-cargo-packager-and-windows-signing.md) | Packaging with cargo-packager and Windows signing |
| [0023](0023-drift-matrix-column-sizing-stretch-to-fill.md) | Drift-matrix column sizing: stretch to fill |
| [0024](0024-shared-aws-auth-base-crate.md) | Shared `janitor-aws-auth` base crate |
| [0025](0025-remote-dotenv-over-ssm-provider.md) | Remote `.env` over SSM Provider (pure-Rust MGS data channel) |
| [0026](0026-shared-discovery-orchestrator-in-core.md) | Shared Discovery orchestrator in `core` |
| [0027](0027-covering-the-shared-auth-shell-with-replay-and-live-tests.md) | Covering the shared auth shell with replay + live tests |
| [0028](0028-remote-dotenv-write-over-ssm-command-channel.md) | Remote `.env` write over the SSM command channel *(superseded by 0029)* |
| [0029](0029-remote-dotenv-write-via-interactive-pty-data-channel-stream.md) | Remote `.env` write via an interactive-pty data-channel stream |
| [0030](0030-matrix-sticky-group-headers-and-resizable-entry-column.md) | Matrix sticky group headers and resizable Entry column |
| [0031](0031-unify-aws-family-providers-behind-swappable-resource-method.md) | Unify AWS-family Providers behind a swappable resource method |
| [0032](0032-wire-write-seam-to-provider-port-and-read-write-lock.md) | Wire the write seam to the `Provider` port + read-write lock |
| [0033](0033-pluggable-sign-in-browser-and-portal-cookie-isolation.md) | Pluggable sign-in browser and portal-cookie isolation |
| [0034](0034-windows-auto-update-via-msix-and-app-installer.md) | Windows auto-update via MSIX and App Installer |
| [0035](0035-swiftui-macos-shell-over-uniffi.md) | SwiftUI macOS shell over the Rust core via UniFFI |
| [0036](0036-three-repos-core-slint-shell-macos-shell.md) | Three repositories: the core, the Slint shell, and the macOS shell |
| [0037](0037-apache-2-0-replaces-gpl-3-0-only.md) | Apache-2.0 replaces GPL-3.0-only. The Slint shell stays GPL because it links Slint. |

New hard-to-reverse decisions get the next number here. See
[CLAUDE.md](../../CLAUDE.md) for the conventions.
