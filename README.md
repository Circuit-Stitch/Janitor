# Janitor

[![CI](https://github.com/Circuit-Stitch/Janitor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Circuit-Stitch/Janitor/actions/workflows/ci.yml)
[![core coverage](https://img.shields.io/codecov/c/github/Circuit-Stitch/Janitor?flag=core&label=core%20coverage)](https://codecov.io/gh/Circuit-Stitch/Janitor)
[![aws coverage](https://img.shields.io/codecov/c/github/Circuit-Stitch/Janitor?flag=aws&label=aws%20coverage)](https://codecov.io/gh/Circuit-Stitch/Janitor)
[![aws-auth coverage](https://img.shields.io/codecov/c/github/Circuit-Stitch/Janitor?flag=aws-auth&label=aws-auth%20coverage)](https://codecov.io/gh/Circuit-Stitch/Janitor)
[![mock coverage](https://img.shields.io/codecov/c/github/Circuit-Stitch/Janitor?flag=mock&label=mock%20coverage)](https://codecov.io/gh/Circuit-Stitch/Janitor)
[![ssm coverage](https://img.shields.io/codecov/c/github/Circuit-Stitch/Janitor?flag=ssm&label=ssm%20coverage)](https://codecov.io/gh/Circuit-Stitch/Janitor)

> An ephemeral desktop client onto your AWS secrets — **Secrets Manager** Sets
> and remote **`.env`** files reached over **SSM**. It stores no secrets and no
> credentials of its own — it borrows them on demand and forgets them. The name
> is the thesis: the janitor holds the most keys, yet keeps none.

**License:** [GPL-3.0-only](LICENSE) · **Status:** v0.1.4 released (Linux ·
macOS · Windows MSIX with auto-update). The masked drift matrix reads real AWS —
Secrets Manager Sets and remote `.env` files over SSM (offline mock behind
`JANITOR_MOCK=1`). Both write engines are built and tested but the app ships
**read-only by default**, with the write paths reachable only via human-gated
live-verify binaries ([details below](#status)) · **CI:** lint · test · coverage

---

## What it is

Janitor is a cross-platform desktop tool designed for two jobs that the AWS
console makes awkward and risky:

1. **Drift detection** — line up the *same logical* Secret Set across N
   Environments (prod / staging / dev — possibly different AWS accounts and
   regions) in one masked matrix, so missing or mismatched Entries jump out.
2. **Safe mutation** — change a few Entries without ever risking an accidental
   overwrite of the whole Set.

By design it is an **ephemeral client**: Values and Credentials are kept in
memory only and zeroized after use; the only thing written to disk is non-secret
**Config** — *where* Secret Sets live, never a Value. The domain vocabulary
(*Secret Set*, *Entry*, *Value*, *Environment*, *Application*) is defined in
[CONTEXT.md](CONTEXT.md).

## Why it exists

The dangerous operation in AWS Secrets Manager is the everyday one. A Secret
Set's value is a single JSON blob, so "change one Entry" easily becomes a
`PutSecretValue` of a whole in-memory blob that silently drops a teammate's
concurrent edit. Janitor's reason to exist is to make that *structurally
impossible* — every write is designed to go through an op-based,
replay-on-fresh-fetch, atomic compare-and-swap engine
([ADR 0001](docs/adr/0001-non-stomping-writes-via-staged-put-and-cas.md)), never
a naive overwrite. The drift matrix is the other half: see the holes — the
**Gap** finding — before they page someone.

## What drift looks like

*This is how the matrix reads in the running GUI (see [Status](#status)).*

Janitor compares Values **masked**: it shows presence, Value *length*, and
equality grouping (by hash) without revealing plaintext. Each Entry lands in
exactly one state:

```
Entry                     prod          staging       dev
─────────────────────     ─────────     ─────────     ─────────
SENTRY_DSN                ••• 61 #a     ••• 61 #a     ••• 61 #a     ✓ Aligned
POSTHOG_API_KEY           ••• 47 #b     ••• 41 #c     ••• 47 #d     ~ Drift
ZITADEL_CLIENT_SECRET     ••• 36 #e     ••• 36 #e     —             ! Gap
```

- **Aligned** — present everywhere with identical Values (same hash group). The
  healthy, boring case.
- **Drift** — present everywhere, but Values differ. Sometimes intended (a
  per-Environment `DATABASE_URL`), sometimes a bug.
- **Gap** — present in some Environments, missing in others. The highest-signal
  finding — usually a Terraform / compose hole.

`•••` is the masked Value (plaintext is shown only on an explicit, momentary
per-cell reveal), the number is its length, `#x` is the hash-equality group
(same letter ⇒ identical Value), and `—` means the Entry is absent. Value
length is a deliberate, accepted side-channel — see the
[threat model](docs/THREAT-MODEL.md).

## Status

The app is live: it signs in to IAM Identity Center in a browser, runs guided
Discovery, and renders the masked drift matrix from real AWS — across two
Providers (Secrets Manager Sets and remote `.env` files over SSM) and across
regions. Both write engines are built and tested behind fakes + replay, but the
shipped app stays **read-only**; the write paths are reachable only via
human-gated `live-verify-*-write` binaries while live verification finishes.

| Area | State |
| --- | --- |
| Secret-shape model — comparable Entries + lossless flatten / unflatten | ✅ Implemented & tested — [ADR 0008](docs/adr/0008-secret-shape-flattening-scheme.md) |
| Zeroizing secret types — `Value` kept out of `Debug` / `Display` / logs | ✅ Implemented & tested |
| `Config` load / save — atomic TOML write, locations only | ✅ Implemented & tested |
| Comparison matrix (Aligned / Drift / Gap) + masked read model | ✅ Implemented & tested — [ADR 0009](docs/adr/0009-comparison-engine-result-model.md) / [0014](docs/adr/0014-drift-matrix-model-n-column-and-comparison-columns.md) |
| The shells — masked matrix, per-cell reveal, guided Discovery wizard, Manage window, region picker, in-app diagnostic log | ✅ Live on real AWS (`JANITOR_MOCK=1` for offline mock) — [ADR 0003](docs/adr/0003-core-gui-split-slint-and-secret-display.md) / [0013](docs/adr/0013-guided-discovery-in-gui-step-machine-and-manage-window.md) / [0015](docs/adr/0015-region-picker-and-cross-region-discovery.md) / [0017](docs/adr/0017-in-app-diagnostic-log-panel-and-zero-terminal-output.md) |
| Identity Center sign-in + per-Environment Credentials + GUI↔AWS worker bridge | ✅ Implemented & tested (logic vs. fakes; browser/SDK shell untested by design) — [ADR 0002](docs/adr/0002-identity-center-only-memory-only-auth.md) / [0010](docs/adr/0010-aws-adapter-crate-and-auth-object-model.md) / [0012](docs/adr/0012-gui-aws-bridge-worker-and-lazy-sign-in.md) |
| Guided sign-in + Discovery — auto-discovered account / role / secret, remembered picks | ✅ Implemented & tested — [ADR 0011](docs/adr/0011-guided-sign-in-and-discovery.md) / [0026](docs/adr/0026-shared-discovery-orchestrator-in-core.md) |
| **Secrets Manager Provider** (read) | ✅ Live in the matrix |
| **Remote `.env` over SSM Provider** (read) — pure-Rust MGS data channel, no `session-manager-plugin` | ✅ Live-verified 2026-06-07 — [ADR 0025](docs/adr/0025-remote-dotenv-over-ssm-provider.md) |
| Non-stomping Secrets Manager write — staged-put + atomic CAS | ⚙️ Built & tested behind fakes/replay; read-only, reachable via `live-verify-sm-write` — [ADR 0001](docs/adr/0001-non-stomping-writes-via-staged-put-and-cas.md) |
| Remote `.env` over SSM write — non-stomping, hash-guarded | ⚙️ Built & tested; read-only, reachable via `live-verify-ssm-write` — [ADR 0029](docs/adr/0029-remote-dotenv-write-via-interactive-pty-data-channel-stream.md) |
| Read-write lock — writes unreachable until deliberately unlocked | ✅ Worker-enforced invariant — [ADR 0032](docs/adr/0032-wire-write-seam-to-provider-port-and-read-write-lock.md) |
| Packaging + releases — Linux deb/rpm/AppImage, macOS dmg, Windows MSIX auto-update | ✅ v0.1.4, released from `Janitor-slint` — [ADR 0007](docs/adr/0007-ci-and-distribution.md) / [0022](docs/adr/0022-packaging-cargo-packager-and-windows-signing.md) / [0034](docs/adr/0034-windows-auto-update-via-msix-and-app-installer.md) |
| `JanitorKit.xcframework` — the core as a checksum-pinned SwiftPM binary target | ✅ Published to the depot on a `kit-vX.Y.Z` tag — [ADR 0035](docs/adr/0035-swiftui-macos-shell-over-uniffi.md) |

The workspace is six crates: `janitor-core` (offline bedrock — model, compare,
`Config`, the `Provider` port, the Discovery orchestrator, the shared
presentation seams), `janitor-app` (the worker, the `Command` / `Event` protocol,
the AWS composition root, and the UniFFI boundary; ADR 0035), `janitor-aws-auth`
(shared Identity Center auth base; ADR 0024), `janitor-aws` (Secrets Manager
Provider), `janitor-ssm` (remote `.env` over SSM Provider; ADR 0025), and
`janitor-mock` (offline canned-data Provider; ADR 0019). `cargo test --workspace`
runs them all; ≥80% coverage gates cover the crates where correctness is proven
(ADR 0010 §5, ADR 0016) — the browser / SDK / socket shells stay untested by
design.

## Three repositories

The core has two shells on two toolchains, so each shell has its own repository
([ADR 0036](docs/adr/0036-three-repos-core-slint-shell-macos-shell.md)). Every
ADR, `CONTEXT.md`, and the threat model stay here, because a decision log split
across repositories is a decision log nobody reads.

| Repository | Holds | Produces |
| --- | --- | --- |
| **`Janitor`** (this one) | the six crates, every ADR, `CONTEXT.md`, `THREAT-MODEL.md` | `JanitorKit.xcframework` on the depot |
| [`Janitor-slint`](https://github.com/Circuit-Stitch/Janitor-slint) | the Slint shell | rpm, deb, AppImage, dmg, MSIX |
| [`Janitor-macos`](https://github.com/Circuit-Stitch/Janitor-macos) | the SwiftUI shell and its Xcode project | the Mac App Store build |

`Janitor-slint` takes the core by Cargo path from a checkout beside it, so a core
change is picked up on the next build with nothing to publish and nothing to
bump. **It does not build from a clean clone alone** — it needs this repository
checked out next to it. `Janitor-macos` takes the core as
`JanitorKit.xcframework`, pinned by URL and checksum, because a binary target is
the only way an Xcode project can take Rust.

## Install

Prebuilt bundles ship on
[`Janitor-slint`'s Releases page](https://github.com/Circuit-Stitch/Janitor-slint/releases):

- **Linux** — `.deb`, `.rpm`, or `.AppImage`
- **macOS** — `.dmg` (Apple Silicon)
- **Windows** — `.msix`, installed via App Installer with auto-update
  ([ADR 0034](docs/adr/0034-windows-auto-update-via-msix-and-app-installer.md))

The app ships **read-only**: it reads and compares secrets but makes no mutating
AWS calls. You bring your own IAM Identity Center org — see
[docs/iam_setup.md](docs/iam_setup.md).

## Build & test

Standard Cargo across the six-crate workspace. No crate here links a GUI toolkit,
so a Linux build needs no extra system packages. Full commands — build, test,
coverage, the xcframework, and the human-gated live-verify binaries — live in
**[docs/building.md](docs/building.md)**.

## Architecture

Crates split along a trust boundary
([ADR 0003](docs/adr/0003-core-gui-split-slint-and-secret-display.md)). The
security-critical logic lives in `core` and the Provider crates behind a
`Provider` port ([ADR 0019](docs/adr/0019-provider-port-in-core-and-janitor-mock-crate.md));
a shell is a thin, softer-trust view:

- **`janitor-core`** *(trusted)* — no GUI deps: the secret-shape model,
  zeroizing in-memory types, `Config`, the comparison engine, the write-seam
  types, the provider-agnostic Discovery orchestrator
  ([ADR 0026](docs/adr/0026-shared-discovery-orchestrator-in-core.md)), the
  `Provider` port every backend implements, and the presentation seams that
  decide what a shell renders. This is where correctness is proven.
- **`janitor-app`** *(trusted)* — the worker thread that drives a `Provider`, the
  `Command` / `Event` protocol every shell speaks, and the composition root that
  builds the real AWS Provider. It sits above the adapter crates because it names
  them all, which `janitor-core` cannot do
  ([ADR 0035](docs/adr/0035-swiftui-macos-shell-over-uniffi.md)).
- **`janitor-aws-auth` / `janitor-aws` / `janitor-ssm` / `janitor-mock`**
  *(trusted)* — the Providers: a shared Identity Center auth base, the Secrets
  Manager backend, the remote-`.env`-over-SSM backend, and the offline mock.
  Network / SDK / socket I/O sits behind seams so the logic stays mockable and
  the coverage gates stay reachable.
- **The shells** *(softer-trust)* — thin views, each in its own repository: the
  masked comparison matrix, momentary per-cell reveal, the Discovery wizard, the
  Manage window, and an in-app diagnostic log. No auth / AWS / compare / write
  logic lives in either. Neither names an adapter crate; both drive
  `janitor-app`.

## Non-negotiable invariants

These are the spine of the project; the [threat model](docs/THREAT-MODEL.md)
explains what each one defends against.

- **Nothing secret touches disk** — no Values, no Credentials, no SSO-token
  cache. Config (locations only) is the *only* thing persisted. Secret material
  lives in zeroizing types and stays out of `Debug` / `Display` / logs / errors.
- **Never stomp a Secret Set** — all writes go through the op-based,
  replay-on-fresh, atomic compare-and-swap engine
  ([ADR 0001](docs/adr/0001-non-stomping-writes-via-staged-put-and-cas.md)).
- **Read-only by default** — mutating AWS calls are unreachable until the user
  deliberately switches into a lockable read-write mode; v1 ships read-only
  ([ADR 0004](docs/adr/0004-read-only-v1-scope-and-secret-shapes.md)).
- **Memory-only auth** — IAM Identity Center Sign-in each launch; no static
  keys; role Credentials refreshed silently from the SSO token
  ([ADR 0002](docs/adr/0002-identity-center-only-memory-only-auth.md)).

## Docs & decisions

This README is only the front door — the depth lives here:

- **[CONTEXT.md](CONTEXT.md)** — the domain glossary (Secret Set, Entry, Value,
  Environment, Application, the Aligned / Drift / Gap states). Read this first.
- **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** — what Janitor defends
  against, the explicit non-goals, and the trust boundaries.
- **[docs/iam_setup.md](docs/iam_setup.md)** — set up an IAM Identity Center org
  and permission set to run the live `live-verify` harness (Milestone B).
- **[docs/building.md](docs/building.md)** — build, test, coverage, and the
  human-gated live-verify binaries.
- **[Architecture Decision Records](docs/adr/)** — every hard-to-reverse choice,
  indexed in [`docs/adr/README.md`](docs/adr/README.md).
- **[CLAUDE.md](CLAUDE.md)** — working agreements and invariants for
  contributors (and AI assistants).

New hard-to-reverse decisions get an ADR; new domain terms go in CONTEXT.md. See
[CLAUDE.md](CLAUDE.md) for the conventions.

## License

[GPL-3.0-only](LICENSE). The Slint shell builds on [Slint](https://slint.dev)
under its GPL terms, so the project is GPL throughout
([ADR 0003](docs/adr/0003-core-gui-split-slint-and-secret-display.md)). The
obligation follows `JanitorKit.xcframework` into whichever repository consumes
it, because it is compiled from these crates.
