# Janitor

[![CI](https://github.com/Circuit-Stitch/Janitor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Circuit-Stitch/Janitor/actions/workflows/ci.yml)

> An ephemeral desktop client onto **AWS Secrets Manager**. It stores no secrets
> and no credentials of its own — it borrows them on demand and forgets them.
> The name is the thesis: the janitor holds the most keys, yet keeps none.

**License:** [GPL-3.0-only](LICENSE) · **Status:** core + GUI tracer-bullet +
guided Identity Center sign-in landed; no write path yet, GUI still on mock data
([details below](#status)) · **CI:** lint · test · coverage

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

*How the matrix is designed to read — it isn't built yet (see [Status](#status)).*

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

The security-critical core, a GUI tracer-bullet, and a headless Identity Center
auth slice all exist and are tested. The GUI still runs on mock data, and no
write path or live-wired data flow exists yet.

| Area | State |
| --- | --- |
| Secret-shape model — parse a Secret Set into comparable Entries; lossless flatten / unflatten to dotted-path Names | ✅ Implemented & tested |
| Zeroizing secret types — `Value` kept out of `Debug` / `Display` / logs | ✅ Implemented & tested |
| `Config` load / save — atomic TOML write, locations only | ✅ Implemented & tested |
| Comparison matrix (Aligned / Drift / Gap) + masked read model | ✅ Implemented & tested — [ADR 0009](docs/adr/0009-comparison-engine-result-model.md) |
| `janitor-gui` (Slint matrix view) — masked cells, per-cell reveal, settings | ✅ Tracer-bullet on a mock `SecretSource` — [ADR 0003](docs/adr/0003-core-gui-split-slint-and-secret-display.md) |
| Identity Center Sign-in + per-Environment Credentials + Secrets Manager I/O | ✅ Headless slice in `janitor-aws` (logic tested vs. fakes; browser/SDK shell untested by design) — [ADR 0002](docs/adr/0002-identity-center-only-memory-only-auth.md) / [ADR 0010](docs/adr/0010-aws-adapter-crate-and-auth-object-model.md). Live verification (Milestone B) pending |
| Guided sign-in — browser → log in → auto-discovered account / role / secret, org + last pick remembered | ✅ `live-verify` binary in `janitor-aws` (`ListAccounts`/`Roles`/`Secrets` + tested `select::resolve`; stdin/SDK shell untested) — [ADR 0011](docs/adr/0011-guided-sign-in-and-discovery.md). Live verification (Milestone B) pending |
| `janitor-aws` ↔ GUI wiring (real data in the matrix) | 📋 Next slice, not built |
| Non-stomping write engine | 📋 Designed — [ADR 0001](docs/adr/0001-non-stomping-writes-via-staged-put-and-cas.md), not built |

The workspace is three crates — `janitor-core` (offline, ≥80% coverage gate),
`janitor-gui` (Slint), and `janitor-aws` (async AWS adapter). `cargo test
--workspace` runs them all; the coverage gate stays on `janitor-core`, where
correctness is proven (ADR 0010 §5).

## Build & test

Standard Cargo across a three-crate workspace (`janitor-core`, `janitor-gui`,
`janitor-aws`).

```bash
cargo build                          # build the workspace
cargo test --workspace               # all crates (core + gui + janitor-aws fakes)
cargo test -p janitor-core <name>    # a single core test (substring match)
cargo clippy --all-targets           # lint
cargo fmt                            # format

# Coverage (≥80% gate on janitor-core). Needs the cargo-llvm-cov subcommand:
#   cargo install cargo-llvm-cov
cargo llvm-cov -p janitor-core

cargo run -p janitor-gui             # tracer-bullet GUI (mock data; no real AWS)

# janitor-aws human-gated binaries (need a browser + a real Identity Center org):
cargo run -p janitor-aws --bin loopback-spike   # browser↔loopback shell, no AWS
cargo run -p janitor-aws --bin live-verify      # guided sign-in: log in, then pick (ADR 0011)
```

## Architecture

Two crates, split along a trust boundary
([ADR 0003](docs/adr/0003-core-gui-split-slint-and-secret-display.md)):

- **`janitor-core`** *(trusted)* — all the security-critical logic, with **no
  GUI dependencies**: the secret-shape model, zeroizing in-memory types, Config,
  and — in future slices — Identity Center auth, Secrets Manager I/O, the
  comparison engine, and the non-stomping write engine. AWS access will sit
  behind a client **trait** so the network stays mockable and the coverage gate
  stays reachable. This is where correctness is proven.
- **`janitor-gui`** *(softer-trust, not yet built)* — a thin
  [Slint](https://slint.dev) view: the masked comparison matrix, momentary
  per-cell reveal, confirm-diff dialogs, and browser launch for Sign-in. No
  auth / AWS / compare / write logic lives here.

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
- **Architecture Decision Records** in [`docs/adr/`](docs/adr/):
  - [0001](docs/adr/0001-non-stomping-writes-via-staged-put-and-cas.md) — Non-stomping writes via staged `PutSecretValue` + atomic stage CAS
  - [0002](docs/adr/0002-identity-center-only-memory-only-auth.md) — Identity-Center-only, memory-only authentication
  - [0003](docs/adr/0003-core-gui-split-slint-and-secret-display.md) — Core/GUI split, Slint for the view, and the secret-display stance
  - [0004](docs/adr/0004-read-only-v1-scope-and-secret-shapes.md) — Read-only v1 scope, and how non-flat secret shapes are handled
  - [0005](docs/adr/0005-clipboard-and-read-model.md) — Clipboard handling and the matrix read model
  - [0006](docs/adr/0006-version-history-and-restore.md) — Version history and restore as a first-class feature
  - [0007](docs/adr/0007-ci-and-distribution.md) — CI and distribution: cargo-packager bundles, signed on macOS and Windows
  - [0008](docs/adr/0008-secret-shape-flattening-scheme.md) — Secret-shape flattening: leaf-type-preserving dotted paths with escaped dots
  - [0009](docs/adr/0009-comparison-engine-result-model.md) — Comparison engine result model (Aligned / Drift / Gap)
  - [0010](docs/adr/0010-aws-adapter-crate-and-auth-object-model.md) — `janitor-aws` adapter crate and the Identity Center auth object model
  - [0011](docs/adr/0011-guided-sign-in-and-discovery.md) — Guided sign-in: issuer-scoped registration, post-sign-in discovery, remembered picks
- **[CLAUDE.md](CLAUDE.md)** — working agreements and invariants for
  contributors (and AI assistants).

New hard-to-reverse decisions get an ADR; new domain terms go in CONTEXT.md. See
[CLAUDE.md](CLAUDE.md) for the conventions.

## License

[GPL-3.0-only](LICENSE). The GUI builds on [Slint](https://slint.dev) under its
GPL terms, so the project is GPL throughout
([ADR 0003](docs/adr/0003-core-gui-split-slint-and-secret-display.md)).
