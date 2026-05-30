# Janitor

> An ephemeral desktop client onto **AWS Secrets Manager**. It stores no secrets
> and no credentials of its own — it borrows them on demand and forgets them.
> The name is the thesis: the janitor holds the most keys, yet keeps none.

**License:** [GPL-3.0-only](LICENSE) · **Status:** core foundation only — no AWS,
GUI, or write path yet ([details below](#status)) · **CI:** lint · test · coverage

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

The repository is at the **foundation** stage. The security-critical core exists
and is tested; nothing here talks to the network yet.

| Area | State |
| --- | --- |
| Secret-shape model — parse a Secret Set into comparable Entries; lossless flatten / unflatten to dotted-path Names | ✅ Implemented & tested |
| Zeroizing secret types — `Value` kept out of `Debug` / `Display` / logs | ✅ Implemented & tested |
| `Config` load / save — atomic TOML write, locations only | ✅ Implemented & tested |
| Identity Center Sign-in + per-Environment Credentials | 📋 Designed — [ADR 0002](docs/adr/0002-identity-center-only-memory-only-auth.md), not built |
| Secrets Manager I/O + comparison matrix | 📋 Designed — [ADR 0005](docs/adr/0005-clipboard-and-read-model.md), not built |
| Non-stomping write engine | 📋 Designed — [ADR 0001](docs/adr/0001-non-stomping-writes-via-staged-put-and-cas.md), not built |
| `janitor-gui` (Slint matrix view) | 📋 Designed — [ADR 0003](docs/adr/0003-core-gui-split-slint-and-secret-display.md), not built |

Today the workspace is a single offline crate, `janitor-core`, whose unit tests
pass under a ≥80% coverage gate.

## Build & test

Standard Cargo. Only `janitor-core` exists today; the GUI joins the workspace in
a later slice.

```bash
cargo build                          # build the workspace
cargo test -p janitor-core           # run core tests (offline, no network)
cargo test -p janitor-core <name>    # a single test (substring match)
cargo clippy --all-targets           # lint
cargo fmt                            # format

# Coverage (≥80% gate on janitor-core). Needs the cargo-llvm-cov subcommand:
#   cargo install cargo-llvm-cov
cargo llvm-cov -p janitor-core

# cargo run -p janitor-gui           # not yet — the GUI lands in a later slice
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
- **[CLAUDE.md](CLAUDE.md)** — working agreements and invariants for
  contributors (and AI assistants).

New hard-to-reverse decisions get an ADR; new domain terms go in CONTEXT.md. See
[CLAUDE.md](CLAUDE.md) for the conventions.

## License

[GPL-3.0-only](LICENSE). The GUI builds on [Slint](https://slint.dev) under its
GPL terms, so the project is GPL throughout
([ADR 0003](docs/adr/0003-core-gui-split-slint-and-secret-display.md)).
