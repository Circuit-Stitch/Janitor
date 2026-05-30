# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Status: foundation landed.** The Cargo workspace and `janitor-core`'s offline
> bedrock exist — secret-shape model (parse/flatten/unflatten), zeroizing `Value`,
> and `Config` load/save — under a CI lint/test/coverage lane. No AWS, GUI, or
> write path yet. The design is specified in [`CONTEXT.md`](CONTEXT.md) (domain
> glossary), [`docs/adr/`](docs/adr/) (decisions 0001–0008), and
> [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) (security posture). **Read those
> first** — this file only summarizes.

## What this is

**Janitor** is a cross-platform desktop application that is an **ephemeral client
onto AWS Secrets Manager**. It stores no secrets and no credentials of its own —
it borrows them on demand and forgets them. The name is the thesis: the janitor
holds the most keys, but Janitor itself keeps none.

Two core jobs:
1. **Drift detection** — compare the same logical Secret Set across N Environments
   (prod/staging/dev, possibly different AWS accounts and regions) in a masked
   matrix. Each Entry is **Aligned** (same everywhere), **Drift** (present
   everywhere, values differ), or **Gap** (missing in some) — Gap being the
   high-signal "Terraform/compose hole" finding.
2. **Safe mutation** — change a few Entries without ever accidentally overwriting
   the whole Set. This is the reason the tool exists (see ADR 0001).

## Non-negotiable invariants

These are the spine of the project. Violating one is never a "small" change —
surface it loudly (see [THREAT-MODEL.md](docs/THREAT-MODEL.md)):

- **Nothing secret touches disk.** No Values, no Credentials, no SSO-token cache.
  Config (locations only, never Values) is the *only* thing persisted. Hold
  secret material in zeroizing types (`zeroize`/`secrecy`); keep it out of
  `Debug`/`Display`/logs/errors.
- **Never stomp a Secret Set.** All writes go through the op-based, replay-on-fresh,
  atomic compare-and-swap engine in **ADR 0001** — never a naive `PutSecretValue`
  of the in-memory blob.
- **Read-only by default.** Mutating AWS calls are unreachable until the user
  deliberately switches into (lockable) read-write mode. v1 ships read-only.
- **Auth is Identity Center only, memory-only.** Browser Sign-in each launch; no
  static keys; role Credentials refreshed silently from the SSO token (ADR 0002).
- **`core` holds the secrets logic; the GUI is a thin, softer-trust view.** Don't
  push auth/AWS/compare/write logic into `janitor-gui` (ADR 0003).

## Architecture (target)

- **`janitor-core`** — no GUI deps. Identity Center auth + per-Environment
  Credential model, Secrets Manager I/O, the non-stomping write engine, the
  comparison engine, Config load/save, secret-in-memory handling. **Target ≥80%
  test coverage** — this is where correctness is proven.
- **`janitor-gui`** — thin Slint (GPL) view: the comparison matrix (sortable,
  filterable by Entry name incl. prefix clusters), masked cells with momentary
  per-cell reveal, confirm-diff dialogs, browser launch. No secret logic.

## Commands

> Standard Cargo, valid once the workspace is initialized. Verify against the real
> `Cargo.toml` / workspace layout once it exists.

```bash
cargo build                       # build
cargo test                        # all tests
cargo test -p janitor-core <name> # a single core test (substring match)
cargo test -- --nocapture         # show test stdout/stderr
cargo clippy --all-targets        # lint
cargo fmt                         # format
cargo llvm-cov -p janitor-core    # coverage (≥80% gate)
# cargo run -p janitor-gui        # (not yet — GUI lands in a later slice)
```

## Working agreements

- **Decisions get ADRs.** When you make a hard-to-reverse, non-obvious,
  real-trade-off choice, add `docs/adr/NNNN-slug.md` (see existing ones for
  format) rather than burying it in a diff.
- **New domain terms go in `CONTEXT.md`**, and only there — it is a glossary, not
  a spec or scratchpad. Keep implementation detail out of it.
- **ADR 0001 has open API-behavior items** ("verify against the live API")—
  resolve those with real AWS calls before relying on the write path.
