# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Status: GUI↔AWS bridge landed (ADR 0012) — the matrix now reads real AWS.** The Cargo
> workspace now holds three crates under a CI lint/test/coverage lane:
> `janitor-core`'s offline bedrock (secret-shape model, zeroizing `Value`,
> `Config` load/save, comparison engine); a thin `janitor-gui` (Slint)
> tracer-bullet rendering the masked Aligned/Drift/Gap matrix (per-cell momentary
> reveal, sidebar Application switching, in-memory settings) from a mock
> `SecretSource`; and a new async `janitor-aws` crate implementing real Identity
> Center Sign-in (browser Auth Code + PKCE → in-memory SSO token →
> `GetRoleCredentials` → `GetSecretValue` → `SecretShape`) behind a tested
> `AuthenticatedSource` facade. All of `janitor-aws`'s brokering / orchestration /
> error logic is unit-tested against fakes; only the browser/loopback/SDK shell is
> untested by design (ADR 0010 §5). The `live-verify` binary is now a **guided
> sign-in**: browser → log in → auto-discovered account/role/secret (via
> `ListAccounts`/`ListAccountRoles`/`ListSecrets`, with a pure tested
> 0/1/many+remembered-default `select::resolve`), with the org + last pick
> remembered in `Config` (ADR 0011). The `--authorize-endpoint` flag is gone —
> the endpoint is read from `RegisterClient`'s response and `issuerUrl` is passed.
> **GUI↔AWS bridge landed (ADR 0012):** the GUI now feeds the masked matrix from
> **real** AWS via a worker-threaded `janitor-aws::Session` (lazy browser sign-in
> off the UI thread, one Application at a time; secrets resident only in the
> worker; reveal is an on-demand round-trip; whole-app error on any env failure);
> `JANITOR_MOCK=1` runs it offline on `MockSource`. **Still deferred:**
> discovery-driven column assembly, per-column error rendering, the typed
> `GetSecretValue` error mapping, and live re-verification (browser + real org)
> pending **Milestone B** — running `live-verify` against a real org to resolve
> the ADR 0010/0011 verify lists (incl. whether the start URL is accepted as
> `issuerUrl`). Design and plan:
> [`docs/adr/0012-gui-aws-bridge-worker-and-lazy-sign-in.md`](docs/adr/0012-gui-aws-bridge-worker-and-lazy-sign-in.md),
> [`docs/superpowers/specs/2026-05-31-gui-aws-bridge-design.md`](docs/superpowers/specs/2026-05-31-gui-aws-bridge-design.md),
> and [`docs/superpowers/plans/2026-05-31-gui-aws-bridge.md`](docs/superpowers/plans/2026-05-31-gui-aws-bridge.md).
> Domain glossary: [`CONTEXT.md`](CONTEXT.md); decisions: [`docs/adr/`](docs/adr/)
> (0001–0012); security posture: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).
> **Read those first** — this file only summarizes.

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
cargo build                       # build the workspace
cargo test --workspace            # all crates (core + gui + janitor-aws fakes)
cargo test -p janitor-core <name> # a single core test (substring match)
cargo test -- --nocapture         # show test stdout/stderr
cargo clippy --all-targets        # lint
cargo fmt                         # format
cargo llvm-cov -p janitor-core    # core coverage (≥80% gate)
cargo llvm-cov -p janitor-aws --ignore-filename-regex 'src/bin/'  # aws lib coverage (≥80% gate, ADR 0016)
cargo run -p janitor-gui          # real AWS via the worker bridge (browser sign-in; needs a configured org)
$env:JANITOR_MOCK=1; cargo run -p janitor-gui   # offline mock — Windows PowerShell
JANITOR_MOCK=1 cargo run -p janitor-gui         # offline mock — bash

# janitor-aws human-gated binaries (ADR 0010 Milestone B — need a browser):
# Identity Center org + permission-set setup for these: docs/iam_setup.md
cargo run -p janitor-aws --bin loopback-spike   # browser↔loopback shell, no AWS
cargo run -p janitor-aws --bin live-verify -- … # live Identity Center round-trip
```

## Working agreements

- **Decisions get ADRs.** When you make a hard-to-reverse, non-obvious,
  real-trade-off choice, add `docs/adr/NNNN-slug.md` (see existing ones for
  format) rather than burying it in a diff.
- **New domain terms go in `CONTEXT.md`**, and only there — it is a glossary, not
  a spec or scratchpad. Keep implementation detail out of it.
- **ADR 0001 has open API-behavior items** ("verify against the live API")—
  resolve those with real AWS calls before relying on the write path.

## Agent skills

### Issue tracker

Issues and PRDs are tracked as GitHub issues (`Circuit-Stitch/Janitor`) via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary — `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
