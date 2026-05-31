# Handoff — Identity Center auth, Milestone B (live-verified)

**Date:** 2026-05-31 · **Branch:** `feat/identity-center-auth` · **PR:** [#4](https://github.com/Circuit-Stitch/Janitor/pull/4) (OPEN, 32 commits, base `main`)

## 1. Summary

The Identity Center auth slice (`janitor-aws` crate, ADR 0010) plus **guided
sign-in** (ADR 0011) is implemented and **proven end-to-end against a real
Identity Center org (Milestone B)**: `live-verify` does browser PKCE sign-in →
SSO token → role credential → account/role/secret discovery → masked drift
matrix, never printing a plaintext value. Running it live disproved three
assumptions baked into the never-run SDK/loopback shell; all three are fixed and
committed. The work is on an open PR, fully green (fmt, 44 `janitor-aws` + 64
`janitor-core` tests, clippy `--all-targets -D warnings`), working tree clean.

## 2. Completed (this session)

- **Diagnosed + fixed 3 live-only auth bugs** (commit `a398db0`,
  `janitor-aws/src/{loopback.rs,aws_impl.rs,bin/live-verify.rs}`):
  1. Loopback redirect **path must be exactly `/oauth/callback`** (was
     `/callback` → `InvalidRedirectUriException`). Register **port-less** (RFC
     8252 §7.3); bound port added at authorize/token time.
  2. `RegisterClient` returns **null `authorizationEndpoint`** → new
     `authorize_endpoint()` derives `https://oidc.<sso-region>.amazonaws.com/authorize`.
  3. `issuerUrl` must be the **Issuer URL**, not the portal `…/start` URL
     (portal → `"Invalid start url provided"`). Doc-only fix (Config already
     carries whatever the user enters).
  - Added `live-verify --reset-config`; added stderr `eprintln!` diagnostics on
    `RegisterClient`/`CreateToken`/`GetSecretValue` errors (metadata only, never
    a value).
- **Docs** (commit `0c8a2f7`): ADR 0011 gained a "Milestone B outcome
  (2026-05-31)" section; `docs/iam_setup.md` corrected — policy now includes
  `kms:Decrypt`, Issuer-URL guidance, KMS key-policy fallback, verified banner.
- **Earlier in session** (already committed before this push): `docs/iam_setup.md`
  created (`d84b913`); README/CLAUDE.md links.
- **Opened PR #4**; updated auto-memory `janitor-project.md` with the Milestone B
  outcome.
- **Live run result:** masked 20-entry matrix from `deferno/staging/app-secrets`
  (account `circuitstitch` / `744043381173`, permission set `JanitorSecretsRead`,
  `us-west-2`).

## 3. In progress / incomplete

None mid-flight — every change is committed and the tree is clean. The items
below are *deferred by decision*, not half-done.

## 4. Key decisions & context

- **The 3 fixes were verified empirically**, not theorized: `RegisterClient` is
  unauthenticated, so it was probed directly with `curl` (single-variable
  matrices) to isolate that the *path* — not the port, not the URL — caused the
  loopback error. An earlier port-less-but-still-`/callback` fix attempt failed
  identically; that ruled out the port. Don't "simplify" the `/oauth/callback`
  path or the port-less registration — both are load-bearing.
- **`eprintln!` diagnostics are temporary scaffolding.** They de-blinded the
  never-run shell. They print error *metadata* only (a secret value exists only
  on a `GetSecretValue` **success**, never an error), so they don't violate the
  no-secrets-in-logs invariant — but they are not production logging.
- **Test-regression honesty:** one existing test was *replaced*, not weakened —
  `redirect_uris_use_literal_loopback_ip` asserted the port-bearing `/callback`
  that AWS rejects. Replaced with exact-equality on the correct port-less
  `/oauth/callback`. Surfaced in the commit body and PR.
- **KMS gotcha is real and now documented:** production secrets use a
  customer-managed CMK, so the permission set needs `kms:Decrypt` on top of
  `secretsmanager:GetSecretValue` — else `ListSecrets` works but `GetSecretValue`
  → `AccessDeniedException "Access to KMS is not allowed"`.

## 5. Next steps (ordered)

1. **Get PR #4 reviewed / merged.** It's green and self-contained. (The
   subagent-driven-development flow's terminal "final code-reviewer over the
   whole slice" was *not* run this session — optional but available.)
2. **Typed `GetSecretValue` error mapping** (the main deferred code item): map to
   `SessionError::{AccessDenied,NotFound}` via
   `aws_smithy_types::error::metadata::ProvideErrorMetadata::code()` — AWS
   returns AccessDenied as an SDK **`Unhandled`** variant, so matching a modeled
   variant or the discriminant won't work. Re-verify against the live org
   (AccessDenied is reproducible by pointing `--secret-id` at a CMK-encrypted
   secret without `kms:Decrypt`; NotFound by a bogus `--secret-id`). Then
   **remove the temporary `eprintln!` diagnostics**.
3. **Finish the remaining Milestone-B checklist items** (still untested live):
   token-expiry → exactly one re-sign-in (no loop); explicit `--secret-id`
   NotFound; confirm `roleCredentials.expiration` is read (not a hardcoded 1h).
4. **Next slice: `janitor-aws` ↔ GUI bridge** — wire real data into the matrix
   (GUI still on `MockSource`).

## 6. Blockers & open questions

- No blockers. Milestone B is reproducible on demand (the user has the org;
  `cargo run -p janitor-aws --bin live-verify`, pick a secret).
- Open question for the reviewer: ship the `eprintln!` diagnostics as-is (ADR
  marks the proper mapping deferred) **or** do the typed mapping before merge?
  The author leaned toward doing the mapping now while a live org is handy; the
  user chose to open the PR first.

## 7. Environment / setup notes

- **Platform:** Windows 11, PowerShell + Bash both available. Cargo's "Finished"
  line renders as a red `NativeCommandError` in PS 5.1 — **not** a failure; judge
  by exit code / `test result: ok`.
- **Remote:** `git@github.com:Circuit-Stitch/Janitor.git` (SSH). `gh` authed as
  `Kyle-Falconer`. Branch tracks `origin/main`. 32 commits ahead.
- **Live-verify is human-gated** (browser + stdin) — run it in a real terminal
  via the `! cargo run …` prefix, not the agent's Bash tool.
- **Config** (locations only, never values):
  `%APPDATA%\Janitor\Janitor\config\config.toml`. `--reset-config` wipes it.
  Use the **Issuer URL** at the start-URL prompt.
- **Subagent gotcha (from memory):** in any subagent prompt, forbid
  branch-changing git (shared CWD/HEAD); trust `cargo` over stale harness
  diagnostics.
- Commands: `cargo test --workspace`, `cargo clippy --workspace --all-targets`,
  `cargo fmt --all`, `cargo llvm-cov -p janitor-core` (≥80 % gate, core only).
