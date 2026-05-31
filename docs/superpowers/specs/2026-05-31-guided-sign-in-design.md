# Guided sign-in: log-in-and-that's-it, with auto-discovered account / role / secret

**Status:** approved (brainstorm) — ready for planning
**Date:** 2026-05-31
**Related:** ADR 0002 (Identity-Center-only, memory-only auth), ADR 0010 (`janitor-aws`
adapter + auth object model + verify list), **ADR 0011** (this slice's decisions),
ADR 0004 (read-only v1, secret shapes), `CONTEXT.md`, `docs/THREAT-MODEL.md`.
Builds directly on the headless slice from
[`docs/superpowers/plans/2026-05-30-identity-center-auth.md`](../plans/2026-05-30-identity-center-auth.md)
(Milestone A landed).

## Why

The headless slice proved the auth chain works against *fakes* and builds a
`live-verify` binary — but that binary makes the human supply six flags every run
(`--authorize-endpoint`, `--sso-region`, `--account-id`, `--role`,
`--secret-region`, `--secret-id`). The goal of this slice is the opposite
experience:

> **The browser opens, I log in, and that's it.** The tool figures out the rest.

Everything except *which org* and *which secret to look at first* can be
discovered from AWS after sign-in. This slice delivers that — and, in doing so,
fixes a latent correctness gap in the (never-run-live) sign-in shell.

### The correctness finding (surfaced, not buried)

While confirming the SDK contract for this work, two gaps turned up in the
**committed-but-never-run-live** `authenticator.rs` / `aws_impl.rs`:

1. **`RegisterClient` passes no `issuerUrl`.** Every reference implementation
   (botocore, AWS CLI v2 ≥2.22.0, community PKCE clients) passes
   `issuerUrl = <org start/issuer URL>` so the browser consent screen is scoped to
   the user's org. Without it the `/authorize` page has no org context. ADR 0010
   §2a already lists *"whether `issuerUrl` is mandatory"* as an open verify item —
   this slice resolves it by passing it.
2. **The `/authorize` endpoint is a hand-passed flag**, but `RegisterClient`'s
   *response* returns `authorizationEndpoint` (and `tokenEndpoint`) directly —
   confirmed present in the installed `aws-sdk-ssooidc 1.102`
   (`RegisterClientOutput::authorization_endpoint() -> Option<&str>`).

So the fix and the feature are the same move: **pass `issuerUrl` from saved
Config → read the authorize endpoint from the registration response → delete the
flag.** This changes behavior in untested shell code that has not yet run live;
it is called out here and will be re-confirmed in Milestone B.

## Goal / non-goals

**In scope**
- Pass `issuerUrl` to `RegisterClient`; surface `authorization_endpoint` on
  `ClientRegistration`; have `Authenticator` read it from the response. Remove the
  `--authorize-endpoint` flag and the `authorize_endpoint` constructor arg.
- "Enter once, remember" for the org: first run prompts for SSO start URL + SSO
  region (+ secret-browse region); persisted via core `Config` (already tested).
- After sign-in, **auto-discover**: list entitled accounts → roles for the chosen
  account → secrets in the browse region. Selection rule per step: **0 → clear
  error; exactly 1 → auto-pick silently; ≥2 → numbered menu**, pre-selecting a
  remembered choice as the default.
- Always end by **fetching the chosen secret** through the existing
  `AuthenticatedSource::fetch` and printing the **masked** matrix (output
  discipline unchanged).
- Remember the chosen account/role/secret and offer it as the default next run.
- **Rework `live-verify` into this guided flow.** Flags become optional overrides
  (skip a discovery step) rather than required inputs.

**Out of scope (YAGNI / later slices)**
- GUI wiring (`janitor-aws` ↔ Slint). This binary is terminal-only.
- The write path; read-only stays (ADR 0004).
- Fetching *all* secrets in an account, or a standing secrets cache.
- A reusable `GuidedSession` facade object. The reusable pieces (pure selection,
  discovery traits, SDK-free summaries) are extracted; the stdin menu glue is not
  (a GUI won't reuse a terminal menu).
- Disk-caching the client registration (ADR 0010 §8 keeps it memory-only).

## The two flows

**First run (empty Config):**

```
load Config (empty)
  → prompt: SSO start URL, SSO region, secret-browse region   → save to Config
    → RegisterClient(issuerUrl = start URL, redirect_uris)     [returns authz endpoint]
      → browser PKCE sign-in → SSO token (memory)
        → ListAccounts(token)            → resolve → account
          → ListAccountRoles(token, acct)→ resolve → role
            → GetRoleCredentials         → role Credential (memory)
              → ListSecrets(cred, region)→ resolve → secret
                → AuthenticatedSource::fetch(Mapping) → SecretShape
                  → project() → MASKED matrix print
                    → save chosen (acct, role, secret, region) as Config.last_pick
```

**Steady state (Config populated):**

```
load Config → RegisterClient → browser sign-in → (discovery steps auto-pick where
unambiguous, and pre-select last_pick as the menu default where not) → fetch →
masked matrix.  In the common single-account / single-role / same-secret case:
open browser, log in, done.
```

## Architecture

All new logic lands in `janitor-aws` and follows ADR 0010 §5: SDK ops behind
narrow traits with SDK-free I/O; pure logic unit-tested; only the stdin menu, the
browser, and the real SDK adapters stay untested shell.

### 1. Auth fix (`wire.rs`, `aws_impl.rs`, `authenticator.rs`)

- `ClientRegistration` gains `pub authorization_endpoint: String`.
- `OidcClient::register_client` signature becomes
  `register_client(&self, issuer_url: &str, redirect_uris: &[String])`; the real
  impl adds `.issuer_url(issuer_url)` and reads `out.authorization_endpoint()`.
- `Authenticator::new(oidc, issuer_url)` — the `authorize_endpoint` arg is
  replaced by `issuer_url`; `sign_in_once()` reads the endpoint from the
  registration instead of a stored field.
- `issuer_url` is fed from `Config.sso_start_url`. (Verify item: confirm AWS
  accepts the start URL as `issuerUrl`; the dedicated Issuer URL is the documented
  alternative. References use the start URL.)

### 2. Discovery seam (`wire.rs` + `aws_impl.rs`)

New SDK-free summary types:

```rust
pub struct AccountSummary { pub id: String, pub name: String }
pub struct RoleSummary    { pub name: String }              // account implied by query
pub struct SecretSummary  { pub name: String, pub arn: String }
```

New trait (authorized by the **SSO token**, via `aws-sdk-sso`):

```rust
#[async_trait]
pub trait AccountCatalog: Send + Sync {
    async fn list_accounts(&self, token: &SsoToken)
        -> Result<Vec<AccountSummary>, SessionError>;
    async fn list_account_roles(&self, token: &SsoToken, account_id: &str)
        -> Result<Vec<RoleSummary>, SessionError>;
}
```

One new method on the existing `SecretsApi` (authorized by the **role
Credential**, same client as `get_secret_value`):

```rust
async fn list_secrets(&self, cred: &Credential, region: &str)
    -> Result<Vec<SecretSummary>, SessionError>;
```

Real impls paginate (`into_paginator` / `next_token`) and map list errors with
the same conservative `discriminant`-based mapping as the existing adapters until
Milestone B refines them. SDK accessors confirmed: `AccountInfo::{account_id,
account_name}`, `RoleInfo::role_name`, and `aws-sdk-secretsmanager` `SecretListEntry::{name, arn}`.

**Surfaced (additive) test change:** the `cfg(test)` fakes
`FakeSecretsApi` gains a scripted `list_secrets`, and a new `FakeAccountCatalog`
is added. These are *additions*; no existing test's asserted behavior changes.

### 3. Pure selection (`select.rs`, new — fully tested)

The 0 / 1 / many + remembered-default branching is the one piece of real logic,
so it is pure and seam-free:

```rust
pub trait Selectable { fn key(&self) -> &str; fn label(&self) -> String; }

pub enum SelectionPlan {
    Empty,                           // caller errors out with a clear message
    Auto(usize),                     // exactly one → take it, no prompt
    Ask { default: Option<usize> },  // ≥2 → caller prompts, with this default index
}

/// Pure. `remembered` is the previously-chosen key, if any.
pub fn plan_selection<T: Selectable>(items: &[T], remembered: Option<&str>) -> SelectionPlan;
```

`AccountSummary` / `RoleSummary` / `SecretSummary` implement `Selectable`
(`key` = id/name/arn; `label` = human line). Tested cases: empty → `Empty`; one →
`Auto(0)`; many with no remembered → `Ask { default: None }`; many with remembered
present → `Ask { default: Some(i) }`; many with remembered absent →
`Ask { default: None }`.

### 4. Stdin menu (in the binary — untested shell)

A small `prompt_choice(prompt, labels: &[String], default: Option<usize>) -> usize`
that reads stdin (Enter accepts the default). Untested by design, like the browser
and loopback. It is only reached on the `Ask` branch.

### 5. Config changes (`janitor-core` — surfaced, two additive fields)

Core is the gated bedrock, so these are called out explicitly. Both are
`#[serde(default)]`-covered (the struct already carries `#[serde(default)]`), so
an existing `config.toml` without them still loads — backward compatible.

```rust
pub struct Config {
    pub sso_start_url: String,
    pub sso_region: String,
    pub secret_region: String,            // NEW: default region for the ListSecrets menu;
                                          // empty → fall back to sso_region at runtime.
                                          // "switchable" = a settings field today, GUI later.
    pub last_pick: Option<Mapping>,       // NEW: the last guided pick, offered as default.
    pub applications: Vec<Application>,
}
```

New tests in core: round-trip with both fields populated; an old-style TOML
(without the new keys) loads to defaults (`secret_region == ""`,
`last_pick == None`). These are *new* tests; no existing core test changes.

`last_pick` is a `Mapping` (its `environment` is set to `"live"` for guided
picks). When the GUI lands, picks graduate into named `Application`s; `last_pick`
is the harness's lightweight memory until then.

### 6. Reworked binary (`bin/live-verify.rs` → guided flow)

Orchestrates: load Config → prompt+save any missing org fields → build
`Authenticator` (issuer = start URL) → sign in → `AccountCatalog` discovery +
`plan_selection` + `prompt_choice` for account then role → `GetRoleCredentials` →
`list_secrets` + select → assemble `Mapping` → `AuthenticatedSource::fetch` →
masked `project()` print → save `last_pick`. Optional override flags
(`--secret-region`, `--account-id`, `--role`, `--secret-id`) short-circuit the
matching discovery step. The binary holds no testable logic — every decision is in
`plan_selection`, the summaries, or the facade.

The ADR 0010 verify checklist the old binary printed is preserved (still the way
to force error paths for Milestone B).

## Error handling

- `plan_selection` → `Empty` (no accounts / no roles / no secrets): the binary
  prints a specific message ("you are not entitled to any accounts", etc.) and
  exits non-zero. **No new `SessionError` variant** — the taxonomy stays stable;
  emptiness is a binary-level outcome, not a session fault.
- Discovery calls run immediately after sign-in, so a dead token is unlikely; a
  `ReauthRequired` from a discovery call is propagated with a "session expired,
  re-run" message rather than folded into `AuthenticatedSource`'s escalation
  (which still owns re-auth for the actual `fetch`).
- All other discovery errors map through the existing conservative `Sdk`
  catch-all until Milestone B.

## Output discipline (unchanged)

The only thing printed for the secret is core's masked `MatrixView` (lengths,
group ids, masked tokens) via `project()`. Account names, role names, and secret
*names/ARNs* are non-secret metadata and may print (they are exactly what AWS
shows in its own menus). A secret **Value** is never formatted directly, and
errors are never `{:?}`-printed with a body (ADR 0010 §2).

## Tested vs. untested split (ADR 0010 §5)

- **Tested (CI, against fakes):** `plan_selection` (all branches); the list→
  summary mappings; new discovery error mappings; `register_client` returning
  `authorization_endpoint`; `Config` round-trip + backward-compat for the two new
  fields.
- **Untested shell (consistent with ADR 0010 §5):** stdin `prompt_choice`; the
  real `AccountCatalog` / `list_secrets` / `register_client` SDK adapters; the
  browser + loopback. Exercised only by the human-run binary.

## Decisions to record in ADR 0011

1. Pass `issuerUrl` to `RegisterClient`; read `authorizationEndpoint` from its
   response; drop the `--authorize-endpoint` flag (resolves an ADR 0010 §2a verify
   item; corrects untested shell).
2. Post-sign-in discovery model (`ListAccounts` / `ListAccountRoles` /
   `ListSecrets` behind narrow traits) with the pure **0 / 1 / many +
   remembered-default** selection rule.
3. Two additive `Config` fields (`secret_region`, `last_pick`) — the org and the
   last pick are *locations*, never Values, so they remain on-thesis for the
   only-file-on-disk invariant.
4. `live-verify` becomes the guided sign-in flow; flags are optional overrides.

## Open items to confirm in Milestone B (live)

- Does AWS accept `Config.sso_start_url` as `RegisterClient.issuerUrl`, or is the
  dedicated Issuer URL required? (References use the start URL.)
- Real error shapes for `ListAccounts` / `ListAccountRoles` / `ListSecrets`
  (token-expiry, throttle), to refine the conservative mappings.
- Pagination behavior on accounts/secrets large enough to page.
- (Carried from ADR 0010) the `GetRoleCredentials` / `GetSecretValue` error-shape
  items remain open.
