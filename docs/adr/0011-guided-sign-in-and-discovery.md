# Guided sign-in: issuer-scoped registration, post-sign-in discovery, and remembered picks

**Status:** accepted

## Context

[ADR 0010](0010-aws-adapter-crate-and-auth-object-model.md) built the headless
auth slice: a `live-verify` binary that signs in and fetches one Secret Set. But
it requires the human to supply six flags every run (`--authorize-endpoint`,
`--sso-region`, `--account-id`, `--role`, `--secret-region`, `--secret-id`). The
desired experience is "the browser opens, I log in, and that's it" — the tool
discovers everything it can.

Two facts make that reachable, and one makes part of it impossible:

- **`RegisterClient`'s response already carries the answer.** It returns
  `authorizationEndpoint` and `tokenEndpoint`
  (`RegisterClientOutput::authorization_endpoint() -> Option<&str>`, confirmed in
  `aws-sdk-ssooidc 1.102`). The endpoint never needed to be a flag.
- **The SSO token can enumerate entitlements.** `aws-sdk-sso` `ListAccounts` /
  `ListAccountRoles` (authorized by the SSO token) and `aws-sdk-secretsmanager`
  `ListSecrets` (authorized by the role Credential) let the tool present what the
  user can actually reach. Accessors confirmed: `AccountInfo::{account_id,
  account_name}`, `RoleInfo::role_name`, `SecretListEntry::{name, arn}`; all three
  list ops expose `into_paginator()`.
- **The org identity is irreducible.** The SSO start/issuer URL and SSO region
  *are* "which company's AWS" — they cannot be discovered from inside that AWS.
  They must come from the user once.

A latent gap also surfaced while confirming the above: the committed (never-run-
live) `register_client` passes **no `issuerUrl`**, and the `Authenticator` takes
the authorize endpoint as a constructor arg rather than reading it from the
registration. ADR 0010 §2a explicitly left *"whether `issuerUrl` is mandatory"*
as a verify item; reference clients (botocore, AWS CLI v2 ≥2.22.0) all pass it so
the consent screen is org-scoped. This ADR resolves that item by passing it.

Design detail lives in
[`docs/superpowers/specs/2026-05-31-guided-sign-in-design.md`](../superpowers/specs/2026-05-31-guided-sign-in-design.md).

## Decision

- **Issuer-scoped registration; endpoint from the response (with a region
  fallback).** `RegisterClient` is called with `issuerUrl = Config.sso_start_url`.
  `ClientRegistration` gains `authorization_endpoint`, read from
  `RegisterClientOutput`; `Authenticator` takes the issuer URL (not a hardcoded
  endpoint). The `--authorize-endpoint` flag and the `authorize_endpoint`
  constructor arg are removed. **Milestone B correction:** the live API returns a
  *null* `authorizationEndpoint`, so reading it from the response is necessary but
  not sufficient — `authorize_endpoint()` falls back to the canonical
  `https://oidc.<sso-region>.amazonaws.com/authorize` when the response value is
  absent/empty. See "Milestone B outcome" below.

- **Post-sign-in discovery behind narrow traits (ADR 0010 §5 seam).** A new
  `AccountCatalog` trait (`list_accounts`, `list_account_roles`, authorized by the
  SSO token) and a new `list_secrets` method on the existing `SecretsApi`
  (authorized by the role Credential). I/O are SDK-free owned summaries
  (`AccountSummary`, `RoleSummary`, `SecretSummary`). Real impls paginate and map
  errors conservatively (the ADR 0010 `discriminant`-based `Sdk` catch-all) until
  Milestone B; fakes drive tests.

- **Selection is a pure, tested function — `0 / 1 / many + remembered default`.**
  `plan_selection(items, remembered) -> SelectionPlan { Empty | Auto(i) | Ask {
  default } }` holds the only real logic: no entitlements → a clear error; exactly
  one → auto-pick with no prompt; several → a numbered menu pre-selecting any
  remembered choice. The stdin menu that consumes an `Ask` is untested shell, like
  the browser and loopback. Emptiness is a **binary-level outcome, not a new
  `SessionError`** — the taxonomy stays stable.

- **Remember the org and the last pick in `Config` — locations, never Values.**
  `Config` gains two `#[serde(default)]` fields: `secret_region` (the default
  region for the `ListSecrets` menu; empty → fall back to `sso_region`) and
  `last_pick: Option<Mapping>` (offered as the default next run). Both are
  *locations* — they cannot structurally hold a secret — so the "Config is the
  only file on disk, and it holds no Values" invariant (THREAT-MODEL) is
  untouched. Old `config.toml` files without the keys still load (backward
  compatible). `secret_region` is a plain field today so it is trivially
  "switchable" from a future settings surface.

- **`live-verify` becomes the guided flow; flags become optional overrides.**
  Rather than keep a second binary, the existing harness is reworked into the
  guided sign-in. `--secret-region` / `--account-id` / `--role` / `--secret-id`
  still exist but only to short-circuit the matching discovery step (and to force
  the ADR 0010 error-path checklist). One tool, one job, less duplication.

## Considered options

- **Keep `--authorize-endpoint` and just add discovery for account/role/secret.**
  Rejected: leaves a flag that the `RegisterClient` response already obviates, and
  leaves the `issuerUrl` gap (an open ADR 0010 verify item) unresolved.
- **Read `~/.aws/config` `[sso-session]` for the org.** Rejected as the *primary*
  path: this machine has no `~/.aws/config`, and depending on the AWS CLI being
  configured couples Janitor to another tool's state. May return later as an
  optional convenience that pre-fills the one-time prompt.
- **A reusable `GuidedSession` facade object.** Rejected (YAGNI): discovery
  interleaves with user choices, so it needs the menu seam anyway and is harder to
  test as a unit than the pure `plan_selection`. The reusable parts (pure
  selection, discovery traits, SDK-free summaries) drop into the future GUI; the
  terminal menu glue does not, so it stays in the binary.
- **A second `sign-in` binary alongside `live-verify`.** Rejected: two
  near-identical harnesses drift. Overrides give the old scriptable behavior.
- **A new `SessionError::NoEntitlements` (or similar) for the empty case.**
  Rejected: emptiness is a UX outcome of a successful call, not a session fault;
  adding a variant no production path consumes is the unreachable-variant smell
  ADR 0010 §9 rejects.
- **Fetch all secrets in the account (zero secret input ever).** Rejected for this
  slice: many `GetSecretValue` calls, needs the same `ListSecrets` op anyway, and
  is noisy/slow on large accounts. The menu pick is the smallest thing that meets
  the goal.

## Consequences

- The `OidcClient::register_client` signature changes (adds `issuer_url`) and
  `ClientRegistration` gains a field — both within `janitor-aws`'s untested SDK
  seam; the `cfg(test)` fakes update accordingly. **Surfaced additive test
  changes:** `FakeSecretsApi` gains a scripted `list_secrets` and a
  `FakeAccountCatalog` is added; no existing test's asserted behavior changes.
- `janitor-core` gains two backward-compatible `Config` fields with new
  round-trip + old-file-loads-defaults tests. The coverage gate is unaffected
  (additive, tested).
- The guided flow's new logic (`plan_selection`, summary mappings, registration
  endpoint plumbing) is CI-tested against fakes; only the stdin menu, the real
  list adapters, the browser, and loopback stay untested (consistent with
  ADR 0010 §5).
- **New open items for Milestone B:** whether AWS accepts the start URL as
  `issuerUrl` (vs. the dedicated Issuer URL); real `ListAccounts` /
  `ListAccountRoles` / `ListSecrets` error and pagination shapes. These join,
  rather than replace, ADR 0010's still-open `GetRoleCredentials` /
  `GetSecretValue` error-shape items. **All of the items in this bullet are
  resolved below.**

## Milestone B outcome (2026-05-31)

Ran `live-verify` end-to-end against a real Identity Center org (single account
`circuitstitch`, permission set `JanitorSecretsRead`, region `us-west-2`):
browser PKCE sign-in → SSO token → `GetRoleCredentials` → `ListAccounts` (1) →
`ListAccountRoles` (1) → `ListSecrets` (8) → menu pick → `GetSecretValue` →
masked 20-entry matrix. Three design assumptions were **wrong** and are now
corrected in code (all in `janitor-aws`'s untested SDK/loopback shell):

1. **`issuerUrl` must be the Issuer URL, not the portal `…/start` URL.** The
   portal URL fails `RegisterClient` with `InvalidRequestException: "Invalid
   start url provided"`. The Issuer URL
   (`https://identitycenter.amazonaws.com/ssoins-…`) works. (Resolves the
   ADR 0010 §2a / this ADR open item — opposite of the original guess that they
   were interchangeable.)
2. **`authorizationEndpoint` comes back `null`.** "Read the endpoint from the
   response" is insufficient; `authorize_endpoint()` derives
   `https://oidc.<sso-region>.amazonaws.com/authorize` as the fallback. A null
   endpoint previously produced a malformed `?response_type=…` browser URL.
3. **The loopback redirect path must be exactly `/oauth/callback`.** Any other
   path (`/callback`, `/`, …) is rejected — confusingly — as
   `InvalidRedirectUriException: "Requested client type must use loopback
   interface for redirect"`. The port is *not* part of the constraint (port-less
   and port-bearing `/oauth/callback` both register OK; we register port-less per
   RFC 8252 §7.3 and add the bound port at authorize/token time). Verified by
   direct probing of the unauthenticated `RegisterClient` endpoint.

Confirmed-correct behaviors: single account and single role **auto-pick** with
no prompt; multiple secrets show the numbered menu; output discipline holds (only
the masked matrix prints, never a Value); the last pick is remembered. A real
`GetSecretValue` **AccessDenied** (`"Access to KMS is not allowed"` — the role
lacked `kms:Decrypt` on the secret's CMK) surfaced cleanly and **exited without a
retry loop** — adding `kms:Decrypt` fixed it (now documented in
[`docs/iam_setup.md`](../iam_setup.md)).

**Still open (deferred to a follow-up):** typed `GetSecretValue` error mapping —
AWS returns `AccessDenied` as an SDK **`Unhandled`** variant, so the fix must
read `ProvideErrorMetadata::code()`, not match a modeled variant or the
`discriminant`. The current mapping stays the scrubbed `Sdk { context }`
catch-all plus a stderr diagnostic. Also still untested live: token-expiry →
single re-Sign-in, an explicit `--secret-id` NotFound, and reading the real
`roleCredentials.expiration`.
