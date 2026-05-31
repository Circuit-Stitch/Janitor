# Identity-Center-only, memory-only authentication

**Status:** accepted — implemented by [ADR 0010](0010-aws-adapter-crate-and-auth-object-model.md) (crate, object model, headless slice)

## Context

Janitor must let a user authenticate to AWS via a web browser, hold nothing
sensitive on disk, and reach Secret Sets that may live in different AWS accounts
and regions. AWS offers browser-based sign-in through IAM Identity Center
(formerly AWS SSO), which yields short-lived credentials and no long-lived secret
on the machine. The alternative — static IAM access keys — is not browser-based
and leaves a long-lived secret at rest, contradicting Janitor's reason to exist.

Assumption: the org reaches AWS through IAM Identity Center (which may itself
front any upstream IdP — Okta, Entra, Google — transparently to Janitor). If an
org uses raw SAML federation with no Identity Center, this decision must be
revisited.

## Decision

- **IAM Identity Center is the only auth path. No static-access-key path** —
  a deliberate "no", so that no long-lived AWS secret ever touches the machine.
- **Authorization Code + PKCE with a `localhost` redirect** is the primary flow
  (browser opens, user approves, browser redirects to a port Janitor listens on
  — no code copy-paste). Device Authorization grant may be added later as a
  fallback for environments where binding a localhost port isn't possible.
- **Memory-only, re-auth every launch.** Janitor does **not** cache the SSO token
  or any derived credentials on disk — stricter than the AWS CLI, which caches
  the SSO token for hours. Opening Janitor always requires a fresh browser
  Sign-in.
- **Two distinct lifetimes; only one needs the browser.** The SSO **access
  token** (typically ~8h) is obtained by the browser Sign-in. Per-Environment
  **role Credentials** from `GetRoleCredentials` are short-lived — duration is the
  permission set's configured session length (1–12h), so Janitor must read the
  actual `roleCredentials.expiration` returned by AWS and **never hardcode 1h**.
  These Credentials lapse mid-session; Janitor **silently refreshes** them from
  the still-valid in-memory SSO token — **no browser** — when they near expiry. A
  browser re-auth is required **only** when the SSO token itself expires. This is
  the difference between a usable tool and one that throws a browser at you every
  hour.
- **One sign-in, N Credentials.** A single SSO Sign-in is exchanged via
  `GetRoleCredentials` into one short-lived Credential per Environment
  (account + permission set). Each Environment's Secrets Manager client targets
  that Environment's **region**.

## Consequences

- No long-lived secret and no credential cache at rest: the worst case for a
  stolen laptop is whatever is in live process memory, only while Janitor runs.
- Worse convenience than the AWS CLI: a browser sign-in on every launch, and
  again whenever the SSO token expires during a session. Accepted as the price of
  the memory-only stance.
- Janitor is coupled to Identity Center's OIDC endpoints and the
  `sso`/`sso-oidc` APIs; orgs without Identity Center are unsupported in v1.
