# `janitor-aws` adapter crate, decomposed auth object model, and the headless Identity Center slice

**Status:** accepted

## Context

[ADR 0002](0002-identity-center-only-memory-only-auth.md) decided *what* Janitor's
authentication is (IAM Identity Center only, memory-only, Authorization Code +
PKCE primary, two token lifetimes with silent role-credential refresh). It did
not decide *where that code lives, how it is shaped into objects, or how it is
tested without live AWS and a human at a browser.* This ADR settles those, and
scopes the first implementation as a **headless vertical slice**.

The pressure that forces these choices:

- `janitor-core` carries a **≥80% coverage gate** and the "security-critical
  bedrock" label. Its `lib.rs` anticipated an "AWS-client trait, with the
  concrete AWS SDK adapter isolated." But a real Identity Center sign-in pulls in
  `tokio`, four AWS SDK crates, a browser launcher, and a loopback HTTP listener —
  a large surface that is **untestable without live AWS**. Putting that inside
  core would force an `llvm-cov` carve-out and erode the gate's honesty.
- The web flow itself was confirmed current (not stale relative to ADR 0002):
  `RegisterClient` takes `grantTypes` incl. `authorization_code`,
  `clientType: "public"`, and client-defined `redirectUris`; **PKCE has been the
  AWS CLI default since v2.22.0**. So we implement ADR 0002 as written.
- This project forbids silent test regressions and "implied" coverage. The auth
  refresh/error state machine is exactly the kind of logic that fails silently,
  so it must be reachable by CI tests — which constrains the object model.

## Decision

### 1. A third workspace crate, `janitor-aws` — async-native

The AWS adapter is a **sibling crate**, not a module in core. It depends on
`janitor-core` for domain types (`Mapping`, `SecretShape`, `Value`) and adds
`tokio` + `aws-config` + `aws-sdk-ssooidc` + `aws-sdk-sso` +
`aws-sdk-secretsmanager` + a browser launcher + a loopback listener. It is
**async-native** and exposes its own async API.

Consequence: `janitor-core` is **untouched** by this slice — its sync
`SecretSource` + `MockSource` and all existing tests stand, so the coverage gate
stays honest and there is zero regression risk to the GUI/compare path. The
sync→async flip of `SecretSource` and the async↔Slint threading remain deferred
to the GUI integration slice, exactly as the tracer-bullet spec planned.

### 2. Headless vertical scope

The deliverable is a runnable thread through the real architecture, with the
**smallest blast radius**:

```
browser PKCE Sign-in → SSO token (memory)
  → GetRoleCredentials for ONE Environment (memory)
    → ONE real GetSecretValue
      → parse to SecretShape (core)
        → print masked summary
```

The GUI, `MockSource`, real `Config` persistence, and the write path are **out**.
The entry point is a trivial `main()` that calls the facade below; it holds **no
logic**.

**Output discipline.** The "masked summary" the harness prints comes **only** from
core's existing masked projection (`project()` → `MatrixView`: lengths, group
ids, masked tokens). The harness **never** formats a `Value` or a `SecretShape`
directly, and never `{:?}`-prints an error that may carry a response body. This
keeps "the GUI is the only place plaintext ever surfaces" true even for this
throwaway binary — the one place in the slice where a real Value is in hand.

### 2a. Build order — spike the loopback round-trip first

The fiddliest, **untested** code in the slice is the async browser→loopback hop:
open the browser, block on a one-shot loopback HTTP server for a single
`?code=&state=` request, with a timeout and clean listener shutdown. Mirroring
the GUI slice's "open a blank window first" step-0, the **first implementation
step is a standalone spike** that proves browser-open → loopback-catch →
code-extraction works on Windows against a *hardcoded fake* `/authorize` URL —
**before any SDK wiring**. This flushes the real integration risk early, exactly
what a tracer bullet is for.

**In parallel, probe the real `RegisterClient` / `/authorize` parameter contract
early.** The loopback spike proves the *shell* against a fake endpoint, but the
thing most likely to surprise is the *real* IdC parameter reality: which `scopes`
are required at `RegisterClient` vs `/authorize`, whether `issuerUrl` is
mandatory, and the exact `redirect_uri` match rule. Make one real
`RegisterClient` call plus a *manual* paste-the-`/authorize`-URL round-trip
**before the facade hardens around guesses** — discovering this late forces a
re-shape of the `Authenticator` trait. This is the early-resolution half of the
verify list below, not a post-hoc check.

### 3. Decomposed objects + a thin **tested** composing facade

Three single-purpose objects, each behind narrow traits:

- **`Authenticator`** — `sign_in()` runs `RegisterClient` + the browser PKCE hop +
  `CreateToken`; returns a zeroizing `SsoToken` **by value**.
- **`CredentialBroker`** — constructed from the `SsoToken` (owns it); caches one
  `Credential` per Environment; `credentials_for(&Mapping)` returns a
  currently-valid Credential, silently re-minting via `GetRoleCredentials` when
  near expiry. **No browser.**
- **`SecretsClient`** — dumb `GetSecretValue` → `SecretShape`; holds no auth state.
  Maps the SDK response by field: a `SecretString` becomes `SecretShape::Json`
  (if it parses as a JSON object) or `SecretShape::Raw`; a `SecretBinary`
  response becomes `SecretShape::Binary` (len/hash only, **never** decoded to text
  — ADR 0004). Both cases flow through the masked print unchanged; the mapping is
  the first thing the implementer must get right, so it is named here.

**Why three objects for a one-secret slice (against YAGNI).** A single stateful
`AwsSecretSource` would ship *this* slice faster. The decomposition is priced in
now because the GUI integration slice needs concurrent **N-Environment**
brokering (one shared broker, deduped re-mints — the reason `credentials_for`
takes `&self`), and retrofitting these seams later would churn the very trait
surface the fakes pin. We pay the four-type cost once, here, rather than
re-shaping tested code later.

Because three objects give testable *parts* but nothing tests their
*composition* — and the composition (re-mint, re-auth, error classification) is
**itself the security-critical logic** — a thin **`AuthenticatedSource` facade**
in `janitor-aws` composes them and owns the orchestration. The facade is
**unit-tested with fakes**; the `main()` harness is throwaway and holds none of
this logic.

**`credentials_for` takes `&self`, not `&mut self`** — the per-Environment cache
lives behind interior mutability (an async-aware lock). The headless slice fetches
one Environment, so there is no contention to manage *yet*; but the trait surface
outlives the slice, and a future GUI that fetches N Environments concurrently must
be able to share one broker and dedupe concurrent re-mints for the same
Environment. Freezing `&self` now makes that a non-breaking future addition rather
than a trait-signature break.

**"Session" is a domain concept, not a type.** CONTEXT.md's `Session` (the
authenticated lifetime from Sign-in to SSO-token expiry) is **not** a struct in
`janitor-aws`. It is realized by the `SsoToken`'s in-memory lifetime inside the
`CredentialBroker`: the Session begins when `sign_in()` yields the token, lasts as
long as that token drives `GetRoleCredentials`, and ends when the token dies and
the broker is rebuilt. A reader grepping for `struct Session` will (correctly)
find nothing.

### 4. The orchestration contract (the load-bearing part)

`AuthenticatedSource::fetch(&Mapping)` runs **one chained escalation**, not two
independent branches — because a dead SSO token can surface either at the broker
(when it re-mints) *or* at `GetSecretValue` (when the broker handed out a cached,
not-yet-expired Credential whose underlying SSO token has since died). The chain
collapses both into one path:

1. `credentials_for(&mapping)` → `GetSecretValue`. On success, done.
2. **On an auth-class `GetSecretValue` failure**, force-refresh the broker's
   Credential for that Mapping **exactly once**, then retry the `GetSecretValue`.
   - If the forced `GetRoleCredentials` *succeeds* and the retry still auth-fails
     → classify **`AccessDenied`** (genuine policy denial; no further retry).
   - If the forced `GetRoleCredentials` *itself* raises `ReauthRequired` (the SSO
     token is dead — this is the cached-creds-outlived-the-token case) → go to 3.
3. **`ReauthRequired`** (raised by the broker, whether on a near-expiry re-mint in
   step 1 or the forced refresh in step 2): re-run `sign_in()` **exactly once**,
   build a **fresh** broker (the old broker drops → its `SsoToken` is zeroized
   once), then retry from step 1. If `GetRoleCredentials` still throws
   `UnauthorizedException` after the fresh Sign-in → classify **fatal** (no
   infinite browser loop).

So `ReauthRequired` is a *signal the broker raises*, but the **secrets-client auth
failure is what triggers the broker refresh that exposes it** — the facade owns
this chaining; neither object sees the whole loop. Each escalation (re-mint,
re-Sign-in) happens **at most once** per `fetch`.

**On discrimination (stated honestly):** we likely *cannot* tell a stale-credential
rejection from a genuine policy denial at the `GetSecretValue` layer — Secrets
Manager returns `AccessDeniedException` for both. So step 2 force-refreshes **once
unconditionally** on any auth-class failure and accepts **one wasted re-mint** on a
true policy denial before classifying `AccessDenied`. This is correct, just not
free; the verify list confirms the real error shapes.

Two distinct refreshes, never conflated:

- **Role-credential staleness** (common, ~1–12h) → silent `GetRoleCredentials`,
  **no browser** (ADR 0002).
- **SSO-token expiry** (the *only* browser trigger) → one re-Sign-in.

The broker takes an **injectable clock** and a named **refresh skew** (re-mint
when `expiration - now < 60s`), so expiry behavior is testable without sleeping
and the trait surface is frozen with the clock already in it.

### 5. Test strategy — wrap the SDK behind narrow traits

Each SDK operation we use sits behind a small `janitor-aws` trait
(`register_client` + `create_token`, `get_role_credentials`, `get_secret_value`).
Real impls wrap the SDK; **fakes** drive unit tests for the facade's
orchestration, the broker's caching + near-expiry re-mint, token-expiry →
re-Sign-in, error classification, and `SecretShape` parsing. The **only**
untested code is the browser-open + loopback-listener shell.

Live verification is a **consciously-invoked `live-verify` binary**
(`cargo run -p janitor-aws --bin live-verify`) that drives the real org and prints
a checklist of the error paths to force (happy path, token-expiry → re-Sign-in,
access-denied, throttle) — **not** an `#[ignore]`d test. An ignored test is
invisible: it doesn't show as skipped in normal runs and silently stops being run
once the slice ships. A binary you must deliberately invoke ages better, and it
*is* the "trivial `main()`" harness §2 already calls for.

**The fakes are load-bearing.** This slice's refresh/error correctness is
verified *only against fakes that encode our assumptions about AWS error and
expiry semantics* until the `live-verify` binary is run against the real org. The
"verify against the live API" items below are what confirm those assumptions; a
green CI alone proves only that the code matches our guesses.

### 6. PKCE + CSRF state as first-class tested pure functions

The security-load-bearing crypto is pure free functions, unit-tested directly:
PKCE verifier generation, `S256` `code_challenge`, base64url-no-pad (against
RFC 7636 known-answer vectors); and the CSRF `state` nonce with a
**state-mismatch-is-rejected** test. The browser/listener shell merely calls
them.

### 7. Loopback redirect

`RegisterClient` registers a small fixed set of `http://127.0.0.1:PORT` redirect
URIs (a primary + 2–3 alternates, as the AWS CLI / rclone do); at Sign-in, Janitor
binds the first free one **from that registered set** — never an OS-assigned
ephemeral `:0`, because the `redirect_uri` sent to `/authorize` and `CreateToken`
must *exactly match* a registered URI. **`127.0.0.1` literally** (not `localhost`,
to avoid the IPv6 `::1` mismatch). The ordering is load-bearing: **bind a specific
registered port → learn which one bound → build the `/authorize` URL with that
exact `redirect_uri` → open the browser.** The listener returns a tiny "you can
close this tab" page.

### 8. Memory-only, including the client registration

`RegisterClient` is re-run **in memory on each launch**; nothing is cached to
disk. This *extends* ADR 0002's memory-only stance (which already excludes the
SSO token and role Credentials) to the client registration too, for the cost of
one extra unauthenticated call per launch. **Config remains the only file Janitor
writes** — the THREAT-MODEL invariant is untouched, so no amendment there.

### 9. Error taxonomy

Two enums: `SignInError` (browser-launch failed, listener timeout, state/CSRF
mismatch, token-endpoint, network) for `sign_in()`; and a fetch/session error
with `ReauthRequired`, `AccessDenied`, `NotFound`, `Throttled`/`Transient`,
`Unsupported` (e.g. binary, never revealable — ADR 0004), and a **scrubbed**
`Sdk` catch-all that must not leak secret material into `Debug`/`Display`.

`Throttled`/`Transient` must be **reachable, not a forward-compat placeholder**:
the SDK-wrap layer **produces** it (mapping a retry-exhausted throttle / timeout
`SdkError`) and the facade **propagates** it to the caller — with a fake-driven
test asserting that round-trip. What it deliberately lacks is a *retry handler*
this slice (the SDK already retries throttles internally; a Janitor-level backoff
arrives with the write path). An enum variant that no code path produces or
consumes would read as dead code and imply coverage that doesn't exist — exactly
the anti-silent-coverage smell this project rejects — so we make it producible and
tested rather than carrying it unreachable.

### 10. Deliberately bypass AWS's default credential chain (an explicit "no")

`janitor-aws` lists `aws-config`, but it must **not** use the default credential
provider chain. That chain reads `~/.aws/{config,credentials}`, `AWS_*` env vars,
and IMDS — any of which could silently supply ambient static credentials and
quietly violate the "Identity Center only, no static keys" invariant (ADR 0002).
So:

- The `ssooidc` / `sso` clients for the **unauthenticated** calls
  (`RegisterClient`, `CreateToken`, `GetRoleCredentials`) are built with an
  explicit `Region` and **no credential provider** (`no_credentials()` /
  anonymous) — these calls are authorized by the SSO token in the request body,
  not by SigV4 ambient creds.
- The `secretsmanager` client is built with the **per-Environment `Credential`
  Janitor minted**, injected explicitly — never the default chain.

This is an "explicit no" worth recording precisely because the obvious path
(`aws_config::load_from_env()`) would *appear* to work while undermining the
project's central guarantee. The ADR-format note that the no-s are as valuable as
the yes-s applies here.

## Considered options

- **AWS code as an isolated module in `janitor-core`** (the literal `lib.rs`
  wording). Rejected: drags heavy untestable deps into the gated bedrock crate
  and forces a coverage carve-out — the kind of exception this project avoids.
- **One stateful `AwsSecretSource`** that lazily signs in on first fetch.
  Rejected: fuses Sign-in into fetch (a split CONTEXT.md deliberately makes),
  buries the browser launch in the data source, and makes "please re-Sign-in"
  awkward to surface.
- **Bare three objects, composition in the harness.** Rejected: the composition
  *is* the security logic; leaving it in throwaway harness code ships it
  untested, contradicting the wrap-for-test choice.
- **Disk-cache the `RegisterClient` registration like the AWS CLI.** Rejected:
  introduces a second Janitor-written file, eroding "Config is the only file on
  disk," for one sub-second startup call — and unlike the CLI's per-command
  processes, Janitor is long-running, so in-memory reuse already captures the
  benefit.
- **Device Authorization grant as the primary flow.** Rejected for this slice:
  ADR 0002 named Auth Code + PKCE primary and device-grant a later fallback;
  choosing it now would reverse that ordering and change the UX.

## Definition of done — two milestones, not one

A real IAM Identity Center org is available, so live verification is **in scope**,
but it is **human-gated** and must not hold a mergeable branch hostage. Split it:

- **Milestone A — code-complete (mergeable).** All tested-against-fakes logic is
  green in CI; the `live-verify` binary builds and runs end to end against the
  real org's *happy path* at least once by hand. This is a normal PR and merges.
- **Milestone B — live-verified (follow-up gate).** A human has driven the forced
  error paths via `live-verify` (token-expiry → re-Sign-in, access-denied,
  throttle) and **resolved every item in the verify list below**, correcting the
  fakes wherever observed AWS behavior diverged. Until B is closed, the path is
  "correct per our assumptions, pending live confirmation" — not to be relied on
  by the GUI slice.

Splitting them keeps Milestone A from sitting unmergeable behind a manual step,
while keeping B an explicit, named gate rather than a check that quietly rots.

## To verify against the live API before relying on this path

- **`GetRoleCredentials` `UnauthorizedException` is overloaded.** It fires both
  when the SSO token is dead (→ `ReauthRequired`, correct) **and** when the token
  is valid but the user is not entitled to that account/permission-set (→ should
  be `AccessDenied`, fatal for that Mapping). Confirm whether the SDK error shape
  separates these. Until confirmed, the at-most-once re-Sign-in cap (§4) is what
  prevents a misconfigured Mapping from looping the browser forever.
- **Auth-class `GetSecretValue` error shape.** Confirm whether a genuinely-denied
  secret (`AccessDeniedException` from IAM policy) is *distinguishable* from a
  stale-credential rejection. §4 currently assumes it is **not** and force-refreshes
  once unconditionally; confirm that, and also confirm `ResourceNotFoundException`
  vs an auth failure so `NotFound` is classified separately from `AccessDenied`.
- **Loopback URI acceptance + match rule.** Confirm Identity Center accepts
  multiple `http://127.0.0.1:PORT` redirect URIs and the exact-match rule it
  applies at `/authorize` and `CreateToken`.
- **Never hardcode 1h** (carried from ADR 0002): read the actual
  `roleCredentials.expiration` returned by `GetRoleCredentials`; the broker's
  skew math depends on it.

## Consequences

- `janitor-core` is unchanged; its coverage gate and existing tests are
  unaffected. New tested logic lands in `janitor-aws`.
- The only untested code is the browser/loopback shell and the SDK-wrapping
  trait impls; everything that can fail silently (refresh, re-auth,
  classification, parsing) is under CI against fakes, with the human-run
  `live-verify` binary (§5) as the backstop.
- The workspace gains `tokio` and the AWS SDK at the `janitor-aws` boundary only;
  the GUI and core stay free of them until the integration slice.
- A future ADR formalizes the `SecretSource` sync→async flip and the async↔Slint
  threading when the GUI consumes this crate.
- **Secret material transits the AWS SDK's non-zeroizing buffers first.**
  `CreateTokenOutput` and `GetRoleCredentialsOutput` hold the access token / secret
  access key as plain `String`s that the SDK heap-allocated before Janitor can wrap
  them in zeroizing types. We cannot zeroize what the SDK already allocated, so a
  copy of each secret briefly lives in a buffer we do not control. This is an
  **accepted limitation**, below our trust boundary in the same sense as the
  framebuffer and clipboard (THREAT-MODEL §3): Janitor zeroizes *its own* copies
  and never persists any, but the SDK's transient `String` is the AWS dependency's
  to manage. Named here because the project's memory-only stance is strict enough
  that this gap should be explicit, not discovered later.
