# Covering the shared auth shell: replay/local CI tests + an env-gated live-AWS suite

**Status:** accepted

**Supersedes** the "the only untested code is the browser/loopback/SDK shell"
framing of [ADR 0010](0010-aws-adapter-crate-and-auth-object-model.md) §5 and
fulfils the "future ADR … cover the shell by integration tests against a real AWS
account" promised by [ADR 0016](0016-per-crate-coverage-badges-and-aws-gate.md)
(Consequences) and named as the #61 blocker in
[ADR 0024](0024-shared-aws-auth-base-crate.md) (implementation note 4).

## Context

The `janitor-aws-auth` split (ADR 0024) concentrated the three "untested by
design" shell files — `loopback`, `authenticator`, `aws_impl` (the browser/socket
I/O + the real AWS SDK calls) — into one crate, dropping it to **76.3% lines** and
holding the ≥80% per-crate gate RED. The owner's standing decision (ADR 0024 note
4, ADR 0016) is to **keep the gate and close the gap with real tests, never by
weakening the threshold or excluding the shell.**

ADR 0010 §5 declared this shell untestable without "live AWS and a human at a
browser," and routed live verification to a deliberately-invoked binary
(`live-verify`) rather than an `#[ignore]`d test, because an ignored test is
*invisible* — it neither shows as skipped nor keeps being run once the slice
ships. That reasoning still holds for **truly** live verification. But it
conflated two things the measured gap forces us to separate:

1. **Does the shell code execute correctly** (the socket round-trip parses; the
   SDK-wrap maps each response/error shape into our taxonomy)? — answerable
   *without* live AWS by exercising the real shell against canned transport.
2. **Do our canned shapes match what AWS really returns** (the ADR 0010 §5 verify
   list: `issuerUrl` acceptance, the overloaded `UnauthorizedException`,
   `AccessDenied` vs `NotFound`, the real `expiration`)? — answerable *only*
   against the real org.

ADR 0010 §5 only ever addressed (2). The shell lines are uncovered because nobody
had written tests for (1) — not because (1) needs live AWS. The dependency tree
already carries `aws-smithy-http-client`'s `StaticReplayClient` (a canned-HTTP
transport that drops into the SDK config exactly where a real connector goes), and
the loopback listener can be driven by a local `TcpStream` from the test itself.

## Decision

Cover the shell in **two layers**, each answering one of the questions above:

### Layer 1 — replay/local tests that run in CI and turn the gate green

These execute the **real shell code** against canned transport; no AWS, no
browser, no human. They run in the normal `cargo test` / coverage lane.

- **`loopback`** — a local-socket integration test binds via `bind_first_free`,
  then the test itself connects and writes a raw `GET /oauth/callback?code=…&state=…`
  request; asserts `wait_for_redirect` returns the query and writes the
  "close this tab" page. Plus timeout (no client connects → `ListenerTimeout`) and
  malformed-request paths. Real `tokio` socket I/O, deterministic.

- **`aws_impl`** — drive the real `ssooidc`/`sso` SDK clients against
  `StaticReplayClient` with canned success bodies **and** the exact ADR 0010 §5
  verify-list error shapes (`UnauthorizedException`, `ForbiddenException`,
  `ResourceNotFoundException`, throttle), asserting `register_client`,
  `create_token`, `get_role_credentials`, and `list_accounts`/`list_account_roles`
  pagination map correctly — through the **real `SdkError` → `map_aws_err`** path,
  not a synthetic code string.

- **`authenticator`** — drive `sign_in_once` end-to-end against a fake `OidcClient`
  and a **fake browser-opener** (the minimal seam below) that echoes the CSRF
  `state` back through the loopback, asserting the happy path, state-mismatch, and
  missing-code branches.

### Layer 2 — an env-gated live-AWS suite that confirms the canned shapes

`janitor-aws-auth/tests/live_aws.rs` holds `#[tokio::test]`s **gated on
`JANITOR_LIVE_AWS=1`** (org config from `JANITOR_LIVE_SSO_START_URL` /
`…_SSO_REGION` / `…_SECRET_REGION`, falling back to `Config`). Unset (the CI/normal
case), each test prints a one-line skip notice and returns; set, it drives the
**real** browser Sign-in + `GetRoleCredentials` + account/role enumeration and
**asserts** the verify-list items (registration accepted with the start URL as
`issuerUrl`; `expiration` read from the response, never a hard-coded 1h; at least
one account/role enumerated). It is the assertion-bearing successor to the
`live-verify` checklist.

**Env-gate, not `#[ignore]`.** ADR 0010 §5 rejected `#[ignore]` because it is
invisible. An env-gated test is *not*: it appears in every `cargo test` run and
prints why it skipped, and is flipped on by an env var rather than a `--ignored`
flag a future reader must know to pass. This keeps §5's spirit (no invisible,
silently-rotting tests) while making the live check a *test* the task asked for,
co-located with the code it verifies, rather than a separate binary.

### The minimal production seams (owner-approved, "minimal seams everywhere")

Layer 1 needs two narrow seams, both the same "wrap I/O behind a substitutable
boundary" pattern ADR 0010 §5 already uses for every other SDK op:

- **`Authenticator` takes an injectable browser-opener** (a `BrowserOpener` trait;
  real impl `OsBrowser` wraps `open::that`). `Authenticator::new` keeps its
  signature and defaults to `OsBrowser`; a test-only `with_opener` injects a fake.
  `sign_in_once` no longer calls the free `open_browser` directly.

- **`AwsOidcClient` / `AwsRoleClient` gain `with_http_client` constructors**, gated
  `#[cfg(any(test, feature = "test-support"))]`, identical to `new` **plus**
  `.http_client(replay)` and `.retry_config(RetryConfig::disabled())` (so a single
  canned error event isn't consumed by the SDK's internal throttle retries). No
  public/default build sees them.

## Considered options

- **Leave the shell uncovered; weaken or carve out the gate.** Rejected by the
  owner's standing decision (ADR 0024 note 4, ADR 0016) — the gate stays at 80%
  and the shell stays *in* the number.
- **Live-AWS tests only (no replay layer).** Rejected: they cannot run in CI (the
  Sign-in needs a human at a browser), so the gate would stay RED forever — #61
  unblocked in name only. They answer question (2), never (1).
- **Replay layer only (no live suite).** Tempting — it greens the gate — but the
  task explicitly asked for *live-AWS* tests, and the verify list (question 2) is
  real outstanding risk the replay fakes cannot retire. We keep both.
- **Keep live verification as the `live-verify` binary, add only the replay
  layer.** Rejected as the *primary* answer for the same reason: the owner asked
  for assertions against the real org. `live-verify` stays as the human-guided
  discovery/round-trip tool; the live *suite* adds the assertions.
- **Mock at the SDK-output layer (hand-built `RegisterClientOutput`, …) instead of
  the HTTP transport.** Rejected: it skips the (de)serialization + `SdkError`
  classification that is the actual untested shell; `StaticReplayClient` exercises
  the real wire path, so the test proves the code AWS will run.

## Consequences

- `janitor-aws-auth` crosses the ≥80% line gate in CI with the shell **in** the
  number; the ADR 0016 / ci.yml "expected RED until those integration tests land"
  note is retired and #61's coverage blocker is closed.
- The crate gains dev-dependencies (`aws-smithy-http-client` `test-util`, `http`)
  and two narrow test seams. Security posture is unchanged: nothing new is
  persisted, the seams add no default behavior, and the fake opener / replay
  transport are never compiled into a normal build.
- The ADR 0010 §5 verify list moves from a manual checklist to **asserted** in
  Layer 2; running it against the real org is what finally closes Milestone B.
- The `live-verify` binary is unchanged — it remains the human-guided
  guided-sign-in/discovery harness (ADR 0011); Layer 2 is the automated,
  assertion-bearing complement, not its replacement.
