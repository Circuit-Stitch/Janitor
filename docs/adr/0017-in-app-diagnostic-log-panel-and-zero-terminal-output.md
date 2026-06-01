# In-app diagnostic log panel as the sole output surface — zero stdout/stderr/file

**Status:** accepted

## Context

When a real-AWS load fails, the GUI shows a masked banner ("AWS error") and the
matrix's "Could not load." pane. The masked phrase comes from the tested
`FetchFailReason::describe()` / `Reason::describe()` seams — there is, by design,
**no way for the operator to see *why*** a fetch failed. Worse, the two error
mappers were asymmetric: `map_secret_err` printed the real SDK error to **stderr**
(`eprintln!`), while `map_role_err` threw everything away but a `std::mem::discriminant`
— so a failure at the `GetRoleCredentials` step (the likely case for a misassigned
permission set) produced a masked "AWS error" with **no detail anywhere**, on
screen or on the terminal.

The masking was attributed to THREAT-MODEL, but that conflates two different
things. The protected asset is the secret **Value** (plus the SSO token and minted
**Credentials**) — and an AWS *error* response can never carry any of those: a
Value appears only in a `GetSecretValue` **success** body, and minted credentials
only in a `GetRoleCredentials` **success** body. An error response carries an
error code, a human message, an ARN, and the calling principal — i.e. *locations
and identity*, which THREAT-MODEL already classes as non-secret ("Config is a
plaintext recon map of *where* secrets live"). So the `describe()` masking on
error paths was never a secret-leak control; it was UI hygiene / defense-in-depth
([ADR 0003](0003-core-gui-split-slint-and-secret-display.md)'s "GUI is a softer
zone"). There is no security reason a diagnostic surface can't show the real
error — and a strong usability reason it should.

Separately, the project owner wants the process to be **silent on the terminal**:
no stdout, no stderr, and no log file. The reasoning is about the **channel**, not
just the content: stdout, stderr, a pipe, a shared TTY, and a log file on disk are
all observable by *other processes on the same host* — a sibling process, say —
**without** compromising the machine. Even the "fair-game" non-secret metadata
(which Secret Sets and accounts exist, timing, error patterns) is reconnaissance
signal, and **any signal is some signal a bad actor could use**. So we deny the
cross-process channel entirely. The in-app panel lives in **process memory**,
which another process cannot read without `ptrace`/root — and a compromised host
is already an explicit THREAT-MODEL non-goal. The only sanctioned ways to learn
what the app is doing are the **in-app log panel** and an attached **debugger**.

## Decision

### The redaction boundary (the load-bearing rule)

Secret material — **Values, minted Credentials, and the SSO token** — never goes
near a log line, the panel, or any file, in the first place. These appear only on
*success* paths and are held in zeroizing, non-`Debug`-exposing types
(`expose()` is required to read them). The rule for call-sites is therefore
simply: **never pass `expose()` output to a log.** As a consequence, *everything
that reaches the diagnostic stream is, by construction, 100% fair game* — AWS
error bodies verbatim (code, message, ARN, principal), and success **metadata**
(account/role/secret id, credential expiry, Entry **count**, string-vs-binary).
Entry **Names** (incl. dotted-path Names) and Value **length** are loggable
(they are locations, not Values, per THREAT-MODEL), though length is omitted by
default to keep lines clean.

### One sink: an in-app, memory-only Diagnostic Log

- **Zero terminal output, zero files.** The shipped GUI emits nothing to stdout
  or stderr and writes nothing to disk but `Config` (the existing
  [ADR 0002](0002-identity-center-auth-and-ephemeral-credentials.md) invariant is
  preserved unchanged — no second persisted artifact). No `eprintln!`, no stderr
  `tracing` layer, no log file, no `RUST_LOG`-to-terminal. The two human-gated CLI
  bins (`live-verify`, `loopback-spike`) are exempt — they are interactive dev
  harnesses a developer runs deliberately, not the product.
- **Panics are silenced, not surfaced.** Rust's default panic hook prints to
  stderr — itself a cross-process channel we are denying — so we replace it with a
  **no-op hook** that suppresses that output. The panic is *not* routed to the
  panel and carries no detail; the process just unwinds quietly. Diagnosing a
  panic is a developer-with-a-debugger task (a debugger breaks at the unwind point
  regardless of the hook), not something the product surfaces. (Considered and
  rejected: routing panics into the panel — machinery for an exceptional path the
  target user can't act on; and leaving the default hook — it reopens the stderr
  channel.)
- **`tracing` is the seam.** `janitor-aws` / `janitor-core` emit structured
  `tracing` events at `info`/`warn`/`error` (replacing the ad-hoc `eprintln!`s).
  The GUI installs a subscriber with **a single custom layer** that formats each
  event into a bounded in-memory ring buffer (~1000 lines, oldest dropped) — and
  **no** `fmt`/stderr layer. The library crates stay ignorant of the GUI.
- **Lean, not chatty.** One line per real boundary crossing (Sign-in, each AWS
  call + its ok/fail, app loaded with Entry count). No per-cache-hit / per-step
  firehose — chattiness costs latency and buries signal.
- **Panel UX.** A collapsible panel renders the stream newest-last with a
  **level dropdown** (Info / Warn / Error) that filters the *view* (capture is
  unconditional), plus **Clear** and **Copy-all**.

### Real error detail reaches the banner too

The whole-app error banner shows the **real** detail, not just the masked phrase:
the classified `FetchFailReason` is kept for control flow (a dead token still
routes to re-Sign-in) and as a fallback label, but the AWS error's actual
`code: message` is carried through and displayed. `describe()`'s tested phrases
remain as the classification labels / fallback.

## Consequences

- A future contributor who adds an `eprintln!`, a stderr `tracing` layer, or a log
  file is contradicting this ADR — the panel is the only sink.
- The redaction boundary is a *call-site discipline*, not a structural guarantee
  on the log itself. It holds because secret material is structurally hard to
  emit (zeroizing, `expose()`-gated); reviewers should still treat any new
  `expose()`-near-a-log as a red flag.
- Error classification in `aws_impl` is now meaningful (token-dead →
  `ReauthRequired`, denial → `AccessDenied`, etc.) rather than an opaque
  discriminant, closing the `GetRoleCredentials` blind spot.
