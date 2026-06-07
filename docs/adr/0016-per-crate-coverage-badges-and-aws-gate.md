# Per-crate coverage badges, and an AWS coverage gate

**Status:** accepted (supersedes the "line gate stays on core only" point of
[ADR 0010](0010-aws-adapter-crate-and-auth-object-model.md) §5 and the
coverage-lane description in [ADR 0007](0007-ci-and-distribution.md))

## Context

Coverage was computed in CI (`cargo llvm-cov --package janitor-core
--fail-under-lines 80`) but the number was *gated and then thrown away* — never
surfaced. We want it reported publicly. As an open-source, security-oriented
tool, transparency is a feature: we show the sausage-making, so a third-party
service that publishes the full report is acceptable rather than a leak.

When we measured, the picture differed from ADR 0010's framing. ADR 0010 §5
declared `janitor-aws` not line-gated because its browser/loopback/SDK *shell* is
"untestable without live AWS." But that shell is small: combined `core`+`aws`
line coverage is ~91%, and `janitor-aws` alone is ~91% once the two run-on-demand
`src/bin/` harnesses (`live-verify`, `loopback-spike`) are set aside. The
well-tested logic (broker, discovery, session, pkce, secrets, wire, select…)
dominates; the untestable shell does not drag the crate below 80%. So the
original reason to leave `aws` ungated no longer holds.

## Decision

- **Two per-crate coverage badges** in the README — `core coverage` and
  `aws coverage` — rendered by shields.io from Codecov-hosted data (so each badge
  carries a readable, crate-scoped label). `janitor-gui` is **excluded entirely**:
  it is a thin view with no secret logic (ADR 0003), so its uncovered glue is not
  a meaningful signal and would only mislead.

- **Both crates are line-gated at ≥80%, enforced in CI**, not by Codecov. Each
  crate runs `cargo llvm-cov … --fail-under-lines 80`; the build's red/green
  stays entirely inside the workflow with no runtime dependency on the third
  party. Codecov is **display-only** — pinned by `codecov.yml`
  (`project: off`, `patch: off`, `comment: false`) so it can never silently
  become a second gate. The gates work even before the Codecov app/token is set
  up; only the badges need the token.

- **The `aws` badge+gate measure the crate's *library* surface, not its
  harnesses.** `--ignore-filename-regex 'src/bin/'` drops `live-verify` and
  `loopback-spike` (run-on-demand test scripts, 0% by design, not shipped logic).
  The genuinely-untestable SDK **shell stays in** the number — so the gate still
  honestly covers the hard AWS boundary, and ~91% proves we tested thoroughly
  *around* it.

## Considered options

- **Self-hosted dynamic badge (shields endpoint JSON committed to the repo)** —
  avoids any third party beyond shields' renderer. Rejected: for an open-source
  project the report is already public, and Codecov's per-file drill-down *is* the
  transparency we want.
- **Codecov enforces the gate via status checks** — rejected: makes build
  pass/fail depend on an external service and a successful upload. The gate is a
  correctness artifact and must stay self-contained.
- **One workspace-wide badge** — rejected: a single number can't honor the
  asymmetry (proven core vs. shell-bearing aws vs. logic-free gui) and would be
  dragged down by code we deliberately don't test.
- **Include `src/bin/` in the `aws` number** — rejected: with `aws` now a *hard
  gate*, counting the 0%-by-design harnesses means every line added to
  `live-verify` pushes the crate toward the 80% cliff — a red CI for writing a
  debugging tool.

## Consequences

- ADR 0010 §5 and the `ci.yml` comment "the 80% line gate stays on core" no
  longer hold: `aws` is now gated too. The `aws` cushion above 80% (~11 points)
  is real but finite; large additions of untested shell could erode it, which is
  the intended pressure — long-term we want the shell covered by integration
  tests against a real AWS account (done for the shared auth base in
  [ADR 0027](0027-covering-the-shared-auth-shell-with-replay-and-live-tests.md)).
- A coverage regression in `aws` *library* code now fails CI, as it already does
  for `core`. A regression confined to the `src/bin/` harnesses does not.
