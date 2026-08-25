# Contributing

Thanks for your interest in Janitor. Contributions are welcome.

## Getting started

- **Build & test:** [docs/building.md](docs/building.md) — commands, Linux system
  deps, coverage gates.
- **Conventions & invariants:** [CLAUDE.md](CLAUDE.md) — how we work, plus the
  non-negotiable security invariants you must not break.
- **Domain glossary:** [CONTEXT.md](CONTEXT.md) — read this first so we share
  vocabulary (Secret Set, Entry, Value, Environment, …).
- **Past decisions:** [docs/adr/](docs/adr/) — hard-to-reverse choices, indexed
  in [docs/adr/README.md](docs/adr/README.md).

## Found a problem?

Open an issue on the [tracker](https://github.com/Circuit-Stitch/Janitor/issues).
Include what you did, what you expected, and what happened — a minimal repro
saves everyone time.

**Security:** Janitor handles secrets. If you find a vulnerability — anything
that could leak a Value, Credential, or token, or stomp a Secret Set — do **not**
open a public issue. Report it privately to
[security@circuitstitch.com](mailto:security@circuitstitch.com) and give us a
chance to fix it first. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for what
we defend against.

## Quality bar

This is a security tool, so the bar is deliberately high:

- **Test-driven.** We write the failing test first, then the code to pass it
  (red → green → refactor). New behavior arrives with the test that proves it;
  bug fixes arrive with the test that would have caught the bug.
- **Coverage is gated.** Every crate here holds a **≥80%** coverage gate in CI
  (`cargo llvm-cov`) except `janitor-app`, which is the worker's I/O loop and the
  AWS composition root. In practice the security-critical crates sit well above
  the gate. The shells live in their own repositories and carry no gate at all
  (ADR 0003, ADR 0036). All auth / AWS / compare / write logic lives in `core` and the Provider
  crates behind seams so it stays testable; only the thin browser / SDK / socket
  shells are untested, by design. PRs that drop coverage on a file they touch
  will be asked to add tests.
- **Never silently weaken a test.** If your change alters the behavior a test
  covers — different output, a skipped/deleted test, a narrowed assertion, an
  updated snapshot — call it out explicitly in the PR. "The new behavior is
  correct" still needs to be named, not buried in the diff.
- **Security is not negotiable.** The invariants in [CLAUDE.md](CLAUDE.md)
  (nothing secret on disk; never stomp a Secret Set; read-only by default;
  memory-only auth) are the spine of the project. A change that touches one of
  them isn't "small" — flag it loudly and expect close review.

## Pull requests

PRs are welcome. Before opening one:

- Run `cargo fmt`, `cargo clippy --all-targets`, and `cargo test --workspace`
  (see [docs/building.md](docs/building.md)). CI runs lint, test, and coverage.
- Keep the security invariants intact (nothing secret on disk; never stomp a
  Secret Set; read-only by default; memory-only auth — [CLAUDE.md](CLAUDE.md)).
- Hard-to-reverse or non-obvious design choices get an ADR; new domain terms go
  in `CONTEXT.md`.
- For anything sizeable, open an issue to discuss it first — it's no fun to write
  a big PR that goes a direction we can't merge.

## Ground rules

Be decent. Don't submit malicious code, anything that exfiltrates data, or
changes that weaken the security posture without saying so loudly. This is a
GPL-3.0 project ([LICENSE](LICENSE)); by contributing you agree your work is
licensed under the same terms.
