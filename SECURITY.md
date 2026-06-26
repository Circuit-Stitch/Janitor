# Security Policy

Janitor is an ephemeral client onto AWS secrets — it handles Values,
Credentials, and tokens. We take vulnerabilities seriously.

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Report privately, either way:

- Use GitHub's **"Report a vulnerability"** button on the
  [Security tab](https://github.com/Circuit-Stitch/Janitor/security/advisories/new)
  (private advisory), or
- Email **[security@circuitstitch.com](mailto:security@circuitstitch.com)**.

Please include what you did, what you expected, what happened, and a minimal
repro if you have one. We'll acknowledge your report, work on a fix, and credit
you (if you'd like) once it's resolved.

## What counts

Anything that could:

- leak a **Value**, **Credential**, or SSO/role token (to disk, logs, errors,
  `Debug`/`Display`, the clipboard, or the network),
- **stomp a Secret Set** — overwrite or drop Entries a write shouldn't touch, or
- defeat the read-only-by-default or memory-only-auth invariants.

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for the full posture, the trust
boundaries, and the explicit non-goals (e.g. Value length is an accepted
side-channel).

## Supported versions

This is pre-1.0 — only the latest release receives security fixes.
