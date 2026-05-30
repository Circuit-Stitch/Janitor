# Janitor — Threat Model

A short statement of what Janitor defends against, what it explicitly does not,
and the trust boundaries the design assumes. Consolidates the security posture
spread across [ADR 0001](adr/0001-non-stomping-writes-via-staged-put-and-cas.md)–
[ADR 0007](adr/0007-ci-and-distribution.md). See [CONTEXT.md](../CONTEXT.md)
for terminology.

## What Janitor is

A cross-platform desktop **viewer/editor onto AWS Secrets Manager**. It stores no
secrets and no credentials of its own; it borrows them on demand and forgets
them. Its core promise is **safety of mutation** — you cannot accidentally
overwrite a whole Secret Set while changing a few Entries — and **drift
visibility** across Environments.

## Assets

- **Values** — secret material fetched from AWS. Highest-value asset. Ephemeral,
  memory-only, zeroized; never written to disk.
- **Credentials / SSO token** — ephemeral AWS auth. Memory-only; never cached.
- **Config** — a *map of where secrets live* (accounts, regions, secret names,
  SSO URL). No Values. Written to disk as plaintext.

## Trust boundaries

1. **`janitor-core` (trusted)** — holds Values in zeroizing buffers, runs the
   safe-write engine, talks to AWS. The part we test to ≥80% and trust most.
2. **`janitor-gui` (softer zone)** — when a Value is revealed/edited, plaintext
   transiently lives in Slint widget state and, on copy, the OS clipboard.
   Cleared on blur/close/timeout; accepted as inherent to *displaying* a secret.
3. **The host OS / display surface (outside our control)** — framebuffer, GPU,
   screenshots, accessibility APIs, clipboard managers. Janitor cannot defend
   below this line (see non-goals).
4. **AWS (trusted dependency)** — Secrets Manager + Identity Center. Janitor
   relies on AWS's atomic stage CAS for its core safety guarantee.

## What Janitor defends against

- **Accidental whole-Set overwrite** — op-based edits + replay-on-fresh-fetch +
  atomic AWSCURRENT compare-and-swap (ADR 0001). Structurally cannot stomp.
- **Silent concurrent clobber** — a teammate's untouched Entries survive; true
  conflicts stop for human review, never auto-merge (ADR 0001). This is the loss a
  user would *never notice*, so restore can't cover it — the engine prevents it.
- **Recoverable mistakes** — version history + restore (ADR 0006) provide undo for
  bad writes the user *does* notice; restore rides the same ADR-0001 CAS rail.
- **Accidental mutation** — read-only by default; writing requires a deliberate,
  lockable mode switch (ADR 0001 / 0004).
- **Secrets at rest on the operator's machine** — nothing secret is persisted:
  no Values, no Credentials, no SSO-token cache (ADR 0002).
- **Long-lived AWS secrets on the machine** — no static access keys; Identity
  Center only (ADR 0002).
- **Casual shoulder/screen exposure** — masked-by-default matrix; plaintext only
  on momentary, explicit per-cell reveal (ADR 0003 / 0005).
- **Clipboard lingering** — copy auto-clears on a timeout (not on focus loss, so
  paste still works) and is excluded from history/sync where possible (ADR 0005).
- **Excess plaintext in memory / API cost** — manual-refresh-only read model; no
  background polling (ADR 0005).
- **Version-quota exhaustion / AWS limits** — enforced write-rate + retry caps +
  mandatory cleanup of staged versions (ADR 0001).
- **Tampered / spoofed downloads** — macOS bundles are Developer ID signed +
  notarized and Windows bundles are Authenticode signed, so users install cleanly
  and the artifact's origin is cryptographically verifiable (ADR 0007). Linux is
  unsigned (no platform gatekeeping). If a signing identity lapses, the release
  job fails loudly rather than shipping unsigned.

## Explicit non-goals (what Janitor does NOT defend against)

- **A compromised host.** Malware, a keylogger, root/admin on the operator's
  machine, or a debugger attached to the process can read Values from memory, the
  framebuffer, or the clipboard. Janitor is not a defense against an attacker who
  already controls the machine.
- **The display side-channel.** A revealed Value is, by definition, on screen —
  screenshots, screen recording, and accessibility APIs can capture it. This is
  why the no-string-glyph idea was rejected as theater (ADR 0003).
- **Value length leakage.** The masked matrix shows Value length and hash-equality
  grouping by design. Length is a deliberate, accepted side-channel — dwarfed by
  the fact that AWS itself retains and serves all versions for 24h to anyone with
  read access.
- **Config confidentiality.** Config is a plaintext recon map of *where* secrets
  live (not their Values). An attacker reading it learns secret names/locations,
  not secrets. Encrypting it was considered and deferred (ADR-pending if revisited).
- **AWS-side authorization.** Janitor enforces nothing AWS doesn't; least
  privilege is the IAM policy's job (v1 read path needs only
  `GetSecretValue` / `ListSecrets` / `DescribeSecret`).
- **Being a secret store or backup.** Janitor has no storage of record; AWS is the
  source of truth.

## Known limitations (decisions, not surprises)

- **Renamed-key drift.** Entries compare by exact Name. `GITHUB_TOKEN` in one
  Environment and `GITHUB_APP_TOKEN` in another show as two separate **Gaps**, not
  a rename. v1 accepts this.
- **GUI is a softer zone than core** (boundary 2 above): transient plaintext in
  widget/clipboard state is inherent to displaying a secret.
