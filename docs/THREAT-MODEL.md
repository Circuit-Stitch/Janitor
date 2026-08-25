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

- **Values** — secret material fetched from AWS, whether from Secrets Manager or
  read as a remote `.env` off an Instance over SSM. Highest-value asset.
  Ephemeral, memory-only, zeroized; never written to disk on the operator's
  machine.
- **Credentials / SSO token** — ephemeral AWS auth. Memory-only; never cached.
- **Config** — a *map of where secrets live* (accounts, regions, secret names,
  SSO URL). No Values. Written to disk as plaintext.

## Trust boundaries

1. **`janitor-core` (trusted)** — holds Values in zeroizing buffers, runs the
   safe-write engine, talks to AWS. The part we test to ≥80% and trust most.
2. **The shells (softer zone)** — when a Value is revealed/edited, plaintext
   transiently lives in widget state and, on copy, the OS clipboard. Accepted as
   inherent to *displaying* a secret. This applies to both: the Slint shell in
   `Circuit-Stitch/Janitor-slint` and the SwiftUI shell in
   `Circuit-Stitch/Janitor-macos` (ADR 0036). Neither carries secret logic, so the
   boundary is the same shape in each. **How long the plaintext lives is not the
   same in each** — see *Clipboard lingering* below.
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
- **Clipboard lingering (SwiftUI macOS shell only)** — a copied Value is marked
  concealed, transient, and sensitive, so clipboard managers skip it and Universal
  Clipboard does not carry it to the operator's other devices. It auto-clears after
  45 seconds, and only while Janitor still owns the clipboard, so paste still works
  and nothing the operator copied since is wiped (ADR 0005 Amendment 2026-08-25).
  The markers are conventions, not enforcement — a clipboard manager that ignores
  them still records the Value. **The Slint shell has none of this**: a copied Value
  sits on the clipboard unmarked until something replaces it. Issue #59 tracks it.
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
  privilege is the IAM policy's job (the Secrets Manager read path needs only
  `GetSecretValue` / `ListSecrets` / `DescribeSecret`; the remote-`.env` path adds
  `ssm:DescribeInstanceInformation` + `ssm:StartSession` scoped to the target
  instances and the `AWS-StartNonInteractiveCommand` document — see
  `docs/iam_setup.md`).
- **SSM session logging to AWS storage.** The remote-`.env` Provider reads the
  file over an SSM Session Manager session. Session Manager can be configured
  **account-wide** to archive session data — including the streamed file
  contents — to **S3 / CloudWatch Logs**; this is the operator's AWS-side config,
  which Janitor cannot disable. Janitor *detects* the setting and *warns* (in the
  Diagnostic Log and the discovery wizard) so the operator knows the read will be
  logged, but it cannot prevent it. Accepted residual risk, sibling to the AWS
  24h version-retention note: the secret already lives in the customer's AWS
  account; Janitor surfaces the exposure rather than defending below it. (B4
  detects this by reading the `SSM-SessionManagerRunShell` document over
  `ssm:GetDocument` — an unreachable probe falls back to an always-on warning, so
  it never *under*-warns. Why not `SendCommand`: its inline output truncates at
  ~2500 chars, so reading a larger `.env` would force output to S3 — a disk write
  to *read* a secret; Session Manager streams arbitrary sizes with archival being
  opt-in/detectable. See [ADR 0025](adr/0025-remote-dotenv-over-ssm-provider.md).)
- **Below-the-data-channel transport security.** The remote read rides the SSM
  Session Manager data channel — a TLS `wss` WebSocket Janitor opens to AWS's
  managed endpoint (`mgs::channel`); the streamed file contents live only in a
  zeroizing `RawSecret` worker-side, never on the operator's disk. Janitor relies
  on that TLS + AWS's session authorization, not on its own channel encryption. If
  the org enables **KMS encryption** of the session data itself, Janitor's pure
  transport does not implement the KMS data-key exchange, so the read fails
  **masked** (`Unsupported`) rather than proceeding unencrypted — a fail-closed,
  not a silent downgrade.
- **Being a secret store or backup.** Janitor has no storage of record; AWS is the
  source of truth.

## Known limitations (decisions, not surprises)

- **Renamed-key drift.** Entries compare by exact Name. `GITHUB_TOKEN` in one
  Environment and `GITHUB_APP_TOKEN` in another show as two separate **Gaps**, not
  a rename. v1 accepts this.
- **A shell is a softer zone than core** (boundary 2 above): transient plaintext
  in widget/clipboard state is inherent to displaying a secret.
- **Windows auto-update is a remote-code-install surface — but manual-only egress
  (ADR 0034).** The Windows MSIX gains a network update channel: a "Check for
  updates" button can fetch and install a new signed package. Two deliberate
  bounds keep this in scope. (1) **No background network activity** — egress is
  manual-only: the `.appinstaller` carries no automatic `UpdateSettings`, so the
  sole update-related network access happens on an explicit user click; Janitor
  still does zero background phone-home. (2) **Authenticode trust anchor** — the
  payload is the maintainer's Trusted-Signing-signed `.msix`, CA-trusted and
  **OS-verified before it installs**; there is **no second/minisign key** (hence
  no new crown-jewel secret and no baked-in-pubkey rotation gap — rotation is the
  CA-managed cert lifecycle). The residual risk is the App Installer URL itself: a
  forged update would have to present a package validly signed by *our* cert, which
  the OS rejects otherwise. The trust assumption is the signing key + Microsoft's
  App Installer engine, the same anchor as the install (above).
