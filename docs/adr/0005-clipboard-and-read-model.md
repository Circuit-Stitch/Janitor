# Clipboard handling and the matrix read model

**Status:** accepted

## Context

Janitor hardens on-screen reveal, but two everyday actions are bigger real-world
leak vectors than the heap-string concern rejected in ADR 0003: copying a Value
to the OS clipboard, and how often the comparison matrix pulls plaintext Values
into memory.

## Decision

**Clipboard: copy with timeout-only auto-clear.** Copying a revealed Value to the
OS clipboard is allowed (a secrets tool must be able to hand you a secret to
paste), but:
- the clipboard is cleared after a short timeout (~15s, possibly
  user-configurable). **Clearing on Janitor focus-loss was rejected** — copy is
  almost always followed by switching to another app (terminal, editor) to paste,
  which *is* a focus-loss event; clearing then would wipe the Value before it can
  be pasted, defeating copy entirely. The timeout, not focus, bounds exposure;
- Janitor only clears the clipboard if it still holds the Value Janitor put there
  (so it never clobbers something the user copied in the meantime);
- where the OS exposes the flag, the entry is excluded from clipboard history and
  cloud sync (Windows Cloud Clipboard, macOS Universal Clipboard);
- "no clipboard at all" was rejected as too purist (unusable); direct
  inject/type-out was deferred to v2+ as platform-fragile.

**Read model: manual refresh only.** The matrix fetches Values only on an
explicit user action (open Application / click Refresh). **No background polling
and no TTL cache** — plaintext enters memory only when the user asks, and the
matrix is an explicitly point-in-time snapshot. `DescribeSecret` (metadata, no
Value) may be used for cheap presence/version checks; `GetSecretValue` (pulls
plaintext) runs only on refresh.

## Consequences

- Residual clipboard exposure remains during the clear window (a process reading
  the clipboard in those seconds). Acknowledged, not eliminated — the honest
  floor for "let me paste this secret."
- The matrix can be stale; that's intentional and surfaced (last-refreshed
  indicator). Live drift requires a manual refresh.
- No background API traffic against Secrets Manager; predictable cost and
  throttle behavior.
