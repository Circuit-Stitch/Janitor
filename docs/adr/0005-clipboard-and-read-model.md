# Clipboard handling and the matrix read model

**Status:** accepted, amended 2026-08-25

## Context

Janitor hardens on-screen reveal, but two everyday actions are bigger real-world
leak vectors than the heap-string concern rejected in ADR 0003: copying a Value
to the OS clipboard, and how often the comparison matrix pulls plaintext Values
into memory.

## Decision

**Clipboard: copy with timeout-only auto-clear.** Copying a revealed Value to the
OS clipboard is allowed (a secrets tool must be able to hand you a secret to
paste), but (the amendment below records how much of this ships, and where):
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

## Amendment 2026-08-25 — what the shells actually do

The decision above describes the target. It read as shipped behavior, which it was
not. This records the two shells separately, because they differ.

**The SwiftUI macOS shell meets it.** A copied Value carries three markers:
`org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType`, which are the
conventions clipboard managers read as "do not record this", and
`com.apple.is-sensitive`, which keeps the item off Universal Clipboard. The pasteboard
is cleared 45 seconds later, and only while Janitor still owns it — the clear compares
the pasteboard's change count against the one Janitor wrote, so a Value that aged out
goes without wiping whatever the operator copied since. A Clear Clipboard menu item
does the same on demand, and quitting the app does it too. An Entry name is metadata,
so it is copied plainly and left alone. `Janitor-macos` ADR 0003 holds the reasoning,
and `PasteboardTests` asserts the markers land.

**The Slint shell does not.** It copies through `arboard`, which is cross-platform and
carries no marker for any of this. There is no timeout clear. A copied Value stays on
the clipboard until something replaces it, is recorded by clipboard managers, and
syncs through Universal Clipboard on macOS. Janitor issue #59 tracks closing that gap.

**Two numbers changed.** The timeout above is ~15 seconds; macOS ships 45. A Value long
enough to need a scroll takes longer than 15 seconds to paste somewhere useful. The
timeout is also not user-configurable — it is a constant in the shell.

**Each shell owns its own clipboard.** Nothing about this crosses the UniFFI boundary.
The core hands a shell a `Plaintext` and the shell decides what the platform can be
told about it, so the markers are per-platform by construction rather than by a
lowest-common-denominator port method.

## Consequences

- Residual clipboard exposure remains during the clear window (a process reading
  the clipboard in those seconds). Acknowledged, not eliminated — the honest
  floor for "let me paste this secret."
- None of the three markers is enforced by the operating system, and two of them
  are community conventions rather than API. A clipboard manager that ignores them
  still records the Value. They are the strongest levers macOS offers, not a
  guarantee.
- The matrix can be stale; that's intentional and surfaced (last-refreshed
  indicator). Live drift requires a manual refresh.
- No background API traffic against Secrets Manager; predictable cost and
  throttle behavior.
