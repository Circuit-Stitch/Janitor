# Core/GUI split, Slint for the view, and the secret-display stance

**Status:** accepted

## Context

Janitor handles secret material in a cross-platform desktop GUI. The
security-critical logic must be testable headlessly and not entangled with a UI
toolkit, and we need a stance on how secret Values are displayed without turning
hardening into security theater.

## Decision

**Two crates.** `janitor-core` (no GUI dependencies) owns everything that
matters: Identity Center auth and the per-Environment Credential model, Secrets
Manager I/O, the non-stomping write engine (ADR 0001), the comparison engine
(Aligned/Drift/Gap, hashing, lengths), Config load/save, and all
secret-in-memory handling (zeroizing types). `janitor-gui` is a thin view that
renders state and sends user intents back; it holds no secret logic. **`core`
targets ≥80% test coverage**; it is the part we can and must test rigorously.

**Slint for the v1 view.** Chosen over egui/iced for a more polished,
declarative UI. Because the spine lives in `core`, the toolkit is a relatively
reversible choice — a future re-skin rewrites only `janitor-gui`.

**Secret-display stance — masked by default, momentary reveal.**
- The matrix compares Values **masked**: presence, Value length (rendered as
  length-sized dots — no plaintext), and equality grouping by hash. Plaintext is
  never rendered in this mode.
- Plaintext is shown only on an **explicit, momentary, per-cell reveal**
  (auto-hide on timeout/blur; never bulk-reveal).
- The canonical Value lives in `core` in a zeroizing buffer; the GUI never owns a
  long-lived copy.

## Considered options

- **egui** — best built-in data grid, fastest to build; rejected for v1 in favor
  of Slint's polish (the choice is cheap to reverse given the core/GUI split).
- **A custom "no-string" reveal/edit widget** (render legible glyphs that never
  materialize as a `String`) — **rejected as architecture / security theater.**
  To be human-legible a Value's glyphs are already in the framebuffer, GPU atlas,
  and reachable by screenshot/recording/accessibility APIs; an attacker who can
  read a heap `String` can equally read `core`'s zeroizing buffer or the
  framebuffer. The heap-string lifetime sits *below* the security floor set by
  the display surface. Additionally, Slint's stock text/edit widgets hold content
  as `SharedString`, so using them materializes plaintext inside Slint anyway,
  and avoiding them would tightly couple the GUI to Slint against the thin-view
  goal. May be revisited only as a last, non-load-bearing hardening spike.

## Consequences

- The effort that would go into no-string rendering goes instead into
  masked-by-default rendering and reveal-window discipline, which defend the
  vector that actually matters.
- The GUI is a **softer zeroization zone** than `core`: revealed/edited plaintext
  transiently exists in Slint widget state. Rule: reveal/edit buffers are cleared
  on blur/close; we accept transient exposure as inherent to displaying a secret.
- **Slint licensed under GPL.** Janitor adopts Slint's royalty-free GPLv3
  option; Janitor itself is therefore GPL. This is acceptable for the project and
  removes the open licensing question.
