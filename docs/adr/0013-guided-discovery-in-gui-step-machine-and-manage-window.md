# Guided discovery in the GUI: a reusable Discovery step-machine and a non-modal Manage Application window

**Status:** accepted

## Context

Launched without `JANITOR_MOCK`, the GUI reads `Config::load()`, which for a fresh
user is empty — zero Applications. After Sign-in there is nothing to load, so the
matrix is blank ("no projects, no secrets"). The only way to populate it today is
to hand-type account IDs, regions, secret ARNs, and permission-set names into the
editor — values the user does not know offhand. **Discovery** (the post-Sign-in
browse of reachable accounts/roles/Secret Sets, per [CONTEXT.md](../../CONTEXT.md))
is the missing piece. [ADR 0012](0012-gui-aws-bridge-worker-and-lazy-sign-in.md)
explicitly deferred "discovery-driven column assembly."

The primitives already exist and are tested: the `AccountCatalog` /
`SecretsApi::list_secrets` seams, the SDK-free summaries, and the pure
`select::{plan_selection, resolve}` (`0 → Empty`, `1 → Auto`, `many → Ask`).
`live-verify` wires them into a working CLI flow.

What does not yet exist is an *orchestrator* for the interleaved walk (account →
role → secret, fetch-then-ask, repeat). [ADR 0011](0011-guided-sign-in-and-discovery.md)
considered and **rejected a reusable `GuidedSession` facade as YAGNI** — for the
**CLI**, where a straight-line procedural walk driving a *blocking* stdin
`Chooser` is fine, and keeping orchestration in the binary avoided a hard-to-test
stateful object. The GUI breaks that calculus: its UI thread cannot block, it
wants cancelation, and the sequencing must run off-thread and be relayed over a
channel. That sequencing — which step is next, auto-pick collapsing, remembered
defaults, terminal error states — **is real logic, and per [ADR 0003](0003-core-gui-split-slint-and-secret-display.md)
real logic belongs in a tested crate, not the GUI shell.** The project owner also
stated a standing preference for generic, reusable implementations over narrow,
tightly-coupled ones, and did not endorse ADR 0011's facade rejection. This ADR
therefore **supersedes that specific rejection.**

## Decision

- **A reusable, tested `Discovery` step-machine in `janitor-aws`** is the single
  orchestrator for discovery. It is **presenter-agnostic** — it knows nothing of
  stdin, channels, or Slint:

  ```
  start()            -> Step
  advance(choice)    -> Step
  Step = Ask { what, choices: Vec<label>, default: Option<index> }
       | Done(Mapping) | Empty(what) | Failed(reason)
  ```

  It owns the interleaved walk and reuses `plan_selection` internally to collapse
  `0/1` choices (auto-pick, no `Ask`) and pre-select the remembered default on
  `many`. **`Ask` is one presenter-ready variant (#7), not three typed ones:** it
  carries the `Selectable::label` lines (in list order) and the remembered
  `default` index directly, while the typed account/role/secret items stay inside
  the machine — so a presenter renders a list and returns a bare index, knowing
  nothing of the AWS summary types. `what` (Accounts/Roles/Secrets) lets it title
  the list. This unification follows the owner's generic-over-coupled preference
  (above): the GUI and a future stdin presenter share one rendering shape. It is unit-tested against the existing `wire::fakes` with no blocking
  and no real I/O — the testability ADR 0011 wanted, now extended to the
  sequencing itself. Each consumer writes a thin **presenter** that renders the
  current `Ask` and feeds back a choice. This dissolves ADR 0011's YAGNI argument:
  there are now two genuine consumers.

- **Per-Environment guided wizard: account → role → secret.** One completed walk
  yields one `Mapping` (its `region` = the resolved browse region,
  `permission_set` = the role, `account_id` + `secret_id`(ARN) from the picks).
  An Application is built one Environment at a time, respecting that Environments
  may live in different accounts/regions (CONTEXT.md). The browse region is
  `config.secret_region` if set, else `sso_region`; **no region step in this
  slice** (single-region orgs work with zero region input).

- **Relayed over the existing `Command`/`Event` channel; the GUI presenter is
  wired now.** Each `Ask` crosses to the UI as an `Event`; the user's pick returns
  as a `Command`; the machine advances. Non-blocking and cancelable (drop the
  machine). **`live-verify` was not migrated in this slice** — it kept its
  procedural walk; migrating it onto the step-machine (via a stdin presenter)
  was a tracked follow-up. The engine was designed for that second consumer from
  day one, so the migration was a presenter swap, not a rewrite. **Done (issue
  #11):** `live-verify` now drives the same `Discovery` via
  `presenter::drive_discovery`, proving the engine is genuinely generic.

- **On `Done(Mapping)`: append → save → auto-load.** The Mapping is appended to
  the current Application, `Config` is persisted (locations only), and the
  Application is re-loaded so the masked matrix shows real data immediately. A
  newly added Environment that fails `GetSecretValue` surfaces via the existing
  whole-app error rule (ADR 0012). A typed Environment name that already exists is
  **rejected inline** rather than silently overwriting its Mapping (the Mapping is
  what stops Janitor guessing which Secret Set an Environment means). Remembered
  defaults come from `config.last_pick` and are updated after each successful add,
  so adding `staging` after `prod` pre-selects the same account/role.

- **Failures surface inline in the wizard, masked, retryable.** `Failed`/`Empty`
  carry a masked reason: `NoChoices` → "No accounts/roles/secrets you can access"
  (per step); `SessionError` → the existing `FetchFailReason::describe()` phrases;
  `ReauthRequired` → "session expired — sign in again" and back to Sign-in. **No
  SDK text** (THREAT-MODEL). The message shows inside the wizard so the user can
  adjust or close.

- **A non-modal `Manage Application` pop-out window** (a second Slint `Window`,
  shown non-modally, sharing the UI-thread `AppState` via the existing
  `thread_local`) is the home for everything about one Application: the
  Environment list (`env · account · region · secret`), `+ Add env` (launches the
  discovery wizard), `Remove`, and `Rename`. It is **bound to the Application it
  opened for** — selecting a different app in the sidebar does not retarget it, so
  a discovered Environment can never land in the wrong Application. Per-Environment
  editing moves out of the global Settings overlay, which shrinks to truly global
  concerns (SSO start URL, region, theme/sort/reveal-seconds). Because the parent
  stays interactive, commands from both windows hit the single worker loop and are
  serialized there; the in-progress `Discovery` state lives independently of the
  fetched-secret cache.

- **Scope: Slice 1 is discovery on the existing N-column matrix.** Creating an
  Application stays the sidebar `+` (name only); a signed-in, app-less state shows
  "No Applications yet — create one with +", not a blank loaded screen.

## Considered options

- **Blocking channel-`Chooser` reusing `resolve()` verbatim.** Rejected: parks the
  worker's runtime thread for the wizard's duration, and `Chooser::choose` returns
  `usize` (not `Result`), so cancelation needs a sentinel/channel-close hack.
- **Expose thin list wrappers; sequence in the GUI/worker.** Rejected: pushes the
  real sequencing logic into untested shell, against ADR 0003.
- **Keep ADR 0011's split (pure parts + per-consumer procedural glue).** Rejected:
  the GUI's glue cannot be straight-line/blocking like the CLI's, so it is not
  trivial glue; duplicating sequencing per consumer is the coupling the owner
  explicitly wants to avoid.
- **`app_region` as a compare axis / horizontal region tabs.** Rejected: an
  Application's Environments can span regions, so a single active region cannot
  coherently display a cross-region matrix, and tabs only *switch* — they cannot
  show the drift matrix's side-by-side `Aligned/Drift/Gap`. Region stays metadata
  on a Mapping; Environment stays the compare axis.
- **Single account/role + multi-select secrets to build a whole Application at
  once.** Rejected: assumes every Environment shares one account/role, contradicting
  the cross-account/region domain model.
- **Auto-cluster secrets by name prefix into proposed Applications.** Rejected for
  this slice: bakes in a naming convention the org may not follow; most net-new
  logic.
- **In-app modal Manage panel (like today's Settings overlay).** Rejected: the
  owner wants a non-modal pop-out that does not block the parent window.
- **Migrate `live-verify` onto the step-machine now.** Deferred (not rejected):
  lower-risk to leave the human-verified Milestone B CLI path untouched this slice;
  tracked as a follow-up so the temporary sequencing duplication is repaid.

## Consequences

- `janitor-aws` gains a new public, tested `Discovery` module (step-machine + `Step`
  enum), built on ADR 0011's existing pure parts. Coverage gate (core-only) is
  unaffected; `janitor-aws` stays at/above its test bar via the fakes.
- `janitor-gui` gains a second `Window` and the `Ask`/choice relay plumbing
  (untested I/O shell, consistent with ADR 0010 §5); no auth/AWS/compare logic
  lands in the GUI.
- **ADR 0011's rejection of a reusable discovery orchestrator is superseded.** Its
  pure `plan_selection`/traits/summaries remain correct and are reused.
- ~~`live-verify` temporarily duplicates the account→role→secret sequencing until the
  tracked CLI-migration follow-up lands.~~ **Repaid (issue #11):** `live-verify`
  now drives the shared `Discovery` step-machine through a tested stdin presenter
  (`presenter::drive_discovery`); the parallel sequencing is gone. The per-step
  `--account-id`/`--role`/`--secret-id` overrides were dropped with it (the
  machine auto-picks singletons and menus the rest).
- `CONTEXT.md` gains the **Discovery** term (already added).
- ~~**Deferred to Slice 2 (a later ADR):** the left/right Environment-dropdown 2-up
  diff (pick 2 of N), switching `load()` to fetch only the two selected
  Environments, the pairwise `= / ≠ / ø` glyph, the AWS-console-style region
  picker, and cross-region discovery.~~ **Resolved/superseded:** the pairwise 2-up
  diff is **rejected** by
  [ADR 0014](0014-drift-matrix-model-n-column-and-comparison-columns.md), which
  keeps the **N-column** matrix with a frozen whole-row state column and view-level
  **Comparison Columns** (swap/hide columns without mutating config). The region
  picker + cross-region discovery survive in issue #12. An "Ad-hoc compare" (compare
  two arbitrary Secret Sets without saving an Application) is noted but unscheduled.
- Live re-verification (browser + real org) stays human-gated, like `live-verify`;
  the `Discovery` logic is CI-tested against fakes.
