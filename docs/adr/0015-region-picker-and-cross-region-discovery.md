# An AWS-console-style region picker, and cross-region Discovery built on it

**Status:** accepted

## Context

Discovery browses exactly one AWS region, and there is no UI to change it. The
browse region is resolved as `config.secret_region` if set, else
`config.sso_region` — the rule [ADR 0013](0013-guided-discovery-in-gui-step-machine-and-manage-window.md)
fixed for its slice ("the browse region is `config.secret_region` if set, else
`sso_region`; **no region step in this slice**"). That rule is live in code: the
GUI's `begin_discovery` (`janitor-gui/src/main.rs`) computes
`if st.config.secret_region.is_empty() { sso_region } else { secret_region }`
and hands it to `Command::BeginDiscovery { region, … }`; the `Discovery`
step-machine (`janitor-aws/src/discovery.rs`) stores that one `region` and uses
it for every `get_role_credentials` and `list_secrets` call in the walk, then
stamps it onto the resulting `Mapping.region`. `live-verify` does the same from
its `--secret-region` / prompt.

Two `Config` fields (`janitor-core/src/config/mod.rs`) already exist for this and
are forward-compatible (`#[serde(default)]`, covered by
`old_config_without_new_fields_loads_defaults`): `sso_region` (where Identity
Center lives) and `secret_region`, whose doc comment already states "Empty →
callers fall back to `sso_region`" and "a plain field so a future settings
surface can flip it." Today nothing flips it — `secret_region` is only ever set
by `live-verify`'s prompt, never from the GUI. The Settings overlay
(`janitor-gui/ui/app.slint`) exposes a free-text `LineEdit` for `sso_region`
**only**; there is no `secret_region` control at all.

The consequence: every Environment a user discovers lands in the single resolved
region. But `Mapping.region` is **per-Environment** — an Application's
`environments: Vec<Mapping>` can already hold Mappings in different regions (the
test fixture has `prod` in `us-east-1` and `staging` in `us-west-2`), and the
domain model (CONTEXT.md) says Environments may span accounts and regions. So an
Application whose Sets genuinely live in different regions **cannot be assembled
through Discovery** — only by hand-editing region strings, the exact thing
Discovery exists to avoid (ADR 0013 Context). This ADR adds the missing control
and the cross-region walk it unlocks, **without** making region a compare axis.

## Decision

- **An AWS-console-style region picker — a selectable region, never free text.**
  The user picks from a known list of AWS regions (a dropdown), mirroring the
  console's region switcher. This replaces the free-text `sso-region` editing
  shape for the *browse* region and prevents the typo class (`us-east1`,
  `eu-west`) that silently produces an empty/wrong Secret listing.

- **Two surfaces, one value.** The picker appears in **two** places, both bound
  to `config.secret_region`:
  - **Global Settings** — the persisted default browse region, alongside the
    existing SSO start URL / SSO region fields. This is "where Discovery looks
    unless I say otherwise."
  - **At-hand, next to `+ Add env` in the Manage window** — a per-add override so
    the user can flip region *between* successive `+ Add env` runs without
    detouring into Settings. Changing it here writes the same
    `config.secret_region` (and persists), so the override and the default are
    one sticky value, not two competing ones. This is the minimum surface that
    makes cross-region Discovery ergonomic: the region the next walk uses is
    visible right where the walk is launched.

- **Persistence writes `config.secret_region`; default-when-unset is
  `sso_region`.** No new `Config` field, no schema change — the existing
  `secret_region` field and its documented fallback are exactly the contract.
  This stays **locations-only**: a region name is not a Value or a Credential,
  so the no-secrets-on-disk invariant (THREAT-MODEL) is untouched. An empty
  `secret_region` keeps meaning "fall back to `sso_region`," so single-region
  orgs need zero region input, as today.

- **Scope of effect: Discovery browsing, and only that.** The picked region is
  passed as the browse `region` into `Command::BeginDiscovery` (replacing the
  hard-coded `secret_region`-else-`sso_region` computation), so it governs
  **which region the walk browses** — the `get_role_credentials` mint and the
  `list_secrets` call inside the account/role/secret walk. It is recorded onto
  the completed `Mapping.region`, exactly as the walk does today. It is **not** a
  comparison or display axis: it never reorders, filters, or selects matrix
  columns, and it has no effect on a loaded Application's matrix. The matrix
  stays the N-column masked Aligned/Drift/Gap view keyed on **Environment**;
  `Mapping.region` remains passive metadata shown in the Manage list
  (`env · account · region · secret`), never a header.

- **Cross-region Discovery falls out for free.** Because the picker is sticky and
  re-read at the start of each walk, the user can: add `prod` with the picker on
  `us-east-1`, flip the picker to `us-west-2`, then add `staging` — yielding one
  Application with mixed-region Mappings. Nothing new is needed in the
  step-machine: it already takes one browse `region` per `start()` and stamps it
  onto its one `Mapping`. The cross-region capability is entirely "let the user
  change the region the next walk receives," which the picker provides.

- **A static, well-known region list — not enumerated from AWS.** The dropdown is
  a built-in list of standard commercial AWS regions (it may seed/include
  `sso_region` and any region already present on a saved `Mapping`, so the user's
  own regions always appear). Enumerating regions live (e.g. EC2
  `DescribeRegions` / SSM public parameters) is possible but adds a credentialed,
  failable, opt-in-region-sensitive call before the user can even pick — for a
  set that changes a few times a year. A static list is offline, deterministic,
  and trivially testable; staleness is repaired by editing the list, and the
  fallback (typing-free selection from known-good strings) already beats today's
  free text.

## Considered options

- **Keep a free-text region field (today's `sso-region` shape) for the browse
  region.** Rejected: typo-prone — a bad region name yields an empty or wrong
  Secret listing with no obvious cause, and the whole point of a picker is to make
  the region un-mistypeable.

- **Region as a compare axis / horizontal region tabs.** Already rejected by
  [ADR 0013](0013-guided-discovery-in-gui-step-machine-and-manage-window.md)
  ("`app_region` as a compare axis / horizontal region tabs"): an Application's
  Environments can span regions, so a single active region cannot coherently
  display the matrix, and tabs only *switch* — they cannot show side-by-side
  drift. Restated here only to be explicit that this ADR's picker is **Discovery
  browse-state**, not a view axis; **region stays metadata on a Mapping,
  Environment stays the compare axis.** This is also consistent with the
  N-column matrix and view-level Comparison Columns settled separately (the
  region picker touches neither column membership nor ordering).

- **A per-Environment region *step inside* every Discovery walk vs. a sticky
  picker.** A region `Ask` could be injected as the first step of each walk
  (account → role → secret would become region → account → role → secret).
  Rejected in favor of the **sticky picker**: a per-walk step taxes the common
  single-region org with an extra prompt on *every* add, and it buries a
  cross-cutting, sticky choice (most users add several Environments in the same
  region) inside the per-Environment wizard. The sticky picker defaults to the
  last choice, costs nothing when unchanged, and keeps the step-machine's clean
  "one browse region per `start()`" contract — no new `Step` variant, no change
  to the tested walk. The picker sitting next to `+ Add env` keeps the region
  visible at the moment of the add, recovering the discoverability a step would
  have given, without the per-add tax.

- **Auto-detect the region from the chosen account / role.** Rejected: an account
  is not bound to one region — its Secret Sets can live in many — so there is
  nothing to infer; the region is genuinely a user choice about *where to look*,
  not a property of the account. Inferring it would re-introduce the "Janitor
  guessing which Set an Environment means" hazard ADR 0013 designed out.

## Consequences

- **`janitor-core` (`Config`): no structural change.** `secret_region` already
  exists with the documented `sso_region` fallback and forward-compat coverage;
  this ADR just gives it a GUI writer. (A future "add a region to the static list"
  is a code edit, not a config-schema change.)

- **`janitor-aws`: browse region becomes genuinely variable per add, with no
  step-machine change.** `Discovery` / `Session::begin_discovery` already accept
  one browse `region` per walk and stamp it onto the `Mapping`; they keep working
  unchanged. `live-verify` keeps its `--secret-region` / prompt for the CLI and is
  unaffected.

- **`janitor-gui`: the picker widget plus plumbing.** A region-dropdown control in
  the Settings overlay and beside `+ Add env` in the Manage window
  (`app.slint`), bound through a new property/callback to write
  `config.secret_region` and persist (mirroring the existing `save-sso` path,
  real-backend-only). `begin_discovery` reads the picked region (the same
  `secret_region`-else-`sso_region` resolution, now user-set) into
  `Command::BeginDiscovery`. This is untested UI shell, consistent with the
  core/GUI split (ADR 0003) and ADR 0010 §5; no auth/AWS/compare logic moves into
  the GUI.

- **Tests:** the picker→`secret_region`→`begin_discovery` resolution stays the
  pure, already-tested `secret_region`-else-`sso_region` rule; the static region
  list is a trivial pure unit (non-empty, includes `sso_region`/known Mapping
  regions). The cross-region outcome is already provable in `janitor-aws` by
  driving two walks with different browse regions and asserting two `Mapping`s
  with the two regions — no new engine surface to test.

- **Out of scope:** the unscheduled **"Ad-hoc compare"** (comparing two arbitrary
  Secret Sets without saving an Application) noted in ADR 0013 and issue #12 stays
  out. So does any change to the matrix's columns, ordering, or the
  Environment-keyed compare axis — region remains Discovery browse-metadata, full
  stop.
