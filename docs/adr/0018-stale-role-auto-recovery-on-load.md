# Auto-recover a stale Mapping permission set on load

**Status:** accepted

## Context

A saved [Mapping](../../CONTEXT.md) pins which permission set ("role") Janitor
uses to read an Environment's Secret Set. That role is whatever
[Discovery](../../CONTEXT.md) resolved when the Environment was added — and it can
go stale: the user's Identity Center assignment for that account changes (a role
is removed, or a least-privilege `JanitorSecretsRead` replaces an earlier
`SystemAdministrator`). When it does, `GetRoleCredentials(account, stale_role)`
returns `ForbiddenException: No access`, the whole-app load fails, and the matrix
shows "access denied" — even though the user *does* have a working role on that
account.

Until now the only fix was manual: delete the Environment and re-add it through
the Manage window, which re-runs Discovery and (when the account has a single
entitled role) silently resolves the correct one with no browser. The project
owner's position: **the app should recover from this automatically** — the data to
self-heal (the live SSO token + `list_account_roles`) is already in hand.

This required first splitting the error taxonomy: role-step `Forbidden` /
`AccessDenied` had been collapsed into the scrubbed `Sdk` catch-all
([ADR 0017](0017-in-app-diagnostic-log-panel-and-zero-terminal-output.md)), which
gave the banner real detail but no programmatic hook.

## Decision

- **A new typed `SessionError::RoleNotEntitled`** is produced by `classify_aws`
  for a role-step `ForbiddenException` / `AccessDeniedException` (a dead/expired
  token stays `ReauthRequired`; a *secret*-step `AccessDenied` stays
  `AccessDenied` so the facade's existing force-refresh tier is untouched). It
  carries the same error-safe detail as `Sdk`, and `FetchFailReason::from` maps it
  to `AccessDenied`, so an *un*-recovered denial still surfaces as "access denied"
  — no user-visible change on the give-up path.

- **Recovery lives in `Session::load`**, which already owns the live SSO token and
  the `AccountCatalog`. On a per-Environment `RoleNotEntitled`, it re-resolves the
  account's entitled roles via `list_account_roles` (no browser) and the shared
  pure `select::plan_selection`, then:
  - **exactly one entitled role, different from the stored one** → rewrite that
    Environment's `Mapping.permission_set` and **retry the fetch once**; on success
    the corrected Mapping rides out in `Loaded { view, corrected }`.
  - **zero / many / same-as-stored roles, or a re-list error** → keep the original
    denial.

  This is a new **at-most-once** escalation tier (mirroring ADR 0010 §4): one
  re-list + one retry per Environment, the retry's result final — never a loop,
  never a second recovery.

- **Silent only when unambiguous.** Recovery auto-picks *only* when there is
  exactly one entitled role. With several, Janitor refuses and surfaces the denial
  — it must never silently choose a role for the user, least of all the
  most-privileged one. The just-denied stored role is passed as `remembered:
  None`, so a stale pick can neither bias nor "authorize" a silent switch. The
  interactive "choose among several roles" path stays a future Manage-window flow,
  never a load-time decision.

- **`corrected` persists through the GUI**, app-name-guarded against a mid-load
  sidebar switch, via a new location-only `Application::set_permission_set`
  (never `add_environment`, so it cannot create or stomp a Mapping) + the existing
  mock-guarded `Config::save`.

## Consequences

- This rewrites a *saved Config location*, not a Secret Set, so [ADR 0001](0001-non-stomping-writes-via-staged-put-and-cas.md)'s
  no-stomp/CAS engine does not apply; it stays within the read-only, locations-only,
  at-most-once invariants. The rewrite is logged (error-safe) in the Diagnostic Log.
- **Read-write caveat (deferred):** when a write path ships, an auto-recovered role
  must re-prompt before any write — silently switching to a different (possibly
  broader) role and then writing under it is a privilege-escalation hazard. This
  ADR is read-path only.
- **Milestone B verify items:** confirm a live org returns `Forbidden`/`AccessDenied`
  (not an overloaded code) for a not-entitled role at `GetRoleCredentials`.
