# Janitor

Janitor is a cross-platform desktop application for working with secrets that live in AWS Secrets Manager. It holds no secrets of its own — it is a window onto secrets stored in AWS, reaching for them on demand and forgetting them when done.

## Language

**Janitor**:
The desktop application itself. Named for the organizational janitor who holds the most keys — though Janitor stores none, it only borrows them on demand and never keeps them.

**Secret Set** (or **Set**):
One AWS Secrets Manager secret, whose stored value is a collection of Entries (typically a JSON object of string → string). This is the unit Janitor reads and writes as a whole. Always ephemeral inside Janitor — held in memory only, never written to disk.
_Avoid_: the bare word "secret" (ambiguous between the AWS resource and the sensitive material) — say Secret Set, Entry, or Value.

**Entry**:
One Name → Value pair inside a Secret Set. The thing the user adds, edits, or removes. Compared across Environments by Name. Nested JSON is represented as Entries with **dotted-path Names** (`database.primary.url`); a raw non-JSON secret is a single Entry.
_Avoid_: key, field, pair (use Entry; "key" is overloaded with KMS/access/SSH keys)

**Value**:
The secret string of a single Entry. The sensitive, ephemeral material that must never be persisted or leaked.

**Environment**:
A named deployment context (e.g. prod, staging, dev) that has its own Secret Set for the same logical set of Entries. An Environment's Set lives at a specific **AWS account + region**; different Environments may sit in different accounts and/or regions. Janitor compares the same logical Set across **N** Environments side by side (an Entry-name × Environment matrix), not just two.
_Avoid_: stage, tier (use Environment)

**Application**:
A named grouping that ties one logical set of Entries to its Secret Set in each Environment (e.g. Application `myapp` → `myapp/prod`, `myapp/staging`, `myapp/dev`). The unit the user opens to get a comparison matrix. Saved in Config; holds only locations, never Values.
_Avoid_: project, service, app group (use Application)

**Mapping**:
The saved record, inside an Application, of which concrete AWS secret (account + region + name/ARN + permission set) backs a given Environment. Plain data in Config; the thing that prevents Janitor from ever guessing which secret an Environment refers to.

**Sign-in**:
The browser-based AWS IAM Identity Center authentication the user performs when opening Janitor. Yields the ephemeral SSO token, from which per-Environment Credentials are derived. Never cached to disk — every launch requires a fresh Sign-in.
_Avoid_: login, SSO (use Sign-in)

**Session**:
The live, authenticated span that begins at a Sign-in and lasts until the SSO token expires. While it lasts, Janitor holds the SSO token in memory and derives a Credential per Environment from it; those Credentials refresh silently as they lapse, but once the SSO token itself expires the Session is over and a fresh Sign-in is required. Memory-only; every launch is a new Session.
_Avoid_: connection, login session (a Session is an authenticated lifetime, not a network connection)

**Credential**:
The ephemeral, short-lived AWS role credentials (one per Environment) that let Janitor call AWS. Derived from the SSO token via `GetRoleCredentials` and silently refreshed without a browser; distinct from a Secret (a Credential is how Janitor talks to AWS; a Secret is what the user manages there). Never persisted.
_Avoid_: token, key (a Credential is not a Secret; the SSO token is the Sign-in artifact, not a Credential)

**Config**:
The user's saved, non-secret settings: Applications, Mappings, regions, and SSO start URL. The only data Janitor writes to disk (plaintext, OS config dir). Holds locations, never Values.
_Avoid_: settings, preferences (use Config)

**Discovery**:
The post-Sign-in process of browsing which AWS accounts, roles (permission sets), and Secret Sets the signed-in user can actually reach, to assemble an Application's Mappings without hand-typing account IDs or ARNs. Walks account → role → Secret Set, auto-selecting whenever there is exactly one choice and asking only when there are several. Yields locations (a Mapping), never Values.
_Avoid_: scan, import (use Discovery)

## Comparison states

Across an Application's matrix, each Entry name is in exactly one state. These drive the view's colors, filters, and labels.

**Aligned**:
Present in every compared Environment with identical Values (detected by hash, no plaintext needed). The boring, healthy case — collapsed by default.

**Drift**:
Present in every compared Environment but the Values differ. Often expected (e.g. a per-Environment `DB_URL`), sometimes a bug.

**Gap**:
Present in some Environments and missing in others. The highest-signal finding — flags a likely Terraform / docker-compose hole. Surfaced most loudly.

By default Janitor compares Values **masked**: it shows presence, Value **length**, and equality grouping (by hash) without revealing plaintext. Plaintext is shown only on an explicit, momentary per-cell reveal. (Length is a deliberate, acceptable side-channel: AWS itself retains and exposes all versions for 24h to anyone with read access, so length leakage is dwarfed by what AWS already shows — and the operator can reveal the Value outright anyway.)

## Example dialogue

> **Dev:** "ZITADEL_CLIENT_SECRET is showing as a Gap."
> **Janitor expert:** "Right — that Entry is present in some Environments of the Application but missing in others. Probably a Terraform hole in whichever Environment it's absent from."
> **Dev:** "And POSTHOG_API_KEY is Drift?"
> **Expert:** "Present everywhere, but the Values differ across Environments. Could be intentional per-Environment config, could be a mistake — the matrix won't decide that for you. It compares by hash, so it knows they differ without ever revealing the Values; the differing lengths are your first clue."

## Known limitations

- **Renamed-key drift** — Entries compare by exact Name, so `GITHUB_TOKEN` in one
  Environment vs `GITHUB_APP_TOKEN` in another show as two **Gaps**, not a rename.
  v1 accepts this.

## Flagged ambiguities

_None open._
