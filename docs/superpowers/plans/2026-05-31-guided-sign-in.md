# Guided Sign-in Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `janitor-aws`'s `live-verify` binary into a guided sign-in where the browser opens, the user logs in, and the tool auto-discovers account → role → secret (remembering the org and the last pick), printing a masked matrix.

**Architecture:** Implements [ADR 0011](../../adr/0011-guided-sign-in-and-discovery.md) / [the 2026-05-31 spec](../specs/2026-05-31-guided-sign-in-design.md) on top of the headless slice (ADR 0010). Pass `issuerUrl` to `RegisterClient` and read `authorizationEndpoint` from its response (deleting the `--authorize-endpoint` flag); add `ListAccounts`/`ListAccountRoles`/`ListSecrets` behind narrow traits; a pure `plan_selection` + a `Chooser`-seam `resolve()` hold the 0/1/many+remembered-default logic (CI-tested); two backward-compatible `Config` fields remember the org and last pick. Only the stdin menu, the real SDK list adapters, the browser, and loopback stay untested (ADR 0010 §5).

**Tech Stack:** Rust 2021, tokio, `aws-sdk-ssooidc`/`aws-sdk-sso`/`aws-sdk-secretsmanager` (installed: ssooidc 1.102, sso 1.100, secretsmanager 1.106), `async-trait`, `serde`/`toml` (core Config).

**Read before starting:** the [spec](../specs/2026-05-31-guided-sign-in-design.md), [ADR 0011](../../adr/0011-guided-sign-in-and-discovery.md), ADR 0010 (the seam this extends), and the memory note `subagent-execution-gotchas` (forbid branch-changing git in subagent prompts; trust `cargo` over stale red-phase diagnostics).

**Two conventions this plan follows (from the headless slice):**
1. **The tested surface has zero placeholders.** Pure functions, the `Config` fields, the selection logic, the summary `Selectable` impls, and all *fakes* are given in full. The only code that references the AWS SDK API directly is the untestable shell (Tasks 3 real impls, Task 4 auth shell, Task 5 binary); there, exact SDK method/field names must be confirmed against the *installed* crate docs — that is the ADR 0010 §5 boundary, not a plan gap.
2. **Surface any test-behavior change.** Per the user's global rule, this slice should only *add* tests and *add* fields/methods. The two places existing tests are touched are **additive and named**: extending core's `Config` test `sample()` helper (Task 1) and adding `list_secrets` to `FakeSecretsApi` (Task 3). Neither weakens an existing assertion. If you find yourself *changing* what an existing test asserts, STOP and surface it.

---

## File structure

**New file:**

| File | Responsibility |
|---|---|
| `janitor-aws/src/select.rs` | Pure selection: `Selectable`, `SelectionPlan`, `plan_selection`; the `Chooser` seam, `DiscoverError`, and `resolve()`. Fully unit-tested. |

**Modified:**

| File | Change |
|---|---|
| `janitor-core/src/config/mod.rs` | Add `secret_region: String` + `last_pick: Option<Mapping>` (backward-compatible) + tests |
| `janitor-aws/src/lib.rs` | `pub mod select;` |
| `janitor-aws/src/wire.rs` | `AccountSummary`/`RoleSummary`/`SecretSummary` + `Selectable` impls; `AccountCatalog` trait; `list_secrets` on `SecretsApi`; `FakeSecretsApi::list_secrets` |
| `janitor-aws/src/aws_impl.rs` | `impl AccountCatalog for AwsRoleClient`; `AwsSecretsApi::list_secrets`; `issuerUrl` + read `authorization_endpoint` in `register_client` |
| `janitor-aws/src/authenticator.rs` | `Authenticator` takes `issuer_url`, reads the authorize endpoint from the registration |
| `janitor-aws/src/bin/live-verify.rs` | Task 4: swap `--authorize-endpoint`→`--start-url`. Task 5: full guided rework |
| `CLAUDE.md`, `README.md` | Task 6: status refresh |

---

## Task 1: Core `Config` — `secret_region` + `last_pick`

**Files:**
- Modify: `janitor-core/src/config/mod.rs`

The org and the last pick are *locations*, never Values (ADR 0011 / THREAT-MODEL), so they belong in `Config`. Both are covered by the struct's existing `#[serde(default)]`, so an old `config.toml` without them still loads.

- [ ] **Step 1: Add the two fields**

In `janitor-core/src/config/mod.rs`, the `Config` struct (currently `sso_start_url`, `sso_region`, `applications`) gains two fields. Replace the struct body:

```rust
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// IAM Identity Center start URL (e.g. `https://my-org.awsapps.com/start`).
    pub sso_start_url: String,
    /// AWS region hosting Identity Center (where SSO-OIDC calls go).
    pub sso_region: String,
    /// Default region for the guided "list secrets" step. Empty → callers fall
    /// back to `sso_region`. A plain field so a future settings surface can flip
    /// it (ADR 0011).
    pub secret_region: String,
    /// The last account/role/secret picked in the guided flow, offered as the
    /// default next run. A `Mapping` (its `environment` is `"live"` for guided
    /// picks). `None` until the first successful pick.
    pub last_pick: Option<Mapping>,
    /// Saved Applications, each tying a logical Entry set to a Set per Environment.
    pub applications: Vec<Application>,
}
```

- [ ] **Step 2: Extend the test `sample()` and add a backward-compat test**

In the `#[cfg(test)] mod tests` block: the `sample()` helper currently builds a `Config { sso_start_url, sso_region, applications }`. **This is an additive change to an existing test helper — the round-trip assertion is strengthened to also cover the new fields; no existing assertion is weakened.** Update `sample()` to populate the new fields, and add the new fields' assertions + a backward-compat test.

Replace the `sample()` function:

```rust
    fn sample() -> Config {
        Config {
            sso_start_url: "https://acme.awsapps.com/start".into(),
            sso_region: "us-east-1".into(),
            secret_region: "us-west-2".into(),
            last_pick: Some(Mapping {
                environment: "live".into(),
                account_id: "333333333333".into(),
                region: "us-west-2".into(),
                secret_id: "myapp/live".into(),
                permission_set: "ReadOnly".into(),
            }),
            applications: vec![Application {
                name: "myapp".into(),
                environments: vec![
                    Mapping {
                        environment: "prod".into(),
                        account_id: "111111111111".into(),
                        region: "us-east-1".into(),
                        secret_id: "myapp/prod".into(),
                        permission_set: "ReadOnly".into(),
                    },
                    Mapping {
                        environment: "staging".into(),
                        account_id: "222222222222".into(),
                        region: "us-west-2".into(),
                        secret_id: "myapp/staging".into(),
                        permission_set: "ReadOnly".into(),
                    },
                ],
            }],
        }
    }
```

Update `default_config_is_empty` to also assert the new defaults:

```rust
    #[test]
    fn default_config_is_empty() {
        let c = Config::default();
        assert!(c.sso_start_url.is_empty());
        assert!(c.secret_region.is_empty());
        assert!(c.last_pick.is_none());
        assert!(c.applications.is_empty());
    }
```

Add this new test (place it after `missing_file_loads_default`):

```rust
    #[test]
    fn old_config_without_new_fields_loads_defaults() {
        // A config.toml written before secret_region / last_pick existed must
        // still load: the missing keys fall back to defaults (#[serde(default)]).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
sso_start_url = "https://old.awsapps.com/start"
sso_region = "us-east-1"
applications = []
"#,
        )
        .unwrap();
        let c = Config::load_from(&path).unwrap();
        assert_eq!(c.sso_start_url, "https://old.awsapps.com/start");
        assert_eq!(c.secret_region, "", "missing secret_region → default empty");
        assert!(c.last_pick.is_none(), "missing last_pick → default None");
    }
```

- [ ] **Step 3: Run the core config tests**

Run: `cargo test -p janitor-core --lib config`
Expected: PASS — the existing round-trip/overwrite tests still pass (now also covering the new fields), plus the new backward-compat test. If `save_then_load_round_trips` fails, the `Serialize`/`Deserialize` of the new fields is wrong; if `old_config_without_new_fields_loads_defaults` fails, confirm `#[serde(default)]` is still on the struct.

- [ ] **Step 4: Commit**

```bash
git add janitor-core/src/config/mod.rs
git commit -m "feat(core): Config.secret_region + last_pick for guided sign-in (ADR 0011)"
```

---

## Task 2: `select.rs` — pure selection + the `Chooser` seam

**Files:**
- Create: `janitor-aws/src/select.rs`
- Modify: `janitor-aws/src/lib.rs`

> **Refinement vs. spec (strengthening, surfaced):** the spec put `plan_selection` (pure) in `select.rs` and the menu in the binary. This task additionally extracts a **sync `resolve()`** behind a `Chooser` trait (the seam the spec's "Approaches" section named), so the *entire* 0/1/many+remembered-default decision is CI-tested with fakes. Only the stdin reader (the real `Chooser`, Task 5) stays untested shell. No behavior the spec described is removed — this tests more of it.

- [ ] **Step 1: Register the module**

In `janitor-aws/src/lib.rs`, add to the tested-module list (after `pub mod secrets;` or alphabetically near it):

```rust
pub mod select;
```

- [ ] **Step 2: Write `select.rs` with `plan_selection`, the `Chooser` seam, `resolve`, and full tests**

Create `janitor-aws/src/select.rs`:

```rust
//! Selection logic for the guided flow (ADR 0011): given a list of discovered
//! choices (accounts / roles / secrets) and an optionally-remembered prior pick,
//! decide whether to auto-pick, error on emptiness, or ask — and, when asking,
//! delegate to a `Chooser` seam. All pure/sync and fully tested; the only
//! untested piece is the real stdin `Chooser` in the binary.

/// Anything the guided flow can choose among. `key` is the stable identity used
/// to match a remembered pick; `label` is the human menu line.
pub trait Selectable {
    fn key(&self) -> &str;
    fn label(&self) -> String;
}

/// What to do with a discovered list of choices.
#[derive(Debug, PartialEq)]
pub enum SelectionPlan {
    /// No choices at all — the caller reports a clear error and stops.
    Empty,
    /// Exactly one choice — take it silently (index is always 0 here, but carried
    /// explicitly so the caller never re-derives it).
    Auto(usize),
    /// Several choices — ask. `default` is the index of the remembered pick if it
    /// is still present, else `None`.
    Ask { default: Option<usize> },
}

/// Pure decision: 0 → `Empty`; 1 → `Auto(0)`; ≥2 → `Ask { default }` where
/// `default` is the index whose `key` equals `remembered` (if any is present).
pub fn plan_selection<T: Selectable>(items: &[T], remembered: Option<&str>) -> SelectionPlan {
    match items.len() {
        0 => SelectionPlan::Empty,
        1 => SelectionPlan::Auto(0),
        _ => {
            let default = remembered.and_then(|key| items.iter().position(|it| it.key() == key));
            SelectionPlan::Ask { default }
        }
    }
}

/// The seam that turns an `Ask` into a concrete index. The real impl reads stdin
/// (untested shell, in the binary); the test fake scripts the choice.
pub trait Chooser {
    /// Present `labels` and return the chosen index. `default` is the index to
    /// pre-select (Enter accepts it). Implementations MUST return an index in
    /// `0..labels.len()`.
    fn choose(&self, labels: &[String], default: Option<usize>) -> usize;
}

/// Why a discovery step could not yield a choice. A binary-level outcome, not a
/// `SessionError` — emptiness is a successful call with nothing to pick (ADR 0011).
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum DiscoverError {
    /// AWS returned no choices for this step (e.g. no entitled accounts).
    #[error("no {0} available to choose from")]
    NoChoices(&'static str),
}

/// Resolve a discovered list to a single chosen item: error on empty, auto-pick
/// the lone item (without calling the chooser), otherwise ask via `chooser`.
/// `what` names the thing being chosen (for the error message). Consumes `items`
/// and returns the chosen one by value.
pub fn resolve<T: Selectable>(
    mut items: Vec<T>,
    remembered: Option<&str>,
    chooser: &dyn Chooser,
    what: &'static str,
) -> Result<T, DiscoverError> {
    match plan_selection(&items, remembered) {
        SelectionPlan::Empty => Err(DiscoverError::NoChoices(what)),
        SelectionPlan::Auto(i) => Ok(items.swap_remove(i)),
        SelectionPlan::Ask { default } => {
            let labels: Vec<String> = items.iter().map(|it| it.label()).collect();
            let raw = chooser.choose(&labels, default);
            // Guard against an out-of-range index from a misbehaving chooser.
            let i = raw.min(items.len() - 1);
            Ok(items.swap_remove(i))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Item {
        k: String,
        l: String,
    }
    impl Item {
        fn new(k: &str, l: &str) -> Self {
            Item { k: k.into(), l: l.into() }
        }
    }
    impl Selectable for Item {
        fn key(&self) -> &str {
            &self.k
        }
        fn label(&self) -> String {
            self.l.clone()
        }
    }

    /// Records what it was asked and returns a scripted index.
    struct FakeChooser {
        pick: usize,
        calls: Mutex<u32>,
        last_default: Mutex<Option<Option<usize>>>,
    }
    impl FakeChooser {
        fn new(pick: usize) -> Self {
            FakeChooser {
                pick,
                calls: Mutex::new(0),
                last_default: Mutex::new(None),
            }
        }
        fn calls(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
        fn last_default(&self) -> Option<Option<usize>> {
            *self.last_default.lock().unwrap()
        }
    }
    impl Chooser for FakeChooser {
        fn choose(&self, _labels: &[String], default: Option<usize>) -> usize {
            *self.calls.lock().unwrap() += 1;
            *self.last_default.lock().unwrap() = Some(default);
            self.pick
        }
    }

    // ---- plan_selection ----

    #[test]
    fn empty_list_plans_empty() {
        let items: Vec<Item> = vec![];
        assert_eq!(plan_selection(&items, None), SelectionPlan::Empty);
    }

    #[test]
    fn single_item_plans_auto() {
        let items = vec![Item::new("a", "A")];
        assert_eq!(plan_selection(&items, None), SelectionPlan::Auto(0));
    }

    #[test]
    fn many_without_remembered_plans_ask_no_default() {
        let items = vec![Item::new("a", "A"), Item::new("b", "B")];
        assert_eq!(plan_selection(&items, None), SelectionPlan::Ask { default: None });
    }

    #[test]
    fn many_with_present_remembered_plans_ask_with_default_index() {
        let items = vec![Item::new("a", "A"), Item::new("b", "B"), Item::new("c", "C")];
        assert_eq!(
            plan_selection(&items, Some("c")),
            SelectionPlan::Ask { default: Some(2) }
        );
    }

    #[test]
    fn many_with_absent_remembered_plans_ask_no_default() {
        let items = vec![Item::new("a", "A"), Item::new("b", "B")];
        assert_eq!(
            plan_selection(&items, Some("zzz")),
            SelectionPlan::Ask { default: None }
        );
    }

    // ---- resolve ----

    #[test]
    fn resolve_empty_is_error_and_never_asks() {
        let chooser = FakeChooser::new(0);
        let items: Vec<Item> = vec![];
        let err = resolve(items, None, &chooser, "accounts").unwrap_err();
        assert_eq!(err, DiscoverError::NoChoices("accounts"));
        assert_eq!(chooser.calls(), 0, "must not prompt when there is nothing to pick");
    }

    #[test]
    fn resolve_single_auto_picks_without_asking() {
        let chooser = FakeChooser::new(0);
        let items = vec![Item::new("only", "Only")];
        let chosen = resolve(items, None, &chooser, "roles").unwrap();
        assert_eq!(chosen.key(), "only");
        assert_eq!(chooser.calls(), 0, "single choice must not prompt");
    }

    #[test]
    fn resolve_many_asks_and_returns_chosen() {
        let chooser = FakeChooser::new(1); // pick index 1 → "b"
        let items = vec![Item::new("a", "A"), Item::new("b", "B"), Item::new("c", "C")];
        let chosen = resolve(items, None, &chooser, "secrets").unwrap();
        assert_eq!(chosen.key(), "b");
        assert_eq!(chooser.calls(), 1);
        assert_eq!(chooser.last_default(), Some(None));
    }

    #[test]
    fn resolve_many_passes_remembered_as_default() {
        let chooser = FakeChooser::new(0);
        let items = vec![Item::new("a", "A"), Item::new("b", "B"), Item::new("c", "C")];
        let _ = resolve(items, Some("c"), &chooser, "accounts").unwrap();
        assert_eq!(chooser.last_default(), Some(Some(2)), "remembered key → default index");
    }

    #[test]
    fn resolve_clamps_out_of_range_choice() {
        let chooser = FakeChooser::new(99); // misbehaving: out of range
        let items = vec![Item::new("a", "A"), Item::new("b", "B")];
        let chosen = resolve(items, None, &chooser, "roles").unwrap();
        assert_eq!(chosen.key(), "b", "clamped to last valid index");
    }
}
```

- [ ] **Step 3: Run the selection tests**

Run: `cargo test -p janitor-aws --lib select`
Expected: PASS (11 tests). If `resolve_single_auto_picks_without_asking` fails on `calls() == 0`, the `Auto` arm is wrongly calling the chooser — fix `resolve`, not the test.

- [ ] **Step 4: Commit**

```bash
git add janitor-aws/src/lib.rs janitor-aws/src/select.rs
git commit -m "feat(aws): pure plan_selection + Chooser-seam resolve for guided pick (ADR 0011)"
```

---

## Task 3: Discovery seam — summaries, `AccountCatalog`, `list_secrets`

**Files:**
- Modify: `janitor-aws/src/wire.rs`
- Modify: `janitor-aws/src/aws_impl.rs`

Wrap the three new AWS reads behind narrow traits with SDK-free I/O (ADR 0010 §5). The **tested** parts are the SDK-free summary types and their `Selectable` impls; the real SDK adapters are shell (compile + Milestone B). Adding `list_secrets` to the `SecretsApi` trait forces every impl (the fake and the real one) to be updated in this task so the crate stays green.

- [ ] **Step 1: Add summaries + `Selectable` impls + the `AccountCatalog` trait + `list_secrets` to `SecretsApi` in `wire.rs`**

In `janitor-aws/src/wire.rs`, add the import at the top (with the other `use crate::...` lines):

```rust
use crate::select::Selectable;
```

Add these SDK-free summary types and their `Selectable` impls (place them after the `RawSecret` struct, before the fakes module):

```rust
/// One account the signed-in user is entitled to (`ListAccounts`).
#[derive(Debug, Clone, PartialEq)]
pub struct AccountSummary {
    pub id: String,
    pub name: String,
}
impl Selectable for AccountSummary {
    fn key(&self) -> &str {
        &self.id
    }
    fn label(&self) -> String {
        format!("{} ({})", self.name, self.id)
    }
}

/// One permission-set role available in an account (`ListAccountRoles`).
#[derive(Debug, Clone, PartialEq)]
pub struct RoleSummary {
    pub name: String,
}
impl Selectable for RoleSummary {
    fn key(&self) -> &str {
        &self.name
    }
    fn label(&self) -> String {
        self.name.clone()
    }
}

/// One secret in a region (`ListSecrets`). `arn` is the stable identity; `name`
/// is the friendly label.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretSummary {
    pub name: String,
    pub arn: String,
}
impl Selectable for SecretSummary {
    fn key(&self) -> &str {
        &self.arn
    }
    fn label(&self) -> String {
        self.name.clone()
    }
}

/// Wraps the SSO-token-authorized account/role enumeration ops.
#[async_trait]
pub trait AccountCatalog: Send + Sync {
    /// `ListAccounts` for everything `token` is entitled to.
    async fn list_accounts(&self, token: &SsoToken)
        -> Result<Vec<AccountSummary>, SessionError>;

    /// `ListAccountRoles` for one account.
    async fn list_account_roles(
        &self,
        token: &SsoToken,
        account_id: &str,
    ) -> Result<Vec<RoleSummary>, SessionError>;
}
```

In the **same file**, add `list_secrets` to the existing `SecretsApi` trait (add the method after `get_secret_value`):

```rust
    /// `ListSecrets` in `region`, authorized by `cred`. Returns name+ARN only —
    /// never a Value.
    async fn list_secrets(
        &self,
        cred: &Credential,
        region: &str,
    ) -> Result<Vec<SecretSummary>, SessionError>;
```

- [ ] **Step 2: Add `list_secrets` to `FakeSecretsApi` + a `Selectable` self-test**

Still in `wire.rs`, inside `#[cfg(test)] pub mod fakes`. **Surfaced additive change:** `FakeSecretsApi` gains a `list_secrets` arm so it remains a complete `SecretsApi` test double; this does not alter its existing `get_secret_value` behavior or any existing test. Extend the `FakeSecretsApi` struct and impl:

Replace the `FakeSecretsApi` struct definition with one that also scripts secret lists:

```rust
    /// A scripted secrets client.
    pub struct FakeSecretsApi {
        pub outcomes: Mutex<Vec<Result<RawSecret, SessionError>>>,
        pub list_outcomes: Mutex<Vec<Result<Vec<SecretSummary>, SessionError>>>,
        pub calls: Mutex<u32>,
    }
    impl FakeSecretsApi {
        pub fn new(outcomes: Vec<Result<RawSecret, SessionError>>) -> Self {
            FakeSecretsApi {
                outcomes: Mutex::new(outcomes),
                list_outcomes: Mutex::new(Vec::new()),
                calls: Mutex::new(0),
            }
        }
        /// Build a fake whose `list_secrets` returns `lists` (one per call).
        pub fn with_lists(lists: Vec<Result<Vec<SecretSummary>, SessionError>>) -> Self {
            FakeSecretsApi {
                outcomes: Mutex::new(Vec::new()),
                list_outcomes: Mutex::new(lists),
                calls: Mutex::new(0),
            }
        }
        pub fn call_count(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
    }
```

Update the `impl SecretsApi for FakeSecretsApi` block to add the `list_secrets` method (keep the existing `get_secret_value` exactly as-is):

```rust
    #[async_trait]
    impl SecretsApi for FakeSecretsApi {
        async fn get_secret_value(
            &self,
            _cred: &Credential,
            _secret_id: &str,
            _region: &str,
        ) -> Result<RawSecret, SessionError> {
            *self.calls.lock().unwrap() += 1;
            let mut v = self.outcomes.lock().unwrap();
            if v.is_empty() {
                panic!("FakeSecretsApi called more times than scripted");
            }
            v.remove(0)
        }

        async fn list_secrets(
            &self,
            _cred: &Credential,
            _region: &str,
        ) -> Result<Vec<SecretSummary>, SessionError> {
            let mut v = self.list_outcomes.lock().unwrap();
            if v.is_empty() {
                panic!("FakeSecretsApi::list_secrets called more times than scripted");
            }
            v.remove(0)
        }
    }
```

Add a small self-test of the summaries (inside the `fakes` module, alongside the existing `fake_role_client_counts_calls_and_scripts_outcomes` test). This proves the `Selectable` impls and the new fake arm, so later code can rely on them:

```rust
    #[test]
    fn summaries_expose_keys_and_labels() {
        let a = AccountSummary { id: "111".into(), name: "Prod".into() };
        assert_eq!(a.key(), "111");
        assert_eq!(a.label(), "Prod (111)");

        let r = RoleSummary { name: "ReadOnly".into() };
        assert_eq!(r.key(), "ReadOnly");
        assert_eq!(r.label(), "ReadOnly");

        let s = SecretSummary { name: "myapp/prod".into(), arn: "arn:aws:...:myapp/prod".into() };
        assert_eq!(s.key(), "arn:aws:...:myapp/prod");
        assert_eq!(s.label(), "myapp/prod");
    }

    #[test]
    fn fake_secrets_api_scripts_list_outcomes() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let fake = FakeSecretsApi::with_lists(vec![Ok(vec![SecretSummary {
            name: "n".into(),
            arn: "a".into(),
        }])]);
        let cred = Credential::new("a".into(), "b".into(), "c".into(), SystemTime::UNIX_EPOCH);
        rt.block_on(async {
            let list = fake.list_secrets(&cred, "us-east-1").await.unwrap();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].name, "n");
        });
    }
```

> Note: the `fakes` module already imports `super::*` and `std::time::{Duration, SystemTime}` (used by `FakeClock`/`FakeRoleClient`); `Credential` and the summaries resolve via `super::*`. If `SystemTime` is not in scope in this module after your edits, add `use std::time::SystemTime;` — confirm with the compiler.

- [ ] **Step 3: Implement the real adapters in `aws_impl.rs` (shell)**

> ⚠️ ADR 0010 §5 boundary: confirm SDK method/field names against the installed crates (`aws-sdk-sso 1.100`, `aws-sdk-secretsmanager 1.106`). Accessors confirmed at planning time: `AccountInfo::{account_id, account_name}`, `RoleInfo::role_name`, `SecretListEntry::{name, arn}`, with `account_list()`/`role_list()`/`secret_list()` outputs and `next_token()` for pagination. If `account_list()` returns `Option<&[..]>` in the installed version, adjust the iteration accordingly.

In `janitor-aws/src/aws_impl.rs`, update the imports from `wire` to include the new items:

```rust
use crate::wire::{
    AccountCatalog, AccountSummary, ClientRegistration, OidcClient, RawSecret, RoleCredentialClient,
    RoleSummary, SecretSummary, SecretsApi, TokenExchange,
};
```

Add an `AccountCatalog` impl for the existing `AwsRoleClient` (it already wraps `aws_sdk_sso::Client`). Place it after the existing `impl RoleCredentialClient for AwsRoleClient`:

```rust
#[async_trait]
impl AccountCatalog for AwsRoleClient {
    async fn list_accounts(
        &self,
        token: &SsoToken,
    ) -> Result<Vec<AccountSummary>, SessionError> {
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut req = self.inner.list_accounts().access_token(token.expose());
            if let Some(t) = &next {
                req = req.next_token(t);
            }
            let page = req.send().await.map_err(map_role_err)?;
            for a in page.account_list() {
                out.push(AccountSummary {
                    id: a.account_id().unwrap_or_default().to_string(),
                    name: a.account_name().unwrap_or_default().to_string(),
                });
            }
            match page.next_token() {
                Some(t) => next = Some(t.to_string()),
                None => break,
            }
        }
        Ok(out)
    }

    async fn list_account_roles(
        &self,
        token: &SsoToken,
        account_id: &str,
    ) -> Result<Vec<RoleSummary>, SessionError> {
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut req = self
                .inner
                .list_account_roles()
                .access_token(token.expose())
                .account_id(account_id);
            if let Some(t) = &next {
                req = req.next_token(t);
            }
            let page = req.send().await.map_err(map_role_err)?;
            for r in page.role_list() {
                out.push(RoleSummary {
                    name: r.role_name().unwrap_or_default().to_string(),
                });
            }
            match page.next_token() {
                Some(t) => next = Some(t.to_string()),
                None => break,
            }
        }
        Ok(out)
    }
}
```

Add the `list_secrets` method to the existing `impl SecretsApi for AwsSecretsApi`. The per-call client is built exactly as `get_secret_value` already does (injected `Credential` only — ADR 0010 §10). Add this method inside that impl block:

```rust
    async fn list_secrets(
        &self,
        cred: &Credential,
        region: &str,
    ) -> Result<Vec<SecretSummary>, SessionError> {
        let creds = aws_sdk_secretsmanager::config::Credentials::new(
            cred.access_key_id(),
            cred.secret_access_key(),
            Some(cred.session_token().to_string()),
            None,
            "janitor",
        );
        let conf = aws_sdk_secretsmanager::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(aws_sdk_secretsmanager::config::Region::new(region.to_string()))
            .credentials_provider(creds)
            .build();
        let client = aws_sdk_secretsmanager::Client::from_conf(conf);

        let mut out = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut req = client.list_secrets();
            if let Some(t) = &next {
                req = req.next_token(t);
            }
            let page = req.send().await.map_err(map_secret_err)?;
            for s in page.secret_list() {
                out.push(SecretSummary {
                    name: s.name().unwrap_or_default().to_string(),
                    arn: s.arn().unwrap_or_default().to_string(),
                });
            }
            match page.next_token() {
                Some(t) => next = Some(t.to_string()),
                None => break,
            }
        }
        Ok(out)
    }
```

- [ ] **Step 4: Build and test**

Run: `cargo build -p janitor-aws`
Expected: PASS. Compile errors are almost always SDK-signature mismatches (the §5 boundary) — align with `cargo doc -p aws-sdk-sso --open` / `aws-sdk-secretsmanager`. Do **not** add `unwrap()` on network results; keep the `map_*_err` mapping.

Run: `cargo test -p janitor-aws --lib wire`
Expected: PASS — the existing `fake_role_client...` test plus the two new ones (`summaries_expose_keys_and_labels`, `fake_secrets_api_scripts_list_outcomes`).

- [ ] **Step 5: Commit**

```bash
git add janitor-aws/src/wire.rs janitor-aws/src/aws_impl.rs
git commit -m "feat(aws): ListAccounts/Roles/Secrets seam + SDK-free summaries (ADR 0011)"
```

---

## Task 4: Auth fix — `issuerUrl` + endpoint-from-response

**Files:**
- Modify: `janitor-aws/src/wire.rs`
- Modify: `janitor-aws/src/aws_impl.rs`
- Modify: `janitor-aws/src/authenticator.rs`
- Modify: `janitor-aws/src/bin/live-verify.rs`

This corrects untested shell that has never run live (ADR 0011 / resolves the ADR 0010 §2a `issuerUrl` verify item). `RegisterClient` is called with `issuerUrl = <start URL>`; the `/authorize` endpoint is read from the response instead of a flag. The binary is minimally updated to keep compiling and to give a **standalone Milestone-B checkpoint** (sign in with just `--start-url`, no discovery yet).

- [ ] **Step 1: Add `authorization_endpoint` to `ClientRegistration` and change the trait signature**

In `janitor-aws/src/wire.rs`, extend `ClientRegistration`:

```rust
/// A public-client registration from `RegisterClient`. The `client_secret` is a
/// public-client secret (not confidential — PKCE is what protects the flow), but
/// we still hold it as an opaque string and never log it.
#[derive(Clone)]
pub struct ClientRegistration {
    pub client_id: String,
    pub client_secret: String,
    /// The `/authorize` endpoint AWS returns for this registration (ADR 0011);
    /// used to build the browser URL instead of a hardcoded host.
    pub authorization_endpoint: String,
}
```

Change the `OidcClient::register_client` signature to take the issuer URL:

```rust
    /// `RegisterClient` for a public client with the org `issuer_url`, the given
    /// loopback redirect URIs, and the `authorization_code` + `refresh_token`
    /// grants. The returned registration carries the authorize endpoint.
    async fn register_client(
        &self,
        issuer_url: &str,
        redirect_uris: &[String],
    ) -> Result<ClientRegistration, SignInError>;
```

- [ ] **Step 2: Update the real `register_client` (shell)**

In `janitor-aws/src/aws_impl.rs`, replace `AwsOidcClient::register_client` so it passes `issuer_url` and reads the endpoint from the response:

```rust
    async fn register_client(
        &self,
        issuer_url: &str,
        redirect_uris: &[String],
    ) -> Result<ClientRegistration, SignInError> {
        let mut req = self
            .inner
            .register_client()
            .client_name("janitor")
            .client_type("public")
            .issuer_url(issuer_url)
            .grant_types("authorization_code")
            .grant_types("refresh_token")
            .scopes("sso:account:access");
        for uri in redirect_uris {
            req = req.redirect_uris(uri.clone());
        }
        let out = req.send().await.map_err(|_| SignInError::Sdk {
            context: "RegisterClient".into(),
        })?;
        Ok(ClientRegistration {
            client_id: out.client_id().unwrap_or_default().to_string(),
            client_secret: out.client_secret().unwrap_or_default().to_string(),
            authorization_endpoint: out.authorization_endpoint().unwrap_or_default().to_string(),
        })
    }
```

> §5 boundary: `RegisterClientFluentBuilder::issuer_url` and `RegisterClientOutput::authorization_endpoint() -> Option<&str>` confirmed in `aws-sdk-ssooidc 1.102`. If `issuer_url` is rejected at runtime against the live org, that is a Milestone-B finding (the dedicated Issuer URL vs. start URL question, ADR 0011 open items).

- [ ] **Step 3: Update `Authenticator` to take the issuer URL and read the endpoint from the registration**

In `janitor-aws/src/authenticator.rs`, replace the struct, constructor, and the relevant part of `sign_in_once`:

```rust
/// Drives a full Identity Center browser Sign-in.
pub struct Authenticator {
    oidc: Arc<dyn OidcClient>,
    /// The org's IAM Identity Center start/issuer URL (e.g.
    /// `https://my-org.awsapps.com/start`). Passed to `RegisterClient` as
    /// `issuerUrl`; the `/authorize` endpoint comes back in the registration.
    issuer_url: String,
}

impl Authenticator {
    pub fn new(oidc: Arc<dyn OidcClient>, issuer_url: String) -> Self {
        Authenticator { oidc, issuer_url }
    }

    /// Run the flow once, returning a fresh SSO token.
    pub async fn sign_in_once(&self) -> Result<SsoToken, SignInError> {
        // 1. Register a public client (issuer-scoped) for our loopback redirects.
        let uris = redirect_uris();
        let registration = self.oidc.register_client(&self.issuer_url, &uris).await?;

        // 2. Bind a loopback port from the registered set, THEN build the URL
        //    with that exact redirect_uri (ADR 0010 §7 ordering).
        let (listener, redirect_uri) = bind_first_free().await?;
        let pkce = pkce::generate();
        let csrf = state::generate();
        let authorize_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&scopes=sso:account:access",
            registration.authorization_endpoint,
            urlencode(&registration.client_id),
            urlencode(&redirect_uri),
            urlencode(&pkce.challenge),
            urlencode(&csrf),
        );

        // 3. Open the browser and wait for the redirect.
        open_browser(&authorize_url)?;
        let query = wait_for_redirect(listener, SIGN_IN_TIMEOUT).await?;

        // 4. Verify CSRF state BEFORE using the code.
        let returned_state = query_param(&query, "state").unwrap_or_default();
        if !state::matches(&csrf, &returned_state) {
            return Err(SignInError::StateMismatch);
        }
        let code = query_param(&query, "code").ok_or(SignInError::TokenEndpoint)?;

        // 5. Exchange the code (+ PKCE verifier) for the SSO token.
        self.oidc
            .create_token(TokenExchange {
                registration: &registration,
                code: &code,
                code_verifier: &pkce.verifier,
                redirect_uri: &redirect_uri,
            })
            .await
    }
}
```

(The `urlencode` function and its test below it are unchanged.)

- [ ] **Step 4: Minimally update the binary to keep it compiling (checkpoint)**

In `janitor-aws/src/bin/live-verify.rs`, change only the endpoint flag to a start-URL flag (the full guided rework is Task 5). Update the header doc comment's example line from `--authorize-endpoint https://oidc.<region>.amazonaws.com/authorize` to `--start-url https://<org>.awsapps.com/start`, then change the two relevant lines in `main`:

Replace:

```rust
    let authorize_endpoint = arg("--authorize-endpoint").expect("--authorize-endpoint");
```

with:

```rust
    let start_url = arg("--start-url").expect("--start-url");
```

and replace:

```rust
    let authenticator = Arc::new(Authenticator::new(oidc, authorize_endpoint));
```

with:

```rust
    let authenticator = Arc::new(Authenticator::new(oidc, start_url));
```

- [ ] **Step 5: Build + test the whole crate**

Run: `cargo build -p janitor-aws --all-targets`
Expected: PASS (the binary compiles against the new `Authenticator::new`).
Run: `cargo test -p janitor-aws --lib`
Expected: PASS (no logic regressions; `authenticator`'s `urlencode` test still passes).

- [ ] **Step 6: Commit**

```bash
git add janitor-aws/src/wire.rs janitor-aws/src/aws_impl.rs janitor-aws/src/authenticator.rs janitor-aws/src/bin/live-verify.rs
git commit -m "feat(aws): pass issuerUrl + read authorizationEndpoint from RegisterClient (ADR 0011)"
```

---

## Task 5: Guided binary — Config-driven sign-in + discovery + remembered pick

**Files:**
- Modify: `janitor-aws/src/bin/live-verify.rs`

The guided flow. All shell (stdin + real adapters + browser), verified by compile and Milestone B; every testable decision already lives in `select.rs` / core `Config`. Flags become optional overrides.

- [ ] **Step 1: Rewrite the binary**

Replace the entire contents of `janitor-aws/src/bin/live-verify.rs` with:

```rust
//! Guided sign-in + live verification harness (ADR 0011, ADR 0010 §5 Milestone B).
//! Run by a human against a real Identity Center org:
//!
//!   cargo run -p janitor-aws --bin live-verify
//!
//! First run prompts once for the org (SSO start URL, SSO region, secret region)
//! and saves them to Config. Then the browser opens; after sign-in the tool
//! auto-discovers the account, role, and secret (auto-picking when there is only
//! one, offering the remembered pick as the default otherwise), fetches the
//! chosen secret, and prints a MASKED single-environment matrix (never a Value).
//! The chosen account/role/secret is remembered for next time.
//!
//! Optional overrides skip a step: `--start-url`, `--sso-region`,
//! `--secret-region`, `--account-id`, `--role`, `--secret-id`.

use std::env;
use std::io::{self, Write};
use std::sync::Arc;

use janitor_aws::authenticator::Authenticator;
use janitor_aws::aws_impl::{AwsOidcClient, AwsRoleClient, AwsSecretsApi};
use janitor_aws::broker::CredentialBroker;
use janitor_aws::secrets::SecretsClient;
use janitor_aws::select::{resolve, Chooser};
use janitor_aws::source::AuthenticatedSource;
use janitor_aws::types::SystemClock;
use janitor_aws::wire::{AccountCatalog, SecretsApi};
use janitor_core::compare::Comparison;
use janitor_core::config::{Config, Mapping};
use janitor_core::view::project;

fn arg(flag: &str) -> Option<String> {
    let args: Vec<String> = env::args().collect();
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Read a non-empty line of free text for `prompt` from stdin.
fn prompt_line(prompt: &str) -> String {
    loop {
        print!("{prompt}: ");
        io::stdout().flush().ok();
        let mut s = String::new();
        io::stdin().read_line(&mut s).expect("read stdin");
        let s = s.trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }
}

/// The real `Chooser`: prints a numbered menu and reads the choice from stdin.
struct StdinChooser;
impl Chooser for StdinChooser {
    fn choose(&self, labels: &[String], default: Option<usize>) -> usize {
        loop {
            println!();
            for (i, label) in labels.iter().enumerate() {
                let marker = if Some(i) == default { " (default)" } else { "" };
                println!("  [{}] {label}{marker}", i + 1);
            }
            let hint = match default {
                Some(i) => format!("choose 1-{} [default {}]", labels.len(), i + 1),
                None => format!("choose 1-{}", labels.len()),
            };
            print!("{hint}: ");
            io::stdout().flush().ok();
            let mut s = String::new();
            io::stdin().read_line(&mut s).expect("read stdin");
            let s = s.trim();
            if s.is_empty() {
                if let Some(i) = default {
                    return i;
                }
                continue;
            }
            if let Ok(n) = s.parse::<usize>() {
                if (1..=labels.len()).contains(&n) {
                    return n - 1;
                }
            }
            println!("  invalid choice, try again");
        }
    }
}

#[tokio::main]
async fn main() {
    // 1. Load Config; prompt+save any missing org fields (flags override).
    let mut config = Config::load().unwrap_or_default();

    if let Some(v) = arg("--start-url") {
        config.sso_start_url = v;
    }
    if config.sso_start_url.is_empty() {
        config.sso_start_url = prompt_line("IAM Identity Center start URL");
    }
    if let Some(v) = arg("--sso-region") {
        config.sso_region = v;
    }
    if config.sso_region.is_empty() {
        config.sso_region = prompt_line("SSO region (e.g. us-east-1)");
    }
    if let Some(v) = arg("--secret-region") {
        config.secret_region = v;
    }
    if config.secret_region.is_empty() {
        config.secret_region = prompt_line("Secrets Manager region to browse");
    }
    config.save().expect("save config");

    let chooser = StdinChooser;
    let remembered = config.last_pick.clone();

    // 2. Build the real adapters (no ambient credentials — ADR 0010 §10).
    let oidc = Arc::new(AwsOidcClient::new(config.sso_region.clone()).await);
    let role_client = Arc::new(AwsRoleClient::new(config.sso_region.clone()).await);
    let secrets_api = Arc::new(AwsSecretsApi::new());
    let clock = Arc::new(SystemClock);
    let authenticator = Arc::new(Authenticator::new(oidc, config.sso_start_url.clone()));

    // 3. Sign in (opens the browser).
    println!("Signing in (a browser tab will open)...");
    let token = authenticator.sign_in_once().await.expect("sign-in");
    println!("Signed in. SSO token acquired (held in memory only).");

    // 4. Discover account (override flag short-circuits the listing).
    let account_id = match arg("--account-id") {
        Some(id) => id,
        None => {
            let accounts = role_client.list_accounts(&token).await.expect("list accounts");
            let acct = resolve(
                accounts,
                remembered.as_ref().map(|m| m.account_id.as_str()),
                &chooser,
                "accounts",
            )
            .expect("choose account");
            println!("Account: {} ({})", acct.name, acct.id);
            acct.id
        }
    };

    // 5. Discover role for that account.
    let role = match arg("--role") {
        Some(r) => r,
        None => {
            let roles = role_client
                .list_account_roles(&token, &account_id)
                .await
                .expect("list roles");
            let role = resolve(
                roles,
                remembered.as_ref().map(|m| m.permission_set.as_str()),
                &chooser,
                "roles",
            )
            .expect("choose role");
            println!("Role: {}", role.name);
            role.name
        }
    };

    // 6. Mint a role credential for (account, role, secret-region), then list
    //    secrets in that region and pick one (override flag short-circuits).
    let secret_region = config.secret_region.clone();
    let probe = Mapping {
        environment: "live".into(),
        account_id: account_id.clone(),
        region: secret_region.clone(),
        secret_id: String::new(), // unused for minting; broker keys on acct|role|region
        permission_set: role.clone(),
    };
    let broker = CredentialBroker::new(token, role_client.clone(), clock.clone());
    let cred = broker
        .credentials_for(&probe)
        .await
        .expect("mint role credential");

    let secret_id = match arg("--secret-id") {
        Some(s) => s,
        None => {
            let secrets = secrets_api
                .list_secrets(&cred, &secret_region)
                .await
                .expect("list secrets");
            let secret = resolve(
                secrets,
                remembered.as_ref().map(|m| m.secret_id.as_str()),
                &chooser,
                "secrets",
            )
            .expect("choose secret");
            println!("Secret: {}", secret.name);
            // Use the ARN as the stable id; GetSecretValue accepts name or ARN.
            secret.arn
        }
    };

    // 7. Assemble the full Mapping and fetch through the facade.
    let mapping = Mapping {
        environment: "live".into(),
        account_id,
        region: secret_region,
        secret_id,
        permission_set: role,
    };
    let secrets = SecretsClient::new(secrets_api);
    let mut source =
        AuthenticatedSource::new(broker, secrets, authenticator, role_client, clock);
    let shape = source.fetch(&mapping).await.expect("fetch");

    // 8. Output discipline: project to a MASKED matrix, never print a Value.
    let sets = vec![(mapping.environment.clone(), shape)];
    let comparison = Comparison::build(&sets);
    let view = project(&comparison);
    println!("\nMASKED MATRIX (single environment):");
    println!("environments: {:?}", view.environments);
    for row in &view.rows {
        println!("  {} [{:?}] -> {:?}", row.name, row.state, row.cells);
    }

    // 9. Remember this pick for next time.
    config.last_pick = Some(mapping);
    config.save().expect("save config");
    println!("\nRemembered this pick (account/role/secret) for next run.");

    println!("\n--- ADR 0010/0011 verify checklist (force these by hand) ---");
    println!("[ ] issuerUrl accepted: confirm the start URL works as RegisterClient issuerUrl (else try the Issuer URL)");
    println!("[ ] endpoint-from-response: confirm sign-in works with NO --authorize-endpoint flag");
    println!("[ ] single account/role auto-picks; multiple shows a menu with the remembered default");
    println!("[ ] token-expiry → re-Sign-in: confirm ONE browser reopen, no loop");
    println!("[ ] access-denied: point --secret-id at a denied secret, confirm AccessDenied (not a loop)");
    println!("[ ] not-found: point --secret-id at a missing name, confirm NotFound");
    println!("[ ] confirm roleCredentials.expiration is read (not a hardcoded 1h)");
}
```

> Design note (kept honest): the discovery credential is minted via the broker (`credentials_for` on a probe Mapping keyed by `account|role|region`); the same broker is then moved into `AuthenticatedSource`, so the final `fetch` reuses the cached credential (no second mint). `secret_id` is left empty on the probe because the broker's cache key ignores it.

- [ ] **Step 2: Build the binary**

Run: `cargo build -p janitor-aws --bin live-verify`
Expected: PASS. Errors are SDK/signature mismatches at the §5 boundary or a missing trait import — bring `AccountCatalog` / `SecretsApi` into scope (already in the `use` list above) so the trait methods resolve on the concrete `Arc<AwsRoleClient>` / `Arc<AwsSecretsApi>`.

- [ ] **Step 3: Commit**

```bash
git add janitor-aws/src/bin/live-verify.rs
git commit -m "feat(aws): guided sign-in — Config-driven org, discovery, remembered pick (ADR 0011)"
```

---

## Task 6: Workspace green + docs (Milestone A close for this slice)

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

- [ ] **Step 1: Confirm the whole workspace is green**

Run: `cargo fmt --all -- --check`
Expected: PASS (run `cargo fmt --all` first if not).
Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: PASS. Fix any clippy findings in the new code (a likely one: `clippy::new_without_default` is already handled for `AwsSecretsApi`; the `StdinChooser` unit struct needs none).
Run: `cargo test --workspace`
Expected: PASS — core (now incl. the new Config tests) + janitor-aws (incl. `select` and the new `wire` tests). Confirm no existing test's asserted behavior changed beyond the two named additive edits (Task 1 `sample()`, Task 3 `FakeSecretsApi`).

- [ ] **Step 2: Confirm the core coverage gate still passes**

Run: `cargo llvm-cov -p janitor-core --fail-under-lines 80`
Expected: PASS — core gained only tested code (the two Config fields with new tests), so coverage stays ≥80%.

- [ ] **Step 3: Update the CLAUDE.md status blurb**

In `CLAUDE.md`, update the status paragraph to note the guided sign-in landed: `live-verify` is now a guided flow (browser → log in → auto-discovered account/role/secret → masked matrix), the org + last pick persist in `Config`, the `--authorize-endpoint` flag is gone (endpoint read from `RegisterClient`), and Milestone B (live confirmation of `issuerUrl` + discovery error shapes) remains the open gate. Bump the ADR range to 0001–0011. Keep the one-paragraph style.

- [ ] **Step 4: Update the README status + commands**

In `README.md`: the Identity Center row of the status table gains "+ guided sign-in (auto-discovered account/role/secret, remembered org)"; the `live-verify` command example drops `--authorize-endpoint` and shows the no-flag form `cargo run -p janitor-aws --bin live-verify`; add ADR 0011 to the ADR list.

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: guided sign-in landed — Config-remembered org + auto-discovery (ADR 0011)"
```

---

## Self-review checklist (for the executor's awareness)

- **Spec coverage vs. the 2026-05-31 spec / ADR 0011:** auth fix (issuerUrl + endpoint-from-response, drop `--authorize-endpoint`) → Task 4; discovery seam (ListAccounts/Roles/Secrets behind traits, SDK-free summaries) → Task 3; pure 0/1/many+remembered selection → Task 2 (`plan_selection`); the `Chooser` seam + `resolve` (strengthening refinement) → Task 2; `Config.secret_region` + `last_pick` (backward-compatible) → Task 1; reworked `live-verify` with optional override flags + remembered pick → Tasks 4–5; output discipline (masked `project()`, no Value) → Task 5; "binary-level emptiness, no new SessionError" → `DiscoverError` in Task 2.
- **No existing test's behavior changed silently:** the only edits to existing tests are additive and named — Task 1 extends `sample()` and strengthens `default_config_is_empty` (new assertions, none removed); Task 3 adds `list_secrets` to `FakeSecretsApi` (new arm, existing `get_secret_value` untouched). Both are called out per the user's global rule.
- **Type consistency:** `Selectable`/`SelectionPlan`/`plan_selection`/`Chooser`/`DiscoverError`/`resolve` (Task 2) are used unchanged in Tasks 3 (summary impls) and 5 (binary); `AccountSummary{id,name}`/`RoleSummary{name}`/`SecretSummary{name,arn}` and `AccountCatalog::{list_accounts,list_account_roles}` + `SecretsApi::list_secrets` (Task 3) are consumed verbatim in Task 5; `ClientRegistration.authorization_endpoint` + `register_client(issuer_url, uris)` + `Authenticator::new(oidc, issuer_url)` (Task 4) match `Config.sso_start_url` (Task 1) at the call site; `Mapping` fields and `Comparison::build(&[(String, SecretShape)])` / `project()` match `janitor-core` as read at planning time.
- **Known soft spots (SDK boundary, Tasks 3–5):** exact SDK setter/getter names (`issuer_url`, `authorization_endpoint`, `account_list`/`role_list`/`secret_list`, `next_token`) and whether `*_list()` is a slice or `Option` must be confirmed against the installed crates — the ADR 0010 §5 untested shell, not a logic gap. The `issuerUrl`-vs-Issuer-URL question and the list-op error/pagination shapes are the new Milestone-B verify items (ADR 0011).
```
