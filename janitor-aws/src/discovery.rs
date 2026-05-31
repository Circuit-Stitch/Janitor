//! `Discovery` (ADR 0013): the single, presenter-agnostic step-machine that
//! drives the guided account → role → secret walk and yields one `Mapping`.
//!
//! It knows nothing of stdin, channels, or Slint — `start()`/`advance()` return
//! a `Step` describing either what to ask next or a terminal outcome, and each
//! consumer writes a thin presenter. The interleaved sequencing (which step is
//! next, auto-pick collapsing, the per-step listing + credential mint) is the
//! real logic that ADR 0003 keeps in a tested crate; it reuses the pure
//! `select::plan_selection` to collapse `0/1` choices and pre-select a
//! remembered default on `many`. Fully tested against `wire::fakes`.

use std::sync::Arc;

use janitor_core::config::Mapping;

use crate::select::{plan_selection, Selectable, SelectionPlan};
use crate::session::FetchFailReason;
use crate::types::{Credential, SsoToken};
use crate::wire::SecretsApi;
use crate::wire::{
    AccountCatalog, AccountSummary, RoleCredentialClient, RoleSummary, SecretSummary,
};

/// Which step of the walk produced an empty choice list. Carried by
/// `Step::Empty` so the presenter can say "No accounts/roles/secrets you can
/// access" without the machine knowing about phrasing (ADR 0013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum What {
    Accounts,
    Roles,
    Secrets,
}

/// What the wizard is currently asking, or its terminal outcome (ADR 0013).
/// `Ask` is presenter-ready: `choices` are the `Selectable::label` lines to
/// render in list order and `default` is the index to pre-select (the remembered
/// pick, if still present); the typed items stay inside the machine so the user's
/// pick comes back as a bare index via [`Discovery::advance`]. `what` lets the
/// presenter title the list without knowing the variant. `Done` carries the
/// fully-formed Mapping ready to append. `Empty`/`Failed` are masked terminal
/// states (no SDK text).
#[derive(Debug)]
pub enum Step {
    Ask {
        what: What,
        choices: Vec<String>,
        default: Option<usize>,
    },
    Done(Mapping),
    Empty(What),
    Failed(FetchFailReason),
    /// The SSO token is dead and could not be silently refreshed — a fresh
    /// browser Sign-in is required. A distinct terminal state (not `Failed`) so
    /// the presenter routes back to Sign-in rather than offering Back/Close
    /// (ADR 0013).
    Reauth,
}

/// The choices the machine listed for the step it is currently blocked on, so
/// [`Discovery::advance`] can resolve a chosen index back to the item without
/// re-listing.
enum Awaiting {
    Account(Vec<AccountSummary>),
    Role(Vec<RoleSummary>),
    Secret(Vec<SecretSummary>),
}

/// The guided discovery walk for one Environment. Holds the SSO token and the
/// AWS seams; accumulates the account/role/credential picks as it advances.
pub struct Discovery {
    token: Arc<SsoToken>,
    catalog: Arc<dyn AccountCatalog>,
    role_client: Arc<dyn RoleCredentialClient>,
    secrets: Arc<dyn SecretsApi>,
    /// Environment name being added (typed by the user; not discovered).
    environment: String,
    /// Resolved browse region (`config.secret_region` else `sso_region`).
    region: String,
    /// The previous guided pick, offered as the default on a `many` step.
    remembered: Option<Mapping>,
    account: Option<AccountSummary>,
    role: Option<RoleSummary>,
    cred: Option<Credential>,
    awaiting: Option<Awaiting>,
}

impl Discovery {
    /// Build a walk. No I/O happens until [`start`](Self::start).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        environment: String,
        region: String,
        token: Arc<SsoToken>,
        catalog: Arc<dyn AccountCatalog>,
        role_client: Arc<dyn RoleCredentialClient>,
        secrets: Arc<dyn SecretsApi>,
        remembered: Option<Mapping>,
    ) -> Self {
        Discovery {
            token,
            catalog,
            role_client,
            secrets,
            environment,
            region,
            remembered,
            account: None,
            role: None,
            cred: None,
            awaiting: None,
        }
    }

    /// Begin the walk: list accounts and auto-collapse singleton steps until the
    /// first `many` choice (an `Ask`) or a terminal outcome.
    pub async fn start(&mut self) -> Step {
        self.resume().await
    }

    /// Feed back the user's chosen index for the step the machine is blocked on,
    /// then continue collapsing singletons until the next `Ask` or a terminal
    /// outcome. Out-of-range indices are clamped (mirrors `select::resolve`).
    pub async fn advance(&mut self, choice: usize) -> Step {
        match self.awaiting.take() {
            Some(Awaiting::Account(items)) => {
                self.account = Some(pick(items, choice));
                self.resume().await
            }
            Some(Awaiting::Role(items)) => {
                self.role = Some(pick(items, choice));
                self.resume().await
            }
            Some(Awaiting::Secret(items)) => {
                let secret = pick(items, choice);
                Step::Done(self.build_mapping(&secret))
            }
            // advance() with nothing pending is a presenter bug; re-drive so we
            // never wedge (resume is idempotent on already-made picks).
            None => self.resume().await,
        }
    }

    /// The shared forward drive: process whichever step is not yet decided,
    /// auto-picking singletons and falling through to the next, stopping at the
    /// first `Ask`/terminal state.
    async fn resume(&mut self) -> Step {
        if self.account.is_none() {
            let items = match self.catalog.list_accounts(&self.token).await {
                Ok(v) => v,
                Err(e) => return terminal_for(&e),
            };
            match plan_selection(&items, self.remembered_account()) {
                SelectionPlan::Empty => return Step::Empty(What::Accounts),
                SelectionPlan::Ask { default } => {
                    let step = ask(What::Accounts, &items, default);
                    self.awaiting = Some(Awaiting::Account(items));
                    return step;
                }
                SelectionPlan::Auto(i) => self.account = Some(pick(items, i)),
            }
        }

        if self.role.is_none() {
            let account_id = self.account.as_ref().unwrap().id.clone();
            let items = match self
                .catalog
                .list_account_roles(&self.token, &account_id)
                .await
            {
                Ok(v) => v,
                Err(e) => return terminal_for(&e),
            };
            match plan_selection(&items, self.remembered_role()) {
                SelectionPlan::Empty => return Step::Empty(What::Roles),
                SelectionPlan::Ask { default } => {
                    let step = ask(What::Roles, &items, default);
                    self.awaiting = Some(Awaiting::Role(items));
                    return step;
                }
                SelectionPlan::Auto(i) => self.role = Some(pick(items, i)),
            }
        }

        // Mint one role Credential for the chosen account+role+region so we can
        // list secrets. A dead token / policy refusal surfaces as `Failed`.
        if self.cred.is_none() {
            let account_id = self.account.as_ref().unwrap().id.clone();
            let role = self.role.as_ref().unwrap().name.clone();
            match self
                .role_client
                .get_role_credentials(&self.token, &account_id, &role, &self.region)
                .await
            {
                Ok(c) => self.cred = Some(c),
                Err(e) => return terminal_for(&e),
            }
        }

        let cred = self.cred.as_ref().unwrap();
        let items = match self.secrets.list_secrets(cred, &self.region).await {
            Ok(v) => v,
            Err(e) => return terminal_for(&e),
        };
        match plan_selection(&items, self.remembered_secret()) {
            SelectionPlan::Empty => Step::Empty(What::Secrets),
            SelectionPlan::Ask { default } => {
                let step = ask(What::Secrets, &items, default);
                self.awaiting = Some(Awaiting::Secret(items));
                step
            }
            SelectionPlan::Auto(i) => {
                let secret = pick(items, i);
                Step::Done(self.build_mapping(&secret))
            }
        }
    }

    fn remembered_account(&self) -> Option<&str> {
        self.remembered.as_ref().map(|m| m.account_id.as_str())
    }
    fn remembered_role(&self) -> Option<&str> {
        self.remembered.as_ref().map(|m| m.permission_set.as_str())
    }
    fn remembered_secret(&self) -> Option<&str> {
        self.remembered.as_ref().map(|m| m.secret_id.as_str())
    }

    /// Assemble the completed Mapping. `secret_id` is the ARN (the stable id);
    /// `region` is the resolved browse region; `permission_set` is the role.
    fn build_mapping(&self, secret: &SecretSummary) -> Mapping {
        let account = self.account.as_ref().expect("account chosen before Done");
        let role = self.role.as_ref().expect("role chosen before Done");
        Mapping {
            environment: self.environment.clone(),
            account_id: account.id.clone(),
            region: self.region.clone(),
            secret_id: secret.arn.clone(),
            permission_set: role.name.clone(),
        }
    }
}

/// Build a presenter-ready `Step::Ask`: project the listed items to their
/// `Selectable::label` lines (in list order, so the returned index maps straight
/// back to the kept items) and carry the remembered `default`.
fn ask<T: Selectable>(what: What, items: &[T], default: Option<usize>) -> Step {
    Step::Ask {
        what,
        choices: items.iter().map(|it| it.label()).collect(),
        default,
    }
}

/// Classify a `SessionError` into the right terminal `Step`. `ReauthRequired`
/// (a dead token the facade could not silently refresh) becomes `Reauth` so the
/// presenter routes back to Sign-in; everything else becomes a masked,
/// retryable `Failed` carrying only the tested `FetchFailReason` (no SDK text —
/// THREAT-MODEL).
fn terminal_for(e: &crate::error::SessionError) -> Step {
    match e {
        crate::error::SessionError::ReauthRequired => Step::Reauth,
        _ => Step::Failed(e.into()),
    }
}

/// Resolve a chosen index against a listed set, clamping out-of-range to the
/// last item (a misbehaving presenter must never panic the walk).
fn pick<T>(mut items: Vec<T>, choice: usize) -> T {
    let i = choice.min(items.len() - 1);
    items.swap_remove(i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fakes::{CredSpec, FakeAccountCatalog, FakeRoleClient, FakeSecretsApi};
    use std::time::{Duration, SystemTime};

    fn token() -> Arc<SsoToken> {
        Arc::new(SsoToken::new(
            "session".into(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(28800),
        ))
    }
    fn account(id: &str, name: &str) -> AccountSummary {
        AccountSummary {
            id: id.into(),
            name: name.into(),
        }
    }
    fn role(name: &str) -> RoleSummary {
        RoleSummary { name: name.into() }
    }
    fn secret(name: &str, arn: &str) -> SecretSummary {
        SecretSummary {
            name: name.into(),
            arn: arn.into(),
        }
    }
    fn cred_ok() -> Result<CredSpec, crate::error::SessionError> {
        Ok(CredSpec {
            expires_in: Duration::from_secs(3600),
            tag: "t",
        })
    }

    #[tokio::test]
    async fn single_account_role_secret_auto_picks_to_done() {
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111111111111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Ok(vec![secret(
            "myapp/prod",
            "arn:aws:secretsmanager:us-west-2:111111111111:secret:myapp/prod",
        )])]));

        let mut d = Discovery::new(
            "prod".into(),
            "us-west-2".into(),
            token(),
            cat,
            rolec.clone(),
            api,
            None,
        );

        let step = d.start().await;
        let Step::Done(m) = step else {
            panic!("expected Done, got {step:?}");
        };
        assert_eq!(m.environment, "prod");
        assert_eq!(m.account_id, "111111111111");
        assert_eq!(m.region, "us-west-2");
        assert_eq!(m.permission_set, "ReadOnly");
        assert_eq!(
            m.secret_id, "arn:aws:secretsmanager:us-west-2:111111111111:secret:myapp/prod",
            "secret_id is the ARN, not the friendly name"
        );
        assert_eq!(rolec.call_count(), 1, "minted exactly once");
    }

    #[tokio::test]
    async fn many_accounts_ask_carries_labels_and_remembered_default() {
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod"), account("222", "Staging")])],
            vec![Ok(vec![role("ReadOnly")])],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Ok(vec![secret(
            "s", "arn:s",
        )])]));
        // A prior guided pick chose account 222; it should pre-select.
        let remembered = Mapping {
            environment: "live".into(),
            account_id: "222".into(),
            region: "us-east-1".into(),
            secret_id: "arn:old".into(),
            permission_set: "ReadOnly".into(),
        };

        let mut d = Discovery::new(
            "staging".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec,
            api,
            Some(remembered),
        );

        let Step::Ask {
            what,
            choices,
            default,
        } = d.start().await
        else {
            panic!("expected Ask");
        };
        assert_eq!(what, What::Accounts);
        assert_eq!(
            choices,
            vec!["Prod (111)".to_string(), "Staging (222)".to_string()],
            "choices are the presenter labels, in list order"
        );
        assert_eq!(
            default,
            Some(1),
            "remembered account 222 pre-selects index 1"
        );
    }

    #[tokio::test]
    async fn many_accounts_asks_first_without_over_fetching_then_advances_to_done() {
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod"), account("222", "Staging")])],
            vec![Ok(vec![role("ReadOnly")])],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Ok(vec![secret(
            "myapp/staging",
            "arn:secret:myapp/staging",
        )])]));

        let mut d = Discovery::new(
            "staging".into(),
            "us-east-1".into(),
            token(),
            cat.clone(),
            rolec.clone(),
            api,
            None,
        );

        // start() lists accounts, sees >1, and stops at the Ask — it must not
        // have listed roles, minted a credential, or listed secrets yet.
        let step = d.start().await;
        let Step::Ask { what, choices, .. } = step else {
            panic!("expected Ask, got {step:?}");
        };
        assert_eq!(what, What::Accounts);
        assert_eq!(choices.len(), 2);
        assert_eq!(
            cat.role_call_count(),
            0,
            "must not list roles before the account is chosen"
        );
        assert_eq!(
            rolec.call_count(),
            0,
            "must not mint before the account is chosen"
        );

        // Choosing the second account continues the (now-singleton) walk to Done.
        let step = d.advance(1).await;
        let Step::Done(m) = step else {
            panic!("expected Done, got {step:?}");
        };
        assert_eq!(m.account_id, "222", "advanced to the chosen account");
        assert_eq!(m.permission_set, "ReadOnly");
        assert_eq!(m.secret_id, "arn:secret:myapp/staging");
    }

    #[tokio::test]
    async fn single_account_then_many_roles_asks_roles_with_remembered_default() {
        // One account auto-picks; the role step then has many → Ask roles. The
        // credential must NOT be minted yet (no role chosen).
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly"), role("Admin")])],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Ok(vec![secret(
            "s", "arn:s",
        )])]));
        let remembered = Mapping {
            environment: "live".into(),
            account_id: "111".into(),
            region: "us-east-1".into(),
            secret_id: "arn:old".into(),
            permission_set: "Admin".into(),
        };
        let mut d = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec.clone(),
            api,
            Some(remembered),
        );

        let Step::Ask {
            what,
            choices,
            default,
        } = d.start().await
        else {
            panic!("expected Ask roles");
        };
        assert_eq!(what, What::Roles);
        assert_eq!(choices, vec!["ReadOnly".to_string(), "Admin".to_string()]);
        assert_eq!(
            default,
            Some(1),
            "remembered role Admin pre-selects index 1"
        );
        assert_eq!(
            rolec.call_count(),
            0,
            "must not mint a credential before the role is chosen"
        );

        // Choosing ReadOnly (not the default) advances through the lone secret.
        let Step::Done(m) = d.advance(0).await else {
            panic!("expected Done");
        };
        assert_eq!(m.account_id, "111");
        assert_eq!(m.permission_set, "ReadOnly");
    }

    #[tokio::test]
    async fn many_secrets_asks_secrets_and_chosen_secret_arn_lands_in_mapping() {
        // Singleton account+role auto-pick and the credential is minted; the
        // secret step then has many → Ask secrets, labelled by friendly name.
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Ok(vec![
            secret("myapp/a", "arn:a"),
            secret("myapp/b", "arn:b"),
        ])]));
        let remembered = Mapping {
            environment: "live".into(),
            account_id: "111".into(),
            region: "us-east-1".into(),
            secret_id: "arn:b".into(),
            permission_set: "ReadOnly".into(),
        };
        let mut d = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec.clone(),
            api,
            Some(remembered),
        );

        let Step::Ask {
            what,
            choices,
            default,
        } = d.start().await
        else {
            panic!("expected Ask secrets");
        };
        assert_eq!(what, What::Secrets);
        assert_eq!(
            choices,
            vec!["myapp/a".to_string(), "myapp/b".to_string()],
            "secrets are labelled by friendly name, not ARN"
        );
        assert_eq!(
            default,
            Some(1),
            "remembered secret arn:b pre-selects index 1"
        );
        assert_eq!(
            rolec.call_count(),
            1,
            "credential minted once to list secrets"
        );

        // Choosing index 0 → the Done mapping carries that secret's ARN.
        let Step::Done(m) = d.advance(0).await else {
            panic!("expected Done");
        };
        assert_eq!(
            m.secret_id, "arn:a",
            "chosen secret's ARN lands in the Mapping"
        );
    }

    #[tokio::test]
    async fn advance_clamps_out_of_range_choice() {
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod"), account("222", "Staging")])],
            vec![Ok(vec![role("ReadOnly")])],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Ok(vec![secret(
            "s",
            "arn:secret:s",
        )])]));
        let mut d = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec,
            api,
            None,
        );
        assert!(matches!(d.start().await, Step::Ask { .. }));
        let Step::Done(m) = d.advance(99).await else {
            panic!("expected Done");
        };
        assert_eq!(
            m.account_id, "222",
            "out-of-range clamps to the last account"
        );
    }

    #[tokio::test]
    async fn no_accounts_is_empty_for_that_step() {
        let cat = Arc::new(FakeAccountCatalog::new(vec![Ok(vec![])], vec![]));
        let rolec = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![]));
        let mut d = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec,
            api,
            None,
        );
        assert!(matches!(d.start().await, Step::Empty(What::Accounts)));
    }

    #[tokio::test]
    async fn list_error_is_failed_with_a_masked_reason() {
        use crate::error::SessionError;
        // The Sdk catch-all carries a context label; it must NOT reach the
        // user-facing reason (THREAT-MODEL — no SDK text leaks).
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Err(SessionError::Sdk {
                context: "hunter2".into(),
            })],
            vec![],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![]));
        let mut d = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec,
            api,
            None,
        );
        let Step::Failed(reason) = d.start().await else {
            panic!("expected Failed");
        };
        assert_eq!(reason, FetchFailReason::Other);
        assert!(!reason.describe().contains("hunter2"), "no SDK text leaks");
    }

    #[tokio::test]
    async fn reauth_required_listing_accounts_is_reauth_step() {
        use crate::error::SessionError;
        // A dead SSO token surfaces as a distinct terminal `Reauth` (not a
        // `Failed` Back/Close message) so the GUI can route back to Sign-in.
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Err(SessionError::ReauthRequired)],
            vec![],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![]));
        let mut d = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec,
            api,
            None,
        );
        assert!(matches!(d.start().await, Step::Reauth));
    }

    #[tokio::test]
    async fn access_denied_listing_roles_is_failed_with_that_reason() {
        use crate::error::SessionError;
        // A non-reauth SessionError at the role stage is a retryable, masked
        // Failed carrying the matching reason — not Reauth, not a leak.
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod")])],
            vec![Err(SessionError::AccessDenied)],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![]));
        let mut d = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec,
            api,
            None,
        );
        let Step::Failed(reason) = d.start().await else {
            panic!("expected Failed");
        };
        assert_eq!(reason, FetchFailReason::AccessDenied);
    }

    #[tokio::test]
    async fn throttled_listing_secrets_is_failed_with_that_reason_no_leak() {
        use crate::error::SessionError;
        // Account + role auto-pick, credential mints; the secret listing is
        // throttled → Failed(Throttled), and even an Sdk context never leaks.
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Err(
            SessionError::Throttled,
        )]));
        let mut d = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec,
            api,
            None,
        );
        let Step::Failed(reason) = d.start().await else {
            panic!("expected Failed");
        };
        assert_eq!(reason, FetchFailReason::Throttled);
        assert_eq!(reason.describe(), "throttled, try again");
    }

    #[tokio::test]
    async fn reauth_required_listing_roles_is_reauth_step() {
        use crate::error::SessionError;
        // Account auto-picks (singleton); the role listing then finds the token
        // dead → Reauth, not Failed.
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod")])],
            vec![Err(SessionError::ReauthRequired)],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![]));
        let mut d = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec,
            api,
            None,
        );
        assert!(matches!(d.start().await, Step::Reauth));
    }

    #[tokio::test]
    async fn reauth_required_minting_credentials_is_reauth_step() {
        use crate::error::SessionError;
        // Account + role auto-pick; minting the role credential to list secrets
        // hits a dead token → Reauth.
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![Err(SessionError::ReauthRequired)]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![]));
        let mut d = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec,
            api,
            None,
        );
        assert!(matches!(d.start().await, Step::Reauth));
    }

    #[tokio::test]
    async fn reauth_required_listing_secrets_is_reauth_step() {
        use crate::error::SessionError;
        // Account + role auto-pick and the credential mints; listing secrets
        // then finds the token dead → Reauth.
        let cat = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod")])],
            vec![Ok(vec![role("ReadOnly")])],
        ));
        let rolec = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Err(
            SessionError::ReauthRequired,
        )]));
        let mut d = Discovery::new(
            "prod".into(),
            "us-east-1".into(),
            token(),
            cat,
            rolec,
            api,
            None,
        );
        assert!(matches!(d.start().await, Step::Reauth));
    }
}
