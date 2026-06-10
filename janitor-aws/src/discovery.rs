//! `Discovery` (ADR 0013 / ADR 0026): the Secrets Manager Provider's guided
//! account → role → secret walk, expressed as a `janitor_core::discovery` *method*
//! ([`Steps`]) driven by the shared [`Orchestrator`].
//!
//! It knows nothing of stdin, channels, or Slint — `start()`/`advance()` return a
//! `Step` describing either what to ask next or a terminal outcome, and each
//! consumer writes a thin presenter. The walk *sequencing* (auto-pick collapsing,
//! stop-at-first-`Ask`, resume, index clamping) now lives once in the provider-
//! agnostic [`Orchestrator`] (ADR 0026, #33); this file supplies only the AWS
//! *method*: the shared `account → role → mint` front half (via
//! [`front_half`], ADR 0024 Decision 6) plus the Secrets Manager tail (list secrets
//! → pick). Fully tested against `wire::fakes`.

use std::sync::Arc;

use async_trait::async_trait;

use janitor_core::config::{Mapping, Method};
use janitor_core::discovery::{Choice, Orchestrator, StepPlan, Steps};
use janitor_core::provider::{Step, What};

use janitor_aws_auth::authwalk::{front_half, terminal_for, FrontHalf};
use janitor_aws_auth::types::{Credential, SsoToken};
use janitor_aws_auth::wire::{AccountCatalog, RoleCredentialClient};

use crate::wire::SecretsApi;

/// The Secrets Manager Discovery method. Holds the SSO token and the AWS seams; the
/// only state it carries across the (re-entrant) walk is the once-minted Credential
/// — the chosen account/role/secret keys live in the orchestrator's `chosen`.
/// `pub(crate)` so [`SecretsManagerMethod`](crate::method::SecretsManagerMethod) can
/// build it as its Discovery tail (ADR 0031) — the same steps the `Discovery` handle
/// the live-verify binary uses drives.
pub(crate) struct AwsSteps {
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
    /// The role Credential, minted once when account+role are chosen (guards the
    /// one-shot front-half mint against a re-entrant `next`).
    cred: Option<Credential>,
}

impl AwsSteps {
    /// Build the Secrets Manager Discovery method (no I/O until driven).
    pub(crate) fn new(
        token: Arc<SsoToken>,
        catalog: Arc<dyn AccountCatalog>,
        role_client: Arc<dyn RoleCredentialClient>,
        secrets: Arc<dyn SecretsApi>,
        environment: String,
        region: String,
        remembered: Option<Mapping>,
    ) -> Self {
        AwsSteps {
            token,
            catalog,
            role_client,
            secrets,
            environment,
            region,
            remembered,
            cred: None,
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

    /// Assemble the completed Mapping from the chosen keys. `secret_id` is the ARN
    /// (the stable id); `region` is the resolved browse region; `permission_set` is
    /// the role.
    fn build_mapping(&self, account_id: &str, role: &str, secret_arn: &str) -> Mapping {
        Mapping {
            environment: self.environment.clone(),
            account_id: account_id.to_string(),
            region: self.region.clone(),
            secret_id: secret_arn.to_string(),
            permission_set: role.to_string(),
            method: Method::SecretsManager,
        }
    }
}

#[async_trait]
impl Steps for AwsSteps {
    /// `chosen` accumulates `[account_id, role, secret_arn]`. The shared front half
    /// owns the first two (and the credential mint); the tail lists secrets with the
    /// minted Credential and assembles the Mapping.
    async fn next(&mut self, chosen: &[String]) -> StepPlan {
        // Front half: account → role → mint (runs only until we hold a Credential).
        if self.cred.is_none() {
            match front_half(
                chosen,
                &self.token,
                self.catalog.as_ref(),
                self.role_client.as_ref(),
                &self.region,
                self.remembered_account(),
                self.remembered_role(),
            )
            .await
            {
                FrontHalf::Plan(plan) => return plan,
                FrontHalf::Ready { cred, .. } => self.cred = Some(cred),
            }
        }

        // Tail: list secrets with the minted Credential, then pick one → Done.
        if chosen.len() < 3 {
            let cred = self.cred.as_ref().unwrap();
            return match self.secrets.list_secrets(cred, &self.region).await {
                Ok(items) => StepPlan::List {
                    what: What::Secrets,
                    choices: Choice::project(&items),
                    remembered: self.remembered_secret().map(str::to_string),
                },
                Err(e) => StepPlan::Terminal(terminal_for(&e)),
            };
        }
        StepPlan::Done(self.build_mapping(&chosen[0], &chosen[1], &chosen[2]))
    }
}

/// The guided Secrets Manager discovery walk for one Environment: a thin handle over
/// the shared [`Orchestrator`] driving an [`AwsSteps`] method. The public
/// `new`/`start`/`advance` surface is unchanged (the worker/presenter are untouched).
pub struct Discovery {
    orch: Orchestrator<AwsSteps>,
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
            orch: Orchestrator::new(AwsSteps::new(
                token,
                catalog,
                role_client,
                secrets,
                environment,
                region,
                remembered,
            )),
        }
    }

    /// Begin the walk: auto-collapse singleton steps until the first `many` choice
    /// (an `Ask`) or a terminal outcome.
    pub async fn start(&mut self) -> Step {
        self.orch.start().await
    }

    /// Feed back the user's chosen index for the step the walk is blocked on, then
    /// continue collapsing singletons until the next `Ask` or a terminal outcome.
    /// Out-of-range indices are clamped.
    pub async fn advance(&mut self, choice: usize) -> Step {
        self.orch.advance(choice).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{fakes::FakeSecretsApi, SecretSummary};
    use janitor_aws_auth::wire::fakes::{CredSpec, FakeAccountCatalog, FakeRoleClient};
    use janitor_aws_auth::wire::{AccountSummary, RoleSummary};
    use janitor_core::provider::FetchFailReason;
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
    fn cred_ok() -> Result<CredSpec, janitor_aws_auth::error::SessionError> {
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
    async fn two_walks_with_different_browse_regions_yield_cross_region_mappings() {
        // ADR 0015: flipping the at-hand browse region between successive
        // `+ Add env` runs builds one Application whose Environments span regions.
        // Each walk takes its own browse region and stamps it onto the completed
        // Mapping — no new engine surface, just a different region per `start()`.
        async fn discover_in(region: &str, env: &str) -> Mapping {
            let cat = Arc::new(FakeAccountCatalog::new(
                vec![Ok(vec![account("111111111111", "Prod")])],
                vec![Ok(vec![role("ReadOnly")])],
            ));
            let rolec = Arc::new(FakeRoleClient::new(vec![cred_ok()]));
            let api = Arc::new(FakeSecretsApi::with_lists(vec![Ok(vec![secret(
                "myapp",
                "arn:secret:myapp",
            )])]));
            let mut d = Discovery::new(env.into(), region.into(), token(), cat, rolec, api, None);
            let Step::Done(m) = d.start().await else {
                panic!("expected Done");
            };
            m
        }

        let east = discover_in("us-east-1", "prod").await;
        let west = discover_in("us-west-2", "staging").await;

        assert_eq!(east.region, "us-east-1");
        assert_eq!(west.region, "us-west-2");
        assert_ne!(
            east.region, west.region,
            "the two Environments of one Application span regions"
        );
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
            method: Method::SecretsManager,
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
            method: Method::SecretsManager,
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
            method: Method::SecretsManager,
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
        use janitor_aws_auth::error::SessionError;
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
        use janitor_aws_auth::error::SessionError;
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
        use janitor_aws_auth::error::SessionError;
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
        use janitor_aws_auth::error::SessionError;
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
        use janitor_aws_auth::error::SessionError;
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
        use janitor_aws_auth::error::SessionError;
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
        use janitor_aws_auth::error::SessionError;
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
