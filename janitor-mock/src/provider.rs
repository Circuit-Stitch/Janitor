//! [`MockProvider`] — the offline [`Provider`] implementation. It produces
//! `SecretShape`s from [`crate::data`] and calls `core` (`Comparison::build`,
//! `project`) for the comparison, exactly as a real Provider does. `sign_in`
//! succeeds instantly, `reveal` returns the cached Value, and Discovery is a
//! trivial local stub (a fabricated 2-account org → one `Ask` → a `Mapping`).

use async_trait::async_trait;

use janitor_core::compare::{Comparison, RowKey};
use janitor_core::config::{Application, Mapping, Method};
use janitor_core::provider::{AppError, Loaded, Provider, SignInFailed, Step, What};
use janitor_core::secret::SecretShape;
use janitor_core::view::{project, reveal_value};

use crate::data;

/// The offline Provider. Holds the last-loaded plaintext Sets (so `reveal` works
/// without a round-trip) and any guided walk paused on a choice.
#[derive(Debug, Default)]
pub struct MockProvider {
    cached: Vec<(String, SecretShape)>,
    pending: Option<MockWalk>,
}

/// A mock guided walk paused on the account choice, so the picker (and remembered
/// default) can be exercised offline. `advance_discovery` finishes it into a
/// `Mapping`.
#[derive(Debug)]
struct MockWalk {
    environment: String,
    region: String,
    /// Candidate accounts as `(name, id)`, in label order.
    accounts: Vec<(String, String)>,
}

impl MockProvider {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Provider for MockProvider {
    async fn sign_in(&mut self) -> Result<(), SignInFailed> {
        Ok(())
    }

    async fn load(&mut self, app: &Application) -> Result<Loaded, AppError> {
        let sets: Vec<(String, SecretShape)> = app
            .environments
            .iter()
            .map(|m| (m.environment.clone(), data::fetch(m)))
            .collect();
        let view = project(&Comparison::build(&sets));
        // Plaintext Sets stay Provider-side (in `cached`); only the masked view
        // crosses the port. The mock never fails a fetch, so `corrected` is empty.
        self.cached = sets;
        Ok(Loaded {
            view,
            corrected: Vec::new(),
        })
    }

    fn reveal(&self, key: &RowKey, col: usize) -> Option<String> {
        reveal_value(&self.cached, key, col).map(|v| v.expose().to_string())
    }

    async fn begin_discovery(
        &mut self,
        _method: Method,
        environment: String,
        region: String,
        remembered: Option<Mapping>,
    ) -> Result<Step, SignInFailed> {
        // The mock has a single fabricated backend, so it ignores the chosen method
        // (a real Provider dispatches on it). No AWS, so fabricate a small
        // multi-account org and ask, exercising the
        // picker (and remembered default) offline without a browser. Role + secret
        // then "auto-pick" — `advance_discovery` goes straight to `Done`.
        let accounts = vec![
            ("Prod".to_string(), "000000000001".to_string()),
            ("Staging".to_string(), "000000000002".to_string()),
        ];
        let default = remembered
            .as_ref()
            .and_then(|m| accounts.iter().position(|(_, id)| *id == m.account_id));
        let choices = accounts
            .iter()
            .map(|(name, id)| format!("{name} ({id})"))
            .collect();
        self.pending = Some(MockWalk {
            environment,
            region,
            accounts,
        });
        Ok(Step::Ask {
            what: What::Accounts,
            choices,
            default,
        })
    }

    async fn advance_discovery(&mut self, choice: usize) -> Option<Step> {
        let walk = self.pending.take()?;
        // Clamp a stray index so a presenter bug can never panic; role + secret
        // are auto-picked, so the chosen account completes the walk into a Mapping.
        let i = choice.min(walk.accounts.len() - 1);
        let (_, account_id) = &walk.accounts[i];
        Some(Step::Done(Mapping {
            environment: walk.environment.clone(),
            account_id: account_id.clone(),
            region: walk.region,
            secret_id: format!("discovered/{}", walk.environment),
            permission_set: "ReadOnly".into(),
            method: Method::SecretsManager,
        }))
    }

    async fn provide_input(&mut self, _text: String) -> Option<Step> {
        // The mock walk only ever poses an account `Ask`, never a free-text
        // `Step::Input`, so there is nothing to feed text into (ADR 0025).
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use janitor_core::compare::EntryState;
    use janitor_core::secret::EntryName;

    #[tokio::test]
    async fn sign_in_succeeds_instantly() {
        // The offline Provider has no authentication, so Sign-in is a no-op that
        // always succeeds — this is what lets `main` auto-send SignIn at startup
        // to preserve the "opens already signed in" demo feel (ADR 0019).
        let mut p = MockProvider::new();
        assert!(p.sign_in().await.is_ok());
    }

    #[tokio::test]
    async fn load_payments_projects_the_aligned_drift_gap_matrix() {
        // Loading the seeded Payments Application reproduces the mockup matrix:
        // GITHUB_APP_ID identical (Aligned), STRIPE_API_KEY differs (Drift), and
        // database.replica.url is prod-only (Gap). The mock never fails a fetch,
        // so there is nothing to auto-correct.
        let payments = crate::seeded_config().applications[0].clone();
        let mut p = MockProvider::new();
        let loaded = p.load(&payments).await.unwrap();
        assert!(loaded.corrected.is_empty(), "mock never auto-corrects");
        let view = loaded.view;
        assert_eq!(view.environments, vec!["prod", "staging"]);
        let state = |name: &str| view.rows.iter().find(|r| r.name == name).map(|r| r.state);
        assert_eq!(state("GITHUB_APP_ID"), Some(EntryState::Aligned));
        assert_eq!(state("STRIPE_API_KEY"), Some(EntryState::Drift));
        assert_eq!(state("database.replica.url"), Some(EntryState::Gap));
    }

    #[tokio::test]
    async fn reveal_returns_cached_value_for_present_and_none_for_absent() {
        let payments = crate::seeded_config().applications[0].clone();
        let mut p = MockProvider::new();
        let stripe = RowKey::Entry(EntryName::from_path(&["STRIPE_API_KEY".to_string()]));
        assert!(p.reveal(&stripe, 0).is_none(), "nothing cached before load");

        p.load(&payments).await.unwrap();
        assert_eq!(
            p.reveal(&stripe, 0).as_deref(),
            Some("sk_live_prod_b80a0011"),
            "present cell reveals its plaintext from the cached Set"
        );

        // database.replica.url is prod-only → absent in staging (col 1).
        let replica = RowKey::Entry(EntryName::from_path(&[
            "database".to_string(),
            "replica".to_string(),
            "url".to_string(),
        ]));
        assert!(
            p.reveal(&replica, 1).is_none(),
            "an absent cell is unrevealable"
        );
    }

    fn remembered_account(id: &str) -> Mapping {
        Mapping {
            environment: "live".into(),
            account_id: id.into(),
            region: "us-east-1".into(),
            secret_id: "remembered/secret".into(),
            permission_set: "ReadOnly".into(),
            method: Method::SecretsManager,
        }
    }

    #[tokio::test]
    async fn begin_discovery_asks_for_an_account_honoring_the_remembered_default() {
        let mut p = MockProvider::new();
        let step = p
            .begin_discovery(
                Method::SecretsManager,
                "prod".into(),
                "us-east-1".into(),
                None,
            )
            .await
            .unwrap();
        let Step::Ask {
            what,
            choices,
            default,
        } = step
        else {
            panic!("expected Ask, got {step:?}");
        };
        assert_eq!(what, What::Accounts);
        assert_eq!(choices.len(), 2, "the fabricated org has two accounts");
        assert_eq!(default, None, "nothing remembered → no preselect");

        // A remembered pick at the second fabricated account preselects index 1.
        let step = p
            .begin_discovery(
                Method::SecretsManager,
                "prod".into(),
                "us-east-1".into(),
                Some(remembered_account("000000000002")),
            )
            .await
            .unwrap();
        let Step::Ask { default, .. } = step else {
            panic!("expected Ask, got {step:?}");
        };
        assert_eq!(default, Some(1), "remembered account preselected");
    }

    #[tokio::test]
    async fn advance_discovery_builds_a_mapping_from_the_chosen_account() {
        let mut p = MockProvider::new();
        p.begin_discovery(
            Method::SecretsManager,
            "prod".into(),
            "us-east-1".into(),
            None,
        )
        .await
        .unwrap();
        let step = p.advance_discovery(1).await.expect("a walk is in progress");
        let Step::Done(m) = step else {
            panic!("expected Done, got {step:?}");
        };
        assert_eq!(m.environment, "prod");
        assert_eq!(m.account_id, "000000000002", "the chosen account");
        assert_eq!(m.region, "us-east-1");
        assert_eq!(m.secret_id, "discovered/prod");
        assert_eq!(m.permission_set, "ReadOnly");
        // The walk is consumed — a second advance has nothing to drive.
        assert!(
            p.advance_discovery(0).await.is_none(),
            "walk consumed after Done"
        );
    }

    #[tokio::test]
    async fn advance_discovery_is_none_without_a_walk() {
        let mut p = MockProvider::new();
        assert!(
            p.advance_discovery(0).await.is_none(),
            "nothing to advance before begin_discovery"
        );
    }

    #[tokio::test]
    async fn provide_input_is_always_none_the_mock_poses_no_input_step() {
        // The mock never emits a free-text `Step::Input`, so feeding it text is a
        // no-op (the additive `Input` rail, #62 / ADR 0025) — even mid-walk.
        let mut p = MockProvider::new();
        assert!(p.provide_input("/app/.env".into()).await.is_none());
        p.begin_discovery(
            Method::SecretsManager,
            "prod".into(),
            "us-east-1".into(),
            None,
        )
        .await
        .unwrap();
        assert!(
            p.provide_input("/app/.env".into()).await.is_none(),
            "even with a walk in progress the mock has no Input to satisfy"
        );
    }
}
