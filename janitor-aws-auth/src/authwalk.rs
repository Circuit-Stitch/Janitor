//! The shared `account → role → mint` front half (ADR 0024 Decision 6 / ADR 0026,
//! #33). Every AWS-family Provider's Discovery walk begins identically: list the
//! accounts the SSO token is entitled to, list the chosen account's roles, then
//! mint one role Credential for the `(account, role, region)`. Only the *tail* —
//! what the minted Credential is then used to reach (a Secrets Manager secret, a
//! remote `.env` on an SSM-managed Instance, …) — varies per Provider.
//!
//! That front half is expressed as the first stages of a `janitor_core::discovery`
//! method (`Steps`): given the keys chosen so far, [`front_half`] returns the
//! account list (`chosen` empty), the role list (one key chosen), or — once both
//! are in — mints and hands back [`FrontHalf::Ready`] so the Provider proceeds to
//! its own tail. The Provider calls this only while it has not yet minted (caching
//! the returned Credential), so the one-shot mint never repeats on a re-entrant
//! `next`. This repays the duplication ADR 0024 deliberately left in the two real
//! walks until a second Provider existed to shape the seam.

use crate::error::SessionError;
use crate::types::{Credential, SsoToken};
use crate::wire::{AccountCatalog, RoleCredentialClient};

use janitor_core::discovery::{Choice, StepPlan};
use janitor_core::provider::{Step, What};

/// Classify a [`SessionError`] into the right terminal [`Step`] (shared by every
/// AWS-family walk): `ReauthRequired` — a dead token the facade could not silently
/// refresh — becomes [`Step::Reauth`] so the presenter routes back to Sign-in;
/// everything else becomes a masked, retryable [`Step::Failed`] carrying only the
/// tested [`FetchFailReason`](janitor_core::provider::FetchFailReason) (no SDK text;
/// THREAT-MODEL).
pub fn terminal_for(e: &SessionError) -> Step {
    match e {
        SessionError::ReauthRequired => Step::Reauth,
        _ => Step::Failed(e.into()),
    }
}

/// The outcome of driving the shared front half for the current `chosen` prefix.
pub enum FrontHalf {
    /// Still resolving the account/role list, or a terminal — hand straight to the
    /// orchestrator as the method's `StepPlan`.
    Plan(StepPlan),
    /// The account and role are chosen and a Credential has been minted; the
    /// Provider caches `cred` and proceeds to its own tail. `account_id`/`role` are
    /// the chosen keys, surfaced for the Provider's `Mapping` assembly (they are
    /// also `chosen[0]`/`chosen[1]`).
    Ready {
        account_id: String,
        role: String,
        cred: Credential,
    },
}

/// Drive the shared `account → role → mint` front half for the chosen prefix:
///
/// - `chosen` empty → list accounts (a `StepPlan::List` of [`What::Accounts`],
///   pre-selecting `remembered_account`).
/// - one key chosen → list the chosen account's roles ([`What::Roles`],
///   pre-selecting `remembered_role`).
/// - two keys chosen → mint a Credential for `(chosen[0], chosen[1], region)` and
///   return [`FrontHalf::Ready`].
///
/// A list/mint I/O error is masked into a terminal `StepPlan` via [`terminal_for`].
/// The caller MUST gate this on "no Credential minted yet" so the two-key mint runs
/// exactly once across a re-entrant walk.
pub async fn front_half(
    chosen: &[String],
    token: &SsoToken,
    catalog: &dyn AccountCatalog,
    role_client: &dyn RoleCredentialClient,
    region: &str,
    remembered_account: Option<&str>,
    remembered_role: Option<&str>,
) -> FrontHalf {
    if chosen.is_empty() {
        return match catalog.list_accounts(token).await {
            Ok(items) => FrontHalf::Plan(StepPlan::List {
                what: What::Accounts,
                choices: Choice::project(&items),
                remembered: remembered_account.map(str::to_string),
            }),
            Err(e) => FrontHalf::Plan(StepPlan::Terminal(terminal_for(&e))),
        };
    }
    if chosen.len() == 1 {
        return match catalog.list_account_roles(token, &chosen[0]).await {
            Ok(items) => FrontHalf::Plan(StepPlan::List {
                what: What::Roles,
                choices: Choice::project(&items),
                remembered: remembered_role.map(str::to_string),
            }),
            Err(e) => FrontHalf::Plan(StepPlan::Terminal(terminal_for(&e))),
        };
    }
    // Both chosen: mint one role Credential for the account+role+region.
    match role_client
        .get_role_credentials(token, &chosen[0], &chosen[1], region)
        .await
    {
        Ok(cred) => FrontHalf::Ready {
            account_id: chosen[0].clone(),
            role: chosen[1].clone(),
            cred,
        },
        Err(e) => FrontHalf::Plan(StepPlan::Terminal(terminal_for(&e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SsoToken;
    use crate::wire::fakes::{CredSpec, FakeAccountCatalog, FakeRoleClient};
    use crate::wire::{AccountSummary, RoleSummary};
    use janitor_core::provider::FetchFailReason;
    use std::time::{Duration, SystemTime};

    fn token() -> SsoToken {
        SsoToken::new(
            "session".into(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(28800),
        )
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
    fn cred_ok() -> Result<CredSpec, SessionError> {
        Ok(CredSpec {
            expires_in: Duration::from_secs(3600),
            tag: "t",
        })
    }

    /// Assert a `StepPlan::List` and return its `(what, keys, labels, remembered)`.
    fn expect_list(plan: StepPlan) -> (What, Vec<String>, Vec<String>, Option<String>) {
        let StepPlan::List {
            what,
            choices,
            remembered,
        } = plan
        else {
            panic!("expected a List plan");
        };
        let keys = choices.iter().map(|c| c.key.clone()).collect();
        let labels = choices.into_iter().map(|c| c.label).collect();
        (what, keys, labels, remembered)
    }

    #[tokio::test]
    async fn lists_accounts_when_nothing_chosen_and_passes_the_remembered_key() {
        let cat = FakeAccountCatalog::new(
            vec![Ok(vec![account("111", "Prod"), account("222", "Staging")])],
            vec![],
        );
        let rolec = FakeRoleClient::new(vec![]);
        let FrontHalf::Plan(plan) =
            front_half(&[], &token(), &cat, &rolec, "us-east-1", Some("222"), None).await
        else {
            panic!("expected a Plan");
        };
        let (what, keys, labels, remembered) = expect_list(plan);
        assert_eq!(what, What::Accounts);
        assert_eq!(keys, vec!["111".to_string(), "222".to_string()]);
        assert_eq!(
            labels,
            vec!["Prod (111)".to_string(), "Staging (222)".to_string()]
        );
        assert_eq!(remembered.as_deref(), Some("222"));
        assert_eq!(rolec.call_count(), 0, "no mint while listing accounts");
    }

    #[tokio::test]
    async fn lists_roles_for_the_chosen_account() {
        let cat = FakeAccountCatalog::new(vec![], vec![Ok(vec![role("ReadOnly"), role("Admin")])]);
        let rolec = FakeRoleClient::new(vec![]);
        let FrontHalf::Plan(plan) = front_half(
            &["111".into()],
            &token(),
            &cat,
            &rolec,
            "us-east-1",
            None,
            Some("Admin"),
        )
        .await
        else {
            panic!("expected a Plan");
        };
        let (what, keys, _labels, remembered) = expect_list(plan);
        assert_eq!(what, What::Roles);
        assert_eq!(keys, vec!["ReadOnly".to_string(), "Admin".to_string()]);
        assert_eq!(remembered.as_deref(), Some("Admin"));
        assert_eq!(cat.role_call_count(), 1, "listed roles for the account");
    }

    #[tokio::test]
    async fn mints_once_when_account_and_role_are_chosen() {
        let cat = FakeAccountCatalog::new(vec![], vec![]);
        let rolec = FakeRoleClient::new(vec![cred_ok()]);
        let FrontHalf::Ready {
            account_id,
            role,
            cred: _,
        } = front_half(
            &["111".into(), "ReadOnly".into()],
            &token(),
            &cat,
            &rolec,
            "us-east-1",
            None,
            None,
        )
        .await
        else {
            panic!("expected Ready once both keys are chosen");
        };
        assert_eq!(account_id, "111");
        assert_eq!(role, "ReadOnly");
        assert_eq!(rolec.call_count(), 1, "minted exactly once");
    }

    #[tokio::test]
    async fn masks_a_list_error_as_a_terminal_failed_with_no_sdk_text() {
        let cat = FakeAccountCatalog::new(
            vec![Err(SessionError::Sdk {
                context: "hunter2".into(),
            })],
            vec![],
        );
        let rolec = FakeRoleClient::new(vec![]);
        let FrontHalf::Plan(StepPlan::Terminal(Step::Failed(reason))) =
            front_half(&[], &token(), &cat, &rolec, "us-east-1", None, None).await
        else {
            panic!("expected a masked Failed terminal");
        };
        assert_eq!(reason, FetchFailReason::Other);
        assert!(!reason.describe().contains("hunter2"), "no SDK text leaks");
    }

    #[tokio::test]
    async fn a_dead_token_at_mint_is_a_reauth_terminal() {
        let cat = FakeAccountCatalog::new(vec![], vec![]);
        let rolec = FakeRoleClient::new(vec![Err(SessionError::ReauthRequired)]);
        let outcome = front_half(
            &["111".into(), "ReadOnly".into()],
            &token(),
            &cat,
            &rolec,
            "us-east-1",
            None,
            None,
        )
        .await;
        assert!(matches!(
            outcome,
            FrontHalf::Plan(StepPlan::Terminal(Step::Reauth))
        ));
    }

    #[test]
    fn terminal_for_routes_reauth_to_reauth_and_others_to_masked_failed() {
        assert!(matches!(
            terminal_for(&SessionError::ReauthRequired),
            Step::Reauth
        ));
        let Step::Failed(reason) = terminal_for(&SessionError::AccessDenied) else {
            panic!("non-reauth is a masked Failed");
        };
        assert_eq!(reason, FetchFailReason::AccessDenied);
    }
}
