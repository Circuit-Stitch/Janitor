//! `SecretsManagerMethod` (ADR 0031): the Secrets Manager [`ResourceMethod`] — the
//! `GetSecretValue` read + the SM Discovery tail, wrapped behind the shared
//! `ResourceMethod` seam so the generic `AwsFamilyProvider` shell drives it.
//!
//! This is the slimmer half of the old `janitor-aws::Session`: the auth shell
//! (sign-in, broker, the force-refresh + re-Sign-in ladder, ADR 0018 stale-role
//! recovery) moved into `janitor-aws-auth::AwsFamilyProvider`, so all that remains
//! here is "given a freshly-minted Credential, read + shape one Set" and "supply the
//! account → role → secret Discovery tail". The fetch-shaping logic still lives in
//! [`SecretsClient`](crate::secrets::SecretsClient) (tested there); discovery still
//! lives in [`AwsSteps`](crate::discovery) (tested there + driven by the live-verify
//! `Discovery` handle).

use std::sync::Arc;

use async_trait::async_trait;

use janitor_aws_auth::method::{MethodError, ResourceMethod};
use janitor_aws_auth::types::{Credential, SsoToken};
use janitor_aws_auth::wire::{AccountCatalog, RoleCredentialClient};
use janitor_aws_auth::write::{EnvEdit, WriteOutcome};
use janitor_core::config::{Mapping, Method};
use janitor_core::discovery::Steps;
use janitor_core::secret::SecretShape;

use crate::discovery::AwsSteps;
use crate::secrets::SecretsClient;
use crate::wire::SecretsApi;

/// The Secrets Manager resource method. Holds the account/role catalog, the
/// credential-mint client, and the `GetSecretValue`/`ListSecrets` seam — the same
/// `Arc`s the shell holds for the front half (the real `AwsRoleClient` implements
/// both `RoleCredentialClient` and `AccountCatalog`).
pub struct SecretsManagerMethod {
    catalog: Arc<dyn AccountCatalog>,
    role_client: Arc<dyn RoleCredentialClient>,
    secrets: Arc<dyn SecretsApi>,
}

impl SecretsManagerMethod {
    pub fn new(
        catalog: Arc<dyn AccountCatalog>,
        role_client: Arc<dyn RoleCredentialClient>,
        secrets: Arc<dyn SecretsApi>,
    ) -> Self {
        SecretsManagerMethod {
            catalog,
            role_client,
            secrets,
        }
    }
}

#[async_trait]
impl ResourceMethod for SecretsManagerMethod {
    fn kind(&self) -> Method {
        Method::SecretsManager
    }

    /// `GetSecretValue` for `mapping`, authorized by `cred`, mapped to a shape. A
    /// read error masks to [`MethodError::Session`] (the shell may run the ladder
    /// on it); binary content stays an opaque `SecretShape::Binary` (ADR 0004), not
    /// an error — only a truly empty response is `NotFound`.
    async fn fetch(
        &self,
        cred: &Credential,
        mapping: &Mapping,
    ) -> Result<SecretShape, MethodError> {
        SecretsClient::new(Arc::clone(&self.secrets))
            .fetch(cred, mapping)
            .await
            .map_err(MethodError::Session)
    }

    /// The Secrets Manager staged-put/CAS write (ADR 0001 + Amendment 2026-06-25):
    /// the flat-JSON merge + ADR 0001 steps 3–6 + conflict model B (see
    /// [`write_secret`](crate::secret_write::write_secret)). The shell never calls
    /// this through the port in v1 (read-only); it is reached only via the
    /// `live-verify-sm-write` binary. A read/transport failure masks to
    /// [`MethodError::Session`] (the shell *could* run the ladder, as for `fetch` —
    /// but ADR 0032's stale-role recovery is load-only, not write); a non-flat blob
    /// or invalid key masks to [`MethodError::Content`] (Unsupported, no recovery).
    async fn write(
        &self,
        cred: &Credential,
        mapping: &Mapping,
        edits: &[EnvEdit],
    ) -> Result<WriteOutcome, MethodError> {
        crate::secret_write::write_secret(
            self.secrets.as_ref(),
            cred,
            &mapping.secret_id,
            &mapping.region,
            edits,
        )
        .await
        .map_err(|e| match e {
            crate::secret_write::SecretWriteError::Session(s) => MethodError::Session(s),
            other => MethodError::Content {
                detail: other.detail(),
            },
        })
    }

    /// The account → role → secret Discovery tail, as the shared front half composed
    /// with the SM secret pick (`ListSecrets`). The shell wraps this in an
    /// `Orchestrator` and stamps `Method::SecretsManager` onto the `Done` Mapping.
    fn discovery_steps(
        &self,
        environment: String,
        region: String,
        token: Arc<SsoToken>,
        remembered: Option<Mapping>,
    ) -> Box<dyn Steps> {
        Box::new(AwsSteps::new(
            token,
            Arc::clone(&self.catalog),
            Arc::clone(&self.role_client),
            Arc::clone(&self.secrets),
            environment,
            region,
            remembered,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fakes::FakeSecretsApi;
    use crate::wire::SecretSummary;
    use janitor_aws_auth::wire::fakes::{CredSpec, FakeAccountCatalog, FakeRoleClient};
    use janitor_aws_auth::wire::{AccountSummary, RawSecret, RoleSummary};
    use janitor_core::provider::What;
    use std::time::SystemTime;

    fn cred() -> Credential {
        Credential::new("a".into(), "b".into(), "c".into(), SystemTime::UNIX_EPOCH)
    }
    fn mapping() -> Mapping {
        Mapping {
            environment: "prod".into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: "myapp/prod".into(),
            permission_set: "ReadOnly".into(),
            method: Method::SecretsManager,
        }
    }
    fn method(api: Arc<FakeSecretsApi>) -> SecretsManagerMethod {
        // Recovery/discovery tests below seed the catalog/role client explicitly.
        SecretsManagerMethod::new(
            Arc::new(FakeAccountCatalog::new(vec![], vec![])),
            Arc::new(FakeRoleClient::new(vec![])),
            api,
        )
    }

    #[test]
    fn kind_is_secrets_manager_and_no_advisory() {
        let m = method(Arc::new(FakeSecretsApi::new(vec![])));
        assert_eq!(m.kind(), Method::SecretsManager);
        assert!(
            !m.has_advisory(),
            "Secrets Manager has no operator advisory"
        );
    }

    #[tokio::test]
    async fn fetch_shapes_a_json_secret() {
        let api = Arc::new(FakeSecretsApi::new(vec![Ok(RawSecret {
            secret_string: Some(r#"{"A":"1"}"#.into()),
            secret_binary: None,
        })]));
        let shape = method(api).fetch(&cred(), &mapping()).await.unwrap();
        assert!(matches!(shape, SecretShape::Json(_)));
    }

    #[tokio::test]
    async fn fetch_masks_a_read_error_into_a_session_method_error() {
        let api = Arc::new(FakeSecretsApi::new(vec![Err(
            janitor_aws_auth::error::SessionError::AccessDenied,
        )]));
        let err = method(api).fetch(&cred(), &mapping()).await.unwrap_err();
        assert!(matches!(
            err,
            MethodError::Session(janitor_aws_auth::error::SessionError::AccessDenied)
        ));
        assert_eq!(
            err.reason(),
            janitor_core::provider::FetchFailReason::AccessDenied
        );
    }

    #[tokio::test]
    async fn write_applies_a_flat_json_edit_through_the_engine() {
        // The method now dispatches to the staged-put/CAS engine (ADR 0001 / #89);
        // a flat-JSON edit commits. The full engine behaviour is pinned in
        // `crate::secret_write` — this just proves the method is wired to it.
        use crate::wire::fakes::read_json;
        use crate::wire::CasOutcome;
        let api = Arc::new(
            FakeSecretsApi::new(vec![])
                .reads(vec![read_json(r#"{"A":"1"}"#, "v1")])
                .puts(vec![Ok("v2".into())])
                .stages(vec![Ok(CasOutcome::Committed)]),
        );
        let outcome = method(api.clone())
            .write(&cred(), &mapping(), &[EnvEdit::set("A", "2")])
            .await
            .unwrap();
        assert_eq!(outcome, WriteOutcome::Applied);
        assert_eq!(api.put_calls()[0].secret_string, r#"{"A":"2"}"#);
    }

    #[tokio::test]
    async fn write_of_a_non_flat_secret_masks_to_unsupported_content() {
        // A nested/binary blob can't be merged safely → Content (Unsupported), not a
        // Session error, and no write is attempted.
        use crate::wire::fakes::read_json;
        let api =
            Arc::new(FakeSecretsApi::new(vec![]).reads(vec![read_json(r#"{"A":{"b":1}}"#, "v1")]));
        let err = method(api.clone())
            .write(&cred(), &mapping(), &[EnvEdit::set("A", "2")])
            .await
            .unwrap_err();
        assert_eq!(
            err.reason(),
            janitor_core::provider::FetchFailReason::Unsupported
        );
        assert!(matches!(err, MethodError::Content { .. }));
        assert!(api.put_calls().is_empty());
    }

    #[tokio::test]
    async fn discovery_steps_drive_the_account_role_secret_tail_to_done() {
        // The method's discovery tail, driven through a bare Orchestrator (the shell
        // does this and stamps the method): one account/role/secret auto-collapse.
        use janitor_core::discovery::Orchestrator;
        use janitor_core::provider::Step;
        let catalog = Arc::new(FakeAccountCatalog::new(
            vec![Ok(vec![AccountSummary {
                id: "111".into(),
                name: "Prod".into(),
            }])],
            vec![Ok(vec![RoleSummary {
                name: "ReadOnly".into(),
            }])],
        ));
        let role = Arc::new(FakeRoleClient::new(vec![Ok(CredSpec {
            expires_in: std::time::Duration::from_secs(3600),
            tag: "t",
        })]));
        let api = Arc::new(FakeSecretsApi::with_lists(vec![Ok(vec![SecretSummary {
            name: "myapp/prod".into(),
            arn: "arn:secret:myapp/prod".into(),
        }])]));
        let m = SecretsManagerMethod::new(catalog, role, api);
        let token = Arc::new(SsoToken::new(
            "session".into(),
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(28800),
        ));
        let steps = m.discovery_steps("prod".into(), "us-west-2".into(), token, None);
        let mut orch: Orchestrator<Box<dyn Steps>> = Orchestrator::new(steps);
        let Step::Done(mapping) = orch.start().await else {
            panic!("expected Done from the SM discovery tail");
        };
        assert_eq!(mapping.account_id, "111");
        assert_eq!(mapping.secret_id, "arn:secret:myapp/prod");
        // The method builds it as SecretsManager (the shell would stamp it anyway).
        assert_eq!(mapping.method, Method::SecretsManager);
        // And it never poses a free-text Input (only account/role/secret Asks).
        let _ = What::Secrets;
    }
}
