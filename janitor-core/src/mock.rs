//! A **non-production** [`SecretSource`] that returns canned Secret Sets so the
//! GUI can be built and demoed before AWS auth + I/O exist. Not for release.

use crate::config::Mapping;
use crate::secret::SecretShape;
use crate::source::{FetchError, SecretSource};

/// In-memory mock source. Knows a few hand-seeded Sets (reproducing the design
/// mockup's Payments API) and deterministically fabricates a plausible Set for
/// anything else.
#[derive(Debug, Default)]
pub struct MockSource;

impl MockSource {
    pub fn new() -> Self {
        MockSource
    }
}

impl SecretSource for MockSource {
    fn fetch(&self, mapping: &Mapping) -> Result<SecretShape, FetchError> {
        Ok(seeded(&mapping.secret_id)
            .unwrap_or_else(|| fallback(&mapping.secret_id, &mapping.environment)))
    }
}

/// Hand-seeded Sets keyed by `secret_id`. `prod` carries `database.replica.url`
/// and `GITHUB_APP_WEBHOOK_SECRET` that `staging` lacks (→ Gap);
/// `GITHUB_APP_ID` is identical (→ Aligned); the rest differ (→ Drift).
fn seeded(secret_id: &str) -> Option<SecretShape> {
    let json = match secret_id {
        "payments/prod" => PAYMENTS_PROD,
        "payments/staging" => PAYMENTS_STAGING,
        _ => return None,
    };
    Some(SecretShape::from_secret_string(json))
}

const PAYMENTS_PROD: &str = r#"{
  "database": {
    "primary": { "url": "postgres://prod-db.internal:5432/payments", "password": "prod-pw-9f04aa" },
    "pool": { "max": 200 },
    "replica": { "url": "postgres://prod-replica.internal:5432/payments" }
  },
  "GITHUB_APP_ID": 123456,
  "GITHUB_APP_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----prodKEYmaterial-----END RSA PRIVATE KEY-----",
  "GITHUB_APP_WEBHOOK_SECRET": "whsec_prod_44c1aa",
  "STRIPE_API_KEY": "sk_live_prod_b80a0011",
  "STRIPE_WEBHOOK_SECRET": "whsec_live_prod_c019aa"
}"#;

const PAYMENTS_STAGING: &str = r#"{
  "database": {
    "primary": { "url": "postgres://staging-db.internal:5432/payments", "password": "stg-pw-3ae8bb" },
    "pool": { "max": 20 }
  },
  "GITHUB_APP_ID": 123456,
  "GITHUB_APP_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----stagingKEYmaterial-----END RSA PRIVATE KEY-----",
  "STRIPE_API_KEY": "sk_test_stg_2f6caa",
  "STRIPE_WEBHOOK_SECRET": "whsec_test_stg_7d3ebb"
}"#;

/// Deterministically fabricate a plausible Set for an unseeded `secret_id`.
/// Same `(secret_id, environment)` always yields the same Set (no RNG), so the
/// matrix is stable across refreshes. Produces a mix: `SERVICE_NAME` is derived
/// from the base name only (→ Aligned across envs), `API_KEY`/`DATABASE_URL`
/// depend on `secret_id` which includes the env (→ Drift), and `LEGACY_TOKEN`
/// is prod-only (→ Gap).
fn fallback(secret_id: &str, environment: &str) -> SecretShape {
    let service = secret_id.split('/').next().unwrap_or(secret_id);
    let mut obj = serde_json::json!({
        "SERVICE_NAME": service,
        "API_KEY": fake_hex(&format!("{secret_id}:API_KEY")),
        "DATABASE_URL": format!("postgres://{service}-{}/{service}", fake_hex(secret_id)),
    });
    if environment == "prod" {
        obj["LEGACY_TOKEN"] = serde_json::Value::String(fake_hex(&format!("{secret_id}:LEGACY")));
    }
    SecretShape::from_secret_string(&obj.to_string())
}

/// A tiny deterministic non-secret hex tag (FNV-1a, 16 chars) — for fabricated
/// mock values only, never applied to real secret material.
fn fake_hex(seed: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in seed.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::{LeafKind, SecretShape};

    fn map(secret_id: &str, env: &str) -> Mapping {
        Mapping {
            environment: env.into(),
            account_id: "000000000000".into(),
            region: "us-east-1".into(),
            secret_id: secret_id.into(),
            permission_set: "ReadOnly".into(),
        }
    }

    /// Comparable snapshot of a Json shape: `name -> (exposed, kind)`, sorted by
    /// the BTreeMap so it is deterministic. `Value` has no `PartialEq`, so this
    /// is how we assert equality of shapes.
    fn entries(shape: &SecretShape) -> Vec<(String, String, LeafKind)> {
        match shape {
            SecretShape::Json(m) => m
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.expose().to_string(), v.kind()))
                .collect(),
            other => panic!("expected Json, got {other:?}"),
        }
    }

    fn value_of(shape: &SecretShape, name: &str) -> Option<(String, LeafKind)> {
        entries(shape)
            .into_iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, v, k)| (v, k))
    }

    #[test]
    fn seeded_payments_has_the_mockup_entries() {
        let prod = MockSource::new()
            .fetch(&map("payments/prod", "prod"))
            .unwrap();
        let names: Vec<String> = entries(&prod).into_iter().map(|(n, _, _)| n).collect();
        assert!(names.contains(&"database.primary.url".to_string()));
        assert!(names.contains(&"database.replica.url".to_string()));
        assert!(names.contains(&"GITHUB_APP_ID".to_string()));
    }

    #[test]
    fn seeded_github_app_id_aligned_replica_is_gap_stripe_drifts() {
        let prod = MockSource::new()
            .fetch(&map("payments/prod", "prod"))
            .unwrap();
        let stg = MockSource::new()
            .fetch(&map("payments/staging", "staging"))
            .unwrap();
        assert_eq!(
            value_of(&prod, "GITHUB_APP_ID"),
            value_of(&stg, "GITHUB_APP_ID"),
            "identical → Aligned"
        );
        assert_ne!(
            value_of(&prod, "STRIPE_API_KEY"),
            value_of(&stg, "STRIPE_API_KEY"),
            "differ → Drift"
        );
        assert!(
            value_of(&stg, "database.replica.url").is_none(),
            "replica is prod-only → Gap"
        );
    }

    #[test]
    fn fallback_is_deterministic_and_mixes_states() {
        let a = MockSource::new().fetch(&map("auth/prod", "prod")).unwrap();
        let b = MockSource::new().fetch(&map("auth/prod", "prod")).unwrap();
        assert_eq!(entries(&a), entries(&b), "same input → same shape");

        let prod = MockSource::new().fetch(&map("auth/prod", "prod")).unwrap();
        let stg = MockSource::new()
            .fetch(&map("auth/staging", "staging"))
            .unwrap();
        assert_eq!(
            value_of(&prod, "SERVICE_NAME"),
            value_of(&stg, "SERVICE_NAME"),
            "base-derived → Aligned"
        );
        assert_ne!(
            value_of(&prod, "API_KEY"),
            value_of(&stg, "API_KEY"),
            "secret_id includes env → Drift"
        );
        assert!(value_of(&stg, "LEGACY_TOKEN").is_none(), "prod-only → Gap");
    }
}
