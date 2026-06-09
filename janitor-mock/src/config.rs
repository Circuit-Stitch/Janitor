//! The seeded demo [`Config`] (relocated from the GUI). A few Applications whose
//! Mappings point at the canned/fabricated [`crate::data`] Sets, so the offline
//! Provider has something to load. Locations only — never a Value (THREAT-MODEL).

use janitor_core::config::{Application, Config, Mapping};

/// A few seeded Applications. Payments is hand-seeded in [`crate::data`]; the
/// others fall back to deterministic fabrication, and some have >2 Environments
/// to show the matrix generalize.
pub fn seeded_config() -> Config {
    let app = |name: &str, base: &str, envs: &[(&str, &str, &str)]| Application {
        name: name.into(),
        environments: envs
            .iter()
            .map(|(env, account, region)| Mapping {
                environment: (*env).into(),
                account_id: (*account).into(),
                region: (*region).into(),
                secret_id: format!("{base}/{env}"),
                permission_set: "ReadOnly".into(),
                method: janitor_core::config::Method::SecretsManager,
            })
            .collect(),
    };
    Config {
        sso_start_url: "https://identitycenter.amazonaws.com/ssoins-mockmock0000".into(),
        sso_region: "us-east-1".into(),
        applications: vec![
            app(
                "Payments API",
                "payments",
                &[
                    ("prod", "914xxxxxx021", "us-east-1"),
                    ("staging", "550xxxxxx118", "us-west-2"),
                ],
            ),
            app(
                "Auth Service",
                "auth",
                &[
                    ("prod", "914xxxxxx021", "us-east-1"),
                    ("staging", "550xxxxxx118", "us-west-2"),
                    ("dev", "330xxxxxx777", "us-west-2"),
                ],
            ),
            app(
                "Billing Worker",
                "billing",
                &[
                    ("prod", "914xxxxxx021", "us-east-1"),
                    ("staging", "550xxxxxx118", "us-west-2"),
                ],
            ),
            app(
                "Notifications",
                "notif",
                &[
                    ("prod", "914xxxxxx021", "us-east-1"),
                    ("staging", "550xxxxxx118", "us-west-2"),
                    ("dev", "330xxxxxx777", "us-west-2"),
                    ("qa", "330xxxxxx777", "us-west-2"),
                ],
            ),
        ],
        // secret_region / last_pick (ADR 0011) default to ""/None — the mock seed
        // needs neither. `..Default::default()` keeps this site from breaking when
        // locations-only Config fields are added.
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_the_four_demo_applications() {
        let cfg = seeded_config();
        let names: Vec<&str> = cfg.applications.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "Payments API",
                "Auth Service",
                "Billing Worker",
                "Notifications"
            ]
        );
    }

    #[test]
    fn payments_app_points_at_the_seeded_payments_sets() {
        // The Payments API Application's Mappings must use the `payments/{env}`
        // secret ids the canned data is keyed by, so loading it reproduces the
        // mockup's Aligned/Drift/Gap matrix rather than fabricated noise.
        let cfg = seeded_config();
        let payments = &cfg.applications[0];
        let ids: Vec<&str> = payments
            .environments
            .iter()
            .map(|m| m.secret_id.as_str())
            .collect();
        assert_eq!(ids, vec!["payments/prod", "payments/staging"]);
    }
}
