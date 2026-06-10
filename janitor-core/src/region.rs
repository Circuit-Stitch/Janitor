//! Region choices for the Discovery browse-region picker (ADR 0015): the
//! console-style dropdown of selectable AWS regions, plus the browse-region
//! resolve rule. Pure/sync and fully tested; the GUI binds to it so no region
//! logic lives in the view (ADR 0003). A region name is a location, never a
//! Value, so all of this is safe on disk (THREAT-MODEL).

use crate::config::Config;

/// Standard commercial AWS regions offered in the picker, in a stable display
/// order. Not enumerated live from AWS (ADR 0015): a static list is offline,
/// deterministic, and trivially testable; staleness is repaired by editing this
/// list. A user's own gov/opt-in region still appears — [`region_choices`]
/// unions in the regions they already reference.
pub const KNOWN_REGIONS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ca-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-north-1",
    "eu-south-1",
    "ap-south-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-southeast-1",
    "ap-southeast-2",
    "sa-east-1",
];

/// The regions to offer in the picker (ADR 0015): the known commercial regions,
/// plus any region the user already references, so their own region always
/// appears. Known regions come first in their canonical order.
pub fn region_choices(config: &Config) -> Vec<String> {
    let mut choices: Vec<String> = KNOWN_REGIONS.iter().map(|r| r.to_string()).collect();
    let mut push_if_new = |region: &str| {
        if !region.is_empty() && !choices.iter().any(|c| c == region) {
            choices.push(region.to_string());
        }
    };
    push_if_new(&config.sso_region);
    if let Some(last) = &config.last_pick {
        push_if_new(&last.region);
    }
    for app in &config.applications {
        for mapping in &app.environments {
            push_if_new(&mapping.region);
        }
    }
    choices
}

/// The region Discovery browses, and the picker's current selection (ADR
/// 0013/0015): `secret_region` if the user set it, else a fall back to
/// `sso_region`. An empty `secret_region` keeps meaning "use the SSO region,"
/// so a single-region org needs no region input.
pub fn browse_region(config: &Config) -> &str {
    if config.secret_region.is_empty() {
        &config.sso_region
    } else {
        &config.secret_region
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Application, Mapping, Method};

    #[test]
    fn default_config_offers_standard_commercial_regions() {
        let choices = region_choices(&Config::default());
        assert!(
            choices.iter().any(|r| r == "us-east-1"),
            "picker should offer us-east-1; got {choices:?}"
        );
        assert!(
            choices.iter().any(|r| r == "us-west-2"),
            "picker should offer us-west-2; got {choices:?}"
        );
    }

    #[test]
    fn includes_users_sso_region_when_outside_the_static_list() {
        let config = Config {
            sso_region: "us-gov-west-1".into(),
            ..Config::default()
        };
        let choices = region_choices(&config);
        assert!(
            choices.iter().any(|r| r == "us-gov-west-1"),
            "a user's own SSO region must always appear; got {choices:?}"
        );
    }

    /// A [`Mapping`] in `region`, attached to a fresh single-Environment
    /// Application — the minimum to put a region on a saved Mapping.
    fn config_with_mapping_region(region: &str) -> Config {
        Config {
            applications: vec![Application {
                name: "myapp".into(),
                environments: vec![Mapping {
                    environment: "prod".into(),
                    account_id: "111111111111".into(),
                    region: region.into(),
                    secret_id: "arn:secret".into(),
                    permission_set: "ReadOnly".into(),
                    method: Method::default(),
                }],
            }],
            ..Config::default()
        }
    }

    #[test]
    fn includes_regions_from_saved_mappings() {
        let config = config_with_mapping_region("us-gov-east-1");
        let choices = region_choices(&config);
        assert!(
            choices.iter().any(|r| r == "us-gov-east-1"),
            "a region the user already discovered into must appear; got {choices:?}"
        );
    }

    #[test]
    fn never_duplicates_a_known_region() {
        // sso_region and a Mapping region that are both already known: each must
        // appear exactly once, and known regions stay first.
        let mut config = config_with_mapping_region("us-west-2");
        config.sso_region = "us-east-1".into();
        let choices = region_choices(&config);
        assert_eq!(
            choices.iter().filter(|r| *r == "us-east-1").count(),
            1,
            "us-east-1 must not be duplicated; got {choices:?}"
        );
        assert_eq!(
            choices.iter().filter(|r| *r == "us-west-2").count(),
            1,
            "us-west-2 must not be duplicated; got {choices:?}"
        );
        assert_eq!(
            choices.len(),
            KNOWN_REGIONS.len(),
            "no new entries when every referenced region is already known"
        );
    }

    #[test]
    fn browse_region_falls_back_to_sso_region_when_secret_region_unset() {
        let config = Config {
            sso_region: "us-east-1".into(),
            secret_region: String::new(),
            ..Config::default()
        };
        assert_eq!(browse_region(&config), "us-east-1");
    }

    #[test]
    fn browse_region_uses_secret_region_when_the_user_picked_one() {
        let config = Config {
            sso_region: "us-east-1".into(),
            secret_region: "us-west-2".into(),
            ..Config::default()
        };
        assert_eq!(
            browse_region(&config),
            "us-west-2",
            "a picked browse region overrides the SSO region"
        );
    }

    #[test]
    fn includes_the_remembered_last_pick_region() {
        let config = Config {
            last_pick: Some(Mapping {
                environment: "live".into(),
                account_id: "222222222222".into(),
                region: "us-gov-west-1".into(),
                secret_id: "arn:secret".into(),
                permission_set: "ReadOnly".into(),
                method: Method::default(),
            }),
            ..Config::default()
        };
        let choices = region_choices(&config);
        assert!(
            choices.iter().any(|r| r == "us-gov-west-1"),
            "the remembered last-pick region must appear; got {choices:?}"
        );
    }
}
