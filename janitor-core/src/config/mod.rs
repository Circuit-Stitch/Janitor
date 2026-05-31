//! Config: the user's saved, non-secret locations (Applications and their
//! per-Environment Mappings) plus Identity Center settings. This is the *only*
//! data Janitor writes to disk, and it holds **locations, never Values**
//! (THREAT-MODEL.md): the types below cannot structurally hold a secret.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Everything Janitor persists. Plain, non-secret data.
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

/// A named grouping of one logical Entry set across Environments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Application {
    /// User-facing Application name (e.g. `myapp`).
    pub name: String,
    /// One Mapping per Environment compared in this Application's matrix.
    pub environments: Vec<Mapping>,
}

/// Which concrete AWS Secret Set backs one Environment of an Application.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mapping {
    /// Environment name (e.g. `prod`, `staging`).
    pub environment: String,
    /// AWS account id that owns the Set.
    pub account_id: String,
    /// AWS region the Set lives in.
    pub region: String,
    /// Secret name or ARN of the Set.
    pub secret_id: String,
    /// IAM Identity Center permission set used to reach this account.
    pub permission_set: String,
}

/// Errors loading or saving [`Config`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The per-OS config directory could not be determined.
    #[error("could not determine the OS config directory")]
    NoConfigDir,
    /// Reading or writing the config file failed.
    #[error("config file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The config file was not valid TOML.
    #[error("config file is not valid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    /// The config could not be serialized to TOML.
    #[error("could not serialize config to TOML: {0}")]
    Serialize(#[from] toml::ser::Error),
}

impl Config {
    /// The default config file path: `<OS config dir>/config.toml`.
    ///
    /// The `(qualifier, organization, application)` triple below is a **stable
    /// path contract**: changing any of it relocates the config dir and silently
    /// orphans existing users' config (load then falls back to defaults). Settle
    /// these values before the first release.
    pub fn config_path() -> Result<PathBuf, ConfigError> {
        let dirs = directories::ProjectDirs::from("com", "Janitor", "Janitor")
            .ok_or(ConfigError::NoConfigDir)?;
        Ok(dirs.config_dir().join("config.toml"))
    }

    /// Load config from the default path (missing file → [`Config::default`]).
    pub fn load() -> Result<Config, ConfigError> {
        Self::load_from(&Self::config_path()?)
    }

    /// Save config to the default path, creating the directory if needed.
    pub fn save(&self) -> Result<(), ConfigError> {
        self.save_to(&Self::config_path()?)
    }

    /// Load config from an explicit path. Missing file → [`Config::default`].
    pub fn load_from(path: &Path) -> Result<Config, ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) => Ok(toml::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(ConfigError::Io(e)),
        }
    }

    /// Save config to an explicit path. Writes a sibling temp file then renames
    /// it over the target, so a concurrent reader never sees a half-written file
    /// (atomic with respect to readers). Not `fsync`-durable: a power loss
    /// mid-rename may leave the previous config — acceptable for locations-only
    /// data the user can re-enter.
    pub fn save_to(&self, path: &Path) -> Result<(), ConfigError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, text)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn default_config_is_empty() {
        let c = Config::default();
        assert!(c.sso_start_url.is_empty());
        assert!(c.secret_region.is_empty());
        assert!(c.last_pick.is_none());
        assert!(c.applications.is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = sample();
        original.save_to(&path).unwrap();
        assert_eq!(Config::load_from(&path).unwrap(), original);
    }

    #[test]
    fn missing_file_loads_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        assert_eq!(Config::load_from(&path).unwrap(), Config::default());
    }

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

    #[test]
    fn invalid_toml_is_a_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "this is = = not toml").unwrap();
        assert!(matches!(
            Config::load_from(&path).unwrap_err(),
            ConfigError::Parse(_)
        ));
    }

    #[test]
    fn save_creates_missing_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("sub").join("config.toml");
        sample().save_to(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn default_config_path_ends_with_config_toml() {
        // Relies on a resolvable home/config dir (true on dev machines & CI runners).
        let path = Config::config_path().unwrap();
        assert_eq!(path.file_name().unwrap(), "config.toml");
    }

    #[test]
    fn save_overwrites_existing_config_and_leaves_no_temp() {
        // Exercises the tmp+rename path's *overwrite* case — the reason the
        // pattern exists. Saving over an existing file replaces its contents and
        // leaves no stray `.toml.tmp` behind.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let tmp = path.with_extension("toml.tmp");

        sample().save_to(&path).unwrap();
        let updated = Config {
            sso_start_url: "https://new.awsapps.com/start".into(),
            ..sample()
        };
        updated.save_to(&path).unwrap();

        assert_eq!(Config::load_from(&path).unwrap(), updated);
        assert!(!tmp.exists(), "stale .toml.tmp left after successful save");
    }
}
