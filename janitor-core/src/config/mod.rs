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
    /// Optional command Janitor runs to open the Sign-in browser, with `{url}`
    /// substituted for the authorize URL (e.g. `firefox -private-window {url}`).
    /// `None` → the OS default browser (today's behaviour). A private/incognito
    /// command isolates the Identity Center portal cookie from other browser-based
    /// AWS tools like the CLI (ADR 0033). The reserved value `"@native"` selects the
    /// macOS ephemeral `ASWebAuthenticationSession` opener (no separate browser app;
    /// degrades to the OS default off-macOS). Non-secret — a launch command, never a
    /// Value — so it is safe on disk (THREAT-MODEL). Consumed by
    /// `janitor_aws_auth::browser::select` (sentinel: `browser::NATIVE_SENTINEL`).
    pub browser_command: Option<String>,
    /// The last account/role/secret picked in the guided flow, offered as the
    /// default next run. A `Mapping` (its `environment` is `"live"` for guided
    /// picks). `None` until the first successful pick.
    pub last_pick: Option<Mapping>,
    /// Persisted width (logical px) of the matrix ENTRY column (#42). View-state,
    /// not a location and never a Value — structurally a number, so it is safe on
    /// disk (THREAT-MODEL). `None` until the user first drags the resize handle;
    /// the GUI then falls back to its layout default. Stored values are clamped to
    /// the layout floor by [`Config::set_entry_column_width`].
    pub entry_column_width: Option<f64>,
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

/// Rejected attempt to add an Environment whose name already exists in the
/// Application. Surfaced (not silently applied) because a Mapping is what stops
/// Janitor guessing which Secret Set an Environment means — overwriting one
/// would silently retarget a compare column (ADR 0013).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("environment \"{0}\" already exists")]
pub struct DuplicateEnvironment(pub String);

impl Application {
    /// Append a new Environment Mapping, refusing to overwrite an existing one.
    /// Returns [`DuplicateEnvironment`] (leaving the list untouched) when an
    /// Environment of the same name is already present — never a silent stomp.
    pub fn add_environment(&mut self, mapping: Mapping) -> Result<(), DuplicateEnvironment> {
        if self
            .environments
            .iter()
            .any(|m| m.environment == mapping.environment)
        {
            return Err(DuplicateEnvironment(mapping.environment));
        }
        self.environments.push(mapping);
        Ok(())
    }

    /// Remove the Environment Mapping at `index`. An out-of-range index is a
    /// no-op, so the caller (a GUI list) need not pre-validate.
    pub fn remove_environment(&mut self, index: usize) {
        if index < self.environments.len() {
            self.environments.remove(index);
        }
    }

    /// Apply a recovered role (ADR 0018) to the Environment it was computed for,
    /// updating ONLY `permission_set`. The target Environment is matched by full
    /// identity — name **and** `account_id` **and** `secret_id` — so a same-named
    /// Environment in a different Application (names are not unique) can never be
    /// mis-corrected. Returns whether a matching Environment was found. A
    /// location-only edit, never an account/secret retarget and never an append
    /// (so it cannot create or stomp a Mapping).
    pub fn apply_corrected_role(&mut self, corrected: &Mapping) -> bool {
        match self.environments.iter_mut().find(|m| {
            m.environment == corrected.environment
                && m.account_id == corrected.account_id
                && m.secret_id == corrected.secret_id
        }) {
            Some(m) => {
                m.permission_set = corrected.permission_set.clone();
                true
            }
            None => false,
        }
    }
}

/// Which AWS-family **Method** backs one Mapping — the swappable resource tail
/// behind the shared `account → role → mint` auth front half (ADR 0031). A closed
/// enum: `SecretsManager` reads the Set via `GetSecretValue`; `SsmDotenv` reads a
/// remote `.env` off an SSM-managed Instance. It is method *identity* (the same
/// granularity `What::{Secrets,Instances,FilePath}` already carries) — not the AWS
/// auth vocabulary `core` keeps out (ADR 0019); it lives here because `Mapping`
/// serializes it and the per-Mapping registry key must be provider-agnostic.
///
/// `Default` is `SecretsManager`, and the `Mapping::method` field is
/// `#[serde(default)]`, so every existing `config.toml` (written before this tag
/// existed, with no `method` key) loads as `SecretsManager` — exactly the prior
/// behaviour. `Ord`/`Hash` so it can key the shell's method registry.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// AWS Secrets Manager (`GetSecretValue`). The back-compat default.
    #[default]
    SecretsManager,
    /// A remote `.env` on an SSM-managed Instance, read over Session Manager.
    SsmDotenv,
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
    /// The [`Method`] that reaches this Set (ADR 0031). `#[serde(default)]` so a
    /// pre-`method` `config.toml` loads as [`Method::SecretsManager`]. `secret_id`
    /// keeps overloading the ARN (Secrets Manager) vs `<instance-id>:<path>` (SSM);
    /// this tag *disambiguates the method* so nothing parses the string to guess
    /// the backend.
    #[serde(default)]
    pub method: Method,
}

impl Method {
    /// The short tag an Environment row shows (ADR 0031). A location tag, never a
    /// Value. Both shells render it, so the mapping lives here rather than in
    /// either one.
    pub fn label(self) -> &'static str {
        match self {
            Method::SecretsManager => "SM",
            Method::SsmDotenv => "SSM",
        }
    }

    /// The full name, for the picker that chooses a Method before a walk starts.
    pub fn full_name(self) -> &'static str {
        match self {
            Method::SecretsManager => "AWS Secrets Manager",
            Method::SsmDotenv => "Remote .env over SSM",
        }
    }

    /// Every Method, in the order a picker lists them. [`Method::from_index`] is the
    /// inverse.
    ///
    /// A function rather than an associated `const`, because a `const` inside an `impl`
    /// carries a coverage region that is never executed, and llvm-cov attributes it to
    /// the lines that follow — which reported most of this file as unreached.
    pub fn all() -> &'static [Method] {
        &[Method::SecretsManager, Method::SsmDotenv]
    }

    /// Map a picker index to a Method. Index 0 is Secrets Manager and 1 is the
    /// remote `.env`; anything else falls back to the Secrets Manager default, so
    /// a picker that lost its selection cannot produce a Mapping with no method
    /// (ADR 0031 Decision 7).
    pub fn from_index(index: usize) -> Method {
        match index {
            1 => Method::SsmDotenv,
            _ => Method::SecretsManager,
        }
    }
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
    /// Rename the Application at `index` to the trimmed `name`. Returns whether
    /// the rename was applied: an empty/whitespace-only name or an out-of-range
    /// index is refused (so a stray Enter cannot blank an Application's name).
    pub fn rename_application(&mut self, index: usize, name: &str) -> bool {
        let name = name.trim();
        if name.is_empty() {
            return false;
        }
        match self.applications.get_mut(index) {
            Some(app) => {
                app.name = name.to_string();
                true
            }
            None => false,
        }
    }

    /// Resolve the persisted matrix ENTRY-column width (#42) in logical px,
    /// clamped to the `min` floor: a stored width is returned as-is when at/above
    /// the floor, clamped up to `min` if a stale or hand-edited value sits below
    /// it, and `default` (itself floored to `min`) when nothing is stored yet. The
    /// caller (the GUI) supplies the layout's floor/default so this stays ignorant
    /// of view px (ADR 0003) — it only enforces the never-below-floor invariant.
    pub fn entry_column_width_or(&self, min: f64, default: f64) -> f64 {
        match self.entry_column_width {
            Some(w) => w.max(min),
            None => default.max(min),
        }
    }

    /// Persist a resized matrix ENTRY-column width (#42), clamping to the `min`
    /// floor so a stored width can never violate the layout floor (even if a
    /// future caller passes a smaller value). View-state only — never a Value.
    pub fn set_entry_column_width(&mut self, px: f64, min: f64) {
        self.entry_column_width = Some(px.max(min));
    }

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

    #[test]
    fn a_method_carries_its_own_labels_and_its_picker_index() {
        // These moved out of janitor-gui, which had them as bin-local functions no
        // other shell could reach (ADR 0035 / #97).
        assert_eq!(Method::SecretsManager.label(), "SM");
        assert_eq!(Method::SsmDotenv.label(), "SSM");
        assert_eq!(Method::SecretsManager.full_name(), "AWS Secrets Manager");
        assert_eq!(Method::SsmDotenv.full_name(), "Remote .env over SSM");

        // ADR 0031 Decision 7: index 0 is the back-compat default, and so is any
        // index the picker should never produce.
        assert_eq!(Method::from_index(0), Method::SecretsManager);
        assert_eq!(Method::from_index(1), Method::SsmDotenv);
        assert_eq!(Method::from_index(99), Method::SecretsManager);
    }

    #[test]
    fn every_method_appears_in_picker_order() {
        // `all` is what a picker renders and `from_index` is what it sends back, so a
        // Method added to one and not the other would pick the wrong backend.
        assert_eq!(Method::all(), &[Method::SecretsManager, Method::SsmDotenv]);
        for (index, method) in Method::all().iter().enumerate() {
            assert_eq!(Method::from_index(index), *method);
        }
    }

    fn sample() -> Config {
        Config {
            sso_start_url: "https://acme.awsapps.com/start".into(),
            sso_region: "us-east-1".into(),
            secret_region: "us-west-2".into(),
            // A non-default value so the save/load round-trip test also proves the
            // optional command persists through TOML (None is simply omitted).
            browser_command: Some("firefox -private-window {url}".into()),
            last_pick: Some(Mapping {
                environment: "live".into(),
                account_id: "333333333333".into(),
                region: "us-west-2".into(),
                secret_id: "myapp/live".into(),
                permission_set: "ReadOnly".into(),
                method: Method::SecretsManager,
            }),
            entry_column_width: Some(280.0),
            applications: vec![Application {
                name: "myapp".into(),
                environments: vec![
                    Mapping {
                        environment: "prod".into(),
                        account_id: "111111111111".into(),
                        region: "us-east-1".into(),
                        secret_id: "myapp/prod".into(),
                        permission_set: "ReadOnly".into(),
                        method: Method::SecretsManager,
                    },
                    Mapping {
                        environment: "staging".into(),
                        account_id: "222222222222".into(),
                        region: "us-west-2".into(),
                        secret_id: "myapp/staging".into(),
                        permission_set: "ReadOnly".into(),
                        method: Method::SecretsManager,
                    },
                ],
            }],
        }
    }

    fn mapping(env: &str) -> Mapping {
        Mapping {
            environment: env.into(),
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            secret_id: format!("myapp/{env}"),
            permission_set: "ReadOnly".into(),
            method: Method::SecretsManager,
        }
    }

    #[test]
    fn add_environment_appends_a_new_mapping() {
        let mut app = Application {
            name: "myapp".into(),
            environments: vec![mapping("prod")],
        };
        app.add_environment(mapping("staging")).unwrap();
        let names: Vec<&str> = app
            .environments
            .iter()
            .map(|m| m.environment.as_str())
            .collect();
        assert_eq!(names, ["prod", "staging"]);
    }

    #[test]
    fn add_environment_rejects_a_duplicate_name_without_overwriting() {
        // The no-stomp invariant: re-adding "prod" must not replace its Mapping.
        let mut app = Application {
            name: "myapp".into(),
            environments: vec![mapping("prod")],
        };
        let mut intruder = mapping("prod");
        intruder.secret_id = "someone-elses/prod".into();

        let err = app.add_environment(intruder).unwrap_err();

        assert_eq!(err, DuplicateEnvironment("prod".into()));
        assert_eq!(app.environments.len(), 1, "no Mapping appended");
        assert_eq!(
            app.environments[0].secret_id, "myapp/prod",
            "existing Mapping left untouched (not overwritten)"
        );
    }

    #[test]
    fn remove_environment_drops_the_mapping_at_index() {
        let mut app = Application {
            name: "myapp".into(),
            environments: vec![mapping("prod"), mapping("staging"), mapping("dev")],
        };
        app.remove_environment(1);
        let names: Vec<&str> = app
            .environments
            .iter()
            .map(|m| m.environment.as_str())
            .collect();
        assert_eq!(names, ["prod", "dev"]);
    }

    #[test]
    fn remove_environment_out_of_range_is_a_noop() {
        let mut app = Application {
            name: "myapp".into(),
            environments: vec![mapping("prod")],
        };
        app.remove_environment(5);
        assert_eq!(app.environments.len(), 1);
    }

    #[test]
    fn apply_corrected_role_updates_only_permission_set_of_the_identity_match() {
        let mut app = Application {
            name: "myapp".into(),
            environments: vec![mapping("prod"), mapping("staging")],
        };
        let mut corrected = mapping("staging");
        corrected.permission_set = "PowerUser".into();
        assert!(app.apply_corrected_role(&corrected));
        let staging = &app.environments[1];
        assert_eq!(staging.permission_set, "PowerUser");
        // Only permission_set moved; the other locations are untouched.
        assert_eq!(staging.account_id, "111111111111");
        assert_eq!(staging.region, "us-east-1");
        assert_eq!(staging.secret_id, "myapp/staging");
        // prod is untouched.
        assert_eq!(app.environments[0].permission_set, "ReadOnly");
    }

    #[test]
    fn apply_corrected_role_is_a_noop_when_account_or_secret_differs() {
        // Same env NAME but a different account/secret (e.g. a same-named env in
        // another Application's matrix) must NOT be corrected — identity guard.
        let mut app = Application {
            name: "myapp".into(),
            environments: vec![mapping("prod")],
        };
        let mut wrong_account = mapping("prod");
        wrong_account.account_id = "999999999999".into();
        wrong_account.permission_set = "PowerUser".into();
        assert!(!app.apply_corrected_role(&wrong_account));
        assert_eq!(app.environments[0].permission_set, "ReadOnly");

        let mut wrong_secret = mapping("prod");
        wrong_secret.secret_id = "myapp/other".into();
        wrong_secret.permission_set = "PowerUser".into();
        assert!(!app.apply_corrected_role(&wrong_secret));
        assert_eq!(app.environments[0].permission_set, "ReadOnly");
    }

    #[test]
    fn rename_application_sets_the_trimmed_name() {
        let mut config = sample();
        assert!(config.rename_application(0, "  Renamed App  "));
        assert_eq!(config.applications[0].name, "Renamed App");
    }

    #[test]
    fn rename_application_refuses_a_blank_name() {
        let mut config = sample();
        assert!(!config.rename_application(0, "   "));
        assert_eq!(config.applications[0].name, "myapp", "name left unchanged");
    }

    #[test]
    fn rename_application_out_of_range_is_refused() {
        let mut config = sample();
        assert!(!config.rename_application(9, "Whatever"));
    }

    #[test]
    fn default_config_is_empty() {
        let c = Config::default();
        assert!(c.sso_start_url.is_empty());
        assert!(c.secret_region.is_empty());
        assert!(c.last_pick.is_none());
        assert!(c.entry_column_width.is_none());
        assert!(c.applications.is_empty());
    }

    #[test]
    fn entry_column_width_or_falls_back_to_default_when_unset() {
        // Never resized → the GUI's layout default (floored to `min`).
        let c = Config::default();
        assert_eq!(c.entry_column_width_or(200.0, 300.0), 300.0);
    }

    #[test]
    fn entry_column_width_or_returns_a_stored_value_at_or_above_the_floor() {
        let c = Config {
            entry_column_width: Some(420.0),
            ..Config::default()
        };
        assert_eq!(c.entry_column_width_or(200.0, 300.0), 420.0);
    }

    #[test]
    fn entry_column_width_or_clamps_a_below_floor_value_up_to_the_floor() {
        // A stale or hand-edited config below the layout floor must never render a
        // sub-floor column — the never-below-floor invariant holds on read too.
        let c = Config {
            entry_column_width: Some(120.0),
            ..Config::default()
        };
        assert_eq!(c.entry_column_width_or(200.0, 300.0), 200.0);
    }

    #[test]
    fn set_entry_column_width_stores_and_clamps_to_the_floor() {
        let mut c = Config::default();
        c.set_entry_column_width(360.0, 200.0);
        assert_eq!(c.entry_column_width, Some(360.0));
        // Below the floor → stored at the floor, never below it.
        c.set_entry_column_width(50.0, 200.0);
        assert_eq!(c.entry_column_width, Some(200.0));
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
        assert!(
            c.entry_column_width.is_none(),
            "missing entry_column_width → default None (GUI falls back to its layout default)"
        );
    }

    #[test]
    fn method_defaults_to_secrets_manager() {
        // The back-compat default (ADR 0031 Decision 6): an untagged Mapping is a
        // Secrets Manager one, so existing matrices keep working unchanged.
        assert_eq!(Method::default(), Method::SecretsManager);
        assert_eq!(mapping("prod").method, Method::SecretsManager);
    }

    #[test]
    fn mapping_round_trips_its_method_tag() {
        // A non-default method survives save → load (the per-Mapping selection a
        // mixed-method matrix records in Config).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut original = sample();
        original.applications[0].environments[1].method = Method::SsmDotenv;
        original.save_to(&path).unwrap();
        let loaded = Config::load_from(&path).unwrap();
        assert_eq!(loaded, original);
        assert_eq!(
            loaded.applications[0].environments[0].method,
            Method::SecretsManager,
            "prod kept its Secrets Manager method"
        );
        assert_eq!(
            loaded.applications[0].environments[1].method,
            Method::SsmDotenv,
            "staging's SSM method round-tripped"
        );
    }

    #[test]
    fn old_config_mapping_without_method_loads_as_secrets_manager() {
        // A config.toml written before the `method` tag existed (no `method` key on
        // its Mappings) must still load, defaulting every Mapping to Secrets Manager
        // — the exact prior behaviour (#[serde(default)], ADR 0031 Decision 6).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
sso_start_url = "https://old.awsapps.com/start"
sso_region = "us-east-1"

[[applications]]
name = "myapp"

[[applications.environments]]
environment = "prod"
account_id = "111111111111"
region = "us-east-1"
secret_id = "myapp/prod"
permission_set = "ReadOnly"
"#,
        )
        .unwrap();
        let c = Config::load_from(&path).unwrap();
        assert_eq!(
            c.applications[0].environments[0].method,
            Method::SecretsManager,
            "a Mapping with no `method` key defaults to Secrets Manager"
        );
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
