//! The UniFFI boundary: `Command` and `Event` expressed for a foreign caller.
//!
//! The SwiftUI shell in `Janitor-macos` drives this crate the way the Slint shell
//! drives it in Rust (ADR 0035 / ADR 0036). Swift builds a [`Worker`], hands it an
//! [`EventSink`], sends [`Command`]s, and receives [`Event`]s. That is the whole
//! surface. It is the worker protocol, not a second one.
//!
//! The module is behind the `uniffi` Cargo feature, so a Slint build compiles none
//! of it (ADR 0035, Amendment 2026-08-21).
//!
//! ## Why UniFFI
//!
//! UniFFI has no Rust-to-foreign borrow type. Every payload crosses by value, so
//! "copy the secret out, never lend a pointer into a zeroizing buffer" is a
//! compiler rule rather than a review rule. Do not reintroduce a borrow.
//!
//! ## No `async fn` crosses
//!
//! Every exported function returns immediately. [`Worker::send`] queues a command
//! and returns; results arrive later on the sink. Swift gets a fire-and-forget call
//! plus a stream, never a `try await`. This also avoids UniFFI's async bindings
//! inheriting `@MainActor` under Xcode 26's `SWIFT_DEFAULT_ACTOR_ISOLATION`.
//!
//! ## Where the types are declared
//!
//! `Command` and `Event` are this crate's, so they carry the derive directly. The
//! types they *carry* belong to `janitor-core`, which has no UniFFI dependency —
//! adding one there would push `uniffi` into all four adapter crates and both
//! shells. They cross as `#[uniffi::remote]` mirrors instead. A mirror is
//! destructured by the generated code, so a field that is renamed, retyped, or
//! added in `janitor-core` fails to compile here. That is the tripwire.
//!
//! ## Checking the Swift
//!
//! `scripts/generate-swift-bindings.sh` generates the bindings and compiles them
//! as module `JanitorKit` with library evolution, which verifies the emitted
//! `.swiftinterface`. That verification is what catches an exported type sharing
//! the module's name (ADR 0035). The tests below cover the Rust half: every type
//! in the protocol lowers and lifts.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use janitor_core::compare::{EntryState, RowKey};
use janitor_core::config::{Application, Config, ConfigError, Mapping, Method};
use janitor_core::pane::{LoadStatus, MainPane};
use janitor_core::provider::{AppError, Failure, FetchFailReason, What};
use janitor_core::rows::MatrixItem;
use janitor_core::secret::{EntryName, LeafKind, Plaintext};
use janitor_core::sidebar::SidebarApp;
use janitor_core::view::{MatrixCell, MatrixRow, MatrixView};
use janitor_core::write::{EditAction, EditSummary, EnvEdit};

use crate::worker::{spawn, Command, Event, ProviderKind};

// ---------------------------------------------------------------------------
// Custom types
// ---------------------------------------------------------------------------

uniffi::custom_type!(
    /// `usize` is not one of UniFFI's primitives, and the protocol uses it for matrix
    /// coordinates, choice indexes, and byte lengths. It crosses as `u64`.
    ///
    /// Lowering is infallible on every platform Janitor targets, all of which are
    /// 32- or 64-bit. Lifting is checked, because a foreign caller controls the value.
    usize, u64, {
    remote,
    lower: |v| v as u64,
    try_lift: |v| Ok(usize::try_from(v)?),
});

uniffi::custom_type!(
    /// **The plaintext crossing.** An exposed secret Value reaches Swift here and
    /// nowhere else, and an edit's new Value enters here and nowhere else. Grep
    /// `Plaintext` to find every one (THREAT-MODEL).
    ///
    /// `expose_owned` is the deliberate copy out of the zeroizing buffer. Swift
    /// receives an ordinary `String`: to be legible the glyphs are already in the
    /// framebuffer, so the heap-string lifetime sits below the floor the display
    /// surface sets (ADR 0003, carried forward by ADR 0035). The Rust buffer still
    /// zeroes on drop.
    Plaintext, String, {
    remote,
    lower: |v| v.expose_owned(),
    try_lift: |v| Ok(Plaintext::new(v)),
});

uniffi::custom_type!(
    /// An Entry name crosses as its rendered form and comes back through the escaping
    /// rules (ADR 0008). Swift holds a `RowKey` it was given and hands it back to ask
    /// for a reveal, so this round trip is load-bearing.
    EntryName, String, {
    remote,
    lower: |v| v.as_str().to_owned(),
    try_lift: |v| Ok(EntryName::from_rendered(&v)),
});

// ---------------------------------------------------------------------------
// `janitor-core` types the protocol carries
// ---------------------------------------------------------------------------

#[uniffi::remote(Record)]
pub struct Config {
    pub sso_start_url: String,
    pub sso_region: String,
    pub secret_region: String,
    pub browser_command: Option<String>,
    pub last_pick: Option<Mapping>,
    pub entry_column_width: Option<f64>,
    pub applications: Vec<Application>,
}

#[uniffi::remote(Record)]
pub struct Application {
    pub name: String,
    pub environments: Vec<Mapping>,
}

#[uniffi::remote(Record)]
pub struct Mapping {
    pub environment: String,
    pub account_id: String,
    pub region: String,
    pub secret_id: String,
    pub permission_set: String,
    pub method: Method,
}

#[uniffi::remote(Enum)]
pub enum Method {
    SecretsManager,
    SsmDotenv,
}

#[uniffi::remote(Record)]
pub struct MatrixView {
    pub environments: Vec<String>,
    pub rows: Vec<MatrixRow>,
}

#[uniffi::remote(Record)]
pub struct MatrixRow {
    pub key: RowKey,
    pub name: String,
    pub state: EntryState,
    pub kind: Option<LeafKind>,
    pub cells: Vec<MatrixCell>,
}

#[uniffi::remote(Enum)]
pub enum MatrixCell {
    Present {
        len: usize,
        group: u32,
        hex: String,
        kind: Option<LeafKind>,
    },
    Absent,
}

#[uniffi::remote(Enum)]
pub enum RowKey {
    Entry(EntryName),
    WholeSet,
}

#[uniffi::remote(Enum)]
pub enum EntryState {
    Aligned,
    Drift,
    Gap,
}

#[uniffi::remote(Enum)]
pub enum LeafKind {
    String,
    Number,
    Bool,
    Null,
    Json,
}

/// A whole-Application load failure. It crosses as a record, not as a thrown
/// error: it is the payload of `Event::AppFailed`, which the shell renders as a
/// banner rather than catching.
#[uniffi::remote(Record)]
pub struct AppError {
    pub failures: Vec<Failure>,
}

#[uniffi::remote(Record)]
pub struct Failure {
    pub environment: String,
    pub reason: FetchFailReason,
    pub detail: String,
}

#[uniffi::remote(Enum)]
pub enum FetchFailReason {
    NeedsSignIn,
    AccessDenied,
    NotFound,
    Throttled,
    Unsupported,
    Other,
}

#[uniffi::remote(Enum)]
pub enum What {
    Accounts,
    Roles,
    Secrets,
    Instances,
    FilePath,
}

#[uniffi::remote(Enum)]
pub enum EnvEdit {
    Set { key: String, value: Plaintext },
    Remove { key: String },
}

#[uniffi::remote(Enum)]
pub enum MatrixItem {
    Header {
        label: String,
        count: usize,
    },
    Row {
        index: usize,
        zebra: bool,
        group_label: Option<String>,
    },
}

#[uniffi::remote(Record)]
pub struct SidebarApp {
    pub name: String,
    pub subtitle: String,
    pub drift: String,
    pub selected: bool,
}

#[uniffi::remote(Enum)]
pub enum MainPane {
    SignIn,
    Signing,
    Loading,
    EmptyApps,
    Matrix,
    Error,
}

#[uniffi::remote(Enum)]
pub enum LoadStatus {
    Idle,
    SigningIn,
    Loading,
    Loaded,
    Failed,
}

#[uniffi::remote(Enum)]
pub enum EditAction {
    Set,
    Remove,
}

#[uniffi::remote(Record)]
pub struct EditSummary {
    pub key: String,
    pub action: EditAction,
    pub value_len: Option<usize>,
}

// ---------------------------------------------------------------------------
// The boundary
// ---------------------------------------------------------------------------

/// How a foreign [`EventSink`] reports that it did not take an event.
///
/// UniFFI turns an unexpected foreign failure — a Swift error the sink does not
/// declare — into `UnexpectedUniFFICallbackError`. Without a `From` impl for it
/// the generated code panics on the worker thread, which is a thread the shell
/// never sees, so the app would go quiet with no diagnosis. This type is that
/// impl.
///
/// It carries no message. A foreign error's text is outside Janitor's masking
/// rules, so relaying it could put a Value or SDK text into a Rust log
/// (THREAT-MODEL).
#[derive(Debug, uniffi::Error)]
pub enum SinkError {
    /// The sink refused the event, or failed in a way it did not declare.
    Rejected,
}

impl std::fmt::Display for SinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the event sink did not accept the event")
    }
}

impl std::error::Error for SinkError {}

impl From<uniffi::UnexpectedUniFFICallbackError> for SinkError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Rejected
    }
}

/// Where a [`Worker`]'s events go. Swift implements this.
///
/// **Called on the worker thread, not the main thread.** A SwiftUI shell must
/// marshal to the main actor before touching view state.
#[uniffi::export(foreign)]
pub trait EventSink: Send + Sync {
    /// Take one event. Returning an error drops it; the worker keeps running.
    fn on_event(&self, event: Event) -> Result<(), SinkError>;
}

/// A running worker, addressable from Swift.
///
/// Constructing one spawns the thread and starts delivering to the sink. The
/// thread stops on `Command::Shutdown`.
#[derive(uniffi::Object)]
pub struct Worker {
    commands: Sender<Command>,
}

#[uniffi::export]
impl Worker {
    /// Spawn the worker and begin delivering events to `sink`.
    ///
    /// `kind` picks the Provider and `config` supplies the org locations. For AWS
    /// the browser Sign-in is deferred to the first `SignIn` or `LoadApp`.
    #[uniffi::constructor]
    pub fn start(kind: ProviderKind, config: Config, sink: Arc<dyn EventSink>) -> Arc<Self> {
        let commands = spawn(kind, config, move |event| {
            // A sink that refuses an event drops it. Logging the refusal here would
            // log on every event of a failing sink, and the reason is the foreign
            // side's to report.
            let _ = sink.on_event(event);
        });
        Arc::new(Self { commands })
    }

    /// Queue one command. Returns immediately; the reply arrives on the sink.
    ///
    /// A send after `Shutdown` is dropped rather than reported, because the
    /// protocol's only answer to a command is an event and a stopped worker emits
    /// none.
    pub fn send(&self, command: Command) {
        let _ = self.commands.send(command);
    }
}

/// Whether the cell at (`row`, `col`) is the one currently revealed.
///
/// Exported so the un-mask-exactly-one rule stays tested Rust. Reimplementing it
/// in Swift is what would un-mask a whole row of Values (`janitor_core::reveal`).
#[uniffi::export]
pub fn is_revealed(revealed_row: i32, revealed_col: i32, row: i32, col: i32) -> bool {
    janitor_core::reveal::is_revealed(revealed_row, revealed_col, row, col)
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// A failure loading or saving Config, as a thrown Swift error.
///
/// `janitor_core::config::ConfigError` carries an `io::Error`, a TOML parse error,
/// or a TOML serialize error as its source. Those types have no crossing of their
/// own, so the reason arrives as text. It is safe to show: Config holds locations
/// and view preferences and cannot structurally hold a Value (THREAT-MODEL), so
/// the worst a parse error can quote is a start URL or an account id the shell is
/// already displaying.
#[derive(Debug, uniffi::Error)]
pub enum ConfigFailure {
    /// The per-OS config directory could not be determined.
    NoConfigDir,
    /// Reading, writing, parsing, or serializing the file failed.
    File { reason: String },
}

impl std::fmt::Display for ConfigFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoConfigDir => f.write_str("could not determine the OS config directory"),
            Self::File { reason } => f.write_str(reason),
        }
    }
}

impl std::error::Error for ConfigFailure {}

impl From<ConfigError> for ConfigFailure {
    fn from(error: ConfigError) -> Self {
        match error {
            ConfigError::NoConfigDir => Self::NoConfigDir,
            other => Self::File {
                reason: other.to_string(),
            },
        }
    }
}

/// The Identity Center org: where the portal is and which region hosts it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IdentityCenter {
    pub start_url: String,
    pub region: String,
}

/// The Config the shell reads and writes, held in one place.
///
/// Config is a record, so it crosses by value. A shell that held its own copy
/// would be the place a Mapping is assembled and the place two copies disagree.
/// This object is the one copy: every read answers from it and every edit runs
/// `janitor_core`'s own rule — the duplicate-Environment refusal, the blank-name
/// refusal, the column-width floor — and then writes the file.
///
/// Every method here is synchronous and makes no network call.
#[derive(uniffi::Object)]
pub struct ConfigStore {
    inner: Mutex<Config>,
    /// Whether an edit reaches the file. False for the in-memory store, so an
    /// offline launch and the test suite cannot overwrite a real operator's
    /// Applications and Mappings.
    persist: bool,
}

impl ConfigStore {
    fn read<T>(&self, f: impl FnOnce(&Config) -> T) -> T {
        f(&self
            .inner
            .lock()
            .expect("the config lock is never poisoned"))
    }

    /// Run an edit, then persist. A refused edit writes nothing, so a rejected
    /// rename cannot rewrite the file with the name it refused.
    fn edit<T>(&self, f: impl FnOnce(&mut Config) -> (T, bool)) -> Result<T, ConfigFailure> {
        let mut config = self
            .inner
            .lock()
            .expect("the config lock is never poisoned");
        let (answer, changed) = f(&mut config);
        if changed && self.persist {
            config.save()?;
        }
        Ok(answer)
    }
}

#[uniffi::export]
impl ConfigStore {
    /// Read the config from its usual path. A missing file is not a failure: it
    /// loads as the default, which is what a first launch sees.
    #[uniffi::constructor]
    pub fn load() -> Result<Arc<Self>, ConfigFailure> {
        Ok(Arc::new(Self {
            inner: Mutex::new(Config::load()?),
            persist: true,
        }))
    }

    /// Build a store over a config that is never written. The mock Provider runs
    /// against this, so an offline launch cannot touch the real file. Edits still
    /// run every rule; they just stop before the write.
    #[uniffi::constructor]
    pub fn in_memory(config: Config) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(config),
            persist: false,
        })
    }

    /// The whole config, by value. `Worker::start` takes one of these.
    pub fn snapshot(&self) -> Config {
        self.read(Clone::clone)
    }

    /// The Applications in sidebar order.
    pub fn applications(&self) -> Vec<Application> {
        self.read(|c| c.applications.clone())
    }

    /// One Application's Environments, in column order. An index out of range
    /// answers empty, so a window bound to an Application that was removed
    /// elsewhere renders empty rather than trapping.
    pub fn environments(&self, application: usize) -> Vec<Mapping> {
        self.read(|c| {
            c.applications
                .get(application)
                .map(|a| a.environments.clone())
                .unwrap_or_default()
        })
    }

    /// The sidebar rows for a selection and a loaded view. The drift badge shows
    /// on the selected, loaded row alone — see `janitor_core::sidebar`.
    pub fn sidebar_apps(
        &self,
        selected: usize,
        view: MatrixView,
        status: LoadStatus,
    ) -> Vec<SidebarApp> {
        self.read(|c| janitor_core::sidebar::sidebar_apps(c, selected, &view, status.as_token()))
    }

    /// Which pane the main area shows.
    pub fn main_pane(&self, status: LoadStatus) -> MainPane {
        self.read(|c| janitor_core::pane::main_pane_of(status, !c.applications.is_empty()))
    }

    /// Add an Application with no Environments and answer its index. A blank name
    /// is refused and answers nothing.
    pub fn add_application(&self, name: String) -> Result<Option<usize>, ConfigFailure> {
        self.edit(|config| {
            let name = name.trim();
            if name.is_empty() {
                return (None, false);
            }
            config.applications.push(Application {
                name: name.to_string(),
                environments: Vec::new(),
            });
            (Some(config.applications.len() - 1), true)
        })
    }

    /// Remove an Application and every Environment mapped under it. This drops
    /// compare columns; it touches no Secret Set.
    pub fn remove_application(&self, index: usize) -> Result<(), ConfigFailure> {
        self.edit(|config| {
            if index >= config.applications.len() {
                return ((), false);
            }
            config.applications.remove(index);
            ((), true)
        })
    }

    /// Rename an Application, answering whether the name changed. A blank name is
    /// refused, so a stray Return cannot erase one.
    pub fn rename_application(&self, index: usize, name: String) -> Result<bool, ConfigFailure> {
        self.edit(|config| {
            let renamed = config.rename_application(index, &name);
            (renamed, renamed)
        })
    }

    /// Append a discovered Environment, answering whether it landed. A name
    /// already present is refused rather than overwritten: overwriting one would
    /// silently retarget a compare column at a different Secret Set.
    pub fn add_environment(
        &self,
        application: usize,
        mapping: Mapping,
    ) -> Result<bool, ConfigFailure> {
        self.edit(|config| match config.applications.get_mut(application) {
            Some(app) => {
                let added = app.add_environment(mapping).is_ok();
                (added, added)
            }
            None => (false, false),
        })
    }

    /// Remove one Environment from one Application.
    pub fn remove_environment(
        &self,
        application: usize,
        index: usize,
    ) -> Result<(), ConfigFailure> {
        self.edit(|config| match config.applications.get_mut(application) {
            Some(app) if index < app.environments.len() => {
                app.remove_environment(index);
                ((), true)
            }
            _ => ((), false),
        })
    }

    /// Fold auto-corrected permission sets into one Application (ADR 0018).
    ///
    /// A load can discover that the role an Environment names is gone and recover a
    /// working one. The recovered Mapping is matched by full identity — name and
    /// account and Secret id — so a same-named Environment in another Application
    /// can never be mis-corrected, and only `permission_set` is touched. Answers
    /// how many Environments changed.
    pub fn apply_corrected_roles(
        &self,
        application: usize,
        corrected: Vec<Mapping>,
    ) -> Result<usize, ConfigFailure> {
        self.edit(|config| match config.applications.get_mut(application) {
            Some(app) => {
                let applied = corrected
                    .iter()
                    .filter(|m| app.apply_corrected_role(m))
                    .count();
                (applied, applied > 0)
            }
            None => (0, false),
        })
    }

    /// The regions the browse picker offers: the known commercial ones, plus every
    /// region this operator already refers to, so their own is always present.
    pub fn region_choices(&self) -> Vec<String> {
        self.read(janitor_core::region::region_choices)
    }

    /// The region the next Discovery walk browses. One sticky value, shown in more
    /// than one place.
    pub fn browse_region(&self) -> String {
        self.read(|c| janitor_core::region::browse_region(c).to_string())
    }

    pub fn set_browse_region(&self, region: String) -> Result<(), ConfigFailure> {
        self.edit(|config| {
            let changed = config.secret_region != region;
            config.secret_region = region;
            ((), changed)
        })
    }

    /// The Identity Center start URL and the region hosting it.
    pub fn identity_center(&self) -> IdentityCenter {
        self.read(|c| IdentityCenter {
            start_url: c.sso_start_url.clone(),
            region: c.sso_region.clone(),
        })
    }

    pub fn set_identity_center(
        &self,
        start_url: String,
        region: String,
    ) -> Result<(), ConfigFailure> {
        self.edit(|config| {
            let changed = config.sso_start_url != start_url || config.sso_region != region;
            config.sso_start_url = start_url;
            config.sso_region = region;
            ((), changed)
        })
    }

    /// The persisted width of the matrix ENTRY column, in points. The caller
    /// supplies the floor and the fallback, so Config knows nothing about view
    /// sizes; it enforces one rule, that a stored width is never returned below
    /// the floor. `fallback` is what a column with nothing stored gets.
    ///
    /// The parameter is not called `default`. UniFFI writes an argument name
    /// straight into the C header, and `default` is a keyword there, so the
    /// generated module fails to build.
    pub fn entry_column_width(&self, minimum: f64, fallback: f64) -> f64 {
        self.read(|c| c.entry_column_width_or(minimum, fallback))
    }

    pub fn set_entry_column_width(&self, points: f64, minimum: f64) -> Result<(), ConfigFailure> {
        self.edit(|config| {
            config.set_entry_column_width(points, minimum);
            ((), true)
        })
    }
}

// ---------------------------------------------------------------------------
// The pure rules
//
// Each one delegates. The shell calls them rather than reimplementing them,
// because every rule below is already tested in `janitor-core` and a Swift copy
// would be an untested second answer.
// ---------------------------------------------------------------------------

/// An Entry name split for the two-tone render: the muted prefix up to and
/// including the last separator, and the bold final segment.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct NameParts {
    pub prefix: String,
    pub leaf: String,
}

/// The rendered row list. When `grouped`, names that share a prefix collapse under
/// a cluster header.
#[uniffi::export]
pub fn matrix_items(names: Vec<String>, grouped: bool) -> Vec<MatrixItem> {
    let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
    janitor_core::rows::matrix_items(&borrowed, grouped)
}

/// Split an Entry name for display, first dropping the cluster prefix its header
/// already shows.
#[uniffi::export]
pub fn display_name_parts(group_label: Option<String>, name: String) -> NameParts {
    let (prefix, leaf) = janitor_core::rows::display_name_parts(group_label.as_deref(), &name);
    NameParts {
        prefix: prefix.to_string(),
        leaf: leaf.to_string(),
    }
}

/// The type-badge text for a leaf kind. Empty for a Binary row, which has none.
#[uniffi::export]
pub fn badge_label(kind: Option<LeafKind>) -> String {
    janitor_core::rows::badge_label(kind).to_string()
}

/// The frozen STATE-column glyph.
#[uniffi::export]
pub fn state_glyph(state: EntryState) -> String {
    janitor_core::view::state_glyph(state).to_string()
}

/// The error banner: one `environment: detail` clause per failed Environment.
#[uniffi::export]
pub fn error_banner(error: AppError) -> String {
    janitor_core::errors::banner(&error)
}

/// The top-bar title for a pane.
#[uniffi::export]
pub fn pane_title(pane: MainPane) -> String {
    pane.title().to_string()
}

/// The centered body copy for a pane. On an error the `status_message` carries the
/// real, already-masked reason.
#[uniffi::export]
pub fn pane_body(pane: MainPane, status_message: Option<String>) -> String {
    pane.body_copy(status_message.as_deref().unwrap_or_default())
}

/// The question above a Discovery picker.
#[uniffi::export]
pub fn choice_prompt(what: What) -> String {
    what.prompt().to_string()
}

/// The short Method tag on an Environment row.
#[uniffi::export]
pub fn method_label(method: Method) -> String {
    method.label().to_string()
}

/// The full Method name, for the picker that chooses one before a walk.
#[uniffi::export]
pub fn method_name(method: Method) -> String {
    method.full_name().to_string()
}

/// Every Method, in the order a picker lists them.
#[uniffi::export]
pub fn method_choices() -> Vec<Method> {
    Method::all().to_vec()
}

/// Pending edits masked to key, action, and Value length. The length is what makes
/// a confirm dialog reviewable without putting the new Value on screen.
#[uniffi::export]
pub fn summarize_edits(edits: Vec<EnvEdit>) -> Vec<EditSummary> {
    janitor_core::write::summarize_edits(&edits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniffi::{Lift, Lower};

    /// Lower a value the way the FFI does, then lift it back. Every type in the
    /// protocol has to survive this, and the test suite is where that is checked
    /// without an Xcode project.
    fn round_trip<T>(value: T) -> T
    where
        T: Lower<crate::UniFfiTag> + Lift<crate::UniFfiTag>,
    {
        let mut buf = Vec::new();
        T::write(value, &mut buf);
        let mut slice = buf.as_slice();
        let lifted = T::try_read(&mut slice).expect("lifts back");
        assert!(slice.is_empty(), "the whole buffer is consumed");
        lifted
    }

    fn entry_key(name: &str) -> RowKey {
        RowKey::Entry(EntryName::from_path(&[name.to_string()]))
    }

    #[test]
    fn a_plaintext_survives_the_crossing_and_still_redacts() {
        let back = round_trip(Plaintext::new("sk_live_prod_b80a0011"));
        assert_eq!(back.expose(), "sk_live_prod_b80a0011");
        assert!(
            !format!("{back:?}").contains("sk_live"),
            "the lifted Plaintext must still redact its Debug"
        );
    }

    #[test]
    fn an_entry_name_survives_the_crossing_with_its_escaping() {
        // A dotted key and a nested path render differently and must stay
        // distinct across the boundary (ADR 0008).
        let dotted = EntryName::from_path(&["a.b".to_string()]);
        let nested = EntryName::from_path(&["a".to_string(), "b".to_string()]);
        assert_eq!(round_trip(dotted.clone()), dotted);
        assert_eq!(round_trip(nested.clone()), nested);
        assert_ne!(round_trip(dotted), round_trip(nested));
    }

    #[test]
    fn a_usize_survives_the_crossing() {
        assert_eq!(round_trip(0usize), 0);
        assert_eq!(round_trip(4_294_967_296usize), 4_294_967_296);
    }

    #[test]
    fn every_command_variant_crosses() {
        // Constructing one of each is what proves the payload types are all
        // FFI-able; the round trip proves the encoding agrees with itself.
        let mapping = Mapping {
            environment: "prod".to_string(),
            account_id: "111122223333".to_string(),
            region: "us-east-1".to_string(),
            secret_id: "myapp/prod".to_string(),
            permission_set: "ReadOnly".to_string(),
            method: Method::SecretsManager,
        };
        let commands = vec![
            Command::SignIn,
            Command::LoadApp(Application {
                name: "payments".to_string(),
                environments: vec![mapping.clone()],
            }),
            Command::Reveal {
                row: 0,
                col: 1,
                key: entry_key("STRIPE_API_KEY"),
            },
            Command::CopyValue {
                row: 2,
                col: 3,
                key: RowKey::WholeSet,
            },
            Command::BeginDiscovery {
                method: Method::SsmDotenv,
                environment: "staging".to_string(),
                region: "us-west-2".to_string(),
                remembered: Some(mapping.clone()),
            },
            Command::AdvanceDiscovery { choice: 4 },
            Command::ProvideInput("/opt/app/.env".to_string()),
            Command::SetReadWrite(true),
            Command::ApplyEdits {
                mapping,
                edits: vec![EnvEdit::set("A", "1"), EnvEdit::remove("B")],
            },
            Command::Shutdown,
        ];
        assert_eq!(
            commands.len(),
            10,
            "the protocol is 10 commands in; a new one needs a case here"
        );
        for command in commands {
            round_trip(command);
        }
    }

    #[test]
    fn every_event_variant_crosses() {
        let mapping = Mapping {
            environment: "prod".to_string(),
            account_id: "111122223333".to_string(),
            region: "us-east-1".to_string(),
            secret_id: "myapp/prod".to_string(),
            permission_set: "ReadOnly".to_string(),
            method: Method::SecretsManager,
        };
        let view = MatrixView {
            environments: vec!["prod".to_string(), "staging".to_string()],
            rows: vec![MatrixRow {
                key: entry_key("STRIPE_API_KEY"),
                name: "STRIPE_API_KEY".to_string(),
                state: EntryState::Gap,
                kind: Some(LeafKind::String),
                cells: vec![
                    MatrixCell::Present {
                        len: 21,
                        group: 0,
                        hex: "beef".to_string(),
                        kind: Some(LeafKind::String),
                    },
                    MatrixCell::Absent,
                ],
            }],
        };
        let events = vec![
            Event::SignInStarted,
            Event::SignedIn,
            Event::SignInFailed("could not reach Identity Center".to_string()),
            Event::AppLoading,
            Event::AppLoaded {
                view,
                corrected: vec![mapping.clone()],
                app_name: "payments".to_string(),
            },
            Event::AppFailed(AppError::needs_sign_in()),
            Event::Revealed {
                row: 0,
                col: 0,
                text: Plaintext::new("sk_live_prod_b80a0011"),
            },
            Event::RevealUnavailable,
            Event::CopyValue {
                row: 0,
                col: 0,
                text: Plaintext::new("sk_live_prod_b80a0011"),
            },
            Event::CopyUnavailable,
            Event::EnvDiscovered(mapping),
            Event::DiscoveryChoice {
                what: What::Accounts,
                labels: vec!["payments (111122223333)".to_string()],
                default: Some(0),
            },
            Event::DiscoveryInput {
                what: What::FilePath,
                prompt: "path to the .env".to_string(),
                default: Some("/opt/app/.env".to_string()),
            },
            Event::DiscoveryFailed("no accounts you can access".to_string()),
            Event::DiscoveryReauthRequired,
            Event::Warning("session logging archives this read".to_string()),
            Event::ReadWriteModeChanged(true),
            Event::WriteApplied {
                environment: "prod".to_string(),
            },
            Event::WriteConflict {
                environment: "prod".to_string(),
            },
            Event::WriteFailed {
                environment: "prod".to_string(),
                detail: "the write was refused".to_string(),
            },
            Event::WriteRefused {
                environment: "prod".to_string(),
            },
        ];
        assert_eq!(
            events.len(),
            21,
            "the protocol is 21 events out; a new one needs a case here"
        );
        for event in events {
            round_trip(event);
        }
    }

    #[test]
    fn a_config_survives_the_crossing() {
        // Swift hands one of these to `Worker::start`.
        let config = janitor_mock::seeded_config();
        assert_eq!(round_trip(config.clone()), config);
    }

    #[test]
    fn every_added_type_crosses() {
        // The Config surface and the pure rules carry six more core types (#97).
        round_trip(MatrixItem::Header {
            label: "database.*".to_string(),
            count: 3,
        });
        round_trip(MatrixItem::Row {
            index: 2,
            zebra: true,
            group_label: Some("database.*".to_string()),
        });
        round_trip(SidebarApp {
            name: "payments".to_string(),
            subtitle: "2 envs".to_string(),
            drift: "1 drift".to_string(),
            selected: true,
        });
        round_trip(MainPane::EmptyApps);
        round_trip(LoadStatus::SigningIn);
        round_trip(EditSummary {
            key: "STRIPE_API_KEY".to_string(),
            action: EditAction::Set,
            value_len: Some(21),
        });
        round_trip(IdentityCenter {
            start_url: "https://acme.awsapps.com/start".to_string(),
            region: "us-east-1".to_string(),
        });
        round_trip(NameParts {
            prefix: "database.".to_string(),
            leaf: "host".to_string(),
        });
    }

    #[test]
    fn every_exported_rule_is_the_core_one() {
        // Not reimplementations: each export delegates, so the tested rule in
        // janitor-core is the one Swift calls.
        let names = vec![
            "database.host".to_string(),
            "database.port".to_string(),
            "STRIPE_API_KEY".to_string(),
        ];
        let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
        for grouped in [false, true] {
            assert_eq!(
                matrix_items(names.clone(), grouped),
                janitor_core::rows::matrix_items(&borrowed, grouped)
            );
        }

        let parts = display_name_parts(Some("database.".to_string()), "database.host".to_string());
        let (prefix, leaf) =
            janitor_core::rows::display_name_parts(Some("database."), "database.host");
        assert_eq!(
            parts,
            NameParts {
                prefix: prefix.to_string(),
                leaf: leaf.to_string()
            }
        );

        assert_eq!(
            badge_label(Some(LeafKind::String)),
            janitor_core::rows::badge_label(Some(LeafKind::String))
        );
        assert_eq!(badge_label(None), janitor_core::rows::badge_label(None));

        for state in [EntryState::Aligned, EntryState::Drift, EntryState::Gap] {
            assert_eq!(state_glyph(state), janitor_core::view::state_glyph(state));
        }

        let error = AppError {
            failures: vec![Failure {
                environment: "prod".to_string(),
                reason: FetchFailReason::AccessDenied,
                detail: "access denied".to_string(),
            }],
        };
        assert_eq!(
            error_banner(error.clone()),
            janitor_core::errors::banner(&error)
        );

        for pane in [
            MainPane::SignIn,
            MainPane::Signing,
            MainPane::Loading,
            MainPane::EmptyApps,
            MainPane::Matrix,
            MainPane::Error,
        ] {
            assert_eq!(pane_title(pane), pane.title());
            assert_eq!(pane_body(pane, None), pane.body_copy(""));
            assert_eq!(
                pane_body(pane, Some("the role is gone".to_string())),
                pane.body_copy("the role is gone")
            );
        }

        for what in [
            What::Accounts,
            What::Roles,
            What::Secrets,
            What::Instances,
            What::FilePath,
        ] {
            assert_eq!(choice_prompt(what), what.prompt());
        }

        assert_eq!(method_choices(), Method::all().to_vec());
        for method in method_choices() {
            assert_eq!(method_label(method), method.label());
            assert_eq!(method_name(method), method.full_name());
        }

        // EnvEdit is not Clone: a Set holds a zeroizing Value, and a derived copy
        // would be a second buffer nothing zeroes. Each call builds its own.
        let edits = || vec![EnvEdit::set("A", "1234"), EnvEdit::remove("B")];
        assert_eq!(
            summarize_edits(edits()),
            janitor_core::write::summarize_edits(&edits())
        );
        assert_eq!(
            summarize_edits(edits())[0].value_len,
            Some(4),
            "a Set is masked to the new Value's length, never the Value"
        );
    }

    /// A store over the seeded mock config. Nothing here writes to disk: the
    /// in-memory constructor is what keeps a test run off a real operator's
    /// config.toml.
    fn store() -> Arc<ConfigStore> {
        ConfigStore::in_memory(janitor_mock::seeded_config())
    }

    #[test]
    fn the_in_memory_store_never_writes() {
        // Every edit below would otherwise reach Config::save and the real path.
        let store = store();
        assert!(!store.persist);
        store.add_application("scratch".to_string()).unwrap();
        store.set_browse_region("eu-west-1".to_string()).unwrap();
        store.set_entry_column_width(400.0, 120.0).unwrap();
        assert_eq!(store.browse_region(), "eu-west-1");
    }

    #[test]
    fn config_edits_run_the_core_rules() {
        let store = store();
        let before = store.applications().len();

        // A blank name is refused, and refusing writes nothing.
        assert_eq!(store.add_application("   ".to_string()).unwrap(), None);
        assert_eq!(store.applications().len(), before);

        let index = store
            .add_application("  payments  ".to_string())
            .unwrap()
            .expect("a real name lands");
        assert_eq!(store.applications()[index].name, "payments", "trimmed");

        assert!(!store.rename_application(index, "  ".to_string()).unwrap());
        assert_eq!(store.applications()[index].name, "payments");
        assert!(store
            .rename_application(index, "billing".to_string())
            .unwrap());
        assert_eq!(store.applications()[index].name, "billing");
        assert!(
            !store
                .rename_application(9_999, "nowhere".to_string())
                .unwrap(),
            "an index out of range is refused, not a panic"
        );

        let mapping = Mapping {
            environment: "prod".to_string(),
            account_id: "111122223333".to_string(),
            region: "us-east-1".to_string(),
            secret_id: "billing/prod".to_string(),
            permission_set: "ReadOnly".to_string(),
            method: Method::SecretsManager,
        };
        assert!(store.add_environment(index, mapping.clone()).unwrap());
        assert!(
            !store.add_environment(index, mapping).unwrap(),
            "a duplicate Environment is refused, never overwritten (ADR 0013)"
        );
        assert_eq!(store.environments(index).len(), 1);
        assert!(
            store.environments(9_999).is_empty(),
            "an index out of range answers empty rather than trapping"
        );

        store.remove_environment(index, 0).unwrap();
        assert!(store.environments(index).is_empty());

        store.remove_application(index).unwrap();
        assert_eq!(store.applications().len(), before);
    }

    #[test]
    fn a_corrected_role_lands_on_the_environment_it_was_computed_for() {
        let store = store();
        let index = store
            .add_application("billing".to_string())
            .unwrap()
            .expect("a real name lands");
        let mapping = Mapping {
            environment: "prod".to_string(),
            account_id: "111122223333".to_string(),
            region: "us-east-1".to_string(),
            secret_id: "billing/prod".to_string(),
            permission_set: "GoneRole".to_string(),
            method: Method::SecretsManager,
        };
        assert!(store.add_environment(index, mapping.clone()).unwrap());

        let recovered = Mapping {
            permission_set: "WorkingRole".to_string(),
            ..mapping.clone()
        };
        assert_eq!(
            store.apply_corrected_roles(index, vec![recovered]).unwrap(),
            1
        );
        assert_eq!(store.environments(index)[0].permission_set, "WorkingRole");

        // A same-named Environment pointing somewhere else is not the same
        // Environment (ADR 0018), so it is left alone.
        let elsewhere = Mapping {
            secret_id: "someone-else/prod".to_string(),
            permission_set: "WrongRole".to_string(),
            ..mapping
        };
        assert_eq!(
            store.apply_corrected_roles(index, vec![elsewhere]).unwrap(),
            0
        );
        assert_eq!(store.environments(index)[0].permission_set, "WorkingRole");
    }

    #[test]
    fn the_column_width_floor_survives_the_crossing() {
        let store = store();
        // Nothing stored yet: the caller's default, floored.
        assert_eq!(store.entry_column_width(120.0, 200.0), 200.0);
        assert_eq!(store.entry_column_width(240.0, 200.0), 240.0);

        store.set_entry_column_width(40.0, 120.0).unwrap();
        assert_eq!(
            store.entry_column_width(120.0, 200.0),
            120.0,
            "a width below the floor is clamped, not stored as given"
        );
    }

    #[test]
    fn the_browse_region_and_the_org_are_one_value_each() {
        let store = store();
        store
            .set_browse_region("ap-southeast-2".to_string())
            .unwrap();
        assert_eq!(store.browse_region(), "ap-southeast-2");
        assert!(
            store
                .region_choices()
                .contains(&"ap-southeast-2".to_string()),
            "the operator's own region is always offered"
        );

        store
            .set_identity_center(
                "https://acme.awsapps.com/start".to_string(),
                "us-east-1".to_string(),
            )
            .unwrap();
        assert_eq!(
            store.identity_center(),
            IdentityCenter {
                start_url: "https://acme.awsapps.com/start".to_string(),
                region: "us-east-1".to_string(),
            }
        );
        assert_eq!(store.snapshot().sso_region, "us-east-1");
    }

    #[test]
    fn the_store_answers_the_panes_and_the_sidebar_from_core() {
        let store = store();
        let view = MatrixView {
            environments: Vec::new(),
            rows: Vec::new(),
        };

        assert_eq!(store.main_pane(LoadStatus::Idle), MainPane::SignIn);
        assert_eq!(store.main_pane(LoadStatus::Loaded), MainPane::Matrix);

        let empty = ConfigStore::in_memory(Config::default());
        assert_eq!(
            empty.main_pane(LoadStatus::Loaded),
            MainPane::EmptyApps,
            "signed in with nothing configured points at the sidebar, not a blank matrix"
        );

        assert_eq!(
            store.sidebar_apps(0, view.clone(), LoadStatus::Loaded),
            janitor_core::sidebar::sidebar_apps(&store.snapshot(), 0, &view, "loaded")
        );
    }

    #[test]
    fn a_config_failure_keeps_its_reason() {
        // The variant with no source is named; every other kind arrives as text.
        assert!(matches!(
            ConfigFailure::from(janitor_core::config::ConfigError::NoConfigDir),
            ConfigFailure::NoConfigDir
        ));
        let io = janitor_core::config::ConfigError::Io(std::io::Error::other("disk is full"));
        let reason = io.to_string();
        match ConfigFailure::from(io) {
            ConfigFailure::File { reason: carried } => assert_eq!(carried, reason),
            other => panic!("an I/O failure is a File failure, got {other:?}"),
        }
    }

    #[test]
    fn the_exported_reveal_gate_is_the_core_one() {
        // Not a reimplementation: the export delegates, so the tested rule in
        // `janitor_core::reveal` is the one Swift calls.
        for row in 0..4i32 {
            for col in 0..4i32 {
                assert_eq!(
                    is_revealed(1, 2, row, col),
                    janitor_core::reveal::is_revealed(1, 2, row, col)
                );
                assert_eq!(is_revealed(1, 2, row, col), row == 1 && col == 2);
            }
        }
        assert!(
            !is_revealed(-1, -1, 0, 0),
            "the idle sentinel reveals nothing"
        );
    }

    #[test]
    fn a_refusing_sink_never_stops_the_worker() {
        // The `From<UnexpectedUniFFICallbackError>` impl is what keeps a foreign
        // failure from panicking the worker thread silently.
        struct Refusing;
        impl EventSink for Refusing {
            fn on_event(&self, _event: Event) -> Result<(), SinkError> {
                Err(SinkError::Rejected)
            }
        }
        let worker = Worker::start(
            ProviderKind::Mock,
            janitor_mock::seeded_config(),
            Arc::new(Refusing),
        );
        worker.send(Command::SignIn);
        worker.send(Command::Shutdown);
    }

    #[test]
    fn a_sink_receives_what_the_worker_emits() {
        use std::sync::mpsc::channel;
        struct Relay(std::sync::Mutex<std::sync::mpsc::Sender<Event>>);
        impl EventSink for Relay {
            fn on_event(&self, event: Event) -> Result<(), SinkError> {
                self.0
                    .lock()
                    .unwrap()
                    .send(event)
                    .map_err(|_| SinkError::Rejected)
            }
        }
        let (tx, rx) = channel();
        let worker = Worker::start(
            ProviderKind::Mock,
            janitor_mock::seeded_config(),
            Arc::new(Relay(std::sync::Mutex::new(tx))),
        );
        worker.send(Command::SignIn);
        // Time-bounded so a boundary that never calls the sink fails rather than
        // hanging the suite.
        let first = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the sink is driven from the worker thread");
        assert!(matches!(first, Event::SignInStarted));
        worker.send(Command::Shutdown);
    }
}
