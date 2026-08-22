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
use std::sync::Arc;

use janitor_core::compare::{EntryState, RowKey};
use janitor_core::config::{Application, Config, Mapping, Method};
use janitor_core::provider::{AppError, Failure, FetchFailReason, What};
use janitor_core::secret::{EntryName, LeafKind, Plaintext};
use janitor_core::view::{MatrixCell, MatrixRow, MatrixView};
use janitor_core::write::EnvEdit;

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
