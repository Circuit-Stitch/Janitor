//! `janitor-ssm` — Janitor's remote-`.env`-over-SSM resource **Method**
//! ([Provider](../../CONTEXT.md) family, ADR 0025 / ADR 0031).
//!
//! It supplies a [`SsmDotenvMethod`] (the [`ResourceMethod`](janitor_aws_auth::ResourceMethod)
//! the generic `AwsFamilyProvider` shell drives) plus the [`SsmDiscovery`]
//! step-machine for its guided walk. The walk runs the shared `account → role →
//! mint Credential` front half over the [`janitor-aws-auth`](janitor_aws_auth) base
//! (it depends on `janitor-core` + `janitor-aws-auth`, **never** `janitor-aws`),
//! then walks its own tail: `instance → .env path → read+parse`. The auth shell
//! (sign-in, broker, the fetch ladder, ADR 0018 recovery) lives in the base, so
//! this crate is the Method's tail only.
//! A remote `.env` is flat `KEY=VALUE`, so [`parse_dotenv`] turns it into the
//! same flat [`SecretShape`](janitor_core::secret::SecretShape) a JSON Set
//! produces and it slots into the existing comparison model with no `core` change
//! (ADR 0008).
//!
//! ## Trust & memory posture
//! Nothing here is persisted. The SSO token and role Credentials live only in
//! memory, in zeroizing buffers (in `janitor-aws-auth`); a remote `.env`'s bytes
//! live in a zeroizing `RawSecret` and each Entry's Value in a zeroizing `Value`.
//! No SSM/SDK text or `.env` line content reaches a Value, an `Event`, or the
//! Diagnostic Log — read failures mask through `SessionError → FetchFailReason`
//! and a malformed `.env` through `DotenvError → FetchFailReason` at the SSM seam.
//! Read-only (ADR 0004). See ADR 0002 / ADR 0025 / THREAT-MODEL.md.
//!
//! ## Test seam
//! Each SSM op sits behind a narrow trait in [`wire`] whose I/O are our own
//! SDK-free types, so the orchestration/parsing/error-mapping is unit-tested
//! against the fakes here (plus the front-half fakes from
//! `janitor_aws_auth::wire::fakes`). The concrete SSM transport behind those
//! seams is the untested shell deferred to **B4** (ADR 0025 §3) and lives in the
//! GUI's worker shell until then, so this crate is all tested logic.

mod discovery;
mod dotenv;
mod dotenv_edit;
mod method;
mod source;
pub mod wire;

pub mod logging;
pub mod mgs;
pub mod transport;

pub use discovery::SsmDiscovery;
pub use dotenv::{parse_dotenv, DotenvError};
pub use dotenv_edit::{apply_edits, encode_value, sha256_hex, validate_edits};
pub use logging::{LoggingPreference, LoggingState};
pub use method::SsmDotenvMethod;
pub use source::{DotenvWriteError, SsmWriter};
pub use transport::{AwsInstanceCatalog, AwsLoggingPreference, SsmFileReader, SsmFileWriter};
// The write-seam types live in the shared base now (ADR 0031); re-export so the
// public `janitor-ssm` surface (the write binary, the GUI) is unchanged.
pub use janitor_aws_auth::write::{EnvEdit, EnvWriteError, WriteOutcome};
