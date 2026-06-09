//! The method-agnostic **write seam** types (ADR 0031 / ADR 0001 / ADR 0029).
//!
//! These were born in `janitor-ssm` (the only writer so far), but the
//! [`ResourceMethod`](crate::method::ResourceMethod) write method that *every*
//! AWS-family Method exposes lives here in the shared base, so its argument and
//! result types must too (a tail crate may not own the `ResourceMethod` trait).
//! The `.env`-flavoured names are kept (the SSM writer is the only producer today);
//! a future Secrets Manager staged-put/CAS write (ADR 0001, still unbuilt) reuses
//! the same [`WriteOutcome`] CAS vocabulary.
//!
//! Pure data only — no I/O. The textual `apply_edits`/`encode_value` engine that
//! consumes an [`EnvEdit`] stays in `janitor-ssm` (it is `.env`-specific); this
//! module holds only the edit *unit*, its validation error, and the CAS outcome.
//! A `Set`'s Value is secret and held zeroizing; nothing here logs or `Debug`-prints
//! it (THREAT-MODEL).

use zeroize::Zeroizing;

/// The compare-and-swap result of one remote write (ADR 0001). The CAS hash is the
/// file as read; the write commits only if it still matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The CAS matched and the atomic replace committed.
    Applied,
    /// The file's `sha256` no longer matched what we read, so the write refused
    /// (ADR 0001). The caller re-reads, re-applies onto the fresh text, and retries.
    Conflict,
}

/// One surgical edit to a remote Set, keyed by the **literal** key (a single
/// literal Entry-name segment, ADR 0008 — never a dotted path). The key is
/// non-secret config metadata; a `Set`'s value is secret and is held zeroizing
/// until the writer encodes it.
pub enum EnvEdit {
    /// Set `key` to `value`: rewrite the right-hand side of the **last** physical
    /// line owning `key` (duplicate keys are last-wins, mirroring the parser); if
    /// no line owns `key`, append a new `key=value` line.
    Set {
        key: String,
        value: Zeroizing<String>,
    },
    /// Remove **every** physical line owning `key` (leaving an earlier duplicate
    /// would keep the key present under last-wins). A no-op if no line owns `key`.
    Remove { key: String },
}

impl EnvEdit {
    /// A `Set` edit. `value` is the plaintext to write; it is taken into a
    /// zeroizing buffer immediately.
    pub fn set(key: impl Into<String>, value: impl Into<String>) -> Self {
        EnvEdit::Set {
            key: key.into(),
            value: Zeroizing::new(value.into()),
        }
    }

    /// A `Remove` edit.
    pub fn remove(key: impl Into<String>) -> Self {
        EnvEdit::Remove { key: key.into() }
    }

    /// The (non-secret) key this edit targets.
    pub fn key(&self) -> &str {
        match self {
            EnvEdit::Set { key, .. } | EnvEdit::Remove { key } => key,
        }
    }
}

// Manual Debug: a `Set`'s value is a secret Value and must never be printed
// (THREAT-MODEL). The key is non-secret metadata.
impl std::fmt::Debug for EnvEdit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvEdit::Set { key, .. } => f
                .debug_struct("Set")
                .field("key", key)
                .field("value", &format_args!("<redacted>"))
                .finish(),
            EnvEdit::Remove { key } => f.debug_struct("Remove").field("key", key).finish(),
        }
    }
}

/// Why a set of edits could not be applied. Error-safe: never carries a Value or
/// any line content (THREAT-MODEL).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvWriteError {
    /// A `Set` targets a key that is not a valid literal key — empty, or containing
    /// `=`, a newline, or leading/trailing whitespace (such a key has no unambiguous
    /// `KEY=VALUE` spelling, so writing it could corrupt the file). The key is
    /// non-secret metadata, but it is omitted to keep the error minimal.
    #[error("invalid .env key for a write")]
    InvalidKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_remove_constructors_carry_the_key() {
        assert_eq!(EnvEdit::set("DB_URL", "secret").key(), "DB_URL");
        assert_eq!(EnvEdit::remove("OLD").key(), "OLD");
    }

    #[test]
    fn debug_never_leaks_a_set_value_but_keeps_the_key() {
        let e = EnvEdit::set("PASSWORD", "hunter2");
        let rendered = format!("{e:?}");
        assert!(!rendered.contains("hunter2"), "Set Debug leaked a Value");
        assert!(rendered.contains("<redacted>"));
        assert!(
            rendered.contains("PASSWORD"),
            "the key is non-secret metadata"
        );
        // Remove has no value, so its Debug is unconditionally safe.
        assert!(format!("{:?}", EnvEdit::remove("OLD")).contains("OLD"));
    }

    #[test]
    fn write_outcome_is_a_plain_copy_enum() {
        assert_eq!(WriteOutcome::Applied, WriteOutcome::Applied);
        assert_ne!(WriteOutcome::Applied, WriteOutcome::Conflict);
    }
}
