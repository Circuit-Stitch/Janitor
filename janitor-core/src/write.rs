//! The provider-agnostic **write seam** types (ADR 0032 / ADR 0001 / ADR 0029):
//! the edit *unit*, its validation error, the compare-and-swap outcome, and the
//! masked confirm-diff summary a presenter shows before a write.
//!
//! These were born in `janitor-ssm`, then shared up into `janitor-aws-auth` for the
//! [`ResourceMethod`](../../janitor_aws_auth/method/trait.ResourceMethod.html) seam
//! (ADR 0031). They live **here in `core`** now (ADR 0032) because the
//! [`Provider::write`](crate::provider::Provider::write) port speaks them and `core`
//! cannot depend on any AWS crate — `janitor-aws-auth::write` re-exports them so the
//! AWS-family code keeps its `janitor_aws_auth::write::…` paths. The `.env`-flavoured
//! names are kept (the SSM writer is the only producer today); a future Secrets
//! Manager staged-put/CAS write (ADR 0001, still unbuilt) reuses the same
//! [`WriteOutcome`] CAS vocabulary.
//!
//! Pure data only — no I/O. The textual `apply_edits`/`encode_value` engine that
//! consumes an [`EnvEdit`] stays in `janitor-ssm` (it is `.env`-specific); this
//! module holds only the edit unit, its validation error, the CAS outcome, and the
//! masked [`summarize_edits`] confirm helper. A `Set`'s Value is secret and held
//! zeroizing; nothing here logs, `Debug`-prints, or summarizes it (THREAT-MODEL).

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

/// Which action one [`EnvEdit`] performs, for the masked confirm summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditAction {
    /// Set/overwrite a key. `value_len` carries the *length* of the new Value.
    Set,
    /// Remove a key.
    Remove,
}

/// A masked, presenter-ready summary of one pending edit, for the confirm-diff
/// dialog (ADR 0032). It carries the **non-secret** key + the action + (for a `Set`)
/// the new Value's **length only** — never the Value's plaintext, exactly as the
/// matrix masks a present cell as length-dots (THREAT-MODEL). Putting this masking in
/// `core` keeps the security rule in tested Rust, not an inline `.slint` expression
/// (ADR 0003), so the eventual confirm dialog renders an already-masked list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditSummary {
    /// The literal key this edit targets (non-secret metadata, OK to show).
    pub key: String,
    /// Whether the edit sets or removes the key.
    pub action: EditAction,
    /// The new Value's byte length for a `Set` (rendered as masked dots by the
    /// presenter); `None` for a `Remove` (nothing to write).
    pub value_len: Option<usize>,
}

/// Summarize pending `edits` into masked [`EditSummary`] lines for the confirm-diff
/// dialog, preserving order. The new Value is reduced to its **length** and never
/// copied out of its zeroizing buffer (THREAT-MODEL) — so the summary is safe to
/// cross to the UI thread and render, the same masking the matrix already applies.
pub fn summarize_edits(edits: &[EnvEdit]) -> Vec<EditSummary> {
    edits
        .iter()
        .map(|e| match e {
            EnvEdit::Set { key, value } => EditSummary {
                key: key.clone(),
                action: EditAction::Set,
                value_len: Some(value.len()),
            },
            EnvEdit::Remove { key } => EditSummary {
                key: key.clone(),
                action: EditAction::Remove,
                value_len: None,
            },
        })
        .collect()
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

    #[test]
    fn summarize_masks_a_set_to_key_and_length_never_the_value() {
        // The confirm-diff summary carries the key + the new Value's LENGTH only —
        // never the plaintext (THREAT-MODEL), exactly as the matrix masks a cell.
        let summary = summarize_edits(&[EnvEdit::set("DB_PASSWORD", "hunter2")]);
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].key, "DB_PASSWORD");
        assert_eq!(summary[0].action, EditAction::Set);
        assert_eq!(summary[0].value_len, Some(7), "the length of \"hunter2\"");
        assert!(
            !format!("{summary:?}").contains("hunter2"),
            "the masked summary must never carry the Value plaintext"
        );
    }

    #[test]
    fn summarize_marks_a_remove_with_no_length_and_preserves_order() {
        let summary =
            summarize_edits(&[EnvEdit::remove("OLD_KEY"), EnvEdit::set("NEW_KEY", "abcd")]);
        assert_eq!(summary.len(), 2, "order is preserved");
        assert_eq!(summary[0].key, "OLD_KEY");
        assert_eq!(summary[0].action, EditAction::Remove);
        assert_eq!(summary[0].value_len, None, "a Remove writes no Value");
        assert_eq!(summary[1].action, EditAction::Set);
        assert_eq!(summary[1].value_len, Some(4));
    }

    #[test]
    fn summarize_of_no_edits_is_empty() {
        assert!(summarize_edits(&[]).is_empty());
    }
}
