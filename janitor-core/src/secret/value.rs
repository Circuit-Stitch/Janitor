//! The secret Value of an Entry and the JSON leaf type it came from.

use secrecy::{ExposeSecret, SecretString};

/// The JSON type of a leaf, preserved so a v2 write round-trips the original
/// type (a numeric Entry serializes back as `5432`, not `"5432"`). See ADR 0008.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafKind {
    /// A JSON string. `content` is the unescaped string contents.
    String,
    /// A JSON number. `content` is the number token (e.g. `5432`, `1.5`).
    Number,
    /// A JSON boolean. `content` is `"true"` or `"false"`.
    Bool,
    /// JSON `null`. `content` is `"null"`.
    Null,
    /// An opaque JSON subtree kept verbatim: arrays and empty objects.
    /// `content` is the compact JSON text (e.g. `["a","b"]`, `{}`).
    Json,
}

/// One Entry's secret Value: content held in a zeroizing, redacted buffer plus
/// the JSON leaf type. The content is **never** exposed via `Debug`/`Display` —
/// only through the explicit [`Value::expose`] accessor.
pub struct Value {
    content: SecretString,
    kind: LeafKind,
}

impl Value {
    /// Construct a Value of the given kind from already-decoded content.
    pub fn new(content: impl Into<String>, kind: LeafKind) -> Self {
        Self {
            content: SecretString::from(content.into()),
            kind,
        }
    }

    /// A JSON string Value (also used for a Raw, non-JSON Secret Set).
    pub fn string(content: impl Into<String>) -> Self {
        Self::new(content, LeafKind::String)
    }

    /// The leaf's JSON type.
    pub fn kind(&self) -> LeafKind {
        self.kind
    }

    /// Borrow the secret content. Call sites that touch this are the ones that
    /// must respect the reveal/clipboard rules — keep them few.
    pub fn expose(&self) -> &str {
        self.content.expose_secret()
    }
}

// Manual Debug so a Value never prints its content. (`SecretString` already
// redacts; spelled out here so the guarantee is local and obvious.)
impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Value")
            .field("kind", &self.kind)
            .field("content", &format_args!("<redacted>"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_value_exposes_content_and_kind() {
        let v = Value::string("hunter2");
        assert_eq!(v.expose(), "hunter2");
        assert_eq!(v.kind(), LeafKind::String);
    }

    #[test]
    fn number_value_keeps_token_and_kind() {
        let v = Value::new("5432", LeafKind::Number);
        assert_eq!(v.expose(), "5432");
        assert_eq!(v.kind(), LeafKind::Number);
    }

    #[test]
    fn debug_never_leaks_content() {
        let v = Value::string("hunter2");
        let rendered = format!("{v:?}");
        assert!(
            !rendered.contains("hunter2"),
            "Debug leaked secret: {rendered}"
        );
        // Pin the explicit manual redaction marker, so swapping this impl for a
        // derive (which would redact via SecretString but lose the local
        // guarantee) is caught as a regression.
        assert!(
            rendered.contains("<redacted>"),
            "Debug should show the explicit redaction marker: {rendered}"
        );
    }
}
