//! `SecretShape`: how Janitor interprets a Secret Set's stored value
//! (ADR 0004 / ADR 0008).

use std::collections::BTreeMap;

use secrecy::{ExposeSecret, SecretBox};
use serde_json::Value as Json;

use super::flatten::flatten;
use super::name::EntryName;
use super::value::Value;

/// Opaque bytes of a `SecretBinary`, held in a zeroizing buffer and never
/// rendered (ADR 0004). The comparison engine compares them by content
/// (`bytes_eq`) and surfaces only their length as a masked token.
pub struct SecretBytes(SecretBox<[u8]>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes(SecretBox::from(bytes.into_boxed_slice()))
    }

    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Crate-internal byte equality, used by the comparison engine to group
    /// Binary cells. Deliberately **not** a public `PartialEq`: a secret type
    /// should not gain broad value comparison. Not constant-time — both
    /// operands are in-process secrets the same user owns, so there is no
    /// cross-trust timing channel to defend.
    pub(crate) fn bytes_eq(&self, other: &SecretBytes) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the bytes; length is a tolerated side-channel (CONTEXT.md).
        f.debug_struct("SecretBytes")
            .field("len", &self.len())
            .finish()
    }
}

/// How Janitor interprets a Secret Set's stored value.
#[derive(Debug)]
pub enum SecretShape {
    /// A JSON object, flattened to dotted-path Entries.
    Json(BTreeMap<EntryName, Value>),
    /// A value that is not a JSON object (non-JSON text, or a top-level JSON
    /// array/scalar): one opaque Entry holding the verbatim text.
    Raw(Value),
    /// `SecretBinary`: opaque bytes, never rendered.
    Binary(SecretBytes),
}

impl SecretShape {
    /// Interpret a `SecretString` value. A JSON *object* flattens to Entries;
    /// anything else is [`SecretShape::Raw`] holding the verbatim string.
    pub fn from_secret_string(secret_string: &str) -> Self {
        match serde_json::from_str::<Json>(secret_string) {
            Ok(Json::Object(object)) => SecretShape::Json(flatten(&object)),
            _ => SecretShape::Raw(Value::string(secret_string)),
        }
    }

    /// Interpret a `SecretBinary` value: always [`SecretShape::Binary`].
    pub fn from_secret_binary(bytes: Vec<u8>) -> Self {
        SecretShape::Binary(SecretBytes::new(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::value::LeafKind;

    #[test]
    fn json_object_becomes_entries() {
        match SecretShape::from_secret_string(r#"{"A":"1"}"#) {
            SecretShape::Json(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries.values().next().unwrap().expose(), "1");
            }
            other => panic!("expected Json, got {other:?}"),
        }
    }

    #[test]
    fn non_json_text_becomes_raw() {
        match SecretShape::from_secret_string("just-a-token") {
            SecretShape::Raw(v) => {
                assert_eq!(v.expose(), "just-a-token");
                assert_eq!(v.kind(), LeafKind::String);
            }
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    #[test]
    fn top_level_array_is_raw_verbatim() {
        match SecretShape::from_secret_string("[1,2,3]") {
            SecretShape::Raw(v) => assert_eq!(v.expose(), "[1,2,3]"),
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    #[test]
    fn top_level_scalar_is_raw_verbatim() {
        // "1.50" re-serializes as "1.5" under serde_json; Raw must preserve the
        // original string exactly rather than re-serialize through the parser.
        match SecretShape::from_secret_string("1.50") {
            SecretShape::Raw(v) => assert_eq!(v.expose(), "1.50"),
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    #[test]
    fn binary_reports_length() {
        match SecretShape::from_secret_binary(vec![1, 2, 3, 4]) {
            SecretShape::Binary(b) => {
                assert_eq!(b.len(), 4);
                assert!(!b.is_empty());
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn bytes_eq_compares_contents_not_just_length() {
        let a = SecretBytes::new(vec![1, 2, 3]);
        let b = SecretBytes::new(vec![1, 2, 3]);
        let same_len_diff = SecretBytes::new(vec![1, 2, 4]); // equal length, different bytes
        let diff_len = SecretBytes::new(vec![1, 2]);
        assert!(a.bytes_eq(&b), "identical bytes must be equal");
        assert!(
            !a.bytes_eq(&same_len_diff),
            "equal length but different bytes must NOT be equal"
        );
        assert!(!a.bytes_eq(&diff_len), "different length must not be equal");
    }

    #[test]
    fn debug_redacts_values_and_bytes() {
        let json = SecretShape::from_secret_string(r#"{"password":"hunter2"}"#);
        assert!(
            !format!("{json:?}").contains("hunter2"),
            "leaked value in Debug"
        );

        let bin = SecretShape::from_secret_binary(vec![1, 2, 3, 4]);
        assert!(
            format!("{bin:?}").contains("len: 4"),
            "Binary Debug should show length"
        );

        let raw = SecretShape::from_secret_string("hunter2");
        assert!(
            !format!("{raw:?}").contains("hunter2"),
            "leaked value in Raw Debug"
        );
    }
}
