//! `Plaintext`: the type an exposed secret Value travels in.
//!
//! A revealed Value leaves the core in exactly one type, and an edit's new Value
//! enters in the same one. Naming that type makes every plaintext crossing one
//! greppable symbol, which is what lets the UniFFI boundary declare a single
//! custom type with a single `lower` closure (ADR 0035).
//!
//! The buffer zeroes on drop. Reading the content is an explicit call:
//! [`Plaintext::expose`] borrows it, [`Plaintext::expose_owned`] copies it out.
//! Those two names are the grep. Nothing else reaches the content — `Debug`
//! prints a redaction marker, and there is no `Display`.
//!
//! [`Value`](super::Value) is the *stored* secret and carries its JSON leaf type.
//! `Plaintext` is the *moving* one and carries no type tag, because a reveal and
//! a clipboard copy need the characters and nothing else.

use zeroize::Zeroizing;

/// One exposed secret Value in transit across a seam.
#[derive(Clone)]
pub struct Plaintext(Zeroizing<String>);

impl Plaintext {
    /// Take `text` into a zeroizing buffer.
    pub fn new(text: impl Into<String>) -> Self {
        Self(Zeroizing::new(text.into()))
    }

    /// Borrow the content. One of the two call sites a THREAT-MODEL review greps
    /// for; keep them few.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Copy the content out into a plain `String`, which does **not** zeroize.
    /// This is the deliberate hand-off: to a clipboard, to a widget property, or
    /// across the FFI. The buffer it was copied from still zeroes on drop.
    pub fn expose_owned(&self) -> String {
        self.0.as_str().to_owned()
    }

    /// The content's byte length. Masked presentation needs the length without
    /// touching the characters, the same way a matrix cell renders length-dots.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the content is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Plaintext {
    fn from(text: String) -> Self {
        Self::new(text)
    }
}

impl From<&str> for Plaintext {
    fn from(text: &str) -> Self {
        Self::new(text)
    }
}

// Manual Debug so a Plaintext never prints its content (THREAT-MODEL). Spelled
// out rather than derived, so the guarantee is local and obvious.
impl std::fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Plaintext")
            .field(&format_args!("<redacted>"))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_the_content_it_was_built_from() {
        let p = Plaintext::new("hunter2");
        assert_eq!(p.expose(), "hunter2");
        assert_eq!(p.expose_owned(), "hunter2");
    }

    #[test]
    fn debug_never_leaks_content() {
        let p = Plaintext::new("hunter2");
        let rendered = format!("{p:?}");
        assert!(
            !rendered.contains("hunter2"),
            "Debug leaked secret: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "Debug should show the explicit redaction marker: {rendered}"
        );
    }

    #[test]
    fn length_is_readable_without_touching_the_characters() {
        // The masked matrix and the confirm-diff summary both render a length.
        // They must reach it without an `expose` call, so a grep for `expose`
        // finds only the real plaintext reads.
        let p = Plaintext::new("hunter2");
        assert_eq!(p.len(), 7);
        assert!(!p.is_empty());
        assert!(Plaintext::new("").is_empty());
    }

    #[test]
    fn length_counts_bytes_not_characters() {
        // `len` is the byte length, matching `MatrixCell::Present.len` and
        // `EditSummary.value_len`, both of which are byte lengths.
        assert_eq!(Plaintext::new("é").len(), 2);
    }

    #[test]
    fn clone_and_conversions_round_trip() {
        let p = Plaintext::from("s3cret".to_string());
        assert_eq!(p.clone().expose(), "s3cret");
        assert_eq!(Plaintext::from("s3cret").expose(), "s3cret");
    }
}
