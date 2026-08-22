//! `EntryName`: the dotted-path name of an Entry, with literal dots/backslashes
//! escaped so the path↔name mapping is a bijection (ADR 0008).

/// The name of an Entry: nested JSON keys joined by `.`, with any literal `.`
/// or `\` inside a key escaped (`.` → `\.`, `\` → `\\`). The mapping is
/// reversible, so `{"a.b": …}` and `{"a": {"b": …}}` get distinct names.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryName(String);

impl EntryName {
    /// Build a name from a key path (one element per nesting level).
    ///
    /// The path must be non-empty — every Entry has at least one key segment
    /// (ADR 0008), so `flatten` never produces an empty path. Asserted in debug
    /// builds to catch that programmer error at the boundary.
    pub fn from_path(path: &[String]) -> Self {
        debug_assert!(
            !path.is_empty(),
            "EntryName::from_path requires a non-empty path"
        );
        let escaped: Vec<String> = path.iter().map(|seg| escape_segment(seg)).collect();
        EntryName(escaped.join("."))
    }

    /// Recover the original key path. Inverse of [`EntryName::from_path`].
    pub fn segments(&self) -> Vec<String> {
        split_escaped(&self.0)
    }

    /// The rendered name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Rebuild a name from its rendered form — the inverse of [`EntryName::as_str`].
    ///
    /// A `RowKey` makes a round trip when a shell hands one back to ask for a
    /// reveal, and across the UniFFI boundary the rendered name is what actually
    /// crosses (ADR 0035). Anything `as_str` produced comes back identical.
    /// Anything else is normalized through the escaping rules rather than
    /// rejected, so a name always has one spelling.
    pub fn from_rendered(rendered: &str) -> Self {
        Self::from_path(&split_escaped(rendered))
    }
}

impl std::fmt::Display for EntryName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Debug for EntryName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // An Entry *name* is config metadata (e.g. DB_URL), not a secret.
        write!(f, "EntryName({:?})", self.0)
    }
}

fn escape_segment(seg: &str) -> String {
    let mut out = String::with_capacity(seg.len());
    for ch in seg.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '.' => out.push_str("\\."),
            other => out.push(other),
        }
    }
    out
}

/// Split an escaped name on unescaped `.` and unescape each segment.
fn split_escaped(name: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = name.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next() {
                // The next char is literal (escaped).
                Some(next) => current.push(next),
                // Trailing lone backslash (not produced by our escaper): keep it.
                None => current.push('\\'),
            },
            '.' => segments.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    segments.push(current);
    segments
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(segs: &[&str]) -> Vec<String> {
        segs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn joins_simple_path_with_dots() {
        assert_eq!(
            EntryName::from_path(&p(&["db", "primary", "url"])).as_str(),
            "db.primary.url"
        );
    }

    #[test]
    fn escapes_literal_dot_in_key() {
        // A single key containing a dot must NOT look like nesting.
        let dotted = EntryName::from_path(&p(&["a.b"]));
        let nested = EntryName::from_path(&p(&["a", "b"]));
        assert_eq!(dotted.as_str(), "a\\.b");
        assert_eq!(nested.as_str(), "a.b");
        assert_ne!(dotted, nested); // injective: distinct paths → distinct names
    }

    #[test]
    fn escapes_literal_backslash() {
        assert_eq!(EntryName::from_path(&p(&["a\\b"])).as_str(), "a\\\\b");
    }

    #[test]
    fn rendered_name_round_trips() {
        // What `as_str` renders, `from_rendered` reads back — the property the
        // UniFFI custom type for `EntryName` relies on (ADR 0035).
        for path in [
            p(&["A"]),
            p(&["db", "url"]),
            p(&["a.b"]),
            p(&["a", "b"]),
            p(&["a\\b"]),
            p(&["weird\\.key", "x"]),
            p(&[""]),
        ] {
            let name = EntryName::from_path(&path);
            assert_eq!(
                EntryName::from_rendered(name.as_str()),
                name,
                "round-trip failed for {path:?} -> {name}"
            );
        }
    }

    #[test]
    fn from_rendered_normalizes_a_name_our_escaper_never_writes() {
        // A trailing lone backslash is not something `from_path` emits. It is
        // read as a literal backslash and re-rendered escaped, so every name has
        // exactly one spelling.
        let normalized = EntryName::from_rendered("a\\");
        assert_eq!(normalized.segments(), p(&["a\\"]));
        assert_eq!(normalized.as_str(), "a\\\\");
    }

    #[test]
    fn path_round_trips_through_name() {
        let cases = vec![
            p(&["A"]),
            p(&["db", "url"]),
            p(&["a.b"]),
            p(&["a", "b"]),
            p(&["a\\b"]),
            p(&["a.b", "c"]),
            p(&["weird\\.key", "x"]),
            p(&[""]),      // single empty-string key
            p(&["a", ""]), // trailing empty segment
        ];
        for path in cases {
            let name = EntryName::from_path(&path);
            assert_eq!(
                name.segments(),
                path,
                "round-trip failed for {path:?} -> {name}"
            );
        }
    }
}
