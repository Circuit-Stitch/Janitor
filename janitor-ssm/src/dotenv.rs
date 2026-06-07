//! `.env` → [`SecretShape`] parsing (ADR 0025, ADR 0008).
//!
//! A `.env` file is flat `KEY=VALUE` text, so it maps onto the *same* flat
//! representation a flat JSON Secret Set produces: each `KEY` becomes one
//! **literal** Entry Name and its decoded text becomes one zeroizing Entry
//! [`Value`]. That lets a remote `.env` slot straight into the existing
//! comparison / Aligned / Drift / Gap model with **no change to `janitor-core`**.
//!
//! This is a pure, offline function: it never touches AWS or disk, never logs,
//! and never carries a Value or any line content in its error. The SSM tail
//! (B3) is responsible for pulling the `&str` out of its `RawSecret` before
//! calling, and for mapping [`DotenvError`] onto a `FetchFailReason` at the wire
//! seam — a pure `.env` parser does not import the AWS error taxonomy.

use std::collections::BTreeMap;

use janitor_core::secret::{EntryName, SecretShape, Value};

/// A `.env` line could not be parsed.
///
/// Deliberately **error-safe**: it names at most the offending line's 1-based
/// number and **never** an Entry Name, a Value, or any line content
/// (THREAT-MODEL.md). B3 maps this onto a `FetchFailReason` at the SSM seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DotenvError {
    /// A non-comment, non-blank line had no `=`, so it is not a `KEY=VALUE`
    /// assignment. Carries the 1-based line number only.
    #[error("malformed .env line {line}")]
    Malformed { line: usize },
}

/// Parse `.env` text into a [`SecretShape::Json`] of Entry Name → [`Value`].
///
/// Each `KEY` is a **single literal** Entry Name built via
/// [`EntryName::from_path`]`(&[key])` (ADR 0008) — a KEY containing a dot is
/// escaped (`A.B` → `A\.B`), **not** read as a nested path; a `.env` key is
/// literal text, not a dotted JSON path. Every Value is stored in the zeroizing
/// [`Value`] type as a string leaf (`.env` values carry no JSON type).
///
/// Decoding rules (standard dotenv semantics):
/// - `#`-comment lines and blank / whitespace-only lines are ignored.
/// - a leading `export ` is stripped.
/// - an unquoted value runs up to a whitespace-preceded inline `#` comment
///   (which is dropped); surrounding whitespace is trimmed.
/// - a single-quoted value (`'…'`) is literal — no unescaping; an inner `#`
///   stays literal.
/// - a double-quoted value (`"…"`) has its quotes stripped and unescapes `\n`
///   and `\"`; an inner `#` stays literal.
/// - duplicate `KEY`s: last occurrence wins.
/// - an unterminated quote takes the value verbatim from the opening quote
///   onward (no special-casing, no error).
///
/// A non-comment, non-blank line with no `=` — or one with an empty KEY — returns
/// [`DotenvError::Malformed`] (carrying only the 1-based line number).
pub fn parse_dotenv(raw: &str) -> Result<SecretShape, DotenvError> {
    let mut entries: BTreeMap<EntryName, Value> = BTreeMap::new();

    for (index, line) in raw.lines().enumerate() {
        let line_number = index + 1; // 1-based, for an error-safe label only.
        let trimmed = line.trim_start();

        // Blank / whitespace-only lines and full-line `#` comments are ignored.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // A leading `export ` is cosmetic; drop it (and any gap after it).
        let assignment = trimmed
            .strip_prefix("export ")
            .map(str::trim_start)
            .unwrap_or(trimmed);

        let Some(eq) = assignment.find('=') else {
            return Err(DotenvError::Malformed { line: line_number });
        };

        // A keyless line (`=value`, or whitespace before `=`) is as malformed as
        // one with no `=`: it has no Entry Name. Rejecting it also avoids a
        // silent last-wins collision of several such lines onto one `""` Entry.
        let key = assignment[..eq].trim();
        if key.is_empty() {
            return Err(DotenvError::Malformed { line: line_number });
        }

        let value = decode_value(&assignment[eq + 1..]);

        // `BTreeMap::insert` overwrites, so duplicate KEYs resolve last-wins.
        entries.insert(EntryName::from_path(&[key.to_string()]), value);
    }

    Ok(SecretShape::Json(entries))
}

/// Decode the text to the right of the first `=` into a [`Value`]. Every `.env`
/// value is literal text, so the leaf is always a string.
fn decode_value(rhs: &str) -> Value {
    let rhs = rhs.trim_start();
    let decoded = match rhs.as_bytes().first() {
        Some(b'\'') => decode_single_quoted(rhs),
        Some(b'"') => decode_double_quoted(rhs),
        _ => decode_unquoted(rhs),
    };
    Value::string(decoded)
}

/// `'…'`: a literal — no unescaping, an inner `#` stays literal. Anything after
/// the closing quote (whitespace / a `# comment`) is dropped.
fn decode_single_quoted(rhs: &str) -> String {
    let inner = &rhs[1..]; // safe: `rhs` starts with the ASCII `'`.
    match inner.find('\'') {
        Some(end) => inner[..end].to_string(),
        // Unterminated: take the value verbatim from the opening quote onward.
        None => rhs.to_string(),
    }
}

/// `"…"`: strip the quotes, unescape `\n` and `\"`, keep an inner `#` literal.
/// Anything after the closing quote is dropped.
fn decode_double_quoted(rhs: &str) -> String {
    let mut out = String::with_capacity(rhs.len());
    let mut chars = rhs[1..].chars(); // skip the opening `"`.
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return out, // closing quote — drop the trailing remainder.
            // A backslash always consumes the next char, so a `\"` or a `\\`
            // can never let the real closing quote be re-read as an escape.
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('"') => out.push('"'),
                // Only `\n` and `\"` are recognized escapes (ADR 0025); any
                // other backslash (and the char after it) is kept literally.
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                // A lone trailing backslash before end-of-line: keep it.
                None => out.push('\\'),
            },
            other => out.push(other),
        }
    }
    // Unterminated: no closing quote → value verbatim from the opening quote.
    rhs.to_string()
}

/// Unquoted: trim surrounding whitespace and drop a trailing inline `#` comment.
/// A `#` starts a comment only when it begins the value or is preceded by
/// whitespace, so a `#` *inside* a token (a URL fragment, a password) stays
/// literal — standard dotenv behavior.
fn decode_unquoted(rhs: &str) -> String {
    let bytes = rhs.as_bytes();
    let mut end = rhs.len();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            end = i;
            break;
        }
    }
    rhs[..end].trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use janitor_core::secret::LeafKind;

    /// The Entry map from a successful parse, or panic.
    fn entries(raw: &str) -> BTreeMap<EntryName, Value> {
        match parse_dotenv(raw).expect("parse should succeed") {
            SecretShape::Json(map) => map,
            other => panic!("expected SecretShape::Json, got {other:?}"),
        }
    }

    /// The decoded text of the Entry named by a single literal `KEY`.
    fn value_of<'a>(map: &'a BTreeMap<EntryName, Value>, key: &str) -> &'a str {
        map[&EntryName::from_path(&[key.to_string()])].expose()
    }

    #[test]
    fn decodes_values_table() {
        // (raw .env, KEY, expected decoded value)
        let cases: &[(&str, &str, &str)] = &[
            // bare KEY=VALUE
            ("A=1", "A", "1"),
            // surrounding whitespace trimmed (key and unquoted value)
            ("A =  hello  ", "A", "hello"),
            // internal whitespace in an unquoted value is preserved
            ("A=a b c", "A", "a b c"),
            // leading `export ` stripped (and any extra gap after it)
            ("export TOKEN=abc", "TOKEN", "abc"),
            ("export   X=1", "X", "1"),
            // the `export ` prefix is exact: a KEY merely starting with the
            // letters `export`, or `export` + a tab, is NOT stripped
            ("exported=1", "exported", "1"),
            ("export\tA=1", "export\tA", "1"),
            // trailing inline `# comment` trimmed (whitespace-preceded, unquoted)
            ("A=hello # trailing comment", "A", "hello"),
            ("A=a b # c", "A", "a b"),
            // a `#` NOT preceded by whitespace stays literal (URL frag / password)
            ("A=pa#ss", "A", "pa#ss"),
            // a value that is only a comment decodes to empty
            ("A=# just a comment", "A", ""),
            // empty value
            ("A=", "A", ""),
            // single-quoted: literal, no unescaping, inner `#` stays literal
            (r"A='lit\n#x'", "A", r"lit\n#x"),
            // double-quoted: quotes stripped, `\n` and `\"` unescaped, `#` literal
            (r#"A="a\nb\"c#d""#, "A", "a\nb\"c#d"),
            // an unrecognized escape keeps its backslash literally
            (r#"A="x\ty""#, "A", r"x\ty"),
            // a backslash right before the closing quote stays literal and the
            // quote still terminates (a doubled `\\` stays doubled — no `\\` escape)
            (r#"A="end\\""#, "A", r"end\\"),
            (r#"A="a\\b""#, "A", r"a\\b"),
            (r#"A="C:\\" # path"#, "A", r"C:\\"),
            // trailing whitespace after a closing quote is trimmed
            (r#"A="v"   "#, "A", "v"),
            // a trailing comment after a closing quote is dropped
            (r#"A="v" # comment"#, "A", "v"),
            // unterminated double quote: verbatim from the opening quote
            (r#"A="unterminated"#, "A", r#""unterminated"#),
            // unterminated double quote ending in a lone backslash: verbatim
            (r#"A="ab\"#, "A", r#""ab\"#),
            // unterminated single quote: verbatim from the opening quote
            ("A='unterminated", "A", "'unterminated"),
        ];
        for (raw, key, expected) in cases {
            let map = entries(raw);
            assert_eq!(value_of(&map, key), *expected, "case: {raw:?}");
        }
    }

    #[test]
    fn ignores_comments_blank_and_whitespace_only_lines() {
        let raw = "# a full-line comment\n   # an indented comment\n\n   \t  \nA=1\nB=2\n";
        let map = entries(raw);
        assert_eq!(map.len(), 2);
        assert_eq!(value_of(&map, "A"), "1");
        assert_eq!(value_of(&map, "B"), "2");
    }

    #[test]
    fn duplicate_keys_last_wins() {
        let map = entries("A=first\nA=second\nA=third");
        assert_eq!(map.len(), 1);
        assert_eq!(value_of(&map, "A"), "third");
    }

    #[test]
    fn line_without_equals_is_malformed_and_leaks_nothing() {
        let raw = "A=ok\nthis_line_has_no_equals_sign\nB=ok";
        let err = parse_dotenv(raw).unwrap_err();
        assert_eq!(err, DotenvError::Malformed { line: 2 });

        // The error names a 1-based line number only — never the line content.
        let display = format!("{err}");
        let debug = format!("{err:?}");
        for rendered in [&display, &debug] {
            assert!(
                !rendered.contains("this_line_has_no_equals_sign"),
                "error leaked line content: {rendered}"
            );
        }
        assert!(
            display.contains('2'),
            "error should name the 1-based line: {display}"
        );
    }

    #[test]
    fn malformed_line_number_counts_skipped_blank_and_comment_lines() {
        // The line number is the *physical* 1-based line, so skipped blank and
        // comment lines still advance it — a refactor that counted only parsed
        // assignments would report the wrong line on a real-world `.env`.
        let cases: &[(&str, usize)] = &[("\n\nbadline", 3), ("# a comment\n\nA=ok\nbadline", 4)];
        for (raw, line) in cases {
            assert_eq!(
                parse_dotenv(raw).unwrap_err(),
                DotenvError::Malformed { line: *line },
                "case: {raw:?}"
            );
        }
    }

    #[test]
    fn keyless_line_is_malformed_and_leaks_nothing() {
        // A line with an `=` but no KEY (`=value`, or whitespace before `=`) is
        // malformed — it has no Entry Name, and several would otherwise collide
        // onto one `""` Entry via last-wins (silent data loss).
        for (raw, content) in [
            ("=SUPERSECRET", "SUPERSECRET"),
            ("   =alsosecret", "alsosecret"),
            ("\t= spaced", "spaced"),
        ] {
            let err = parse_dotenv(raw).unwrap_err();
            assert_eq!(err, DotenvError::Malformed { line: 1 }, "case: {raw:?}");
            // The error names only a line number — never the value content.
            for rendered in [format!("{err}"), format!("{err:?}")] {
                assert!(
                    !rendered.contains(content),
                    "error leaked line content: {rendered}"
                );
            }
        }
    }

    #[test]
    fn export_line_without_equals_is_malformed() {
        // The `export ` prefix is stripped *before* the no-`=` check, so an
        // `export` line that is not an assignment is still Malformed.
        assert_eq!(
            parse_dotenv("export NOEQ").unwrap_err(),
            DotenvError::Malformed { line: 1 }
        );
    }

    #[test]
    fn literal_dot_key_is_one_escaped_entry_not_nested() {
        let map = entries("A.B=v");
        let escaped = EntryName::from_path(&["A.B".to_string()]);
        let nested = EntryName::from_path(&["A".to_string(), "B".to_string()]);

        assert_eq!(map.len(), 1);
        assert_eq!(escaped.as_str(), "A\\.B");
        assert!(
            map.contains_key(&escaped),
            "KEY should be one literal Entry"
        );
        assert!(
            !map.contains_key(&nested),
            "a dotted KEY must NOT become a nested path"
        );
        assert_eq!(value_of(&map, "A.B"), "v");
    }

    #[test]
    fn every_value_is_a_string_leaf() {
        // `.env` values are text — `1`/`true`/`null` are strings, not typed
        // leaves (contrast a JSON Set, where these flatten to Number/Bool/Null).
        let map = entries("A=1\nB=true\nC=null\nD=\"x\"\nE='y'");
        for key in ["A", "B", "C", "D", "E"] {
            let v = &map[&EntryName::from_path(&[key.to_string()])];
            assert_eq!(
                v.kind(),
                LeafKind::String,
                "KEY {key} should be a String leaf"
            );
        }
    }

    #[test]
    fn debug_never_leaks_decoded_values() {
        // The whole-shape Debug (and thus any accidental log of it) must not
        // render a Value's plaintext (THREAT-MODEL.md).
        let shape = parse_dotenv("PASSWORD=hunter2").unwrap();
        assert!(
            !format!("{shape:?}").contains("hunter2"),
            "Debug leaked a Value"
        );
    }

    #[test]
    fn empty_input_yields_an_empty_json_shape() {
        assert!(entries("").is_empty());
    }
}
