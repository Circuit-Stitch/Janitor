//! The `.env` **write** side (ADR 0029; semantics from ADR 0028 / ADR 0001): the
//! pure op-apply → new-content step and the value encoder that is a *total*
//! inverse of [`parse_dotenv`](crate::dotenv::parse_dotenv).
//!
//! Two pure pieces, both fully unit-tested (no I/O, no AWS, no clock):
//!
//! - [`encode_value`] turns a Value's plaintext into the right-hand side of a
//!   `.env` line such that `parse_dotenv("K=" + encode_value(v)) == v` for **every**
//!   `v` — the totality the `\\` grammar amendment (ADR 0025) enables. It picks the
//!   least-noisy faithful style (bare, then single-quoted, then a universally
//!   correct double-quoted fallback).
//! - [`apply_edits`] is the **non-stomping** transform (ADR 0001): given the
//!   freshly-read raw `.env` *text* and a list of per-Entry [`EnvEdit`]s, it
//!   rewrites only the edited keys' lines and **preserves comments, blank lines,
//!   ordering, indentation, `export `, and the file's line endings** byte-for-byte
//!   on every untouched line. It mirrors `parse_dotenv`'s line model exactly so
//!   "the key the user edited" maps to the same physical line the parser read.
//!
//! All secret material (the new Values, the assembled file) is held in zeroizing
//! buffers; nothing here logs or `Debug`-prints a Value (THREAT-MODEL).

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// The write-edit unit + its validation error live in `janitor-core` now (ADR 0032,
// so the `Provider::write` port can speak them), re-exported through
// `janitor_aws_auth::write` for the AWS-family callers. The `.env`-specific *engine*
// that consumes them (`apply_edits`/`encode_value`) stays here.
use janitor_aws_auth::write::{EnvEdit, EnvWriteError};

/// Encode `value`'s plaintext into the right-hand side of a `.env` line that
/// re-parses to exactly `value` (a total inverse of `parse_dotenv`, ADR 0029).
/// Prefers the least-noisy faithful style; the double-quoted fallback is correct
/// for **every** string, so this is total (never fails). Pure; the returned
/// `String` holds secret content — the caller keeps it zeroizing.
pub fn encode_value(value: &str) -> String {
    if can_unquoted(value) {
        value.to_string()
    } else if can_single_quoted(value) {
        format!("'{value}'")
    } else {
        encode_double_quoted(value)
    }
}

/// Whether `v` round-trips with **no quoting** (`K=v`). The parser trims
/// surrounding whitespace, dispatches on a leading `'`/`"`, treats a leading or
/// whitespace-preceded `#` as a comment, and is line-based — so bare encoding is
/// faithful only when none of those bite.
fn can_unquoted(v: &str) -> bool {
    if v.is_empty() {
        return false; // emit `''` for clarity (also faithful, but explicit)
    }
    if v != v.trim() {
        return false; // leading/trailing whitespace would be trimmed away
    }
    match v.chars().next() {
        Some('\'') | Some('"') | Some('#') => return false, // dispatch / comment
        _ => {}
    }
    if v.contains('\n') || v.contains('\r') {
        return false; // line-based: a newline can only ride the `\n` escape
    }
    // A `#` preceded by ASCII whitespace starts an inline comment (dropped).
    let bytes = v.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b'#' && bytes[i - 1].is_ascii_whitespace() {
            return false;
        }
    }
    true
}

/// Whether `v` round-trips **single-quoted** (`'v'`). Single quotes are fully
/// literal, so this is faithful for any `v` with no `'` and no newline (a newline
/// would split the line).
fn can_single_quoted(v: &str) -> bool {
    !v.contains('\'') && !v.contains('\n')
}

/// The universally-correct double-quoted encoding: escape `\`→`\\`, `"`→`\"`, and
/// a newline→`\n`; every other char is literal. With the `\\` grammar (ADR 0025
/// amendment) this round-trips for **every** string.
fn encode_double_quoted(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for ch in v.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Apply `edits` to the freshly-read `.env` `raw` text, returning the new file
/// content (ADR 0001 op-apply → new-content). Edits are applied in order; each
/// sees the result of the previous. Untouched lines — comments, blanks, and
/// unrelated assignments — are preserved byte-for-byte, as are the file's line
/// endings (`\r\n`/`\n`) and trailing-newline state. Fails closed
/// ([`EnvWriteError::InvalidKey`]) before producing any text if a `Set` key is
/// not a writable literal key. The result holds secret content in a zeroizing
/// buffer.
pub fn apply_edits(raw: &str, edits: &[EnvEdit]) -> Result<Zeroizing<String>, EnvWriteError> {
    // Fail closed up front: every `Set` must target a writable key, before we
    // mutate anything (a Remove with an odd key simply matches nothing).
    validate_edits(edits)?;

    let dominant_nl = if raw.contains("\r\n") { "\r\n" } else { "\n" };
    let had_trailing_newline = raw.ends_with('\n');
    let mut lines = split_lines(raw);

    for edit in edits {
        match edit {
            EnvEdit::Set { key, value } => {
                set_key(&mut lines, key, value, dominant_nl, had_trailing_newline)
            }
            EnvEdit::Remove { key } => {
                lines.retain(|l| owned_key(&l.content).as_deref() != Some(key))
            }
        }
    }

    let mut out = Zeroizing::new(String::new());
    for line in &lines {
        out.push_str(&line.content);
        out.push_str(line.term);
    }
    Ok(out)
}

/// The lowercase-hex SHA-256 of `bytes` — the `expected_sha256` compare-and-swap
/// guard (ADR 0001 / ADR 0029): the digest `sha256sum` computes for the file *as
/// read*, which the remote command checks before writing. The digest of a `.env`
/// is not secret (it does not reveal the content). Pure.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(hex, "{byte:02x}").expect("write hex");
    }
    hex
}

/// Fail closed if any `Set` targets an unwritable key (ADR 0028 fail-closed). The
/// write orchestration calls this *before* reading the remote file, so a malformed
/// edit never triggers a wasted SSM round-trip; [`apply_edits`] re-checks too.
pub fn validate_edits(edits: &[EnvEdit]) -> Result<(), EnvWriteError> {
    for e in edits {
        if let EnvEdit::Set { key, .. } = e {
            if !is_writable_key(key) {
                return Err(EnvWriteError::InvalidKey);
            }
        }
    }
    Ok(())
}

/// Whether `key` is a writable literal `.env` key: non-empty, no `=`, no newline,
/// and no surrounding whitespace (so it has an unambiguous `KEY=` spelling).
fn is_writable_key(key: &str) -> bool {
    !key.is_empty()
        && key == key.trim()
        && !key.contains('=')
        && !key.contains('\n')
        && !key.contains('\r')
}

/// One physical line: its content (no terminator) in a zeroizing buffer (it may
/// hold a secret Value), plus the exact terminator to reproduce (`"\r\n"`,
/// `"\n"`, or `""` for an unterminated last line).
struct Line {
    content: Zeroizing<String>,
    term: &'static str,
}

/// Split `raw` into physical lines, preserving each line's terminator so the
/// rewrite is byte-faithful. A trailing newline does **not** produce an empty
/// final line (so re-joining reproduces the original).
fn split_lines(raw: &str) -> Vec<Line> {
    let mut out = Vec::new();
    let mut rest = raw;
    while !rest.is_empty() {
        match rest.find('\n') {
            Some(idx) => {
                let line = &rest[..idx];
                let (content, term) = if let Some(stripped) = line.strip_suffix('\r') {
                    (stripped, "\r\n")
                } else {
                    (line, "\n")
                };
                out.push(Line {
                    content: Zeroizing::new(content.to_string()),
                    term,
                });
                rest = &rest[idx + 1..];
            }
            None => {
                out.push(Line {
                    content: Zeroizing::new(rest.to_string()),
                    term: "",
                });
                rest = "";
            }
        }
    }
    out
}

/// Rewrite the last line owning `key`, or append `key=value` if none owns it.
fn set_key(
    lines: &mut Vec<Line>,
    key: &str,
    value: &str,
    dominant_nl: &'static str,
    had_trailing_newline: bool,
) {
    if let Some(i) = lines
        .iter()
        .rposition(|l| owned_key(&l.content).as_deref() == Some(key))
    {
        // Preserve the left side exactly (indentation, `export `, original key
        // text, the `=`); replace only the right-hand side. Any trailing inline
        // comment on the edited line is dropped (documented; v1).
        let eq = first_eq_byte(&lines[i].content).expect("an owning line has an `=`");
        let mut rewritten = Zeroizing::new(lines[i].content[..=eq].to_string());
        rewritten.push_str(&encode_value(value));
        lines[i].content = rewritten;
    } else {
        // Append. Ensure the current last line is terminated so the new line is on
        // its own row, then add `key=value`, reproducing the file's trailing-
        // newline style.
        if let Some(last) = lines.last_mut() {
            if last.term.is_empty() {
                last.term = dominant_nl;
            }
        }
        let mut content = Zeroizing::new(format!("{key}="));
        content.push_str(&encode_value(value));
        lines.push(Line {
            content,
            // Reproduce the file's trailing-newline state (an empty file has none).
            term: if had_trailing_newline {
                dominant_nl
            } else {
                ""
            },
        });
    }
}

/// The (trimmed) key a physical line owns, or `None` for a blank line, a `#`
/// comment, or a keyless/malformed line. Mirrors `parse_dotenv` exactly: strip
/// leading whitespace, skip blank/`#`, strip a leading `export `, split on the
/// first `=`, trim the key, and reject an empty key.
fn owned_key(content: &str) -> Option<String> {
    let trimmed = content.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let assignment = trimmed
        .strip_prefix("export ")
        .map(str::trim_start)
        .unwrap_or(trimmed);
    let eq = assignment.find('=')?;
    let key = assignment[..eq].trim();
    if key.is_empty() {
        None
    } else {
        Some(key.to_string())
    }
}

/// The byte index of the first `=` in `content` (in the original string, after the
/// leading-whitespace/`export ` prefix), for an owning line. Mirrors the offset
/// math of [`owned_key`].
fn first_eq_byte(content: &str) -> Option<usize> {
    let lead = content.len() - content.trim_start().len();
    let trimmed = &content[lead..];
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (assignment, offset) = match trimmed.strip_prefix("export ") {
        Some(rest) => {
            let after = rest.trim_start();
            (after, lead + (trimmed.len() - after.len()))
        }
        None => (trimmed, lead),
    };
    let eq = assignment.find('=')?;
    if assignment[..eq].trim().is_empty() {
        return None;
    }
    Some(offset + eq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dotenv::parse_dotenv;
    use janitor_core::secret::{EntryName, SecretShape, Value};

    // ---- encode_value: round-trip is the contract ----

    /// The decoded Value of `K=<rhs>` for the single literal key `K`.
    fn parse_one(rhs: &str) -> String {
        match parse_dotenv(&format!("K={rhs}")).expect("parse K=rhs") {
            SecretShape::Json(map) => map[&EntryName::from_path(&["K".to_string()])]
                .expose()
                .to_string(),
            other => panic!("expected Json, got {other:?}"),
        }
    }

    /// The property the whole write path leans on: encode is a total inverse of
    /// parse. (No randomness in the workflow env, so this is an explicit corpus of
    /// the nasty cases rather than a generator.)
    #[test]
    fn encode_value_is_a_total_inverse_of_parse() {
        let corpus = [
            "",                       // empty
            "1",                      // bare
            "hello world",            // internal space (bare keeps it)
            " leading",               // leading space (forces quoting)
            "trailing ",              // trailing space
            "a b # not-comment",      // a `#` after ws (would be a comment unquoted)
            "#leadinghash",           // leading `#`
            "'singlequoted'literal'", // single quotes inside
            "\"doublequoted\"",       // leading double quote
            "with\nnewline",          // embedded newline (only `\n` escape works)
            "back\\slash",            // a lone backslash
            "back\\nslash",           // backslash adjacent to n (the classic trap)
            "back\\\"slash",          // backslash adjacent to quote
            "C:\\\\share",            // doubled backslash
            "quote\"and'both",        // both quote kinds
            "'\\",                    // single-quote AND backslash (the old residual)
            "tab\tinside",            // a tab
            "=startswith-eq",         // value starting with `=`
            "ends-with-backslash\\",  // trailing backslash
            "  ",                     // only whitespace
            "\u{1f600}unicode",       // non-ASCII
        ];
        for v in corpus {
            let encoded = encode_value(v);
            assert_eq!(
                parse_one(&encoded),
                v,
                "round-trip failed for {v:?} (encoded as {encoded:?})"
            );
        }
    }

    #[test]
    fn encode_value_prefers_the_least_noisy_faithful_style() {
        assert_eq!(encode_value("1"), "1", "bare when safe");
        assert_eq!(encode_value("a b c"), "a b c", "internal spaces stay bare");
        assert_eq!(encode_value(""), "''", "empty is single-quoted for clarity");
        assert_eq!(
            encode_value(" leading"),
            "' leading'",
            "leading space → single-quote (literal)"
        );
        // A quote or backslash *mid-value* is literal when bare — no quoting needed.
        assert_eq!(
            encode_value("has'quote"),
            "has'quote",
            "mid-value quote stays bare"
        );
        assert_eq!(
            encode_value("a\\b"),
            "a\\b",
            "mid-value backslash stays bare"
        );
        // When quoting IS forced (here a leading space), a `'` rules out single-quote
        // → double-quote; a `\` (no `'`) prefers single-quote.
        assert_eq!(
            encode_value(" a'b"),
            r#"" a'b""#,
            "forced-quote + a single-quote → double-quote"
        );
        assert_eq!(
            encode_value(" a\\b"),
            "' a\\b'",
            "forced-quote + a backslash (no quote) → single-quote (literal)"
        );
    }

    #[test]
    fn encode_value_never_leaves_a_value_in_a_panic_or_log() {
        // encode is total: it returns for every input (no unwrap/expect on the
        // value). This pins that the residual-set refusal is gone (ADR 0029).
        let _ = encode_value("'\\\n\"#"); // a pathological mix — must not panic
    }

    // ---- apply_edits: the non-stomping textual transform ----

    fn set(key: &str, value: &str) -> EnvEdit {
        EnvEdit::set(key, value)
    }
    fn remove(key: &str) -> EnvEdit {
        EnvEdit::remove(key)
    }
    fn apply(raw: &str, edits: &[EnvEdit]) -> String {
        apply_edits(raw, edits).expect("apply").to_string()
    }

    #[test]
    fn set_existing_rewrites_only_the_value_preserving_everything_else() {
        let raw = "# header comment\nA=1\n\nB=old # inline\nexport C=3\n";
        let out = apply(raw, &[set("B", "new value")]);
        assert_eq!(
            out, "# header comment\nA=1\n\nB=new value\nexport C=3\n",
            "only B's RHS changes; comments/blank/order/export preserved (inline comment dropped)"
        );
    }

    #[test]
    fn set_preserves_indentation_export_and_key_text() {
        let raw = "  export   FOO=bar\n";
        let out = apply(raw, &[set("FOO", "baz")]);
        assert_eq!(
            out, "  export   FOO=baz\n",
            "indentation, `export`, and the key spelling are kept; only RHS swapped"
        );
    }

    #[test]
    fn set_absent_appends_a_new_line() {
        let raw = "A=1\nB=2\n";
        let out = apply(raw, &[set("C", "three")]);
        assert_eq!(out, "A=1\nB=2\nC=three\n");
    }

    #[test]
    fn set_absent_on_file_without_trailing_newline_terminates_then_appends() {
        let raw = "A=1\nB=2"; // no trailing newline
        let out = apply(raw, &[set("C", "3")]);
        assert_eq!(
            out, "A=1\nB=2\nC=3",
            "the prior last line gets a newline; the new line keeps the no-trailing-newline style"
        );
    }

    #[test]
    fn set_into_empty_file() {
        assert_eq!(apply("", &[set("A", "1")]), "A=1");
    }

    #[test]
    fn duplicate_key_set_rewrites_the_last_occurrence_last_wins() {
        // The parser reads the LAST occurrence, so to change the effective value we
        // must rewrite the last line; the earlier (shadowed) duplicate is untouched.
        let raw = "A=first\nA=second\n";
        let out = apply(raw, &[set("A", "third")]);
        assert_eq!(out, "A=first\nA=third\n");
        // And the read-back of the result is the new value.
        assert_eq!(read_back(&out, "A"), "third");
    }

    #[test]
    fn remove_deletes_every_owning_line() {
        let raw = "A=1\nB=2\nA=dup\nC=3\n";
        let out = apply(raw, &[remove("A")]);
        assert_eq!(
            out, "B=2\nC=3\n",
            "both A lines gone; B and C kept in order"
        );
        assert!(parse_one_absent(&out, "A"));
    }

    #[test]
    fn remove_absent_key_is_a_noop() {
        let raw = "A=1\nB=2\n";
        assert_eq!(apply(raw, &[remove("Z")]), raw);
    }

    #[test]
    fn key_appearing_only_in_a_comment_is_never_matched() {
        let raw = "# SECRET_TOKEN was here\nA=1\n";
        // Remove does nothing (the comment doesn't own the key); Set appends.
        assert_eq!(apply(raw, &[remove("SECRET_TOKEN")]), raw);
        assert_eq!(
            apply(raw, &[set("SECRET_TOKEN", "v")]),
            "# SECRET_TOKEN was here\nA=1\nSECRET_TOKEN=v\n",
            "the comment line is preserved verbatim; the key is appended"
        );
    }

    #[test]
    fn keyless_and_malformed_lines_are_left_untouched() {
        // A keyless `=v` line and a no-`=` line are never matched; an edit to a real
        // key beside them leaves them verbatim.
        let raw = "=keyless\nA=1\nnoequals\n";
        let out = apply(raw, &[set("A", "2")]);
        assert_eq!(out, "=keyless\nA=2\nnoequals\n");
    }

    #[test]
    fn crlf_line_endings_are_preserved() {
        let raw = "A=1\r\nB=2\r\n";
        let out = apply(raw, &[set("B", "3"), set("C", "4")]);
        assert_eq!(
            out, "A=1\r\nB=3\r\nC=4\r\n",
            "existing CRLF kept; appended line uses the dominant CRLF"
        );
    }

    #[test]
    fn edits_apply_in_order_set_then_remove() {
        let raw = "A=1\n";
        let out = apply(raw, &[set("B", "2"), remove("B")]);
        assert_eq!(out, "A=1\n", "the appended B is then removed");
    }

    #[test]
    fn set_then_set_same_key_keeps_one_line() {
        let raw = "A=1\n";
        let out = apply(raw, &[set("B", "2"), set("B", "3")]);
        assert_eq!(
            out, "A=1\nB=3\n",
            "the second Set rewrites the appended line"
        );
    }

    #[test]
    fn an_edited_value_round_trips_through_a_re_parse() {
        // The whole point: after a write, reading the file back yields the new Value
        // exactly — even for a nasty value.
        let raw = "DB_URL=postgres://old\n";
        let nasty = "p@ss w'rd\\#\"x";
        let out = apply(raw, &[set("DB_URL", nasty)]);
        assert_eq!(read_back(&out, "DB_URL"), nasty);
    }

    #[test]
    fn invalid_set_key_fails_closed_before_any_text() {
        // Invalid: empty, an `=`, a newline, or surrounding whitespace (which the
        // parser would trim, mismatching the key). Internal whitespace IS allowed
        // (the parser preserves it), so `A B` is valid and not in this list.
        for bad in ["", "A=B", "A\nB", " A", "A "] {
            let err = apply_edits("X=1\n", &[set(bad, "v")]).unwrap_err();
            assert_eq!(err, EnvWriteError::InvalidKey, "bad key {bad:?}");
        }
        // A Remove with an odd key is NOT an error (it just matches nothing).
        assert!(apply_edits("X=1\n", &[remove("A=B")]).is_ok());
    }

    #[test]
    fn sha256_hex_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex(b"x").len(), 64, "always 64 lowercase hex chars");
    }

    // `EnvEdit`'s Debug redaction is tested where the type now lives
    // (`janitor_core::write`, re-exported via `janitor_aws_auth::write`); the engine
    // tests below exercise it via `set`.

    // ---- test helpers ----

    fn read_back(env_text: &str, key: &str) -> String {
        match parse_dotenv(env_text).expect("re-parse") {
            SecretShape::Json(map) => map
                .get(&EntryName::from_path(&[key.to_string()]))
                .map(Value::expose)
                .unwrap_or("<absent>")
                .to_string(),
            other => panic!("expected Json, got {other:?}"),
        }
    }
    fn parse_one_absent(env_text: &str, key: &str) -> bool {
        match parse_dotenv(env_text).expect("re-parse") {
            SecretShape::Json(map) => !map.contains_key(&EntryName::from_path(&[key.to_string()])),
            other => panic!("expected Json, got {other:?}"),
        }
    }
}
