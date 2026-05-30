//! Owned, masked projection of a [`Comparison`] for the GUI. Carries no secret
//! Values — only presence, byte length, equality grouping, and a cosmetic tag —
//! so the view may hold it long-lived (ADR 0003). Plaintext reveal goes through
//! [`reveal_value`] against the still-owned Sets, never through this DTO.

use crate::compare::{Cell, Comparison, EntryState, RowKey};
use crate::secret::{SecretShape, Value};

/// An owned, non-secret matrix ready to map onto view models.
#[derive(Debug, Clone, PartialEq)]
pub struct MatrixView {
    pub environments: Vec<String>,
    pub rows: Vec<MatrixRow>,
}

/// One projected row.
#[derive(Debug, Clone, PartialEq)]
pub struct MatrixRow {
    /// The row's identity, kept so [`reveal_value`] can re-index the Sets.
    pub key: RowKey,
    /// Display name (`EntryName` text, or `"(whole set)"`).
    pub name: String,
    pub state: EntryState,
    pub cells: Vec<MatrixCell>,
}

/// One projected cell — masked only.
#[derive(Debug, Clone, PartialEq)]
pub enum MatrixCell {
    /// Present: byte length, row-local equality group, and a cosmetic hex tag.
    Present { len: usize, group: u32, hex: String },
    /// Missing in this Environment.
    Absent,
}

/// Project a freshly-built [`Comparison`] into an owned [`MatrixView`].
pub fn project(comparison: &Comparison) -> MatrixView {
    let rows = comparison
        .rows
        .iter()
        .map(|row| {
            let name = match &row.key {
                RowKey::Entry(n) => n.as_str().to_string(),
                RowKey::WholeSet => "(whole set)".to_string(),
            };
            let cells = row
                .cells
                .iter()
                .map(|cell| match cell {
                    // `group.0` is pub(crate) on GroupId — readable here in-crate.
                    Cell::Text { len, group, .. } => MatrixCell::Present {
                        len: *len,
                        group: group.0,
                        hex: hex_tag(&name, group.0),
                    },
                    Cell::Binary { len, group } => MatrixCell::Present {
                        len: *len,
                        group: group.0,
                        hex: hex_tag(&name, group.0),
                    },
                    Cell::Absent => MatrixCell::Absent,
                })
                .collect();
            MatrixRow {
                key: row.key.clone(),
                name,
                state: row.state,
                cells,
            }
        })
        .collect();
    MatrixView {
        environments: comparison.environments.clone(),
        rows,
    }
}

/// Borrow the plaintext Value at `(row key, column)` for a momentary reveal,
/// indexing the still-owned Sets directly (independent of any `Comparison`).
/// `None` when the column is out of range, the Entry is absent there, or the
/// Set is Binary (never revealable, ADR 0004).
pub fn reveal_value<'a>(
    sets: &'a [(String, SecretShape)],
    key: &RowKey,
    col: usize,
) -> Option<&'a Value> {
    let (_, shape) = sets.get(col)?;
    match (key, shape) {
        (RowKey::Entry(name), SecretShape::Json(map)) => map.get(name),
        (RowKey::WholeSet, SecretShape::Raw(value)) => Some(value),
        _ => None,
    }
}

/// Row ordering for the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    /// The engine's default — Entry name order.
    Name,
    /// High-signal rows on top: Gap, then Drift, then Aligned.
    GapFirst,
}

/// Reorder `view.rows` per `sort`. Stable, so within a rank the engine's name
/// order is preserved. `Name` is a no-op (the engine already name-sorts).
pub fn sort_rows(view: &mut MatrixView, sort: SortKey) {
    if sort == SortKey::GapFirst {
        view.rows.sort_by_key(|r| match r.state {
            EntryState::Gap => 0u8,
            EntryState::Drift => 1,
            EntryState::Aligned => 2,
        });
    }
}

/// Cosmetic 4-hex-char tag from the Entry name + equality group (**never** the
/// Value). Equal cells in a row share a tag; different Entries differ. Display
/// flavor only — the equality mechanism is the group id.
fn hex_tag(name: &str, group: u32) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes().chain(std::iter::once(b':')).chain(group.to_le_bytes()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:04x}", h & 0xffff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compare::Comparison;
    use crate::secret::SecretShape;

    fn env(name: &str, json: &str) -> (String, SecretShape) {
        (name.to_string(), SecretShape::from_secret_string(json))
    }
    fn find<'a>(v: &'a MatrixView, name: &str) -> &'a MatrixRow {
        v.rows.iter().find(|r| r.name == name).expect("row exists")
    }

    #[test]
    fn project_preserves_environments_and_row_names() {
        let sets = [env("prod", r#"{"A":"1"}"#), env("staging", r#"{"A":"1"}"#)];
        let view = project(&Comparison::build(&sets));
        assert_eq!(view.environments, vec!["prod", "staging"]);
        assert_eq!(view.rows.len(), 1);
        assert_eq!(view.rows[0].name, "A");
    }

    #[test]
    fn aligned_cells_share_group_and_hex() {
        let sets = [env("prod", r#"{"A":"1"}"#), env("staging", r#"{"A":"1"}"#)];
        let view = project(&Comparison::build(&sets));
        let r = find(&view, "A");
        assert_eq!(r.state, EntryState::Aligned);
        match (&r.cells[0], &r.cells[1]) {
            (
                MatrixCell::Present { group: g0, hex: h0, .. },
                MatrixCell::Present { group: g1, hex: h1, .. },
            ) => {
                assert_eq!(g0, g1, "aligned → same group");
                assert_eq!(h0, h1, "same group in a row → same cosmetic hex");
            }
            _ => panic!("expected two Present cells"),
        }
    }

    #[test]
    fn drift_cells_have_different_groups() {
        let sets = [env("prod", r#"{"A":"1"}"#), env("staging", r#"{"A":"2"}"#)];
        let view = project(&Comparison::build(&sets));
        let r = find(&view, "A");
        assert_eq!(r.state, EntryState::Drift);
        match (&r.cells[0], &r.cells[1]) {
            (MatrixCell::Present { group: g0, .. }, MatrixCell::Present { group: g1, .. }) => {
                assert_ne!(g0, g1)
            }
            _ => panic!("expected Present cells"),
        }
    }

    #[test]
    fn gap_row_has_absent_cell_and_len_is_byte_length() {
        let sets = [env("prod", r#"{"A":"hello"}"#), env("staging", r#"{"B":"x"}"#)];
        let view = project(&Comparison::build(&sets));
        let a = find(&view, "A");
        assert_eq!(a.state, EntryState::Gap);
        assert!(matches!(a.cells[0], MatrixCell::Present { len: 5, .. }));
        assert!(matches!(a.cells[1], MatrixCell::Absent));
    }

    #[test]
    fn project_handles_raw_and_binary_whole_set_rows() {
        // Raw (non-JSON) sets → a single WholeSet row named "(whole set)".
        let raw = [env("prod", "tok-aaaa"), env("staging", "tok-bbbb")];
        let rv = project(&Comparison::build(&raw));
        assert_eq!(rv.rows.len(), 1);
        assert_eq!(rv.rows[0].name, "(whole set)");
        assert!(matches!(rv.rows[0].cells[0], MatrixCell::Present { .. }));

        // Binary sets → WholeSet row, masked length only (never a Value).
        let bin = [
            ("prod".to_string(), SecretShape::from_secret_binary(vec![1, 2, 3, 4])),
            ("staging".to_string(), SecretShape::from_secret_binary(vec![1, 2, 3, 9])),
        ];
        let bv = project(&Comparison::build(&bin));
        assert_eq!(bv.rows[0].name, "(whole set)");
        assert!(matches!(bv.rows[0].cells[0], MatrixCell::Present { len: 4, .. }));
    }

    use crate::compare::RowKey;
    use crate::secret::EntryName;

    fn entry_key(name: &str) -> RowKey {
        RowKey::Entry(EntryName::from_path(&[name.to_string()]))
    }

    #[test]
    fn reveal_present_json_entry_and_raw_whole_set() {
        let sets = [env("prod", r#"{"A":"secret"}"#)];
        assert_eq!(
            reveal_value(&sets, &entry_key("A"), 0).map(|v| v.expose()),
            Some("secret")
        );
        let raw = [("prod".to_string(), SecretShape::from_secret_string("raw-token"))];
        assert_eq!(
            reveal_value(&raw, &RowKey::WholeSet, 0).map(|v| v.expose()),
            Some("raw-token")
        );
    }

    #[test]
    fn reveal_is_none_for_absent_oob_and_binary() {
        let sets = [
            env("prod", r#"{"A":"x"}"#),
            ("bin".to_string(), SecretShape::from_secret_binary(vec![1, 2, 3])),
        ];
        assert!(reveal_value(&sets, &entry_key("MISSING"), 0).is_none());
        assert!(reveal_value(&sets, &entry_key("A"), 9).is_none(), "col out of range");
        assert!(reveal_value(&sets, &RowKey::WholeSet, 1).is_none(), "binary never reveals");
    }

    #[test]
    fn gap_first_sort_is_stable_and_high_signal_first() {
        // aaa: drift, bbb: aligned, ccc: prod-only gap. Engine order: aaa,bbb,ccc.
        let sets = [
            env("prod", r#"{"aaa":"1","bbb":"1","ccc":"1"}"#),
            env("staging", r#"{"aaa":"2","bbb":"1"}"#),
        ];
        let mut view = project(&Comparison::build(&sets));
        sort_rows(&mut view, SortKey::GapFirst);
        let order: Vec<&str> = view.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(order, vec!["ccc", "aaa", "bbb"], "Gap, then Drift, then Aligned");
    }

    #[test]
    fn name_sort_keeps_engine_order() {
        let sets = [
            env("prod", r#"{"bbb":"1","aaa":"1"}"#),
            env("staging", r#"{"bbb":"1","aaa":"1"}"#),
        ];
        let mut view = project(&Comparison::build(&sets));
        sort_rows(&mut view, SortKey::Name);
        let order: Vec<&str> = view.rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(order, vec!["aaa", "bbb"], "engine already sorts by name");
    }
}
