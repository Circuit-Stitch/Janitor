//! Comparison construction and classification.

// NOTE: `BTreeSet`, `EntryName`, `SecretShape`, and the `Cell`/`Comparison`/
// `EntryState`/`Row`/`RowKey` model types are used by `build`/`build_row` in
// Task 4. They are imported now but unused until then — do NOT remove them when
// tidying warnings; Task 4 will not compile without them.
use std::collections::BTreeSet;

use crate::secret::{EntryName, SecretBytes, SecretShape, Value};

use super::model::{Cell, Comparison, EntryState, GroupId, Row, RowKey};

/// The present content of one cell, borrowed for equality grouping. References
/// are `Copy`, so `Present` is too.
#[derive(Clone, Copy)]
enum Present<'a> {
    Text(&'a Value),
    Binary(&'a SecretBytes),
}

/// Are two present cells the same Value? Text matches on content bytes **and**
/// `LeafKind` (ADR 0009: Aligned ⇔ a v2 copy would be a no-op). Binary matches
/// on bytes. Text and Binary are never equal.
fn same_value(a: &Present, b: &Present) -> bool {
    match (a, b) {
        (Present::Text(x), Present::Text(y)) => {
            x.kind() == y.kind() && x.expose().as_bytes() == y.expose().as_bytes()
        }
        (Present::Binary(x), Present::Binary(y)) => x.bytes_eq(y),
        _ => false,
    }
}

/// Assign a row-local [`GroupId`] to each present cell: equal Values share an
/// id, ids issued in first-seen (column) order. O(n^2) over the present cells in
/// a row — n is the number of Environments, so this is tiny.
fn group_ids(present: &[Present]) -> Vec<GroupId> {
    let mut ids = Vec::with_capacity(present.len());
    let mut representatives: Vec<usize> = Vec::new(); // index of each group's first cell
    for (i, cell) in present.iter().enumerate() {
        // `r` is always a valid index into `present`: each representative was
        // pushed as an `i` from this same enumerate loop, so `r < present.len()`.
        match representatives
            .iter()
            .position(|&r| same_value(&present[r], cell))
        {
            Some(group) => ids.push(GroupId(group as u32)),
            None => {
                ids.push(GroupId(representatives.len() as u32));
                representatives.push(i);
            }
        }
    }
    ids
}

impl<'a> Comparison<'a> {
    /// Compare N successfully-fetched Sets, labelled by Environment name, into a
    /// masked Aligned/Drift/Gap matrix (ADR 0009). **Total** — never panics:
    /// N = 0 yields an empty matrix; N = 1 yields one column in which every
    /// present Entry is trivially Aligned. A partial fetch is handled upstream
    /// and never reaches here (the input cannot express an absent Environment).
    pub fn build(environments: &'a [(String, SecretShape)]) -> Comparison<'a> {
        let labels = environments.iter().map(|(name, _)| name.clone()).collect();

        // Row universe: the union of JSON Entry names, plus a single WholeSet row
        // iff any Environment is a Raw or Binary Set (which has no entry names).
        let mut entry_names: BTreeSet<EntryName> = BTreeSet::new();
        let mut has_whole_set = false;
        for (_, shape) in environments {
            match shape {
                SecretShape::Json(entries) => entry_names.extend(entries.keys().cloned()),
                SecretShape::Raw(_) | SecretShape::Binary(_) => has_whole_set = true,
            }
        }

        let mut rows: Vec<Row<'a>> = Vec::with_capacity(entry_names.len() + has_whole_set as usize);
        for name in &entry_names {
            rows.push(build_row(RowKey::Entry(name.clone()), environments, |shape| {
                match shape {
                    SecretShape::Json(entries) => entries.get(name).map(Present::Text),
                    SecretShape::Raw(_) | SecretShape::Binary(_) => None,
                }
            }));
        }
        if has_whole_set {
            rows.push(build_row(RowKey::WholeSet, environments, |shape| match shape {
                SecretShape::Raw(value) => Some(Present::Text(value)),
                SecretShape::Binary(bytes) => Some(Present::Binary(bytes)),
                SecretShape::Json(_) => None,
            }));
        }

        Comparison { environments: labels, rows }
    }
}

/// Build one row: project each Environment's shape to a cell via `cell_of`,
/// group the present cells, classify, and assemble the column-aligned cells.
fn build_row<'a>(
    key: RowKey,
    environments: &'a [(String, SecretShape)],
    cell_of: impl Fn(&'a SecretShape) -> Option<Present<'a>>,
) -> Row<'a> {
    // Per-column present content (None = Absent), in input order.
    let present_by_col: Vec<Option<Present<'a>>> =
        environments.iter().map(|(_, shape)| cell_of(shape)).collect();

    // Group ids over just the present cells, in column order.
    let present: Vec<Present<'a>> = present_by_col.iter().copied().flatten().collect();
    let ids = group_ids(&present);

    // Assemble cells, threading the present-only group ids back onto columns.
    let mut cells: Vec<Cell<'a>> = Vec::with_capacity(present_by_col.len());
    let mut next = 0usize;
    let mut any_absent = false;
    for slot in present_by_col.iter().copied() {
        match slot {
            None => {
                cells.push(Cell::Absent);
                any_absent = true;
            }
            Some(Present::Text(value)) => {
                let group = ids[next];
                next += 1;
                cells.push(Cell::Text { value, len: value.expose().len(), group });
            }
            Some(Present::Binary(bytes)) => {
                let group = ids[next];
                next += 1;
                cells.push(Cell::Binary { len: bytes.len(), group });
            }
        }
    }

    // Every row has >=1 present cell, so `any_absent` alone means "present in some,
    // missing in others" — Gap, which beats Drift. Otherwise all present: one
    // group => Aligned, >=2 groups => Drift.
    let all_equal = ids.windows(2).all(|w| w[0] == w[1]);
    let state = if any_absent {
        EntryState::Gap
    } else if all_equal {
        EntryState::Aligned
    } else {
        EntryState::Drift
    };

    Row { key, state, cells }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::LeafKind;

    #[test]
    fn group_ids_assign_by_equality_in_column_order() {
        let a = Value::string("x");
        let b = Value::string("x");
        let c = Value::string("y");
        let present = [Present::Text(&a), Present::Text(&b), Present::Text(&c)];
        assert_eq!(
            group_ids(&present),
            vec![GroupId(0), GroupId(0), GroupId(1)]
        );
    }

    #[test]
    fn group_ids_are_leafkind_sensitive() {
        let number = Value::new("5432", LeafKind::Number);
        let string = Value::new("5432", LeafKind::String);
        let present = [Present::Text(&number), Present::Text(&string)];
        // Same bytes, different JSON type => different groups (ADR 0009).
        assert_eq!(group_ids(&present), vec![GroupId(0), GroupId(1)]);
    }

    #[test]
    fn group_ids_never_equate_text_and_binary() {
        let text = Value::string("AAAA");
        let bytes = SecretBytes::new(b"AAAA".to_vec());
        let present = [Present::Text(&text), Present::Binary(&bytes)];
        assert_eq!(group_ids(&present), vec![GroupId(0), GroupId(1)]);
    }

    #[test]
    fn group_ids_compare_binary_by_bytes() {
        let a = SecretBytes::new(vec![1, 2, 3]);
        let b = SecretBytes::new(vec![1, 2, 3]);
        let c = SecretBytes::new(vec![1, 2, 4]);
        let present = [
            Present::Binary(&a),
            Present::Binary(&b),
            Present::Binary(&c),
        ];
        assert_eq!(
            group_ids(&present),
            vec![GroupId(0), GroupId(0), GroupId(1)]
        );
    }

    #[test]
    fn group_ids_of_empty_input_is_empty() {
        let present: &[Present] = &[];
        assert_eq!(group_ids(present), Vec::new());
    }

    // `SecretShape`, the model types, and `EntryName` are already in scope via
    // the `use super::*;` at the top of this `mod tests`.

    fn env(name: &str, shape: SecretShape) -> (String, SecretShape) {
        (name.to_string(), shape)
    }
    fn json(s: &str) -> SecretShape {
        SecretShape::from_secret_string(s)
    }

    fn row<'a>(cmp: &'a Comparison<'a>, name: &str) -> &'a Row<'a> {
        cmp.rows
            .iter()
            .find(|r| matches!(&r.key, RowKey::Entry(n) if n.as_str() == name))
            .unwrap_or_else(|| panic!("no Entry row named {name}"))
    }
    fn whole_set<'a>(cmp: &'a Comparison<'a>) -> &'a Row<'a> {
        cmp.rows
            .iter()
            .find(|r| r.key == RowKey::WholeSet)
            .expect("no WholeSet row")
    }

    #[test]
    fn aligned_when_present_and_equal_everywhere() {
        let envs = [env("prod", json(r#"{"A":"1"}"#)), env("staging", json(r#"{"A":"1"}"#))];
        let cmp = Comparison::build(&envs);
        assert_eq!(cmp.environments, vec!["prod".to_string(), "staging".to_string()]);
        let r = row(&cmp, "A");
        assert_eq!(r.state, EntryState::Aligned);
        assert!(matches!(r.cells[0], Cell::Text { group: GroupId(0), .. }));
        assert!(matches!(r.cells[1], Cell::Text { group: GroupId(0), .. }));
    }

    #[test]
    fn drift_when_present_everywhere_but_values_differ() {
        let envs = [env("prod", json(r#"{"A":"1"}"#)), env("staging", json(r#"{"A":"2"}"#))];
        let cmp = Comparison::build(&envs);
        let r = row(&cmp, "A");
        assert_eq!(r.state, EntryState::Drift);
        assert!(matches!((&r.cells[0], &r.cells[1]),
            (Cell::Text { group: GroupId(0), .. }, Cell::Text { group: GroupId(1), .. })));
    }

    #[test]
    fn gap_when_present_in_some_and_absent_in_others() {
        let envs = [env("prod", json(r#"{"A":"1"}"#)), env("staging", json(r#"{"B":"1"}"#))];
        let cmp = Comparison::build(&envs);
        assert_eq!(row(&cmp, "A").state, EntryState::Gap);
        assert!(matches!(row(&cmp, "A").cells[1], Cell::Absent));
        assert_eq!(row(&cmp, "B").state, EntryState::Gap);
        assert!(matches!(row(&cmp, "B").cells[0], Cell::Absent));
    }

    #[test]
    fn gap_beats_drift_when_differing_and_also_absent() {
        // Present-but-differing in prod & staging, absent in dev => Gap, not Drift.
        let envs = [
            env("prod", json(r#"{"A":"1"}"#)),
            env("staging", json(r#"{"A":"2"}"#)),
            env("dev", json(r#"{"Z":"9"}"#)),
        ];
        let cmp = Comparison::build(&envs);
        assert_eq!(row(&cmp, "A").state, EntryState::Gap);
    }

    #[test]
    fn leafkind_difference_is_drift() {
        // 5432 (Number) vs "5432" (String): same text, different JSON type.
        let envs = [env("prod", json(r#"{"port":5432}"#)), env("staging", json(r#"{"port":"5432"}"#))];
        let cmp = Comparison::build(&envs);
        assert_eq!(row(&cmp, "port").state, EntryState::Drift);
    }

    #[test]
    fn empty_value_is_present_not_absent() {
        let envs = [env("prod", json(r#"{"A":""}"#)), env("staging", json(r#"{"A":""}"#))];
        let cmp = Comparison::build(&envs);
        let r = row(&cmp, "A");
        assert_eq!(r.state, EntryState::Aligned);
        assert!(matches!(r.cells[0], Cell::Text { len: 0, .. }), "empty value is Present len 0");
    }

    #[test]
    fn raw_sets_compare_as_one_whole_set_row() {
        let envs = [
            env("prod", SecretShape::from_secret_string("token-xyz")),
            env("staging", SecretShape::from_secret_string("token-xyz")),
        ];
        let cmp = Comparison::build(&envs);
        assert_eq!(cmp.rows.len(), 1);
        let r = whole_set(&cmp);
        assert_eq!(r.state, EntryState::Aligned);
        assert!(matches!(r.cells[0], Cell::Text { .. }));
        assert_eq!(r.cells[0].reveal().map(|v| v.expose()), Some("token-xyz"));
    }

    #[test]
    fn binary_sets_are_a_whole_set_row_compared_by_bytes_and_never_revealed() {
        let envs = [
            env("prod", SecretShape::from_secret_binary(vec![1, 2, 3, 4])),
            env("staging", SecretShape::from_secret_binary(vec![1, 2, 3, 4])),
            env("dev", SecretShape::from_secret_binary(vec![1, 2, 3, 9])), // same length, different bytes
        ];
        let cmp = Comparison::build(&envs);
        let r = whole_set(&cmp);
        assert_eq!(r.state, EntryState::Drift, "equal length but different bytes is Drift");
        for cell in &r.cells {
            assert!(matches!(cell, Cell::Binary { len: 4, .. }));
            assert!(cell.reveal().is_none(), "Binary must never reveal");
        }
    }

    #[test]
    fn mixed_shapes_do_not_panic() {
        // prod is JSON, dev is Raw: entries become Gaps and a WholeSet row appears.
        let envs = [env("prod", json(r#"{"A":"1"}"#)), env("dev", SecretShape::from_secret_string("raw"))];
        let cmp = Comparison::build(&envs);
        assert_eq!(row(&cmp, "A").state, EntryState::Gap);
        assert_eq!(whole_set(&cmp).state, EntryState::Gap);
    }

    #[test]
    fn rows_are_sorted_by_name_with_whole_set_last() {
        let envs = [env("prod", json(r#"{"B":"1","A":"1"}"#)), env("staging", SecretShape::from_secret_string("raw"))];
        let cmp = Comparison::build(&envs);
        let keys: Vec<&RowKey> = cmp.rows.iter().map(|r| &r.key).collect();
        assert_eq!(keys[0], &RowKey::Entry(EntryName::from_path(&["A".to_string()])));
        assert_eq!(keys[1], &RowKey::Entry(EntryName::from_path(&["B".to_string()])));
        assert_eq!(keys[2], &RowKey::WholeSet);
    }

    #[test]
    fn build_is_total_for_zero_and_one_environment() {
        let empty: [(String, SecretShape); 0] = [];
        let cmp0 = Comparison::build(&empty);
        assert!(cmp0.environments.is_empty() && cmp0.rows.is_empty());

        let one = [env("prod", json(r#"{"A":"1"}"#))];
        let cmp1 = Comparison::build(&one);
        assert_eq!(row(&cmp1, "A").state, EntryState::Aligned); // single column => trivially Aligned
    }
}
