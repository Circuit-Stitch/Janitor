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
}
