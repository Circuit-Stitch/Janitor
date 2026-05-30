//! The comparison result model: a masked, point-in-time Aligned/Drift/Gap
//! matrix that borrows the canonical zeroizing Values it describes (ADR 0009).

use crate::secret::{EntryName, Value};

/// A point-in-time comparison of one Application's Set across its Environments.
/// Borrows the fetched Sets — build it to render, don't store it (ADR 0009).
#[derive(Debug)]
pub struct Comparison<'a> {
    /// Column labels (Environment names), in input order.
    pub environments: Vec<String>,
    /// Entry rows ordered by name, then the `WholeSet` row (if any) last.
    pub rows: Vec<Row<'a>>,
}

/// One Entry (or the whole Raw/Binary Set) compared across the Environments.
#[derive(Debug)]
pub struct Row<'a> {
    pub key: RowKey,
    pub state: EntryState,
    /// Column-aligned to [`Comparison::environments`].
    pub cells: Vec<Cell<'a>>,
}

/// What a row is keyed by. A JSON Set yields `Entry` rows; a Raw or Binary Set
/// (which has no JSON entry names) yields the single `WholeSet` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowKey {
    Entry(EntryName),
    WholeSet,
}

/// The comparison state of a row across all compared Environments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// Present in every Environment with an identical Value (and `LeafKind`).
    Aligned,
    /// Present in every Environment, but Values differ.
    Drift,
    /// Present in some Environments and missing in others — the high-signal finding.
    Gap,
}

/// One Environment's view of a row.
pub enum Cell<'a> {
    /// A JSON leaf Entry or a Raw whole-value — revealable.
    Text {
        value: &'a Value,
        /// Byte length of the Value, **precomputed** so the masked view can
        /// render length-sized dots without exposing the Value (ADR 0003). The
        /// engine is the sole constructor and sets this from `value.expose().len()`.
        len: usize,
        group: GroupId,
    },
    /// A `SecretBinary` Set — length and equality only; never revealable.
    Binary {
        /// Byte length of the binary blob (`SecretBytes::len`) — the masked
        /// length token; there is no Value to expose for a binary cell.
        len: usize,
        group: GroupId,
    },
    /// Not present in this Environment.
    Absent,
}

impl Cell<'_> {
    /// Borrow the plaintext Value for a momentary reveal (the GUI handles the
    /// auto-hide timing — ADR 0003). `Some` only for `Text`; `Binary` is never
    /// revealable (ADR 0004) and `Absent` has nothing to show.
    pub fn reveal(&self) -> Option<&Value> {
        match self {
            Cell::Text { value, .. } => Some(value),
            Cell::Binary { .. } | Cell::Absent => None,
        }
    }
}

// Manual Debug so a cell never prints its Value; length is a tolerated
// side-channel (CONTEXT.md). `Comparison`/`Row` derive Debug on top of this.
impl std::fmt::Debug for Cell<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cell::Text { len, group, .. } => f
                .debug_struct("Text")
                .field("len", len)
                .field("group", group)
                .finish_non_exhaustive(),
            Cell::Binary { len, group } => f
                .debug_struct("Binary")
                .field("len", len)
                .field("group", group)
                .finish(),
            Cell::Absent => f.write_str("Absent"),
        }
    }
}

/// Row-local opaque equality token: `Copy + Eq`, comparable only within one
/// `Row` (group ids carry no meaning across rows; the view compares them to
/// colour cells that match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupId(pub(crate) u32);

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> EntryName {
        EntryName::from_path(&[name.to_string()])
    }

    #[test]
    fn reveal_exposes_text_but_not_binary_or_absent() {
        let v = Value::string("s3cr3t");
        let text = Cell::Text {
            value: &v,
            len: 6,
            group: GroupId(0),
        };
        let binary = Cell::Binary {
            len: 4,
            group: GroupId(0),
        };
        let absent = Cell::Absent;
        assert_eq!(text.reveal().map(|v| v.expose()), Some("s3cr3t"));
        assert!(binary.reveal().is_none(), "Binary must never reveal");
        assert!(absent.reveal().is_none());
    }

    #[test]
    fn debug_never_leaks_a_value() {
        // Exercise all three Cell Debug arms (Text, Binary, Absent); the Binary
        // arm is the security-relevant one — it carries length, the deliberate
        // side-channel, and must still never print bytes.
        let v = Value::string("hunter2");
        let cmp = Comparison {
            environments: vec!["prod".to_string(), "staging".to_string(), "dev".to_string()],
            rows: vec![Row {
                key: RowKey::Entry(entry("PASSWORD")),
                state: EntryState::Gap,
                cells: vec![
                    Cell::Text {
                        value: &v,
                        len: 7,
                        group: GroupId(0),
                    },
                    Cell::Binary {
                        len: 4,
                        group: GroupId(1),
                    },
                    Cell::Absent,
                ],
            }],
        };
        let rendered = format!("{cmp:?}");
        assert!(
            !rendered.contains("hunter2"),
            "Debug leaked the secret: {rendered}"
        );
        assert!(
            rendered.contains("PASSWORD"),
            "Entry names are metadata and should show"
        );
    }
}
