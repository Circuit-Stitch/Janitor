//! Pure assembly of the matrix's rendered item list — prefix-cluster group
//! headers + data rows with per-group zebra parity, the type-badge label, and
//! the muted-prefix / bold-leaf name split. Kept out of the `.slint` view so it
//! stays testable (ADR 0003; matches the `pane.rs` / `worker.rs` seams). Wires
//! core's `cluster_rows` into the table (issue #20).

use janitor_core::cluster::cluster_rows;
use janitor_core::secret::LeafKind;

/// One line of the rendered table: a prefix-cluster header, or a data row that
/// points back at its `MatrixView` row index (the reveal coordinate space).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatrixItem {
    /// A cluster header: its label (e.g. `"database.*"`) and member count.
    Header { label: String, count: usize },
    /// A data row: `index` into `MatrixView.rows`, plus the zebra parity
    /// (`true` = the shaded stripe). Parity resets to the unshaded stripe at
    /// each header so striping reads per-group, not across the whole table.
    Row { index: usize, zebra: bool },
}

/// Assemble the table's display items from the rows' Entry `names`, in display
/// order. When `grouped`, runs core's `cluster_rows`: each 2+ cluster emits a
/// `Header` and restarts the zebra stripe; lone rows render flat (no 1-item
/// header) and continue the running stripe. When not `grouped`, every row is
/// flat with one continuous zebra stripe and no headers.
pub fn matrix_items(names: &[&str], grouped: bool) -> Vec<MatrixItem> {
    if !grouped {
        return names
            .iter()
            .enumerate()
            .map(|(i, _)| MatrixItem::Row {
                index: i,
                zebra: i % 2 == 1,
            })
            .collect();
    }

    let mut items = Vec::new();
    // The running stripe counter; reset to 0 under each header so the first row
    // of every cluster is the unshaded stripe regardless of what preceded it.
    let mut stripe = 0usize;
    for cluster in cluster_rows(names) {
        if let Some(label) = cluster.label {
            items.push(MatrixItem::Header {
                label,
                count: cluster.members.len(),
            });
            stripe = 0;
        }
        for index in cluster.members {
            items.push(MatrixItem::Row {
                index,
                zebra: stripe % 2 == 1,
            });
            stripe += 1;
        }
    }
    items
}

/// The type-badge text for a row's representative [`LeafKind`] — uppercase JSON
/// type, or `""` for a Binary row (no leaf type). Sourced from the engine's
/// kind, never hard-coded (issue #20).
pub fn badge_label(kind: Option<LeafKind>) -> &'static str {
    match kind {
        Some(LeafKind::String) => "STRING",
        Some(LeafKind::Number) => "NUMBER",
        Some(LeafKind::Bool) => "BOOL",
        Some(LeafKind::Null) => "NULL",
        Some(LeafKind::Json) => "JSON",
        None => "",
    }
}

/// Split an Entry name for the two-tone render: a muted prefix (up to and
/// including the last `.`/`_` separator) and the bold leaf (the final segment).
/// A separator-less name has an empty prefix and is all leaf.
pub fn split_name(name: &str) -> (&str, &str) {
    match name.rfind(['.', '_']) {
        Some(i) => (&name[..=i], &name[i + 1..]),
        None => ("", name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ungrouped_is_flat_with_one_continuous_zebra_and_no_headers() {
        let items = matrix_items(&["a", "b", "c"], false);
        assert_eq!(
            items,
            vec![
                MatrixItem::Row {
                    index: 0,
                    zebra: false
                },
                MatrixItem::Row {
                    index: 1,
                    zebra: true
                },
                MatrixItem::Row {
                    index: 2,
                    zebra: false
                },
            ]
        );
    }

    #[test]
    fn grouped_emits_a_header_per_cluster_with_member_count_and_view_indices() {
        // Two siblings cluster; STRIPE_KEY is lone. Row indices point back at the
        // MatrixView positions (0,1,2), not the display positions (which the
        // header shifts).
        let items = matrix_items(&["db.a", "db.b", "STRIPE_KEY"], true);
        assert_eq!(
            items[0],
            MatrixItem::Header {
                label: "db.*".into(),
                count: 2
            }
        );
        assert_eq!(
            items[1],
            MatrixItem::Row {
                index: 0,
                zebra: false
            }
        );
        assert_eq!(
            items[2],
            MatrixItem::Row {
                index: 1,
                zebra: true
            }
        );
        // Lone row: no header, stripe continues (count reached 2 → even → unshaded).
        assert_eq!(
            items[3],
            MatrixItem::Row {
                index: 2,
                zebra: false
            }
        );
    }

    #[test]
    fn zebra_resets_under_each_header() {
        // Two 3-member clusters: the second cluster's first row is the unshaded
        // stripe again even though three rows preceded it.
        let names = ["db.a", "db.b", "db.c", "GH_A", "GH_B", "GH_C"];
        let items = matrix_items(&names, true);
        assert_eq!(
            items[1],
            MatrixItem::Row {
                index: 0,
                zebra: false
            }
        );
        assert_eq!(
            items[3],
            MatrixItem::Row {
                index: 2,
                zebra: false
            }
        );
        assert!(matches!(items[4], MatrixItem::Header { .. }));
        assert_eq!(
            items[5],
            MatrixItem::Row {
                index: 3,
                zebra: false
            },
            "stripe restarts under the second header"
        );
    }

    #[test]
    fn lone_rows_render_flat_without_a_one_item_header() {
        // Distinct first segments → both lone; no headers, continuous stripe.
        let items = matrix_items(&["STRIPE_KEY", "LOG_LEVEL"], true);
        assert_eq!(
            items,
            vec![
                MatrixItem::Row {
                    index: 0,
                    zebra: false
                },
                MatrixItem::Row {
                    index: 1,
                    zebra: true
                },
            ]
        );
    }

    #[test]
    fn badge_label_maps_leaf_kinds_and_blanks_for_binary() {
        assert_eq!(badge_label(Some(LeafKind::String)), "STRING");
        assert_eq!(badge_label(Some(LeafKind::Number)), "NUMBER");
        assert_eq!(badge_label(Some(LeafKind::Bool)), "BOOL");
        assert_eq!(badge_label(Some(LeafKind::Null)), "NULL");
        assert_eq!(badge_label(Some(LeafKind::Json)), "JSON");
        assert_eq!(badge_label(None), "");
    }

    #[test]
    fn split_name_separates_muted_prefix_from_bold_leaf() {
        assert_eq!(
            split_name("database.primary.url"),
            ("database.primary.", "url")
        );
        assert_eq!(split_name("GITHUB_APP_ID"), ("GITHUB_APP_", "ID"));
        assert_eq!(split_name("STRIPEKEY"), ("", "STRIPEKEY"));
    }
}
