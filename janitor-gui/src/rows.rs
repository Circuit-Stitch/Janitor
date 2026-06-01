//! Pure assembly of the matrix's rendered item list — prefix-cluster group
//! headers + data rows with per-group zebra parity, the type-badge label, and
//! the muted-prefix / bold-leaf name split. Kept out of the `.slint` view so it
//! stays testable (ADR 0003; matches the `pane.rs` / `worker.rs` seams). Wires
//! core's `cluster_rows` into the table (issue #20).

use janitor_core::cluster::{cluster_relative_name, cluster_rows};
use janitor_core::secret::LeafKind;

/// One line of the rendered table: a prefix-cluster header, or a data row that
/// points back at its `MatrixView` row index (the reveal coordinate space).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatrixItem {
    /// A cluster header: its label (e.g. `"database.*"`) and member count.
    Header { label: String, count: usize },
    /// A data row: `index` into `MatrixView.rows`, the zebra parity (`true` = the
    /// shaded stripe; resets to unshaded under each header so striping reads
    /// per-group), and the row's cluster `group_label` (e.g. `Some("database.*")`)
    /// when grouped, or `None` when flat / lone. The name renderer strips this
    /// prefix so a grouped row omits what its header already shows (#40).
    Row {
        index: usize,
        zebra: bool,
        group_label: Option<String>,
    },
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
                group_label: None,
            })
            .collect();
    }

    let mut items = Vec::new();
    // The running stripe counter; reset to 0 under each header so the first row
    // of every cluster is the unshaded stripe regardless of what preceded it.
    let mut stripe = 0usize;
    for cluster in cluster_rows(names) {
        let group_label = cluster.label;
        if let Some(label) = &group_label {
            items.push(MatrixItem::Header {
                label: label.clone(),
                count: cluster.members.len(),
            });
            stripe = 0;
        }
        for index in cluster.members {
            items.push(MatrixItem::Row {
                index,
                zebra: stripe % 2 == 1,
                group_label: group_label.clone(),
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

/// The two-tone display parts of a row's Entry name (#40): first omit the
/// cluster's common prefix the header already shows (`group_label` `Some("db.*")`
/// strips `db.`; `None` keeps the whole name), then [`split_name`] the remainder
/// into the muted prefix + bold leaf. So `Some("database.*")` +
/// `"database.primary.url"` renders as muted `"primary."` + bold `"url"`.
pub fn display_name_parts<'a>(group_label: Option<&str>, name: &'a str) -> (&'a str, &'a str) {
    split_name(cluster_relative_name(group_label, name))
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
                    zebra: false,
                    group_label: None,
                },
                MatrixItem::Row {
                    index: 1,
                    zebra: true,
                    group_label: None,
                },
                MatrixItem::Row {
                    index: 2,
                    zebra: false,
                    group_label: None,
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
                zebra: false,
                group_label: Some("db.*".into()),
            }
        );
        assert_eq!(
            items[2],
            MatrixItem::Row {
                index: 1,
                zebra: true,
                group_label: Some("db.*".into()),
            }
        );
        // Lone row: no header, stripe continues (count reached 2 → even → unshaded);
        // a lone row carries no cluster label, so the name renderer keeps it whole.
        assert_eq!(
            items[3],
            MatrixItem::Row {
                index: 2,
                zebra: false,
                group_label: None,
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
                zebra: false,
                group_label: Some("db.*".into()),
            }
        );
        assert_eq!(
            items[3],
            MatrixItem::Row {
                index: 2,
                zebra: false,
                group_label: Some("db.*".into()),
            }
        );
        assert!(matches!(items[4], MatrixItem::Header { .. }));
        assert_eq!(
            items[5],
            MatrixItem::Row {
                index: 3,
                zebra: false,
                group_label: Some("GH_*".into()),
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
                    zebra: false,
                    group_label: None,
                },
                MatrixItem::Row {
                    index: 1,
                    zebra: true,
                    group_label: None,
                },
            ]
        );
    }

    #[test]
    fn grouped_rows_carry_their_cluster_label_so_the_prefix_can_be_omitted() {
        // Members of a labelled cluster carry the label (the renderer strips it);
        // a lone row and every row in flat mode carry None (rendered whole).
        let grouped = matrix_items(&["db.a", "db.b", "LONE"], true);
        let labels: Vec<Option<&str>> = grouped
            .iter()
            .filter_map(|it| match it {
                MatrixItem::Row { group_label, .. } => Some(group_label.as_deref()),
                MatrixItem::Header { .. } => None,
            })
            .collect();
        assert_eq!(labels, vec![Some("db.*"), Some("db.*"), None]);

        let flat = matrix_items(&["db.a", "db.b"], false);
        assert!(flat.iter().all(|it| matches!(
            it,
            MatrixItem::Row {
                group_label: None,
                ..
            }
        )));
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

    #[test]
    fn display_name_parts_omits_the_cluster_prefix_then_splits() {
        // Grouped: the header already shows "database.*", so the row renders the
        // cluster-relative tail, split into muted prefix + bold leaf.
        assert_eq!(
            display_name_parts(Some("database.*"), "database.primary.url"),
            ("primary.", "url")
        );
        // Underscore cluster: "GITHUB_APP_*" strips to "ID" — all leaf, no prefix.
        assert_eq!(
            display_name_parts(Some("GITHUB_APP_*"), "GITHUB_APP_ID"),
            ("", "ID")
        );
        // Flat / lone (None): the whole name is split, the prefix kept.
        assert_eq!(
            display_name_parts(None, "database.primary.url"),
            ("database.primary.", "url")
        );
    }
}
