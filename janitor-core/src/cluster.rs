//! Prefix-clustering of matrix rows into named groups (ADR 0014; the v1
//! grouping rule that issue #20 introduces, ahead of the richer algorithm
//! deferred to ADR #24).
//!
//! Pure and view-agnostic: it takes the ordered Entry-name strings of a
//! `MatrixView`'s rows and returns the groups the table should render — a header
//! for each cluster of 2+ rows that share a prefix, and lone (header-less) rows
//! for everything else. No secret material is involved — Entry **names** are
//! metadata (CONTEXT.md), never Values.

/// One rendered grouping over the input rows: either a cluster of 2+ rows that
/// share a common prefix, or a single ungrouped row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowCluster {
    /// Header label for a cluster (e.g. `"database.*"`). `None` for a lone row,
    /// which renders flat with no header.
    pub label: Option<String>,
    /// Indices into the input slice, in input order.
    pub members: Vec<usize>,
}

/// The Entry-name separators the v1 rule splits on (ADR #24 may refine these).
const SEPARATORS: &[char] = &['.', '_'];

/// Group `names` (the matrix rows' Entry names, in display order) into prefix
/// clusters. A cluster forms when 2+ names share the same first segment (the
/// text up to the first `.` or `_`); its label is the longest prefix common to
/// all its members, ending at a separator, plus `*`. Names that share their
/// first segment with no other row are returned lone (`label: None`).
pub fn cluster_rows(names: &[&str]) -> Vec<RowCluster> {
    // Gather member indices by first-segment key, in first-appearance order so
    // the output order is stable and independent of HashMap iteration.
    let mut keys: Vec<&str> = Vec::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let key = first_segment(name);
        match keys.iter().position(|k| *k == key) {
            Some(g) => groups[g].push(i),
            None => {
                keys.push(key);
                groups.push(vec![i]);
            }
        }
    }

    groups
        .into_iter()
        .map(|members| {
            if members.len() < 2 {
                RowCluster {
                    label: None,
                    members,
                }
            } else {
                let member_names: Vec<&str> = members.iter().map(|&i| names[i]).collect();
                RowCluster {
                    label: Some(group_label(&member_names)),
                    members,
                }
            }
        })
        .collect()
}

/// The first segment of a name: the text up to (not including) the first
/// separator, or the whole name when it has none.
fn first_segment(name: &str) -> &str {
    match name.find(|c| SEPARATORS.contains(&c)) {
        Some(i) => &name[..i],
        None => name,
    }
}

/// The display header for a cluster: the longest common prefix of its members,
/// truncated to end at its last separator, plus `*`.
fn group_label(members: &[&str]) -> String {
    let lcp = longest_common_prefix(members);
    // Keep the prefix up to and including its last separator so the label reads
    // as a clean boundary (`database.`, `GITHUB_APP_`); if the common prefix has
    // no internal separator, keep all of it.
    let cut = lcp
        .rfind(|c| SEPARATORS.contains(&c))
        .map(|i| i + 1)
        .unwrap_or(lcp.len());
    format!("{}*", &lcp[..cut])
}

/// Longest prefix common to every member (UTF-8 safe; returns a slice of the
/// first member). Assumes a non-empty slice.
fn longest_common_prefix<'a>(members: &[&'a str]) -> &'a str {
    let first = members[0];
    let mut end = first.len();
    for m in members.iter().skip(1) {
        let common = first
            .char_indices()
            .zip(m.chars())
            .take_while(|((_, a), b)| a == b)
            .map(|((i, a), _)| i + a.len_utf8())
            .last()
            .unwrap_or(0);
        end = end.min(common);
    }
    &first[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_dotted_siblings_form_one_labelled_cluster() {
        let out = cluster_rows(&["database.primary.url", "database.primary.pass"]);
        assert_eq!(
            out,
            vec![RowCluster {
                label: Some("database.primary.*".to_string()),
                members: vec![0, 1],
            }],
        );
    }

    #[test]
    fn a_row_with_a_unique_first_segment_is_lone_with_no_header() {
        let out = cluster_rows(&["STRIPE_KEY", "LOG_LEVEL"]);
        assert_eq!(
            out,
            vec![
                RowCluster {
                    label: None,
                    members: vec![0],
                },
                RowCluster {
                    label: None,
                    members: vec![1],
                },
            ],
        );
    }

    #[test]
    fn underscore_siblings_label_uses_longest_common_prefix() {
        // All three share "GITHUB_APP_" — the label is the deepest shared
        // prefix, not just the first segment "GITHUB_".
        let out = cluster_rows(&["GITHUB_APP_ID", "GITHUB_APP_KEY", "GITHUB_APP_SECRET"]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].label.as_deref(), Some("GITHUB_APP_*"));
        assert_eq!(out[0].members, vec![0, 1, 2]);
    }

    #[test]
    fn divergent_second_segments_fall_back_to_the_shared_first_segment() {
        // Two share "database.primary.", one diverges at "database.replica." —
        // the whole-cluster common prefix is just "database.".
        let out = cluster_rows(&[
            "database.primary.url",
            "database.primary.pass",
            "database.replica.url",
        ]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].label.as_deref(), Some("database.*"));
        assert_eq!(out[0].members, vec![0, 1, 2]);
    }

    #[test]
    fn separatorless_names_never_cluster_even_if_one_prefixes_another() {
        // "apple" and "applesauce" have distinct first segments (no separator),
        // so they do not group — avoids spurious substring clustering.
        let out = cluster_rows(&["apple", "applesauce"]);
        assert_eq!(
            out,
            vec![
                RowCluster {
                    label: None,
                    members: vec![0]
                },
                RowCluster {
                    label: None,
                    members: vec![1]
                },
            ]
        );
    }

    #[test]
    fn members_are_gathered_by_key_in_first_appearance_order() {
        // A lone row between two cluster members: the cluster gathers both
        // members and is emitted at the key's first appearance.
        let out = cluster_rows(&["db.a", "LONE", "db.b"]);
        assert_eq!(
            out,
            vec![
                RowCluster {
                    label: Some("db.*".to_string()),
                    members: vec![0, 2],
                },
                RowCluster {
                    label: None,
                    members: vec![1],
                },
            ],
        );
    }

    #[test]
    fn empty_input_yields_no_clusters() {
        assert_eq!(cluster_rows(&[]), Vec::new());
    }

    #[test]
    fn full_mixed_set_groups_dotted_and_underscore_and_leaves_singletons_flat() {
        let names = [
            "database.primary.url",
            "database.primary.pass",
            "database.replica.url",
            "GITHUB_APP_ID",
            "GITHUB_APP_KEY",
            "GITHUB_APP_SECRET",
            "STRIPE_KEY",
            "LOG_LEVEL",
        ];
        let out = cluster_rows(&names);
        let summary: Vec<(Option<&str>, usize)> = out
            .iter()
            .map(|c| (c.label.as_deref(), c.members.len()))
            .collect();
        assert_eq!(
            summary,
            vec![
                (Some("database.*"), 3),
                (Some("GITHUB_APP_*"), 3),
                (None, 1), // STRIPE_KEY
                (None, 1), // LOG_LEVEL
            ],
        );
    }
}
