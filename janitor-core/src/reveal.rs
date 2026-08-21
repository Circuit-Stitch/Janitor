//! The per-cell reveal gate. One rule lives here: a momentary reveal un-masks
//! exactly one targeted cell, never a whole row or column. Deciding it in core
//! keeps it testable without driving a GUI (ADR 0003), and gives every shell the
//! same predicate.
//!
//! Reveal is press-and-hold momentary (ADR 0003 / THREAT-MODEL). A press writes the
//! single revealed coordinate. Release zeroes it back to the `-1` sentinel. A shell
//! binds each cell's masked-or-plaintext choice to this function; the Slint view
//! does it through the `is-cell-revealed` callback on `MainWindow`.
//!
//! This predicate is the only thing that turns masked dots into plaintext. Widening
//! it — matching on the row alone, say — would un-mask a whole row of secret Values.
//! The tests below pin that shut.

/// Whether the cell at (`row`, `col`) is the one currently revealed.
///
/// `revealed_row` / `revealed_col` are the single live reveal coordinate, or `-1`
/// each when nothing is revealed (the press-release sentinel — never a real cell
/// coordinate, so a fully-masked matrix falls out for free). A cell un-masks only
/// when **both** coordinates match: matching on just one would reveal a whole row
/// or column of Values.
pub fn is_revealed(revealed_row: i32, revealed_col: i32, row: i32, col: i32) -> bool {
    revealed_row == row && revealed_col == col
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_targeted_cell_is_revealed() {
        assert!(is_revealed(2, 3, 2, 3));
    }

    #[test]
    fn exactly_one_cell_in_a_grid_un_masks() {
        // Sweep a small grid with one revealed coordinate and assert that the
        // single targeted cell — and nothing else — un-masks. This is the
        // load-bearing security property: a momentary reveal exposes one Value.
        let (rr, rc) = (1, 2);
        let mut revealed = Vec::new();
        for row in 0..4 {
            for col in 0..4 {
                if is_revealed(rr, rc, row, col) {
                    revealed.push((row, col));
                }
            }
        }
        assert_eq!(
            revealed,
            vec![(rr, rc)],
            "exactly the targeted cell un-masks"
        );
    }

    #[test]
    fn never_un_masks_a_whole_row() {
        // Same row, every other column stays masked — a row-only match would leak
        // the whole row of Values.
        let row = 5;
        for col in 0..10 {
            let revealed = is_revealed(row, 3, row, col);
            assert_eq!(
                revealed,
                col == 3,
                "row {row} col {col}: only the matching column may reveal"
            );
        }
    }

    #[test]
    fn never_un_masks_a_whole_column() {
        // Same column, every other row stays masked.
        let col = 7;
        for row in 0..10 {
            let revealed = is_revealed(4, col, row, col);
            assert_eq!(
                revealed,
                row == 4,
                "col {col} row {row}: only the matching row may reveal"
            );
        }
    }

    #[test]
    fn the_minus_one_sentinel_matches_no_real_cell() {
        // The release/idle state: revealed-row/col are both -1. No non-negative
        // (real) cell coordinate may un-mask, so the whole matrix renders masked.
        for row in 0..6 {
            for col in 0..6 {
                assert!(
                    !is_revealed(-1, -1, row, col),
                    "({row},{col}) must stay masked when nothing is revealed"
                );
            }
        }
    }

    #[test]
    fn a_half_sentinel_never_reveals() {
        // Defense in depth: even if only one coordinate is the sentinel (a state
        // the press/release flow shouldn't produce), nothing reveals.
        assert!(!is_revealed(-1, 2, 0, 2));
        assert!(!is_revealed(2, -1, 2, 0));
    }
}
