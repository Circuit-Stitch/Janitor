//! Horizontal-scrollbar geometry for the drift-matrix env region (issue #60),
//! decided in pure Rust so the thumb sizing / position and the drag inverse are
//! unit-tested without driving Slint (ADR 0003 / ADR 0021 — prefer extraction
//! over UI geometry tests; matches the `reveal.rs` / `pane.rs` seams).
//!
//! Why a scrollbar at all: the env-body `Flickable` is `interactive: false` so
//! the cell `TouchArea`s get real press-and-hold reveals and right-clicks (an
//! interactive Flickable defers the pointer grab to detect a flick and only
//! synthesises a tap at release — breaking press-and-hold and swallowing the
//! right-click). Going non-interactive dropped the ADR 0023 drag-scroll of the
//! Comparison Columns; this restores reaching the off-screen columns with an
//! always-on scrollbar instead of re-enabling the Flickable. The `.slint` binds
//! its thumb metrics to these functions through `pure callback`s
//! (`ui.on_sb_*` in `main.rs` and the view-test fixture).
//!
//! No secret material is involved — this is view geometry only (lengths in
//! logical px, `f32` to match Slint's `length`). All functions are total: every
//! degenerate input (non-positive content/track, a thumb that fills the track, a
//! zero scroll range) returns a sane clamped value rather than dividing by zero.

/// Whether the content overflows the viewport, so the scrollbar is shown at all.
/// Strictly greater by a hairline tolerance so an exactly-filled band (the ADR
/// 0023 stretch-to-fill regime, where `envs-w == available`) hides the bar and
/// only the floor regime (`envs-w > available`) shows it.
pub fn is_scrollable(content_w: f32, viewport_w: f32) -> bool {
    content_w > viewport_w + 0.5
}

/// The scrollable distance — how far the content extends beyond the viewport.
/// Clamped to 0 when the content fits (the `viewport-x` travel is `[-this, 0]`).
pub fn max_scroll(content_w: f32, viewport_w: f32) -> f32 {
    (content_w - viewport_w).max(0.0)
}

/// The thumb's pixel length along the track: the track scaled by the visible
/// fraction (`viewport / content`), floored at `min_thumb` so it stays grabbable
/// and capped at the track length. Degenerate inputs (non-positive content or
/// track) collapse to the full (non-negative) track length.
pub fn thumb_len(track_w: f32, viewport_w: f32, content_w: f32, min_thumb: f32) -> f32 {
    if track_w <= 0.0 || content_w <= 0.0 {
        return track_w.max(0.0);
    }
    let proportional = track_w * (viewport_w / content_w);
    // Floor at `min_thumb`, but never above the track itself (a track shorter
    // than `min_thumb` just yields a full-track thumb).
    proportional.clamp(min_thumb.min(track_w), track_w)
}

/// The thumb's left offset along the track for a given scroll distance. Maps
/// `scroll_x ∈ [0, max_scroll]` onto the thumb's travel `[0, track − thumb]`.
/// Returns 0 when there is no travel (the thumb fills the track) or nothing to
/// scroll.
pub fn thumb_offset(track_w: f32, thumb_len: f32, scroll_x: f32, max_scroll: f32) -> f32 {
    let travel = track_w - thumb_len;
    if travel <= 0.0 || max_scroll <= 0.0 {
        return 0.0;
    }
    let frac = (scroll_x / max_scroll).clamp(0.0, 1.0);
    frac * travel
}

/// The scroll distance for a given thumb left offset — the inverse of
/// [`thumb_offset`]. The drag handler uses it to turn a dragged thumb position
/// back into a scroll distance (negated into `viewport-x`). Clamped to
/// `[0, max_scroll]`, so an over-dragged thumb pins at an end rather than
/// scrolling past the content.
pub fn scroll_from_thumb(thumb_offset: f32, track_w: f32, thumb_len: f32, max_scroll: f32) -> f32 {
    let travel = track_w - thumb_len;
    if travel <= 0.0 || max_scroll <= 0.0 {
        return 0.0;
    }
    let frac = (thumb_offset / travel).clamp(0.0, 1.0);
    frac * max_scroll
}

#[cfg(test)]
mod tests {
    use super::*;

    // A close-enough comparison for the float geometry (logical px).
    fn approx(a: f32, b: f32) {
        assert!((a - b).abs() <= 0.01, "expected {a} ≈ {b}");
    }

    #[test]
    fn scrollable_only_when_content_overflows_the_viewport() {
        // Floor regime: 8 cols × 200px floor over a 382px band → overflow.
        assert!(is_scrollable(1600.0, 382.0));
        // Stretch-to-fill regime (ADR 0023): envs-w == available exactly → hidden.
        assert!(!is_scrollable(782.0, 782.0));
        // A hairline over is still "fits" (no thumb you couldn't move).
        assert!(!is_scrollable(382.4, 382.0));
        assert!(is_scrollable(383.0, 382.0));
    }

    #[test]
    fn max_scroll_is_the_overflow_and_never_negative() {
        approx(max_scroll(1600.0, 382.0), 1218.0);
        approx(max_scroll(382.0, 382.0), 0.0);
        approx(max_scroll(300.0, 382.0), 0.0); // content fits → clamped to 0
    }

    #[test]
    fn thumb_len_is_proportional_to_the_visible_fraction() {
        // track == viewport (the bar spans the visible band): fraction = track/content.
        // 382 × (382/1600) ≈ 91.2.
        approx(
            thumb_len(382.0, 382.0, 1600.0, 32.0),
            382.0 * 382.0 / 1600.0,
        );
    }

    #[test]
    fn thumb_len_floors_at_min_thumb_so_it_stays_grabbable() {
        // A huge content makes the proportional thumb tiny; the floor saves it.
        let len = thumb_len(382.0, 382.0, 100_000.0, 32.0);
        approx(len, 32.0);
    }

    #[test]
    fn thumb_len_never_exceeds_the_track_and_degenerates_safely() {
        // Content fits → thumb would be ≥ track; capped at the track length.
        approx(thumb_len(382.0, 382.0, 200.0, 32.0), 382.0);
        // Degenerate: zero/negative content or track → full (non-negative) track.
        approx(thumb_len(382.0, 382.0, 0.0, 32.0), 382.0);
        approx(thumb_len(0.0, 0.0, 1600.0, 32.0), 0.0);
        // A track shorter than the min-thumb yields a full-track thumb, not a
        // thumb wider than its track.
        approx(thumb_len(20.0, 20.0, 1600.0, 32.0), 20.0);
    }

    #[test]
    fn thumb_offset_spans_zero_to_the_full_travel() {
        let track = 382.0;
        let thumb = thumb_len(track, track, 1600.0, 32.0);
        let max = max_scroll(1600.0, track);
        let travel = track - thumb;
        // Leftmost scroll → offset 0; rightmost → the full travel (thumb's right
        // edge meets the track's right edge).
        approx(thumb_offset(track, thumb, 0.0, max), 0.0);
        approx(thumb_offset(track, thumb, max, max), travel);
        // Halfway scroll → halfway along the travel.
        approx(thumb_offset(track, thumb, max / 2.0, max), travel / 2.0);
    }

    #[test]
    fn thumb_offset_clamps_and_handles_no_travel() {
        let track = 382.0;
        let thumb = thumb_len(track, track, 1600.0, 32.0);
        let max = max_scroll(1600.0, track);
        let travel = track - thumb;
        // Over-/under-scroll pins the thumb at an end.
        approx(thumb_offset(track, thumb, max * 2.0, max), travel);
        approx(thumb_offset(track, thumb, -100.0, max), 0.0);
        // No scroll range (content fits) or a track-filling thumb → offset 0
        // (and avoids a divide-by-zero — the same invariant `scroll_from_thumb`'s
        // no-travel test pins for the drag handler's inverse).
        approx(thumb_offset(track, thumb, 50.0, 0.0), 0.0);
        approx(thumb_offset(track, track, 50.0, max), 0.0);
    }

    #[test]
    fn scroll_from_thumb_is_the_inverse_of_thumb_offset() {
        let track = 382.0;
        let thumb = thumb_len(track, track, 1600.0, 32.0);
        let max = max_scroll(1600.0, track);
        // Round-trip across the whole scroll range.
        for k in 0..=10 {
            let scroll = max * (k as f32) / 10.0;
            let off = thumb_offset(track, thumb, scroll, max);
            approx(scroll_from_thumb(off, track, thumb, max), scroll);
        }
    }

    #[test]
    fn scroll_from_thumb_clamps_and_handles_no_travel() {
        let track = 382.0;
        let thumb = thumb_len(track, track, 1600.0, 32.0);
        let max = max_scroll(1600.0, track);
        let travel = track - thumb;
        // Dragging the thumb past either end pins at that end's scroll value.
        approx(scroll_from_thumb(travel * 2.0, track, thumb, max), max);
        approx(scroll_from_thumb(-50.0, track, thumb, max), 0.0);
        // No travel / no range → no scroll (avoids a divide-by-zero).
        approx(scroll_from_thumb(50.0, track, track, max), 0.0);
        approx(scroll_from_thumb(50.0, track, thumb, 0.0), 0.0);
    }
}
