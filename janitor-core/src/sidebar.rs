//! Pure assembly of the sidebar's Application rows. The non-obvious rule is the
//! drift badge: it shows **only** for the selected, loaded Application. Keeping the
//! assembly in core makes that rule unit-testable, and a shell maps the returned
//! `Vec<SidebarApp>` onto its own row widgets with no logic of its own (ADR 0003).
//!
//! The badge is suppressed elsewhere because the drift count comes from the loaded
//! `MatrixView`, which describes the selected Application alone. Counting the others
//! would mean fetching every Application's secrets — a sign-in and `GetSecretValue`
//! storm against real AWS. A non-selected or not-yet-loaded row shows no badge
//! rather than a stale or storm-fetched one.

use crate::compare::EntryState;
use crate::config::Config;
use crate::view::MatrixView;

/// One rendered sidebar row: the Application name, its `"N envs"` subtitle, the
/// drift badge text (`""` when suppressed — see module docs), and whether it is the
/// selected row. All non-secret metadata (names + counts), never a Value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidebarApp {
    pub name: String,
    pub subtitle: String,
    pub drift: String,
    pub selected: bool,
}

/// Build the sidebar rows from Config + the loaded view.
///
/// The drift badge text is `"N drift"` only when this row is the `selected`
/// Application **and** `status == "loaded"` **and** at least one row is in
/// [`EntryState::Drift`]; otherwise it is empty. `view` describes the selected
/// Application's last load, so the count is meaningful for that row alone.
pub fn sidebar_apps(
    config: &Config,
    selected: usize,
    view: &MatrixView,
    status: &str,
) -> Vec<SidebarApp> {
    config
        .applications
        .iter()
        .enumerate()
        .map(|(i, app)| {
            let is_selected = i == selected;
            let drift = drift_badge(is_selected, status, view);
            SidebarApp {
                name: app.name.clone(),
                subtitle: format!("{} envs", app.environments.len()),
                drift,
                selected: is_selected,
            }
        })
        .collect()
}

/// The badge text for one row: `"N drift"` only for the selected, loaded row with
/// a positive drift count; `""` everywhere else.
fn drift_badge(is_selected: bool, status: &str, view: &MatrixView) -> String {
    if !(is_selected && status == "loaded") {
        return String::new();
    }
    let n = view
        .rows
        .iter()
        .filter(|r| r.state == EntryState::Drift)
        .count();
    if n > 0 {
        format!("{n} drift")
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compare::RowKey;
    use crate::config::{Application, Mapping};
    use crate::view::MatrixRow;

    fn app(name: &str, envs: usize) -> Application {
        Application {
            name: name.into(),
            environments: (0..envs)
                .map(|i| Mapping {
                    environment: format!("env{i}"),
                    account_id: "111".into(),
                    region: "us-east-1".into(),
                    secret_id: "arn".into(),
                    permission_set: "ps".into(),
                    method: crate::config::Method::SecretsManager,
                })
                .collect(),
        }
    }

    fn row(state: EntryState) -> MatrixRow {
        MatrixRow {
            key: RowKey::WholeSet,
            name: "x".into(),
            state,
            kind: None,
            cells: Vec::new(),
        }
    }

    fn view_with_drift(n: usize) -> MatrixView {
        MatrixView {
            environments: vec!["prod".into()],
            rows: std::iter::repeat_with(|| row(EntryState::Drift))
                .take(n)
                .chain([row(EntryState::Aligned), row(EntryState::Gap)])
                .collect(),
        }
    }

    fn config_with(apps: &[(&str, usize)]) -> Config {
        Config {
            applications: apps.iter().map(|(n, e)| app(n, *e)).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn name_and_env_subtitle_are_rendered_for_every_app() {
        let config = config_with(&[("Payments", 3), ("Billing", 0)]);
        let items = sidebar_apps(&config, 0, &view_with_drift(0), "loaded");
        assert_eq!(items[0].name, "Payments");
        assert_eq!(items[0].subtitle, "3 envs");
        assert_eq!(items[1].name, "Billing");
        assert_eq!(items[1].subtitle, "0 envs");
    }

    #[test]
    fn exactly_the_selected_row_is_marked_selected() {
        let config = config_with(&[("A", 1), ("B", 1), ("C", 1)]);
        let items = sidebar_apps(&config, 1, &view_with_drift(0), "loaded");
        assert_eq!(
            items.iter().map(|s| s.selected).collect::<Vec<_>>(),
            vec![false, true, false]
        );
    }

    #[test]
    fn selected_and_loaded_with_drift_shows_the_count() {
        let config = config_with(&[("A", 1), ("B", 1)]);
        let items = sidebar_apps(&config, 0, &view_with_drift(2), "loaded");
        assert_eq!(items[0].drift, "2 drift");
    }

    #[test]
    fn the_drift_badge_is_suppressed_on_non_selected_rows() {
        // The view (with drift) describes the selected app only; a sibling row must
        // never borrow that count — it would imply a storm-fetch of every app.
        let config = config_with(&[("A", 1), ("B", 1)]);
        let items = sidebar_apps(&config, 0, &view_with_drift(2), "loaded");
        assert_eq!(items[1].drift, "", "non-selected app shows no drift badge");
    }

    #[test]
    fn no_badge_until_the_selected_app_is_loaded() {
        // Same selected app + drift in the (stale) view, but status isn't "loaded":
        // transient/error states must not flash a drift badge.
        let config = config_with(&[("A", 1)]);
        for status in ["unauth", "signing", "loading", "error"] {
            let items = sidebar_apps(&config, 0, &view_with_drift(2), status);
            assert_eq!(items[0].drift, "", "status {status:?} must show no badge");
        }
    }

    #[test]
    fn loaded_with_zero_drift_shows_no_badge() {
        let config = config_with(&[("A", 1)]);
        let items = sidebar_apps(&config, 0, &view_with_drift(0), "loaded");
        assert_eq!(
            items[0].drift, "",
            "zero drift renders no badge, not \"0 drift\""
        );
    }
}
