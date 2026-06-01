//! Selection logic for the guided flow (ADR 0011): given a list of discovered
//! choices (accounts / roles / secrets) and an optionally-remembered prior pick,
//! decide whether to auto-pick, error on emptiness, or ask — and, when asking,
//! delegate to a `Chooser` seam. All pure/sync and fully tested. The pure
//! 0/1/many + remembered-default resolver is the one Discovery primitive proven
//! generic by use, so it lives in `core` (ADR 0019) and every Provider shares it.

/// Anything the guided flow can choose among. `key` is the stable identity used
/// to match a remembered pick; `label` is the human menu line.
pub trait Selectable {
    fn key(&self) -> &str;
    fn label(&self) -> String;
}

/// What to do with a discovered list of choices.
#[derive(Debug, PartialEq)]
pub enum SelectionPlan {
    /// No choices at all — the caller reports a clear error and stops.
    Empty,
    /// Exactly one choice — take it silently (index is always 0 here, but carried
    /// explicitly so the caller never re-derives it).
    Auto(usize),
    /// Several choices — ask. `default` is the index of the remembered pick if it
    /// is still present, else `None`.
    Ask { default: Option<usize> },
}

/// Pure decision: 0 → `Empty`; 1 → `Auto(0)`; ≥2 → `Ask { default }` where
/// `default` is the index whose `key` equals `remembered` (if any is present).
pub fn plan_selection<T: Selectable>(items: &[T], remembered: Option<&str>) -> SelectionPlan {
    match items.len() {
        0 => SelectionPlan::Empty,
        1 => SelectionPlan::Auto(0),
        _ => {
            let default = remembered.and_then(|key| items.iter().position(|it| it.key() == key));
            SelectionPlan::Ask { default }
        }
    }
}

/// The seam that turns an `Ask` into a concrete index. The real impl reads stdin
/// (untested shell, in the binary); the test fake scripts the choice.
pub trait Chooser {
    /// Present `labels` and return the chosen index. `default` is the index to
    /// pre-select (Enter accepts it). Implementations MUST return an index in
    /// `0..labels.len()`.
    fn choose(&self, labels: &[String], default: Option<usize>) -> usize;
}

/// Why a discovery step could not yield a choice. A binary-level outcome, not a
/// `SessionError` — emptiness is a successful call with nothing to pick (ADR 0011).
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum DiscoverError {
    /// AWS returned no choices for this step (e.g. no entitled accounts).
    #[error("no {0} available to choose from")]
    NoChoices(&'static str),
}

/// Resolve a discovered list to a single chosen item: error on empty, auto-pick
/// the lone item (without calling the chooser), otherwise ask via `chooser`.
/// `what` names the thing being chosen (for the error message). Consumes `items`
/// and returns the chosen one by value.
pub fn resolve<T: Selectable>(
    mut items: Vec<T>,
    remembered: Option<&str>,
    chooser: &dyn Chooser,
    what: &'static str,
) -> Result<T, DiscoverError> {
    match plan_selection(&items, remembered) {
        SelectionPlan::Empty => Err(DiscoverError::NoChoices(what)),
        SelectionPlan::Auto(i) => Ok(items.swap_remove(i)),
        SelectionPlan::Ask { default } => {
            let labels: Vec<String> = items.iter().map(|it| it.label()).collect();
            let raw = chooser.choose(&labels, default);
            // Guard against an out-of-range index from a misbehaving chooser.
            let i = raw.min(items.len() - 1);
            Ok(items.swap_remove(i))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct Item {
        k: String,
        l: String,
    }
    impl Item {
        fn new(k: &str, l: &str) -> Self {
            Item {
                k: k.into(),
                l: l.into(),
            }
        }
    }
    impl Selectable for Item {
        fn key(&self) -> &str {
            &self.k
        }
        fn label(&self) -> String {
            self.l.clone()
        }
    }

    /// Records what it was asked and returns a scripted index.
    struct FakeChooser {
        pick: usize,
        calls: Mutex<u32>,
        last_default: Mutex<Option<Option<usize>>>,
    }
    impl FakeChooser {
        fn new(pick: usize) -> Self {
            FakeChooser {
                pick,
                calls: Mutex::new(0),
                last_default: Mutex::new(None),
            }
        }
        fn calls(&self) -> u32 {
            *self.calls.lock().unwrap()
        }
        fn last_default(&self) -> Option<Option<usize>> {
            *self.last_default.lock().unwrap()
        }
    }
    impl Chooser for FakeChooser {
        fn choose(&self, _labels: &[String], default: Option<usize>) -> usize {
            *self.calls.lock().unwrap() += 1;
            *self.last_default.lock().unwrap() = Some(default);
            self.pick
        }
    }

    // ---- plan_selection ----

    #[test]
    fn empty_list_plans_empty() {
        let items: Vec<Item> = vec![];
        assert_eq!(plan_selection(&items, None), SelectionPlan::Empty);
    }

    #[test]
    fn single_item_plans_auto() {
        let items = vec![Item::new("a", "A")];
        assert_eq!(plan_selection(&items, None), SelectionPlan::Auto(0));
    }

    #[test]
    fn many_without_remembered_plans_ask_no_default() {
        let items = vec![Item::new("a", "A"), Item::new("b", "B")];
        assert_eq!(
            plan_selection(&items, None),
            SelectionPlan::Ask { default: None }
        );
    }

    #[test]
    fn many_with_present_remembered_plans_ask_with_default_index() {
        let items = vec![
            Item::new("a", "A"),
            Item::new("b", "B"),
            Item::new("c", "C"),
        ];
        assert_eq!(
            plan_selection(&items, Some("c")),
            SelectionPlan::Ask { default: Some(2) }
        );
    }

    #[test]
    fn many_with_absent_remembered_plans_ask_no_default() {
        let items = vec![Item::new("a", "A"), Item::new("b", "B")];
        assert_eq!(
            plan_selection(&items, Some("zzz")),
            SelectionPlan::Ask { default: None }
        );
    }

    // ---- resolve ----

    #[test]
    fn resolve_empty_is_error_and_never_asks() {
        let chooser = FakeChooser::new(0);
        let items: Vec<Item> = vec![];
        let err = resolve(items, None, &chooser, "accounts").unwrap_err();
        assert_eq!(err, DiscoverError::NoChoices("accounts"));
        assert_eq!(
            chooser.calls(),
            0,
            "must not prompt when there is nothing to pick"
        );
    }

    #[test]
    fn resolve_single_auto_picks_without_asking() {
        let chooser = FakeChooser::new(0);
        let items = vec![Item::new("only", "Only")];
        let chosen = resolve(items, None, &chooser, "roles").unwrap();
        assert_eq!(chosen.key(), "only");
        assert_eq!(chooser.calls(), 0, "single choice must not prompt");
    }

    #[test]
    fn resolve_many_asks_and_returns_chosen() {
        let chooser = FakeChooser::new(1); // pick index 1 → "b"
        let items = vec![
            Item::new("a", "A"),
            Item::new("b", "B"),
            Item::new("c", "C"),
        ];
        let chosen = resolve(items, None, &chooser, "secrets").unwrap();
        assert_eq!(chosen.key(), "b");
        assert_eq!(chooser.calls(), 1);
        assert_eq!(chooser.last_default(), Some(None));
    }

    #[test]
    fn resolve_many_passes_remembered_as_default() {
        let chooser = FakeChooser::new(0);
        let items = vec![
            Item::new("a", "A"),
            Item::new("b", "B"),
            Item::new("c", "C"),
        ];
        let _ = resolve(items, Some("c"), &chooser, "accounts").unwrap();
        assert_eq!(
            chooser.last_default(),
            Some(Some(2)),
            "remembered key → default index"
        );
    }

    #[test]
    fn resolve_clamps_out_of_range_choice() {
        let chooser = FakeChooser::new(99); // misbehaving: out of range
        let items = vec![Item::new("a", "A"), Item::new("b", "B")];
        let chosen = resolve(items, None, &chooser, "roles").unwrap();
        assert_eq!(chosen.key(), "b", "clamped to last valid index");
    }
}
