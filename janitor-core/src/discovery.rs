//! The provider-agnostic Discovery orchestrator (ADR 0026, #33). One step-machine
//! drives every Provider's guided walk: it auto-collapses singleton choices, stops
//! at the first `Ask`/`Input`, resumes on the user's pick, clamps out-of-range
//! indices, and accumulates the chosen keys — knowing nothing of accounts, roles,
//! secrets, instances, or AWS at all (ADR 0019 / 0024). A Provider supplies its
//! *method* — the divergent sequence of list/input steps and the side effects
//! between them — as a [`Steps`] impl; the orchestrator owns all the pending/resume
//! state the two real walks used to each re-implement.
//!
//! The one insight that makes this generic: every Provider only ever needs each
//! pick's [`Selectable::key`] downstream (`account.id`, `role.name`, `secret.arn`,
//! `instance.id` are each exactly the key), so the orchestrator can work entirely
//! in type-erased [`Choice`] terms and hand back the chosen *key* as a `String`.
//! The heterogeneous typed picks and per-step `Awaiting` enums the providers used
//! to carry collapse into one `chosen: Vec<String>`.
//!
//! Behaviour is the union of what `janitor-aws::Discovery` and
//! `janitor-ssm::SsmDiscovery` did before this extraction; their crate-level tests
//! are the behaviour-preservation guard, and the unit tests here pin the engine in
//! isolation against a scripted [`Steps`] fake.

use async_trait::async_trait;

use crate::config::Mapping;
use crate::provider::{Step, What};
use crate::select::{plan_selection, Selectable, SelectionPlan};

/// A type-erased choice in a list step. `key` is the stable identity — it both
/// matches a remembered pick and is the only thing a Provider keeps after the pick
/// (see the module note); `label` is the presenter menu line.
#[derive(Debug, Clone, PartialEq)]
pub struct Choice {
    pub key: String,
    pub label: String,
}

impl Choice {
    /// Project a slice of `Selectable` items to presenter-ready choices, in list
    /// order (so a chosen index maps straight back to a key).
    pub fn project<T: Selectable>(items: &[T]) -> Vec<Choice> {
        items
            .iter()
            .map(|it| Choice {
                key: it.key().to_string(),
                label: it.label(),
            })
            .collect()
    }
}

impl Selectable for Choice {
    fn key(&self) -> &str {
        &self.key
    }
    fn label(&self) -> String {
        self.label.clone()
    }
}

/// What a [`Steps`] method wants next, given the keys chosen so far. The
/// orchestrator turns `List`/`Input` into presenter-ready [`Step`]s (collapsing
/// singletons, pre-selecting a remembered default) and passes terminals straight
/// through.
pub enum StepPlan {
    /// Offer a list. The orchestrator runs [`plan_selection`]: 0 →
    /// `Step::Empty(what)`, 1 → auto-pick (no `Ask`, drive on), many → `Step::Ask`
    /// pre-selecting `remembered`. The chosen `Choice::key` is appended to `chosen`.
    List {
        what: What,
        choices: Vec<Choice>,
        remembered: Option<String>,
    },
    /// Ask for free text (e.g. a path). Always pauses with `Step::Input`; the typed
    /// text is appended to `chosen` verbatim.
    Input {
        what: What,
        prompt: String,
        default: Option<String>,
    },
    /// The walk is complete — the assembled Mapping.
    Done(Mapping),
    /// A masked terminal state (`Empty`/`Failed`/`Reauth`) the method produced
    /// itself (an I/O error mapped to `Failed`, a dead token → `Reauth`). Passed
    /// through unchanged so the method owns its own error/empty taxonomy.
    Terminal(Step),
}

/// A Provider's Discovery *method*: given the keys chosen so far (in walk order),
/// produce the next step or a terminal. The orchestrator owns all the
/// pending/resume/clamp mechanics; an implementor just inspects `chosen` to decide
/// which stage it is at, performs its own I/O and side effects (credential mint,
/// advisory probes), and returns one [`StepPlan`]. It keeps no pending state of its
/// own — `chosen` is the whole walk so far, so `next` is re-entrant: it must skip
/// stages already represented in `chosen` (and never re-run a one-shot side effect
/// it has already performed — guard those on its own cached state, e.g. a minted
/// credential).
#[async_trait]
pub trait Steps: Send {
    async fn next(&mut self, chosen: &[String]) -> StepPlan;
}

/// What the orchestrator is paused on, so a resolution maps back without the method
/// tracking it.
enum Pending {
    /// Paused on a list `Ask`; holds the offered keys in list order so a chosen
    /// index resolves to a key (clamped).
    List(Vec<String>),
    /// Paused on a free-text `Input`.
    Input,
}

/// The single, presenter-agnostic Discovery driver (ADR 0013 / ADR 0026). Drives
/// any [`Steps`] method through a sequence of list/input steps, collapsing
/// singletons, stopping at the first `Ask`/`Input`, and accumulating the chosen
/// keys. `start`/`advance`/`provide_input` each return a `Step` describing what to
/// ask next or a terminal outcome; each consumer writes a thin presenter.
pub struct Orchestrator<S: Steps> {
    steps: S,
    chosen: Vec<String>,
    pending: Option<Pending>,
}

impl<S: Steps> Orchestrator<S> {
    /// Build a walk over `steps`. No I/O happens until [`start`](Self::start).
    pub fn new(steps: S) -> Self {
        Orchestrator {
            steps,
            chosen: Vec::new(),
            pending: None,
        }
    }

    /// Borrow the underlying method — e.g. for a Provider to drain an advisory the
    /// method accumulated mid-walk (ADR 0025), which the engine itself never sees.
    pub fn steps_mut(&mut self) -> &mut S {
        &mut self.steps
    }

    /// Begin the walk: drive until the first `Ask`/`Input` or a terminal outcome.
    pub async fn start(&mut self) -> Step {
        self.drive().await
    }

    /// Feed back the user's chosen index for the list step the walk is paused on,
    /// then continue. Out-of-range indices are clamped (a misbehaving presenter must
    /// never panic the walk). An index supplied while paused on an `Input` (or
    /// nothing) is a presenter bug: the index is ignored and the walk re-renders the
    /// pending step rather than wedging.
    pub async fn advance(&mut self, choice: usize) -> Step {
        if let Some(Pending::List(mut keys)) = self.pending.take() {
            let i = choice.min(keys.len() - 1);
            self.chosen.push(keys.swap_remove(i));
        }
        self.drive().await
    }

    /// Feed the user's typed text into a walk paused on an `Input`, then continue.
    /// Text supplied while a list `Ask` is pending (or nothing) is a presenter bug:
    /// it is ignored and the walk re-renders the pending step rather than wedging.
    pub async fn provide_input(&mut self, text: String) -> Step {
        if let Some(Pending::Input) = self.pending.take() {
            self.chosen.push(text);
        }
        self.drive().await
    }

    /// The forward drive: ask the method for the next step, auto-collapse singleton
    /// lists (falling through to the next stage), and stop at the first `Ask`,
    /// `Input`, or terminal outcome.
    async fn drive(&mut self) -> Step {
        loop {
            match self.steps.next(&self.chosen).await {
                StepPlan::List {
                    what,
                    choices,
                    remembered,
                } => match plan_selection(&choices, remembered.as_deref()) {
                    SelectionPlan::Empty => {
                        self.pending = None;
                        return Step::Empty(what);
                    }
                    SelectionPlan::Auto(i) => {
                        self.chosen.push(choices[i].key.clone());
                        // fall through: drive the next stage
                    }
                    SelectionPlan::Ask { default } => {
                        let keys = choices.iter().map(|c| c.key.clone()).collect();
                        let labels = choices.into_iter().map(|c| c.label).collect();
                        self.pending = Some(Pending::List(keys));
                        return Step::Ask {
                            what,
                            choices: labels,
                            default,
                        };
                    }
                },
                StepPlan::Input {
                    what,
                    prompt,
                    default,
                } => {
                    self.pending = Some(Pending::Input);
                    return Step::Input {
                        what,
                        prompt,
                        default,
                    };
                }
                StepPlan::Done(m) => {
                    self.pending = None;
                    return Step::Done(m);
                }
                StepPlan::Terminal(step) => {
                    self.pending = None;
                    return step;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::FetchFailReason;

    /// One scripted stage, keyed by `chosen.len()`: the method returns the stage at
    /// index `chosen.len()`, so the engine drives a deterministic walk without any
    /// AWS. (Re-entrant by construction — re-driving the same `chosen` re-reads the
    /// same stage, mirroring how a real method re-lists on a stray resolution.)
    enum Stage {
        /// `keys` become `Choice`s `key-N` / `label-N`; `remembered` is the default key.
        List {
            what: What,
            keys: Vec<&'static str>,
            remembered: Option<&'static str>,
        },
        Input {
            default: Option<&'static str>,
        },
        Done,
        Failed(FetchFailReason),
        Reauth,
    }

    struct FakeSteps {
        stages: Vec<Stage>,
        calls: usize,
    }

    impl FakeSteps {
        fn new(stages: Vec<Stage>) -> Self {
            FakeSteps { stages, calls: 0 }
        }
    }

    /// Encode the whole `chosen` vector into a Mapping's `secret_id` (pipe-joined)
    /// so a test can assert the exact accumulated key/text sequence at `Done`.
    fn mapping_from(chosen: &[String]) -> Mapping {
        Mapping {
            environment: "env".into(),
            account_id: chosen.first().cloned().unwrap_or_default(),
            region: "r".into(),
            secret_id: chosen.join("|"),
            permission_set: chosen.get(1).cloned().unwrap_or_default(),
        }
    }

    #[async_trait]
    impl Steps for FakeSteps {
        async fn next(&mut self, chosen: &[String]) -> StepPlan {
            self.calls += 1;
            match &self.stages[chosen.len()] {
                Stage::List {
                    what,
                    keys,
                    remembered,
                } => StepPlan::List {
                    what: *what,
                    choices: keys
                        .iter()
                        .map(|k| Choice {
                            key: (*k).to_string(),
                            label: format!("label-{k}"),
                        })
                        .collect(),
                    remembered: remembered.map(|s| s.to_string()),
                },
                Stage::Input { default } => StepPlan::Input {
                    what: What::FilePath,
                    prompt: "type a path".into(),
                    default: default.map(|s| s.to_string()),
                },
                Stage::Done => StepPlan::Done(mapping_from(chosen)),
                Stage::Failed(r) => StepPlan::Terminal(Step::Failed(*r)),
                Stage::Reauth => StepPlan::Terminal(Step::Reauth),
            }
        }
    }

    fn orch(stages: Vec<Stage>) -> Orchestrator<FakeSteps> {
        Orchestrator::new(FakeSteps::new(stages))
    }

    #[tokio::test]
    async fn singletons_auto_collapse_straight_to_done() {
        // account → role → secret, each a singleton: the walk never asks, and the
        // chosen keys accumulate in order into the Done mapping.
        let mut o = orch(vec![
            Stage::List {
                what: What::Accounts,
                keys: vec!["acct"],
                remembered: None,
            },
            Stage::List {
                what: What::Roles,
                keys: vec!["role"],
                remembered: None,
            },
            Stage::List {
                what: What::Secrets,
                keys: vec!["secret"],
                remembered: None,
            },
            Stage::Done,
        ]);
        let Step::Done(m) = o.start().await else {
            panic!("expected Done");
        };
        assert_eq!(m.secret_id, "acct|role|secret");
        assert_eq!(
            o.steps_mut().calls,
            4,
            "consulted once per stage, no re-fetch"
        );
    }

    #[tokio::test]
    async fn stops_at_first_ask_without_over_fetching_then_advances() {
        // Two accounts → Ask immediately; the method must be consulted exactly once
        // (the downstream role/secret stages are not driven until the account is in).
        let mut o = orch(vec![
            Stage::List {
                what: What::Accounts,
                keys: vec!["a0", "a1"],
                remembered: None,
            },
            Stage::List {
                what: What::Roles,
                keys: vec!["role"],
                remembered: None,
            },
            Stage::List {
                what: What::Secrets,
                keys: vec!["secret"],
                remembered: None,
            },
            Stage::Done,
        ]);
        let Step::Ask {
            what,
            choices,
            default,
        } = o.start().await
        else {
            panic!("expected Ask");
        };
        assert_eq!(what, What::Accounts);
        assert_eq!(
            choices,
            vec!["label-a0".to_string(), "label-a1".to_string()]
        );
        assert_eq!(default, None);
        assert_eq!(o.steps_mut().calls, 1, "did not drive past the first Ask");

        let Step::Done(m) = o.advance(1).await else {
            panic!("expected Done");
        };
        assert_eq!(
            m.secret_id, "a1|role|secret",
            "the chosen account key lands"
        );
    }

    #[tokio::test]
    async fn remembered_key_pre_selects_the_default_index() {
        let mut o = orch(vec![Stage::List {
            what: What::Accounts,
            keys: vec!["a0", "a1", "a2"],
            remembered: Some("a2"),
        }]);
        let Step::Ask { default, .. } = o.start().await else {
            panic!("expected Ask");
        };
        assert_eq!(default, Some(2), "remembered key resolves to its index");
    }

    #[tokio::test]
    async fn advance_clamps_out_of_range_to_the_last_choice() {
        let mut o = orch(vec![
            Stage::List {
                what: What::Accounts,
                keys: vec!["a0", "a1"],
                remembered: None,
            },
            Stage::Done,
        ]);
        assert!(matches!(o.start().await, Step::Ask { .. }));
        let Step::Done(m) = o.advance(99).await else {
            panic!("expected Done");
        };
        assert_eq!(m.account_id, "a1", "clamped to the last choice");
    }

    #[tokio::test]
    async fn empty_list_is_the_empty_step_for_that_what() {
        let mut o = orch(vec![Stage::List {
            what: What::Roles,
            keys: vec![],
            remembered: None,
        }]);
        assert!(matches!(o.start().await, Step::Empty(What::Roles)));
    }

    #[tokio::test]
    async fn input_pauses_then_provide_input_appends_text_and_completes() {
        // account auto-picks, then a free-text Input; the typed text is appended to
        // chosen verbatim and shows up in the Done mapping.
        let mut o = orch(vec![
            Stage::List {
                what: What::Accounts,
                keys: vec!["acct"],
                remembered: None,
            },
            Stage::Input {
                default: Some("/app/.env"),
            },
            Stage::Done,
        ]);
        let Step::Input {
            what,
            prompt,
            default,
        } = o.start().await
        else {
            panic!("expected Input");
        };
        assert_eq!(what, What::FilePath);
        assert_eq!(prompt, "type a path");
        assert_eq!(default.as_deref(), Some("/app/.env"));

        let Step::Done(m) = o.provide_input("/srv/.env".into()).await else {
            panic!("expected Done");
        };
        assert_eq!(m.secret_id, "acct|/srv/.env", "the typed path is appended");
    }

    #[tokio::test]
    async fn terminal_failed_and_reauth_pass_through_unchanged() {
        let mut failed = orch(vec![Stage::Failed(FetchFailReason::Throttled)]);
        assert!(matches!(
            failed.start().await,
            Step::Failed(FetchFailReason::Throttled)
        ));

        let mut reauth = orch(vec![Stage::Reauth]);
        assert!(matches!(reauth.start().await, Step::Reauth));
    }

    #[tokio::test]
    async fn stray_input_while_a_list_is_pending_re_renders_without_wedging() {
        // provide_input() while paused on an Ask is a presenter bug: the text is
        // dropped and the walk re-renders the same Ask (chosen unchanged).
        let mut o = orch(vec![Stage::List {
            what: What::Accounts,
            keys: vec!["a0", "a1"],
            remembered: None,
        }]);
        assert!(matches!(o.start().await, Step::Ask { .. }));
        let again = o.provide_input("ignored".into()).await;
        assert!(matches!(
            again,
            Step::Ask {
                what: What::Accounts,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn stray_advance_while_an_input_is_pending_re_renders_without_wedging() {
        // advance() while paused on an Input is a presenter bug: the index is
        // dropped and the walk re-renders the same Input.
        let mut o = orch(vec![
            Stage::List {
                what: What::Accounts,
                keys: vec!["acct"],
                remembered: None,
            },
            Stage::Input { default: None },
            Stage::Done,
        ]);
        assert!(matches!(o.start().await, Step::Input { .. }));
        assert!(matches!(o.advance(0).await, Step::Input { .. }));
    }
}
