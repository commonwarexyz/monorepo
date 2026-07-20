//! Stateright harness over the volume protocol model.
//!
//! The hand-rolled BFS in the parent module is the mutation-tested
//! baseline and the conformance suite's lockstep oracle. This module
//! drives the SAME transition function ([`step`]) and the SAME invariant
//! checks through the [Stateright](https://github.com/stateright/stateright)
//! model checker as an independent core: nothing of the spec is duplicated
//! here — the harness only adapts `step`'s shape to Stateright's [`Model`]
//! trait. Sensitivity parity is pinned by re-running a sample of the
//! parent's mutation tests through this harness, and state-space parity by
//! comparing unique-state counts on rule-complete runs. The payoff is
//! Stateright's parallel checkers, which push the same workloads to
//! budgets the parent's single-threaded BFS cannot reach (see
//! `tests::deep_core`).
//!
//! # Action encoding
//!
//! [`step`] is one-to-many: a crash fans out over every per-block disk
//! resolution, a failed fsync fans out over every cache outcome, and a
//! re-crash during recovery repairs recurses into further fans — all
//! flattened into one deterministic successor list. Stateright instead
//! wants enumerable actions with one successor each, so a harness action
//! ([`Choice`]) is a workload action plus an index into that successor
//! list: enumeration runs `step` once per workload action and emits one
//! choice per successor, and `next_state` picks the indexed successor
//! out of the same list (memoized per thread, see
//! [`Harness::with_step`]). The reachable graph is therefore exactly the
//! hand-rolled checker's.
//!
//! # Invariants as one property
//!
//! The invariants (I1-I7) are checked INSIDE the transition logic, which
//! reports a violation instead of successors. The harness maps that error
//! onto a terminal [`Explored::Violated`] state and checks a single
//! `always` property: no reachable state is a violation. Detection is the
//! parent module's own code, never a re-derivation. A violating
//! transition enumerates as one choice, mirroring the hand-rolled
//! checker, which aborts on it without fanning further.
//!
//! # Dedup semantics
//!
//! Stateright deduplicates states by a 64-bit fingerprint where the
//! hand-rolled BFS deduplicates by full state equality, so a fingerprint
//! collision would silently merge two distinct states (and prune the
//! branch behind the collided one). The exact-count parity tests on the
//! CORE and PRUNE workloads would fail on such a collision at the default
//! budgets.

use super::{initial_state, step, Action, Rules, State};
use commonware_utils::{thread_local_cache, Cached};
use stateright::{Model, Property};
use std::convert::Infallible;

/// Name of the harness's single `always` property.
const INVARIANTS: &str = "invariants (I1-I7)";

/// Name of the script mode's completion property (see
/// [`Workload::Script`]).
const COMPLETES: &str = "script runs to completion";

/// Name of the script mode's enabledness property (see
/// [`Workload::Script`]).
const NEVER_BLOCKS: &str = "script action always enabled";

/// One enumerable transition: a workload action plus the index of the
/// successor it selects among the action's fan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Choice {
    action: Action,
    /// Index into the deterministic successor list [`step`] produces for
    /// `action` (0 selects the violation itself when `step` reports one).
    outcome: usize,
}

/// How the harness feeds actions to the checker.
enum Workload {
    /// Every menu action is enabled at every step — the exploration mode
    /// of the hand-rolled checker's `check`.
    Menu(&'static [Action]),
    /// Action `i` is enabled only as the `i`-th step — the hand-rolled
    /// `run_trace` mode for directed mutation traces. Crash fans still
    /// explore every outcome, exactly as `run_trace` does.
    Script(&'static [Action]),
}

/// The existing model driven as a Stateright [`Model`].
struct Harness {
    workload: Workload,
    actions: u8,
    crashes: u8,
    rules: Rules,
}

impl Harness {
    /// A harness exploring `menu` under the same budgets as `check`.
    const fn menu(menu: &'static [Action], actions: u8, crashes: u8, rules: Rules) -> Self {
        Self {
            workload: Workload::Menu(menu),
            actions,
            crashes,
            rules,
        }
    }

    /// A harness replaying `script` under the same budgets as `run_trace`
    /// (one action budget per step, one crash).
    const fn script(script: &'static [Action], rules: Rules) -> Self {
        assert!(
            script.len() <= u8::MAX as usize,
            "script exceeds the budget"
        );
        Self {
            workload: Workload::Script(script),
            actions: script.len() as u8,
            crashes: 1,
            rules,
        }
    }

    /// The workload actions enabled in `state`. The script index derives
    /// from consumed actions — re-crashes during recovery are part of the
    /// crash step's flattened fan, so they never shift the script.
    fn enabled(&self, state: &State) -> &[Action] {
        match &self.workload {
            Workload::Menu(menu) => menu,
            Workload::Script(script) => {
                let consumed = (self.actions - state.actions_left) as usize;
                script.get(consumed).map_or(&[], std::slice::from_ref)
            }
        }
    }
}

/// One memoized [`step`] result: the successor fan, the violation's
/// reason, or `Ok(None)` for a disabled action.
type Fan = Result<Option<Vec<State>>, String>;

/// The memoized [`step`] results for one spec state, per enabled action.
struct FanCache {
    state: State,
    rules: Rules,
    fans: Vec<(Action, Fan)>,
}

thread_local_cache!(static FANS: Option<FanCache>);

impl Harness {
    /// Run `inspect` over the memoized `step` result for (`state`,
    /// `action`), computing it on first use. The checkers enumerate and
    /// then expand one state's choices consecutively per thread, so a
    /// per-thread memo of the current state's fans collapses the
    /// per-successor recomputation of `step` (a pure function of its
    /// inputs) into a lookup: the total transition work matches the
    /// hand-rolled BFS's one `step` per (state, action).
    fn with_step<R>(&self, state: &State, action: Action, inspect: impl FnOnce(&Fan) -> R) -> R {
        let mut cache = Cached::take(&FANS, || Ok::<_, Infallible>(None), |_| Ok(()))
            .expect("creating an empty memo cannot fail");
        let valid = cache
            .as_ref()
            .is_some_and(|c| c.rules == self.rules && c.state == *state);
        if !valid {
            *cache = Some(FanCache {
                state: state.clone(),
                rules: self.rules,
                fans: Vec::new(),
            });
        }
        let cache = cache.as_mut().expect("memo was just filled");
        if !cache.fans.iter().any(|&(a, _)| a == action) {
            // The trace parameter only feeds the hand-rolled checker's
            // violation rendering — Stateright reconstructs its own
            // counterexample path — so an empty trace is passed.
            let result = step(state, action, &self.rules, &[]).map_err(|v| v.reason);
            cache.fans.push((action, result));
        }
        let (_, result) = cache
            .fans
            .iter()
            .find(|&&(a, _)| a == action)
            .expect("fan was just inserted");
        inspect(result)
    }
}

/// A discovered state: the spec state (boxed to keep the enum small), or
/// the violation `step` reported in place of successors.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Explored {
    Live(Box<State>),
    /// Terminal violation state carrying the reported reason. The
    /// `always` property flags it, and Stateright's counterexample path
    /// holds the trace.
    Violated(String),
}

impl Model for Harness {
    type State = Explored;
    type Action = Choice;

    fn init_states(&self) -> Vec<Self::State> {
        vec![Explored::Live(Box::new(initial_state(
            self.actions,
            self.crashes,
        )))]
    }

    fn actions(&self, state: &Self::State, actions: &mut Vec<Self::Action>) {
        let Explored::Live(state) = state else {
            return;
        };
        for &action in self.enabled(state) {
            self.with_step(state, action, |result| match result {
                Ok(None) => {}
                Ok(Some(successors)) => {
                    actions.extend((0..successors.len()).map(|outcome| Choice { action, outcome }));
                }
                Err(_) => actions.push(Choice { action, outcome: 0 }),
            });
        }
    }

    fn next_state(&self, state: &Self::State, choice: Self::Action) -> Option<Self::State> {
        let Explored::Live(state) = state else {
            return None;
        };
        self.with_step(state, choice.action, |result| match result {
            Ok(None) => None,
            Ok(Some(successors)) => {
                Some(Explored::Live(Box::new(successors[choice.outcome].clone())))
            }
            Err(reason) => Some(Explored::Violated(reason.clone())),
        })
    }

    fn properties(&self) -> Vec<Property<Self>> {
        let mut properties = vec![Property::always(INVARIANTS, |_, state: &Explored| {
            !matches!(state, Explored::Violated(_))
        })];
        if matches!(self.workload, Workload::Script(_)) {
            // Mirrors `run_trace`'s panic on a disabled step: the scripted
            // action must stay enabled on EVERY branch until the budget is
            // consumed (a violation counts as continuing — `run_trace`
            // reports it rather than panicking), so a mutated rule cannot
            // silently truncate the trace it is supposed to replay.
            properties.push(Property::always(
                NEVER_BLOCKS,
                |model: &Self, state: &Explored| {
                    let Explored::Live(s) = state else {
                        return true;
                    };
                    if s.actions_left == 0 {
                        return true;
                    }
                    let [action] = model.enabled(s) else {
                        return false;
                    };
                    model.with_step(s, *action, |fan| !matches!(fan, Ok(None)))
                },
            ));
            // The end of the script is reachable — no zero-successor
            // step hides a truncated run from the property above.
            properties.push(Property::sometimes(
                COMPLETES,
                |_, state: &Explored| matches!(state, Explored::Live(s) if s.actions_left == 0),
            ));
        }
        properties
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            check,
            tests::{BATCH, CAPTURE_GATED_FREES_TRACE, CORE, MANIFEST_FRESH_SHADOW_TRACE, PRUNE},
            Rules, SPEC,
        },
        Harness, INVARIANTS,
    };
    use stateright::{Checker as _, Model as _};

    /// Threads for the non-ignored harness runs, bounded so the suite
    /// stays well-behaved under nextest's own test parallelism.
    fn threads() -> usize {
        std::thread::available_parallelism().map_or(2, |n| n.get().min(4))
    }

    /// The spec holds on the core workload under the Stateright core, and
    /// the unique-state count matches the hand-rolled BFS exactly (the
    /// graphs agree state for state unless a 64-bit fingerprint collision
    /// merges two, which would break the equality).
    #[test]
    fn holds_and_matches_core() {
        let expected = check(CORE, 8, 2, &SPEC).expect("spec must hold");
        let checker = Harness::menu(CORE, 8, 2, SPEC)
            .checker()
            .threads(threads())
            .spawn_bfs()
            .join();
        checker.assert_properties();
        assert_eq!(checker.unique_state_count(), expected);
    }

    /// [`holds_and_matches_core`] for the pruning workload.
    #[test]
    fn holds_and_matches_prune() {
        let expected = check(PRUNE, 8, 2, &SPEC).expect("spec must hold");
        let checker = Harness::menu(PRUNE, 8, 2, SPEC)
            .checker()
            .threads(threads())
            .spawn_bfs()
            .join();
        checker.assert_properties();
        assert_eq!(checker.unique_state_count(), expected);
    }

    /// Sensitivity parity with `tests::mutation_table_binding_detected`:
    /// same menu, budgets, and disabled rule.
    #[test]
    fn mutation_table_binding_detected() {
        let rules = Rules {
            bind_table: false,
            ..SPEC
        };
        let checker = Harness::menu(CORE, 9, 2, rules)
            .checker()
            .threads(threads())
            .spawn_bfs()
            .join();
        assert!(
            checker.discovery(INVARIANTS).is_some(),
            "harness missed table aliasing"
        );
    }

    /// Sensitivity parity with `tests::mutation_batch_split_detected`.
    #[test]
    fn mutation_batch_split_detected() {
        let rules = Rules {
            respect_groups: false,
            ..SPEC
        };
        let checker = Harness::menu(BATCH, 8, 2, rules)
            .checker()
            .threads(threads())
            .spawn_bfs()
            .join();
        assert!(
            checker.discovery(INVARIANTS).is_some(),
            "harness missed a split batch"
        );
    }

    /// Sensitivity parity with
    /// `tests::mutation_capture_gated_frees_detected`: the directed trace
    /// replayed as a script. The spec run must hold and complete, and the
    /// mutated run must reach the violation.
    #[test]
    fn mutation_capture_gated_frees_detected() {
        let spec = Harness::script(CAPTURE_GATED_FREES_TRACE, SPEC)
            .checker()
            .spawn_bfs()
            .join();
        spec.assert_properties();
        let rules = Rules {
            capture_gated_frees: false,
            ..SPEC
        };
        let mutated = Harness::script(CAPTURE_GATED_FREES_TRACE, rules)
            .checker()
            .spawn_bfs()
            .join();
        assert!(
            mutated.discovery(INVARIANTS).is_some(),
            "harness missed the capture-gated free"
        );
    }

    /// Sensitivity parity with
    /// `tests::mutation_manifest_fresh_shadow_detected`, as a script.
    #[test]
    fn mutation_manifest_fresh_shadow_detected() {
        let spec = Harness::script(MANIFEST_FRESH_SHADOW_TRACE, SPEC)
            .checker()
            .spawn_bfs()
            .join();
        spec.assert_properties();
        let rules = Rules {
            manifest_fresh_shadow: false,
            ..SPEC
        };
        let mutated = Harness::script(MANIFEST_FRESH_SHADOW_TRACE, rules)
            .checker()
            .spawn_bfs()
            .join();
        assert!(
            mutated.discovery(INVARIANTS).is_some(),
            "harness missed the unverified shadow splice"
        );
    }

    /// Deeper-than-default sweep of the core workload on the parallel
    /// checker — a budget the single-threaded BFS cannot reach in
    /// reasonable time (run with the full test profile). The extra budget
    /// goes to a THIRD crash: 10 actions exhaust the model's block
    /// capacity on both cores (a history of uncommitted allocations plus
    /// deferred frees empties the 10-block free list and trips
    /// `Volume::allocate`), so deeper action budgets need a bigger
    /// modeled disk, not a faster checker. For scale: actions 9 with two
    /// crashes covers ~4.1M states — the hand-rolled deep sweep's
    /// minutes-long budget.
    #[test]
    #[ignore]
    fn deep_core() {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let checker = Harness::menu(CORE, 9, 3, SPEC)
            .checker()
            .threads(threads)
            .spawn_dfs()
            .join();
        checker.assert_properties();
        let states = checker.unique_state_count();
        println!("deep core (actions 9, crashes 3): {states} unique states");
        assert!(
            states > 5_000_000,
            "suspiciously small deep state space: {states}"
        );
    }
}
