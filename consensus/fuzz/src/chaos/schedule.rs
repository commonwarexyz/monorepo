//! The pure fault-schedule core, adapted from the zksync-os-server chaos rig.
//!
//! One invariant governs every decision: **the schedule always knows whether the
//! committee should be live**. It never reduces the healthy set below quorum
//! except through a deliberate, bounded outage window (a rare draw), and every
//! fault it schedules comes with its own paired heal a small bounded number of
//! steps later. Due heals always go first, so no fault outlives its horizon.
//!
//! The core is pure: it owns no entropy (every draw comes through the caller's
//! RNG, at runtime the deterministic context seeded from the fuzzer input) and
//! performs no I/O. The runner enacts the returned [`Action`]s; unit tests drive
//! the core over thousands of steps to check its constraints.

use rand::{Rng, RngExt as _};

/// Soonest and latest a fault's paired heal is scheduled, in steps after the
/// fault. Every heal is drawn from and allocated within `[MIN, MAX]`, so the
/// window has `MAX - MIN + 1 = 5` distinct due steps. [`Schedule::schedule_heal`]
/// gives each pending heal a unique step; a free one exists whenever the window
/// has at least `n` slots, and at most `n - 1` heals are already pending when a
/// new fault is drawn (a sanctioned outage can break the last healthy node), so
/// the fit is guaranteed for `n <= 5`. Chaos ships N4, so the past-the-window
/// fallback in `schedule_heal` is never taken and only guards against a hang.
const HEAL_HORIZON_MIN: u64 = 2;
const HEAL_HORIZON_MAX: u64 = 6;

/// One validator's condition as the schedule believes it to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Condition {
    Healthy,
    /// Crash-stopped (tasks aborted). Restarted by a scheduled [`Action::Start`].
    Killed,
    /// Detached from the cluster network; the process keeps running.
    Disconnected,
}

/// What the schedule can do to the cluster. The runner maps these onto the
/// harness primitives; tests record them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// Dirty crash: abort the node's tasks immediately.
    Kill(usize),
    /// Durable restart of a killed node on its existing storage (journal replay).
    Start(usize),
    /// Bounded-downtime restart in one step: abort, fixed downtime, then the
    /// same durable rebuild as [`Action::Start`]. Self-healing (the condition
    /// stays [`Condition::Healthy`]), so it is only drawn while the remaining
    /// live set stays at or above quorum through the downtime.
    Reload(usize),
    /// Remove every network link adjacent to the node.
    Disconnect(usize),
    /// Restore the node's links to every currently-connected peer.
    Reconnect(usize),
    /// Let standing faults ride to their scheduled heal: healing early on
    /// every non-breaking draw would starve the disruption horizon of coverage.
    Wait,
}

/// The pure decision core: owns the believed cluster state and produces one
/// action at a time from the caller's RNG.
pub(crate) struct Schedule {
    conditions: Vec<Condition>,
    quorum: usize,
    /// Heals due at a given step: `(due_step, action)`.
    pending_heals: Vec<(u64, Action)>,
    step: u64,
}

impl Schedule {
    pub(crate) fn new(validators: usize, quorum: usize) -> Self {
        Self {
            conditions: vec![Condition::Healthy; validators],
            quorum,
            pending_heals: Vec::new(),
            step: 0,
        }
    }

    pub(crate) fn conditions(&self) -> Vec<Condition> {
        self.conditions.clone()
    }

    /// Healthy (participating) validators right now. Drives fault legality:
    /// the schedule keeps this at or above quorum except in a sanctioned
    /// outage, so it never permanently wedges the cluster.
    pub(crate) fn live_count(&self) -> usize {
        self.conditions
            .iter()
            .filter(|&&condition| condition == Condition::Healthy)
            .count()
    }

    /// Produces the next action. Due heals always go first; otherwise a fault is
    /// drawn, constrained so the healthy set stays at or above quorum, except
    /// in a deliberately sanctioned outage (a rare draw), which is followed by
    /// its heal within a small bounded horizon. The sanction menu excludes
    /// [`Action::Reload`]: its transient downtime is not an outage.
    pub(crate) fn next_action(&mut self, rng: &mut impl Rng) -> Action {
        self.step += 1;

        // Enact the earliest-due heal that has come due. Due steps are unique
        // (see `schedule_heal`), so at most one heal is due per step and none
        // is ever stranded a step late behind another sharing its deadline.
        if let Some(position) = (0..self.pending_heals.len())
            .filter(|&i| self.pending_heals[i].0 <= self.step)
            .min_by_key(|&i| self.pending_heals[i].0)
        {
            let (_, heal) = self.pending_heals.remove(position);
            self.apply(heal);
            return heal;
        }

        let healthy: Vec<usize> = self
            .conditions
            .iter()
            .enumerate()
            .filter(|(_, condition)| **condition == Condition::Healthy)
            .map(|(index, _)| index)
            .collect();
        let above_quorum = self.live_count() > self.quorum;
        let sanction_outage = rng.random_ratio(1, 20);
        let can_break = !healthy.is_empty() && (above_quorum || sanction_outage);

        let action = if can_break && rng.random_ratio(2, 3) {
            let target = healthy[rng.random_range(0..healthy.len())];
            let heal_in = rng.random_range(HEAL_HORIZON_MIN..=HEAL_HORIZON_MAX);
            let menu = if above_quorum { 3 } else { 2 };
            match rng.random_range(0..menu) {
                0 => {
                    self.schedule_heal(self.step + heal_in, Action::Start(target));
                    Action::Kill(target)
                }
                1 => {
                    self.schedule_heal(self.step + heal_in, Action::Reconnect(target));
                    Action::Disconnect(target)
                }
                _ => Action::Reload(target),
            }
        } else if self.pending_heals.is_empty() {
            // Everything healthy and the dice said "don't break": kill-and-
            // restart is the most valuable default exercise.
            let target = healthy[rng.random_range(0..healthy.len())];
            self.pending_heals
                .push((self.step + 1, Action::Start(target)));
            Action::Kill(target)
        } else {
            Action::Wait
        };
        self.apply(action);
        action
    }

    /// Push a heal at a UNIQUE due step, so the one-heal-per-step drain never
    /// leaves a second heal that shared a deadline to fire late. Prefers
    /// `base_due` (already drawn within the horizon); otherwise the earliest
    /// free step in the horizon window. A free slot always exists for `n <= 5`
    /// (see [`HEAL_HORIZON_MAX`]), so the past-the-window fallback is never
    /// taken by the shipped N4 targets and only guards against a hang.
    fn schedule_heal(&mut self, base_due: u64, heal: Action) {
        fn is_taken(heals: &[(u64, Action)], due: u64) -> bool {
            heals.iter().any(|(existing, _)| *existing == due)
        }
        let mut due = base_due;
        if is_taken(&self.pending_heals, due) {
            due = self.step + HEAL_HORIZON_MAX + 1;
            for candidate in self.step + HEAL_HORIZON_MIN..=self.step + HEAL_HORIZON_MAX {
                if !is_taken(&self.pending_heals, candidate) {
                    due = candidate;
                    break;
                }
            }
        }
        self.pending_heals.push((due, heal));
    }

    /// Pop and apply the next pending heal, earliest-due first (first index on
    /// ties, so a replay drains deterministically). Returns `None` when none
    /// remain. The finishing phase calls this after the last drawn fault so
    /// every scheduled recovery is enacted, even when the episode budget ended
    /// before the heal came due.
    pub(crate) fn drain_heal(&mut self) -> Option<Action> {
        let position = (0..self.pending_heals.len()).min_by_key(|&i| self.pending_heals[i].0)?;
        let (_, heal) = self.pending_heals.remove(position);
        self.apply(heal);
        Some(heal)
    }

    fn apply(&mut self, action: Action) {
        let (index, condition) = match action {
            Action::Kill(index) => (index, Condition::Killed),
            Action::Disconnect(index) => (index, Condition::Disconnected),
            Action::Start(index) | Action::Reconnect(index) | Action::Reload(index) => {
                (index, Condition::Healthy)
            }
            Action::Wait => return,
        };
        self.conditions[index] = condition;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::TestRng;

    /// Replays a schedule and returns every action taken.
    fn actions(seed: u64, validators: usize, quorum: usize, steps: usize) -> Vec<Action> {
        let mut rng = TestRng::new(seed);
        let mut schedule = Schedule::new(validators, quorum);
        (0..steps).map(|_| schedule.next_action(&mut rng)).collect()
    }

    #[test]
    fn same_rng_same_schedule() {
        assert_eq!(actions(42, 4, 3, 500), actions(42, 4, 3, 500));
        assert_ne!(actions(42, 4, 3, 500), actions(43, 4, 3, 500));
    }

    #[test]
    fn outages_are_sanctioned_and_bounded() {
        // Below-quorum health must only ever follow a deliberate sanction,
        // each carrying a heal due within the bounded horizon. Sanctions can
        // chain, so the bound is per-sanction (a due heal always exists), not
        // a fixed streak length.
        for seed in 0..50 {
            let mut rng = TestRng::new(seed);
            let mut schedule = Schedule::new(4, 3);
            for _ in 0..2_000 {
                schedule.next_action(&mut rng);
                if schedule.live_count() < 3 {
                    assert!(
                        schedule
                            .pending_heals
                            .iter()
                            .any(|(due, _)| *due <= schedule.step + HEAL_HORIZON_MAX),
                        "seed {seed}: below quorum with no heal due within the horizon",
                    );
                }
            }
        }
    }

    #[test]
    fn faults_survive_to_their_scheduled_heal() {
        // Heals fire at their due step (no early healing), so every fault
        // window lasts its drawn horizon: 1 for the default kill-and-restart,
        // HEAL_HORIZON_MIN..=HEAL_HORIZON_MAX for menu faults.
        for seed in 0..20 {
            let mut rng = TestRng::new(seed);
            let mut schedule = Schedule::new(4, 3);
            let mut broken_at: [Option<u64>; 4] = [None; 4];
            let mut saw_horizon = false;
            for _ in 0..2_000 {
                let action = schedule.next_action(&mut rng);
                match action {
                    Action::Kill(i) | Action::Disconnect(i) => {
                        broken_at[i] = Some(schedule.step);
                    }
                    Action::Start(i) | Action::Reconnect(i) => {
                        let gap = schedule.step - broken_at[i].take().unwrap();
                        assert!(
                            (1..=HEAL_HORIZON_MAX).contains(&gap),
                            "seed {seed}: heal gap {gap} outside the horizon",
                        );
                        saw_horizon |= gap >= HEAL_HORIZON_MIN;
                    }
                    Action::Reload(_) | Action::Wait => {}
                }
            }
            assert!(saw_horizon, "seed {seed}: no fault ever rode its horizon");
        }
    }

    #[test]
    fn every_fault_carries_its_paired_heal() {
        // Each non-healthy node has exactly one pending heal, and it names the
        // right restoration; a reload leaves the node healthy with no heal.
        for seed in 0..20 {
            let mut rng = TestRng::new(seed);
            let mut schedule = Schedule::new(4, 3);
            for _ in 0..1_000 {
                let action = schedule.next_action(&mut rng);
                match action {
                    Action::Kill(i) => assert!(
                        schedule
                            .pending_heals
                            .iter()
                            .any(|(_, heal)| *heal == Action::Start(i)),
                        "seed {seed}: kill without a paired start",
                    ),
                    Action::Disconnect(i) => assert!(
                        schedule
                            .pending_heals
                            .iter()
                            .any(|(_, heal)| *heal == Action::Reconnect(i)),
                        "seed {seed}: disconnect without a paired reconnect",
                    ),
                    Action::Reload(i) => {
                        assert_eq!(schedule.conditions[i], Condition::Healthy);
                        assert!(
                            schedule.live_count() >= 3,
                            "seed {seed}: reload drawn without quorum slack",
                        );
                    }
                    Action::Start(_) | Action::Reconnect(_) | Action::Wait => {}
                }
                let broken = schedule
                    .conditions
                    .iter()
                    .filter(|c| **c != Condition::Healthy)
                    .count();
                assert_eq!(
                    broken,
                    schedule.pending_heals.len(),
                    "seed {seed}: pending heals out of sync with broken nodes",
                );
            }
        }
    }

    #[test]
    fn faults_spread_over_the_committee() {
        // Not a fairness proof, just a guard against the picker degenerating
        // to one victim.
        let actions = actions(7, 4, 3, 1_000);
        let mut touched = std::collections::BTreeSet::new();
        for action in actions {
            if let Action::Kill(index) | Action::Disconnect(index) | Action::Reload(index) = action
            {
                touched.insert(index);
            }
        }
        assert_eq!(touched.len(), 4, "every validator gets its turn");
    }
}
