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
    /// live set sustains the liveness expectation through the downtime.
    Reload(usize),
    /// Remove every network link adjacent to the node.
    Disconnect(usize),
    /// Restore the node's links to every currently-connected peer.
    Reconnect(usize),
}

impl Action {
    /// Whether enacting this action restores health rather than breaking it.
    /// Faults publish expectations before landing; heals land before publishing.
    pub(crate) fn is_heal(&self) -> bool {
        matches!(self, Action::Start(_) | Action::Reconnect(_))
    }
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

    /// Validators expected to participate in consensus right now.
    pub(crate) fn live_count(&self) -> usize {
        self.conditions
            .iter()
            .filter(|&&condition| condition == Condition::Healthy)
            .count()
    }

    /// Whether the committee is expected to finalize right now: the fact the
    /// watcher needs to decide if a stalled chain is a finding or the
    /// schedule's own doing.
    pub(crate) fn expect_liveness(&self) -> bool {
        self.live_count() >= self.quorum
    }

    /// Produces the next action. Due heals always go first; otherwise a fault is
    /// drawn, constrained so the healthy set stays at or above quorum, except
    /// in a deliberately sanctioned outage (a rare draw), which is followed by
    /// its heal within a small bounded horizon. The sanction menu excludes
    /// [`Action::Reload`]: its downtime would hide below-quorum time under a
    /// standing liveness expectation.
    pub(crate) fn next_action(&mut self, rng: &mut impl Rng) -> Action {
        self.step += 1;

        if let Some(position) = self
            .pending_heals
            .iter()
            .position(|(due, _)| *due <= self.step)
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
            let heal_in = rng.random_range(2..=6u64);
            let menu = if above_quorum { 3 } else { 2 };
            match rng.random_range(0..menu) {
                0 => {
                    self.pending_heals
                        .push((self.step + heal_in, Action::Start(target)));
                    Action::Kill(target)
                }
                1 => {
                    self.pending_heals
                        .push((self.step + heal_in, Action::Reconnect(target)));
                    Action::Disconnect(target)
                }
                _ => Action::Reload(target),
            }
        } else {
            // Heal something early, or, with everything healthy, default to the
            // most valuable exercise: kill-and-restart.
            match self.pending_heals.pop() {
                Some((_, heal)) => heal,
                None => {
                    let target = healthy[rng.random_range(0..healthy.len())];
                    self.pending_heals
                        .push((self.step + 1, Action::Start(target)));
                    Action::Kill(target)
                }
            }
        };
        self.apply(action);
        action
    }

    fn apply(&mut self, action: Action) {
        let (index, condition) = match action {
            Action::Kill(index) => (index, Condition::Killed),
            Action::Disconnect(index) => (index, Condition::Disconnected),
            Action::Start(index) | Action::Reconnect(index) | Action::Reload(index) => {
                (index, Condition::Healthy)
            }
        };
        self.conditions[index] = condition;
    }

    /// The heals that restore full health, enacted at episode end so the
    /// post-heal liveness oracle runs over the whole committee. Applies them to
    /// the believed conditions as well: the expectations published after
    /// healing must reflect the healed cluster, or the watcher would judge
    /// legitimate post-heal catch-up against a frozen below-quorum baseline.
    pub(crate) fn heal_everything(&mut self) -> Vec<Action> {
        let heals: Vec<Action> = self
            .conditions
            .iter()
            .enumerate()
            .filter_map(|(index, condition)| match condition {
                Condition::Healthy => None,
                Condition::Killed => Some(Action::Start(index)),
                Condition::Disconnected => Some(Action::Reconnect(index)),
            })
            .collect();
        for heal in &heals {
            self.apply(*heal);
        }
        heals
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
        // Below-quorum health must only ever follow a deliberate sanction, and
        // must heal within the bounded horizon (no permanent outage).
        for seed in 0..50 {
            let mut rng = TestRng::new(seed);
            let mut schedule = Schedule::new(4, 3);
            let mut below_quorum_streak = 0u32;
            for _ in 0..2_000 {
                schedule.next_action(&mut rng);
                if schedule.expect_liveness() {
                    below_quorum_streak = 0;
                } else {
                    below_quorum_streak += 1;
                    assert!(
                        below_quorum_streak <= 12,
                        "seed {seed}: outage lasted longer than its bounded heal horizon",
                    );
                }
            }
        }
    }

    #[test]
    fn healing_everything_restores_full_health_and_the_liveness_expectation() {
        for seed in 0..50 {
            let mut rng = TestRng::new(seed);
            let mut schedule = Schedule::new(4, 3);
            for _ in 0..500 {
                schedule.next_action(&mut rng);
            }
            let heals = schedule.heal_everything();
            assert_eq!(schedule.live_count(), 4, "seed {seed}");
            assert!(
                schedule.expect_liveness(),
                "seed {seed}: expectations published after healing must expect liveness",
            );
            assert!(schedule.heal_everything().is_empty(), "seed {seed}");
            for heal in heals {
                assert!(heal.is_heal(), "seed {seed}: heal_everything must only heal");
            }
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
                            schedule.expect_liveness(),
                            "seed {seed}: reload drawn without quorum slack",
                        );
                    }
                    Action::Start(_) | Action::Reconnect(_) => {}
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
