//! Q-learning adaptive fault scheduler for ByzzFuzz (Mallory-style, arXiv:2305.02601).
//!
//! A tabular Q-policy learns, across the whole libFuzzer campaign, which
//! Byzantine fault to enact next given an exact fingerprint of the protocol's
//! observed state. One libFuzzer input drives one episode: each step picks an
//! action by softmax over the state's Q-row, runs the protocol to the next
//! finalization boundary, and applies a temporal-difference update whose reward
//! rewards reaching a novel protocol-state and/or happens-before fingerprint.
//!
//! The Q-table and the novelty registries live in a process-global [`Campaign`]
//! that persists across inputs -- Algorithm 1's outer `repeat until time
//! budget`. Because that state is persistent, replaying the same input bytes can
//! produce a different schedule than the first time (the policy has since moved
//! on); this is inherent to online RL over libFuzzer. The runner logs the chosen
//! actions so a crashing episode can still be reproduced.
//!
//! This module is runtime-agnostic and pure: every stochastic choice is made by
//! an [`Rng`] supplied by the caller (the deterministic runtime context, which
//! is itself seeded from the fuzz input), so the core owns no randomness of its
//! own.

use crate::byzzfuzz::fault::ProcessAction;
use commonware_utils::sync::Mutex;
use rand::{Rng, RngExt as _};
use std::sync::OnceLock;

/// Temporal-difference learning rate (Mallory paper + reference default).
const ALPHA: f64 = 0.1;
/// Discount factor (Mallory paper + reference default).
const GAMMA: f64 = 0.6;
/// Softmax temperature. The paper's plain `exp(Q)` form (`T = 1`) so the policy
/// actually exploits learned values; the reference code ships `T = 100`, which
/// makes softmax near-uniform, and is deliberately not copied.
const TEMPERATURE: f64 = 1.0;
/// Weight of the protocol-state novelty term in the step reward.
const W_STATE: f64 = 1.0;
/// Weight of the happens-before novelty term in the step reward.
const W_HB: f64 = 1.0;

/// Number of Q-table columns (the [`FaultAction`] set).
pub const N_ACTIONS: usize = 5;

/// Fixed number of Q-table rows (a power of two). A state maps to a row by
/// `state & (Q_TABLE_SIZE - 1)`; distinct states that collide share a row -- a
/// bounded, graceful approximation -- so campaign memory never grows.
const Q_TABLE_SIZE: usize = 1 << 16;
/// Fixed number of membership slots per novelty registry (a power of two). A
/// fingerprint sets one bit; slot collisions make a distinct fingerprint
/// occasionally read as seen (a bounded false negative), never unbounded growth.
const SEEN_BITS: usize = 1 << 20;

/// The fault type the policy chooses per step. The learner picks only the fault
/// TYPE; the concrete target (receiver subset, message scope, partition index,
/// crash duration) is filled in by the caller from the same runtime RNG, so
/// byte-level fuzz guidance still reaches those choices (Mallory-faithful).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultAction {
    /// Append nothing for the upcoming view.
    NoFault,
    /// A single-view Byzantine process fault against a sampled receiver subset.
    /// Reuses [`ProcessAction`] (omit vs mutate-and-re-sign) rather than
    /// restating those variants.
    Process(ProcessAction),
    /// Drop traffic across a sampled network partition ([`super::fault::NetworkFault`])
    /// for the upcoming view.
    Partition,
    /// Byzantine suppresses its own outbound (multi-view [`ProcessAction::Omit`])
    /// across a small range of views. NOT a true crash-stop: the engine stays
    /// alive and receiving, and because process faults match a message's carried
    /// view, old-view rebroadcasts within the range still escape.
    Crash,
}

impl FaultAction {
    /// All actions, indexed to their Q-table column.
    pub const ALL: [FaultAction; N_ACTIONS] = [
        Self::NoFault,
        Self::Process(ProcessAction::Omit),
        Self::Process(ProcessAction::MutateVote),
        Self::Partition,
        Self::Crash,
    ];

    /// Q-table column index of this action.
    pub fn index(self) -> usize {
        match self {
            Self::NoFault => 0,
            Self::Process(ProcessAction::Omit) => 1,
            Self::Process(ProcessAction::MutateVote) => 2,
            Self::Partition => 3,
            Self::Crash => 4,
        }
    }

    fn from_index(i: usize) -> Self {
        Self::ALL[i]
    }
}

type QRow = [f64; N_ACTIONS];

/// Tabular Q-policy over a fixed-size, direct-mapped table: a state maps to one
/// of [`Q_TABLE_SIZE`] rows. Colliding states share a row (bounded, graceful
/// saturation); an untouched row is all zeros, so its softmax is uniform.
pub struct QPolicy {
    table: Box<[QRow]>,
}

impl Default for QPolicy {
    fn default() -> Self {
        Self {
            table: vec![[0.0; N_ACTIONS]; Q_TABLE_SIZE].into_boxed_slice(),
        }
    }
}

impl QPolicy {
    /// Whether any row has been updated away from zero. Test-only (episode smoke
    /// tests assert the campaign policy learned something).
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.table.iter().all(|r| r.iter().all(|&q| q == 0.0))
    }

    fn slot(state: u64) -> usize {
        (state & (Q_TABLE_SIZE as u64 - 1)) as usize
    }

    fn row(&self, state: u64) -> QRow {
        self.table[Self::slot(state)]
    }

    /// `max_a Q(state, a)`, zero for an untouched row.
    fn best(&self, state: u64) -> f64 {
        self.row(state).into_iter().fold(f64::MIN, f64::max)
    }

    /// Softmax distribution over a Q-row at [`TEMPERATURE`]. Shifts by the row
    /// max for numerical stability; an all-equal row (e.g. a fresh zero row)
    /// yields the uniform distribution.
    fn distribution(row: &QRow) -> QRow {
        let max = row.iter().copied().fold(f64::MIN, f64::max);
        let mut exps = [0.0; N_ACTIONS];
        let mut sum = 0.0;
        for (i, &q) in row.iter().enumerate() {
            let e = ((q - max) / TEMPERATURE).exp();
            exps[i] = e;
            sum += e;
        }
        for e in &mut exps {
            *e /= sum;
        }
        exps
    }

    /// Sample an action by inverse-CDF over the softmax distribution, drawing
    /// from the caller-supplied RNG (the deterministic runtime context).
    pub fn select(&self, state: u64, rng: &mut impl Rng) -> FaultAction {
        let dist = Self::distribution(&self.row(state));
        // Uniform p in [0, 1) from 53 random bits.
        let p = ((rng.random::<u64>() >> 11) as f64) / ((1u64 << 53) as f64);
        let mut cumulative = 0.0;
        for (i, &d) in dist.iter().enumerate() {
            cumulative += d;
            if p < cumulative {
                return FaultAction::from_index(i);
            }
        }
        FaultAction::from_index(N_ACTIONS - 1)
    }

    /// TD update with bootstrap:
    /// `Q(s,a) <- (1-alpha) Q(s,a) + alpha (R + gamma max_a' Q(s',a'))`.
    pub fn learn(&mut self, state: u64, action: FaultAction, reward: f64, next: u64) {
        let target = reward + GAMMA * self.best(next);
        self.update(state, action, target);
    }

    /// Terminal update (last step of an episode): no bootstrap, target is `R`.
    pub fn learn_terminal(&mut self, state: u64, action: FaultAction, reward: f64) {
        self.update(state, action, reward);
    }

    fn update(&mut self, state: u64, action: FaultAction, target: f64) {
        let q = &mut self.table[Self::slot(state)][action.index()];
        *q = (1.0 - ALPHA) * *q + ALPHA * target;
    }
}

/// Campaign-persistent learning state: the Q-policy plus fixed-size novelty
/// registries for protocol-state and happens-before fingerprints. Lives for the
/// whole libFuzzer campaign (Algorithm 1's outer loop); all storage is fixed, so
/// memory never grows.
pub struct Campaign {
    pub policy: QPolicy,
    seen_state: Box<[u64]>,
    seen_hb: Box<[u64]>,
}

impl Default for Campaign {
    fn default() -> Self {
        Self {
            policy: QPolicy::default(),
            seen_state: vec![0u64; SEEN_BITS / 64].into_boxed_slice(),
            seen_hb: vec![0u64; SEEN_BITS / 64].into_boxed_slice(),
        }
    }
}

impl Campaign {
    /// Novelty of a fingerprint against a fixed-size membership bitset: `0` the
    /// first time its slot is seen this campaign, `-1` after. Slot collisions
    /// make a distinct fingerprint occasionally read as seen; bounded, never
    /// grows.
    fn novelty(bits: &mut [u64], fingerprint: u64) -> f64 {
        let slot = (fingerprint & (SEEN_BITS as u64 - 1)) as usize;
        let mask = 1u64 << (slot & 63);
        let word = &mut bits[slot >> 6];
        if *word & mask != 0 {
            -1.0
        } else {
            *word |= mask;
            0.0
        }
    }

    /// Novelty of a protocol-state fingerprint.
    fn state_reward(&mut self, fingerprint: u64) -> f64 {
        Self::novelty(&mut self.seen_state, fingerprint)
    }

    /// Novelty of a happens-before fingerprint.
    fn hb_reward(&mut self, fingerprint: u64) -> f64 {
        Self::novelty(&mut self.seen_hb, fingerprint)
    }

    /// Weighted novelty reward for a step's observation: `0` iff both the
    /// protocol-state and happens-before fingerprints are novel this campaign,
    /// down to `-(W_STATE + W_HB)` when neither is.
    pub fn reward(&mut self, state_fingerprint: u64, hb_fingerprint: u64) -> f64 {
        W_STATE * self.state_reward(state_fingerprint) + W_HB * self.hb_reward(hb_fingerprint)
    }
}

static CAMPAIGN: OnceLock<Mutex<Campaign>> = OnceLock::new();

/// Process-global campaign state, initialised on first use and persisted across
/// every libFuzzer input for the rest of the campaign.
pub fn campaign() -> &'static Mutex<Campaign> {
    CAMPAIGN.get_or_init(|| Mutex::new(Campaign::default()))
}

/// Reset the process-global campaign. Test-only, so unit tests do not leak
/// learned Q-values or novelty sets into one another.
#[cfg(test)]
pub fn reset_campaign() {
    *campaign().lock() = Campaign::default();
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::FuzzRng;

    #[test]
    fn softmax_is_valid_and_uniform_at_zero_q() {
        let dist = QPolicy::distribution(&[0.0; N_ACTIONS]);
        let sum: f64 = dist.iter().sum();
        assert!((sum - 1.0).abs() < 1e-9, "distribution must sum to 1");
        for d in dist {
            assert!(
                (d - 1.0 / N_ACTIONS as f64).abs() < 1e-9,
                "zero Q-row must be uniform"
            );
        }
    }

    /// The `Omit` process action, spelled once for the tests.
    const OMIT: FaultAction = FaultAction::Process(ProcessAction::Omit);

    #[test]
    fn softmax_prefers_higher_q() {
        let mut row = [0.0; N_ACTIONS];
        row[OMIT.index()] = 1.0;
        let dist = QPolicy::distribution(&row);
        assert!((dist.iter().sum::<f64>() - 1.0).abs() < 1e-9);
        assert!(dist[OMIT.index()] > dist[FaultAction::NoFault.index()]);
        // Untouched columns keep equal probability.
        assert!(
            (dist[FaultAction::NoFault.index()] - dist[FaultAction::Crash.index()]).abs() < 1e-9
        );
    }

    #[test]
    fn td_update_moves_q_toward_rewarded_action() {
        let mut policy = QPolicy::default();
        let state = 42;
        policy.learn_terminal(state, OMIT, 0.0);
        policy.learn_terminal(state, FaultAction::NoFault, -1.0);
        let row = policy.row(state);
        assert!(
            row[OMIT.index()] > row[FaultAction::NoFault.index()],
            "the higher-reward action must gain a higher Q-value"
        );
        let dist = QPolicy::distribution(&row);
        assert!(dist[OMIT.index()] > dist[FaultAction::NoFault.index()]);
    }

    #[test]
    fn terminal_update_uses_no_bootstrap() {
        // A next state seeded with a large Q must not influence a terminal
        // update, but must influence a bootstrapped one.
        let next = 7;

        let mut terminal = QPolicy::default();
        terminal.learn_terminal(next, OMIT, 100.0);
        terminal.learn_terminal(1, FaultAction::NoFault, 5.0);
        let terminal_q = terminal.row(1)[FaultAction::NoFault.index()];
        assert!((terminal_q - ALPHA * 5.0).abs() < 1e-9);

        let mut bootstrapped = QPolicy::default();
        bootstrapped.learn_terminal(next, OMIT, 100.0);
        bootstrapped.learn(2, FaultAction::NoFault, 5.0, next);
        let bootstrapped_q = bootstrapped.row(2)[FaultAction::NoFault.index()];
        let expected = ALPHA * (5.0 + GAMMA * bootstrapped.best(next));
        assert!((bootstrapped_q - expected).abs() < 1e-9);
        assert!(bootstrapped_q > terminal_q, "bootstrap must add next-state value");
    }

    #[test]
    fn novelty_registry_returns_zero_then_minus_one() {
        let mut campaign = Campaign::default();
        assert_eq!(campaign.state_reward(123), 0.0);
        assert_eq!(campaign.state_reward(123), -1.0);
        assert_eq!(campaign.hb_reward(9), 0.0);
        assert_eq!(campaign.hb_reward(9), -1.0);

        let mut weighted = Campaign::default();
        assert_eq!(weighted.reward(1, 2), 0.0, "both novel");
        assert_eq!(weighted.reward(1, 2), -(W_STATE + W_HB), "neither novel");
    }

    #[test]
    fn select_is_in_range_and_deterministic() {
        let mut policy = QPolicy::default();
        policy.learn_terminal(0, FaultAction::Partition, 3.0);
        let draw = || {
            let mut rng = FuzzRng::new(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
            (0..16).map(|_| policy.select(0, &mut rng)).collect::<Vec<_>>()
        };
        let first = draw();
        assert!(first.iter().all(|a| FaultAction::ALL.contains(a)));
        assert_eq!(first, draw(), "same RNG seed must yield the same actions");
    }

    #[test]
    fn q_table_learns_at_any_state_after_saturation() {
        // The fixed table never freezes: after touching far more distinct states
        // than it has rows, an arbitrary state still updates (no permanently
        // uniform "dead" rows), and storage stays fixed by construction.
        let mut policy = QPolicy::default();
        for k in 0..(Q_TABLE_SIZE as u64 * 2 + 7) {
            policy.learn_terminal(k, FaultAction::NoFault, -1.0);
        }
        let probe = 0xdead_beef_u64;
        let before = policy.row(probe)[FaultAction::Partition.index()];
        policy.learn_terminal(probe, FaultAction::Partition, 1.0);
        let after = policy.row(probe)[FaultAction::Partition.index()];
        assert!(after > before, "any state must still learn after saturation");
    }
}
