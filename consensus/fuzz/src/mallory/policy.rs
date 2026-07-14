//! Backend-agnostic tabular Q-policy and campaign state (Mallory-style,
//! arXiv:2305.02601).
//!
//! A tabular Q-policy learns, across the whole libFuzzer campaign, which
//! adversarial action to enact next given an exact fingerprint of the protocol's
//! observed state. One libFuzzer input drives one episode: each step picks an
//! action by softmax over the state's Q-row, runs the protocol to the next
//! boundary, and applies a temporal-difference update whose reward favours
//! reaching a novel protocol-state and/or happens-before fingerprint.
//!
//! The policy is agnostic to what the actions *mean*: it operates on an opaque
//! [`ActionId`] in a fixed catalog order chosen by the caller (the backend).
//! Different backends have different action counts, so the table width
//! ([`QPolicy::n_actions`]) is a runtime value and the table is a flat
//! `Q_TABLE_SIZE * n_actions` slice.
//!
//! Every decision is masked by a per-step `legal` slice: an action the caller
//! reports as unavailable is never selected and never contributes to a bootstrap
//! max, so it can neither be enacted nor receive temporal-difference credit.
//!
//! The Q-table and the novelty registries live in a process-global [`Campaign`]
//! that persists across inputs -- Algorithm 1's outer `repeat until time
//! budget`. Because that state is persistent, replaying the same input bytes can
//! produce a different schedule than the first time (the policy has since moved
//! on); this is inherent to online RL over libFuzzer.
//!
//! This module is runtime-agnostic and pure: every stochastic choice is made by
//! an [`Rng`] supplied by the caller (the deterministic runtime context, itself
//! seeded from the fuzz input), so the core owns no randomness of its own. It
//! imports no backend types; actions are numbers.

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

/// Fixed number of Q-table rows (a power of two). A state maps to a row by
/// `state & (Q_TABLE_SIZE - 1)`; distinct states that collide share a row -- a
/// bounded, graceful approximation -- so campaign memory never grows.
const Q_TABLE_SIZE: usize = 1 << 16;
/// Fixed number of membership slots per novelty registry (a power of two). A
/// fingerprint sets one bit; slot collisions make a distinct fingerprint
/// occasionally read as seen (a bounded false negative), never unbounded growth.
const SEEN_BITS: usize = 1 << 20;

/// Opaque index of an action in the backend's fixed catalog order (0-based). The
/// policy never interprets it; it is the caller's Q-table column.
pub type ActionId = usize;

/// Tabular Q-policy over a fixed-size, direct-mapped table: a state maps to one
/// of [`Q_TABLE_SIZE`] rows, each of `n_actions` columns, laid out flat (row `r`
/// action `a` at `r * n_actions + a`). Colliding states share a row (bounded,
/// graceful saturation); an untouched row is all zeros, so its legal softmax is
/// uniform.
pub struct QPolicy {
    n_actions: usize,
    table: Box<[f64]>,
}

impl QPolicy {
    /// A policy over `n_actions` actions (the backend's catalog size), all Q
    /// values zero.
    pub fn new(n_actions: usize) -> Self {
        assert!(n_actions > 0, "a policy needs at least one action");
        Self {
            n_actions,
            table: vec![0.0; Q_TABLE_SIZE * n_actions].into_boxed_slice(),
        }
    }

    /// Whether any Q value has moved away from zero. Test-only (episode smoke
    /// tests assert the campaign policy learned something).
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.table.iter().all(|&q| q == 0.0)
    }

    fn slot(state: u64) -> usize {
        (state & (Q_TABLE_SIZE as u64 - 1)) as usize
    }

    fn row(&self, state: u64) -> &[f64] {
        let base = Self::slot(state) * self.n_actions;
        &self.table[base..base + self.n_actions]
    }

    /// `max_a Q(state, a)` over the LEGAL actions only, so an unavailable action
    /// never contributes to a bootstrap target. Zero for an untouched row.
    fn best_legal(&self, state: u64, legal: &[bool]) -> f64 {
        self.row(state)
            .iter()
            .zip(legal)
            .filter_map(|(&q, &ok)| ok.then_some(q))
            .fold(f64::MIN, f64::max)
    }

    /// Softmax distribution over a Q-row at [`TEMPERATURE`], with illegal actions
    /// forced to probability zero. Shifts by the legal max for numerical
    /// stability; an all-equal legal set (e.g. a fresh zero row) is uniform over
    /// the legal actions.
    fn softmax(row: &[f64], legal: &[bool]) -> Vec<f64> {
        let max = row
            .iter()
            .zip(legal)
            .filter_map(|(&q, &ok)| ok.then_some(q))
            .fold(f64::MIN, f64::max);
        let mut probs = vec![0.0; row.len()];
        let mut sum = 0.0;
        for (i, (&q, &ok)) in row.iter().zip(legal).enumerate() {
            if ok {
                let e = ((q - max) / TEMPERATURE).exp();
                probs[i] = e;
                sum += e;
            }
        }
        for p in &mut probs {
            *p /= sum;
        }
        probs
    }

    /// Sample a legal action by inverse-CDF over the masked softmax, drawing from
    /// the caller-supplied RNG (the deterministic runtime context). Illegal
    /// actions have zero probability and are never returned. At least one action
    /// must be legal, else the caller is buggy.
    pub fn select(&self, state: u64, legal: &[bool], rng: &mut impl Rng) -> ActionId {
        assert_eq!(
            legal.len(),
            self.n_actions,
            "legal mask length must equal n_actions"
        );
        assert!(
            legal.iter().any(|&ok| ok),
            "select requires at least one legal action"
        );
        let dist = Self::softmax(self.row(state), legal);
        // Uniform p in [0, 1) from 53 random bits.
        let p = ((rng.random::<u64>() >> 11) as f64) / ((1u64 << 53) as f64);
        let mut cumulative = 0.0;
        for (i, &d) in dist.iter().enumerate() {
            cumulative += d;
            if p < cumulative {
                return i;
            }
        }
        // Floating-point guard: the last legal action.
        (0..self.n_actions)
            .rev()
            .find(|&i| legal[i])
            .expect("at least one legal action")
    }

    /// TD update with bootstrap:
    /// `Q(s,a) <- (1-alpha) Q(s,a) + alpha (R + gamma max_a' Q(s',a'))`, where the
    /// bootstrap max is over the actions legal at `next` only.
    pub fn learn(
        &mut self,
        state: u64,
        action: ActionId,
        reward: f64,
        next: u64,
        legal_next: &[bool],
    ) {
        let target = reward + GAMMA * self.best_legal(next, legal_next);
        self.update(state, action, target);
    }

    /// Terminal update (last step of an episode): no bootstrap, target is `R`.
    pub fn learn_terminal(&mut self, state: u64, action: ActionId, reward: f64) {
        self.update(state, action, reward);
    }

    fn update(&mut self, state: u64, action: ActionId, target: f64) {
        let q = &mut self.table[Self::slot(state) * self.n_actions + action];
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
    /// Catalog size this campaign was built for. Fixed for the process: the
    /// global campaign asserts every later request matches it.
    n_actions: usize,
}

impl Campaign {
    /// A campaign over an `n_actions`-wide policy with empty novelty registries.
    pub fn new(n_actions: usize) -> Self {
        Self {
            policy: QPolicy::new(n_actions),
            seen_state: vec![0u64; SEEN_BITS / 64].into_boxed_slice(),
            seen_hb: vec![0u64; SEEN_BITS / 64].into_boxed_slice(),
            n_actions,
        }
    }

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

/// Process-global campaign state, initialised on first use over `n_actions`
/// actions and persisted across every libFuzzer input for the rest of the
/// campaign. The action count is fixed once initialised: a later call with a
/// different `n_actions` is a wiring bug and panics.
pub fn campaign(n_actions: usize) -> &'static Mutex<Campaign> {
    let campaign = CAMPAIGN.get_or_init(|| Mutex::new(Campaign::new(n_actions)));
    assert_eq!(
        campaign.lock().n_actions,
        n_actions,
        "campaign action count is fixed for the process once initialised"
    );
    campaign
}

/// Reset the process-global campaign to an empty one over `n_actions` actions.
/// Test-only, so unit tests do not leak learned Q-values or novelty sets into
/// one another.
#[cfg(test)]
pub fn reset_campaign(n_actions: usize) {
    *campaign(n_actions).lock() = Campaign::new(n_actions);
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::FuzzRng;

    /// Catalog size the ActionId tests exercise.
    const N: usize = 5;
    const ALL_LEGAL: [bool; N] = [true; N];

    #[test]
    fn softmax_is_valid_and_uniform_at_zero_q() {
        let dist = QPolicy::softmax(&[0.0; N], &ALL_LEGAL);
        let sum: f64 = dist.iter().sum();
        assert!((sum - 1.0).abs() < 1e-9, "distribution must sum to 1");
        for d in dist {
            assert!(
                (d - 1.0 / N as f64).abs() < 1e-9,
                "zero Q-row must be uniform"
            );
        }
    }

    #[test]
    fn softmax_prefers_higher_q() {
        let mut row = [0.0; N];
        row[1] = 1.0;
        let dist = QPolicy::softmax(&row, &ALL_LEGAL);
        assert!((dist.iter().sum::<f64>() - 1.0).abs() < 1e-9);
        assert!(dist[1] > dist[0]);
        // Untouched columns keep equal probability.
        assert!((dist[0] - dist[4]).abs() < 1e-9);
    }

    #[test]
    fn td_update_moves_q_toward_rewarded_action() {
        let mut policy = QPolicy::new(N);
        let state = 42;
        policy.learn_terminal(state, 1, 0.0);
        policy.learn_terminal(state, 0, -1.0);
        let row = policy.row(state);
        assert!(
            row[1] > row[0],
            "the higher-reward action must gain a higher Q-value"
        );
        let dist = QPolicy::softmax(row, &ALL_LEGAL);
        assert!(dist[1] > dist[0]);
    }

    #[test]
    fn terminal_update_uses_no_bootstrap() {
        // A next state seeded with a large Q must not influence a terminal
        // update, but must influence a bootstrapped one.
        let next = 7;

        let mut terminal = QPolicy::new(N);
        terminal.learn_terminal(next, 1, 100.0);
        terminal.learn_terminal(1, 0, 5.0);
        let terminal_q = terminal.row(1)[0];
        assert!((terminal_q - ALPHA * 5.0).abs() < 1e-9);

        let mut bootstrapped = QPolicy::new(N);
        bootstrapped.learn_terminal(next, 1, 100.0);
        bootstrapped.learn(2, 0, 5.0, next, &ALL_LEGAL);
        let bootstrapped_q = bootstrapped.row(2)[0];
        let expected = ALPHA * (5.0 + GAMMA * bootstrapped.best_legal(next, &ALL_LEGAL));
        assert!((bootstrapped_q - expected).abs() < 1e-9);
        assert!(
            bootstrapped_q > terminal_q,
            "bootstrap must add next-state value"
        );
    }

    #[test]
    fn novelty_registry_returns_zero_then_minus_one() {
        let mut campaign = Campaign::new(N);
        assert_eq!(campaign.state_reward(123), 0.0);
        assert_eq!(campaign.state_reward(123), -1.0);
        assert_eq!(campaign.hb_reward(9), 0.0);
        assert_eq!(campaign.hb_reward(9), -1.0);

        let mut weighted = Campaign::new(N);
        assert_eq!(weighted.reward(1, 2), 0.0, "both novel");
        assert_eq!(weighted.reward(1, 2), -(W_STATE + W_HB), "neither novel");
    }

    #[test]
    fn select_is_in_range_and_deterministic() {
        let mut policy = QPolicy::new(N);
        policy.learn_terminal(0, 3, 3.0);
        let draw = || {
            let mut rng = FuzzRng::new(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
            (0..16)
                .map(|_| policy.select(0, &ALL_LEGAL, &mut rng))
                .collect::<Vec<_>>()
        };
        let first = draw();
        assert!(first.iter().all(|&a| a < N));
        assert_eq!(first, draw(), "same RNG seed must yield the same actions");
    }

    #[test]
    fn q_table_learns_at_any_state_after_saturation() {
        // The fixed table never freezes: after touching far more distinct states
        // than it has rows, an arbitrary state still updates (no permanently
        // uniform "dead" rows), and storage stays fixed by construction.
        let mut policy = QPolicy::new(N);
        for k in 0..(Q_TABLE_SIZE as u64 * 2 + 7) {
            policy.learn_terminal(k, 0, -1.0);
        }
        let probe = 0xdead_beef_u64;
        let before = policy.row(probe)[3];
        policy.learn_terminal(probe, 3, 1.0);
        let after = policy.row(probe)[3];
        assert!(after > before, "any state must still learn after saturation");
    }

    #[test]
    fn legal_mask_excludes_illegal_from_select_and_bootstrap() {
        // Action 1 is illegal but seeded with a dominant Q value: it must never
        // be selected, and it must never contribute to a bootstrap max.
        let legal = [true, false, true];
        let mut policy = QPolicy::new(3);
        policy.learn_terminal(0, 1, 100.0);

        let mut rng = FuzzRng::new(vec![0x9e, 0x37, 0x79, 0xb9, 0x7f, 0x4a, 0x7c, 0x15]);
        for _ in 0..64 {
            let a = policy.select(0, &legal, &mut rng);
            assert!(legal[a], "select must never return an illegal action");
        }

        let next = 5;
        policy.learn_terminal(next, 1, 100.0); // illegal, huge
        policy.learn_terminal(next, 0, 1.0);
        policy.learn_terminal(next, 2, 2.0);
        let best = policy.best_legal(next, &legal);
        assert!(
            (best - policy.row(next)[2]).abs() < 1e-9,
            "bootstrap max must be the best LEGAL action"
        );
        assert!(
            best < policy.row(next)[1],
            "the excluded illegal action was the larger value"
        );
    }
}
