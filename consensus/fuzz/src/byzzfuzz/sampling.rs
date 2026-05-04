//! Paper-faithful ByzzFuzz schedule sampling (Algorithm 1 `(d, p, r)`).
//!
//! Schedule shape lives here. Content mutation of intercepted messages is
//! delegated to [`crate::strategy::Strategy`] (`SmallScope` is forced by
//! the runner).

use crate::{byzzfuzz::fault::ProcessFault, utils::SetPartition};
use commonware_consensus::types::View;
use commonware_cryptography::PublicKey;
use rand::Rng;

/// Algorithm 1's `(d, p, r)`: process-fault rounds, network-fault rounds,
/// and round budget. `d` and `p` are independent; either set to 0 disables
/// that axis.
#[derive(Clone, Copy, Debug, Default)]
pub struct ByzzFuzz {
    pub d: u64,
    pub p: u64,
    pub r: u64,
}

impl ByzzFuzz {
    pub const fn new(d: u64, p: u64, r: u64) -> Self {
        Self { d, p, r }
    }

    /// `p` independent draws of `(view, partition)` over `[1, r] x` all 15
    /// set partitions of `{0,1,2,3}`. Includes the trivial single-block
    /// (no-op) per the paper's "uniform over partitions of P".
    pub fn network_faults(&self, rng: &mut impl Rng) -> Vec<(View, SetPartition)> {
        if self.p == 0 || self.r == 0 {
            return Vec::new();
        }
        (0..self.p)
            .map(|_| {
                let view = rng.gen_range(1..=self.r);
                let idx = rng.gen_range(0..15);
                (View::new(view), SetPartition::n4(idx))
            })
            .collect()
    }

    /// `d` independent draws of `(view, receivers, seed, omit)`. Receivers
    /// are a uniform (possibly empty) subset of `participants[1..]`;
    /// `omit` fires with probability `1/4`. The byzantine identity
    /// (`participants[0]`, see [`crate::byzzfuzz::BYZANTINE_IDX`]) is
    /// excluded from receiver subsets.
    pub fn process_faults<P: PublicKey>(
        &self,
        participants: &[P],
        rng: &mut impl Rng,
    ) -> Vec<ProcessFault<P>> {
        if self.d == 0 || self.r == 0 {
            return Vec::new();
        }
        let candidates: Vec<P> = participants.iter().skip(1).cloned().collect();
        if candidates.is_empty() {
            return Vec::new();
        }
        (0..self.d)
            .map(|_| {
                let view = rng.gen_range(1..=self.r);
                let receivers: Vec<P> = candidates
                    .iter()
                    .filter(|_| rng.gen_bool(0.5))
                    .cloned()
                    .collect();
                let seed = rng.gen::<u64>();
                let omit = rng.gen_bool(0.25);
                ProcessFault {
                    view,
                    receivers,
                    seed,
                    omit,
                }
            })
            .collect()
    }
}
