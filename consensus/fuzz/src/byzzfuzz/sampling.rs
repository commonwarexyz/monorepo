//! ByzzFuzz schedule sampling (Algorithm 1 `(c, d, r)` with signal-biased
//! deviations from a literal reading: trivial single-block partitions are
//! excluded, receiver subsets are non-empty, and each fault is tagged with
//! a [`super::scope::FaultScope`] so it can target a specific channel +
//! message kind. Content mutation of intercepted messages is delegated to
//! [`crate::strategy::Strategy`] (`SmallScope` is forced by the runner).

use crate::{
    byzzfuzz::{
        fault::{NetworkFault, ProcessFault},
        scope,
    },
    utils::SetPartition,
};
use commonware_consensus::types::View;
use commonware_cryptography::PublicKey;
use rand::Rng;

/// Algorithm 1's `(c, d, r)`: process-fault rounds (`c`), network-fault
/// rounds (`d`), and total round budget (`r`). `c` and `d` are independent;
/// either set to 0 disables that axis.
#[derive(Clone, Copy, Debug, Default)]
pub struct ByzzFuzz {
    pub c: u64,
    pub d: u64,
    pub r: u64,
}

impl ByzzFuzz {
    pub const fn new(c: u64, d: u64, r: u64) -> Self {
        Self { c, d, r }
    }

    /// `d` independent draws of `(view, partition, scope)` over `[1, r] x`
    /// the 14 non-trivial set partitions of `{0,1,2,3}` and a sampled scope.
    pub fn network_faults(&self, rng: &mut impl Rng) -> Vec<NetworkFault> {
        if self.d == 0 || self.r == 0 {
            return Vec::new();
        }
        (0..self.d)
            .map(|_| {
                let view = rng.gen_range(1..=self.r);
                // 14 non-trivial partitions live at N4[1..15].
                let idx = rng.gen_range(1..15);
                NetworkFault {
                    view: View::new(view),
                    partition: SetPartition::n4(idx),
                    scope: scope::sample(rng),
                }
            })
            .collect()
    }

    /// `c` independent draws of `(view, receivers, seed, omit)`. Receivers
    /// are a uniform *non-empty* subset of `participants[1..]` (sampled as
    /// a non-zero bitmask). The byzantine identity (`participants[0]`, see
    /// [`crate::byzzfuzz::BYZANTINE_IDX`]) is excluded from the candidate
    /// set. `omit` fires with probability `1/4`.
    pub fn process_faults<P: PublicKey>(
        &self,
        participants: &[P],
        rng: &mut impl Rng,
    ) -> Vec<ProcessFault<P>> {
        if self.c == 0 || self.r == 0 {
            return Vec::new();
        }
        let candidates: Vec<P> = participants.iter().skip(1).cloned().collect();
        if candidates.is_empty() {
            return Vec::new();
        }
        let nonempty_subsets = (1u32 << candidates.len()) - 1;
        (0..self.c)
            .map(|_| {
                let view = rng.gen_range(1..=self.r);
                let mask = rng.gen_range(1..=nonempty_subsets);
                let receivers: Vec<P> = (0..candidates.len())
                    .filter(|i| (mask >> i) & 1 == 1)
                    .map(|i| candidates[i].clone())
                    .collect();
                let seed = rng.gen::<u64>();
                let omit = rng.gen_bool(0.25);
                ProcessFault {
                    view,
                    receivers,
                    seed,
                    omit,
                    scope: scope::sample(rng),
                }
            })
            .collect()
    }
}
