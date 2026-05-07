//! ByzzFuzz schedule sampling parameterised by `(c, d, r)`: process-fault
//! rounds, network-fault rounds, and total round budget. Signal-biased:
//! trivial single-block partitions are excluded, network views are
//! sampled without replacement, and process receiver subsets are
//! non-empty. Each *process* fault carries a
//! [`super::scope::FaultScope`] for per-(channel, kind) targeting;
//! network faults are total at their view. Vote process faults are
//! semantically mutated + re-signed (see
//! [`super::injector::ByzzFuzzInjector`]); cert and resolver process
//! faults are omit-only.

use crate::{
    byzzfuzz::{
        fault::{NetworkFault, ProcessFault},
        scope,
    },
    utils::SetPartition,
};
use commonware_consensus::types::View;
use commonware_cryptography::PublicKey;
use rand::{seq::SliceRandom, Rng};

fn receiver_candidates<P: PublicKey>(participants: &[P]) -> Vec<P> {
    participants.iter().skip(1).cloned().collect()
}

fn sample_receivers<P: PublicKey>(candidates: &[P], rng: &mut impl Rng) -> Vec<P> {
    let nonempty_subsets = (1u32 << candidates.len()) - 1;
    let mask = rng.gen_range(1..=nonempty_subsets);
    (0..candidates.len())
        .filter(|i| (mask >> i) & 1 == 1)
        .map(|i| candidates[i].clone())
        .collect()
}

/// `(c, d, r)`: process-fault rounds (`c`), network-fault
/// rounds (`d`), and total round budget (`r`). `c` and `d` are independent;
/// either set to 0 disables that fault type.
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

    /// `min(d, r)` draws of `(view, partition)`. Views are sampled
    /// without replacement from `[1, r]` so each network-fault slot
    /// lands on a distinct sender-round window. Partitions are uniform
    /// over the 14 non-trivial set partitions of `{0,1,2,3}`. No
    /// per-channel/kind targeting -- a network partition drops every
    /// channel between isolated blocks.
    pub fn network_faults(&self, rng: &mut impl Rng) -> Vec<NetworkFault> {
        if self.d == 0 || self.r == 0 {
            return Vec::new();
        }
        let take = (self.d as usize).min(self.r as usize);
        let mut views: Vec<u64> = (1..=self.r).collect();
        views.shuffle(rng);
        views
            .into_iter()
            .take(take)
            .map(|view| {
                // 14 non-trivial partitions live at N4[1..15].
                let idx = rng.gen_range(1..15);
                NetworkFault {
                    view: View::new(view),
                    partition: SetPartition::n4(idx),
                }
            })
            .collect()
    }

    /// `c` independent draws of `(view, receivers, omit, scope)`. Views
    /// sampled with replacement from `[1, r]`; receivers are a uniform
    /// *non-empty* subset of `participants[1..]` (sampled as a non-zero
    /// bitmask). The byzantine identity (`participants[0]`, see
    /// [`crate::byzzfuzz::BYZANTINE_IDX`]) is excluded from the candidate
    /// set. `omit` fires with probability `1/4`. No per-fault mutation
    /// seed: the injector pulls mutation entropy directly from the
    /// runtime RNG (fed by the libfuzzer input) so byte-level guidance
    /// applies to the mutation choices themselves.
    pub fn process_faults<P: PublicKey>(
        &self,
        participants: &[P],
        rng: &mut impl Rng,
    ) -> Vec<ProcessFault<P>> {
        if self.c == 0 || self.r == 0 {
            return Vec::new();
        }
        let candidates = receiver_candidates(participants);
        if candidates.is_empty() {
            return Vec::new();
        }
        (0..self.c)
            .map(|_| {
                let view = rng.gen_range(1..=self.r);
                let omit = rng.gen_bool(0.25);
                ProcessFault {
                    view,
                    receivers: sample_receivers(&candidates, rng),
                    omit,
                    scope: scope::sample(rng),
                }
            })
            .collect()
    }

    /// Liveness-only post-GST process faults. The network is synchronous
    /// after GST, but the byzantine sender may continue to omit or mutate
    /// its own messages. The caller supplies concrete future `views`
    /// derived from the byzantine sender's current `rnd(m)` at GST so the
    /// post-GST schedule is not accidentally exhausted by Phase 1 progress.
    pub fn post_gst_process_faults<P: PublicKey>(
        views: impl IntoIterator<Item = u64>,
        participants: &[P],
        rng: &mut impl Rng,
    ) -> Vec<ProcessFault<P>> {
        let candidates = receiver_candidates(participants);
        if candidates.is_empty() {
            return Vec::new();
        }
        views
            .into_iter()
            .map(|view| ProcessFault {
                view,
                receivers: sample_receivers(&candidates, rng),
                omit: rng.gen_bool(0.25),
                scope: scope::FaultScope::Any,
            })
            .collect()
    }
}
