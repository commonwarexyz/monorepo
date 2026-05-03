//! ByzzFuzz process-fault schedule type and sampler.
//!
//! Algorithm 1 of the paper samples each fault as `(rnd, recv, seed)` plus
//! an optional omission flag. The sampler here mirrors the paper's
//! `randomElementFrom([1, c])`, `randomSubsetOf(P)`, `randomElementFrom(Z)`
//! draws, with `omit` added at probability `1/4` to cover the
//! "or omits them" branch in the algorithm.

use commonware_cryptography::PublicKey;
use rand::Rng;

/// A single ByzzFuzz process fault. At view `view` the byzantine process's
/// deliveries to anyone in `receivers` are replaced by `mutate(_, seed)`.
/// When `omit` is true the mutation is the empty message set and the
/// injector emits nothing -- the forwarder's drop is the entire fault.
#[derive(Clone, Debug)]
pub struct ProcessFault<P: PublicKey> {
    pub view: u64,
    pub receivers: Vec<P>,
    pub seed: u64,
    pub omit: bool,
}

/// Sample a process-fault schedule of `count` faults distributed uniformly
/// over `[min_view, max_view]`. Receivers are a uniform random subset of
/// `participants \ {byzantine_idx}` -- including the empty subset, which the
/// paper permits.
pub fn sample<P: PublicKey>(
    count: u64,
    min_view: u64,
    max_view: u64,
    participants: &[P],
    byzantine_idx: usize,
    rng: &mut impl Rng,
) -> Vec<ProcessFault<P>> {
    if count == 0 || max_view < min_view {
        return Vec::new();
    }
    // Exclude the intercepted byzantine identity from its own receiver
    // subset. The paper's `randomSubsetOf(P)` is over abstract process
    // identities under a separate interception layer; in this harness the
    // byzantine process is a real honest engine plus outbound mutation, so
    // a self-targeted mutated delivery would loop back into that local
    // engine -- exercising a deployment artifact rather than a
    // network-delivered ByzzFuzz fault. Do not "fix" this back to `P` for
    // paper literalness.
    let candidates: Vec<P> = participants
        .iter()
        .enumerate()
        .filter(|(idx, _)| *idx != byzantine_idx)
        .map(|(_, pk)| pk.clone())
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }

    let mut faults = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let view = if max_view == min_view {
            min_view
        } else {
            rng.gen_range(min_view..=max_view)
        };
        let receivers: Vec<P> = candidates
            .iter()
            .filter(|_| rng.gen_bool(0.5))
            .cloned()
            .collect();
        let seed = rng.gen::<u64>();
        let omit = rng.gen_bool(0.25);
        faults.push(ProcessFault {
            view,
            receivers,
            seed,
            omit,
        });
    }
    faults
}
