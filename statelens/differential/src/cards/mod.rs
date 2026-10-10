//! The hand-written TSS prefixes, one module per card.
//!
//! Each module opens with the header of SPEC 18.7 and exposes
//! `pub async fn prefix<P, M>(..) -> Prefix<P>`, which drives the card's
//! History on the scenario harness with one stage per event, a witness per
//! stage from exact observables or constructions, `En` read freshly inside
//! `Stages::handoff`, and no fabrication beyond the scenario's own. Every
//! reply of the system under test is raced against [`STAGE_DEADLINE`] of
//! simulated time, and a replica event is polled between mailbox barriers.
//!
//! A prefix returns the handoff description, as the scenario does, and whether
//! every stage held; the test calls `finish` only then, and never in the
//! control run.

pub mod ts9001;
pub mod ts9002;
pub mod ts9003;
pub mod ts9004;
pub mod ts9005;
pub mod ts9006;
pub mod ts9007;

use commonware_consensus::{
    Heightable as _,
    types::{Epoch, Height, Round, View},
};
use commonware_consensus_fuzz_core::simplex::Simplex;
use commonware_consensus_fuzz_marshal::{
    marshal::end_to_end::twins::{B, stack::TwinsMarshal},
    scenarios::{
        environment::{AttackAnchor, Node, ScenarioHandoff},
        harness::{App, FuzzScenarioStandardHarness},
    },
};
use commonware_cryptography::Digestible as _;
use commonware_macros::select;
use commonware_runtime::{Clock as _, deterministic};
use std::{future::Future, time::Duration};

/// The simulated-time deadline of one stage (the harness's `WRAPPER_WAIT`).
pub const STAGE_DEADLINE: Duration = Duration::from_secs(5);

/// A deliberate deviation of a prefix, for the negative controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Twist {
    /// The canonical prefix (or the control run, which withholds the header's
    /// event).
    None,
    /// Skips the action of event `k` outside the control run.
    Withhold(u32),
    /// TS-9005: performs E3's arming before E1's verify while recording the
    /// stages in card order.
    SwapArmAndVerify,
    /// TS-9007: reports the first finalization to `Node::C` instead of B.
    MisrouteFirstFinalization,
    /// Builds `En`'s witness before the `Stages::handoff` call.
    StaleHandoffRead,
    /// TS-9001: also reports the view-1 notarization to `Node::C`, which has
    /// no block for it.
    NotarizationToC,
    /// TS-9002: arms a garbage delivery on B that no fetch of the prefix
    /// consumes.
    ArmGarbage,
}

/// What a prefix leaves: the handoff description, when the prefix can give
/// one, and whether every stage held.
pub struct Prefix<P: Simplex> {
    pub handoff: Option<ScenarioHandoff<P>>,
    pub reached: bool,
}

/// `Round` of `view` in epoch 0.
pub fn round(view: u64) -> Round {
    Round::new(Epoch::zero(), View::new(view))
}

/// The first live view above `block` (`scenarios::attack_above`).
pub fn attack_above<P: Simplex>(block: &B<P>) -> AttackAnchor {
    AttackAnchor {
        height: Height::new(block.height().get() + 1),
        view: View::new(block.context.round.view().get() + 1),
        digest: block.digest(),
    }
}

/// Races a reply of the system under test against the stage deadline.
pub async fn race<T>(
    context: &deterministic::Context,
    reply: impl Future<Output = T>,
) -> Option<T> {
    select! {
        value = reply => Some(value),
        _ = context.sleep(STAGE_DEADLINE) => None,
    }
}

/// Polls `check` between mailbox barriers on `node` until it returns `Some`,
/// or the stage deadline passes.
pub async fn poll<P, M, T>(
    context: &deterministic::Context,
    harness: &FuzzScenarioStandardHarness<P, M>,
    node: Node,
    mut check: impl FnMut() -> Option<T>,
) -> Option<T>
where
    P: Simplex,
    M: TwinsMarshal<P, App<P>>,
{
    let deadline = context.sleep(STAGE_DEADLINE);
    futures::pin_mut!(deadline);
    loop {
        if let Some(found) = check() {
            return Some(found);
        }
        select! {
            _ = harness.barrier(node) => {},
            _ = &mut deadline => return None,
        }
    }
}

/// The text of a `bool` verdict.
pub fn verdict(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}
