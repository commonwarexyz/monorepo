//! Consensus-relay plumbing shared by the marshal application wrappers.

use crate::{
    marshal::{
        application::gates::{Gates, Staged},
        core::{Mailbox, Variant},
    },
    simplex::Plan,
};
use commonware_actor::Feedback;
use commonware_cryptography::certificate::Scheme;
use commonware_p2p::Recipients;
use std::sync::Arc;
use tracing::debug;

/// Relays a consensus broadcast [`Plan`] through marshal for a proposal staged in `gates`.
///
/// A prepare plan sends the staged candidate to all peers and keeps it staged
/// without storing it. A propose plan locks the staged proposal in: it sends
/// the proposal to all peers unless a prepare plan already did, and persists
/// it either way, delivering the durable-sync handle through the staged ack. A
/// forward plan re-sends a stored block to the requested recipients. A propose
/// plan whose staged proposal was already consumed falls back to a best-effort
/// forward of the persisted block.
pub(crate) fn broadcast<S, V, B>(
    gates: &Gates<V::Commitment, B>,
    marshal: &Mailbox<S, V>,
    commitment: V::Commitment,
    plan: Plan<S::PublicKey>,
) -> Feedback
where
    S: Scheme,
    V: Variant<Block = Arc<B>>,
{
    match plan {
        Plan::Prepare { round } => {
            let Some(block) = gates.send_staged(round, commitment) else {
                debug!(%round, %commitment, "no staged candidate to relay early");
                return Feedback::Ok;
            };
            marshal.prepared(round, block, Recipients::All)
        }
        Plan::Propose { round } => {
            let Some(Staged { block, ack, sent }) = gates.take_staged(round, commitment) else {
                debug!(%round, %commitment, "no staged proposal to relay, attempting forwarding");
                return marshal.forward(round, commitment, Recipients::All);
            };
            if sent {
                marshal.verified_deferred(round, block, ack);
                return Feedback::Ok;
            }
            marshal.proposed(round, block, Recipients::All, ack)
        }
        Plan::Forward { round, recipients } => marshal.forward(round, commitment, recipients),
    }
}
