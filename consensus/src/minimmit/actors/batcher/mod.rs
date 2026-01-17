//! Batcher actor for Minimmit consensus.
//!
//! The batcher handles message batching and verification, forwarding verified
//! messages to the voter.
//!
//! Unlike Simplex, Minimmit has only two vote types (Notarize, Nullify) and
//! three certificate types (MNotarization, Nullification, Finalization).
//! Finalization uses the same notarize votes as MNotarization, but with a
//! higher quorum threshold (L-quorum vs M-quorum).

mod actor;
mod ingress;
mod round;
mod verifier;

use crate::{
    minimmit::types::Activity,
    types::{Epoch, ViewDelta},
    Reporter,
};
pub use actor::Actor;
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_p2p::Blocker;
pub use ingress::Mailbox;
use round::Round;
use verifier::Verifier;

/// Configuration for the batcher actor.
pub struct Config<S, B, D, F, T>
where
    S: Scheme,
    B: Blocker,
    D: Digest,
    F: Reporter<Activity = Activity<S, D>>,
{
    pub scheme: S,
    pub blocker: B,
    pub reporter: F,
    pub strategy: T,
    pub epoch: Epoch,
    pub mailbox_size: usize,
    pub activity_timeout: ViewDelta,
    pub skip_timeout: ViewDelta,
}
