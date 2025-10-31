use commonware_cryptography::bls12381::{
    dkg2::Output,
    primitives::{group::Share, variant::Variant},
};

/// An update from the DKG Actor.
pub enum Update<V: Variant, P> {
    /// DKG at this epoch has failed.
    Failure { epoch: u64 },
    /// DKG at this epoch has succeeded.
    Success {
        epoch: u64,
        /// The public output, shared by all parties.
        output: Output<V, P>,
        /// We will be missing a share if we were not a player.
        share: Option<Share>,
    },
}

/// What to do post update.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PostUpdate {
    Continue,
    Stop,
}

/// A callback to process updates produced by the actor.
///
/// The return value should be true if
///
/// This can be used to, e.g.
/// - save the result to a file,
/// - send the result across a channel.
pub type UpdateCallBack<V, P> = Box<dyn FnMut(Update<V, P>) -> PostUpdate + Send>;
