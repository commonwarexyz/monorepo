use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::{
    dkg::Output,
    primitives::{group::Share, variant::Variant},
};
use std::{future::Future, pin::Pin};

/// An update from the DKG Actor.
#[allow(dead_code)]
pub enum Update<V: Variant, P> {
    /// DKG at this epoch has failed.
    Failure { epoch: Epoch },
    /// DKG at this epoch has succeeded.
    Success {
        epoch: Epoch,
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
pub trait UpdateCallBack<V: Variant, P>: Send {
    fn on_update(
        &mut self,
        update: Update<V, P>,
    ) -> Pin<Box<dyn Future<Output = PostUpdate> + Send>>;
}

/// An implementor of [UpdateCallBack] which always continues.
pub struct ContinueOnUpdate;

impl ContinueOnUpdate {
    pub fn boxed() -> Box<Self> {
        Box::new(Self)
    }
}

impl<V: Variant, P> UpdateCallBack<V, P> for ContinueOnUpdate {
    fn on_update(
        &mut self,
        _update: Update<V, P>,
    ) -> Pin<Box<dyn Future<Output = PostUpdate> + Send>> {
        Box::pin(async { PostUpdate::Continue })
    }
}
