//! What the probe drivers share: the wrappers through which a driver watches
//! a real actor at its public P2P boundaries, the application a marshal with
//! no application above it is given, and the seeding of a marshal with a
//! fabricated finalized history.
//!
//! A probe driver runs real actors over the simulated network and judges them
//! only by what crosses their boundaries. The wrappers report each crossing to
//! a [`Witness`] from inside the actor's own task, so the witness learns of
//! them in the order the actor made them.

use super::{PublicKey, runner::unattributed};
use commonware_actor::Feedback;
use commonware_consensus::{
    Block, Reporter,
    marshal::{
        Update,
        core::{Mailbox as MarshalMailbox, Variant},
    },
    simplex::{
        scheme::Scheme,
        types::{Activity, Finalization, Finalize, Proposal},
    },
    types::Height,
};
use commonware_cryptography::Digest;
use commonware_p2p::{
    BlockedSubscription, Blocker, Message,
    simulated::{Control, Error, Receiver},
};
use commonware_parallel::Sequential;
use commonware_runtime::deterministic;
use commonware_utils::{Acknowledgement as _, non_empty};
use std::{fmt, marker::PhantomData, num::NonZeroUsize};

/// What a driver is told of an observed actor, as it happens.
pub(crate) trait Witness: Clone + Send + Sync + 'static {
    /// The actor took `bytes`, sent by `peer`, from its receiver.
    fn delivered(&self, peer: &PublicKey, bytes: &[u8]);

    /// The actor blocked `peer`.
    fn blocked(&self, peer: &PublicKey);
}

/// An actor's receiver. With a witness it reports every message at the moment
/// the actor takes it; without one it reports nothing.
pub(crate) struct Observed<W> {
    inner: Receiver<PublicKey>,
    witness: Option<W>,
}

impl<W> Observed<W> {
    /// Wrap `inner`, reporting to `witness` if there is one.
    pub(crate) const fn new(inner: Receiver<PublicKey>, witness: Option<W>) -> Self {
        Self { inner, witness }
    }
}

impl<W> fmt::Debug for Observed<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observed")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<W: Witness> commonware_p2p::Receiver for Observed<W> {
    type Error = Error;
    type PublicKey = PublicKey;

    fn capacity(&self) -> NonZeroUsize {
        self.inner.capacity()
    }

    async fn recv(&mut self) -> Result<Message<PublicKey>, Self::Error> {
        let (peer, bytes) = self.inner.recv().await?;
        if let Some(witness) = &self.witness {
            // The witness is the driver's code, not the actor's.
            unattributed(|| witness.delivered(&peer, bytes.as_ref()));
        }
        Ok((peer, bytes))
    }
}

/// An actor's blocker: reports every block to the witness, then places it on
/// the simulated network.
#[derive(Clone)]
pub(crate) struct ObservedBlocker<W> {
    inner: Control<PublicKey, deterministic::Context>,
    witness: W,
}

impl<W> ObservedBlocker<W> {
    /// Wrap `inner`, reporting to `witness`.
    pub(crate) const fn new(inner: Control<PublicKey, deterministic::Context>, witness: W) -> Self {
        Self { inner, witness }
    }
}

impl<W: Witness> Blocker for ObservedBlocker<W> {
    type PublicKey = PublicKey;

    // The actor has already logged the block it places; this only forwards it.
    #[allow(clippy::disallowed_methods)]
    fn block(&mut self, peer: PublicKey) -> Feedback {
        // The witness is the driver's code, not the actor's.
        unattributed(|| self.witness.blocked(&peer));
        self.inner.block(peer)
    }

    fn blocked(&mut self) -> BlockedSubscription<PublicKey> {
        self.inner.blocked()
    }
}

/// Acknowledges every block marshal delivers, for a marshal that runs no
/// application.
pub(crate) struct Acking<B>(PhantomData<fn() -> B>);

impl<B> Default for Acking<B> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<B> Clone for Acking<B> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<B: Block> Reporter for Acking<B> {
    type Activity = Update<B>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // The application is the driver's code, not marshal's.
        unattributed(|| {
            if let Update::Block(_, ack) = activity {
                ack.acknowledge();
            }
        });
        Feedback::Ok
    }
}

/// A strict prefix of `bytes`, possibly empty: `keep` modulo the length.
pub(crate) fn prefix(bytes: &[u8], keep: u8) -> Vec<u8> {
    let keep = if bytes.is_empty() {
        0
    } else {
        usize::from(keep) % bytes.len()
    };
    bytes[..keep].to_vec()
}

/// The finalization of `proposal`, certified once by the whole of `schemes`.
pub(crate) fn certify<S, D>(schemes: &[S], proposal: Proposal<D>) -> Finalization<S, D>
where
    S: Scheme<D>,
    D: Digest,
{
    let finalizes: Vec<_> = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalize"))
        .collect();
    Finalization::from_finalizes(&schemes[0], non_empty![@finalizes.iter()], &Sequential)
        .expect("assemble finalization")
}

/// Inject the finalized `block` at `height` into `marshal`, so it stores and
/// serves the block and its `finalization`.
pub(crate) async fn inject<S, V>(
    marshal: &MarshalMailbox<S, V>,
    height: Height,
    block: V::Block,
    finalization: Finalization<S, V::Commitment>,
) where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    let round = finalization.round();
    assert!(
        marshal.verified(round, block).await,
        "marshal must persist the seeded block"
    );
    let _ = marshal.clone().report(Activity::Finalization(finalization));
    assert!(
        marshal.get_finalization(height).await.is_some(),
        "marshal must store the seeded finalization"
    );
}
