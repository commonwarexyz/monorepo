use crate::dkg::{reshare::Mailbox, types::Payload, ReshareBlock};
use commonware_consensus::{
    marshal::ancestry::{self, Ancestry},
    types::{EpochPhase, Epocher as _, FixedEpocher, Height},
    Application as ConsensusApplication, CertifiableBlock,
};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Signer};
use commonware_runtime::{Clock, Metrics, Spawner};
use futures::StreamExt as _;
use rand::Rng;
use std::num::NonZeroU64;

/// Per-proposal input handed to an application wrapped by [`Application`].
///
/// Carries the wrapper's parent input alongside the reshare `payload` selected
/// and fetched for the block being proposed. The wrapped application attaches
/// `payload` to the block it builds and uses `parent` for its own purposes.
pub struct Input<Parent, V: Variant, C: Signer> {
    /// Input forwarded from the application wrapping the reshare wrapper.
    pub parent: Parent,

    /// The reshare payload selected for this proposal, if any.
    pub payload: Option<Payload<V, C>>,
}

/// An [`Application`](commonware_consensus::Application) wrapper that enforces the
/// reshare block-validity contract and drives the reshare payload for proposals.
///
/// The reshare protocol requires the application to reject any final block whose
/// payload is not the [`EpochInfo`](crate::dkg::types::EpochInfo) the reshare
/// actor independently reconstructs, and to reject stray payloads carried by
/// non-final blocks in the early dealing window. Wiring these checks by hand is
/// error prone: a verifier that skips them can vote for a malformed final block,
/// which later panics the reshare actor on every honest node once the block
/// finalizes. This wrapper performs those checks in
/// [`verify`](ConsensusApplication::verify).
///
/// For proposals, the wrapper selects and fetches the payload for the block being
/// built (a dealer log from the midpoint onward, the epoch info on the final
/// block) and hands it to the inner application through [`Input`], so the
/// inner application neither talks to the reshare mailbox nor tracks epoch
/// boundaries. It only attaches the handed-over payload to the block it builds,
/// because the wrapper cannot build the application's block type itself.
///
/// The wrapper is a plain [`Application`](commonware_consensus::Application), so
/// it composes with any consensus application, including one adapted through
/// [`stateful`](crate::stateful). It forwards its own parent input to the inner
/// application as [`Input::parent`], so nesting under another
/// input-providing application still works.
pub struct Application<A, B, V, C>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
{
    inner: A,
    reshare: Mailbox<B, V, C>,
    epocher: FixedEpocher,
}

impl<A, B, V, C> Application<A, B, V, C>
where
    B: ReshareBlock,
    V: Variant,
    C: Signer,
{
    /// Wraps `inner`, using `reshare` to select final-block epoch info and dealer
    /// logs and `blocks_per_epoch` to locate epoch boundaries and phases.
    pub const fn new(inner: A, reshare: Mailbox<B, V, C>, blocks_per_epoch: NonZeroU64) -> Self {
        Self {
            inner,
            reshare,
            epocher: FixedEpocher::new(blocks_per_epoch),
        }
    }

    fn final_block(&self, height: Height) -> bool {
        self.epocher
            .containing(height)
            .is_some_and(|info| info.last() == height)
    }

    fn phase(&self, height: Height) -> Option<EpochPhase> {
        self.epocher.containing(height).map(|info| info.phase())
    }
}

impl<A, B, V, C> Clone for Application<A, B, V, C>
where
    A: Clone,
    B: ReshareBlock,
    V: Variant,
    C: Signer,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            reshare: self.reshare.clone(),
            epocher: self.epocher.clone(),
        }
    }
}

impl<A, E, B, V, C, I> ConsensusApplication<E> for Application<A, B, V, C>
where
    E: Rng + Spawner + Metrics + Clock,
    A: ConsensusApplication<E, Block = B, Input = Input<I, V, C>>,
    A::Context: Send,
    B: ReshareBlock<Variant = V, Signer = C> + CertifiableBlock + Clone,
    V: Variant,
    C: Signer,
    I: Send,
{
    type SigningScheme = A::SigningScheme;
    type Context = A::Context;
    type Block = A::Block;
    type Input = I;

    async fn propose(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Self::Block> {
        // Select and fetch the payload for the block being built, then hand it to
        // the inner application alongside its own input.
        let parent = ancestry.peek()?.clone();
        let height = parent.height().next();
        let payload = if self.final_block(height) {
            let payload = self.reshare.epoch_info(ancestry).await;
            return self
                .inner
                .propose(
                    context,
                    ancestry::from_iter([parent]),
                    Input {
                        parent: input,
                        payload,
                    },
                )
                .await;
        } else if matches!(
            self.phase(height),
            Some(EpochPhase::Midpoint | EpochPhase::Late)
        ) {
            self.reshare.next_log(height).await
        } else {
            None
        };
        self.inner
            .propose(
                context,
                ancestry,
                Input {
                    parent: input,
                    payload,
                },
            )
            .await
    }

    async fn verify(
        &mut self,
        context: (E, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        // Buffer the ancestry so it can drive both the reshare payload check and
        // the inner verification. `epoch_info` consumes the stream, so it must be
        // rebuilt; the front of the buffer is the block under verification.
        let blocks: Vec<B> = ancestry.collect().await;
        let Some(tip) = blocks.first().cloned() else {
            return self
                .inner
                .verify(context, ancestry::from_iter(blocks))
                .await;
        };
        let height = tip.height();
        if self.final_block(height) {
            // The final block must carry the epoch info the actor reconstructs.
            let derived = self
                .reshare
                .epoch_info(ancestry::from_iter(blocks.clone()))
                .await;
            if derived != tip.payload() {
                return false;
            }
        } else if matches!(self.phase(height), Some(EpochPhase::Early)) && tip.payload().is_some() {
            // Dealer logs are only posted from the midpoint onward, so an early
            // block must not carry a reshare payload.
            return false;
        }
        self.inner
            .verify(context, ancestry::from_iter(blocks))
            .await
    }
}
