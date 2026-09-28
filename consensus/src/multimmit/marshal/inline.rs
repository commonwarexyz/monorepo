//! A consensus [`Application`] as a Multimmit producer.

use super::{Error, Mailbox};
use crate::{
    Application, Automaton, Heightable as _,
    ancestry::{AncestorStream, BlockProvider},
    multimmit::types::{BlockRef, Body, Context, TransactionBlock},
    types::Height,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_runtime::{
    Clock, Metrics, Spawner,
    telemetry::metrics::{
        MetricsExt as _,
        histogram::{Buckets, Timed},
    },
};
use commonware_utils::channel::{fallible::OneshotExt as _, oneshot};
use rand_core::Rng;
use std::{sync::Arc, time::Duration};
use tracing::debug;

/// Delay before retrying a parent fetch that marshal was too busy to accept.
const BUSY_RETRY: Duration = Duration::from_millis(10);

/// The producer chains marshal holds, as a [`BlockProvider`].
struct ProducerChains<C, H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    clock: Arc<C>,
    marshal: Mailbox<H, V, B>,
}

impl<C, H, V, B> Clone for ProducerChains<C, H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            marshal: self.marshal.clone(),
        }
    }
}

impl<C, H, V, B> ProducerChains<C, H, V, B>
where
    C: Clock,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Fetches `reference` locally or from peers, retrying while marshal is busy.
    ///
    /// Returns `None` once marshal can no longer serve it.
    async fn fetch(&self, reference: BlockRef<H::Digest>) -> Option<Arc<TransactionBlock<H, B>>> {
        loop {
            match self.marshal.fetch_block(reference).await {
                Ok(block) => return Some(block),
                Err(Error::Busy) => self.clock.sleep(BUSY_RETRY).await,
                Err(error) => {
                    debug!(%error, ?reference, "cannot fetch producer block");
                    return None;
                }
            }
        }
    }
}

impl<C, H, V, B> BlockProvider for ProducerChains<C, H, V, B>
where
    C: Clock,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    type Block = TransactionBlock<H, B>;

    fn subscribe_parent(
        &self,
        block: &Self::Block,
    ) -> impl Future<Output = Option<Arc<Self::Block>>> + Send + 'static {
        let chains = self.clone();
        // A chain's first block builds on its genesis tip, which is not a block.
        let parent = (block.height() > Height::new(1)).then(|| block.header().parent_ref());
        async move { chains.fetch(parent?).await }
    }
}

/// Runs a consensus [`Application`] as a Multimmit producer.
///
/// Multimmit orders producer blocks and leaves executing them to whatever consumes marshal's
/// finalized stream. A producer's `verify` therefore only admits a block: marshal must hold its
/// body durably, and the application's checks must pass. Those checks must not depend on state
/// that the block's position in the finalized order determines, because verification happens
/// before that order exists.
///
/// The application's `propose` and `verify` run in spawned tasks:
///
/// - `propose` builds on the producer's own chain, checks that the block occupies the position
///   consensus asked for, stages it with marshal, and answers with its body digest.
/// - `verify` waits for marshal to hold the block durably, then runs the application's checks.
///
/// Broadcasting staged blocks is marshal's [`Relay`](super::Relay), which the engine takes
/// separately.
///
/// # Ancestry
///
/// Both calls see the block's producer chain, newest first: `propose` from the parent of the block
/// it builds, and `verify` from the block itself. A chain's first block builds on its genesis tip,
/// which is not a block, so the ancestry ends there at the latest. It also ends early at a block
/// marshal no longer holds: marshal prunes a chain's blocks at or below the height the engine
/// releases (see [`Activity::CertificateRecorded`](crate::multimmit::types::Activity)), so an
/// application should read only the recent ancestry it needs.
pub struct Inline<E, H, V, B, A>
where
    E: Rng + Spawner + Metrics + Clock,
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    context: Arc<E>,
    application: A,
    marshal: Mailbox<H, V, B>,
    build_duration: Timed,
    ancestor_fetch_duration: Timed,
}

impl<E, H, V, B, A> Clone for Inline<E, H, V, B, A>
where
    E: Rng + Spawner + Metrics + Clock,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    A: Clone,
{
    fn clone(&self) -> Self {
        Self {
            context: Arc::clone(&self.context),
            application: self.application.clone(),
            marshal: self.marshal.clone(),
            build_duration: self.build_duration.clone(),
            ancestor_fetch_duration: self.ancestor_fetch_duration.clone(),
        }
    }
}

impl<E, H, V, B, A> Inline<E, H, V, B, A>
where
    E: Rng + Spawner + Metrics + Clock,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    A: Application<E, Block = TransactionBlock<H, B>, Context = Context<H::Digest>, Input = ()>,
{
    /// Creates a producer that builds and admits blocks with `application`, staging them with
    /// `marshal`.
    ///
    /// Registers the `build_duration` and `ancestor_fetch_duration` histograms.
    pub fn new(context: E, application: A, marshal: Mailbox<H, V, B>) -> Self {
        let build_duration = Timed::new(context.histogram(
            "build_duration",
            "Histogram of time taken for the application to build a new block, in seconds",
            Buckets::LOCAL,
        ));
        let ancestor_fetch_duration = Timed::new(context.histogram(
            "ancestor_fetch_duration",
            "Histogram of time taken to fetch a block via the ancestry stream, in seconds",
            Buckets::LOCAL,
        ));
        Self {
            context: Arc::new(context),
            application,
            marshal,
            build_duration,
            ancestor_fetch_duration,
        }
    }

    /// Returns the producer chain from `initial` back toward its genesis tip.
    fn ancestry(
        &self,
        clock: E,
        initial: Option<Arc<TransactionBlock<H, B>>>,
    ) -> AncestorStream<ProducerChains<E, H, V, B>, E> {
        let clock = Arc::new(clock);
        let chains = ProducerChains {
            clock: Arc::clone(&clock),
            marshal: self.marshal.clone(),
        };
        AncestorStream::new(clock, chains, initial, self.ancestor_fetch_duration.clone())
    }
}

impl<E, H, V, B, A> Automaton for Inline<E, H, V, B, A>
where
    E: Rng + Spawner + Metrics + Clock,
    H: Hasher,
    V: Variant,
    B: Body<H>,
    A: Application<E, Block = TransactionBlock<H, B>, Context = Context<H::Digest>, Input = ()>,
{
    type Context = Context<H::Digest>;
    type Digest = H::Digest;

    /// Builds a block at `context` and answers with its body digest once marshal stages it.
    ///
    /// Answers nothing if the application declines, builds a block for another position, or
    /// marshal stops before staging it. Staging is retried while marshal is busy.
    #[allow(clippy::async_yields_async)]
    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (mut response, receiver) = oneshot::channel();
        // A chain's first block builds on its genesis tip, which is not a block.
        let parent = context
            .height()
            .previous()
            .filter(|height| !height.is_zero())
            .map(|height| BlockRef::new(context.chain(), height, context.parent()));
        let producer = self.clone();
        self.context
            .child("propose")
            .spawn(move |runtime| async move {
                let chains = ProducerChains {
                    clock: Arc::new(runtime.child("parent")),
                    marshal: producer.marshal.clone(),
                };
                let parent = match parent {
                    Some(parent) => select! {
                        _ = response.closed() => return,
                        parent = chains.fetch(parent) => match parent {
                            Some(parent) => Some(parent),
                            None => return,
                        },
                    },
                    None => None,
                };
                let ancestry = producer.ancestry(runtime.child("ancestry"), parent);
                let mut application = producer.application.clone();
                let timer = producer.build_duration.timer(&runtime);
                let build = application.propose((runtime.child("build"), context), ancestry, ());
                let block = select! {
                    _ = response.closed() => return,
                    block = build => block,
                };
                let Some(block) = block else {
                    debug!(
                        chain = context.chain().get(),
                        height = context.height().get(),
                        "application declined to build"
                    );
                    return;
                };
                timer.observe(&runtime);
                if block.header().context() != context {
                    debug!(
                        chain = context.chain().get(),
                        height = context.height().get(),
                        "application built a block for another position"
                    );
                    return;
                }
                let body = block.header().body_digest();
                let block = Arc::new(block);
                // Marshal rejects staging under pressure, and a dropped build would be lost.
                loop {
                    let stage = producer.marshal.stage_block(Arc::clone(&block));
                    let staged = select! {
                        _ = response.closed() => return,
                        staged = stage => staged,
                    };
                    match staged {
                        Ok(_) => break,
                        Err(Error::Busy) => select! {
                            _ = response.closed() => return,
                            _ = runtime.sleep(BUSY_RETRY) => {},
                        },
                        Err(error) => {
                            debug!(%error, "cannot stage proposed block");
                            return;
                        }
                    }
                }
                response.send_lossy(body);
            });
        receiver
    }

    /// Answers whether the application admits the block at `context` with body `payload`, once
    /// marshal holds it durably.
    ///
    /// Answers nothing if marshal stops before it holds the block.
    #[allow(clippy::async_yields_async)]
    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (mut response, receiver) = oneshot::channel();
        let reference = context.header(payload).block_ref::<H>();
        let producer = self.clone();
        self.context
            .child("verify")
            .spawn(move |runtime| async move {
                // Marshal returns the block with exactly this reference, whose digest
                // authenticates the header, so the block occupies `context`.
                // Marshal rejects subscriptions under pressure, and a dropped verification would
                // be lost.
                let block = loop {
                    let subscribe = producer.marshal.subscribe_block(reference);
                    let block = select! {
                        _ = response.closed() => return,
                        block = subscribe => block,
                    };
                    match block {
                        Ok(block) => break block,
                        Err(Error::Busy) => select! {
                            _ = response.closed() => return,
                            _ = runtime.sleep(BUSY_RETRY) => {},
                        },
                        Err(error) => {
                            debug!(%error, ?reference, "cannot hold block to verify");
                            return;
                        }
                    }
                };
                let ancestry = producer.ancestry(runtime.child("ancestry"), Some(block));
                let mut application = producer.application.clone();
                let check = application.verify((runtime.child("verify"), context), ancestry);
                let admitted = select! {
                    _ = response.closed() => return,
                    admitted = check => admitted,
                };
                response.send_lossy(admitted);
            });
        receiver
    }
}
