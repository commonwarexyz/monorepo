//! Consensus engine orchestration for threshold reshare epoch transitions.

use crate::dkg::{
    anchor,
    fence::Gate,
    orchestrator::{mailbox::Message, Mailbox},
    types::{EpochInfo, Payload},
    ReshareBlock,
};
use commonware_actor::mailbox;
use commonware_consensus::{
    marshal::core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    simplex::{
        self,
        elector::Config as Elector,
        scheme,
        types::{Context, Finalization},
        Floor, ForwardingPolicy, Plan,
    },
    types::{Epoch, Epocher, FixedEpocher, Height, ViewDelta},
    CertifiableAutomaton, Heightable, Relay,
};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant as BlsVariant,
    certificate::{Provider, Verifier},
    Digest, PublicKey, Signer,
};
use commonware_macros::select_loop;
use commonware_p2p::{
    utils::mux::{Builder, MuxHandle, Muxer},
    Blocker, Channel, Manager, Message as P2pMessage, Receiver, Sender, TrackedPeers,
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    buffer::paged::CacheRef,
    spawn_cell,
    telemetry::metrics::{Gauge, GaugeExt, MetricsExt as _},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
};
use commonware_utils::{acknowledgement::Exact, channel::mpsc, vec::NonEmptyVec, Acknowledgement};
use rand_core::CryptoRngCore;
use std::{
    marker::PhantomData,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::{debug, info};

struct Channels<C, S, R>
where
    C: Verifier,
    S: Sender<PublicKey = C::PublicKey>,
    R: Receiver<PublicKey = C::PublicKey>,
{
    vote: MuxHandle<S, R>,
    vote_backup: mpsc::Receiver<(Channel, P2pMessage<C::PublicKey>)>,
    certificate: MuxHandle<S, R>,
    resolver: MuxHandle<S, R>,
}

struct ActiveEpoch {
    epoch: Epoch,
    handle: Handle<()>,
}

impl Drop for ActiveEpoch {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Public boundary material used for one-time state-sync startup.
pub struct StateSync<S, D, V>
where
    S: scheme::Scheme<D>,
    D: Digest,
    V: BlsVariant,
{
    /// Public boundary material discovered by `dkg::anchor`.
    pub artifact: anchor::Artifact<S, D, V>,

    /// Finalized floor selected by `stateful::probe`.
    pub floor: Finalization<S, D>,
}

struct ResolvedStart<S, D, V, P>
where
    S: scheme::Scheme<D, PublicKey = P>,
    D: Digest,
    V: BlsVariant,
    P: PublicKey,
{
    epoch: Epoch,
    floor: Floor<S, D>,
    info: EpochInfo<V, P>,
}

/// Simplex configuration applied to each epoch engine.
#[derive(Clone)]
pub struct SimplexConfig<L> {
    /// Leader election configuration.
    pub elector: L,

    /// Maximum number of messages to buffer on channels inside each consensus engine.
    pub mailbox_size: NonZeroUsize,

    /// Number of bytes to buffer when replaying consensus state during startup.
    pub replay_buffer: NonZeroUsize,

    /// Number of bytes to buffer when writing consensus journal blobs.
    pub write_buffer: NonZeroUsize,

    /// Page size used by the consensus journal page cache.
    pub page_cache_page_size: NonZeroU16,

    /// Number of pages retained by the consensus journal page cache.
    pub page_cache_pages: NonZeroUsize,

    /// Time to wait for a leader proposal in a view.
    pub leader_timeout: Duration,

    /// Time to wait for certification progress before attempting to skip a view.
    pub certification_timeout: Duration,

    /// Time to wait before retrying a nullify broadcast while stuck in a view.
    pub timeout_retry: Duration,

    /// Time to wait for a peer to respond to a resolver request.
    pub fetch_timeout: Duration,

    /// Number of concurrent resolver requests.
    pub fetch_concurrent: NonZeroUsize,

    /// Number of views behind the finalized tip to retain validator activity.
    pub activity_timeout: ViewDelta,

    /// Recent inactive leader window that triggers immediate nullification.
    pub skip_timeout: ViewDelta,

    /// Policy for proactively forwarding certified blocks.
    pub forwarding: ForwardingPolicy,
}

/// Configuration for the [`Actor`].
pub struct Config<B, M, P, MV, DV, A, L, T>
where
    P: Provider<Scope = Epoch>,
    P::Scheme: scheme::Scheme<MV::Commitment>,
    MV: MarshalVariant,
    DV: BlsVariant,
{
    /// Network blocker shared with each epoch consensus engine.
    pub oracle: B,

    /// P2P manager used to track the active consensus peer set.
    pub manager: M,

    /// Provider of epoch-scoped consensus signing schemes.
    pub provider: P,

    /// Marshal mailbox used to report consensus output and read finalized blocks.
    pub marshal: MarshalMailbox<P::Scheme, MV>,

    /// Application automaton and relay used by each epoch consensus engine.
    pub application: A,

    /// Strategy for parallel verification and signing work.
    pub strategy: T,

    /// Simplex settings applied to every epoch engine.
    pub simplex: SimplexConfig<L>,

    /// Gate for waiting for the signature scheme to be configured prior to
    /// entering an epoch.
    pub gate: Gate,

    /// Public boundary material used only when entering through state sync.
    pub state_sync: Option<StateSync<P::Scheme, MV::Commitment, DV>>,

    /// Number of blocks in each epoch.
    pub blocks_per_epoch: NonZeroU64,

    /// Maximum number of messages to buffer in each network muxer.
    pub muxer_size: usize,

    /// Maximum number of finalized-block reports to buffer.
    pub mailbox_size: NonZeroUsize,

    /// Partition prefix used for per-epoch consensus persistence.
    pub partition_prefix: String,
}

/// Consensus engine orchestrator.
pub struct Actor<E, B, M, P, MV, DV, C, A, L, T, ACK = Exact>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + Storage + Network,
    B: Blocker<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    M: Manager<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    P: Provider<Scope = Epoch>,
    P::Scheme: scheme::Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<Variant = DV, Signer = C>,
    DV: BlsVariant,
    C: Signer<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    A: CertifiableAutomaton<
            Context = Context<MV::Commitment, <P::Scheme as Verifier>::PublicKey>,
            Digest = MV::Commitment,
        > + Relay<
            Digest = MV::Commitment,
            PublicKey = <P::Scheme as Verifier>::PublicKey,
            Plan = Plan<<P::Scheme as Verifier>::PublicKey>,
        >,
    L: Elector<P::Scheme>,
    T: Strategy,
    ACK: Acknowledgement,
{
    context: ContextCell<E>,
    mailbox: mailbox::Receiver<Message<MV::ApplicationBlock, ACK>>,
    oracle: B,
    manager: M,
    provider: P,
    marshal: MarshalMailbox<P::Scheme, MV>,
    application: A,
    strategy: T,
    simplex: SimplexConfig<L>,
    gate: Gate,
    state_sync: Option<StateSync<P::Scheme, MV::Commitment, DV>>,
    blocks_per_epoch: NonZeroU64,
    muxer_size: usize,
    partition_prefix: String,
    page_cache_ref: CacheRef,
    latest_epoch: Gauge,
    _payload: PhantomData<(DV, C)>,
}

impl<E, B, M, P, MV, DV, C, A, L, T, ACK> Actor<E, B, M, P, MV, DV, C, A, L, T, ACK>
where
    E: BufferPooler + Spawner + Metrics + CryptoRngCore + Clock + Storage + Network,
    B: Blocker<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    M: Manager<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    P: Provider<Scope = Epoch>,
    P::Scheme: scheme::Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock<Variant = DV, Signer = C>,
    DV: BlsVariant,
    C: Signer<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    A: CertifiableAutomaton<
            Context = Context<MV::Commitment, <P::Scheme as Verifier>::PublicKey>,
            Digest = MV::Commitment,
        > + Relay<
            Digest = MV::Commitment,
            PublicKey = <P::Scheme as Verifier>::PublicKey,
            Plan = Plan<<P::Scheme as Verifier>::PublicKey>,
        >,
    L: Elector<P::Scheme>,
    T: Strategy,
    ACK: Acknowledgement,
{
    /// Build an orchestrator and the mailbox that receives finalized blocks.
    ///
    /// The returned [`Mailbox`] should be installed as a marshal reporter. The
    /// actor uses those finalized-block reports to advance epochs after it is
    /// spawned with [`Actor::start`].
    pub fn new(
        context: E,
        config: Config<B, M, P, MV, DV, A, L, T>,
    ) -> (Self, Mailbox<MV::ApplicationBlock, ACK>) {
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let page_cache_ref = CacheRef::from_pooler(
            &context,
            config.simplex.page_cache_page_size,
            config.simplex.page_cache_pages,
        );
        let latest_epoch = context.gauge("latest_epoch", "current epoch");

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                oracle: config.oracle,
                manager: config.manager,
                provider: config.provider,
                marshal: config.marshal,
                application: config.application,
                strategy: config.strategy,
                simplex: config.simplex,
                gate: config.gate,
                state_sync: config.state_sync,
                blocks_per_epoch: config.blocks_per_epoch,
                muxer_size: config.muxer_size,
                partition_prefix: config.partition_prefix,
                page_cache_ref,
                latest_epoch,
                _payload: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    /// Spawn the orchestrator with the consensus network channels.
    ///
    /// Vote and resolver channels are multiplexed by epoch inside the actor.
    /// The certificate mux must already be running so other actors can observe
    /// unregistered certificate subchannels before the orchestrator enters an
    /// epoch.
    pub fn start<S, R>(
        mut self,
        votes: (S, R),
        certificates: MuxHandle<S, R>,
        resolver: (S, R),
    ) -> Handle<()>
    where
        S: Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        spawn_cell!(self.context, self.run(votes, certificates, resolver,))
    }

    /// Run the actor event loop.
    ///
    /// The loop owns one active Simplex engine at a time. It listens for
    /// finalized boundary blocks from marshal and for backup vote traffic from
    /// future epochs, which is used only to ask marshal for the missing boundary
    /// finalization.
    async fn run<S, R>(
        mut self,
        (vote_sender, vote_receiver): (S, R),
        certificates: MuxHandle<S, R>,
        (resolver_sender, resolver_receiver): (S, R),
    ) where
        S: Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        let mut channels = self.create_channels(
            (vote_sender, vote_receiver),
            certificates,
            (resolver_sender, resolver_receiver),
        );
        let epocher = FixedEpocher::new(self.blocks_per_epoch);
        let start = self.resolve_start(&epocher).await;
        let mut active = self
            .enter_epoch(
                start.epoch,
                start.floor,
                start.info.participants().tracked_peers(),
                &mut channels,
            )
            .await;

        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping orchestrator");
            },
            Some((their_epoch, (from, _))) = channels.vote_backup.recv() else {
                debug!("vote mux backup channel closed, shutting down orchestrator");
                break;
            } => {
                self.handle_backup_vote(&epocher, active.epoch, their_epoch, from);
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down orchestrator");
                break;
            } => match message {
                Message::Finalized {
                    block,
                    acknowledgement,
                } => {
                    self.handle_finalized(
                        &epocher,
                        &mut active,
                        block,
                        acknowledgement,
                        &mut channels,
                    )
                    .await;
                }
            },
        }
    }

    /// Resolve the first epoch this process should run.
    ///
    /// Normal startup resolves from marshal's local boundary blocks. State-sync
    /// startup is the only exception: the node may know a recent public
    /// boundary from `dkg::anchor` before it has the previous boundary block in
    /// local marshal storage.
    async fn resolve_start(
        &mut self,
        epocher: &FixedEpocher,
    ) -> ResolvedStart<P::Scheme, MV::Commitment, DV, <P::Scheme as Verifier>::PublicKey> {
        if let Some(state_sync) = &self.state_sync {
            return ResolvedStart {
                epoch: state_sync.artifact.epoch,
                floor: Floor::Finalized(state_sync.floor.clone()),
                info: state_sync.artifact.info.clone(),
            };
        }

        let epoch =
            self.marshal
                .get_processed_height()
                .await
                .map_or_else(Epoch::zero, |processed| {
                    let height = processed.next();
                    epocher
                        .containing(height)
                        .expect("epocher must know recovered height")
                        .epoch()
                });
        self.resolve_boundary(epoch, epocher).await
    }

    /// Resolve a locally recovered epoch from marshal's finalized boundary block.
    ///
    /// Ordinary restarts should not re-enter the configured bootstrap epoch if
    /// marshal has already delivered finalized blocks to the application. The
    /// processed height names the next block marshal will deliver; from that
    /// height we derive the active epoch, then read the boundary block that
    /// carried that epoch's public [`EpochInfo`]. That boundary block supplies
    /// both the Simplex floor commitment and the peer set to track for the
    /// recovered epoch.
    ///
    /// This is intentionally not used for state-sync startup: during one-time
    /// state sync, marshal is anchored at a probe-selected finalization while the
    /// previous epoch boundary block is not locally available yet. In that
    /// startup path, the anchor artifact is the trusted source of boundary
    /// epoch info.
    async fn resolve_boundary(
        &mut self,
        epoch: Epoch,
        epocher: &FixedEpocher,
    ) -> ResolvedStart<P::Scheme, MV::Commitment, DV, <P::Scheme as Verifier>::PublicKey> {
        let height = epoch
            .previous()
            .and_then(|epoch| epocher.last(epoch))
            .unwrap_or_else(Height::zero);
        let boundary = self
            .marshal
            .get_block(height)
            .await
            .unwrap_or_else(|| panic!("missing finalized boundary block at height {height}"));
        let commitment = MV::commitment(&boundary);
        let block = MV::into_inner(boundary);
        let Some(Payload::EpochInfo(info)) = block.payload() else {
            panic!("boundary block {height} missing epoch info");
        };
        if info.epoch != epoch {
            panic!(
                "boundary block {height} carries epoch info for {}, expected {epoch}",
                info.epoch
            );
        }

        ResolvedStart {
            epoch,
            floor: Floor::Genesis(commitment),
            info,
        }
    }

    /// Start the consensus channel muxers and return handles used to open
    /// epoch-specific subchannels.
    ///
    /// The vote mux includes a backup receiver so the orchestrator can detect
    /// messages for epochs it has not registered locally.
    fn create_channels<S, R>(
        &self,
        (vote_sender, vote_receiver): (S, R),
        certificate: MuxHandle<S, R>,
        (resolver_sender, resolver_receiver): (S, R),
    ) -> Channels<P::Scheme, S, R>
    where
        S: Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        let (mux, vote, vote_backup) = Muxer::builder(
            self.context.child("vote_mux"),
            vote_sender,
            vote_receiver,
            self.muxer_size,
        )
        .with_backup()
        .build();
        mux.start();

        let (mux, resolver) = Muxer::new(
            self.context.child("resolver_mux"),
            resolver_sender,
            resolver_receiver,
            self.muxer_size,
        );
        mux.start();

        Channels {
            vote,
            vote_backup,
            certificate,
            resolver,
        }
    }

    /// Handle traffic for an epoch whose vote subchannel is not registered.
    ///
    /// Messages from past or current epochs are ignored. A future-epoch vote is
    /// evidence that peers have crossed an epoch boundary locally, so the actor
    /// hints marshal to fetch the current epoch's boundary finalization from the
    /// sender.
    fn handle_backup_vote(
        &self,
        epocher: &FixedEpocher,
        our_epoch: Epoch,
        their_epoch: u64,
        from: <P::Scheme as Verifier>::PublicKey,
    ) {
        let their_epoch = Epoch::new(their_epoch);
        if their_epoch <= our_epoch {
            debug!(%their_epoch, %our_epoch, ?from, "received message from past epoch");
            return;
        }

        let boundary_height = epocher
            .last(our_epoch)
            .expect("our epoch should be covered by epoch strategy");
        debug!(
            ?from,
            %their_epoch,
            %our_epoch,
            %boundary_height,
            "received backup message from future epoch, ensuring boundary finalization"
        );
        self.marshal
            .hint_finalized(boundary_height, NonEmptyVec::new(from));
    }

    /// Handle one finalized block delivered by marshal.
    ///
    /// Non-boundary blocks are acknowledged immediately. A boundary block must
    /// carry the next epoch's public [`Payload::EpochInfo`]; once it does, the
    /// actor stops the current Simplex engine and enters the next epoch using
    /// that public peer set.
    async fn handle_finalized<S, R>(
        &mut self,
        epocher: &FixedEpocher,
        active: &mut ActiveEpoch,
        block: MV::ApplicationBlock,
        acknowledgement: ACK,
        channels: &mut Channels<P::Scheme, S, R>,
    ) where
        S: Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        let height = block.height();
        if epocher.last(active.epoch) != Some(height) {
            acknowledgement.acknowledge();
            return;
        }

        let next_epoch = active.epoch.next();
        let Some(Payload::EpochInfo(info)) = block.payload() else {
            panic!("boundary block of epoch {} missing EpochInfo", active.epoch);
        };
        if info.epoch != next_epoch {
            panic!(
                "boundary block of epoch {} carries epoch info for wrong epoch (got: {}, expected: {})",
                active.epoch,
                info.epoch,
                next_epoch
            );
        }

        let boundary = self
            .marshal
            .get_block(height)
            .await
            .unwrap_or_else(|| panic!("missing finalized boundary block at height {height}"));
        let floor = Floor::Genesis(MV::commitment(&boundary));

        *active = self
            .enter_epoch(
                next_epoch,
                floor,
                info.participants().tracked_peers(),
                channels,
            )
            .await;
        acknowledgement.acknowledge();
    }

    /// Enter an epoch and return the active engine handle.
    ///
    /// This is the only path that tracks consensus peers, opens epoch-scoped
    /// mux subchannels, constructs the Simplex engine, and updates the current
    /// epoch metric. Callers must abort the previous [`ActiveEpoch`] before
    /// replacing it with the returned value.
    async fn enter_epoch<S, R>(
        &mut self,
        epoch: Epoch,
        floor: Floor<P::Scheme, MV::Commitment>,
        peers: impl Into<TrackedPeers<<P::Scheme as Verifier>::PublicKey>> + Send,
        channels: &mut Channels<P::Scheme, S, R>,
    ) -> ActiveEpoch
    where
        S: Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        self.gate.wait(epoch).await;

        let _ = self.manager.track(epoch.get(), peers);
        let scheme = self
            .provider
            .scheme(epoch)
            .unwrap_or_else(|| panic!("missing consensus scheme for epoch {epoch}"));
        let context = self
            .context
            .child("consensus_engine")
            .with_attribute("epoch", epoch);
        let engine = simplex::Engine::new(
            context,
            simplex::Config {
                scheme: scheme.as_ref().clone(),
                elector: self.simplex.elector.clone(),
                blocker: self.oracle.clone(),
                automaton: self.application.clone(),
                relay: self.application.clone(),
                reporter: self.marshal.clone(),
                strategy: self.strategy.clone(),
                partition: format!("{}_consensus_{epoch}", self.partition_prefix),
                mailbox_size: self.simplex.mailbox_size,
                epoch,
                floor,
                replay_buffer: self.simplex.replay_buffer,
                write_buffer: self.simplex.write_buffer,
                page_cache: self.page_cache_ref.clone(),
                leader_timeout: self.simplex.leader_timeout,
                certification_timeout: self.simplex.certification_timeout,
                timeout_retry: self.simplex.timeout_retry,
                fetch_timeout: self.simplex.fetch_timeout,
                fetch_concurrent: self.simplex.fetch_concurrent,
                activity_timeout: self.simplex.activity_timeout,
                skip_timeout: self.simplex.skip_timeout,
                forwarding: self.simplex.forwarding,
            },
        );

        let vote = channels.vote.register(epoch.get()).await.unwrap();
        let certificate = channels.certificate.register(epoch.get()).await.unwrap();
        let resolver = channels.resolver.register(epoch.get()).await.unwrap();
        let handle = engine.start(vote, certificate, resolver);
        let _ = self.latest_epoch.try_set(epoch.get());

        info!(%epoch, "entered epoch");
        ActiveEpoch { epoch, handle }
    }
}
