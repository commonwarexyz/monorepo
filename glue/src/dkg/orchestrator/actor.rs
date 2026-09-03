//! Consensus engine orchestration for threshold reshare epoch transitions.

use crate::dkg::{
    ReshareBlock,
    fence::Gate,
    network::{Directory, Manager},
    orchestrator::{Mailbox, mailbox::Message},
    state_sync::{self, Plan as StateSyncPlan},
    types::{EpochInfo, Payload},
};
use commonware_actor::mailbox;
use commonware_consensus::{
    CertifiableAutomaton, Heightable, Relay,
    marshal::core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    simplex::{
        self, Floor, ForwardPolicy, Plan, SkipPolicy, elector::Config as Elector, scheme,
        types::Context,
    },
    types::{Epoch, Epocher, FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::{
    Digest, PublicKey, Signer,
    bls12381::primitives::variant::Variant as BlsVariant,
    certificate::{Provider, Verifier},
};
use commonware_macros::{select, select_loop};
use commonware_p2p::{
    Blocker, Channel, Message as P2pMessage, Receiver, Sender,
    utils::mux::{Builder, MuxHandle, Muxer},
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Network, Spawner, Storage,
    buffer::paged::CacheRef,
    spawn_cell,
    telemetry::metrics::{Gauge, GaugeExt, MetricsExt as _},
};
use commonware_utils::{Acknowledgement, acknowledgement::Exact, channel::mpsc, vec::NonEmptyVec};
use rand_core::CryptoRng;
use std::{
    marker::PhantomData,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, info, warn};

struct Channels<C, S, R>
where
    C: Verifier,
    S: Sender<PublicKey = C::PublicKey>,
    R: Receiver<PublicKey = C::PublicKey>,
{
    vote: MuxHandle<S, R>,
    vote_backup: mpsc::Receiver<(Channel, P2pMessage<C::PublicKey>)>,
    certificate: MuxHandle<S, R>,
    certificate_backup: mpsc::Receiver<(Channel, P2pMessage<C::PublicKey>)>,
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

enum EnterEpochError<E> {
    GateClosed,
    PeerSet(E),
    MuxClosed,
    Stopped,
}

struct ResolvedStart<S, D, V, P, Dir>
where
    S: scheme::Scheme<D, PublicKey = P>,
    D: Digest,
    V: BlsVariant,
    P: PublicKey,
    Dir: Directory<P>,
{
    epoch: Epoch,
    floor: Floor<S, D>,
    info: EpochInfo<V, P, Dir>,
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

    /// Number of views behind the finalized tip to retain validator activity.
    pub view_retention: ViewDelta,

    /// Policy governing whether `nullify(v)` may be broadcast before the normal round deadlines.
    pub skip: SkipPolicy,

    /// Track individual votes after certification.
    ///
    /// By default, full vote evidence is released when the corresponding certificate
    /// is constructed or received, making later conflict reporting and peer blocking
    /// best effort. Enabling this retains each recorded vote until its round is
    /// pruned, increasing memory usage.
    pub track_historical_votes: bool,

    /// Policy for proactively forwarding certified blocks.
    pub forward: ForwardPolicy,
}

/// Configuration for the [`Actor`].
pub struct Config<B, M, P, MV, DV, A, L, T>
where
    P: Provider<Scope = Epoch>,
    P::Scheme: scheme::Scheme<MV::Commitment>,
    MV: MarshalVariant,
    MV::ApplicationBlock: ReshareBlock,
    <MV::ApplicationBlock as ReshareBlock>::Signer:
        Signer<PublicKey = <P::Scheme as Verifier>::PublicKey>,
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

    /// Shared DKG state-sync startup recovery plan.
    pub state_sync: StateSyncPlan<
        P::Scheme,
        MV::Commitment,
        DV,
        <MV::ApplicationBlock as ReshareBlock>::Directory,
    >,

    /// Number of blocks in each epoch.
    pub blocks_per_epoch: NonZeroU64,

    /// Number of prior epoch peer sets to retain in addition to the current epoch.
    ///
    /// On restart, only peer sets whose authenticated boundary blocks remain
    /// available in local marshal storage can be restored. In particular, a
    /// state-sync artifact authenticates the current epoch but does not restore
    /// missing boundary history for prior epochs.
    pub peer_set_retention: u64,

    /// Peer-set capacity configured on the underlying P2P manager.
    ///
    /// This must match the transport configuration. Construction rejects a
    /// retention horizon that does not leave one slot for the current epoch.
    pub peer_set_capacity: NonZeroUsize,

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
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + Storage + Network,
    B: Blocker<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    M: Manager<
            PublicKey = <P::Scheme as Verifier>::PublicKey,
            Directory = <MV::ApplicationBlock as ReshareBlock>::Directory,
        >,
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
    state_sync: StateSyncPlan<
        P::Scheme,
        MV::Commitment,
        DV,
        <MV::ApplicationBlock as ReshareBlock>::Directory,
    >,
    blocks_per_epoch: NonZeroU64,
    peer_set_retention: u64,
    muxer_size: usize,
    partition_prefix: String,
    page_cache_ref: CacheRef,
    latest_epoch: Gauge,
    _payload: PhantomData<(DV, C)>,
}

impl<E, B, M, P, MV, DV, C, A, L, T, ACK> Actor<E, B, M, P, MV, DV, C, A, L, T, ACK>
where
    E: BufferPooler + Spawner + Metrics + CryptoRng + Clock + Storage + Network,
    B: Blocker<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    M: Manager<
            PublicKey = <P::Scheme as Verifier>::PublicKey,
            Directory = <MV::ApplicationBlock as ReshareBlock>::Directory,
        >,
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
        assert!(
            config.peer_set_retention < config.peer_set_capacity.get() as u64,
            "peer-set capacity must cover retained epochs plus the current epoch"
        );
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
                peer_set_retention: config.peer_set_retention,
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
    /// Vote, certificate, and resolver channels are multiplexed by epoch
    /// inside the actor.
    pub fn start<S, R>(
        mut self,
        votes: (S, R),
        certificates: (S, R),
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
    /// finalized boundary blocks from marshal and for backup vote and
    /// certificate traffic from future epochs, which is used only to ask
    /// marshal for the missing boundary finalization.
    async fn run<S, R>(
        mut self,
        (vote_sender, vote_receiver): (S, R),
        (certificate_sender, certificate_receiver): (S, R),
        (resolver_sender, resolver_receiver): (S, R),
    ) where
        S: Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        let mut channels = self.create_channels(
            (vote_sender, vote_receiver),
            (certificate_sender, certificate_receiver),
            (resolver_sender, resolver_receiver),
        );
        let epocher = FixedEpocher::new(self.blocks_per_epoch);
        let Some(start) = self.resolve_start(&epocher).await else {
            debug!("context shutdown while resolving startup epoch");
            return;
        };
        if let Err(error) = self.track_retained_peer_sets(start.epoch, &epocher).await {
            warn!(
                epoch = start.epoch.get(),
                %error,
                "failed to activate retained peer set"
            );
            return;
        }
        let mut active = match self
            .enter_epoch(start.epoch, start.floor, &start.info, &mut channels)
            .await
        {
            Ok(active) => active,
            Err(EnterEpochError::GateClosed) => {
                debug!(
                    epoch = start.epoch.get(),
                    "epoch gate closed before startup"
                );
                return;
            }
            Err(EnterEpochError::PeerSet(error)) => {
                warn!(epoch = %start.epoch, %error, "failed to activate startup peer set");
                return;
            }
            Err(EnterEpochError::MuxClosed) => {
                debug!(
                    epoch = start.epoch.get(),
                    "consensus mux closed before startup epoch"
                );
                return;
            }
            Err(EnterEpochError::Stopped) => {
                debug!("context shutdown before startup epoch");
                return;
            }
        };

        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping orchestrator");
            },
            Some((their_epoch, (from, _))) = channels.vote_backup.recv() else {
                debug!("vote mux backup channel closed, shutting down orchestrator");
                break;
            } => {
                self.handle_backup(&epocher, active.epoch, their_epoch, from);
            },
            Some((their_epoch, (from, _))) = channels.certificate_backup.recv() else {
                debug!("certificate mux backup channel closed, shutting down orchestrator");
                break;
            } => {
                self.handle_backup(&epocher, active.epoch, their_epoch, from);
            },
            result = &mut active.handle => match result {
                Ok(()) => {
                    debug!(epoch = active.epoch.get(), "simplex engine stopped, shutting down orchestrator");
                    break;
                }
                Err(error) => {
                    panic!("simplex engine for epoch {} stopped unexpectedly: {error}", active.epoch);
                }
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down orchestrator");
                break;
            } => match message {
                Message::Finalized {
                    block,
                    acknowledgement,
                } => {
                    let keep_running = self
                        .handle_finalized(
                            &epocher,
                            &mut active,
                            block,
                            acknowledgement,
                            &mut channels,
                        )
                        .await;
                    if !keep_running {
                        break;
                    }
                }
            },
        }
    }

    /// Resolve the first epoch this process should run.
    ///
    /// Normal startup resolves from marshal's local boundary blocks. State-sync
    /// startup and recovery are exceptions: the node may know a recent public
    /// boundary from `dkg::probe` without having the previous boundary block in
    /// local marshal storage.
    ///
    /// Returns `None` when startup data cannot be fetched from marshal, which
    /// requires the orchestrator to shut down.
    async fn resolve_start(
        &mut self,
        epocher: &FixedEpocher,
    ) -> Option<
        ResolvedStart<
            P::Scheme,
            MV::Commitment,
            DV,
            <P::Scheme as Verifier>::PublicKey,
            <MV::ApplicationBlock as ReshareBlock>::Directory,
        >,
    > {
        let recovered_epoch = state_sync::recovered_epoch(&self.marshal, epocher).await;
        if let Some(state_sync) = self
            .state_sync
            .resolve(
                self.context.as_present().child("state_sync"),
                recovered_epoch,
            )
            .await
        {
            return Some(ResolvedStart {
                epoch: state_sync.info.epoch,
                floor: Floor::Finalized(state_sync.floor),
                info: state_sync.info,
            });
        }

        self.resolve_boundary(recovered_epoch.unwrap_or_else(Epoch::zero), epocher)
            .await
    }

    /// Activate retained prior peer sets before the current peer set.
    ///
    /// Marshal boundary blocks are the authenticated source for prior epoch
    /// metadata. Missing history is skipped because state sync may begin from a
    /// recent floor without restoring older boundaries. This helper never
    /// starts Simplex and excludes `current`, which is tracked by [`Self::enter_epoch`].
    async fn track_retained_peer_sets(
        &mut self,
        current: Epoch,
        epocher: &FixedEpocher,
    ) -> Result<(), M::Error> {
        let first = current.get().saturating_sub(self.peer_set_retention);
        for epoch in first..current.get() {
            let epoch = Epoch::new(epoch);
            let Some(height) = Self::boundary_height(epoch, epocher) else {
                debug!(%epoch, "retained epoch boundary height overflowed");
                continue;
            };
            let Some(boundary) = self.marshal.get_block(height).await else {
                debug!(%epoch, %height, "retained epoch boundary block unavailable");
                continue;
            };
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

            self.manager
                .track(epoch, info.participants().tracked_peers(), &info.directory)?;
            info!(%epoch, "activated retained epoch peer set");
        }

        Ok(())
    }

    /// Return the finalized block height that carries an epoch's public metadata.
    fn boundary_height(epoch: Epoch, epocher: &FixedEpocher) -> Option<Height> {
        epoch
            .previous()
            .map_or(Some(Height::zero()), |epoch| epocher.last(epoch))
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
    /// state sync, marshal is anchored at the probe-sampled floor while the
    /// previous epoch boundary block is not locally available yet. In that
    /// startup path, the probe artifact is the trusted source of boundary
    /// epoch info.
    ///
    /// Returns `None` when the boundary block cannot be fetched from marshal,
    /// which requires the orchestrator to shut down.
    async fn resolve_boundary(
        &mut self,
        epoch: Epoch,
        epocher: &FixedEpocher,
    ) -> Option<
        ResolvedStart<
            P::Scheme,
            MV::Commitment,
            DV,
            <P::Scheme as Verifier>::PublicKey,
            <MV::ApplicationBlock as ReshareBlock>::Directory,
        >,
    > {
        let Some(height) = Self::boundary_height(epoch, epocher) else {
            debug!(%epoch, "boundary height overflowed, shutting down orchestrator");
            return None;
        };
        let Some(boundary) = self.marshal.get_block(height).await else {
            debug!(%height, "boundary block unavailable, shutting down orchestrator");
            return None;
        };
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

        Some(ResolvedStart {
            epoch,
            floor: Floor::Genesis(commitment),
            info,
        })
    }

    /// Start the consensus channel muxers and return handles used to open
    /// epoch-specific subchannels.
    ///
    /// The vote mux includes a backup receiver so the orchestrator can detect
    /// messages for epochs it has not registered locally.
    fn create_channels<S, R>(
        &self,
        (vote_sender, vote_receiver): (S, R),
        (certificate_sender, certificate_receiver): (S, R),
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

        let (mux, certificate, certificate_backup) = Muxer::builder(
            self.context.child("certificate_mux"),
            certificate_sender,
            certificate_receiver,
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
            certificate_backup,
            resolver,
        }
    }

    /// Handle traffic for an epoch whose vote or certificate subchannel is not
    /// registered.
    ///
    /// Messages from past or current epochs are ignored. A future-epoch
    /// message is evidence that peers have crossed an epoch boundary locally,
    /// so the actor hints marshal to fetch the current epoch's boundary
    /// finalization from the sender.
    fn handle_backup(
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
        block: Arc<MV::ApplicationBlock>,
        acknowledgement: ACK,
        channels: &mut Channels<P::Scheme, S, R>,
    ) -> bool
    where
        S: Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        let height = block.height();
        let current = active.epoch;
        if epocher.last(current) != Some(height) {
            acknowledgement.acknowledge();
            return true;
        }

        let next_epoch = current.next();
        let Some(Payload::EpochInfo(info)) = block.payload() else {
            panic!("boundary block of epoch {current} missing EpochInfo");
        };
        if info.epoch != next_epoch {
            panic!(
                "boundary block of epoch {current} carries epoch info for wrong epoch (got: {}, expected: {next_epoch})",
                info.epoch
            );
        }

        let Some(boundary) = self.marshal.get_block(height).await else {
            debug!(%height, "boundary block unavailable, shutting down orchestrator");
            return false;
        };
        let floor = Floor::Genesis(MV::commitment(&boundary));

        let next = self.enter_epoch(next_epoch, floor, &info, channels).await;
        let next = match next {
            Ok(next) => next,
            Err(EnterEpochError::GateClosed) => {
                debug!(%next_epoch, "epoch gate closed before boundary transition");
                return false;
            }
            Err(EnterEpochError::PeerSet(error)) => {
                warn!(%next_epoch, %error, "failed to activate boundary peer set");
                return false;
            }
            Err(EnterEpochError::MuxClosed) => {
                debug!(%next_epoch, "consensus mux closed before boundary transition");
                return false;
            }
            Err(EnterEpochError::Stopped) => {
                debug!(%next_epoch, "context shutdown while waiting to enter epoch");
                return false;
            }
        };

        *active = next;
        acknowledgement.acknowledge();
        true
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
        info: &EpochInfo<
            DV,
            <P::Scheme as Verifier>::PublicKey,
            <MV::ApplicationBlock as ReshareBlock>::Directory,
        >,
        channels: &mut Channels<P::Scheme, S, R>,
    ) -> Result<ActiveEpoch, EnterEpochError<M::Error>>
    where
        S: Sender<PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Receiver<PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        // Shutdown is polled first so a stop signal wins over an
        // already-marked gate.
        let mut shutdown = self.context.stopped();
        select! {
            _ = &mut shutdown => {
                return Err(EnterEpochError::Stopped);
            },
            result = self.gate.wait(epoch) => {
                if result.is_err() {
                    return Err(EnterEpochError::GateClosed);
                }
            },
        };
        drop(shutdown);

        self.manager
            .track(epoch, info.participants().tracked_peers(), &info.directory)
            .map_err(EnterEpochError::PeerSet)?;
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
                view_retention: self.simplex.view_retention,
                skip: self.simplex.skip,
                forward: self.simplex.forward,
                track_historical_votes: self.simplex.track_historical_votes,
            },
        );

        // Each epoch is registered exactly once, so a registration failure
        // means the muxer has stopped: the vote, certificate, and resolver
        // muxers all exit with this context, which is a clean-stop condition.
        let Ok(vote) = channels.vote.register(epoch.get()).await else {
            return Err(EnterEpochError::MuxClosed);
        };
        let Ok(certificate) = channels.certificate.register(epoch.get()).await else {
            return Err(EnterEpochError::MuxClosed);
        };
        let Ok(resolver) = channels.resolver.register(epoch.get()).await else {
            return Err(EnterEpochError::MuxClosed);
        };
        let handle = engine.start(vote, certificate, resolver);
        let _ = self.latest_epoch.try_set(epoch.get());

        info!(%epoch, "entered epoch");
        Ok(ActiveEpoch { epoch, handle })
    }
}
