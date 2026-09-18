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
    CertifiableAutomaton, HandoffPublication, Heightable, Relay,
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
    num::{NonZeroU64, NonZeroUsize},
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

// Replacing the active epoch aborts the previous engine.
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

/// Simplex settings applied to every epoch engine.
///
/// Each field is passed to the [`simplex::Config`] field of the same name, which
/// documents its constraints. An invalid configuration panics when the
/// orchestrator enters an epoch.
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

    /// Page cache for the consensus journals.
    pub page_cache: CacheRef,

    /// Time to wait for a leader proposal in a view.
    pub leader_timeout: Duration,

    /// Time to wait for certification progress before attempting to skip a view.
    /// Must be greater than `leader_timeout`.
    pub certification_timeout: Duration,

    /// Time to wait before retrying a nullify broadcast while stuck in a view.
    pub timeout_retry: Duration,

    /// Time to wait for a peer to respond to a resolver request.
    pub fetch_timeout: Duration,

    /// Number of views behind the finalized tip to retain validator activity.
    pub view_retention: ViewDelta,

    /// Policy governing whether `nullify(v)` may be broadcast before the normal round deadlines.
    pub skip: SkipPolicy,

    /// Whether to retain individual votes after certification (see
    /// [`simplex::Config::track_historical_votes`]).
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

    /// Peer manager that activates each epoch's peers.
    pub manager: M,

    /// Provider of epoch-scoped consensus signing schemes.
    ///
    /// The actor panics if the provider has no scheme for an epoch it enters.
    pub provider: P,

    /// Marshal mailbox used to report consensus output and read finalized blocks.
    pub marshal: MarshalMailbox<P::Scheme, MV>,

    /// Application automaton and relay used by each epoch consensus engine.
    pub application: A,

    /// Strategy for parallel verification and signing work.
    pub strategy: T,

    /// Simplex settings applied to every epoch engine.
    pub simplex: SimplexConfig<L>,

    /// The actor enters an epoch only after this gate reaches it.
    pub gate: Gate,

    /// State-sync startup plan shared with the reshare actor.
    pub state_sync: StateSyncPlan<
        P::Scheme,
        MV::Commitment,
        DV,
        <MV::ApplicationBlock as ReshareBlock>::Directory,
    >,

    /// Number of blocks in each epoch.
    pub blocks_per_epoch: NonZeroU64,

    /// Maximum number of messages to buffer in each network muxer.
    pub muxer_size: usize,

    /// Maximum number of finalized-block reports to buffer.
    pub mailbox_size: NonZeroUsize,

    /// Partition prefix used for per-epoch consensus persistence.
    pub partition_prefix: String,
}

/// Runs one Simplex engine per epoch (see the
/// [module docs](crate::dkg::orchestrator)).
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
    muxer_size: usize,
    partition_prefix: String,
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
    /// Creates an orchestrator and the mailbox that receives finalized blocks.
    ///
    /// The returned [`Mailbox`] should be installed as a marshal reporter. The
    /// actor advances epochs from those reports once started with
    /// [`Actor::start`].
    pub fn new(
        context: E,
        config: Config<B, M, P, MV, DV, A, L, T>,
    ) -> (Self, Mailbox<MV::ApplicationBlock, ACK>) {
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
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
                latest_epoch,
                _payload: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    /// Spawns the orchestrator on the vote, certificate, and resolver channels,
    /// which it multiplexes by epoch.
    ///
    /// See [Failures](crate::dkg::orchestrator#failures) for when the returned
    /// task exits or panics.
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

    /// Drives epoch consensus from finalized blocks and future-epoch traffic
    /// until shutdown.
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

    /// Resolves the startup epoch from state-sync material if the plan resolves
    /// to any, and otherwise from the boundary block of marshal's recovered
    /// epoch.
    ///
    /// Returns `None` if marshal cannot supply that boundary block.
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
        let recovered_epoch = self
            .marshal
            .get_processed()
            .await
            .map(|processed| state_sync::recovered_epoch(processed, epocher));
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

    /// Resolves `epoch` from the finalized boundary block that carries its
    /// [`EpochInfo`].
    ///
    /// Returns `None` if marshal cannot supply the block. Panics if the block
    /// carries no [`EpochInfo`] or one for another epoch.
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
        let height = epoch
            .previous()
            .and_then(|epoch| epocher.last(epoch))
            .unwrap_or_else(Height::zero);
        let Some(boundary) = self.marshal.get_block(height).await else {
            debug!(%height, "boundary block unavailable, shutting down orchestrator");
            return None;
        };
        let commitment = MV::commitment(&boundary);
        let block = MV::into_shared(boundary);
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

    /// Starts the consensus muxers and returns their epoch-scoped channel handles.
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

    /// Asks `from` for the finalization of `our_epoch`'s final block if
    /// `their_epoch` is later (see
    /// [Catching Up](crate::dkg::orchestrator#catching-up)).
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

    /// Handles a finalized block and returns whether the actor keeps running.
    ///
    /// Acknowledges any block below the active epoch's final block
    /// immediately. For the final block, enters the next epoch and acknowledges
    /// the block once the new engine has started. Returns `false` if marshal
    /// cannot supply the block or the next epoch cannot be entered. Panics if
    /// the block is above the active epoch's final block (marshal skipped the
    /// final block) or if the final block does not carry the next epoch's
    /// [`EpochInfo`].
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
        let last = epocher
            .last(current)
            .expect("active epoch should be covered by epoch strategy");
        assert!(
            height <= last,
            "finalized block skips the final block of epoch {current}"
        );
        if height != last {
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

    /// Waits for the gate to reach `epoch`, activates its peers, and starts its
    /// Simplex engine.
    ///
    /// Returns an error if the runtime stops or the gate closes before the gate
    /// reaches `epoch`, if peer activation fails, or if a muxer has stopped.
    /// Panics if the provider has no scheme for `epoch`. The previous engine
    /// keeps running until the caller drops its [`ActiveEpoch`].
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
                handoff_publication: HandoffPublication::AfterCertification,
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
                page_cache: self.simplex.page_cache.clone(),
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

        // Each epoch registers once, so a registration failure means the muxers
        // stopped with this context.
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
