//! Production lifecycle for fixed-epoch aggregation engines.
//!
//! The lifecycle keeps only the configured epoch horizon network-active. Older
//! unfinished epochs are represented by journal descriptors and are recovered
//! through bounded parked passes. The aggregation journal remains authoritative
//! until durable history returns an exact cleanup authorization.

use super::{
    aggregation::{self as history, RequestError, Retirement},
    aggregation_parked::{self as parked, Outcome as ParkedOutcome},
    aggregation_router::Registry,
    checkpoints::FinalizedBlock,
};
use crate::dkg::fence::Gate;
use commonware_actor::{Feedback, Unreliable, mailbox};
use commonware_codec::Encode as _;
use commonware_consensus::{
    Reporter,
    aggregation::{
        Config as AggregationConfig, Engine, EngineOutcome, JournalConfig, JournalIdentity,
        Recovery, Stopper,
        scheme::Scheme,
        types::{Certificate, RecoveryKey, RecoveryNamespace},
    },
    marshal::Update,
    types::{Epoch, Epocher as _, FixedEpocher},
};
use commonware_cryptography::{
    Digest,
    certificate::{Provider as SchemeProvider, Verifier},
};
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Sender, utils::mux::MuxHandle};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Metrics, Spawner, Storage,
    buffer::paged::CacheRef,
    reschedule, spawn_cell,
    telemetry::metrics::{Gauge, GaugeExt as _, MetricsExt as _},
};
use commonware_utils::{Acknowledgement, NonZeroDuration};
use futures::{FutureExt as _, StreamExt as _, future, stream::FuturesUnordered};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    ops::Bound::{Excluded, Unbounded},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;

/// Fixed settings shared by every epoch engine.
#[derive(Clone)]
pub struct EngineConfig {
    /// Whether acknowledgements use the priority network queue.
    pub priority_acks: bool,
    /// Acknowledgement rebroadcast interval.
    pub rebroadcast_timeout: NonZeroDuration,
    /// Rebroadcast ticks before resolver recovery begins.
    pub recovery_after_rebroadcasts: NonZeroU64,
    /// Maximum live positions in each engine.
    pub window: NonZeroU64,
    /// Prefix used to derive one immutable journal partition per epoch.
    pub journal_partition_prefix: String,
    /// Journal write buffer.
    pub journal_write_buffer: NonZeroUsize,
    /// Journal replay buffer.
    pub journal_replay_buffer: NonZeroUsize,
    /// Positions per journal section.
    pub journal_heights_per_section: NonZeroU64,
    /// Journal compression level.
    pub journal_compression: Option<u8>,
    /// Journal page cache.
    pub journal_page_cache: CacheRef,
}

/// Aggregation lifecycle policy and engine dependencies.
pub struct Config<A, B, T> {
    /// Aggregation recovery namespace owned by this lifecycle.
    pub namespace: RecoveryNamespace,
    /// Latest epoch known at startup.
    pub current_epoch: Epoch,
    /// Fixed mapping from epochs to global heights.
    pub epocher: FixedEpocher,
    /// Number of old engines allowed alongside the current engine.
    pub active_old_epochs: usize,
    /// Capacity of finalized-block ingress.
    pub mailbox_size: NonZeroUsize,
    /// Capacity of the asynchronous local-certificate ingress.
    pub certificate_mailbox_size: NonZeroUsize,
    /// Interval between bounded parked recovery passes.
    pub parked_interval: Duration,
    /// Maximum missing heights scheduled by one parked pass.
    pub parked_missing_batch: NonZeroUsize,
    /// Canonical finalized-checkpoint automaton.
    pub automaton: A,
    /// Peer blocker used by each engine.
    pub blocker: B,
    /// Signature verification strategy.
    pub strategy: T,
    /// Shared per-engine settings.
    pub engine: EngineConfig,
}

/// Fatal lifecycle failure.
#[derive(Debug, Error)]
pub enum Error {
    /// Durable history stopped responding.
    #[error("aggregation history closed")]
    HistoryClosed,
    /// DKG closed before an epoch's scheme became available.
    #[error("aggregation scheme gate closed at epoch {0}")]
    GateClosed(Epoch),
    /// The provider did not contain the scheme promised by the gate.
    #[error("aggregation scheme unavailable at epoch {0}")]
    MissingScheme(Epoch),
    /// The fixed epocher cannot represent the epoch range.
    #[error("aggregation epoch range overflow at epoch {0}")]
    EpochOverflow(Epoch),
    /// The configured scheme belongs to another recovery namespace.
    #[error("aggregation namespace mismatch at epoch {0}")]
    NamespaceMismatch(Epoch),
    /// The acknowledgement muxer could not register an epoch route.
    #[error("aggregation mux registration failed at epoch {epoch}: {source}")]
    Mux {
        /// Epoch whose route failed.
        epoch: Epoch,
        /// Mux failure.
        source: commonware_p2p::utils::mux::Error,
    },
    /// The active resolver router closed.
    #[error("aggregation router closed")]
    RouterClosed,
    /// An engine stopped without an orchestrator parking request.
    #[error("aggregation engine stopped unexpectedly at epoch {0}")]
    EngineStopped(Epoch),
    /// A parked recovery pass failed.
    #[error("parked aggregation recovery failed at epoch {epoch}: {source}")]
    Parked {
        /// Epoch being recovered.
        epoch: Epoch,
        /// Parked recovery failure.
        source: parked::Error,
    },
    /// Durable history rejected a certificate reported by a live engine.
    #[error("aggregation history rejected the live certificate at epoch {epoch}, height {height}")]
    HistoryRejected {
        /// Epoch reported by the live engine.
        epoch: Epoch,
        /// Global height reported by the live engine.
        height: commonware_consensus::types::Height,
    },
}

enum Message<A: Acknowledgement> {
    Finalized { epoch: Epoch, acknowledgement: A },
}

struct FinalizedOverflow<A: Acknowledgement>(Option<Message<A>>);

impl<A: Acknowledgement> Default for FinalizedOverflow<A> {
    fn default() -> Self {
        Self(None)
    }
}

impl<A: Acknowledgement> mailbox::Overflow<Message<A>> for FinalizedOverflow<A> {
    fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<A>) -> Option<Message<A>>,
    {
        if let Some(message) = self.0.take() {
            self.0 = push(message);
        }
    }
}

impl<A: Acknowledgement> mailbox::Policy for Message<A> {
    type Overflow = FinalizedOverflow<A>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // A later epoch subsumes discovery of every earlier epoch. Acknowledge
        // coalesced reports immediately; certification is never an ack barrier.
        if let Some(Self::Finalized {
            acknowledgement, ..
        }) = overflow.0.replace(message)
        {
            acknowledgement.acknowledge();
        }
    }
}

/// Bounded finalized-block reporter for the lifecycle actor.
pub struct Handler<B: FinalizedBlock, A: Acknowledgement> {
    sender: mailbox::Sender<Message<A>>,
    epocher: FixedEpocher,
    _block: PhantomData<fn() -> B>,
}

impl<B: FinalizedBlock, A: Acknowledgement> Clone for Handler<B, A> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            epocher: self.epocher.clone(),
            _block: PhantomData,
        }
    }
}

impl<B: FinalizedBlock, A: Acknowledgement> Reporter for Handler<B, A> {
    type Activity = Update<B, A>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update::Block(block, acknowledgement) = activity else {
            return Feedback::Ok;
        };
        let Some(info) = self.epocher.containing(block.height()) else {
            acknowledgement.acknowledge();
            return Feedback::Ok;
        };
        self.sender.enqueue(Message::Finalized {
            epoch: info.epoch(),
            acknowledgement,
        })
    }
}

struct CertificateMessage<S: commonware_cryptography::certificate::Scheme, D: Digest>(
    Certificate<S, D>,
);

impl<S, D> mailbox::UnreliablePolicy for CertificateMessage<S, D>
where
    S: commonware_cryptography::certificate::Scheme,
    D: Digest,
{
    type Overflow = VecDeque<Self>;

    fn handle(_: &mut Self::Overflow, _: Self) -> bool {
        false
    }
}

#[derive(Clone)]
struct CertificateReporter<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    sender: mailbox::UnreliableSender<CertificateMessage<S, D>>,
}

impl<S, D> Reporter for CertificateReporter<S, D>
where
    S: commonware_cryptography::certificate::Scheme,
    D: Digest,
{
    type Activity = Certificate<S, D>;

    fn report(&mut self, certificate: Self::Activity) -> Feedback {
        match self.sender.enqueue(CertificateMessage(certificate)) {
            Unreliable::Outcome(feedback) => feedback,
            Unreliable::Rejected => Feedback::Backoff,
        }
    }
}

struct EpochDescriptor<S> {
    scheme: Arc<S>,
    journal: JournalConfig,
    journal_archived: bool,
}

struct Active<S> {
    stopper: Option<Stopper>,
    stopping: bool,
    descriptor: EpochDescriptor<S>,
}

type ActiveFuture = Pin<Box<dyn future::Future<Output = (Epoch, EngineOutcome)> + Send>>;
type ParkedFuture =
    Pin<Box<dyn future::Future<Output = (Epoch, Result<ParkedOutcome, parked::Error>)> + Send>>;

/// Owns active engines and parked recovery for one aggregation namespace.
pub struct Actor<E, S, D, P, A, B, T, NS, NR, ACK>
where
    E: BufferPooler + Clock + Spawner + Storage + Metrics + CryptoRng,
    S: Scheme<D>,
    D: Digest,
    P: history::Provider<S> + SchemeProvider<Scope = Epoch, Scheme = S>,
    A: commonware_consensus::Automaton<Context = commonware_consensus::types::Height, Digest = D>,
    B: Blocker<PublicKey = <S as Verifier>::PublicKey>,
    T: Strategy,
    NS: Sender<PublicKey = <S as Verifier>::PublicKey>,
    NR: Receiver<PublicKey = <S as Verifier>::PublicKey>,
    ACK: Acknowledgement,
{
    context: ContextCell<E>,
    config: Config<A, B, T>,
    provider: P,
    history: history::Handler,
    router: Registry<S, D>,
    gate: Gate,
    recovery: Recovery,
    muxer: MuxHandle<NS, NR>,
    receiver: mailbox::Receiver<Message<ACK>>,
    certificate_receiver: mailbox::UnreliableReceiver<CertificateMessage<S, D>>,
    certificate_reporter: CertificateReporter<S, D>,
    current_epoch: Epoch,
    active: BTreeMap<Epoch, Active<S>>,
    active_futures: FuturesUnordered<ActiveFuture>,
    parked: BTreeMap<Epoch, EpochDescriptor<S>>,
    parked_cursor: Option<Epoch>,
    parked_running: BTreeSet<Epoch>,
    parked_futures: FuturesUnordered<ParkedFuture>,
    degraded: BTreeSet<Epoch>,
    parked_epochs: Gauge,
    degraded_epochs: Gauge,
    retained_key_age_epochs: Gauge,
}

impl<E, S, D, P, A, B, T, NS, NR, ACK> Actor<E, S, D, P, A, B, T, NS, NR, ACK>
where
    E: BufferPooler + Clock + Spawner + Storage + Metrics + CryptoRng,
    S: Scheme<D>,
    D: Digest,
    P: history::Provider<S> + SchemeProvider<Scope = Epoch, Scheme = S>,
    A: commonware_consensus::Automaton<Context = commonware_consensus::types::Height, Digest = D>,
    B: Blocker<PublicKey = <S as Verifier>::PublicKey>,
    T: Strategy,
    NS: Sender<PublicKey = <S as Verifier>::PublicKey>,
    NR: Receiver<PublicKey = <S as Verifier>::PublicKey>,
    ACK: Acknowledgement,
{
    /// Creates a lifecycle actor and its finalized-block reporter.
    #[allow(clippy::too_many_arguments)]
    pub fn new<BK: FinalizedBlock>(
        context: E,
        config: Config<A, B, T>,
        provider: P,
        history: history::Handler,
        router: Registry<S, D>,
        gate: Gate,
        recovery: Recovery,
        muxer: MuxHandle<NS, NR>,
    ) -> (Self, Handler<BK, ACK>) {
        assert!(
            !config.parked_interval.is_zero(),
            "parked interval must be non-zero"
        );
        let current_epoch = config.current_epoch;
        let epocher = config.epocher.clone();
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        let (certificate_sender, certificate_receiver) = mailbox::new_unreliable(
            context.child("certificates"),
            config.certificate_mailbox_size,
        );
        let certificate_reporter = CertificateReporter {
            sender: certificate_sender,
        };
        let parked_epochs = context.gauge("parked_epochs", "parked aggregation epochs");
        let degraded_epochs = context.gauge("degraded_epochs", "degraded aggregation epochs");
        let retained_key_age_epochs = context.gauge(
            "retained_key_age_epochs",
            "age in epochs of the oldest retained aggregation key",
        );
        (
            Self {
                context: ContextCell::new(context),
                config,
                provider,
                history,
                router,
                gate,
                recovery,
                muxer,
                receiver,
                certificate_receiver,
                certificate_reporter,
                current_epoch,
                active: BTreeMap::new(),
                active_futures: FuturesUnordered::new(),
                parked: BTreeMap::new(),
                parked_cursor: None,
                parked_running: BTreeSet::new(),
                parked_futures: FuturesUnordered::new(),
                degraded: BTreeSet::new(),
                parked_epochs,
                degraded_epochs,
                retained_key_age_epochs,
            },
            Handler {
                sender,
                epocher,
                _block: PhantomData,
            },
        )
    }

    /// Starts the lifecycle actor.
    pub fn start(self) -> commonware_runtime::Handle<Result<(), Error>> {
        let mut actor = self;
        spawn_cell!(actor.context, actor.run())
    }

    async fn run(mut self) -> Result<(), Error> {
        self.discover_startup().await?;
        let mut parked_deadline = self.context.current() + self.config.parked_interval;
        let mut shutdown = self.context.stopped();

        loop {
            let active = if self.active_futures.is_empty() {
                future::pending().left_future()
            } else {
                self.active_futures.next().right_future()
            };
            let parked = if self.parked_futures.is_empty() {
                future::pending().left_future()
            } else {
                self.parked_futures.next().right_future()
            };
            select! {
                _ = &mut shutdown => break,
                message = self.receiver.recv() => match message {
                    Some(Message::Finalized { epoch, acknowledgement }) => {
                        acknowledgement.acknowledge();
                        if epoch > self.current_epoch {
                            self.advance(epoch).await?;
                        }
                    }
                    None => break,
                },
                certificate = self.certificate_receiver.recv() => {
                    if let Some(CertificateMessage(certificate)) = certificate {
                        self.archive(certificate).await?;
                    }
                },
                completion = active => {
                    if let Some((epoch, outcome)) = completion {
                        self.completed(epoch, outcome).await?;
                    }
                },
                completion = parked => {
                    if let Some((epoch, outcome)) = completion {
                        self.parked_completed(epoch, outcome)?;
                    }
                },
                _ = self.context.sleep_until(parked_deadline) => {
                    self.schedule_parked();
                    parked_deadline = self.context.current() + self.config.parked_interval;
                },
            }
        }

        self.shutdown().await
    }

    async fn discover_startup(&mut self) -> Result<(), Error> {
        self.drain_cleanups().await?;
        let floor = loop {
            match self.history.oldest_unretired(self.config.namespace).await {
                Ok(floor) => break floor,
                Err(RequestError::Backpressured) => reschedule().await,
                Err(RequestError::Closed) => return Err(Error::HistoryClosed),
            }
        }
        .or_else(|| self.provider.oldest_epoch(self.config.namespace));
        let Some(floor) = floor else { return Ok(()) };
        if floor > self.current_epoch {
            return Ok(());
        }
        let horizon = self.horizon(self.current_epoch);
        let mut epoch = floor;
        loop {
            if !self.is_retired(epoch).await? {
                let descriptor = self.descriptor(epoch).await?;
                if epoch < horizon {
                    self.parked.insert(epoch, descriptor);
                    self.degraded.insert(epoch);
                } else {
                    self.start_engine(epoch, descriptor).await?;
                }
            }
            if epoch == self.current_epoch {
                break;
            }
            epoch = Epoch::new(
                epoch
                    .get()
                    .checked_add(1)
                    .ok_or(Error::EpochOverflow(epoch))?,
            );
        }
        self.schedule_parked();
        self.update_lifecycle_metrics();
        Ok(())
    }

    async fn drain_cleanups(&mut self) -> Result<(), Error> {
        loop {
            let cleanups = loop {
                match self
                    .history
                    .pending_cleanups(self.config.namespace, self.config.parked_missing_batch)
                    .await
                {
                    Ok(cleanups) => break cleanups,
                    Err(RequestError::Backpressured) => reschedule().await,
                    Err(RequestError::Closed) => return Err(Error::HistoryClosed),
                }
            };
            if cleanups.is_empty() {
                return Ok(());
            }
            for cleanup in cleanups {
                let epoch = cleanup.retirement.epoch;
                let descriptor = self.descriptor(epoch).await?;
                let mut verifier = self
                    .context
                    .child("cleanup_verifier")
                    .with_attribute("epoch", epoch);
                loop {
                    match parked::cleanup::<_, S, D, _, _>(
                        self.context
                            .child("cleanup_storage")
                            .with_attribute("epoch", epoch),
                        descriptor.journal.clone(),
                        &mut verifier,
                        descriptor.scheme.as_ref(),
                        &self.config.strategy,
                        &mut self.history,
                    )
                    .await
                    {
                        Ok(()) => break,
                        Err(parked::Error::HistoryBackpressured) => reschedule().await,
                        Err(source) => return Err(Error::Parked { epoch, source }),
                    }
                }
            }
        }
    }

    async fn advance(&mut self, current: Epoch) -> Result<(), Error> {
        let previous = self.current_epoch;
        self.current_epoch = current;
        let horizon = self.horizon(current);

        let evictions: Vec<_> = self
            .active
            .range(..horizon)
            .map(|(epoch, _)| *epoch)
            .collect();
        for epoch in evictions {
            self.stop(epoch).await?;
        }

        let mut epoch = Epoch::new(previous.get().saturating_add(1));
        loop {
            if !self.is_retired(epoch).await? {
                let descriptor = self.descriptor(epoch).await?;
                if epoch < horizon {
                    self.parked.insert(epoch, descriptor);
                    self.degraded.insert(epoch);
                } else {
                    self.start_engine(epoch, descriptor).await?;
                }
            }
            if epoch == current {
                break;
            }
            epoch = Epoch::new(
                epoch
                    .get()
                    .checked_add(1)
                    .ok_or(Error::EpochOverflow(epoch))?,
            );
        }
        self.schedule_parked();
        self.update_lifecycle_metrics();
        Ok(())
    }

    const fn horizon(&self, current: Epoch) -> Epoch {
        Epoch::new(
            current
                .get()
                .saturating_sub(self.config.active_old_epochs as u64),
        )
    }

    fn retirement(&self, epoch: Epoch) -> Result<Retirement, Error> {
        let first = self
            .config
            .epocher
            .first(epoch)
            .ok_or(Error::EpochOverflow(epoch))?;
        let last = self
            .config
            .epocher
            .last(epoch)
            .ok_or(Error::EpochOverflow(epoch))?;
        Ok(Retirement {
            namespace: self.config.namespace,
            epoch,
            first,
            last,
        })
    }

    async fn is_retired(&mut self, epoch: Epoch) -> Result<bool, Error> {
        let retirement = self.retirement(epoch)?;
        loop {
            match self.history.retired(retirement).await {
                Ok(retired) => return Ok(retired),
                Err(RequestError::Backpressured) => reschedule().await,
                Err(RequestError::Closed) => return Err(Error::HistoryClosed),
            }
        }
    }

    async fn descriptor(&mut self, epoch: Epoch) -> Result<EpochDescriptor<S>, Error> {
        self.gate
            .wait(epoch)
            .await
            .map_err(|_| Error::GateClosed(epoch))?;
        let scheme = self
            .provider
            .scheme(epoch)
            .ok_or(Error::MissingScheme(epoch))?;
        if scheme.recovery_namespace() != self.config.namespace {
            return Err(Error::NamespaceMismatch(epoch));
        }
        let retirement = self.retirement(epoch)?;
        Ok(EpochDescriptor {
            journal: JournalConfig {
                identity: JournalIdentity::new(
                    scheme.as_ref(),
                    epoch,
                    retirement.first,
                    retirement.last,
                    self.config.engine.window,
                ),
                partition: format!(
                    "{}-{}",
                    self.config.engine.journal_partition_prefix,
                    epoch.get()
                ),
                write_buffer: self.config.engine.journal_write_buffer,
                replay_buffer: self.config.engine.journal_replay_buffer,
                heights_per_section: self.config.engine.journal_heights_per_section,
                compression: self.config.engine.journal_compression,
                page_cache: self.config.engine.journal_page_cache.clone(),
            },
            scheme,
            journal_archived: false,
        })
    }

    async fn start_engine(
        &mut self,
        epoch: Epoch,
        descriptor: EpochDescriptor<S>,
    ) -> Result<(), Error> {
        if self.active.contains_key(&epoch) {
            return Ok(());
        }
        debug_assert!(self.active.len() <= self.config.active_old_epochs);
        let network = self
            .muxer
            .register(epoch.get())
            .await
            .map_err(|source| Error::Mux { epoch, source })?;
        let identity = &descriptor.journal.identity;
        let config = AggregationConfig {
            epoch,
            first: identity.first,
            last: identity.last,
            scheme: descriptor.scheme.as_ref().clone(),
            automaton: self.config.automaton.clone(),
            reporter: self.certificate_reporter.clone(),
            blocker: self.config.blocker.clone(),
            priority_acks: self.config.engine.priority_acks,
            rebroadcast_timeout: self.config.engine.rebroadcast_timeout,
            recovery_after_rebroadcasts: self.config.engine.recovery_after_rebroadcasts,
            recoverer: self.recovery.clone(),
            window: self.config.engine.window,
            journal_partition: descriptor.journal.partition.clone(),
            journal_write_buffer: descriptor.journal.write_buffer,
            journal_replay_buffer: descriptor.journal.replay_buffer,
            journal_heights_per_section: descriptor.journal.heights_per_section,
            journal_compression: descriptor.journal.compression,
            journal_page_cache: descriptor.journal.page_cache.clone(),
            strategy: self.config.strategy.clone(),
        };
        let (engine, mailbox) = Engine::new(
            self.context.child("engine").with_attribute("epoch", epoch),
            config,
        );
        self.register(epoch, mailbox).await?;
        let (handle, stopper) = engine.start_stoppable(network);
        self.active_futures.push(Box::pin(async move {
            let outcome = handle.await.expect("aggregation engine failed");
            (epoch, outcome)
        }));
        self.active.insert(
            epoch,
            Active {
                stopper: Some(stopper),
                stopping: false,
                descriptor,
            },
        );
        debug_assert!(self.active.len() <= self.config.active_old_epochs + 1);
        Ok(())
    }

    async fn register(
        &mut self,
        epoch: Epoch,
        mailbox: commonware_consensus::aggregation::Mailbox<S, D>,
    ) -> Result<(), Error> {
        loop {
            match self
                .router
                .register(self.config.namespace, epoch, mailbox.clone())
            {
                Unreliable::Outcome(Feedback::Ok | Feedback::Backoff) => return Ok(()),
                Unreliable::Outcome(Feedback::Closed) => return Err(Error::RouterClosed),
                Unreliable::Rejected => reschedule().await,
            }
        }
    }

    async fn unregister(&mut self, epoch: Epoch) -> Result<(), Error> {
        loop {
            match self.router.unregister(self.config.namespace, epoch) {
                Unreliable::Outcome(Feedback::Ok | Feedback::Backoff) => return Ok(()),
                Unreliable::Outcome(Feedback::Closed) => return Err(Error::RouterClosed),
                Unreliable::Rejected => reschedule().await,
            }
        }
    }

    async fn stop(&mut self, epoch: Epoch) -> Result<(), Error> {
        if let Some(active) = self.active.get_mut(&epoch)
            && let Some(stopper) = active.stopper.take()
        {
            active.stopping = true;
            stopper.stop();
        }
        // The engine completion branch owns the journal-sync barrier. Poll it
        // directly here before another route is allowed to consume the slot.
        while self.active.contains_key(&epoch) {
            let Some((completed, outcome)) = self.active_futures.next().await else {
                unreachable!("active engine missing completion future");
            };
            self.completed(completed, outcome).await?;
        }
        Ok(())
    }

    async fn completed(&mut self, epoch: Epoch, outcome: EngineOutcome) -> Result<(), Error> {
        let Some(active) = self.active.remove(&epoch) else {
            return Ok(());
        };
        self.unregister(epoch).await?;
        if outcome == EngineOutcome::Stopped && !active.stopping {
            return Err(Error::EngineStopped(epoch));
        }
        if outcome == EngineOutcome::Stopped {
            self.degraded.insert(epoch);
        }
        self.parked.insert(epoch, active.descriptor);
        self.schedule_parked();
        self.update_lifecycle_metrics();
        Ok(())
    }

    async fn archive(&mut self, certificate: Certificate<S, D>) -> Result<(), Error> {
        let key = RecoveryKey {
            namespace: self.config.namespace,
            epoch: certificate.epoch,
            position: certificate.item.position,
        };
        // The request is asynchronous with respect to the engine reporter. If
        // ingress is backpressured, the synced journal remains authoritative
        // and a parked pass will replay it later.
        match self.history.archive(key, certificate.encode()).await {
            Ok(history::ArchiveStatus::Stored | history::ArchiveStatus::Duplicate)
            | Err(RequestError::Backpressured) => Ok(()),
            Ok(history::ArchiveStatus::Rejected) => Err(Error::HistoryRejected {
                epoch: certificate.epoch,
                height: certificate.item.position,
            }),
            Err(RequestError::Closed) => Err(Error::HistoryClosed),
        }
    }

    fn schedule_parked(&mut self) {
        if !self.parked_running.is_empty() {
            return;
        }
        let epoch = next_parked_epoch(&self.parked, self.parked_cursor);
        if let Some(epoch) = epoch {
            self.schedule_epoch(epoch);
        }
    }

    fn schedule_epoch(&mut self, epoch: Epoch) {
        if !self.parked_running.insert(epoch) {
            return;
        }
        let descriptor = self.parked.get(&epoch).expect("parked epoch missing");
        let storage = self
            .context
            .child("parked_storage")
            .with_attribute("epoch", epoch);
        let mut verifier = self
            .context
            .child("parked_verifier")
            .with_attribute("epoch", epoch);
        let journal = descriptor.journal.clone();
        let journal_archived = descriptor.journal_archived;
        let provider = self.provider.clone();
        let scheme = descriptor.scheme.clone();
        let strategy = self.config.strategy.clone();
        let mut history = self.history.clone();
        let mut recovery = self.recovery.clone();
        let missing_batch = self.config.parked_missing_batch;
        self.parked_futures.push(Box::pin(async move {
            let outcome = parked::recover(
                storage,
                journal,
                &provider,
                &mut verifier,
                scheme.as_ref(),
                &strategy,
                &mut history,
                &mut recovery,
                missing_batch,
                journal_archived,
            )
            .await;
            (epoch, outcome)
        }));
    }

    fn parked_completed(
        &mut self,
        epoch: Epoch,
        outcome: Result<ParkedOutcome, parked::Error>,
    ) -> Result<(), Error> {
        self.parked_running.remove(&epoch);
        self.parked_cursor = Some(epoch);
        match outcome {
            Ok(ParkedOutcome::Parked { journal_archived }) => {
                if let Some(descriptor) = self.parked.get_mut(&epoch) {
                    descriptor.journal_archived |= journal_archived;
                }
                Ok(())
            }
            Err(parked::Error::HistoryBackpressured) => Ok(()),
            Ok(ParkedOutcome::Retired) => {
                self.parked.remove(&epoch);
                self.degraded.remove(&epoch);
                self.schedule_parked();
                self.update_lifecycle_metrics();
                Ok(())
            }
            Err(source) => Err(Error::Parked { epoch, source }),
        }
    }

    fn update_lifecycle_metrics(&self) {
        let _ = self.parked_epochs.try_set(self.parked.len());
        let _ = self.degraded_epochs.try_set(self.degraded.len());
        let oldest = self
            .active
            .iter()
            .find_map(|(epoch, active)| active.descriptor.scheme.me().is_some().then_some(epoch))
            .into_iter()
            .chain(
                self.parked.iter().find_map(|(epoch, descriptor)| {
                    descriptor.scheme.me().is_some().then_some(epoch)
                }),
            )
            .min();
        let _ = self
            .retained_key_age_epochs
            .try_set(oldest.map_or(0, |epoch| {
                self.current_epoch.get().saturating_sub(epoch.get())
            }));
    }

    async fn shutdown(&mut self) -> Result<(), Error> {
        for active in self.active.values_mut() {
            if let Some(stopper) = active.stopper.take() {
                active.stopping = true;
                stopper.stop();
            }
        }
        while let Some((epoch, _)) = self.active_futures.next().await {
            self.active.remove(&epoch);
            self.unregister(epoch).await?;
        }
        Ok(())
    }
}

fn next_parked_epoch<T>(parked: &BTreeMap<Epoch, T>, cursor: Option<Epoch>) -> Option<Epoch> {
    cursor
        .and_then(|cursor| {
            parked
                .range((Excluded(cursor), Unbounded))
                .next()
                .map(|(epoch, _)| *epoch)
        })
        .or_else(|| parked.keys().next().copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::orchestrator::aggregation::{
        Actor as HistoryActor, ArchiveStatus, AuthenticatedEpoch, Config as HistoryConfig,
    };
    use commonware_codec::Read;
    use commonware_consensus::{
        Automaton,
        aggregation::{
            Journal, RecoveryCoordinator, scheme,
            types::{Ack, Item},
        },
        types::Height,
    };
    use commonware_cryptography::{Hasher as _, Sha256, certificate::Scoped, ed25519::PublicKey};
    use commonware_macros::test_traced;
    use commonware_p2p::{
        Blocker,
        simulated::{Config as NetworkConfig, Network},
        utils::mux::Muxer,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Quota, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{archive::immutable, metadata};
    use commonware_utils::{
        NZU16, NZU64, NZUsize, NonZeroDuration, acknowledgement::Exact, non_empty,
        ordered::Committee, sync::Mutex,
    };
    use std::{num::NonZeroU32, sync::Arc};

    type TestScheme = scheme::ed25519::Scheme;
    type TestDigest = commonware_cryptography::sha256::Digest;

    #[derive(Clone)]
    struct TestProvider {
        namespace: RecoveryNamespace,
        oldest: Epoch,
        epochs: Arc<BTreeMap<Epoch, AuthenticatedEpoch<TestScheme>>>,
        schemes: Arc<BTreeMap<Epoch, Arc<TestScheme>>>,
    }

    impl history::Provider<TestScheme> for TestProvider {
        fn epoch(
            &self,
            namespace: RecoveryNamespace,
            epoch: Epoch,
        ) -> Option<AuthenticatedEpoch<TestScheme>> {
            (namespace == self.namespace)
                .then(|| self.epochs.get(&epoch).cloned())
                .flatten()
        }

        fn oldest_epoch(&self, namespace: RecoveryNamespace) -> Option<Epoch> {
            (namespace == self.namespace).then_some(self.oldest)
        }
    }

    impl SchemeProvider for TestProvider {
        type Scope = Epoch;
        type Scheme = TestScheme;

        fn scoped(&self, scope: Epoch) -> Option<Scoped<TestScheme>> {
            self.schemes.get(&scope).cloned().map(Scoped::scheme)
        }
    }

    #[derive(Clone, Default)]
    struct PendingApplication(
        Arc<Mutex<BTreeMap<Height, commonware_utils::channel::oneshot::Sender<TestDigest>>>>,
    );

    impl Automaton for PendingApplication {
        type Context = Height;
        type Digest = TestDigest;

        async fn propose(
            &mut self,
            position: Height,
        ) -> commonware_utils::channel::oneshot::Receiver<Self::Digest> {
            let (sender, receiver) = commonware_utils::channel::oneshot::channel();
            self.0.lock().insert(position, sender);
            receiver
        }

        async fn verify(
            &mut self,
            _: Height,
            _: Self::Digest,
        ) -> commonware_utils::channel::oneshot::Receiver<bool> {
            commonware_utils::channel::oneshot::channel().1
        }
    }

    #[derive(Clone)]
    struct NoopBlocker;

    impl Blocker for NoopBlocker {
        type PublicKey = PublicKey;

        fn block(&mut self, _: Self::PublicKey) -> Feedback {
            Feedback::Ok
        }

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            let (_, receiver) = commonware_utils::channel::ring::channel(NZUsize!(1));
            receiver
        }
    }

    fn history_config(
        context: &deterministic::Context,
        namespace: RecoveryNamespace,
        codec_config: <<TestScheme as Verifier>::Certificate as Read>::Cfg,
        suffix: &str,
    ) -> HistoryConfig<<<TestScheme as Verifier>::Certificate as Read>::Cfg> {
        HistoryConfig {
            namespace,
            archive: immutable::Config {
                metadata_partition: format!("lifecycle_archive_metadata_{suffix}"),
                freezer_table_partition: format!("lifecycle_archive_table_{suffix}"),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 4,
                freezer_table_resize_chunk_size: 32,
                freezer_key_partition: format!("lifecycle_archive_keys_{suffix}"),
                freezer_key_page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
                freezer_value_partition: format!("lifecycle_archive_values_{suffix}"),
                freezer_value_target_size: 1024 * 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("lifecycle_archive_ordinal_{suffix}"),
                items_per_section: NZU64!(64),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                codec_config,
            },
            metadata: metadata::Config {
                partition: format!("lifecycle_retirement_{suffix}"),
                codec_config: (),
            },
            mailbox_size: NZUsize!(32),
        }
    }

    fn journal_config(
        context: &deterministic::Context,
        scheme: &TestScheme,
        epoch: Epoch,
        first: Height,
        last: Height,
        partition: &str,
    ) -> JournalConfig {
        JournalConfig {
            identity: JournalIdentity::new::<TestScheme, TestDigest>(
                scheme,
                epoch,
                first,
                last,
                NZU64!(2),
            ),
            partition: partition.into(),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            heights_per_section: NZU64!(4),
            compression: None,
            page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
        }
    }

    fn certificate(
        schemes: &[TestScheme],
        epoch: Epoch,
        position: Height,
    ) -> Certificate<TestScheme, TestDigest> {
        let item = Item {
            position,
            digest: Sha256::hash(&[&position.get().to_be_bytes()]),
        };
        let acks: Vec<_> = schemes
            .iter()
            .filter_map(|scheme| Ack::sign(scheme, item.clone()))
            .collect();
        Certificate::from_acks(&schemes[0], epoch, non_empty![@acks.iter()], &Sequential).unwrap()
    }

    #[test]
    fn parked_round_robin_does_not_starve_newer_epochs() {
        let parked = (1..=4)
            .map(|epoch| (Epoch::new(epoch), ()))
            .collect::<BTreeMap<_, _>>();
        let mut cursor = None;
        let mut scheduled = Vec::new();
        for _ in 0..9 {
            let epoch = next_parked_epoch(&parked, cursor).unwrap();
            scheduled.push(epoch.get());
            // Every pass, including epoch 1, remains permanently incomplete.
            cursor = Some(epoch);
        }
        assert_eq!(scheduled, vec![1, 2, 3, 4, 1, 2, 3, 4, 1]);
    }

    #[test]
    fn reporter_ack_is_nonblocking_and_overflow_is_coalesced() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = mailbox::new(context.child("ingress"), NZUsize!(1));
            let (first, _) = Exact::handle();
            let (superseded, superseded_waiter) = Exact::handle();
            let (latest, _) = Exact::handle();

            assert_eq!(
                sender.enqueue(Message::Finalized {
                    epoch: Epoch::new(1),
                    acknowledgement: first,
                }),
                Feedback::Ok
            );
            assert_eq!(
                sender.enqueue(Message::Finalized {
                    epoch: Epoch::new(2),
                    acknowledgement: superseded,
                }),
                Feedback::Backoff
            );
            assert_eq!(
                sender.enqueue(Message::Finalized {
                    epoch: Epoch::new(3),
                    acknowledgement: latest,
                }),
                Feedback::Backoff
            );

            superseded_waiter
                .await
                .expect("coalesced report should be acknowledged immediately");
            let Some(Message::Finalized { epoch, .. }) = receiver.recv().await else {
                panic!("missing first report");
            };
            assert_eq!(epoch, Epoch::new(1));
            let Some(Message::Finalized { epoch, .. }) = receiver.recv().await else {
                panic!("missing latest report");
            };
            assert_eq!(epoch, Epoch::new(3));

            drop(receiver);
            let mut handler =
                Handler::<crate::dkg::tests::mocks::MockBlock<TestDigest, u64>, Exact> {
                    sender,
                    epocher: FixedEpocher::new(NZU64!(2)),
                    _block: PhantomData,
                };
            let mut cloned = handler.clone();
            assert_eq!(
                cloned.report(Update::Tip(
                    commonware_consensus::types::Round::zero(),
                    Height::zero(),
                    Sha256::hash(&[b"tip"]),
                )),
                Feedback::Ok
            );
            let block = Arc::new(crate::dkg::tests::mocks::MockBlock::new::<Sha256>(
                0,
                Sha256::hash(&[b"parent"]),
                Height::zero(),
                0,
            ));
            let (acknowledgement, acknowledged) = Exact::handle();
            assert_eq!(
                handler.report(Update::Block(block, acknowledgement)),
                Feedback::Closed
            );
            assert!(acknowledged.await.is_err());
        });
    }

    #[test]
    fn certificate_reporter_exposes_bounded_admission() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme::ed25519::fixture(&mut context, b"certificate-reporter", 1);
            let first_certificate = certificate(&fixture.schemes, Epoch::new(1), Height::new(1));
            let (sender, mut receiver) =
                mailbox::new_unreliable(context.child("certificates"), NZUsize!(1));
            let mut reporter = CertificateReporter { sender };

            assert_eq!(reporter.report(first_certificate.clone()), Feedback::Ok);
            assert_eq!(
                reporter.report(first_certificate.clone()),
                Feedback::Backoff
            );
            assert!(matches!(receiver.recv().await, Some(CertificateMessage(_))));
            assert_eq!(reporter.report(first_certificate), Feedback::Ok);
            drop(receiver);
            assert_eq!(
                reporter.report(certificate(&fixture.schemes, Epoch::new(1), Height::new(2),)),
                Feedback::Closed
            );
        });
    }

    #[test_traced]
    fn lifecycle_loop_advances_parks_retires_and_shuts_down() {
        deterministic::Runner::timed(Duration::from_secs(20)).start(|mut context| async move {
            const NAMESPACE: &[u8] = b"aggregation lifecycle transitions";
            let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 7);
            let committee = |indices: &[usize]| {
                Committee::try_from(
                    indices
                        .iter()
                        .map(|index| (fixture.participants[*index].clone(), 1))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            };
            let epoch_schemes = [
                // Small, growing, shrinking-overlap, and disjoint committees.
                TestScheme::signer(
                    NAMESPACE,
                    committee(&[0, 1]),
                    fixture.private_keys[0].clone(),
                )
                .unwrap(),
                TestScheme::signer(
                    NAMESPACE,
                    committee(&[0, 1, 2, 3, 4]),
                    fixture.private_keys[0].clone(),
                )
                .unwrap(),
                TestScheme::signer(
                    NAMESPACE,
                    committee(&[0, 3, 4]),
                    fixture.private_keys[0].clone(),
                )
                .unwrap(),
                TestScheme::signer(
                    NAMESPACE,
                    committee(&[5, 6]),
                    fixture.private_keys[5].clone(),
                )
                .unwrap(),
            ]
            .map(Arc::new);
            let namespace =
                <TestScheme as Scheme<TestDigest>>::recovery_namespace(epoch_schemes[0].as_ref());
            assert!(epoch_schemes.iter().all(|scheme| {
                <TestScheme as Scheme<TestDigest>>::recovery_namespace(scheme.as_ref()) == namespace
            }));

            let epocher = FixedEpocher::new(NZU64!(2));
            let mut epochs = BTreeMap::new();
            let mut schemes = BTreeMap::new();
            for epoch_number in 0..=7 {
                let epoch = Epoch::new(epoch_number);
                let scheme = epoch_schemes[(epoch_number / 2) as usize].clone();
                epochs.insert(
                    epoch,
                    AuthenticatedEpoch::new(
                        scheme.clone(),
                        epocher.first(epoch).unwrap(),
                        epocher.last(epoch).unwrap(),
                    )
                    .unwrap(),
                );
                schemes.insert(epoch, scheme);
            }
            let provider = TestProvider {
                namespace,
                oldest: Epoch::zero(),
                epochs: Arc::new(epochs),
                schemes: Arc::new(schemes),
            };

            let (history_actor, mut history) =
                HistoryActor::<_, TestScheme, TestDigest, _, _>::init(
                    context.child("history"),
                    history_config(
                        &context,
                        namespace,
                        epoch_schemes[0].certificate_codec_config(),
                        "transitions",
                    ),
                    provider.clone(),
                    Sequential,
                )
                .await
                .unwrap();
            let history_task = history_actor.start();
            let cleanup_signers = [
                epoch_schemes[0].as_ref().clone(),
                TestScheme::signer(
                    NAMESPACE,
                    committee(&[0, 1]),
                    fixture.private_keys[1].clone(),
                )
                .unwrap(),
            ];
            let cleanup_retirement = Retirement {
                namespace,
                epoch: Epoch::zero(),
                first: epocher.first(Epoch::zero()).unwrap(),
                last: epocher.last(Epoch::zero()).unwrap(),
            };
            for position in cleanup_retirement.first.get()..=cleanup_retirement.last.get() {
                let position = Height::new(position);
                assert_eq!(
                    history
                        .archive(
                            RecoveryKey {
                                namespace,
                                epoch: Epoch::zero(),
                                position,
                            },
                            certificate(&cleanup_signers, Epoch::zero(), position).encode(),
                        )
                        .await
                        .unwrap(),
                    ArchiveStatus::Stored
                );
            }
            assert!(history.retire(cleanup_retirement).await.unwrap().is_some());
            let parked_retirement = Retirement {
                namespace,
                epoch: Epoch::new(1),
                first: epocher.first(Epoch::new(1)).unwrap(),
                last: epocher.last(Epoch::new(1)).unwrap(),
            };
            for position in parked_retirement.first.get()..=parked_retirement.last.get() {
                let position = Height::new(position);
                assert_eq!(
                    history
                        .archive(
                            RecoveryKey {
                                namespace,
                                epoch: Epoch::new(1),
                                position,
                            },
                            certificate(&cleanup_signers, Epoch::new(1), position).encode(),
                        )
                        .await
                        .unwrap(),
                    ArchiveStatus::Stored
                );
            }
            let cleanup_journal = journal_config(
                &context,
                epoch_schemes[0].as_ref(),
                Epoch::zero(),
                cleanup_retirement.first,
                cleanup_retirement.last,
                "lifecycle_engine-0",
            );
            let (journal, certificates) = Journal::<_, TestScheme, TestDigest>::init(
                context.child("cleanup_journal"),
                cleanup_journal.clone(),
                &mut context,
                epoch_schemes[0].as_ref(),
                &Sequential,
            )
            .await
            .unwrap();
            assert!(certificates.is_empty());
            drop(journal);
            let (_recovery_coordinator, recovery) =
                RecoveryCoordinator::staged(context.child("recovery"), NZUsize!(16), NZUsize!(32));
            let (router_actor, _, registry) =
                crate::dkg::orchestrator::aggregation_router::Actor::new(
                    context.child("router"),
                    history.clone(),
                    provider.clone(),
                    recovery.clone(),
                    NZUsize!(32),
                );
            let router_task = router_actor.start();
            let (network, oracle) = Network::new_with_peers(
                context.child("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(1),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
                vec![fixture.participants[0].clone()],
            )
            .await;
            let network_task = network.start();
            let (sender, receiver) = oracle
                .control(fixture.participants[0].clone())
                .register(0, Quota::per_second(NonZeroU32::MAX))
                .await
                .unwrap();
            let (closed_sender, closed_receiver) = oracle
                .control(fixture.participants[0].clone())
                .register(1, Quota::per_second(NonZeroU32::MAX))
                .await
                .unwrap();
            let (muxer, mux_handle) = Muxer::new(context.child("mux"), sender, receiver, 32);
            let mux_task = muxer.start();
            let (_closed_mux, closed_mux_handle) = Muxer::new(
                context.child("closed_mux"),
                closed_sender,
                closed_receiver,
                1,
            );

            let (closed_history_actor, closed_history) =
                HistoryActor::<_, TestScheme, TestDigest, _, _>::init(
                    context.child("closed_history"),
                    history_config(
                        &context,
                        namespace,
                        epoch_schemes[0].certificate_codec_config(),
                        "closed",
                    ),
                    provider.clone(),
                    Sequential,
                )
                .await
                .unwrap();
            drop(closed_history_actor);
            let (closed_router, _, closed_registry) =
                crate::dkg::orchestrator::aggregation_router::Actor::new(
                    context.child("closed_router"),
                    closed_history.clone(),
                    provider.clone(),
                    recovery.clone(),
                    NZUsize!(1),
                );
            let (_closed_fence, closed_gate) = crate::dkg::fence::Fence::new(Epoch::new(7));
            let (mut closed_lifecycle, _) =
                Actor::<_, TestScheme, TestDigest, _, _, _, _, _, _, Exact>::new::<
                    crate::dkg::tests::mocks::MockBlock<TestDigest, u64>,
                >(
                    context.child("closed_lifecycle"),
                    Config {
                        namespace,
                        current_epoch: Epoch::new(2),
                        epocher: epocher.clone(),
                        active_old_epochs: 1,
                        mailbox_size: NZUsize!(1),
                        certificate_mailbox_size: NZUsize!(1),
                        parked_interval: Duration::from_secs(1),
                        parked_missing_batch: NZUsize!(1),
                        automaton: PendingApplication::default(),
                        blocker: NoopBlocker,
                        strategy: Sequential,
                        engine: EngineConfig {
                            priority_acks: false,
                            rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_secs(
                                10,
                            )),
                            recovery_after_rebroadcasts: NZU64!(10),
                            window: NZU64!(2),
                            journal_partition_prefix: "closed_lifecycle_engine".into(),
                            journal_write_buffer: NZUsize!(4096),
                            journal_replay_buffer: NZUsize!(4096),
                            journal_heights_per_section: NZU64!(4),
                            journal_compression: None,
                            journal_page_cache: CacheRef::from_pooler(
                                &context,
                                NZU16!(1024),
                                NZUsize!(10),
                            ),
                        },
                    },
                    provider.clone(),
                    closed_history,
                    closed_registry,
                    closed_gate,
                    recovery.clone(),
                    closed_mux_handle,
                );
            assert!(matches!(
                closed_lifecycle.discover_startup().await,
                Err(Error::HistoryClosed)
            ));
            let closed_certificate = certificate(
                &cleanup_signers,
                Epoch::new(1),
                epocher.first(Epoch::new(1)).unwrap(),
            );
            assert!(matches!(
                closed_lifecycle.archive(closed_certificate).await,
                Err(Error::HistoryClosed)
            ));
            drop(closed_router);

            let (_fence, gate) = crate::dkg::fence::Fence::new(Epoch::new(7));
            let application = PendingApplication::default();
            let requested = application.0.clone();
            let (mut actor, mut handler) =
                Actor::<_, TestScheme, TestDigest, _, _, _, _, _, _, Exact>::new::<
                    crate::dkg::tests::mocks::MockBlock<TestDigest, u64>,
                >(
                    context.child("lifecycle"),
                    Config {
                        namespace,
                        current_epoch: Epoch::new(2),
                        epocher: epocher.clone(),
                        active_old_epochs: 1,
                        mailbox_size: NZUsize!(8),
                        certificate_mailbox_size: NZUsize!(32),
                        parked_interval: Duration::from_secs(1),
                        parked_missing_batch: NZUsize!(2),
                        automaton: application,
                        blocker: NoopBlocker,
                        strategy: Sequential,
                        engine: EngineConfig {
                            priority_acks: false,
                            rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_secs(
                                10,
                            )),
                            recovery_after_rebroadcasts: NZU64!(10),
                            window: NZU64!(2),
                            journal_partition_prefix: "lifecycle_engine".into(),
                            journal_write_buffer: NZUsize!(4096),
                            journal_replay_buffer: NZUsize!(4096),
                            journal_heights_per_section: NZU64!(4),
                            journal_compression: None,
                            journal_page_cache: CacheRef::from_pooler(
                                &context,
                                NZU16!(1024),
                                NZUsize!(10),
                            ),
                        },
                    },
                    provider.clone(),
                    history.clone(),
                    registry,
                    gate,
                    recovery,
                    mux_handle,
                );

            assert!(actor.descriptor(Epoch::new(2)).await.is_ok());
            let schemes = actor.provider.schemes.clone();
            actor.provider.schemes = Arc::new(BTreeMap::new());
            assert!(matches!(
                actor.descriptor(Epoch::new(2)).await,
                Err(Error::MissingScheme(epoch)) if epoch == Epoch::new(2)
            ));
            let rogue = scheme::ed25519::fixture(&mut context, b"rogue lifecycle", 1)
                .schemes
                .into_iter()
                .next()
                .unwrap();
            actor.provider.schemes = Arc::new(BTreeMap::from([(Epoch::new(2), Arc::new(rogue))]));
            assert!(matches!(
                actor.descriptor(Epoch::new(2)).await,
                Err(Error::NamespaceMismatch(epoch)) if epoch == Epoch::new(2)
            ));
            actor.provider.schemes = schemes;

            let (closed_fence, closed_gate) = crate::dkg::fence::Fence::new(Epoch::new(1));
            drop(closed_fence);
            let gate = std::mem::replace(&mut actor.gate, closed_gate);
            assert!(matches!(
                actor.descriptor(Epoch::new(2)).await,
                Err(Error::GateClosed(epoch)) if epoch == Epoch::new(2)
            ));
            actor.gate = gate;

            let descriptor = actor.descriptor(Epoch::new(2)).await.unwrap();
            actor.parked.insert(Epoch::new(2), descriptor);
            actor.parked_running.insert(Epoch::new(2));
            actor
                .parked_completed(
                    Epoch::new(2),
                    Ok(ParkedOutcome::Parked {
                        journal_archived: true,
                    }),
                )
                .unwrap();
            assert!(actor.parked[&Epoch::new(2)].journal_archived);
            assert!(!actor.parked_running.contains(&Epoch::new(2)));
            actor
                .parked_completed(Epoch::new(2), Ok(ParkedOutcome::Retired))
                .unwrap();
            assert!(!actor.parked.contains_key(&Epoch::new(2)));
            actor
                .parked_completed(Epoch::new(2), Ok(ParkedOutcome::Retired))
                .unwrap();
            actor
                .completed(Epoch::new(2), EngineOutcome::Completed)
                .await
                .unwrap();

            let lifecycle_task = actor.start();
            let initial = epocher.first(Epoch::new(2)).unwrap();
            while !requested.lock().contains_key(&initial) {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert!(
                history
                    .pending_cleanups(namespace, NZUsize!(8))
                    .await
                    .unwrap()
                    .is_empty()
            );
            let report = |epoch: Epoch| {
                Arc::new(crate::dkg::tests::mocks::MockBlock::new::<Sha256>(
                    epoch.get(),
                    Sha256::hash(&[b"parent"]),
                    epocher.first(epoch).unwrap(),
                    epoch.get(),
                ))
            };
            let (acknowledgement, acknowledged) = Exact::handle();
            assert!(
                handler
                    .report(Update::Block(report(Epoch::new(5)), acknowledgement))
                    .accepted()
            );
            acknowledged.await.unwrap();
            let advanced = epocher.first(Epoch::new(5)).unwrap();
            while !requested.lock().contains_key(&advanced) {
                context.sleep(Duration::from_millis(1)).await;
            }
            while !history.retired(parked_retirement).await.unwrap() {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert!(
                history
                    .pending_cleanups(namespace, NZUsize!(8))
                    .await
                    .unwrap()
                    .is_empty()
            );

            let (acknowledgement, acknowledged) = Exact::handle();
            assert!(
                handler
                    .report(Update::Block(report(Epoch::new(7)), acknowledgement))
                    .accepted()
            );
            acknowledged.await.unwrap();
            let latest = epocher.first(Epoch::new(7)).unwrap();
            while !requested.lock().contains_key(&latest) {
                context.sleep(Duration::from_millis(1)).await;
            }

            drop(handler);
            lifecycle_task.await.unwrap().unwrap();
            context.child("stop").stop(0, None).await.unwrap();
            history_task.await.unwrap().unwrap();
            router_task.await.unwrap();
            mux_task.await.unwrap().unwrap();
            network_task.await.unwrap();
        });
    }
}
