//! Fixed per-epoch aggregation engine.

use super::{
    Config, Fetcher as _, Recoverer, RegistrationError,
    journal::{Journal, JournalConfig},
    metrics, scheme,
    types::{Ack, Certificate, Error, Item, RecoveryKey, RecoveryNamespace, Scope},
};
use crate::{
    Automaton, Reporter,
    types::{Height, Participant},
};
use bytes::Bytes;
use commonware_actor::{
    Feedback, Unreliable,
    mailbox::{
        self, UnreliablePolicy, UnreliableReceiver as MailboxReceiver,
        UnreliableSender as MailboxSender,
    },
};
use commonware_codec::{Decode as _, Read};
use commonware_cryptography::{Digest, certificate::Verifier};
use commonware_macros::select;
use commonware_p2p::{
    Blocker, Receiver, Recipients, Sender,
    utils::codec::{WrappedSender, wrap},
};
use commonware_parallel::Strategy;
use commonware_resolver::{Outcome, Resolution};
use commonware_runtime::{
    Clock, ContextCell, Handle, Metrics as RuntimeMetrics, Spawner, Storage, spawn_cell,
    telemetry::metrics::{GaugeExt, histogram, status::Status},
};
use commonware_utils::{
    PrioritySet, Widen,
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool as FuturesPool, Aborter},
    non_empty,
    ordered::Quorum as _,
};
use futures::{
    Future, FutureExt as _,
    future::{self, Either},
};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, VecDeque},
    num::NonZeroUsize,
    time::{Duration, SystemTime},
};
use tracing::{debug, info, trace, warn};

enum Shares<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    AwaitingDigest(BTreeMap<Participant, Ack<S, D>>),
    Known(D, BTreeMap<Participant, Ack<S, D>>),
}

/// Recovery state of one uncertified position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recovery {
    /// Counts rebroadcast ticks until the recovery threshold.
    Waiting { ticks: u64 },
    /// Requests recovery on the next opportunity. A rejected fetch stays ready.
    Ready,
    /// The recoverer admitted the fetch.
    Requested,
}

/// State of one uncertified position in the window.
struct Pending<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    shares: Shares<S, D>,
    /// Aborts the digest request, if still outstanding, when the position leaves the window.
    _digest_request: Aborter,
    recovery: Recovery,
}

struct DigestRequest<D: Digest> {
    position: Height,
    result: Result<D, Error>,
    timer: histogram::Timer,
}

/// Result of delivering a recovered certificate to an active engine.
///
/// It converts into the [`Outcome`] for the delivered key. Other mappings can
/// penalize honest peers or retire a key the engine still needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateOutcome {
    /// The certificate was valid and advanced local state.
    Accepted,
    /// The position is not active or the engine has stopped.
    Ignored,
    /// The encoding, key, epoch, range, or signature was invalid.
    Invalid,
    /// The bounded ingress queue was full; the caller should retry later.
    Backpressured,
}

impl From<CertificateOutcome> for Outcome {
    fn from(outcome: CertificateOutcome) -> Self {
        match outcome {
            CertificateOutcome::Accepted => Self::Resolved(Resolution::Complete),
            CertificateOutcome::Ignored => Self::Ignored,
            CertificateOutcome::Invalid => Self::Invalid,
            // Not judged: retry later without scoring the peer.
            CertificateOutcome::Backpressured => Self::Unresolved,
        }
    }
}

/// Reason an aggregation engine stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineOutcome {
    /// Every position in the configured range has a certificate.
    Completed,
    /// The engine stopped before certifying the full range.
    Stopped,
}

/// An encoded certificate delivered for a recovery key.
pub(super) struct Request {
    pub(super) key: RecoveryKey,
    pub(super) value: Bytes,
    pub(super) response: oneshot::Sender<CertificateOutcome>,
}

impl UnreliablePolicy for Request {
    type Overflow = VecDeque<Self>;

    fn handle(_: &mut Self::Overflow, _: Self) -> bool {
        false
    }
}

/// Bounded ingress for encoded certificates recovered for one engine.
///
/// The engine decodes each certificate with its own scheme's bounded codec configuration, so one
/// [`super::Consumer`] can serve engines with different committees.
///
/// The mailbox bounds the number of queued certificates, not their size. Queued bytes are retained
/// until the engine decodes them, so the resolver transport must bound the size of each response.
#[derive(Clone)]
pub struct Mailbox {
    sender: MailboxSender<Request>,
}

/// Gracefully stops one aggregation engine.
///
/// Dropping this handle also requests shutdown. The engine finishes its current operation,
/// cancels recovery, and returns [`EngineOutcome::Stopped`]. Bind it to a named variable for as
/// long as the engine should run. `let (handle, _) = engine.start_stoppable(network)` drops it and
/// stops the engine immediately.
#[must_use = "dropping a Stopper stops its engine"]
pub struct Stopper(oneshot::Sender<()>);

impl Stopper {
    /// Requests graceful shutdown.
    pub fn stop(self) {
        let _ = self.0.send(());
    }
}

impl Mailbox {
    pub(super) fn new(
        metrics: impl RuntimeMetrics,
        capacity: NonZeroUsize,
    ) -> (Self, MailboxReceiver<Request>) {
        let (sender, receiver) = mailbox::new_unreliable(metrics, capacity);
        (Self { sender }, receiver)
    }

    /// Queues `value` as the certificate recovered for `key` and returns the engine's verdict.
    ///
    /// A full mailbox answers [`CertificateOutcome::Backpressured`] and a stopped engine answers
    /// [`CertificateOutcome::Ignored`]. The engine answers [`CertificateOutcome::Invalid`] for a
    /// certificate that does not decode or does not answer `key`. The receiver closes without a
    /// verdict if the engine stops before processing the certificate.
    pub fn deliver(&self, key: RecoveryKey, value: Bytes) -> oneshot::Receiver<CertificateOutcome> {
        let (response, receiver) = oneshot::channel();
        let outcome = match self.sender.enqueue(Request {
            key,
            value,
            response,
        }) {
            Unreliable::Rejected => CertificateOutcome::Backpressured,
            Unreliable::Outcome(feedback) if !feedback.accepted() => CertificateOutcome::Ignored,
            Unreliable::Outcome(_) => return receiver,
        };
        let (response, receiver) = oneshot::channel();
        response.send_lossy(outcome);
        receiver
    }

    /// Delivers `value` for `key` and waits for the verdict.
    #[cfg(test)]
    pub(super) async fn submit(&mut self, key: RecoveryKey, value: Bytes) -> CertificateOutcome {
        self.deliver(key, value)
            .await
            .unwrap_or(CertificateOutcome::Ignored)
    }
}

/// Aggregates every position in one immutable epoch and inclusive global range.
pub struct Engine<E, S, D, A, Z, B, T, R>
where
    E: Clock + Spawner + Storage + RuntimeMetrics + CryptoRng,
    S: scheme::Scheme<D>,
    D: Digest,
    A: Automaton<Context = Height, Digest = D>,
    Z: Reporter<Activity = Certificate<S, D>>,
    B: Blocker<PublicKey = <S as Verifier>::PublicKey>,
    T: Strategy,
    R: Recoverer,
{
    context: ContextCell<E>,
    scope: Scope,
    scheme: S,
    automaton: A,
    reporter: Z,
    blocker: B,
    strategy: T,
    window: u64,
    /// Lowest uncertified position, or `None` once the full range is certified.
    frontier: Option<Height>,
    digest_requests: FuturesPool<'static, DigestRequest<D>>,
    pending: BTreeMap<Height, Pending<S, D>>,
    confirmed: BTreeMap<Height, D>,
    rebroadcast_timeout: Duration,
    rebroadcast_deadlines: PrioritySet<Height, SystemTime>,
    recovery_after_rebroadcasts: u64,
    recovery_namespace: RecoveryNamespace,
    recovery: R::Fetcher,
    recovery_closed: bool,
    journal: Option<Journal<E, S, D>>,
    journal_config: JournalConfig,
    priority_acks: bool,
    certificate_codec: <Certificate<S, D> as Read>::Cfg,
    certificate_mailbox: MailboxReceiver<Request>,
    // Keep the mailbox open so its receive branch remains pending without external senders.
    _mailbox: Mailbox,
    metrics: metrics::Metrics,
}

impl<E, S, D, A, Z, B, T, R> Engine<E, S, D, A, Z, B, T, R>
where
    E: Clock + Spawner + Storage + RuntimeMetrics + CryptoRng,
    S: scheme::Scheme<D>,
    D: Digest,
    A: Automaton<Context = Height, Digest = D>,
    Z: Reporter<Activity = Certificate<S, D>>,
    B: Blocker<PublicKey = <S as Verifier>::PublicKey>,
    T: Strategy,
    R: Recoverer,
{
    /// Creates an engine and registers its scope with the configured recoverer.
    ///
    /// Recovered certificates for the scope reach this engine until it is dropped, which happens
    /// when its task exits or is aborted, or when an unstarted engine is dropped.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrationError::AlreadyRegistered`] while another engine for the same recovery
    /// namespace and epoch exists, and [`RegistrationError::Closed`] if the recoverer has stopped.
    ///
    /// # Panics
    ///
    /// Panics if the scheme's quorum is invalid.
    pub fn new(context: E, cfg: Config<S, D, A, Z, B, T, R>) -> Result<Self, RegistrationError> {
        let participants = cfg.scheme.participants();
        let faults: usize = Widen::widen(participants.max_faults::<S::Faults>());
        let quorum: usize = Widen::widen(participants.quorum::<S::Faults>());
        assert!(
            faults < quorum && quorum <= participants.len().saturating_sub(faults),
            "aggregation quorum must exceed the fault bound and be reachable by honest participants"
        );
        let mailbox_capacity =
            NonZeroUsize::try_from(cfg.window).expect("aggregation window exceeds usize");
        let (mailbox, certificate_mailbox) =
            Mailbox::new(context.child("mailbox"), mailbox_capacity);
        let recovery_namespace = cfg.scheme.recovery_namespace();
        let recovery =
            cfg.recoverer
                .register(recovery_namespace, cfg.scope.epoch(), mailbox.clone())?;
        let certificate_codec = cfg.scheme.certificate_codec_config();
        let metrics = metrics::Metrics::init(&context);
        let journal_config = JournalConfig {
            partition: cfg.journal_partition,
            scope: cfg.scope,
            write_buffer: cfg.journal_write_buffer,
            replay_buffer: cfg.journal_replay_buffer,
            positions_per_section: cfg.journal_positions_per_section,
            compression: cfg.journal_compression,
            page_cache: cfg.journal_page_cache,
        };
        let engine = Self {
            context: ContextCell::new(context),
            scope: cfg.scope,
            scheme: cfg.scheme,
            automaton: cfg.automaton,
            reporter: cfg.reporter,
            blocker: cfg.blocker,
            strategy: cfg.strategy,
            window: cfg.window.get(),
            frontier: Some(cfg.scope.first()),
            digest_requests: FuturesPool::default(),
            pending: BTreeMap::new(),
            confirmed: BTreeMap::new(),
            rebroadcast_timeout: cfg.rebroadcast_timeout.into(),
            rebroadcast_deadlines: PrioritySet::new(),
            recovery_after_rebroadcasts: cfg.recovery_after_rebroadcasts.get(),
            recovery_namespace,
            recovery_closed: false,
            recovery,
            journal: None,
            journal_config,
            priority_acks: cfg.priority_acks,
            certificate_codec,
            certificate_mailbox,
            _mailbox: mailbox,
            metrics,
        };
        Ok(engine)
    }

    /// Returns this engine's certificate ingress.
    #[cfg(test)]
    pub(super) fn mailbox(&self) -> Mailbox {
        self._mailbox.clone()
    }

    /// Starts the engine and reports whether it completed or was stopped.
    ///
    /// `network` must carry only this engine's epoch, for example through a per-epoch mux
    /// subchannel.
    ///
    /// # Panics
    ///
    /// The engine task panics if the journal partition belongs to another scope, has an
    /// unsupported format, or holds a certificate that fails verification.
    pub fn start(
        self,
        network: (
            impl Sender<PublicKey = <S as Verifier>::PublicKey>,
            impl Receiver<PublicKey = <S as Verifier>::PublicKey>,
        ),
    ) -> Handle<EngineOutcome> {
        self.start_inner(network, future::pending())
    }

    /// Starts an engine that can be stopped independently from its runtime context.
    pub fn start_stoppable(
        self,
        network: (
            impl Sender<PublicKey = <S as Verifier>::PublicKey>,
            impl Receiver<PublicKey = <S as Verifier>::PublicKey>,
        ),
    ) -> (Handle<EngineOutcome>, Stopper) {
        let (stopper, stopped) = oneshot::channel();
        (
            self.start_inner(network, stopped.map(|_| ())),
            Stopper(stopper),
        )
    }

    fn start_inner<F>(
        self,
        network: (
            impl Sender<PublicKey = <S as Verifier>::PublicKey>,
            impl Receiver<PublicKey = <S as Verifier>::PublicKey>,
        ),
        stopping: F,
    ) -> Handle<EngineOutcome>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut this = self;
        spawn_cell!(this.context, this.run(network, stopping))
    }

    async fn run<F>(
        mut self,
        network: (
            impl Sender<PublicKey = <S as Verifier>::PublicKey>,
            impl Receiver<PublicKey = <S as Verifier>::PublicKey>,
        ),
        stopping: F,
    ) -> EngineOutcome
    where
        F: Future<Output = ()> + Send,
    {
        let (mut sender, mut receiver) = wrap((), network.0, network.1);
        let restarted = self.init_journal().await;
        self.fill_window(restarted);
        self.set_frontier_metric();
        let mut shutdown = self.context.stopped();
        futures::pin_mut!(stopping);
        // `select!` is biased, so alternate network and maintenance priority to prevent starvation.
        let mut network_first = true;
        loop {
            if self.frontier.is_none() {
                break EngineOutcome::Completed;
            }
            let rebroadcast = match self.rebroadcast_deadlines.peek() {
                Some((_, &deadline)) => Either::Left(self.context.sleep_until(deadline)),
                None => Either::Right(future::pending()),
            };
            let maintenance = async {
                select! {
                    request = self.digest_requests.next_completed() => Either::Left(request),
                    _ = rebroadcast => Either::Right(Either::Left(())),
                    message = self.certificate_mailbox.recv() => Either::Right(Either::Right(message)),
                }
            };
            let event = if network_first {
                select! {
                    _ = &mut shutdown => { debug!("shutdown"); break EngineOutcome::Stopped; },
                    _ = &mut stopping => { debug!("stopping"); break EngineOutcome::Stopped; },
                    message = receiver.recv() => Either::Left(message),
                    maintenance = maintenance => Either::Right(maintenance),
                }
            } else {
                select! {
                    _ = &mut shutdown => { debug!("shutdown"); break EngineOutcome::Stopped; },
                    _ = &mut stopping => { debug!("stopping"); break EngineOutcome::Stopped; },
                    maintenance = maintenance => Either::Right(maintenance),
                    message = receiver.recv() => Either::Left(message),
                }
            };
            network_first = !network_first;

            match event {
                Either::Left(message) => {
                    let (peer, ack) = match message {
                        Ok(value) => value,
                        Err(err) => {
                            warn!(?err, "aggregation ack receiver failed");
                            break EngineOutcome::Stopped;
                        }
                    };
                    let mut guard = self.metrics.acks.guard(Status::Invalid);
                    let ack = match ack {
                        Ok(ack) => ack,
                        Err(err) => {
                            commonware_p2p::block!(self.blocker, peer, ?err, "ack decode failed");
                            continue;
                        }
                    };
                    if let Err(err) = self.validate_ack(&ack, &peer) {
                        if err.blockable() {
                            commonware_p2p::block!(
                                self.blocker,
                                peer,
                                ?err,
                                "ack validation failed"
                            );
                        } else {
                            trace!(?err, ?peer, "ack ignored");
                        }
                        continue;
                    }
                    if self.insert_ack(ack).await {
                        guard.set(Status::Success);
                    } else {
                        guard.set(Status::Failure);
                    }
                }
                Either::Right(Either::Left(request)) => {
                    let Ok(request) = request else {
                        continue;
                    };
                    let DigestRequest {
                        position,
                        result,
                        timer,
                    } = request;
                    match result {
                        Ok(digest) => {
                            timer.observe(self.context.as_ref());
                            self.handle_digest(position, digest, &mut sender).await;
                        }
                        Err(err) => {
                            warn!(?err, %position, "automaton returned error");
                            self.metrics.digest.inc(Status::Dropped);
                            self.recover_declined(position);
                        }
                    }
                }
                Either::Right(Either::Right(Either::Left(()))) => {
                    let (position, _) = self
                        .rebroadcast_deadlines
                        .pop()
                        .expect("deadline disappeared");
                    self.rebroadcast(position, &mut sender);
                }
                Either::Right(Either::Right(Either::Right(message))) => {
                    let Some(Request {
                        key,
                        value,
                        response,
                    }) = message
                    else {
                        unreachable!("engine retains a certificate mailbox sender");
                    };
                    let outcome = match Certificate::decode_cfg(value, &self.certificate_codec) {
                        Ok(certificate) => self.handle_external_certificate(key, certificate).await,
                        Err(_) => CertificateOutcome::Invalid,
                    };
                    response.send_lossy(outcome);
                }
            }
        }
    }

    fn fill_window(&mut self, recover_immediately: bool) {
        let Some(frontier) = self.frontier else {
            return;
        };
        let end = frontier
            .get()
            .saturating_add(self.window - 1)
            .min(self.scope.last().get());
        for raw in frontier.get()..=end {
            let position = Height::new(raw);
            if self.pending.contains_key(&position) || self.confirmed.contains_key(&position) {
                continue;
            }
            let digest_request = self.request_digest(position);
            self.pending.insert(
                position,
                Pending {
                    shares: Shares::AwaitingDigest(BTreeMap::new()),
                    _digest_request: digest_request,
                    recovery: if recover_immediately {
                        Recovery::Ready
                    } else {
                        Recovery::Waiting { ticks: 0 }
                    },
                },
            );
            self.rebroadcast_deadlines
                .put(position, self.context.current() + self.rebroadcast_timeout);
            if recover_immediately {
                self.fetch_recovery(position);
            }
        }
        debug_assert!(self.pending.len() <= self.window as usize);
    }

    fn request_digest(&mut self, position: Height) -> Aborter {
        let mut automaton = self.automaton.clone();
        let timer = self.metrics.digest_duration.timer(self.context.as_ref());
        self.digest_requests.push(async move {
            let result = automaton
                .propose(position)
                .await
                .await
                .map_err(Error::AppProposeCanceled);
            DigestRequest {
                position,
                result,
                timer,
            }
        })
    }

    async fn handle_digest(
        &mut self,
        position: Height,
        digest: D,
        sender: &mut WrappedSender<impl Sender<PublicKey = <S as Verifier>::PublicKey>, Ack<S, D>>,
    ) {
        let Some(pending) = self.pending.get_mut(&position) else {
            return;
        };
        let Shares::AwaitingDigest(shares) = &mut pending.shares else {
            unreachable!("digest completed for an already verified position");
        };
        let mut matching = std::mem::take(shares);
        matching.retain(|_, ack| ack.item.digest == digest);
        pending.shares = Shares::Known(digest, matching);
        let item = Item {
            epoch: self.scope.epoch(),
            position,
            digest,
        };
        let Some(ack) = Ack::sign(&self.scheme, item) else {
            return;
        };
        sender.send(Recipients::All, ack.clone(), self.priority_acks);
        self.insert_ack(ack).await;
    }

    fn validate_ack(
        &mut self,
        ack: &Ack<S, D>,
        peer: &<S as Verifier>::PublicKey,
    ) -> Result<(), Error> {
        let position = ack.item.position;
        // Shares signed for another epoch can verify, so reject them before the pending check.
        // Honest peers never send them on this epoch's channel, but they are not blocked.
        if !self.scope.contains(&ack.item) {
            return Err(Error::AckScope(ack.item.epoch, position));
        }
        if !self.pending.contains_key(&position) {
            return Err(Error::AckPosition(position));
        }
        let Some(signer) = self.scheme.participants().index(peer) else {
            return Err(Error::PeerMismatch);
        };
        if signer != ack.attestation.signer {
            return Err(Error::PeerMismatch);
        }
        match &self.pending.get(&position).expect("checked").shares {
            Shares::Known(digest, _) if *digest != ack.item.digest => {
                return Err(Error::AckDigest(position));
            }
            Shares::Known(_, shares) | Shares::AwaitingDigest(shares)
                if shares.contains_key(&signer) =>
            {
                return Err(Error::AckDuplicate(signer, position));
            }
            _ => {}
        }
        if !ack.verify(self.context.as_mut(), &self.scheme, &self.strategy) {
            return Err(Error::InvalidAckSignature);
        }
        Ok(())
    }

    async fn insert_ack(&mut self, ack: Ack<S, D>) -> bool {
        let position = ack.item.position;
        let Some(pending) = self.pending.get_mut(&position) else {
            return false;
        };
        let digest = ack.item.digest;
        let (shares, known) = match &mut pending.shares {
            Shares::AwaitingDigest(shares) => (shares, false),
            Shares::Known(local, _) if *local != digest => return false,
            Shares::Known(_, shares) => (shares, true),
        };
        shares.entry(ack.attestation.signer).or_insert(ack);
        let matching = if known {
            shares.len()
        } else {
            shares
                .values()
                .filter(|ack| ack.item.digest == digest)
                .count()
        };
        let quorum: usize = Widen::widen(self.scheme.participants().quorum::<S::Faults>());
        if matching < quorum {
            return true;
        }
        let matching: Vec<_> = shares
            .values()
            .filter(|ack| ack.item.digest == digest)
            .collect();
        let certificate =
            Certificate::from_acks(&self.scheme, non_empty![@matching], &self.strategy)
                .expect("verified signer-unique quorum must assemble");
        self.accept_certificate(certificate, false).await;
        true
    }

    async fn accept_certificate(&mut self, certificate: Certificate<S, D>, recovered: bool) {
        let position = certificate.item.position;
        let pending = self
            .pending
            .remove(&position)
            .expect("accepted certificate must be pending");
        if pending.recovery == Recovery::Requested {
            self.recovery.cancel(position);
        }
        self.rebroadcast_deadlines.remove(&position);
        self.record_certificate(certificate.clone()).await;
        self.confirmed.insert(position, certificate.item.digest);
        self.reporter.report(certificate);
        self.metrics.certificates.inc();
        self.advance_frontier();
        self.set_frontier_metric();
        self.fill_window(recovered);
    }

    /// Admits a recovered certificate in this order: exact recovery key, scope, pending
    /// position, then signature.
    async fn handle_external_certificate(
        &mut self,
        key: RecoveryKey,
        certificate: Certificate<S, D>,
    ) -> CertificateOutcome {
        let position = certificate.item.position;
        if key != self.recovery_key(position) || !self.scope.contains(&certificate.item) {
            return CertificateOutcome::Invalid;
        }
        if !self.pending.contains_key(&position) {
            return CertificateOutcome::Ignored;
        }
        if !certificate.verify_for(
            self.context.as_mut(),
            &self.scheme,
            self.scope,
            &self.strategy,
        ) {
            return CertificateOutcome::Invalid;
        }
        self.accept_certificate(certificate, true).await;
        CertificateOutcome::Accepted
    }

    fn rebroadcast(
        &mut self,
        position: Height,
        sender: &mut WrappedSender<impl Sender<PublicKey = <S as Verifier>::PublicKey>, Ack<S, D>>,
    ) {
        let Some(pending) = self.pending.get_mut(&position) else {
            return;
        };
        self.rebroadcast_deadlines
            .put(position, self.context.current() + self.rebroadcast_timeout);
        if let Recovery::Waiting { ticks } = &mut pending.recovery {
            *ticks = ticks.saturating_add(1);
            if *ticks >= self.recovery_after_rebroadcasts {
                pending.recovery = Recovery::Ready;
            }
        }
        let recover = pending.recovery == Recovery::Ready;
        let ack = match (&pending.shares, self.scheme.me().and_then(|me| me.signer())) {
            (Shares::Known(_, shares), Some(signer)) => shares.get(&signer).cloned(),
            _ => None,
        };
        if recover {
            self.fetch_recovery(position);
        }
        if let Some(ack) = ack {
            sender.send(Recipients::All, ack, self.priority_acks);
        }
    }

    /// Recovers a position whose digest the application declined, without waiting for acks.
    ///
    /// A rejected fetch is retried on each later rebroadcast tick.
    fn recover_declined(&mut self, position: Height) {
        let Some(pending) = self.pending.get_mut(&position) else {
            return;
        };
        if let Recovery::Waiting { .. } = pending.recovery {
            pending.recovery = Recovery::Ready;
        }
        self.fetch_recovery(position);
    }

    const fn recovery_key(&self, position: Height) -> RecoveryKey {
        RecoveryKey {
            namespace: self.recovery_namespace,
            epoch: self.scope.epoch(),
            position,
        }
    }

    /// Requests recovery for a ready position. A rejected fetch stays ready for the next tick.
    fn fetch_recovery(&mut self, position: Height) {
        let pending = self
            .pending
            .get_mut(&position)
            .expect("recovery requested for an inactive position");
        if pending.recovery != Recovery::Ready {
            return;
        }
        match self.recovery.fetch(position) {
            Unreliable::Outcome(feedback) if feedback.accepted() => {
                pending.recovery = Recovery::Requested;
            }
            Unreliable::Outcome(Feedback::Closed) if !self.recovery_closed => {
                self.recovery_closed = true;
                warn!(epoch = %self.scope.epoch(), "certificate recovery is closed");
            }
            _ => {}
        }
    }

    async fn init_journal(&mut self) -> bool {
        let context = self.context.child("journal");
        let (journal, certificates) = Journal::init(
            context,
            self.journal_config.clone(),
            self.context.as_mut(),
            &self.scheme,
            &self.strategy,
        )
        .await
        .unwrap_or_else(|error| panic!("aggregation journal init failed: {error}"));
        let restarted = journal.restarted();
        for certificate in certificates {
            self.replay_certificate(certificate);
        }
        self.journal = Some(journal);
        info!(
            epoch = %self.scope.epoch(),
            first = %self.scope.first(),
            last = %self.scope.last(),
            frontier = ?self.frontier,
            "replayed aggregation journal"
        );
        restarted
    }

    /// Reports every journaled certificate and tracks only those at or above the frontier.
    fn replay_certificate(&mut self, certificate: Certificate<S, D>) {
        let position = certificate.item.position;
        if let Some(frontier) = self.frontier
            && position >= frontier
        {
            if let Some(existing) = self.confirmed.insert(position, certificate.item.digest) {
                assert_eq!(
                    existing, certificate.item.digest,
                    "conflicting journal certificates"
                );
            }
            self.advance_frontier();
        }
        self.reporter.report(certificate);
    }

    /// Advances the frontier past consecutive confirmed positions, clearing it after the last.
    fn advance_frontier(&mut self) {
        while let Some(frontier) = self.frontier
            && self.confirmed.remove(&frontier).is_some()
        {
            self.frontier = (frontier < self.scope.last()).then(|| frontier.next());
        }
        if self.frontier.is_none() {
            let _ = self.metrics.complete.try_set(1);
        }
    }

    fn set_frontier_metric(&self) {
        let frontier = self.frontier.unwrap_or(self.scope.last());
        let _ = self.metrics.frontier.try_set(frontier.get());
    }

    async fn record_certificate(&mut self, certificate: Certificate<S, D>) {
        self.journal
            .as_mut()
            .expect("journal unavailable")
            .append(certificate)
            .await
            .expect("unable to append aggregation journal");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregation::{Fetcher, scheme::ed25519},
        simplex::mocks::wrapped::{Behavior, Scheme as WrappedScheme},
        types::Epoch,
    };
    use commonware_actor::{Feedback, Unreliable};
    use commonware_cryptography::{Hasher, Sha256, certificate::mocks::Fixture};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZUsize, NonZeroDuration};
    use std::num::NonZeroU64;

    struct NoopRecoverer;

    impl Recoverer for NoopRecoverer {
        type Fetcher = Self;

        fn register(
            &self,
            _: RecoveryNamespace,
            _: Epoch,
            _: Mailbox,
        ) -> Result<Self, RegistrationError> {
            Ok(Self)
        }
    }

    impl Fetcher for NoopRecoverer {
        fn fetch(&mut self, _: Height) -> Unreliable<Feedback> {
            Unreliable::new(Feedback::Ok)
        }

        fn cancel(&mut self, _: Height) -> Feedback {
            Feedback::Ok
        }
    }

    #[derive(Clone)]
    struct NoopAutomaton;

    impl Automaton for NoopAutomaton {
        type Context = Height;
        type Digest = <Sha256 as Hasher>::Digest;

        async fn propose(&mut self, _context: Height) -> oneshot::Receiver<Self::Digest> {
            oneshot::channel().1
        }

        async fn verify(
            &mut self,
            _context: Height,
            _digest: Self::Digest,
        ) -> oneshot::Receiver<bool> {
            oneshot::channel().1
        }
    }

    #[derive(Clone)]
    struct NoopReporter<S: commonware_cryptography::certificate::Scheme>(
        std::marker::PhantomData<S>,
    );

    impl<S: commonware_cryptography::certificate::Scheme> Reporter for NoopReporter<S> {
        type Activity = Certificate<S, <Sha256 as Hasher>::Digest>;

        fn report(&mut self, _activity: Self::Activity) -> Feedback {
            Feedback::Ok
        }
    }

    #[derive(Clone)]
    struct NoopBlocker;

    impl Blocker for NoopBlocker {
        type PublicKey = commonware_cryptography::ed25519::PublicKey;

        fn block(&mut self, _peer: Self::PublicKey) -> Feedback {
            Feedback::Ok
        }

        fn blocked(&mut self) -> commonware_p2p::BlockedSubscription<Self::PublicKey> {
            let (_, receiver) =
                commonware_utils::channel::ring::channel(commonware_utils::NZUsize!(1));
            receiver
        }
    }

    #[test]
    #[should_panic(expected = "verified signer-unique quorum must assemble")]
    fn assembly_failure_panics() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let Fixture { schemes, .. } =
                ed25519::fixture(&mut context, b"aggregation-recovery-failure", 4);
            let epoch = Epoch::new(111);
            let position = Height::new(0);
            let digest = Sha256::hash(&[b"payload"]);
            let scheme = WrappedScheme::new(schemes[0].clone(), Behavior::RecoveryFailure);
            let mut engine = Engine::new(
                context.child("engine"),
                Config {
                    scope: Scope::new(epoch, position, position).unwrap(),
                    scheme,
                    automaton: NoopAutomaton,
                    reporter: NoopReporter(std::marker::PhantomData),
                    blocker: NoopBlocker,
                    priority_acks: false,
                    rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_secs(1)),
                    recovery_after_rebroadcasts: NonZeroU64::new(1).unwrap(),
                    recoverer: NoopRecoverer,
                    window: NonZeroU64::new(1).unwrap(),
                    journal_partition: "aggregation-recovery-failure".to_string(),
                    journal_write_buffer: NZUsize!(4096),
                    journal_replay_buffer: NZUsize!(4096),
                    journal_positions_per_section: NonZeroU64::new(4).unwrap(),
                    journal_compression: None,
                    journal_page_cache: CacheRef::new(NZU16!(1024), NZUsize!(10)),
                    strategy: Sequential,
                },
            )
            .unwrap();
            let digest_request = engine.request_digest(position);
            engine.pending.insert(
                position,
                Pending {
                    shares: Shares::Known(digest, BTreeMap::new()),
                    _digest_request: digest_request,
                    recovery: Recovery::Waiting { ticks: 0 },
                },
            );

            for scheme in schemes.iter().take(3) {
                let scheme = WrappedScheme::new(scheme.clone(), Behavior::Honest);
                let item = Item {
                    epoch,
                    position,
                    digest,
                };
                let ack = Ack::sign(&scheme, item).unwrap();
                assert!(engine.insert_ack(ack).await);
            }
        });
    }
}
