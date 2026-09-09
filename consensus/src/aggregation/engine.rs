//! Fixed per-epoch aggregation engine.

use super::{
    Config, Journal, JournalConfig, JournalIdentity, Recoverer, metrics, scheme,
    types::{Ack, Certificate, Error, Item, RecoveryKey, RecoveryNamespace},
};
use crate::{
    Automaton, Reporter,
    types::{Epoch, Height, Participant},
};
use commonware_actor::{
    Unreliable,
    mailbox::{
        self, UnreliablePolicy, UnreliableReceiver as MailboxReceiver,
        UnreliableSender as MailboxSender,
    },
};
use commonware_cryptography::{Digest, certificate::Verifier};
use commonware_macros::select;
use commonware_p2p::{
    Blocker, Receiver, Recipients, Sender,
    utils::codec::{WrappedSender, wrap},
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics as RuntimeMetrics, Spawner, Storage,
    spawn_cell,
    telemetry::metrics::{GaugeExt, histogram, status::Status},
};
use commonware_utils::{
    PrioritySet,
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool as FuturesPool, Aborter},
    non_empty,
};
use futures::{
    Future, FutureExt as _,
    future::{self, Either},
};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::NonZeroUsize,
    time::{Duration, SystemTime},
};
use tracing::{debug, info, warn};

enum Pending<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    Unverified(BTreeMap<Participant, Ack<S, D>>),
    Verified(D, BTreeMap<Participant, Ack<S, D>>),
}

fn reaches_quorum<'a, S, D, I>(scheme: &S, acks: I) -> bool
where
    S: scheme::Scheme<D>,
    D: Digest,
    I: IntoIterator<Item = &'a Ack<S, D>>,
    S: 'a,
    D: 'a,
{
    let committee = scheme.participants();
    let weight = committee
        .sum_ordered_weights(acks.into_iter().map(|ack| ack.attestation.signer))
        .expect("verified signer indices must be ordered committee members");
    weight >= committee.quorum_weight::<S::Faults>()
}

struct DigestRequest<D: Digest> {
    position: Height,
    result: Result<D, Error>,
    timer: histogram::Timer,
}

/// Result of submitting a recovered certificate to an active engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateOutcome {
    /// The certificate was valid and advanced local state.
    Accepted,
    /// The position was already certified or is no longer active.
    Ignored,
    /// The epoch, range, or signature was invalid.
    Invalid,
    /// The bounded ingress queue was full; the caller should retry later.
    Backpressured,
}

/// Reason an aggregation engine stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineOutcome {
    /// Every position in the configured range has a certificate.
    Completed,
    /// The engine stopped before certifying the full range.
    Stopped,
}

struct CertificateMessage<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    certificate: Certificate<S, D>,
    response: oneshot::Sender<CertificateOutcome>,
}

impl<S: commonware_cryptography::certificate::Scheme, D: Digest> UnreliablePolicy
    for CertificateMessage<S, D>
{
    type Overflow = VecDeque<Self>;

    fn handle(_: &mut Self::Overflow, _: Self) -> bool {
        false
    }
}

/// Delivers recovered certificates to an active engine.
#[derive(Clone)]
pub struct Mailbox<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    sender: MailboxSender<CertificateMessage<S, D>>,
}

/// Gracefully stops one aggregation engine.
///
/// Dropping this handle also requests shutdown. The engine finishes its current operation,
/// cancels recovery, syncs its journal, and returns [`EngineOutcome::Stopped`].
pub struct Stopper(oneshot::Sender<()>);

impl Stopper {
    /// Requests graceful shutdown.
    pub fn stop(self) {
        let _ = self.0.send(());
    }
}

impl<S: commonware_cryptography::certificate::Scheme, D: Digest> Mailbox<S, D> {
    /// Validates and applies a recovered certificate.
    pub async fn submit(&mut self, certificate: Certificate<S, D>) -> CertificateOutcome {
        let (response, receiver) = oneshot::channel();
        if !self
            .sender
            .enqueue(CertificateMessage {
                certificate,
                response,
            })
            .accepted()
        {
            return CertificateOutcome::Backpressured;
        }
        receiver.await.unwrap_or(CertificateOutcome::Ignored)
    }
}

/// Aggregates every position in one immutable epoch and inclusive global range.
pub struct Engine<E, S, D, A, Z, B, T, R>
where
    E: BufferPooler + Clock + Spawner + Storage + RuntimeMetrics + CryptoRng,
    S: scheme::Scheme<D>,
    D: Digest,
    A: Automaton<Context = Height, Digest = D>,
    Z: Reporter<Activity = Certificate<S, D>>,
    B: Blocker<PublicKey = <S as Verifier>::PublicKey>,
    T: Strategy,
    R: Recoverer,
{
    context: ContextCell<E>,
    epoch: Epoch,
    first: Height,
    last: Height,
    scheme: S,
    automaton: A,
    reporter: Z,
    blocker: B,
    strategy: T,
    window: u64,
    frontier: Height,
    complete: bool,
    digest_requests: FuturesPool<'static, DigestRequest<D>>,
    digest_aborters: BTreeMap<Height, Aborter>,
    pending: BTreeMap<Height, Pending<S, D>>,
    confirmed: BTreeMap<Height, Certificate<S, D>>,
    rebroadcast_timeout: Duration,
    rebroadcast_deadlines: PrioritySet<Height, SystemTime>,
    recovery_after_rebroadcasts: u64,
    recovery_namespace: RecoveryNamespace,
    recoverer: R,
    recovery_ticks: BTreeMap<Height, u64>,
    recovery_requested: BTreeSet<RecoveryKey>,
    journal: Option<Journal<E, S, D>>,
    journal_config: JournalConfig,
    priority_acks: bool,
    certificate_mailbox: MailboxReceiver<CertificateMessage<S, D>>,
    // Keep the mailbox open so its receive branch remains pending without external senders.
    _mailbox_keepalive: Mailbox<S, D>,
    metrics: metrics::Metrics,
}

impl<E, S, D, A, Z, B, T, R> Engine<E, S, D, A, Z, B, T, R>
where
    E: BufferPooler + Clock + Spawner + Storage + RuntimeMetrics + CryptoRng,
    S: scheme::Scheme<D>,
    D: Digest,
    A: Automaton<Context = Height, Digest = D>,
    Z: Reporter<Activity = Certificate<S, D>>,
    B: Blocker<PublicKey = <S as Verifier>::PublicKey>,
    T: Strategy,
    R: Recoverer,
{
    /// Creates an engine. Panics if the configured range is empty.
    pub fn new(context: E, cfg: Config<S, D, A, Z, B, T, R>) -> (Self, Mailbox<S, D>) {
        assert!(cfg.first <= cfg.last, "aggregation range must not be empty");
        let metrics = metrics::Metrics::init(&context);
        let mailbox_capacity = NonZeroUsize::new(
            usize::try_from(cfg.window.get()).expect("aggregation window exceeds usize"),
        )
        .expect("aggregation window must be non-zero");
        let (sender, certificate_mailbox) =
            mailbox::new_unreliable(context.child("mailbox"), mailbox_capacity);
        let mailbox = Mailbox { sender };
        let recovery_namespace = cfg.scheme.recovery_namespace();
        let journal_config = JournalConfig {
            identity: JournalIdentity::new(&cfg.scheme, cfg.epoch, cfg.first, cfg.last, cfg.window),
            partition: cfg.journal_partition,
            write_buffer: cfg.journal_write_buffer,
            replay_buffer: cfg.journal_replay_buffer,
            heights_per_section: cfg.journal_heights_per_section,
            compression: cfg.journal_compression,
            page_cache: cfg.journal_page_cache,
        };
        let engine = Self {
            context: ContextCell::new(context),
            epoch: cfg.epoch,
            first: cfg.first,
            last: cfg.last,
            scheme: cfg.scheme,
            automaton: cfg.automaton,
            reporter: cfg.reporter,
            blocker: cfg.blocker,
            strategy: cfg.strategy,
            window: cfg.window.get(),
            frontier: cfg.first,
            complete: false,
            digest_requests: FuturesPool::default(),
            digest_aborters: BTreeMap::new(),
            pending: BTreeMap::new(),
            confirmed: BTreeMap::new(),
            rebroadcast_timeout: cfg.rebroadcast_timeout.into(),
            rebroadcast_deadlines: PrioritySet::new(),
            recovery_after_rebroadcasts: cfg.recovery_after_rebroadcasts.get(),
            recovery_namespace,
            recoverer: cfg.recoverer,
            recovery_ticks: BTreeMap::new(),
            recovery_requested: BTreeSet::new(),
            journal: None,
            journal_config,
            priority_acks: cfg.priority_acks,
            certificate_mailbox,
            _mailbox_keepalive: mailbox.clone(),
            metrics,
        };
        (engine, mailbox)
    }

    /// Starts the engine and reports whether it completed or was stopped.
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
        let (mut sender, mut receiver) = wrap(
            (),
            self.context.network_buffer_pool().clone(),
            network.0,
            network.1,
        );
        let restarted = self.init_journal().await;
        self.fill_window(restarted);
        let _ = self.metrics.frontier.try_set(self.frontier.get());
        let mut shutdown = self.context.stopped();
        futures::pin_mut!(stopping);
        // `select!` is biased, so alternate network and maintenance priority to prevent starvation.
        let mut network_first = true;
        let outcome = loop {
            if self.complete {
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
                    self.digest_aborters.remove(&position);
                    match result {
                        Ok(digest) => {
                            timer.observe(self.context.as_ref());
                            self.handle_digest(position, digest, &mut sender).await;
                        }
                        Err(err) => {
                            warn!(?err, %position, "automaton returned error");
                            self.metrics.digest.inc(Status::Dropped);
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
                    let Some(CertificateMessage {
                        certificate,
                        response,
                    }) = message
                    else {
                        unreachable!("engine retains a certificate mailbox sender");
                    };
                    let outcome = self.handle_external_certificate(certificate).await;
                    response.send_lossy(outcome);
                }
            }
        };

        self.cancel_all_recovery();
        if let Some(mut journal) = self.journal.take() {
            journal
                .sync_all()
                .await
                .expect("unable to sync aggregation journal");
        }
        outcome
    }

    fn fill_window(&mut self, recover_immediately: bool) {
        if self.complete {
            return;
        }
        let end = self
            .frontier
            .get()
            .saturating_add(self.window - 1)
            .min(self.last.get());
        for raw in self.frontier.get()..=end {
            let position = Height::new(raw);
            if self.pending.contains_key(&position) || self.confirmed.contains_key(&position) {
                continue;
            }
            self.pending
                .insert(position, Pending::Unverified(BTreeMap::new()));
            self.recovery_ticks.insert(
                position,
                if recover_immediately {
                    self.recovery_after_rebroadcasts
                } else {
                    0
                },
            );
            self.rebroadcast_deadlines
                .put(position, self.context.current() + self.rebroadcast_timeout);
            self.request_digest(position);
            if recover_immediately {
                self.fetch_recovery(position);
            }
        }
        debug_assert!(self.pending.len() + self.confirmed.len() <= self.window as usize);
    }

    fn request_digest(&mut self, position: Height) {
        assert!(!self.digest_aborters.contains_key(&position));
        let mut automaton = self.automaton.clone();
        let timer = self.metrics.digest_duration.timer(self.context.as_ref());
        let aborter = self.digest_requests.push(async move {
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
        });
        assert!(self.digest_aborters.insert(position, aborter).is_none());
    }

    async fn handle_digest(
        &mut self,
        position: Height,
        digest: D,
        sender: &mut WrappedSender<impl Sender<PublicKey = <S as Verifier>::PublicKey>, Ack<S, D>>,
    ) {
        let shares = match self.pending.remove(&position) {
            Some(Pending::Unverified(shares)) => shares,
            Some(Pending::Verified(_, _)) => {
                unreachable!("digest completed for an already verified position")
            }
            None => return,
        };
        let matching = shares
            .into_iter()
            .filter(|(_, ack)| ack.item.digest == digest)
            .collect();
        self.pending
            .insert(position, Pending::Verified(digest, matching));
        let Some(ack) = Ack::sign(&self.scheme, Item { position, digest }) else {
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
        if position < self.first || position > self.last || !self.pending.contains_key(&position) {
            return Err(Error::AckPosition(position));
        }
        let Some(signer) = self.scheme.participants().index(peer) else {
            return Err(Error::PeerMismatch);
        };
        if signer != ack.attestation.signer {
            return Err(Error::PeerMismatch);
        }
        match self.pending.get(&position).expect("checked") {
            Pending::Verified(digest, shares) if *digest != ack.item.digest => {
                return Err(Error::AckDigest(position));
            }
            Pending::Verified(_, shares) | Pending::Unverified(shares)
                if shares.contains_key(&signer) =>
            {
                return Err(Error::AckDuplicate(peer.to_string(), position));
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
        let shares = match pending {
            Pending::Unverified(shares) => shares,
            Pending::Verified(digest, _) if *digest != ack.item.digest => return false,
            Pending::Verified(_, shares) => shares,
        };
        shares.entry(ack.attestation.signer).or_insert(ack.clone());
        let matching: Vec<_> = shares
            .values()
            .filter(|other| other.item.digest == ack.item.digest)
            .collect();
        if !reaches_quorum(&self.scheme, matching.iter().copied()) {
            return true;
        }
        let certificate = Certificate::from_acks(
            &self.scheme,
            self.epoch,
            non_empty![@matching],
            &self.strategy,
        )
        .expect("verified signer-unique quorum must assemble");
        self.accept_certificate(certificate).await;
        true
    }

    async fn accept_certificate(&mut self, certificate: Certificate<S, D>) {
        let position = certificate.item.position;
        if certificate.epoch != self.epoch || position < self.frontier || position > self.last {
            return;
        }
        if let Some(existing) = self.confirmed.get(&position) {
            assert_eq!(
                existing.item.digest, certificate.item.digest,
                "conflicting certificates"
            );
            return;
        }
        self.record_certificate(certificate.clone()).await;
        self.reporter.report(certificate.clone());
        self.pending.remove(&position);
        self.digest_aborters.remove(&position);
        self.rebroadcast_deadlines.remove(&position);
        self.recovery_ticks.remove(&position);
        self.cancel_recovery(position);
        self.confirmed.insert(position, certificate);
        self.metrics.certificates.inc();
        while self.confirmed.remove(&self.frontier).is_some() {
            if self.frontier == self.last {
                self.complete = true;
                let _ = self.metrics.complete.try_set(1);
                break;
            }
            self.frontier = self.frontier.next();
        }
        let _ = self.metrics.frontier.try_set(self.frontier.get());
        self.fill_window(false);
    }

    async fn handle_external_certificate(
        &mut self,
        certificate: Certificate<S, D>,
    ) -> CertificateOutcome {
        let position = certificate.item.position;
        if certificate.epoch != self.epoch || position < self.first || position > self.last {
            return CertificateOutcome::Invalid;
        }
        if self.complete || position < self.frontier || self.confirmed.contains_key(&position) {
            return CertificateOutcome::Ignored;
        }
        if !self.pending.contains_key(&position) {
            return CertificateOutcome::Ignored;
        }
        if !certificate.verify_for(
            self.context.as_mut(),
            &self.scheme,
            self.epoch,
            self.first,
            self.last,
            &self.strategy,
        ) {
            return CertificateOutcome::Invalid;
        }
        self.accept_certificate(certificate).await;
        CertificateOutcome::Accepted
    }

    fn rebroadcast(
        &mut self,
        position: Height,
        sender: &mut WrappedSender<impl Sender<PublicKey = <S as Verifier>::PublicKey>, Ack<S, D>>,
    ) {
        if !self.pending.contains_key(&position) {
            return;
        }
        self.rebroadcast_deadlines
            .put(position, self.context.current() + self.rebroadcast_timeout);
        let ticks = self
            .recovery_ticks
            .get_mut(&position)
            .expect("active position missing recovery ticks");
        *ticks = ticks.saturating_add(1);
        if *ticks >= self.recovery_after_rebroadcasts {
            self.fetch_recovery(position);
        }
        let Some(me) = self.scheme.me() else {
            return;
        };
        let Some(Pending::Verified(_, shares)) = self.pending.get(&position) else {
            return;
        };
        if let Some(ack) = shares.get(&me).cloned() {
            sender.send(Recipients::All, ack, self.priority_acks);
        }
    }

    const fn recovery_key(&self, position: Height) -> RecoveryKey {
        RecoveryKey {
            namespace: self.recovery_namespace,
            epoch: self.epoch,
            position,
        }
    }

    fn fetch_recovery(&mut self, position: Height) {
        let key = self.recovery_key(position);
        if self.recovery_requested.contains(&key) {
            return;
        }
        if matches!(self.recoverer.fetch(key), Unreliable::Outcome(feedback) if feedback.accepted())
        {
            self.recovery_requested.insert(key);
        }
    }

    fn cancel_recovery(&mut self, position: Height) {
        let key = self.recovery_key(position);
        if self.recovery_requested.remove(&key) {
            self.recoverer.cancel(key);
        }
    }

    fn cancel_all_recovery(&mut self) {
        for key in std::mem::take(&mut self.recovery_requested) {
            self.recoverer.cancel(key);
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
        info!(epoch = %self.epoch, first = %self.first, last = %self.last, frontier = %self.frontier, "replayed aggregation journal");
        restarted
    }

    fn replay_certificate(&mut self, certificate: Certificate<S, D>) {
        let position = certificate.item.position;
        self.recoverer.cancel(self.recovery_key(position));
        if position >= self.frontier {
            if let Some(existing) = self.confirmed.insert(position, certificate.clone()) {
                assert_eq!(
                    existing.item.digest, certificate.item.digest,
                    "conflicting journal certificates"
                );
            }
            while self.confirmed.remove(&self.frontier).is_some() {
                if self.frontier == self.last {
                    self.complete = true;
                    let _ = self.metrics.complete.try_set(1);
                    break;
                }
                self.frontier = self.frontier.next();
            }
        }
        self.reporter.report(certificate);
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
        aggregation::{Recoverer, scheme::ed25519},
        simplex::mocks::wrapped::{Behavior, Scheme as WrappedScheme},
    };
    use commonware_actor::{Feedback, Unreliable};
    use commonware_cryptography::{
        Hasher, Sha256,
        certificate::{Scheme as _, mocks::Fixture},
    };

    #[derive(Clone)]
    struct NoopRecoverer;

    impl Recoverer for NoopRecoverer {
        fn fetch(&mut self, _: RecoveryKey) -> Unreliable<Feedback> {
            Unreliable::new(Feedback::Ok)
        }

        fn cancel(&mut self, _: RecoveryKey) -> Feedback {
            Feedback::Ok
        }
    }
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{N3f1, NZU16, NZUsize, NonZeroDuration, ordered::Committee, test_rng};
    use std::num::NonZeroU64;

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

    fn weighted_schemes(weights: [u64; 4]) -> Vec<ed25519::Scheme> {
        let mut rng = test_rng();
        let Fixture {
            participants,
            private_keys,
            ..
        } = ed25519::fixture(&mut rng, b"aggregation-weighted-quorum", 4);
        let committee =
            Committee::try_from(participants.into_iter().zip(weights).collect::<Vec<_>>()).unwrap();
        private_keys
            .into_iter()
            .map(|private_key| {
                ed25519::Scheme::signer(
                    b"aggregation-weighted-quorum",
                    committee.clone(),
                    private_key,
                )
                .unwrap()
            })
            .collect()
    }

    fn acks(
        schemes: &[ed25519::Scheme],
        count: usize,
    ) -> Vec<Ack<ed25519::Scheme, <Sha256 as Hasher>::Digest>> {
        let item = Item {
            position: Height::new(0),
            digest: Sha256::hash(&[b"weighted"]),
        };
        schemes
            .iter()
            .take(count)
            .map(|scheme| Ack::sign(scheme, item.clone()).unwrap())
            .collect()
    }

    #[test]
    fn certificate_formation_uses_signer_weight() {
        let epoch = Epoch::new(1);

        let schemes = weighted_schemes([4, 3, 2, 1]);
        let exact = acks(&schemes, 2);
        assert_eq!(
            schemes[0]
                .participants()
                .sum_ordered_weights(exact.iter().map(|ack| ack.attestation.signer))
                .unwrap(),
            schemes[0].participants().quorum_weight::<N3f1>(),
        );
        assert!(reaches_quorum(&schemes[0], exact.iter()));
        assert!(
            Certificate::from_acks(&schemes[0], epoch, non_empty![@exact.iter()], &Sequential,)
                .is_ok()
        );

        let schemes = weighted_schemes([1, 1, 1, 7]);
        let count_quorum = acks(&schemes, 3);
        assert!(!reaches_quorum(&schemes[0], count_quorum.iter()));
        assert!(
            Certificate::from_acks(
                &schemes[0],
                epoch,
                non_empty![@count_quorum.iter()],
                &Sequential,
            )
            .is_err()
        );

        let schemes = weighted_schemes([7, 1, 1, 1]);
        let fewer_signers = acks(&schemes, 1);
        assert!(reaches_quorum(&schemes[0], fewer_signers.iter()));
        assert!(
            Certificate::from_acks(
                &schemes[0],
                epoch,
                non_empty![@fewer_signers.iter()],
                &Sequential,
            )
            .is_ok()
        );
    }

    #[test]
    fn engine_waits_for_quorum_weight() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let schemes = weighted_schemes([1, 1, 1, 7]);
            let epoch = Epoch::new(1);
            let position = Height::new(0);
            let digest = Sha256::hash(&[b"weighted"]);
            let (mut engine, _) = Engine::new(
                context.child("engine"),
                Config {
                    epoch,
                    first: position,
                    last: position,
                    scheme: schemes[0].clone(),
                    automaton: NoopAutomaton,
                    reporter: NoopReporter(std::marker::PhantomData),
                    blocker: NoopBlocker,
                    priority_acks: false,
                    rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_secs(1)),
                    recovery_after_rebroadcasts: NonZeroU64::new(1).unwrap(),
                    recoverer: NoopRecoverer,
                    window: NonZeroU64::new(1).unwrap(),
                    journal_partition: "aggregation-weighted-quorum".to_string(),
                    journal_write_buffer: NZUsize!(4096),
                    journal_replay_buffer: NZUsize!(4096),
                    journal_heights_per_section: NonZeroU64::new(4).unwrap(),
                    journal_compression: None,
                    journal_page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
                    strategy: Sequential,
                },
            );
            let _ = engine.init_journal().await;
            engine
                .pending
                .insert(position, Pending::Verified(digest, BTreeMap::new()));

            // Three light signers meet the old count quorum but not the weight quorum.
            for ack in acks(&schemes, 3) {
                assert!(engine.insert_ack(ack).await);
            }
            assert!(!engine.complete);
            assert!(engine.pending.contains_key(&position));

            // Adding the heavyweight signer forms and records the certificate.
            let heavyweight = acks(&schemes, 4).pop().unwrap();
            assert!(engine.insert_ack(heavyweight).await);
            assert!(engine.complete);
            assert!(!engine.pending.contains_key(&position));
        });
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
            let (mut engine, _) = Engine::new(
                context.child("engine"),
                Config {
                    epoch,
                    first: position,
                    last: position,
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
                    journal_heights_per_section: NonZeroU64::new(4).unwrap(),
                    journal_compression: None,
                    journal_page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
                    strategy: Sequential,
                },
            );
            engine
                .pending
                .insert(position, Pending::Verified(digest, BTreeMap::new()));

            for scheme in schemes.iter().take(3) {
                let scheme = WrappedScheme::new(scheme.clone(), Behavior::Honest);
                let ack = Ack::sign(&scheme, Item { position, digest }).unwrap();
                assert!(engine.insert_ack(ack).await);
            }
        });
    }
}
