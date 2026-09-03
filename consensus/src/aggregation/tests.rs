use super::{
    CertificateOutcome, Config, Engine, EngineOutcome, Journal, JournalConfig, JournalError,
    JournalIdentity, Recoverer,
    scheme::{self, Scheme},
    types::{Ack, Certificate, Item, RecoveryKey, RecoveryNamespace},
};
use crate::{
    Automaton, Reporter,
    types::{Epoch, Height},
};
use commonware_actor::{Feedback, Unreliable};
use commonware_codec::Encode;
use commonware_cryptography::{
    Hasher, Sha256,
    certificate::{Scheme as _, mocks::Fixture},
    ed25519::PublicKey,
    sha256::Digest as Sha256Digest,
};
use commonware_macros::test_traced;
use commonware_p2p::{
    Message, Receiver as P2pReceiver, Recipients, Sender as _,
    simulated::{Control, Link, Network, Oracle, Receiver, Sender},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, Quota, Runner, Spawner as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, Context},
};
use commonware_utils::{
    NZU16, NZUsize, NonZeroDuration, channel::oneshot, non_empty, ordered::Quorum as _,
    probability, sync::Mutex,
};
use futures::future::join_all;
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

const NAMESPACE: &[u8] = b"aggregation fixed epoch test";
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
const LINK: Link = Link {
    latency: Duration::from_millis(1),
    jitter: Duration::ZERO,
    success_rate: probability!(1.0),
};

type Registrations = BTreeMap<PublicKey, (Sender<PublicKey, Context>, Receiver<PublicKey>)>;

fn digest(position: Height) -> Sha256Digest {
    Sha256::hash(&[&position.get().to_be_bytes()])
}

#[derive(Clone, Default)]
struct ImmediateApplication {
    requested: Arc<Mutex<Vec<Height>>>,
}

impl Automaton for ImmediateApplication {
    type Context = Height;
    type Digest = Sha256Digest;

    async fn propose(&mut self, position: Height) -> oneshot::Receiver<Self::Digest> {
        self.requested.lock().push(position);
        let (sender, receiver) = oneshot::channel();
        sender.send(digest(position)).unwrap();
        receiver
    }

    async fn verify(
        &mut self,
        position: Height,
        candidate: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        sender.send(candidate == digest(position)).unwrap();
        receiver
    }
}

#[derive(Clone, Default)]
struct PendingApplication {
    requested: Arc<Mutex<BTreeMap<Height, oneshot::Sender<Sha256Digest>>>>,
}

impl Automaton for PendingApplication {
    type Context = Height;
    type Digest = Sha256Digest;

    async fn propose(&mut self, position: Height) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();
        assert!(self.requested.lock().insert(position, sender).is_none());
        receiver
    }

    async fn verify(
        &mut self,
        _position: Height,
        _candidate: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        sender.send(true).unwrap();
        receiver
    }
}

#[derive(Clone, Default)]
struct ClosedApplication {
    requested: Arc<Mutex<Vec<Height>>>,
}

#[derive(Debug)]
struct ProcessingReceiver<R: P2pReceiver> {
    inner: R,
    processed: Arc<Mutex<BTreeSet<R::PublicKey>>>,
    last_returned: Option<R::PublicKey>,
}

impl<R: P2pReceiver> ProcessingReceiver<R> {
    fn new(inner: R, processed: Arc<Mutex<BTreeSet<R::PublicKey>>>) -> Self {
        Self {
            inner,
            processed,
            last_returned: None,
        }
    }
}

impl<R> P2pReceiver for ProcessingReceiver<R>
where
    R: P2pReceiver,
    R::PublicKey: Ord,
{
    type Error = R::Error;
    type PublicKey = R::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        if let Some(peer) = self.last_returned.take() {
            self.processed.lock().insert(peer);
        }
        let result = self.inner.recv().await;
        if let Ok((peer, _)) = &result {
            self.last_returned = Some(peer.clone());
        }
        result
    }
}

#[derive(Debug)]
struct CountingReceiver<R: P2pReceiver> {
    inner: R,
    processed: Arc<Mutex<usize>>,
    last_returned: bool,
}

impl<R: P2pReceiver> CountingReceiver<R> {
    fn new(inner: R, processed: Arc<Mutex<usize>>) -> Self {
        Self {
            inner,
            processed,
            last_returned: false,
        }
    }
}

impl<R: P2pReceiver> P2pReceiver for CountingReceiver<R> {
    type Error = R::Error;
    type PublicKey = R::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        if self.last_returned {
            *self.processed.lock() += 1;
        }
        let result = self.inner.recv().await;
        self.last_returned = result.is_ok();
        result
    }
}

impl Automaton for ClosedApplication {
    type Context = Height;
    type Digest = Sha256Digest;

    async fn propose(&mut self, position: Height) -> oneshot::Receiver<Self::Digest> {
        self.requested.lock().push(position);
        let (sender, receiver) = oneshot::channel();
        drop(sender);
        receiver
    }

    async fn verify(
        &mut self,
        _position: Height,
        _candidate: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        sender.send(true).unwrap();
        receiver
    }
}

#[derive(Clone)]
struct RecordingReporter<S: commonware_cryptography::certificate::Scheme> {
    certificates: Arc<Mutex<Vec<Certificate<S, Sha256Digest>>>>,
}

impl<S: commonware_cryptography::certificate::Scheme> Default for RecordingReporter<S> {
    fn default() -> Self {
        Self {
            certificates: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl<S: commonware_cryptography::certificate::Scheme> Reporter for RecordingReporter<S> {
    type Activity = Certificate<S, Sha256Digest>;

    fn report(&mut self, certificate: Self::Activity) -> Feedback {
        self.certificates.lock().push(certificate);
        Feedback::Ok
    }
}

async fn simulation<S: Scheme<Sha256Digest, PublicKey = PublicKey>>(
    context: Context,
    fixture: &Fixture<S>,
    connect: bool,
) -> (Oracle<PublicKey, Context>, Registrations) {
    let (network, oracle) = Network::new_with_peers(
        context.child("network"),
        commonware_p2p::simulated::Config {
            max_size: 1024 * 1024,
            max_peers_per_set: NZUsize!(fixture.participants.len()),
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
        },
        fixture.participants.clone(),
    )
    .await;
    network.start();

    let mut registrations = BTreeMap::new();
    for participant in &fixture.participants {
        let registration = oracle
            .control(participant.clone())
            .register(0, QUOTA)
            .await
            .unwrap();
        registrations.insert(participant.clone(), registration);
    }
    if connect {
        for first in &fixture.participants {
            for second in &fixture.participants {
                if first != second {
                    oracle
                        .add_link(first.clone(), second.clone(), LINK.clone())
                        .await
                        .unwrap();
                }
            }
        }
    }
    (oracle, registrations)
}

struct EngineScope {
    partition: String,
    epoch: Epoch,
    first: Height,
    last: Height,
    window: u64,
}

#[derive(Clone, Default)]
struct RecordingRecoverer {
    events: Arc<Mutex<Vec<(bool, RecoveryKey)>>>,
    reject_first: bool,
    rejected: Arc<Mutex<BTreeSet<RecoveryKey>>>,
}

impl RecordingRecoverer {
    fn rejecting_once() -> Self {
        Self {
            reject_first: true,
            ..Self::default()
        }
    }
}

impl Recoverer for RecordingRecoverer {
    fn fetch(&mut self, key: RecoveryKey) -> Unreliable<Feedback> {
        self.events.lock().push((true, key));
        if self.reject_first && self.rejected.lock().insert(key) {
            Unreliable::Rejected
        } else {
            Unreliable::new(Feedback::Ok)
        }
    }

    fn cancel(&mut self, key: RecoveryKey) -> Feedback {
        self.events.lock().push((false, key));
        Feedback::Ok
    }
}

fn config<S, A>(
    context: &Context,
    scheme: S,
    automaton: A,
    reporter: RecordingReporter<S>,
    blocker: Control<PublicKey, Context>,
    scope: EngineScope,
) -> Config<
    S,
    Sha256Digest,
    A,
    RecordingReporter<S>,
    Control<PublicKey, Context>,
    Sequential,
    RecordingRecoverer,
>
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    A: Automaton<Context = Height, Digest = Sha256Digest>,
{
    Config {
        epoch: scope.epoch,
        first: scope.first,
        last: scope.last,
        scheme,
        automaton,
        reporter,
        blocker,
        priority_acks: false,
        rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_millis(50)),
        recovery_after_rebroadcasts: NonZeroU64::new(3).unwrap(),
        recoverer: RecordingRecoverer::default(),
        window: NonZeroU64::new(scope.window).unwrap(),
        journal_partition: scope.partition,
        journal_write_buffer: NZUsize!(4096),
        journal_replay_buffer: NZUsize!(4096),
        journal_heights_per_section: NonZeroU64::new(4).unwrap(),
        journal_compression: None,
        journal_page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
    }
}

fn certificate<S>(
    fixture: &Fixture<S>,
    epoch: Epoch,
    position: Height,
) -> Certificate<S, Sha256Digest>
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
{
    let item = Item {
        position,
        digest: digest(position),
    };
    let quorum = usize::try_from(
        fixture.schemes[0]
            .participants()
            .quorum_count::<S::Faults>(),
    )
    .expect("quorum count must fit in usize");
    let acks: Vec<_> = fixture
        .schemes
        .iter()
        .take(quorum)
        .map(|scheme| Ack::sign(scheme, item.clone()).unwrap())
        .collect();
    Certificate::from_acks(
        &fixture.schemes[0],
        epoch,
        non_empty![@acks.iter()],
        &Sequential,
    )
    .unwrap()
}

fn all_online<S, F>(fixture: F)
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    F: FnOnce(&mut Context, &[u8], u32) -> Fixture<S>,
{
    deterministic::Runner::timed(Duration::from_secs(20)).start(|mut context| async move {
        let fixture = fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(7);
        let first = Height::new(10);
        let last = Height::new(25);
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, true).await;
        let mut handles = Vec::new();
        let mut observations = Vec::new();

        for (index, participant) in fixture.participants.iter().enumerate() {
            let child = context.child("validator").with_attribute("index", index);
            let application = ImmediateApplication::default();
            let requested = application.requested.clone();
            let reporter = RecordingReporter::default();
            let certificates = reporter.certificates.clone();
            let cfg = config(
                &child,
                fixture.schemes[index].clone(),
                application,
                reporter,
                oracle.control(participant.clone()),
                EngineScope {
                    partition: format!("aggregation-{index}"),
                    epoch,
                    first,
                    last,
                    window: 3,
                },
            );
            let (engine, _mailbox) = Engine::new(child.child("engine"), cfg);
            let network = registrations.remove(participant).unwrap();
            handles.push(engine.start(network));
            observations.push((requested, certificates));
        }

        for result in join_all(handles).await {
            assert_eq!(
                result.expect("aggregation engine failed"),
                EngineOutcome::Completed
            );
        }
        for (requested, certificates) in observations {
            let requested = requested.lock();
            assert_eq!(requested.len(), 16);
            assert!(
                requested
                    .iter()
                    .all(|position| *position >= first && *position <= last)
            );

            let certificates = certificates.lock();
            let certificates: BTreeMap<_, _> = certificates
                .iter()
                .map(|certificate| (certificate.item.position, certificate))
                .collect();
            assert_eq!(certificates.len(), 16);
            assert_eq!(certificates.first_key_value().unwrap().0, &first);
            assert_eq!(certificates.last_key_value().unwrap().0, &last);
        }
    });
}

#[test_traced("INFO")]
fn test_fixed_range_all_online() {
    all_online(scheme::ed25519::fixture);
}

#[test_traced("INFO")]
fn test_delayed_digest_broadcasts_quorum_share() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(8);
        let position = Height::new(40);
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, true).await;
        let delayed_application = PendingApplication::default();
        let delayed_requests = delayed_application.requested.clone();
        let processed = Arc::new(Mutex::new(BTreeSet::new()));

        let participant = fixture.participants[0].clone();
        let child = context.child("validator").with_attribute("index", 0);
        let cfg = config(
            &child,
            fixture.schemes[0].clone(),
            delayed_application,
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: "aggregation-delayed-digest-0".into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (engine, _mailbox) = Engine::new(child.child("engine"), cfg);
        let (sender, receiver) = registrations.remove(&participant).unwrap();
        let peers = [
            fixture.participants[1].clone(),
            fixture.participants[2].clone(),
        ];
        let receiver = ProcessingReceiver::new(receiver, processed.clone());
        let mut handles = vec![engine.start((sender, receiver))];

        for index in 1..3 {
            let participant = fixture.participants[index].clone();
            let child = context.child("validator").with_attribute("index", index);
            let cfg = config(
                &child,
                fixture.schemes[index].clone(),
                ImmediateApplication::default(),
                RecordingReporter::default(),
                oracle.control(participant.clone()),
                EngineScope {
                    partition: format!("aggregation-delayed-digest-{index}"),
                    epoch,
                    first: position,
                    last: position,
                    window: 1,
                },
            );
            let (engine, _mailbox) = Engine::new(child.child("engine"), cfg);
            handles.push(engine.start(registrations.remove(&participant).unwrap()));
        }

        while !peers.iter().all(|peer| processed.lock().contains(peer)) {
            context.sleep(Duration::from_millis(1)).await;
        }
        delayed_requests
            .lock()
            .remove(&position)
            .unwrap()
            .send(digest(position))
            .unwrap();

        for result in join_all(handles).await {
            assert_eq!(
                result.expect("aggregation engine failed"),
                EngineOutcome::Completed
            );
        }
    });
}

#[test_traced("INFO")]
fn test_ack_validation_ignores_non_blockable_inputs() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(81);
        let position = Height::new(410);
        let victim = fixture.participants[0].clone();
        let first_peer = fixture.participants[1].clone();
        let second_peer = fixture.participants[2].clone();
        let observer = fixture.participants[3].clone();
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, true).await;
        let application = ImmediateApplication::default();
        let requested = application.requested.clone();
        let reporter = RecordingReporter::default();
        let certificates = reporter.certificates.clone();
        let cfg = config(
            &context,
            fixture.schemes[0].clone(),
            application,
            reporter,
            oracle.control(victim.clone()),
            EngineScope {
                partition: "aggregation-ack-non-blockable".into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (engine, _mailbox) = Engine::new(context.child("engine"), cfg);
        let (sender, receiver) = registrations.remove(&victim).unwrap();
        let processed = Arc::new(Mutex::new(0));
        let receiver = CountingReceiver::new(receiver, processed.clone());
        let handle = engine.start((sender, receiver));
        let (mut first_sender, _) = registrations.remove(&first_peer).unwrap();
        let (mut second_sender, _) = registrations.remove(&second_peer).unwrap();
        let (_, mut observer_receiver) = registrations.remove(&observer).unwrap();

        while !requested.lock().contains(&position) {
            context.sleep(Duration::from_millis(1)).await;
        }
        observer_receiver.recv().await.unwrap();

        let outside = Ack::sign(
            &fixture.schemes[1],
            Item {
                position: position.next(),
                digest: digest(position.next()),
            },
        )
        .unwrap();
        first_sender.send(
            Recipients::One(victim.clone()),
            outside.clone().encode(),
            false,
        );
        first_sender.send(Recipients::One(victim.clone()), outside.encode(), false);
        while *processed.lock() < 1 {
            context.sleep(Duration::from_millis(1)).await;
        }

        let first_valid = Ack::sign(
            &fixture.schemes[1],
            Item {
                position,
                digest: digest(position),
            },
        )
        .unwrap();
        first_sender.send(
            Recipients::One(victim.clone()),
            first_valid.clone().encode(),
            false,
        );
        while *processed.lock() < 2 {
            context.sleep(Duration::from_millis(1)).await;
        }
        first_sender.send(
            Recipients::One(victim.clone()),
            first_valid.clone().encode(),
            false,
        );
        while *processed.lock() < 3 {
            context.sleep(Duration::from_millis(1)).await;
        }
        first_sender.send(Recipients::One(victim.clone()), first_valid.encode(), false);
        while *processed.lock() < 4 {
            context.sleep(Duration::from_millis(1)).await;
        }

        let wrong_digest = Ack::sign(
            &fixture.schemes[2],
            Item {
                position,
                digest: Sha256::hash(&[b"wrong ack digest"]),
            },
        )
        .unwrap();
        second_sender.send(
            Recipients::One(victim.clone()),
            wrong_digest.clone().encode(),
            false,
        );
        while *processed.lock() < 5 {
            context.sleep(Duration::from_millis(1)).await;
        }
        second_sender.send(
            Recipients::One(victim.clone()),
            wrong_digest.encode(),
            false,
        );
        while *processed.lock() < 6 {
            context.sleep(Duration::from_millis(1)).await;
        }

        let second_valid = Ack::sign(
            &fixture.schemes[2],
            Item {
                position,
                digest: digest(position),
            },
        )
        .unwrap();
        second_sender.send(Recipients::One(victim), second_valid.encode(), false);
        while *processed.lock() < 7 {
            context.sleep(Duration::from_millis(1)).await;
        }

        assert!(oracle.blocked().await.unwrap().is_empty());
        assert_eq!(
            handle.await.expect("aggregation engine failed"),
            EngineOutcome::Completed
        );
        let certificates = certificates.lock();
        assert_eq!(certificates.len(), 1);
        assert_eq!(certificates[0].item.position, position);
        assert_eq!(certificates[0].item.digest, digest(position));
    });
}

#[test_traced("INFO")]
fn test_ack_validation_blocks_peer_mismatch_and_invalid_signature() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(82);
        let position = Height::new(420);
        let victim = fixture.participants[0].clone();
        let mismatched_peer = fixture.participants[2].clone();
        let forging_peer = fixture.participants[3].clone();
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, true).await;
        let application = PendingApplication::default();
        let requested = application.requested.clone();
        let cfg = config(
            &context,
            fixture.schemes[0].clone(),
            application,
            RecordingReporter::default(),
            oracle.control(victim.clone()),
            EngineScope {
                partition: "aggregation-ack-blockable".into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (engine, mut mailbox) = Engine::new(context.child("engine"), cfg);
        let handle = engine.start(registrations.remove(&victim).unwrap());

        while !requested.lock().contains_key(&position) {
            context.sleep(Duration::from_millis(1)).await;
        }

        let mismatched = Ack::sign(
            &fixture.schemes[1],
            Item {
                position,
                digest: digest(position),
            },
        )
        .unwrap();
        let (mut mismatched_sender, _) = registrations.remove(&mismatched_peer).unwrap();
        mismatched_sender.send(Recipients::One(victim.clone()), mismatched.encode(), false);
        while !oracle
            .blocked()
            .await
            .unwrap()
            .contains(&(victim.clone(), mismatched_peer.clone()))
        {
            context.sleep(Duration::from_millis(1)).await;
        }

        let mut forged = Ack::sign(
            &fixture.schemes[3],
            Item {
                position,
                digest: digest(position),
            },
        )
        .unwrap();
        forged.item.digest = Sha256::hash(&[b"forged ack"]);
        let (mut forging_sender, _) = registrations.remove(&forging_peer).unwrap();
        forging_sender.send(Recipients::One(victim.clone()), forged.encode(), false);
        while !oracle
            .blocked()
            .await
            .unwrap()
            .contains(&(victim.clone(), forging_peer.clone()))
        {
            context.sleep(Duration::from_millis(1)).await;
        }

        assert_eq!(
            mailbox.submit(certificate(&fixture, epoch, position)).await,
            CertificateOutcome::Accepted
        );
        assert_eq!(
            handle.await.expect("aggregation engine failed"),
            EngineOutcome::Completed
        );
    });
}

fn certificate_ingress<S, F>(fixture: F)
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    F: FnOnce(&mut Context, &[u8], u32) -> Fixture<S>,
{
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(9);
        let position = Height::new(50);
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, false).await;
        let participant = fixture.participants[0].clone();
        let application = PendingApplication::default();
        let requested = application.requested.clone();
        let reporter = RecordingReporter::default();
        let certificates = reporter.certificates.clone();
        let cfg = config(
            &context,
            fixture.schemes[0].clone(),
            application,
            reporter,
            oracle.control(participant.clone()),
            EngineScope {
                partition: "aggregation-ingress".into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (engine, mut mailbox) = Engine::new(context.child("engine"), cfg);
        let handle = engine.start(registrations.remove(&participant).unwrap());

        while !requested.lock().contains_key(&position) {
            context.sleep(Duration::from_millis(1)).await;
        }

        let item = Item {
            position,
            digest: digest(position),
        };
        let quorum = usize::try_from(
            fixture.schemes[0]
                .participants()
                .quorum_count::<S::Faults>(),
        )
        .expect("quorum count must fit in usize");
        let acks: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum)
            .map(|scheme| Ack::sign(scheme, item.clone()).unwrap())
            .collect();
        let certificate = Certificate::from_acks(
            &fixture.schemes[0],
            epoch,
            non_empty![@acks.iter()],
            &Sequential,
        )
        .unwrap();

        let mut wrong_epoch = certificate.clone();
        wrong_epoch.epoch = epoch.next();
        assert_eq!(
            mailbox.submit(wrong_epoch).await,
            CertificateOutcome::Invalid
        );

        let mut outside = certificate.clone();
        outside.item.position = position.next();
        assert_eq!(mailbox.submit(outside).await, CertificateOutcome::Invalid);

        let mut invalid = certificate.clone();
        invalid.item.digest = Sha256::hash(&[b"invalid"]);
        assert_eq!(mailbox.submit(invalid).await, CertificateOutcome::Invalid);
        assert_eq!(
            mailbox.submit(certificate).await,
            CertificateOutcome::Accepted
        );
        assert_eq!(
            handle.await.expect("aggregation engine failed"),
            EngineOutcome::Completed
        );

        let pending_sender = requested.lock().remove(&position).unwrap();
        assert!(pending_sender.send(digest(position)).is_err());
        assert_eq!(certificates.lock().len(), 1);
    });
}

#[test_traced("INFO")]
fn test_certificate_ingress_cancels_digest() {
    certificate_ingress(scheme::ed25519::fixture);
}

#[test_traced("INFO")]
fn test_external_certificate_outcomes_and_recovery_window() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(89);
        let first = Height::new(490);
        let second = first.next();
        let third = second.next();
        let participant = fixture.participants[0].clone();
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, false).await;
        let recoverer = RecordingRecoverer::default();
        let events = recoverer.events.clone();
        let mut cfg = config(
            &context,
            fixture.schemes[0].clone(),
            PendingApplication::default(),
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: "aggregation-external-outcomes".into(),
                epoch,
                first,
                last: third,
                window: 2,
            },
        );
        cfg.recovery_after_rebroadcasts = NonZeroU64::new(1).unwrap();
        cfg.recoverer = recoverer;
        let (engine, mut mailbox) = Engine::new(context.child("engine"), cfg);
        let handle = engine.start(registrations.remove(&participant).unwrap());

        while events.lock().iter().filter(|(fetch, _)| *fetch).count() < 2 {
            context.sleep(Duration::from_millis(1)).await;
        }

        let mut wrong_epoch = certificate(&fixture, epoch, second);
        wrong_epoch.epoch = epoch.next();
        assert_eq!(
            mailbox.submit(wrong_epoch).await,
            CertificateOutcome::Invalid
        );
        assert_eq!(
            mailbox
                .submit(certificate(&fixture, epoch, Height::new(first.get() - 1)))
                .await,
            CertificateOutcome::Invalid
        );
        assert_eq!(
            mailbox
                .submit(certificate(&fixture, epoch, third.next()))
                .await,
            CertificateOutcome::Invalid
        );

        let mut invalid_signature = certificate(&fixture, epoch, second);
        invalid_signature.item.digest = Sha256::hash(&[b"invalid certificate"]);
        assert_eq!(
            mailbox.submit(invalid_signature).await,
            CertificateOutcome::Invalid
        );
        assert_eq!(
            mailbox.submit(certificate(&fixture, epoch, third)).await,
            CertificateOutcome::Ignored
        );
        assert_eq!(
            mailbox.submit(certificate(&fixture, epoch, second)).await,
            CertificateOutcome::Accepted
        );
        assert_eq!(
            mailbox.submit(certificate(&fixture, epoch, second)).await,
            CertificateOutcome::Ignored
        );

        let first_key = RecoveryKey {
            namespace: RecoveryNamespace::derive(NAMESPACE),
            epoch,
            position: first,
        };
        let second_key = RecoveryKey {
            position: second,
            ..first_key
        };
        assert!(events.lock().contains(&(false, second_key)));
        assert!(!events.lock().contains(&(false, first_key)));

        assert_eq!(
            mailbox.submit(certificate(&fixture, epoch, first)).await,
            CertificateOutcome::Accepted
        );
        let third_key = RecoveryKey {
            position: third,
            ..first_key
        };
        while !events.lock().contains(&(true, third_key)) {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert!(events.lock().contains(&(false, first_key)));
        assert_eq!(
            mailbox.submit(certificate(&fixture, epoch, third)).await,
            CertificateOutcome::Accepted
        );
        assert_eq!(
            handle.await.expect("aggregation engine failed"),
            EngineOutcome::Completed
        );
        assert!(events.lock().contains(&(false, third_key)));
    });
}

#[test_traced("INFO")]
fn test_recovery_threshold_cancellation_and_window_bound() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(90);
        let first = Height::new(500);
        let second = first.next();
        let third = second.next();
        let participant = fixture.participants[0].clone();
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, false).await;
        let application = ClosedApplication::default();
        let requested = application.requested.clone();
        let recoverer = RecordingRecoverer::default();
        let events = recoverer.events.clone();
        let mut cfg = config(
            &context,
            fixture.schemes[0].clone(),
            application,
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: "aggregation-recovery-window".into(),
                epoch,
                first,
                last: third,
                window: 2,
            },
        );
        cfg.recovery_after_rebroadcasts = NonZeroU64::new(2).unwrap();
        cfg.recoverer = recoverer;
        let (engine, mut mailbox) = Engine::new(context.child("engine"), cfg);
        let handle = engine.start(registrations.remove(&participant).unwrap());

        while requested.lock().len() < 2 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(requested.lock().as_slice(), &[first, second]);
        context.sleep(Duration::from_millis(99)).await;
        assert!(events.lock().is_empty());
        context.sleep(Duration::from_millis(2)).await;
        assert_eq!(
            events.lock().clone(),
            vec![
                (
                    true,
                    RecoveryKey {
                        namespace: RecoveryNamespace::derive(NAMESPACE),
                        epoch,
                        position: first,
                    },
                ),
                (
                    true,
                    RecoveryKey {
                        namespace: RecoveryNamespace::derive(NAMESPACE),
                        epoch,
                        position: second,
                    },
                ),
            ]
        );

        assert_eq!(
            mailbox.submit(certificate(&fixture, epoch, first)).await,
            CertificateOutcome::Accepted
        );
        while requested.lock().len() < 3 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(events.lock().iter().filter(|(fetch, _)| *fetch).count(), 2);
        context.sleep(Duration::from_millis(101)).await;
        assert_eq!(events.lock().iter().filter(|(fetch, _)| *fetch).count(), 3);

        for position in [second, third] {
            assert_eq!(
                mailbox.submit(certificate(&fixture, epoch, position)).await,
                CertificateOutcome::Accepted
            );
        }
        assert_eq!(
            handle.await.expect("aggregation engine failed"),
            EngineOutcome::Completed
        );
        let events = events.lock();
        assert_eq!(events.iter().filter(|(fetch, _)| *fetch).count(), 3);
        assert_eq!(events.iter().filter(|(fetch, _)| !*fetch).count(), 3);
    });
}

#[test_traced("INFO")]
fn test_recovery_retries_rejected_admission() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(92);
        let position = Height::new(520);
        let participant = fixture.participants[0].clone();
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, false).await;
        let recoverer = RecordingRecoverer::rejecting_once();
        let events = recoverer.events.clone();
        let mut cfg = config(
            &context,
            fixture.schemes[0].clone(),
            ClosedApplication::default(),
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: "aggregation-recovery-rejected-admission".into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        cfg.recovery_after_rebroadcasts = NonZeroU64::new(1).unwrap();
        cfg.recoverer = recoverer;
        let (engine, mut mailbox) = Engine::new(context.child("engine"), cfg);
        let handle = engine.start(registrations.remove(&participant).unwrap());

        while events.lock().iter().filter(|(fetch, _)| *fetch).count() < 2 {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            mailbox.submit(certificate(&fixture, epoch, position)).await,
            CertificateOutcome::Accepted
        );
        assert_eq!(
            handle.await.expect("aggregation engine failed"),
            EngineOutcome::Completed
        );

        let events = events.lock();
        assert_eq!(events.iter().filter(|(fetch, _)| *fetch).count(), 2);
        assert_eq!(events.iter().filter(|(fetch, _)| !*fetch).count(), 1);
    });
}

#[test_traced("INFO")]
fn test_locally_assembled_certificate_cancels_recovery() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(91);
        let position = Height::new(510);
        let participant = fixture.participants[0].clone();
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, true).await;
        let recoverer = RecordingRecoverer::default();
        let events = recoverer.events.clone();
        let mut cfg = config(
            &context,
            fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: "aggregation-local-recovery-cancel".into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        cfg.recovery_after_rebroadcasts = NonZeroU64::new(1).unwrap();
        cfg.recoverer = recoverer;
        let (engine, _mailbox) = Engine::new(context.child("engine"), cfg);
        let handle = engine.start(registrations.remove(&participant).unwrap());

        while events.lock().is_empty() {
            context.sleep(Duration::from_millis(1)).await;
        }
        let item = Item {
            position,
            digest: digest(position),
        };
        for index in 1..3 {
            let peer = fixture.participants[index].clone();
            let (mut sender, _) = registrations.remove(&peer).unwrap();
            let ack = Ack::sign(&fixture.schemes[index], item.clone()).unwrap();
            sender.send(Recipients::One(participant.clone()), ack.encode(), false);
        }

        assert_eq!(
            handle.await.expect("aggregation engine failed"),
            EngineOutcome::Completed
        );
        let events = events.lock();
        assert_eq!(events.len(), 2);
        assert!(events[0].0);
        assert!(!events[1].0);
        assert_eq!(events[0].1, events[1].1);
    });
}

#[test_traced("INFO")]
fn test_closed_proposal_response_is_terminal() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(10);
        let position = Height::new(55);
        let participant = fixture.participants[0].clone();
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, false).await;
        let application = ClosedApplication::default();
        let requested = application.requested.clone();
        let cfg = config(
            &context,
            fixture.schemes[0].clone(),
            application,
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: "aggregation-closed-proposal".into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (engine, mut mailbox) = Engine::new(context.child("engine"), cfg);
        let handle = engine.start(registrations.remove(&participant).unwrap());

        while requested.lock().is_empty() {
            context.sleep(Duration::from_millis(1)).await;
        }
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(requested.lock().as_slice(), &[position]);

        assert_eq!(
            mailbox.submit(certificate(&fixture, epoch, position)).await,
            CertificateOutcome::Accepted
        );
        assert_eq!(
            handle.await.expect("aggregation engine failed"),
            EngineOutcome::Completed
        );
        assert_eq!(requested.lock().as_slice(), &[position]);
    });
}

#[test_traced("INFO")]
fn test_certificate_ingress_is_bounded() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(10);
        let position = Height::new(60);
        let participant = fixture.participants[0].clone();
        let (oracle, _) = simulation(context.child("simulation"), &fixture, false).await;
        let cfg = config(
            &context,
            fixture.schemes[0].clone(),
            PendingApplication::default(),
            RecordingReporter::default(),
            oracle.control(participant),
            EngineScope {
                partition: "aggregation-bounded-ingress".into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (engine, mut mailbox) = Engine::new(context.child("engine"), cfg);

        let item = Item {
            position,
            digest: digest(position),
        };
        let quorum = usize::try_from(
            fixture.schemes[0]
                .participants()
                .quorum_count::<<scheme::ed25519::Scheme as commonware_cryptography::certificate::Verifier>::Faults>(),
        )
        .expect("quorum count must fit in usize");
        let acks: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum)
            .map(|scheme| Ack::sign(scheme, item.clone()).unwrap())
            .collect();
        let certificate = Certificate::from_acks(
            &fixture.schemes[0],
            epoch,
            non_empty![@acks.iter()],
            &Sequential,
        )
        .unwrap();

        let mut first_mailbox = mailbox.clone();
        let first_certificate = certificate.clone();
        let first = context.child("first_submit").spawn(move |_| async move {
            first_mailbox.submit(first_certificate).await
        });
        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(
            mailbox.submit(certificate).await,
            CertificateOutcome::Backpressured
        );

        drop(engine);
        assert_eq!(first.await.unwrap(), CertificateOutcome::Ignored);
    });
}

#[test_traced("INFO")]
fn test_shutdown_reports_stopped() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 1);
        let participant = fixture.participants[0].clone();
        let position = Height::new(70);
        let application = PendingApplication::default();
        let requested = application.requested.clone();
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, false).await;
        let cfg = config(
            &context,
            fixture.schemes[0].clone(),
            application,
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: "aggregation-shutdown".into(),
                epoch: Epoch::new(11),
                first: position,
                last: position,
                window: 1,
            },
        );
        let (engine, _mailbox) = Engine::new(context.child("engine"), cfg);
        let handle = engine.start(registrations.remove(&participant).unwrap());

        while !requested.lock().contains_key(&position) {
            context.sleep(Duration::from_millis(1)).await;
        }
        context.child("stop").stop(0, None).await.unwrap();

        assert_eq!(
            handle.await.expect("aggregation engine failed"),
            EngineOutcome::Stopped
        );
    });
}

#[test_traced("INFO")]
fn test_graceful_stop_reports_stopped() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 1);
        let participant = fixture.participants[0].clone();
        let position = Height::new(71);
        let application = PendingApplication::default();
        let requested = application.requested.clone();
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, false).await;
        let cfg = config(
            &context,
            fixture.schemes[0].clone(),
            application,
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: "aggregation-graceful-stop".into(),
                epoch: Epoch::new(11),
                first: position,
                last: position,
                window: 1,
            },
        );
        let (engine, _mailbox) = Engine::new(context.child("engine"), cfg);
        let (handle, stopper) = engine.start_stoppable(registrations.remove(&participant).unwrap());

        while !requested.lock().contains_key(&position) {
            context.sleep(Duration::from_millis(1)).await;
        }
        stopper.stop();

        assert_eq!(
            handle.await.expect("aggregation engine failed"),
            EngineOutcome::Stopped
        );
    });
}

#[test_traced("INFO")]
fn test_network_receiver_closure_reports_stopped() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 1);
        let participant = fixture.participants[0].clone();
        let position = Height::new(75);
        let application = PendingApplication::default();
        let requested = application.requested.clone();
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, false).await;
        let cfg = config(
            &context,
            fixture.schemes[0].clone(),
            application,
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: "aggregation-network-closure".into(),
                epoch: Epoch::new(12),
                first: position,
                last: position,
                window: 1,
            },
        );
        let (engine, _mailbox) = Engine::new(context.child("engine"), cfg);
        let handle = engine.start(registrations.remove(&participant).unwrap());

        while !requested.lock().contains_key(&position) {
            context.sleep(Duration::from_millis(1)).await;
        }
        let _replacement = oracle
            .control(participant)
            .register(0, QUOTA)
            .await
            .unwrap();

        assert_eq!(
            handle.await.expect("aggregation engine failed"),
            EngineOutcome::Stopped
        );
    });
}

#[test_traced("INFO")]
fn test_restart_reproposes_uncertified_position() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 4);
        let participant = fixture.participants[0].clone();
        let observer = fixture.participants[1].clone();
        let epoch = Epoch::new(13);
        let position = Height::new(76);
        let partition = "aggregation-repropose";
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, true).await;
        let (_, mut observer_receiver) = registrations.remove(&observer).unwrap();

        let first_application = PendingApplication::default();
        let first_requests = first_application.requested.clone();
        let mut first_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            first_application,
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        first_cfg.recovery_after_rebroadcasts = NonZeroU64::new(u64::MAX).unwrap();
        let (first_engine, _mailbox) = Engine::new(context.child("first_engine"), first_cfg);
        let first_handle = first_engine.start(registrations.remove(&participant).unwrap());

        while !first_requests.lock().contains_key(&position) {
            context.sleep(Duration::from_millis(1)).await;
        }
        first_requests
            .lock()
            .remove(&position)
            .unwrap()
            .send(digest(position))
            .unwrap();
        observer_receiver.recv().await.unwrap();

        let restart_registration = oracle
            .control(participant.clone())
            .register(0, QUOTA)
            .await
            .unwrap();
        assert_eq!(
            first_handle.await.expect("first aggregation engine failed"),
            EngineOutcome::Stopped
        );

        let restart_application = PendingApplication::default();
        let restart_requests = restart_application.requested.clone();
        let restart_recoverer = RecordingRecoverer::default();
        let restart_events = restart_recoverer.events.clone();
        let mut restart_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            restart_application,
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        restart_cfg.recovery_after_rebroadcasts = NonZeroU64::new(u64::MAX).unwrap();
        restart_cfg.recoverer = restart_recoverer;
        let (restart_engine, _mailbox) = Engine::new(context.child("restart_engine"), restart_cfg);
        let restart_handle = restart_engine.start(restart_registration);

        while !restart_requests.lock().contains_key(&position) {
            context.sleep(Duration::from_millis(1)).await;
        }
        while restart_events.lock().is_empty() {
            context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            restart_events.lock().as_slice(),
            &[(
                true,
                RecoveryKey {
                    namespace: RecoveryNamespace::derive(NAMESPACE),
                    epoch,
                    position,
                },
            )]
        );
        let _replacement = oracle
            .control(participant)
            .register(0, QUOTA)
            .await
            .unwrap();
        assert_eq!(
            restart_handle
                .await
                .expect("restarted aggregation engine failed"),
            EngineOutcome::Stopped
        );
        assert_eq!(restart_events.lock().len(), 2);
        assert!(!restart_events.lock()[1].0);
    });
}

fn journal_identity<S, F>(fixture: F)
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    F: FnOnce(&mut Context, &[u8], u32) -> Fixture<S>,
{
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = fixture(&mut context, NAMESPACE, 1);
        let participant = fixture.participants[0].clone();
        let epoch = Epoch::new(11);
        let position = Height::new(80);
        let partition = "aggregation-replay";

        let (first_oracle, mut first_registrations) =
            simulation(context.child("first_simulation"), &fixture, false).await;
        let first_reporter = RecordingReporter::default();
        let first_certificates = first_reporter.certificates.clone();
        let first_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            first_reporter,
            first_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (first_engine, _mailbox) = Engine::new(context.child("first_engine"), first_cfg);
        assert_eq!(
            first_engine
                .start(first_registrations.remove(&participant).unwrap())
                .await
                .expect("first aggregation engine failed"),
            EngineOutcome::Completed
        );
        assert_eq!(first_certificates.lock().len(), 1);

        let (second_oracle, mut second_registrations) =
            simulation(context.child("second_simulation"), &fixture, false).await;
        let replay_application = ImmediateApplication::default();
        let replay_requests = replay_application.requested.clone();
        let replay_reporter = RecordingReporter::default();
        let replay_certificates = replay_reporter.certificates.clone();
        let replay_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            replay_application,
            replay_reporter,
            second_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (replay_engine, _mailbox) = Engine::new(context.child("replay_engine"), replay_cfg);
        assert_eq!(
            replay_engine
                .start(second_registrations.remove(&participant).unwrap())
                .await
                .expect("replayed aggregation engine failed"),
            EngineOutcome::Completed
        );
        assert!(replay_requests.lock().is_empty());
        assert_eq!(replay_certificates.lock().len(), 1);
    });
}

#[test_traced("INFO")]
fn test_journal_replay_binds_engine_identity() {
    journal_identity(scheme::ed25519::fixture);
}

#[test_traced("INFO")]
fn test_journal_facade_rejects_mismatch_and_destroys_exact_journal() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 1);
        let scheme = fixture.schemes[0].clone();
        let participant = fixture.participants[0].clone();
        let epoch = Epoch::new(17);
        let position = Height::new(140);
        let partition = "aggregation-facade-destroy";
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, false).await;
        let engine_cfg = config(
            &context,
            scheme.clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let journal_cfg = JournalConfig {
            identity: JournalIdentity::new::<scheme::ed25519::Scheme, Sha256Digest>(
                &scheme,
                epoch,
                position,
                position,
                NonZeroU64::new(1).unwrap(),
            ),
            partition: partition.into(),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            heights_per_section: NonZeroU64::new(4).unwrap(),
            compression: None,
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
        };
        let (engine, _mailbox) = Engine::new(context.child("engine"), engine_cfg);
        assert_eq!(
            engine
                .start(registrations.remove(&participant).unwrap())
                .await
                .unwrap(),
            EngineOutcome::Completed
        );

        let mut mismatch = journal_cfg.clone();
        mismatch.identity.epoch = epoch.next();
        let journal_context = context.child("mismatch");
        let result = Journal::<_, scheme::ed25519::Scheme, Sha256Digest>::init(
            journal_context,
            mismatch,
            &mut context,
            &scheme,
            &Sequential,
        )
        .await;
        assert!(matches!(result, Err(JournalError::EpochMismatch)));

        let journal_context = context.child("verified");
        let (journal, certificates) = Journal::<_, scheme::ed25519::Scheme, Sha256Digest>::init(
            journal_context,
            journal_cfg.clone(),
            &mut context,
            &scheme,
            &Sequential,
        )
        .await
        .unwrap();
        assert_eq!(certificates.len(), 1);
        assert_eq!(certificates[0].item.position, position);
        journal.destroy().await.unwrap();

        let journal_context = context.child("after_destroy");
        let (journal, certificates) = Journal::<_, scheme::ed25519::Scheme, Sha256Digest>::init(
            journal_context,
            journal_cfg,
            &mut context,
            &scheme,
            &Sequential,
        )
        .await
        .unwrap();
        assert!(certificates.is_empty());
        journal.destroy().await.unwrap();
    });
}

#[test_traced("INFO")]
fn test_journal_replay_resumes_partial_mid_range() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 1);
        let participant = fixture.participants[0].clone();
        let epoch = Epoch::new(13);
        let first = Height::new(120);
        let last = Height::new(125);
        let partition = "aggregation-partial-mid-range";
        let replayed = [Height::new(122), Height::new(123)];
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, false).await;

        let first_application = PendingApplication::default();
        let first_requests = first_application.requested.clone();
        let first_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            first_application,
            RecordingReporter::default(),
            oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first,
                last,
                window: 6,
            },
        );
        let (first_engine, mut first_mailbox) =
            Engine::new(context.child("first_engine"), first_cfg);
        let first_handle = first_engine.start(registrations.remove(&participant).unwrap());

        while first_requests.lock().len() < 6 {
            context.sleep(Duration::from_millis(1)).await;
        }
        for position in replayed {
            assert_eq!(
                first_mailbox
                    .submit(certificate(&fixture, epoch, position))
                    .await,
                CertificateOutcome::Accepted
            );
        }

        let registration = oracle
            .control(participant.clone())
            .register(0, QUOTA)
            .await
            .unwrap();
        assert_eq!(
            first_handle.await.expect("first aggregation engine failed"),
            EngineOutcome::Stopped
        );

        let replay_application = ImmediateApplication::default();
        let replay_requests = replay_application.requested.clone();
        let replay_reporter = RecordingReporter::default();
        let replay_certificates = replay_reporter.certificates.clone();
        let replay_recoverer = RecordingRecoverer::default();
        let replay_events = replay_recoverer.events.clone();
        let mut replay_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            replay_application,
            replay_reporter,
            oracle.control(participant),
            EngineScope {
                partition: partition.into(),
                epoch,
                first,
                last,
                window: 6,
            },
        );
        replay_cfg.recoverer = replay_recoverer;
        let (replay_engine, _mailbox) = Engine::new(context.child("replay_engine"), replay_cfg);
        assert_eq!(
            replay_engine
                .start(registration)
                .await
                .expect("replayed aggregation engine failed"),
            EngineOutcome::Completed
        );

        let requested = replay_requests.lock();
        assert_eq!(requested.len(), 4);
        assert!(!requested.contains(&Height::new(122)));
        assert!(!requested.contains(&Height::new(123)));
        let recovered: BTreeSet<_> = replay_events
            .lock()
            .iter()
            .filter_map(|(fetch, key)| fetch.then_some(key.position))
            .collect();
        assert_eq!(
            recovered,
            [120, 121, 124, 125].into_iter().map(Height::new).collect()
        );
        let certified: BTreeSet<_> = replay_certificates
            .lock()
            .iter()
            .map(|certificate| certificate.item.position)
            .collect();
        assert_eq!(certified, (120..=125).map(Height::new).collect());
    });
}

fn journal_namespace_mismatch() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 1);
        let participant = fixture.participants[0].clone();
        let epoch = Epoch::new(12);
        let position = Height::new(90);
        let partition = "aggregation_identity_mismatch";

        let (first_oracle, mut first_registrations) =
            simulation(context.child("first_simulation"), &fixture, false).await;
        let first_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            first_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (first_engine, _mailbox) = Engine::new(context.child("first_engine"), first_cfg);
        assert_eq!(
            first_engine
                .start(first_registrations.remove(&participant).unwrap())
                .await
                .expect("first aggregation engine failed"),
            EngineOutcome::Completed
        );

        let (mismatch_oracle, mut mismatch_registrations) =
            simulation(context.child("mismatch_simulation"), &fixture, false).await;
        let mismatch_scheme = scheme::ed25519::Scheme::signer(
            b"different namespace",
            fixture.schemes[0].participants().clone(),
            fixture.private_keys[0].clone(),
        )
        .unwrap();
        let mismatch_cfg = config(
            &context,
            mismatch_scheme,
            ImmediateApplication::default(),
            RecordingReporter::default(),
            mismatch_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (mismatch_engine, _mailbox) =
            Engine::new(context.child("mismatch_engine"), mismatch_cfg);
        let _ = mismatch_engine
            .start(mismatch_registrations.remove(&participant).unwrap())
            .await;
    });
}

#[test_traced("INFO")]
#[should_panic(expected = "aggregation journal namespace digest mismatch")]
fn test_journal_rejects_signing_namespace_mismatch() {
    journal_namespace_mismatch();
}

fn journal_window_mismatch<S, F>(fixture: F)
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    F: FnOnce(&mut Context, &[u8], u32) -> Fixture<S>,
{
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = fixture(&mut context, NAMESPACE, 1);
        let participant = fixture.participants[0].clone();
        let epoch = Epoch::new(13);
        let position = Height::new(100);
        let partition = "aggregation_window_mismatch";

        let (first_oracle, mut first_registrations) =
            simulation(context.child("first_simulation"), &fixture, false).await;
        let first_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            first_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (first_engine, _mailbox) = Engine::new(context.child("first_engine"), first_cfg);
        first_engine
            .start(first_registrations.remove(&participant).unwrap())
            .await
            .expect("first aggregation engine failed");

        let (mismatch_oracle, mut mismatch_registrations) =
            simulation(context.child("mismatch_simulation"), &fixture, false).await;
        let mismatch_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            mismatch_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first: position,
                last: position,
                window: 2,
            },
        );
        let (mismatch_engine, _mailbox) =
            Engine::new(context.child("mismatch_engine"), mismatch_cfg);
        let _ = mismatch_engine
            .start(mismatch_registrations.remove(&participant).unwrap())
            .await;
    });
}

#[test_traced("INFO")]
#[should_panic(expected = "aggregation journal window mismatch")]
fn test_journal_rejects_window_mismatch() {
    journal_window_mismatch(scheme::ed25519::fixture);
}

fn journal_committee_mismatch<S, F>(fixture: F)
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    F: Fn(&mut Context, &[u8], u32) -> Fixture<S>,
{
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let first_fixture = fixture(&mut context, NAMESPACE, 1);
        let first_participant = first_fixture.participants[0].clone();
        let epoch = Epoch::new(14);
        let position = Height::new(110);
        let partition = "aggregation_committee_mismatch";

        let (first_oracle, mut first_registrations) =
            simulation(context.child("first_simulation"), &first_fixture, false).await;
        let first_cfg = config(
            &context,
            first_fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            first_oracle.control(first_participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (first_engine, _mailbox) = Engine::new(context.child("first_engine"), first_cfg);
        first_engine
            .start(first_registrations.remove(&first_participant).unwrap())
            .await
            .expect("first aggregation engine failed");

        let second_fixture = fixture(&mut context, NAMESPACE, 1);
        let second_participant = second_fixture.participants[0].clone();
        let (mismatch_oracle, mut mismatch_registrations) =
            simulation(context.child("mismatch_simulation"), &second_fixture, false).await;
        let mismatch_cfg = config(
            &context,
            second_fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            mismatch_oracle.control(second_participant.clone()),
            EngineScope {
                partition: partition.into(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (mismatch_engine, _mailbox) =
            Engine::new(context.child("mismatch_engine"), mismatch_cfg);
        let _ = mismatch_engine
            .start(mismatch_registrations.remove(&second_participant).unwrap())
            .await;
    });
}

#[test_traced("INFO")]
#[should_panic(expected = "aggregation journal committee mismatch")]
fn test_journal_rejects_committee_mismatch() {
    journal_committee_mismatch(scheme::ed25519::fixture);
}
