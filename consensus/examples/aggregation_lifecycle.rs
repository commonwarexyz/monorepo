//! Run two finite aggregation epochs from start to journal retirement.
//!
//! Four simulated validators share one committee. Each validator owns one durable certificate
//! archive and one resolver with a shared [RecoveryCoordinator] for all of its epochs. The
//! coordinator's consumer routes resolver responses to the engine registered for each epoch. The
//! example shows this lifecycle:
//!
//! 1. Validators 0, 1, and 2 certify epoch 1. Validator 3 is offline for that epoch.
//! 2. Each validator waits for [EngineOutcome::Completed], writes the full range to its archive,
//!    syncs the archive, and only then deletes the engine journal.
//! 3. Validator 3 starts epoch 1 late and declines every digest. It recovers every certificate
//!    through the resolver from peer archives, after the peers deleted their journals.
//! 4. Validator 3 starts epoch 2, stops it, awaits its handle, and starts a successor for the same
//!    scope. Then all validators certify epoch 2, which covers the next disjoint positions.
//! 5. The runtime crashes. After restart, each archive holds both epochs, every certificate
//!    verifies against the trusted scope, and no engine journal remains.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p commonware-consensus --example aggregation_lifecycle
//! ```

use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::Encode as _;
use commonware_consensus::{
    Automaton, Reporter,
    aggregation::{
        Config, Engine, EngineOutcome, Recovery, RecoveryCoordinator, Stopper, scheme,
        types::{Certificate, RecoveryKey, RecoveryNamespace},
    },
    types::{Epoch, Height},
};
use commonware_cryptography::{
    Hasher as _, Sha256, certificate::Verifier as _, ed25519::PublicKey,
    sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::{Config as NetworkConfig, Link, Network, Oracle};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Error, Handle, Quota, Runner as _, Storage as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, Context},
};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{
    NZU16, NZUsize, NonZeroDuration,
    channel::{fallible::OneshotExt as _, oneshot},
    probability,
    sync::Mutex,
};
use std::{
    collections::BTreeMap,
    num::{NonZeroU32, NonZeroU64},
    sync::Arc,
    time::Duration,
};

type Scheme = scheme::ed25519::Scheme;
type Cert = Certificate<Scheme, Sha256Digest>;
type Archive = Metadata<Context, RecoveryKey, Cert>;

/// Encoded certificates that are already synced to the archive.
type Served = Arc<Mutex<BTreeMap<RecoveryKey, Bytes>>>;

/// Certificates reported by one engine. This map is not durable.
type Staged = Arc<Mutex<BTreeMap<Height, Cert>>>;

const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_AGGREGATION_LIFECYCLE_EXAMPLE";
const VALIDATORS: usize = 4;
const LATE: usize = 3;
const RESOLVER_CHANNEL: u64 = 0;
const QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

/// Trusted scope of one epoch.
///
/// A real node derives the epoch, range, and scheme from authenticated history. It never takes
/// them from the unsigned epoch field of a certificate.
#[derive(Clone, Copy)]
struct Scope {
    epoch: Epoch,
    first: Height,
    last: Height,
}

/// Trusted scopes. Ranges are finite and their global positions do not overlap.
const SCOPES: [Scope; 2] = [
    Scope {
        epoch: Epoch::new(1),
        first: Height::new(0),
        last: Height::new(9),
    },
    Scope {
        epoch: Epoch::new(2),
        first: Height::new(10),
        last: Height::new(19),
    },
];

impl Scope {
    fn positions(self) -> impl Iterator<Item = Height> {
        (self.first.get()..=self.last.get()).map(Height::new)
    }

    fn size(self) -> usize {
        self.positions().count()
    }
}

/// Returns the stable digest for a position. Every clone and restart must agree on it.
fn digest(position: Height) -> Sha256Digest {
    Sha256::hash(&[&position.get().to_be_bytes()])
}

fn recovery_namespace(scheme: &Scheme) -> RecoveryNamespace {
    scheme::Scheme::<Sha256Digest>::recovery_namespace(scheme)
}

fn archive_partition(index: usize) -> String {
    format!("validator-{index}-archive")
}

fn journal_partition(index: usize, epoch: Epoch) -> String {
    format!("validator-{index}-journal-{epoch}")
}

/// Supplies digests. An offline application declines every request, so its engine must recover
/// each certificate through the resolver.
#[derive(Clone)]
struct Application {
    online: bool,
}

impl Automaton for Application {
    type Context = Height;
    type Digest = Sha256Digest;

    async fn propose(&mut self, position: Height) -> oneshot::Receiver<Sha256Digest> {
        let (sender, receiver) = oneshot::channel();
        if self.online {
            sender.send_lossy(digest(position));
        }
        receiver
    }

    async fn verify(&mut self, position: Height, digest: Sha256Digest) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        sender.send_lossy(digest == self::digest(position));
        receiver
    }
}

/// Stages reported certificates until the engine completes.
#[derive(Clone)]
struct Stager(Staged);

impl Reporter for Stager {
    type Activity = Cert;

    fn report(&mut self, certificate: Cert) -> Feedback {
        self.0.lock().insert(certificate.item.position, certificate);
        Feedback::Ok
    }
}

/// Serves exact recovery keys from the synced archive, including retired epochs.
#[derive(Clone)]
struct Producer(Served);

impl commonware_resolver::p2p::Producer for Producer {
    type Key = RecoveryKey;

    fn produce(&mut self, key: RecoveryKey) -> oneshot::Receiver<Bytes> {
        let (sender, receiver) = oneshot::channel();
        if let Some(certificate) = self.0.lock().get(&key) {
            sender.send_lossy(certificate.clone());
        }
        receiver
    }
}

/// A started engine and the state its caller must keep.
struct Running {
    scope: Scope,
    handle: Handle<EngineOutcome>,
    // Dropping the stopper stops the engine.
    stopper: Stopper,
    staged: Staged,
}

struct Validator {
    index: usize,
    context: Context,
    participant: PublicKey,
    scheme: Scheme,
    served: Served,
    archive: Option<Archive>,
    // Keeps the coordinator and resolver serving after every engine stops.
    recovery: Recovery,
}

impl Validator {
    async fn start(
        context: Context,
        oracle: &Oracle<PublicKey, Context>,
        fixture: &commonware_cryptography::certificate::mocks::Fixture<Scheme>,
        index: usize,
    ) -> Self {
        let participant = fixture.participants[index].clone();
        let scheme = fixture.schemes[index].clone();
        let served = Served::default();
        let archive = open_archive(context.child("archive"), &scheme, index).await;
        let (coordinator, recovery, consumer) =
            RecoveryCoordinator::new(context.child("recovery"), NZUsize!(8), NZUsize!(8));

        let (resolver, resolver_mailbox) = commonware_resolver::p2p::Engine::new(
            context.child("resolver"),
            commonware_resolver::p2p::Config {
                peer_provider: oracle.manager(),
                blocker: oracle.control(participant.clone()),
                consumer,
                producer: Producer(served.clone()),
                mailbox_size: NZUsize!(64),
                me: Some(participant.clone()),
                timeout: Duration::from_secs(1),
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let network = oracle
            .control(participant.clone())
            .register(RESOLVER_CHANNEL, QUOTA)
            .await
            .unwrap();
        resolver.start(network);
        coordinator.start(resolver_mailbox);

        Self {
            index,
            context,
            participant,
            scheme,
            served,
            archive: Some(archive),
            recovery,
        }
    }

    /// Starts an engine for a trusted scope.
    async fn start_engine(
        &self,
        oracle: &Oracle<PublicKey, Context>,
        scope: Scope,
        online: bool,
    ) -> Running {
        let staged = Staged::default();
        // Creating the engine registers its scope, so responses reach it before it can request
        // recovery. A predecessor for the same scope must already have been awaited.
        let engine = Engine::new(
            self.context
                .child("engine")
                .with_attribute("epoch", scope.epoch),
            Config {
                epoch: scope.epoch,
                first: scope.first,
                last: scope.last,
                scheme: self.scheme.clone(),
                automaton: Application { online },
                reporter: Stager(staged.clone()),
                blocker: oracle.control(self.participant.clone()),
                priority_acks: false,
                rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_millis(50)),
                recovery_after_rebroadcasts: NonZeroU64::new(3).unwrap(),
                recoverer: self.recovery.clone(),
                window: NonZeroU64::new(4).unwrap(),
                journal_partition: journal_partition(self.index, scope.epoch),
                journal_write_buffer: NZUsize!(4096),
                journal_replay_buffer: NZUsize!(4096),
                journal_heights_per_section: NonZeroU64::new(4).unwrap(),
                journal_compression: None,
                journal_page_cache: CacheRef::new(NZU16!(1024), NZUsize!(10)),
                strategy: Sequential,
            },
        )
        .expect("scope is not registered");
        // Each epoch uses its own channel, so the engine sees only its own epoch.
        let network = oracle
            .control(self.participant.clone())
            .register(scope.epoch.get(), QUOTA)
            .await
            .unwrap();
        let (handle, stopper) = engine.start_stoppable(network);
        Running {
            scope,
            handle,
            stopper,
            staged,
        }
    }

    /// Waits for completion, archives the full range durably, and then retires the journal.
    async fn finish(&mut self, running: Running) {
        let Running {
            scope,
            handle,
            stopper,
            staged,
        } = running;
        assert_eq!(handle.await.unwrap(), EngineOutcome::Completed);
        drop(stopper);
        let namespace = recovery_namespace(&self.scheme);

        // Completed means the journal holds the range. It does not mean the archive does.
        let staged = std::mem::take(&mut *staged.lock());
        assert!(staged.keys().copied().eq(scope.positions()));
        let mut archive = self.archive.take().unwrap();
        let mut encoded = Vec::with_capacity(staged.len());
        for (position, certificate) in staged {
            assert_eq!(certificate.item.digest, digest(position));
            let key = RecoveryKey {
                namespace,
                epoch: scope.epoch,
                position,
            };
            encoded.push((key, certificate.encode()));
            archive.put(key, certificate);
        }
        let archive = archive.sync().await.unwrap();
        self.archive = Some(archive);

        // Serve only synced certificates, then delete the journal.
        self.served.lock().extend(encoded);
        self.context
            .remove(&journal_partition(self.index, scope.epoch), None)
            .await
            .unwrap();
        println!(
            "validator {} archived epoch {} ({} certificates) and deleted its journal",
            self.index,
            scope.epoch,
            scope.size()
        );
    }
}

async fn open_archive(context: Context, scheme: &Scheme, index: usize) -> Archive {
    Metadata::init(
        context,
        metadata::Config {
            partition: archive_partition(index),
            codec_config: scheme.certificate_codec_config(),
        },
    )
    .await
    .unwrap()
}

async fn network(context: Context, participants: &[PublicKey]) -> Oracle<PublicKey, Context> {
    let (network, oracle) = Network::new_with_peers(
        context,
        NetworkConfig {
            max_size: 1024 * 1024,
            max_peers_per_set: NZUsize!(VALIDATORS),
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
        },
        participants.to_vec(),
    )
    .await;
    network.start();
    let link = Link {
        latency: Duration::from_millis(1),
        jitter: Duration::ZERO,
        success_rate: probability!(1.0),
    };
    for from in participants {
        for to in participants {
            if from != to {
                oracle
                    .add_link(from.clone(), to.clone(), link.clone())
                    .await
                    .unwrap();
            }
        }
    }
    oracle
}

fn main() {
    let runner = deterministic::Runner::timed(Duration::from_secs(60));
    let (verifier, checkpoint) = runner.start_and_recover(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, VALIDATORS as u32);
        let oracle = network(context.child("network"), &fixture.participants).await;
        let mut validators = Vec::with_capacity(VALIDATORS);
        for index in 0..VALIDATORS {
            let context = context.child("validator").with_attribute("index", index);
            validators.push(Validator::start(context, &oracle, &fixture, index).await);
        }

        // Epoch 1: three of four validators form a quorum.
        let scope = SCOPES[0];
        let mut running = Vec::new();
        for validator in &validators[..LATE] {
            running.push(validator.start_engine(&oracle, scope, true).await);
        }
        for (validator, running) in validators.iter_mut().zip(running) {
            validator.finish(running).await;
        }

        // The late validator has no digests and no peer sends acks. It recovers every
        // certificate from peer archives after the peers deleted their journals.
        let late = &mut validators[LATE];
        let running = late.start_engine(&oracle, scope, false).await;
        late.finish(running).await;

        // Epoch 2: the late validator stops its first engine. It awaits the handle before it
        // starts a successor for the same scope. The successor opens the same journal.
        let scope = SCOPES[1];
        let first = late.start_engine(&oracle, scope, true).await;
        context.sleep(Duration::from_millis(100)).await;
        first.stopper.stop();
        assert_eq!(first.handle.await.unwrap(), EngineOutcome::Stopped);
        let mut running = vec![late.start_engine(&oracle, scope, true).await];
        for validator in &validators[..LATE] {
            running.push(validator.start_engine(&oracle, scope, true).await);
        }
        let order = [LATE, 0, 1, 2];
        for (index, running) in order.into_iter().zip(running) {
            validators[index].finish(running).await;
        }
        fixture.verifier
    });

    // Crash and restart. Only synced storage survives.
    deterministic::Runner::from(checkpoint).start(|context| async move {
        for index in 0..VALIDATORS {
            let mut context = context.child("validator").with_attribute("index", index);
            let archive = open_archive(context.child("archive"), &verifier, index).await;
            let namespace = recovery_namespace(&verifier);
            for scope in SCOPES {
                for position in scope.positions() {
                    let key = RecoveryKey {
                        namespace,
                        epoch: scope.epoch,
                        position,
                    };
                    let certificate = archive.get(&key).expect("archived certificate");
                    assert_eq!(certificate.item.digest, digest(position));
                    assert!(certificate.verify_for(
                        &mut context,
                        &verifier,
                        scope.epoch,
                        scope.first,
                        scope.last,
                        &Sequential,
                    ));
                }
                match context.scan(&journal_partition(index, scope.epoch)).await {
                    Ok(blobs) => assert!(blobs.is_empty()),
                    Err(Error::PartitionMissing(_)) => {}
                    Err(error) => panic!("journal scan failed: {error}"),
                }
            }

            // The epoch field is not signed. A certificate relabeled with another epoch does not
            // verify against either trusted scope.
            let key = RecoveryKey {
                namespace,
                epoch: SCOPES[0].epoch,
                position: SCOPES[0].first,
            };
            let mut relabeled = archive.get(&key).unwrap().clone();
            relabeled.epoch = SCOPES[1].epoch;
            for scope in SCOPES {
                assert!(!relabeled.verify_for(
                    &mut context,
                    &verifier,
                    scope.epoch,
                    scope.first,
                    scope.last,
                    &Sequential,
                ));
            }
            println!("validator {index} holds both epochs after restart");
        }
    });
}
