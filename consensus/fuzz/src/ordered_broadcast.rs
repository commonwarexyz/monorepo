//! Fuzz harness for the `ordered_broadcast` engine.
//!
//! Honest validators run against the deterministic simulated network.
//! Fuzz input drives runtime non-determinism via [`FuzzRng`], the link
//! conditions, the partition shape, the engine timeouts, and the target
//! height the reporters must reach.

use crate::{
    ordered_broadcast_certificate_mock as cert_mock,
    utils::{link_peers, Action, Partition, SetPartition},
    MAX_SLEEP_DURATION,
};
use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::{
    ordered_broadcast::{
        mocks::{self, ReporterMailbox},
        scheme::Scheme,
        types::{ChunkSigner, ChunkVerifier},
        Config, Engine,
    },
    types::{Epoch, EpochDelta, Height, HeightDelta},
};
use commonware_cryptography::{
    certificate::mocks::Fixture, ed25519::PublicKey, sha256::Digest as Sha256Digest, Hasher, Sha256,
};
use commonware_macros::select;
use commonware_p2p::simulated::{Link, Network, Oracle, Receiver, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, Clock, Quota, Runner, Spawner, Supervisor as _,
};
use commonware_utils::{FuzzRng, NZUsize, NZU16, NZU64};
use futures::future::join_all;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    time::Duration,
};

const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
const NAMESPACE: &[u8] = b"_COMMONWARE_FUZZ_ORDERED_BROADCAST";
const NUM_VALIDATORS: u32 = 4;
const EPOCH: u64 = 111;
const MAX_NETWORK_SIZE: u32 = 1024 * 1024;
const MAX_RAW_BYTES: usize = 32_768;
const MIN_TARGET_HEIGHT: u64 = 1;
const MAX_TARGET_HEIGHT: u64 = 20;
const MIN_LATENCY_MS: u64 = 1;
const MAX_LATENCY_MS: u64 = 100;
const MAX_JITTER_MS: u64 = 50;
const MIN_SUCCESS_PERCENT: u8 = 0;
const MAX_SUCCESS_PERCENT: u8 = 100;
const LIVE_TARGET_CEILING: u64 = 3;
const PERCENT_DENOMINATOR: f64 = 100.0;
const MIN_REBROADCAST_MS: u64 = 100;
const MAX_REBROADCAST_MS: u64 = 5_000;
const REPORTER_POLL_MS: u64 = 100;

type Registrations = BTreeMap<
    PublicKey,
    (
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
    ),
>;

#[derive(Debug, Clone)]
pub struct FuzzInput {
    pub raw_bytes: Vec<u8>,
    pub target_height: u64,
    pub latency_ms: u64,
    pub jitter_ms: u64,
    pub success_rate_percent: u8,
    pub partition: Partition,
    pub rebroadcast_ms: u64,
    pub priority_proposals: bool,
    pub priority_acks: bool,
}

impl Arbitrary<'_> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let target_height = u.int_in_range(MIN_TARGET_HEIGHT..=MAX_TARGET_HEIGHT)?;
        let latency_ms = u.int_in_range(MIN_LATENCY_MS..=MAX_LATENCY_MS)?;
        let jitter_ms = u.int_in_range(0..=MAX_JITTER_MS)?;
        let success_rate_percent = u.int_in_range(MIN_SUCCESS_PERCENT..=MAX_SUCCESS_PERCENT)?;
        let partition = match u.int_in_range(0..=99)? {
            0..=59 => Partition::Connected,
            _ => {
                let idx = u.int_in_range(1..=14)?;
                Partition::Static(SetPartition::n4(idx))
            }
        };
        let rebroadcast_ms = u.int_in_range(MIN_REBROADCAST_MS..=MAX_REBROADCAST_MS)?;
        let priority_proposals = u.arbitrary()?;
        let priority_acks = u.arbitrary()?;

        let remaining = u.len().min(MAX_RAW_BYTES);
        let raw_bytes = if remaining == 0 {
            vec![0]
        } else {
            u.bytes(remaining)?.to_vec()
        };

        Ok(Self {
            raw_bytes,
            target_height,
            latency_ms,
            jitter_ms,
            success_rate_percent,
            partition,
            rebroadcast_ms,
            priority_proposals,
            priority_acks,
        })
    }
}

fn link(input: &FuzzInput) -> Link {
    Link {
        latency: Duration::from_millis(input.latency_ms),
        jitter: Duration::from_millis(input.jitter_ms),
        success_rate: f64::from(input.success_rate_percent) / PERCENT_DENOMINATOR,
    }
}

async fn register_participants(
    oracle: &mut Oracle<PublicKey, deterministic::Context>,
    participants: &[PublicKey],
) -> Registrations {
    let mut registrations = BTreeMap::new();
    for participant in participants {
        let control = oracle.control(participant.clone());
        let proposals = control.register(0, TEST_QUOTA).await.unwrap();
        let acks = control.register(1, TEST_QUOTA).await.unwrap();
        registrations.insert(participant.clone(), (proposals, acks));
    }
    registrations
}

fn spawn_engines<S>(
    context: deterministic::Context,
    fixture: &Fixture<S>,
    registrations: &mut Registrations,
    rebroadcast: Duration,
    priority_proposals: bool,
    priority_acks: bool,
    epoch: Epoch,
) -> BTreeMap<PublicKey, ReporterMailbox<PublicKey, S, Sha256Digest>>
where
    S: Scheme<PublicKey, Sha256Digest>,
{
    let mut reporters = BTreeMap::new();
    for (idx, validator) in fixture.participants.iter().enumerate() {
        let ctx = context
            .child("validator")
            .with_attribute("public_key", validator);
        let monitor = mocks::Monitor::new(epoch);
        let sequencers = mocks::Sequencers::<PublicKey>::new(fixture.participants.clone());
        let validators_provider = mocks::Provider::new();
        assert!(validators_provider.register(epoch, fixture.schemes[idx].clone()));
        let automaton = mocks::Automaton::<PublicKey>::new(|_| false);
        let chunk_verifier = ChunkVerifier::new(NAMESPACE);
        let (reporter, mailbox) = mocks::Reporter::new(
            ctx.child("reporter"),
            chunk_verifier.clone(),
            fixture.verifier.clone(),
            None,
        );
        reporter.start();
        reporters.insert(validator.clone(), mailbox.clone());

        let engine = Engine::new(
            ctx.child("engine"),
            Config {
                sequencer_signer: Some(ChunkSigner::new(
                    NAMESPACE,
                    fixture.private_keys[idx].clone(),
                )),
                chunk_verifier,
                sequencers_provider: sequencers,
                validators_provider,
                automaton: automaton.clone(),
                relay: automaton,
                reporter: mailbox,
                monitor,
                priority_proposals,
                priority_acks,
                rebroadcast_timeout: rebroadcast,
                epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                height_bound: HeightDelta::new(2),
                journal_heights_per_section: NZU64!(10),
                journal_replay_buffer: NZUsize!(4096),
                journal_write_buffer: NZUsize!(4096),
                journal_name_prefix: format!("ordered-broadcast-fuzz-{validator}-"),
                journal_compression: Some(3),
                journal_page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            },
        );
        let ((a1, a2), (b1, b2)) = registrations.remove(validator).unwrap();
        engine.start((a1, a2), (b1, b2));
    }
    reporters
}

fn spawn_target_watchers<S>(
    context: deterministic::Context,
    sequencers: &[PublicKey],
    reporters: &BTreeMap<PublicKey, ReporterMailbox<PublicKey, S, Sha256Digest>>,
    target_height: Height,
    target_epoch: Epoch,
) -> Vec<commonware_runtime::Handle<bool>>
where
    S: Scheme<PublicKey, Sha256Digest>,
{
    let mut handles = Vec::new();
    for mailbox in reporters.values() {
        for sequencer in sequencers {
            let handle = context.child("reporter_watcher").spawn({
                let sequencer = sequencer.clone();
                let mut mailbox = mailbox.clone();
                move |context| async move {
                    loop {
                        let (height, epoch) = mailbox
                            .get_tip(sequencer.clone())
                            .await
                            .unwrap_or((Height::zero(), Epoch::zero()));
                        let contiguous = mailbox
                            .get_contiguous_tip(sequencer.clone())
                            .await
                            .unwrap_or(Height::zero());
                        if height >= target_height
                            && epoch >= target_epoch
                            && contiguous >= target_height
                        {
                            return true;
                        }
                        context.sleep(Duration::from_millis(REPORTER_POLL_MS)).await;
                    }
                }
            });
            handles.push(handle);
        }
    }
    handles
}

pub fn fuzz(input: FuzzInput) {
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let cfg = deterministic::Config::new().with_rng(Box::new(rng));
    let executor = deterministic::Runner::new(cfg);

    executor.start(|mut context| async move {
        let fixture = cert_mock::fixture_with::<false, true, true, _>(
            &mut context,
            NAMESPACE,
            NUM_VALIDATORS,
        );
        let epoch = Epoch::new(EPOCH);
        let target_height = Height::new(input.target_height);

        let (network, mut oracle) = Network::new_with_peers(
            context.child("network"),
            commonware_p2p::simulated::Config {
                max_size: MAX_NETWORK_SIZE,
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(1),
            },
            fixture.participants.clone(),
        )
        .await;
        network.start();

        let mut registrations = register_participants(&mut oracle, &fixture.participants).await;
        link_peers(
            &mut oracle,
            &fixture.participants,
            Action::Link(link(&input)),
            input.partition.set_partition(),
        )
        .await;

        let reporters = spawn_engines(
            context.child("validators"),
            &fixture,
            &mut registrations,
            Duration::from_millis(input.rebroadcast_ms),
            input.priority_proposals,
            input.priority_acks,
            epoch,
        );

        let sequencers = fixture.participants.clone();
        let watchers = spawn_target_watchers(
            context.child("reporter"),
            &sequencers,
            &reporters,
            target_height,
            epoch,
        );

        let completed = select! {
            results = join_all(watchers) => {
                results.iter().all(|r| matches!(r, Ok(true)))
            },
            _ = context.sleep(MAX_SLEEP_DURATION) => false,
        };

        check_no_conflicting_chunks(&reporters, &sequencers).await;

        if input.partition.is_connected()
            && input.success_rate_percent == MAX_SUCCESS_PERCENT
            && input.target_height <= LIVE_TARGET_CEILING
        {
            assert!(
                completed,
                "live config (connected, 100% success, target_height {}) stalled",
                input.target_height,
            );
        }
    });
}

fn expected_chunk_digest(sequencer: &PublicKey, height: Height) -> Sha256Digest {
    let payload = format!("hello world, {sequencer} {height}");
    let mut hasher = Sha256::default();
    hasher.update(payload.as_bytes());
    hasher.finalize()
}

async fn check_no_conflicting_chunks<S>(
    reporters: &BTreeMap<PublicKey, ReporterMailbox<PublicKey, S, Sha256Digest>>,
    sequencers: &[PublicKey],
) where
    S: Scheme<PublicKey, Sha256Digest>,
{
    let mut canonical: BTreeMap<(PublicKey, Height), (Sha256Digest, Epoch)> = BTreeMap::new();
    for mailbox in reporters.values() {
        let mut mailbox = mailbox.clone();
        for sequencer in sequencers {
            let (tip, _) = mailbox
                .get_tip(sequencer.clone())
                .await
                .unwrap_or((Height::zero(), Epoch::zero()));
            let mut h = 0u64;
            while h <= tip.get() {
                let height = Height::new(h);
                if let Some((digest, epoch)) = mailbox.get(sequencer.clone(), height).await {
                    assert_eq!(
                        digest,
                        expected_chunk_digest(sequencer, height),
                        "delivered digest does not match application semantics at {sequencer:?} height {h}",
                    );
                    let key = (sequencer.clone(), height);
                    if let Some((existing_digest, existing_epoch)) = canonical.get(&key) {
                        assert_eq!(
                            existing_digest, &digest,
                            "conflicting chunk digests at {sequencer:?} height {h}",
                        );
                        assert_eq!(
                            existing_epoch, &epoch,
                            "conflicting chunk epochs at {sequencer:?} height {h}",
                        );
                    } else {
                        canonical.insert(key, (digest, epoch));
                    }
                }
                h += 1;
            }
        }
    }
}
