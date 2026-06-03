//! Fuzz harness for the `aggregation` engine.
//!
//! Honest validators run against the deterministic simulated network.
//! Fuzz input drives runtime non-determinism via [`FuzzRng`], the link
//! conditions, the partition shape, the engine timeouts, and the target
//! height the reporters must reach.

use crate::{
    aggregation_certificate_mock as cert_mock,
    utils::{link_peers, Action, Partition, SetPartition},
    MAX_SLEEP_DURATION,
};
use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::{
    aggregation::{
        mocks::{self, ReporterMailbox},
        scheme::Scheme,
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
use commonware_utils::{FuzzRng, NZUsize, NonZeroDuration, NZU16, NZU64};
use futures::future::join_all;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    time::Duration,
};

const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
const NAMESPACE: &[u8] = b"_COMMONWARE_FUZZ_AGGREGATION";
const NUM_VALIDATORS: u32 = 4;
const EPOCH: u64 = 111;
const MAX_NETWORK_SIZE: u32 = 1024 * 1024;
const MAX_RAW_BYTES: usize = 32_768;
const MIN_TARGET_HEIGHT: u64 = 1;
const MAX_TARGET_HEIGHT: u64 = 30;
const MIN_LATENCY_MS: u64 = 1;
const MAX_LATENCY_MS: u64 = 100;
const MAX_JITTER_MS: u64 = 50;
const MIN_SUCCESS_PERCENT: u8 = 0;
const LIVE_TARGET_CEILING: u64 = 3;
const MAX_SUCCESS_PERCENT: u8 = 100;
const PERCENT_DENOMINATOR: f64 = 100.0;
const MIN_REBROADCAST_MS: u64 = 100;
const MAX_REBROADCAST_MS: u64 = 5_000;
const REPORTER_POLL_MS: u64 = 100;

type Registrations = BTreeMap<
    PublicKey,
    (
        Sender<PublicKey, deterministic::Context>,
        Receiver<PublicKey>,
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
    pub priority_acks: bool,
}

impl Arbitrary<'_> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let scenario = u.int_in_range(0..=99)?;
        let max_raw_prefix = u.len().min(MAX_RAW_BYTES);
        let mut raw_bytes = if max_raw_prefix == 0 {
            vec![0]
        } else {
            let raw_len = u.int_in_range(1..=max_raw_prefix)?.min(u.len());
            u.bytes(raw_len)?.to_vec()
        };
        let live = scenario <= 19;
        let target_height = if live {
            u.int_in_range(MIN_TARGET_HEIGHT..=LIVE_TARGET_CEILING)?
        } else {
            u.int_in_range(MIN_TARGET_HEIGHT..=MAX_TARGET_HEIGHT)?
        };
        let latency_ms = u.int_in_range(MIN_LATENCY_MS..=MAX_LATENCY_MS)?;
        let jitter_ms = u.int_in_range(0..=MAX_JITTER_MS)?;
        let success_rate_percent = if live {
            MAX_SUCCESS_PERCENT
        } else {
            u.int_in_range(MIN_SUCCESS_PERCENT..=MAX_SUCCESS_PERCENT)?
        };
        let partition = match scenario {
            0..=59 => Partition::Connected,
            _ => {
                let idx = u.int_in_range(1..=14)?;
                Partition::Static(SetPartition::n4(idx))
            }
        };
        let rebroadcast_ms = u.int_in_range(MIN_REBROADCAST_MS..=MAX_REBROADCAST_MS)?;
        let priority_acks = u.arbitrary()?;

        let remaining = u.len().min(MAX_RAW_BYTES.saturating_sub(raw_bytes.len()));
        if remaining > 0 {
            raw_bytes.extend_from_slice(u.bytes(remaining)?);
        }

        Ok(Self {
            raw_bytes,
            target_height,
            latency_ms,
            jitter_ms,
            success_rate_percent,
            partition,
            rebroadcast_ms,
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
        let (sender, receiver) = oracle
            .control(participant.clone())
            .register(0, TEST_QUOTA)
            .await
            .unwrap();
        registrations.insert(participant.clone(), (sender, receiver));
    }
    registrations
}

fn spawn_engines<S>(
    context: deterministic::Context,
    fixture: &Fixture<S>,
    registrations: &mut Registrations,
    oracle: &mut Oracle<PublicKey, deterministic::Context>,
    rebroadcast: Duration,
    priority_acks: bool,
    epoch: Epoch,
) -> BTreeMap<PublicKey, ReporterMailbox<S, Sha256Digest>>
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
{
    let mut reporters = BTreeMap::new();
    for (idx, participant) in fixture.participants.iter().enumerate() {
        let ctx = context
            .child("validator")
            .with_attribute("public_key", participant);
        let provider = mocks::Provider::new();
        assert!(provider.register(epoch, fixture.schemes[idx].clone()));
        let monitor = mocks::Monitor::new(epoch);
        let automaton = mocks::Application::new(mocks::Strategy::Correct);
        let (reporter, mailbox) =
            mocks::Reporter::new(ctx.child("reporter"), fixture.verifier.clone());
        reporter.start();
        reporters.insert(participant.clone(), mailbox.clone());

        let blocker = oracle.control(participant.clone());
        let engine = Engine::new(
            ctx.child("engine"),
            Config {
                monitor,
                provider,
                automaton,
                reporter: mailbox,
                blocker,
                priority_acks,
                rebroadcast_timeout: NonZeroDuration::new_panic(rebroadcast),
                epoch_bounds: (EpochDelta::new(1), EpochDelta::new(1)),
                window: NZU64!(10),
                activity_timeout: HeightDelta::new(100),
                journal_partition: format!("aggregation-fuzz-{participant}"),
                journal_write_buffer: NZUsize!(4096),
                journal_replay_buffer: NZUsize!(4096),
                journal_heights_per_section: NZU64!(6),
                journal_compression: Some(3),
                journal_page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            },
        );
        let (sender, receiver) = registrations.remove(participant).unwrap();
        engine.start((sender, receiver));
    }
    reporters
}

fn spawn_target_watchers<S>(
    context: deterministic::Context,
    reporters: &BTreeMap<PublicKey, ReporterMailbox<S, Sha256Digest>>,
    target_height: Height,
    target_epoch: Epoch,
) -> Vec<commonware_runtime::Handle<bool>>
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
{
    let mut handles = Vec::new();
    for mailbox in reporters.values() {
        let handle = context.child("reporter_watcher").spawn({
            let mut mailbox = mailbox.clone();
            move |context| async move {
                loop {
                    let (height, epoch) = mailbox
                        .get_tip()
                        .await
                        .unwrap_or((Height::zero(), Epoch::zero()));
                    if height >= target_height && epoch >= target_epoch {
                        return true;
                    }
                    context.sleep(Duration::from_millis(REPORTER_POLL_MS)).await;
                }
            }
        });
        handles.push(handle);
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
            &mut oracle,
            Duration::from_millis(input.rebroadcast_ms),
            input.priority_acks,
            epoch,
        );

        let watchers =
            spawn_target_watchers(context.child("reporter"), &reporters, target_height, epoch);

        let completed = select! {
            results = join_all(watchers) => {
                results.iter().all(|r| matches!(r, Ok(true)))
            },
            _ = context.sleep(MAX_SLEEP_DURATION) => false,
        };

        check_no_conflicting_certs(&reporters).await;

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

fn expected_item_digest(height: Height) -> Sha256Digest {
    let payload = format!("data for height {height}");
    let mut hasher = Sha256::default();
    hasher.update(payload.as_bytes());
    hasher.finalize()
}

async fn check_no_conflicting_certs<S>(
    reporters: &BTreeMap<PublicKey, ReporterMailbox<S, Sha256Digest>>,
) where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
{
    let mut canonical: BTreeMap<Height, (Sha256Digest, Epoch)> = BTreeMap::new();
    for mailbox in reporters.values() {
        let mut mailbox = mailbox.clone();
        let (tip, _) = mailbox
            .get_tip()
            .await
            .unwrap_or((Height::zero(), Epoch::zero()));
        // Keep this invariant bounded to the target-height domain covered by the input.
        let tip = tip.get().min(MAX_TARGET_HEIGHT);
        let mut h = 0u64;
        while h <= tip {
            let height = Height::new(h);
            if let Some((digest, epoch)) = mailbox.get(height).await {
                assert_eq!(
                    digest,
                    expected_item_digest(height),
                    "delivered digest does not match application semantics at height {h}",
                );
                if let Some((existing_digest, existing_epoch)) = canonical.get(&height) {
                    assert_eq!(
                        existing_digest, &digest,
                        "conflicting cert digests at height {h}",
                    );
                    assert_eq!(
                        existing_epoch, &epoch,
                        "conflicting cert epochs at height {h}",
                    );
                } else {
                    canonical.insert(height, (digest, epoch));
                }
            }
            h += 1;
        }
    }
}
