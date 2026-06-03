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
use commonware_codec::Encode;
use commonware_consensus::{
    aggregation::{
        mocks::{self, ReporterMailbox},
        scheme::Scheme,
        types::{Ack, Item, TipAck},
        Config, Engine,
    },
    types::{Epoch, EpochDelta, Height, HeightDelta},
};
use commonware_cryptography::{
    certificate::mocks::Fixture,
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest as Sha256Digest,
    Hasher, Sha256, Signer as _,
};
use commonware_macros::select;
use commonware_p2p::{
    simulated::{Link, Network, Oracle, Receiver, Sender},
    Manager as _, Recipients, Sender as _,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, Clock, Quota, Runner, Spawner, Supervisor as _,
};
use commonware_utils::{
    ordered::Set, sequence::U64, FuzzRng, NZUsize, NonZeroDuration, NZU16, NZU64,
};
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
const NEXT_EPOCH: u64 = EPOCH + 1;
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
const UNKNOWN_PEER_SEEDS: [u64; 4] = [0xA660_0000, 0xA660_0001, 0xA660_0002, 0xA660_0003];
const OUT_OF_BOUNDS_EPOCH_DELTA: u64 = 5;
const INVALID_SIGNATURE_ID: u64 = u64::MAX;

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
    pub faulty_node: Option<(usize, FaultyStrategy)>,
    /// Drive a mid-run epoch refresh (`monitor.update`) so the engine exercises
    /// the epoch-update arm and `SafeTip::reconcile`. Gated off in live scenarios.
    pub epoch_transition: bool,
    /// Restart every engine on its existing journal partition after the run, so
    /// the engine replays journaled acks/certs/tips on startup.
    pub restart: bool,
    /// Inject signed acks for the wrong digest over the simulated network.
    pub inject_bad_ack: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum FaultyStrategy {
    Incorrect,
    Skip,
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
        let incorrect_fault = (20..=39).contains(&scenario);
        let target_height = if live {
            u.int_in_range(MIN_TARGET_HEIGHT..=LIVE_TARGET_CEILING)?
        } else if incorrect_fault {
            u.int_in_range((LIVE_TARGET_CEILING + 1)..=MAX_TARGET_HEIGHT)?
        } else {
            u.int_in_range(MIN_TARGET_HEIGHT..=MAX_TARGET_HEIGHT)?
        };
        let latency_ms = u.int_in_range(MIN_LATENCY_MS..=MAX_LATENCY_MS)?;
        let jitter_ms = u.int_in_range(0..=MAX_JITTER_MS)?;
        let success_rate_percent = if live || incorrect_fault {
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

        // Only ever corrupt a single node, and only in non-live scenarios, so the
        // live assertion's 3-of-4 honest quorum is always preserved.
        let faulty_node = if live {
            None
        } else if incorrect_fault {
            let idx = u.int_in_range(0..=(NUM_VALIDATORS as usize - 1))?;
            Some((idx, FaultyStrategy::Incorrect))
        } else if u.arbitrary()? {
            None
        } else {
            let idx = u.int_in_range(0..=(NUM_VALIDATORS as usize - 1))?;
            let strategy = if u.arbitrary()? {
                FaultyStrategy::Incorrect
            } else {
                FaultyStrategy::Skip
            };
            Some((idx, strategy))
        };

        // Epoch transition perturbs progress, so keep it out of any scenario that
        // the live-config assertion in `fuzz` would require to finalize.
        let live_config = partition.is_connected()
            && success_rate_percent == MAX_SUCCESS_PERCENT
            && target_height <= LIVE_TARGET_CEILING;
        let epoch_transition = !live_config && ((40..=59).contains(&scenario) || u.arbitrary()?);
        let restart = scenario == 0 || (60..=79).contains(&scenario) || u.arbitrary()?;
        let inject_bad_ack = !live_config && ((20..=59).contains(&scenario) || u.arbitrary()?);

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
            faulty_node,
            epoch_transition,
            restart,
            inject_bad_ack,
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

struct SpawnedEngines<S: Scheme<Sha256Digest, PublicKey = PublicKey>> {
    reporters: BTreeMap<PublicKey, ReporterMailbox<S, Sha256Digest>>,
    senders: BTreeMap<PublicKey, Sender<PublicKey, deterministic::Context>>,
    handles: Vec<commonware_runtime::Handle<()>>,
    monitors: Vec<mocks::Monitor>,
}

#[allow(clippy::too_many_arguments)]
fn spawn_engines<S>(
    context: deterministic::Context,
    fixture: &Fixture<S>,
    registrations: &mut Registrations,
    oracle: &mut Oracle<PublicKey, deterministic::Context>,
    rebroadcast: Duration,
    priority_acks: bool,
    epoch: Epoch,
    faulty_node: Option<(usize, FaultyStrategy)>,
) -> SpawnedEngines<S>
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
{
    let mut reporters = BTreeMap::new();
    let mut senders = BTreeMap::new();
    let mut handles = Vec::new();
    let mut monitors = Vec::new();
    for (idx, participant) in fixture.participants.iter().enumerate() {
        let ctx = context
            .child("validator")
            .with_attribute("public_key", participant);
        let provider = mocks::Provider::new();
        assert!(provider.register(epoch, fixture.schemes[idx].clone()));
        // Register the next epoch too so an `epoch_transition` refresh finds a
        // scheme (the engine `.expect`s one for the current epoch).
        assert!(provider.register(Epoch::new(NEXT_EPOCH), fixture.schemes[idx].clone()));
        let monitor = mocks::Monitor::new(epoch);
        monitors.push(monitor.clone());
        let strategy = match faulty_node {
            Some((faulty_idx, FaultyStrategy::Incorrect)) if faulty_idx == idx => {
                mocks::Strategy::Incorrect
            }
            Some((faulty_idx, FaultyStrategy::Skip)) if faulty_idx == idx => {
                mocks::Strategy::Skip {
                    height: Height::new(MIN_TARGET_HEIGHT),
                }
            }
            _ => mocks::Strategy::Correct,
        };
        let automaton = mocks::Application::new(strategy);
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
                // Kept well below the reachable height range so tip advancement
                // crosses the activity threshold (pruning + AckCertified arm) and the
                // window bound (AckHeight arm) become reachable, while still leaving
                // enough room for honest 3-of-4 progress to target <= LIVE_TARGET_CEILING.
                window: NZU64!(5),
                activity_timeout: HeightDelta::new(5),
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
        senders.insert(participant.clone(), sender.clone());
        handles.push(engine.start((sender, receiver)));
    }
    SpawnedEngines {
        reporters,
        senders,
        handles,
        monitors,
    }
}

fn spawn_bad_ack_injector<S>(
    context: deterministic::Context,
    fixture: &Fixture<S>,
    senders: &BTreeMap<PublicKey, Sender<PublicKey, deterministic::Context>>,
    unknown_sender: Option<Sender<PublicKey, deterministic::Context>>,
    epoch: Epoch,
    priority_acks: bool,
) -> commonware_runtime::Handle<()>
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey, Signature = U64>,
{
    let fixture = fixture.clone();
    let senders = senders.clone();
    context
        .child("bad_ack_injector")
        .spawn(move |context| async move {
            let Some(target) = fixture.participants.get(1).cloned() else {
                return;
            };
            let Some(mut signer_sender) = fixture
                .participants
                .first()
                .and_then(|signer| senders.get(signer).cloned())
            else {
                return;
            };
            let mut invalid_sender = fixture
                .participants
                .get(2)
                .and_then(|p| senders.get(p).cloned());

            for delay_ms in [0, 1, 5, 25, 75, 150] {
                context.sleep(Duration::from_millis(delay_ms)).await;
                for h in 0..=MAX_TARGET_HEIGHT {
                    let height = Height::new(h);
                    send_ack(
                        &mut signer_sender,
                        &target,
                        signed_ack(&fixture.schemes[0], epoch, height, bad_item_digest(height)),
                        priority_acks,
                    );
                    send_ack(
                        &mut signer_sender,
                        &target,
                        signed_ack(
                            &fixture.schemes[0],
                            Epoch::new(epoch.get() + OUT_OF_BOUNDS_EPOCH_DELTA),
                            height,
                            expected_item_digest(height),
                        ),
                        priority_acks,
                    );
                    if let Some(sender) = invalid_sender.as_mut() {
                        let mut invalid_ack = signed_ack(
                            &fixture.schemes[2],
                            epoch,
                            height,
                            expected_item_digest(height),
                        );
                        invalid_ack.attestation.signature = U64::new(INVALID_SIGNATURE_ID).into();
                        send_ack(sender, &target, invalid_ack, priority_acks);
                    }
                }
            }

            let Some(peer_mismatch_target) = fixture.participants.get(2).cloned() else {
                return;
            };
            if let Some(mut mismatched_sender) = fixture
                .participants
                .get(1)
                .and_then(|p| senders.get(p).cloned())
            {
                send_ack(
                    &mut mismatched_sender,
                    &peer_mismatch_target,
                    signed_ack(
                        &fixture.schemes[0],
                        epoch,
                        Height::new(MIN_TARGET_HEIGHT),
                        expected_item_digest(Height::new(MIN_TARGET_HEIGHT)),
                    ),
                    priority_acks,
                );
            }

            let _ = signer_sender.send(
                Recipients::One(target.clone()),
                vec![0xA6, 0x60, 0xFF],
                priority_acks,
            );

            if let Some(mut unknown_sender) = unknown_sender {
                send_ack(
                    &mut unknown_sender,
                    &target,
                    signed_ack(
                        &fixture.schemes[0],
                        epoch,
                        Height::new(MIN_TARGET_HEIGHT),
                        expected_item_digest(Height::new(MIN_TARGET_HEIGHT)),
                    ),
                    priority_acks,
                );
            }
        })
}

fn signed_ack<S>(
    scheme: &S,
    epoch: Epoch,
    height: Height,
    digest: Sha256Digest,
) -> Ack<S, Sha256Digest>
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
{
    Ack::sign(scheme, epoch, Item { height, digest }).expect("signer scheme must sign")
}

fn send_ack<S>(
    sender: &mut Sender<PublicKey, deterministic::Context>,
    target: &PublicKey,
    ack: Ack<S, Sha256Digest>,
    priority_acks: bool,
) where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
{
    let _ = sender.send(
        Recipients::One(target.clone()),
        TipAck {
            ack,
            tip: Height::zero(),
        }
        .encode(),
        priority_acks,
    );
}

fn unknown_peer(participants: &[PublicKey]) -> PublicKey {
    for seed in UNKNOWN_PEER_SEEDS {
        let candidate = PrivateKey::from_seed(seed).public_key();
        if !participants.contains(&candidate) {
            return candidate;
        }
    }
    panic!("unable to derive non-participant peer");
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

        let unknown_sender = if input.inject_bad_ack {
            let unknown = unknown_peer(&fixture.participants);
            let mut tracked = fixture.participants.clone();
            tracked.push(unknown.clone());
            oracle.manager().track(1, Set::from_iter_dedup(tracked));
            let (sender, _receiver) = oracle
                .control(unknown.clone())
                .register(0, TEST_QUOTA)
                .await
                .unwrap();
            oracle
                .add_link(unknown, fixture.participants[1].clone(), link(&input))
                .await
                .ok();
            Some(sender)
        } else {
            None
        };

        let spawned = spawn_engines(
            context.child("validators"),
            &fixture,
            &mut registrations,
            &mut oracle,
            Duration::from_millis(input.rebroadcast_ms),
            input.priority_acks,
            epoch,
            input.faulty_node,
        );

        let _bad_ack_injector = input.inject_bad_ack.then(|| {
            spawn_bad_ack_injector(
                context.child("network_faults"),
                &fixture,
                &spawned.senders,
                unknown_sender,
                epoch,
                input.priority_acks,
            )
        });

        let watchers = spawn_target_watchers(
            context.child("reporter"),
            &spawned.reporters,
            target_height,
            epoch,
        );

        let completed = select! {
            results = join_all(watchers) => {
                results.iter().all(|r| matches!(r, Ok(true)))
            },
            _ = context.sleep(MAX_SLEEP_DURATION) => false,
        };

        check_no_conflicting_certs(&spawned.reporters).await;

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

        // Refresh the epoch after the liveness assertion so the epoch-update
        // branch and `SafeTip::reconcile` are exercised without changing the
        // progress oracle above.
        if input.epoch_transition {
            for monitor in &spawned.monitors {
                monitor.update(Epoch::new(NEXT_EPOCH));
            }
            context.sleep(Duration::from_millis(REPORTER_POLL_MS)).await;
        }

        // Restart every engine on its existing journal partition so startup
        // replays the journaled acks/certs/tips. Runs after the liveness
        // assertion, so it cannot affect it.
        if input.restart {
            // Re-registering closes the old channel receivers before restart.
            let mut registrations = register_participants(&mut oracle, &fixture.participants).await;
            context.sleep(Duration::from_millis(REPORTER_POLL_MS)).await;
            for handle in spawned.handles {
                handle.abort();
                let _ = handle.await;
            }
            let restarted = spawn_engines(
                context.child("validators_restart"),
                &fixture,
                &mut registrations,
                &mut oracle,
                Duration::from_millis(input.rebroadcast_ms),
                input.priority_acks,
                epoch,
                None,
            );
            context.sleep(MAX_SLEEP_DURATION).await;
            check_no_conflicting_certs(&restarted.reporters).await;
        }
    });
}

fn expected_item_digest(height: Height) -> Sha256Digest {
    let payload = format!("data for height {height}");
    let mut hasher = Sha256::default();
    hasher.update(payload.as_bytes());
    hasher.finalize()
}

fn bad_item_digest(height: Height) -> Sha256Digest {
    let payload = format!("bad data for height {height}");
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
