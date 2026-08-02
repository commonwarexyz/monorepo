//! Deterministic multi-node Multimmit integration and Twins tests.
//!
//! Every scenario runs complete production engines through [`mocks::cluster::Cluster`]. Schedules
//! are deterministic per seed; failures replay exactly.

use super::mocks::cluster::{Cluster, ClusterOptions};
use crate::{
    Roundable as _, Viewable as _,
    multimmit::{
        actors::{
            resolver::Served,
            wire::{CertificateMessage, ConsensusMessage, Envelope, EnvelopeConfig},
        },
        machine::{Inspection, Profile, Role, Tuning},
    },
    types::{Height, Participant, View, ViewDelta},
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{
    Hasher as _, Sha256,
    bls12381::primitives::variant::{MinPk, MinSig},
    sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::{Receiver as _, Recipients, Sender as _};
use commonware_runtime::{
    Clock as _, Metrics as _, Quota, Runner as _, Spawner as _, Supervisor as _,
    deterministic::{Config as DeterministicConfig, Runner as DeterministicRunner},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU32, NonZeroU64},
    sync::Arc,
    time::Duration,
};

const fn options(seed: u64, n: u32) -> ClusterOptions {
    ClusterOptions {
        n,
        seed,
        extras: 0,
        leaders: None,
        quota: None,
        latency: None,
        jitter: None,
        production: None,
        view_retention: None,
    }
}

#[test_traced]
fn producer_subset_progresses_with_validator_only_nodes() {
    let executor = DeterministicRunner::timed(Duration::from_secs(300));
    executor.start(|context| async move {
        let producers = vec![Participant::new(4), Participant::new(1)];
        let mut cluster =
            Cluster::<MinPk>::new_with_producers(&context, options(898, 6), producers.clone())
                .await;
        let all = [0usize, 1, 2, 3, 4, 5];
        let chains = [0u32, 1];
        cluster.start_all().await;
        cluster.produce_every(1);
        cluster.wait_finalized(&all, &chains, 2, 2400).await;

        cluster.crash(3).await;
        cluster.restart(3).await;
        cluster.crash(4).await;
        cluster.restart(4).await;
        cluster.wait_finalized(&all, &chains, 3, 2400).await;

        for node in all {
            let inspection = cluster.inspect(node).await.expect("engine remains live");
            assert_eq!(inspection.chain_progress().len(), producers.len());
            let expected = producers
                .iter()
                .position(|producer| usize::from(*producer) == node)
                .map(|chain| u32::try_from(chain).expect("chain index is representable"));
            assert_eq!(
                inspection.producer().map(|producer| producer.chain().get()),
                expected
            );
        }
        cluster.observe_finality(&all).await;
    });
}

fn metric_total(metrics: &str, suffix: &str) -> u64 {
    metrics
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|name| name.ends_with(suffix))
        })
        .map(|line| {
            line.split_whitespace()
                .next_back()
                .expect("metric sample has a value")
                .parse::<u64>()
                .expect("counter sample is an integer")
        })
        .sum()
}

fn assert_profile_resource_bounds(
    inspection: &Inspection<Sha256Digest>,
    profile: &Profile<Sha256, MinPk>,
) {
    let resources = profile.resources();
    assert!(inspection.cached_artifacts() <= resources.max_cached_artifacts());
    assert!(inspection.waiting_artifacts() <= resources.max_dependency_waiters());
    assert!(inspection.future_artifacts() <= resources.max_future_artifacts());
    assert!(inspection.verification_jobs().len() <= resources.max_inflight_verifications());
    assert!(inspection.local_artifacts() <= resources.max_cached_artifacts());
    assert!(inspection.outbox().len() <= resources.max_outbox_effects());
    assert!(inspection.resolution_jobs() <= resources.max_dependency_waiters());
    assert!(inspection.pools().len() <= resources.max_finality_pools());
    assert!(inspection.finality().len() <= resources.max_finality_pools());
    assert!(inspection.retained_artifact_references() <= resources.max_cached_artifacts());
    assert_eq!(
        inspection.pending_artifacts()
            + inspection.waiting_artifacts()
            + inspection.ready_artifacts().len()
            + inspection.dropped_artifacts(),
        inspection.cached_artifacts(),
        "every retained artifact has exactly one lifecycle state"
    );
    assert_eq!(
        inspection.chain_progress().len(),
        profile.protocol().codec_config().chains()
    );
    if let Some(producer) = inspection.producer() {
        assert_eq!(
            producer.pipeline_depth(),
            u64::try_from(profile.protocol().codec_config().pipeline_depth())
                .expect("pipeline depth is representable")
        );
        assert!(producer.vote_shares() <= profile.protocol().codec_config().participants());
    }
}

#[test_traced]
fn storage_sync_releaser_stops_across_restart() {
    let executor = DeterministicRunner::timed(Duration::from_secs(60));
    executor.start(|context| async move {
        let mut cluster = Cluster::<MinPk>::new(&context, options(899, 6)).await;
        cluster.set_storage_sync_interval(Duration::from_millis(20));
        cluster.start_one(0).await;
        cluster.await_ready(&[0]).await;

        cluster.crash(0).await;
        cluster.restart(0).await;
        cluster.crash(0).await;
    });
}

#[test_traced]
fn checkpoint_compaction_soak_survives_a_bounded_restart() {
    let executor = DeterministicRunner::timed(Duration::from_secs(1800));
    executor.start(|context| async move {
        const NODES: usize = 6;
        const RETENTION: u64 = 8;
        const CHECKPOINT_INTERVAL: u64 = RETENTION * 4;
        const REQUIRED_CURSOR_ADVANCE: u64 = CHECKPOINT_INTERVAL * 3;
        const REQUIRED_VIEW_ADVANCE: u64 = RETENTION * 4;
        const BUILDS_PER_CHAIN: u64 = 4;
        const MAX_POLLS: usize = 12_000;

        let all = [0usize, 1, 2, 3, 4, 5];
        let peers = [0usize, 1, 2, 3, 4];
        let chains = [0u32, 1, 2, 3, 4, 5];
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                n: NODES as u32,
                seed: 900,
                extras: 0,
                leaders: None,
                quota: None,
                latency: Some(Duration::from_millis(15)),
                jitter: Some(Duration::from_millis(12)),
                production: Some(Duration::from_millis(100)),
                view_retention: Some(ViewDelta::new(RETENTION)),
            },
        )
        .await;
        cluster.set_checkpoint_interval(
            NonZeroU64::new(CHECKPOINT_INTERVAL).expect("checkpoint interval is non-zero"),
        );
        cluster.start_all().await;

        let mut initial_views = [0u64; NODES];
        let mut initial_cursors = [0u64; NODES];
        let mut previous_views = [0u64; NODES];
        let mut previous_cursors = [0u64; NODES];
        let mut previous_finality_floors = [0u64; NODES];
        for node in all {
            let inspection = cluster.inspect(node).await.expect("engine remains live");
            initial_views[node] = inspection.view().get();
            initial_cursors[node] = inspection.cursor().get();
            previous_views[node] = inspection.view().get();
            previous_cursors[node] = inspection.cursor().get();
            previous_finality_floors[node] = inspection.finality_floor().get();
        }

        // Admit exactly four builds per producer. Consensus keeps advancing after production
        // stops, so the remainder of the soak measures protocol and storage work rather than an
        // unbounded synthetic workload.
        for target in 1..=BUILDS_PER_CHAIN {
            cluster.produce_once();
            cluster.wait_produced(&all, target, 1200).await;
        }
        cluster.stop_producing();

        let mut observed_first_prune = [false; NODES];
        let mut observed_second_prune = [false; NODES];
        let mut max_finality_facts = [0usize; NODES];
        let mut completed = false;
        for poll in 0..MAX_POLLS {
            context.sleep(Duration::from_millis(50)).await;

            let mut views_advanced = true;
            let mut cursors_advanced = true;
            let mut chains_finalized = true;
            for node in all {
                let inspection = cluster.inspect(node).await.expect("engine remains live");
                let view = inspection.view().get();
                let cursor = inspection.cursor().get();
                let finality_floor = inspection.finality_floor().get();
                assert!(view >= previous_views[node], "engine {node} regressed its view");
                assert!(
                    cursor >= previous_cursors[node],
                    "engine {node} regressed its journal cursor"
                );
                assert!(
                    finality_floor >= previous_finality_floors[node],
                    "engine {node} regressed its finality floor"
                );
                previous_views[node] = view;
                previous_cursors[node] = cursor;
                previous_finality_floors[node] = finality_floor;
                max_finality_facts[node] =
                    max_finality_facts[node].max(inspection.finality().len());

                views_advanced &=
                    view.saturating_sub(initial_views[node]) >= REQUIRED_VIEW_ADVANCE;
                cursors_advanced &=
                    cursor.saturating_sub(initial_cursors[node]) >= REQUIRED_CURSOR_ADVANCE;
                chains_finalized &= chains.iter().all(|chain| {
                    inspection.chain_progress()[*chain as usize]
                        .finalized()
                        .get()
                        >= BUILDS_PER_CHAIN
                });
            }
            cluster.observe_finality(&all).await;

            if poll.is_multiple_of(10) {
                for node in all {
                    let sections = cluster.journal_sections(node).await;
                    if matches!(sections.as_slice(), [section] if *section >= 1) {
                        observed_first_prune[node] = true;
                    }
                    if matches!(sections.as_slice(), [section] if *section >= 2) {
                        observed_second_prune[node] = true;
                    }
                }
            }

            if views_advanced
                && cursors_advanced
                && chains_finalized
                && observed_first_prune.iter().all(|observed| *observed)
                && observed_second_prune.iter().all(|observed| *observed)
            {
                completed = true;
                break;
            }
        }
        assert!(completed, "cluster did not complete the bounded storage soak");
        assert!(
            max_finality_facts.iter().all(|facts| *facts >= 2),
            "jittered execution never exposed multiple concurrent finality facts: {max_finality_facts:?}"
        );
        for node in all {
            assert!(cluster.checkpoint_blobs(node).await > 0);
        }

        let before = cluster.inspect(5).await.expect("engine remains live");
        let application = cluster.app(5).log();
        cluster.crash(5).await;
        cluster
            .wait_view(
                &peers,
                View::new(before.view().get() + RETENTION / 2),
                1200,
            )
            .await;
        for node in peers {
            let advanced = cluster
                .inspect(node)
                .await
                .expect("peer remains live")
                .view()
                .get()
                .saturating_sub(before.view().get());
            assert!(
                advanced < RETENTION,
                "peer {node} advanced {advanced} views during a within-retention restart"
            );
        }

        cluster.restart(5).await;
        let recovered = cluster.inspect(5).await.expect("engine restarts");
        assert_eq!(recovered.generation(), before.generation() + 1);
        cluster.observe_finality(&all).await;
        assert!(Arc::ptr_eq(&application, &cluster.app(5).log()));
        // Recovery may discard the latest rolled section when no barrier reached it before the
        // crash. The soak above already observed two completed rolls; only the single live suffix
        // must remain after restart.
        assert!(matches!(
            cluster.journal_sections(5).await.as_slice(),
            [_]
        ));

        cluster.produce_once();
        cluster
            .wait_finalized(&all, &chains, BUILDS_PER_CHAIN + 1, 3600)
            .await;
        cluster.observe_finality(&all).await;
    });
}

#[test_traced]
fn retained_artifacts_plateau_across_retention_windows() {
    let executor = DeterministicRunner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        const NODES: usize = 6;
        const RETENTION: u64 = 16;
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                n: NODES as u32,
                seed: 91,
                extras: 0,
                leaders: None,
                quota: None,
                latency: Some(Duration::from_millis(10)),
                jitter: None,
                production: Some(Duration::from_millis(100)),
                view_retention: Some(ViewDelta::new(RETENTION)),
            },
        )
        .await;
        cluster.set_checkpoint_interval(
            NonZeroU64::new(RETENTION * 4).expect("checkpoint interval is non-zero"),
        );
        let fixture = cluster.fixture();
        let bounds = Profile::new(
            fixture.config.clone(),
            Role::Validator(Participant::new(0)),
            Tuning {
                view_timeout: Duration::from_millis(500),
                production_interval: Duration::from_millis(100),
                view_retention: ViewDelta::new(RETENTION),
                ..Tuning::default()
            },
        )
        .expect("cluster profile is valid");
        cluster.start_all().await;
        cluster.produce();

        // Advance every node past `target` while checking every variable-size Inspection field
        // against the same profile-derived ceilings used by the engines.
        let advance_past = async |cluster: &mut Cluster<MinPk>, target: u64| {
            for _ in 0..4000 {
                cluster.refresh();
                context.sleep(Duration::from_millis(50)).await;
                let mut lowest = u64::MAX;
                for node in 0..NODES {
                    let inspection = cluster
                        .inspect(node)
                        .await
                        .unwrap_or_else(|| panic!("engine {node} is still running"));
                    lowest = lowest.min(inspection.view().get());
                    assert_profile_resource_bounds(&inspection, &bounds);
                }
                if lowest >= target {
                    for node in 0..NODES {
                        let sections = cluster.journal_sections(node).await;
                        assert!(
                            (1..=2).contains(&sections.len()),
                            "node {node} retained an invalid journal inventory: {sections:?}"
                        );
                        let checkpoints = cluster.checkpoint_blobs(node).await;
                        assert!(
                            (1..=2).contains(&checkpoints),
                            "node {node} retained {checkpoints} checkpoint slots"
                        );
                    }
                    return;
                }
            }
            panic!("cluster never advanced past view {target}");
        };

        // Warm through the richest retained window, then keep checking the same independent
        // ceilings and complete durable-blob inventory across several later windows.
        for target in [RETENTION * 8, RETENTION * 10, RETENTION * 12] {
            advance_past(&mut cluster, target).await;
        }
    });
}

#[test_traced]
fn n7_f1_cluster_survives_crash_and_recovery() {
    let executor = DeterministicRunner::timed(Duration::from_secs(600));
    executor.start(|context| async move {
        let mut cluster = Cluster::<MinPk>::new(&context, options(81, 7)).await;
        cluster.start_all().await;
        // Keep production poll-driven so the prefix checker observes every bounded diagnostic
        // tail even when persistence becomes fast enough to order hundreds of blocks per tick.
        cluster.produce_every(1);

        let all = [0usize, 1, 2, 3, 4, 5, 6];
        let all_chains = [0u32, 1, 2, 3, 4, 5, 6];
        cluster.wait_finalized(&all, &all_chains, 1, 1200).await;

        // Crash one validator uncleanly; the remaining n-1 = 6 >= n-f keep finalizing.
        cluster.crash(6).await;
        let rest = [0usize, 1, 2, 3, 4, 5];
        cluster
            .wait_finalized(&rest, &[0, 1, 2, 3, 4, 5], 2, 1200)
            .await;

        // The crashed node recovers from its own durable prefix and catches up.
        cluster.restart(6).await;
        cluster.wait_finalized(&all, &all_chains, 3, 2400).await;
        cluster.observe_finality(&all).await;
    });
}

fn run_hailstorm(seed: u64) -> String {
    const NODES: usize = 6;
    const RETENTION: u64 = 4;
    const CRASHES: [usize; 4] = [5, 2, 4, 1];

    let executor = DeterministicRunner::new(
        commonware_runtime::deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(900))),
    );
    executor.start(|context| async move {
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                n: NODES as u32,
                seed: 200 + seed,
                extras: 0,
                leaders: None,
                quota: None,
                latency: Some(Duration::from_millis(15)),
                jitter: Some(Duration::from_millis(12)),
                production: Some(Duration::from_millis(100)),
                view_retention: Some(ViewDelta::new(RETENTION)),
            },
        )
        .await;
        cluster.start_all().await;
        cluster.produce_every(5);

        let all = (0..NODES).collect::<Vec<_>>();
        let chains = (0..NODES as u32).collect::<Vec<_>>();
        let mut finalized_height = 1;
        cluster
            .wait_finalized(&all, &chains, finalized_height, 2400)
            .await;

        for crashed in CRASHES {
            let before = cluster
                .inspect(crashed)
                .await
                .expect("engine remains live before crash");
            let generation = before.generation();
            let crashed_view = before.view();
            cluster.crash(crashed).await;

            let survivors = all
                .iter()
                .copied()
                .filter(|node| *node != crashed)
                .collect::<Vec<_>>();
            let survivor_view = View::new(crashed_view.get() + RETENTION + 2);
            cluster.wait_view(&survivors, survivor_view, 2400).await;

            cluster.restart(crashed).await;
            let recovered = cluster
                .inspect(crashed)
                .await
                .expect("restarted engine remains live");
            assert_eq!(recovered.generation(), generation + 1);

            cluster
                .wait_view(&all, View::new(survivor_view.get() + 2), 3600)
                .await;
            finalized_height += 1;
            cluster
                .wait_finalized(&all, &chains, finalized_height, 3600)
                .await;
            cluster.observe_finality(&all).await;
        }

        finalized_height += 1;
        cluster
            .wait_finalized(&all, &chains, finalized_height, 3600)
            .await;
        cluster.observe_finality(&all).await;
        context.auditor().state()
    })
}

#[test_traced]
fn hailstorm_restarts_catch_up_beyond_retention() {
    assert_eq!(run_hailstorm(0), run_hailstorm(0));
}

#[test_traced]
fn staggered_startup_recovers_after_initial_asynchrony() {
    let executor = DeterministicRunner::timed(Duration::from_secs(600));
    executor.start(|context| async move {
        const NODES: usize = 6;
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                n: NODES as u32,
                seed: 201,
                extras: 0,
                leaders: None,
                quota: None,
                latency: Some(Duration::from_millis(40)),
                jitter: Some(Duration::from_millis(35)),
                production: Some(Duration::from_millis(100)),
                view_retention: Some(ViewDelta::new(4)),
            },
        )
        .await;
        cluster
            .set_network_conditions(Duration::from_millis(40), Duration::from_millis(35), 0.0)
            .await;
        cluster.produce_every(5);

        for node in 0..NODES {
            cluster.start_one(node).await;
            cluster.await_ready(&[node]).await;
            context.sleep(Duration::from_millis(200)).await;
        }
        context.sleep(Duration::from_secs(2)).await;
        cluster
            .set_network_conditions(Duration::from_millis(40), Duration::from_millis(35), 1.0)
            .await;

        let all = (0..NODES).collect::<Vec<_>>();
        let chains = (0..NODES as u32).collect::<Vec<_>>();
        for height in 1..=3 {
            cluster.wait_finalized(&all, &chains, height, 3600).await;
            cluster.observe_finality(&all).await;
        }
    });
}

#[test_traced]
fn n11_f2_finalizes_under_partition_and_heal() {
    let executor = DeterministicRunner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                view_retention: Some(ViewDelta::new(64)),
                ..options(82, 11)
            },
        )
        .await;
        cluster.start_all().await;
        cluster.produce_every(10);

        let all = [0usize, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let chains = (0..11u32).collect::<Vec<_>>();
        cluster.wait_finalized(&all, &chains, 1, 600).await;

        // Cut a two-node minority off; the nine-node majority is exactly n - f and keeps going.
        let majority = [0usize, 1, 2, 3, 4, 5, 6, 7, 8];
        let minority = [9usize, 10];
        cluster.partition(&majority, &minority).await;
        cluster
            .wait_finalized(&majority, &[0, 1, 2, 3, 4, 5, 6, 7, 8], 2, 600)
            .await;

        // After healing, the minority resumes finality progress with the majority.
        cluster.heal().await;
        cluster.wait_finalized(&all, &chains, 2, 600).await;
        cluster.observe_finality(&all).await;
    });
}

#[test_traced]
fn stalled_producer_does_not_block_other_chains() {
    let executor = DeterministicRunner::timed(Duration::from_secs(600));
    executor.start(|context| async move {
        let mut cluster = Cluster::<MinPk>::new(&context, options(92, 6)).await;
        let fixture = cluster.fixture();
        let bounds = Profile::new(
            fixture.config.clone(),
            Role::Validator(Participant::new(0)),
            Tuning {
                view_timeout: Duration::from_millis(500),
                production_interval: Duration::from_millis(100),
                view_retention: ViewDelta::new(16),
                ..Tuning::default()
            },
        )
        .expect("cluster profile is valid");
        cluster.start_all().await;

        // Producer five never returns a body. The other producers, including every scheduled
        // leader when its turn arrives, must continue through multiple full leader rotations.
        cluster.produce_except(&[5]);
        let all = [0usize, 1, 2, 3, 4, 5];
        let starting_view = cluster
            .inspect(0)
            .await
            .expect("engine remains live")
            .view();
        cluster
            .wait_finalized(&all, &[0, 1, 2, 3, 4], 3, 2400)
            .await;
        cluster
            .wait_view(&all, View::new(starting_view.get() + 12), 2400)
            .await;

        for node in all {
            let inspection = cluster.inspect(node).await.expect("engine remains live");
            assert_profile_resource_bounds(&inspection, &bounds);
            let stalled = inspection
                .chain_progress()
                .iter()
                .find(|progress| progress.chain().get() == 5)
                .expect("stalled chain is tracked");
            assert_eq!(stalled.known().get(), 0);
            assert_eq!(stalled.finalized().get(), 0);
        }
        assert_eq!(cluster.app(5).log().lock().built, 0);
        cluster.observe_finality(&all).await;
    });
}

#[test_traced]
fn lossy_jittered_network_converges_after_healing() {
    let executor = DeterministicRunner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        let mut cluster = Cluster::<MinPk>::new(&context, options(93, 6)).await;
        cluster.start_all().await;
        cluster.produce_every(5);

        let all = [0usize, 1, 2, 3, 4, 5];
        let chains = [0u32, 1, 2, 3, 4, 5];
        cluster.wait_finalized(&all, &chains, 1, 1200).await;

        // Messages are dropped and links have variable latency. This test does not script
        // duplication, held delivery, or reordering, so it makes no claim about those faults.
        cluster
            .set_network_conditions(Duration::from_millis(40), Duration::from_millis(35), 0.55)
            .await;
        cluster.produce_once();
        cluster.observe_finality_progress(&all, 50).await;
        cluster.stop_producing();
        cluster.heal().await;

        cluster.produce_every(5);
        cluster.wait_finalized(&all, &chains, 2, 2400).await;
        cluster.observe_finality(&all).await;
    });
}

#[test_traced]
fn duplicated_reordered_certificates_converge_after_healing() {
    let executor = DeterministicRunner::new(
        DeterministicConfig::new()
            .with_seed(102)
            .with_timeout(Some(Duration::from_secs(600))),
    );
    executor.start(|context| async move {
        const EXTRA: usize = 6;
        const TARGET: usize = 5;
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                extras: 1,
                latency: Some(Duration::from_millis(200)),
                jitter: Some(Duration::from_millis(150)),
                ..options(102, 6)
            },
        )
        .await;
        cluster.start_all().await;
        cluster.produce_once();

        let all = [0usize, 1, 2, 3, 4, 5];
        let majority = [0usize, 1, 2, 3, 4];
        let minority = [TARGET];
        let chains = [0u32, 1, 2, 3, 4, 5];
        cluster.wait_finalized(&all, &chains, 1, 2400).await;
        cluster.stop_producing();

        cluster.partition(&majority, &minority).await;
        let fixture = cluster.fixture();
        let epoch = fixture.config.epoch();
        let target_view = cluster
            .inspect(TARGET)
            .await
            .expect("target remains live")
            .view()
            .get();
        let current = fixture.vqc(target_view);
        let earlier = fixture.vqc(target_view + 1);
        let later = fixture.vqc(target_view + 2);
        let (mut sender, _receiver) = cluster.tap(EXTRA, 2).await;
        let recipient = Recipients::One(cluster.identity(TARGET));

        // Install each future exit before releasing its predecessor. The duplicate exercises
        // idempotence while the restart proves that recovery still serves both future views.
        for _ in 0..2 {
            let _ = sender.send(
                recipient.clone(),
                Envelope::new(epoch, CertificateMessage::Vqc(later.clone())).encode(),
                true,
            );
        }
        let mut served = false;
        for _ in 0..400 {
            if matches!(
                cluster.serve(TARGET, View::new(target_view + 2)).await,
                Some(Served::Vqc(proof)) if proof.as_ref() == &later
            ) {
                served = true;
                break;
            }
            context.sleep(Duration::from_millis(25)).await;
        }
        assert!(served, "target retained the later future V-QC");

        let _ = sender.send(
            recipient.clone(),
            Envelope::new(epoch, CertificateMessage::Vqc(earlier.clone())).encode(),
            true,
        );
        served = false;
        for _ in 0..400 {
            if matches!(
                cluster.serve(TARGET, View::new(target_view + 1)).await,
                Some(Served::Vqc(proof)) if proof.as_ref() == &earlier
            ) {
                served = true;
                break;
            }
            context.sleep(Duration::from_millis(25)).await;
        }
        assert!(served, "target retained the earlier future V-QC");

        let mut durable = false;
        for _ in 0..400 {
            let inspection = cluster.inspect(TARGET).await.expect("target remains live");
            if inspection.pending_barrier().is_none() {
                durable = true;
                break;
            }
            context.sleep(Duration::from_millis(25)).await;
        }
        assert!(durable, "future exit forwarding becomes durable");

        cluster.crash(TARGET).await;
        cluster.restart(TARGET).await;
        served = false;
        for _ in 0..400 {
            if matches!(
                cluster.serve(TARGET, View::new(target_view + 2)).await,
                Some(Served::Vqc(proof)) if proof.as_ref() == &later
            ) {
                served = true;
                break;
            }
            context.sleep(Duration::from_millis(25)).await;
        }
        assert!(served, "recovery serves the later future V-QC");

        served = false;
        for _ in 0..400 {
            let requested = View::new(target_view + 1);
            match cluster.serve(TARGET, requested).await {
                Some(Served::Vqc(proof)) if proof.as_ref() == &earlier => {
                    served = true;
                    break;
                }
                Some(Served::Lqc(proof)) if proof.view() >= requested => {
                    served = true;
                    break;
                }
                _ => {}
            }
            context.sleep(Duration::from_millis(25)).await;
        }
        assert!(
            served,
            "recovery serves the earlier future V-QC or a covering L-QC"
        );
        let _ = sender.send(
            recipient,
            Envelope::new(epoch, CertificateMessage::Vqc(current.clone())).encode(),
            true,
        );
        served = false;
        for _ in 0..400 {
            if matches!(
                cluster.serve(TARGET, View::new(target_view)).await,
                Some(Served::Vqc(proof)) if proof.as_ref() == &current
            ) {
                served = true;
                break;
            }
            context.sleep(Duration::from_millis(25)).await;
        }
        assert!(served, "target retained the current V-QC after recovery");
        cluster.observe_finality_progress(&all, 20).await;

        cluster.heal().await;
        cluster.produce_once();
        cluster.wait_finalized(&all, &chains, 2, 3600).await;
        cluster.observe_finality(&all).await;
    });
}

#[test_traced]
fn validator_recovers_durable_state_within_retention_window() {
    let executor = DeterministicRunner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        const RETENTION: u64 = 16;
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                view_retention: Some(ViewDelta::new(RETENTION)),
                ..options(94, 6)
            },
        )
        .await;

        let all = [0usize, 1, 2, 3, 4, 5];
        let peers = [0usize, 1, 2, 3, 4];
        let chains = [0u32, 1, 2, 3, 4, 5];
        cluster.start_all().await;
        cluster.produce_once();
        cluster.wait_produced(&[5], 1, 1200).await;
        cluster.wait_finalized(&all, &chains, 1, 2400).await;

        let before = cluster.inspect(5).await.expect("engine remains live");
        let produced_before = before.produced_blocks();
        let finalized_height_before = before
            .chain_progress()
            .iter()
            .map(|progress| progress.finalized().get())
            .min()
            .expect("inspection covers every producer chain");
        let crashed_view = before.view();
        let recovery_view = View::new(crashed_view.get() + 4);
        let application = cluster.app(5).log();
        let built_before = application.lock().built;

        // This is a real restart: the validator has already built and durably authorized a signed
        // producer block. Its full actor tree stops before peers advance within the retained view
        // horizon and the same storage partitions and application attachment are reopened.
        cluster.crash(5).await;
        cluster.wait_view(&peers, recovery_view, 1200).await;
        for peer in peers {
            let view = cluster
                .inspect(peer)
                .await
                .expect("peer remains live")
                .view();
            let advanced = view.get().saturating_sub(crashed_view.get());
            assert!(advanced > 0 && advanced < RETENTION);
        }

        cluster.restart(5).await;
        assert!(Arc::ptr_eq(&application, &cluster.app(5).log()));
        let recovered = cluster
            .inspect(5)
            .await
            .expect("restarted engine remains live");
        assert_eq!(recovered.produced_blocks(), produced_before);
        cluster.observe_finality(&all).await;
        cluster.wait_view(&all, recovery_view, 1200).await;

        cluster.produce_once();
        cluster.wait_produced(&[5], produced_before + 1, 2400).await;
        cluster
            .wait_finalized(&all, &chains, finalized_height_before + 1, 3600)
            .await;
        assert!(application.lock().built > built_before);
        cluster.observe_finality(&all).await;
    });
}

#[test_traced]
fn all_validators_recover_durable_timeout_batch_before_certificate() {
    let executor = DeterministicRunner::timed(Duration::from_secs(300));
    executor.start(|context| async move {
        const NODES: usize = 6;
        const EXTRA: usize = NODES;
        let stalled = View::new(1);
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                extras: 1,
                ..options(103, NODES as u32)
            },
        )
        .await;
        let fixture = cluster.fixture();
        let offline = fixture.config.leader(stalled).get() as usize;
        let online = (0..NODES)
            .filter(|node| *node != offline)
            .collect::<Vec<_>>();

        // No peer can circulate a timeout share before the crash. The extra identity only
        // witnesses each engine's post-sync publication.
        cluster
            .set_network_conditions(Duration::from_millis(2), Duration::ZERO, 0.0)
            .await;
        let (_relay, mut egress) = cluster.tap(EXTRA, 1).await;
        for &node in &online {
            cluster.set_directed_success_rate(node, EXTRA, 1.0).await;
            cluster.start_one(node).await;
        }
        cluster.await_ready(&online).await;

        let bounds = fixture
            .codec()
            .encoded_bounds::<MinPk, Sha256Digest>()
            .expect("wire bounds are valid");
        let wire = EnvelopeConfig {
            max_frame_bytes: bounds.max_consensus_frame_bytes(),
            epoch: fixture.config.epoch(),
            payload: fixture.codec(),
        };
        let mut novoters = BTreeSet::new();
        let mut nullifiers = BTreeSet::new();
        for _ in 0..1000 {
            let (sender, message) = select! {
                message = egress.recv() => message.expect("timeout publication remains observable"),
                () = context.sleep(Duration::from_millis(10)) => {
                    if novoters.len() == online.len() && nullifiers.len() == online.len() {
                        break;
                    }
                    continue;
                },
            };
            let message =
                Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(message, &wire)
                    .expect("engine emits canonical consensus traffic")
                    .into_payload();
            match message {
                ConsensusMessage::NoVote(novote) if novote.round().view() == stalled => {
                    assert!(fixture.verifier.verify_novote(&novote));
                    novoters.insert(sender);
                }
                ConsensusMessage::Nullify(nullify) if nullify.round().view() == stalled => {
                    assert!(fixture.verifier.verify_nullify(&nullify));
                    nullifiers.insert(sender);
                }
                ConsensusMessage::Vote(vote) if vote.round().view() == stalled => {
                    panic!("validator voted after durably choosing novote in view 1")
                }
                _ => {}
            }
            if novoters.len() == online.len() && nullifiers.len() == online.len() {
                break;
            }
        }
        assert_eq!(novoters.len(), online.len());
        assert_eq!(nullifiers.len(), online.len());

        let mut generations = BTreeMap::new();
        for &node in &online {
            let inspection = cluster.inspect(node).await.expect("engine remains live");
            assert_eq!(inspection.view(), stalled);
            assert_eq!(inspection.local_artifacts(), 2);
            assert!(inspection.pending_barrier().is_none());
            assert!(cluster.serve(node, stalled).await.is_none());
            generations.insert(node, inspection.generation());
        }
        for &node in &online {
            cluster.crash(node).await;
        }

        cluster
            .set_network_conditions(Duration::from_millis(2), Duration::ZERO, 1.0)
            .await;
        for &node in &online {
            cluster.restart(node).await;
            let recovered = cluster.inspect(node).await.expect("engine restarts");
            assert_eq!(recovered.generation(), generations[&node] + 1);
        }

        let mut exited = false;
        for _ in 0..1000 {
            context.sleep(Duration::from_millis(10)).await;
            exited = true;
            for &node in &online {
                let inspection = cluster.inspect(node).await.expect("engine remains live");
                exited &= inspection.view() > stalled;
            }
            if exited {
                break;
            }
        }
        if !exited {
            let mut stalled = Vec::new();
            for &node in &online {
                let inspection = cluster.inspect(node).await.expect("engine remains live");
                stalled.push((
                    node,
                    inspection.view(),
                    inspection.cached_artifacts(),
                    inspection.pending_artifacts(),
                    inspection.waiting_artifacts(),
                    inspection.local_artifacts(),
                    inspection.outbox().len(),
                ));
            }
            panic!("recovered timeout batches did not exit view 1: {stalled:?}");
        }

        for &node in &online {
            let mut retained = None;
            for _ in 0..100 {
                if let Some(proof) = cluster.serve(node, stalled).await {
                    retained = Some(proof);
                    break;
                }
                context.sleep(Duration::from_millis(10)).await;
            }
            match retained.expect("engine retains evidence for the recovered view") {
                Served::Nullification(proof) => {
                    assert_eq!(proof.view(), stalled);
                    assert!(fixture.verifier.verify_nullification(&proof));
                }
                Served::Vqc(proof) => assert_eq!(proof.view(), stalled),
                Served::Lqc(proof) => assert!(proof.view() >= stalled),
            }
        }
    });
}

#[test_traced]
fn validator_beyond_retention_resumes_from_covering_lqc_before_new_epoch_bootstrap() {
    let executor = DeterministicRunner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        const NODES: usize = 6;
        const OFFLINE: usize = NODES - 1;
        const RETENTION: u64 = 4;
        const CHECKPOINT_INTERVAL: u64 = 64;
        let all = [0usize, 1, 2, 3, 4, 5];
        let peers = [0usize, 1, 2, 3, 4];

        let mut old = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                view_retention: Some(ViewDelta::new(RETENTION)),
                ..options(98, NODES as u32)
            },
        )
        .await;
        old.set_checkpoint_interval(NonZeroU64::new(CHECKPOINT_INTERVAL).unwrap());
        old.start_all().await;
        old.produce_once();
        old.wait_produced(&[OFFLINE], 1, 1200).await;
        old.wait_finalized(&all, &[0, 1, 2, 3, 4, 5], 1, 2400).await;
        old.stop_producing();

        let old_epoch = old.fixture().config.epoch();
        let old_identities = old.identities();
        let before = old.inspect(OFFLINE).await.expect("engine remains live");
        let stopped_view = before.view();
        let stopped_finality_floor = before.finality_floor();
        let produced_before = before.produced_blocks();
        let finalized_height_before = before
            .chain_progress()
            .iter()
            .map(|progress| progress.finalized().get())
            .min()
            .expect("inspection covers every producer chain");
        assert!(
            before
                .chain_progress()
                .iter()
                .all(|progress| progress.finalized().get() > 0)
        );
        assert!(produced_before > 0);
        let application = old.app(OFFLINE).log();
        let built_before = application.lock().built;

        // With n=6 and f=1, the remaining n-f validators can advance beyond the offline
        // validator's retained recovery horizon without any greater-than-f execution.
        old.crash(OFFLINE).await;
        let view = stopped_view;
        for peer in peers {
            let mut retained = false;
            for _ in 0..200 {
                if let Some(proof) = old.serve(peer, view).await {
                    retained = match proof {
                        Served::Nullification(proof) => proof.view() == stopped_view,
                        Served::Vqc(proof) => proof.view() == stopped_view,
                        Served::Lqc(proof) => proof.view() >= stopped_view,
                    };
                    if retained {
                        break;
                    }
                }
                context.sleep(Duration::from_millis(25)).await;
            }
            assert!(retained, "peer {peer} initially serves the stopped view");
        }

        let beyond_retention = View::new(stopped_view.get() + RETENTION + CHECKPOINT_INTERVAL);
        old.wait_view(&peers, beyond_retention, 2400).await;
        for peer in peers {
            let inspection = old.inspect(peer).await.expect("peer remains live");
            assert!(inspection.retired_view() >= stopped_view);
        }

        for peer in peers {
            let mut covering_lqc = false;
            for _ in 0..400 {
                if matches!(
                    old.serve(peer, view).await,
                    Some(Served::Lqc(proof)) if proof.view() >= stopped_view
                ) {
                    covering_lqc = true;
                    break;
                }
                context.sleep(Duration::from_millis(25)).await;
            }
            assert!(
                covering_lqc,
                "peer {peer} does not serve an L-QC covering the retired view"
            );
            old.block_certificates(peer, OFFLINE);
        }

        old.restart(OFFLINE).await;
        let recovered = old
            .inspect(OFFLINE)
            .await
            .expect("same-epoch engine recovers");
        assert_eq!(recovered.epoch(), old_epoch);
        assert!(recovered.view() >= stopped_view);
        assert_eq!(recovered.produced_blocks(), produced_before);
        assert!(recovered.generation() > before.generation());
        old.observe_finality(&[OFFLINE]).await;

        old.observe_finality_progress(&[OFFLINE], 20).await;
        let resumed = old
            .inspect(OFFLINE)
            .await
            .expect("same-epoch engine remains live");
        assert!(resumed.view() > stopped_view);
        assert!(
            resumed.finality_floor() > stopped_finality_floor,
            "L-QC did not advance the finality floor"
        );
        assert_eq!(resumed.produced_blocks(), produced_before);
        assert_eq!(application.lock().built, built_before);

        // Re-anchoring is useful only if the same engine can resume ordinary producer and leader
        // transitions. Exercise both paths before replacing the old epoch.
        old.produce_once();
        old.wait_produced(&[OFFLINE], produced_before + 1, 2400)
            .await;
        old.wait_finalized(&all, &[0, 1, 2, 3, 4, 5], finalized_height_before + 1, 3600)
            .await;
        assert!(application.lock().built > built_before);
        old.observe_finality(&all).await;

        // Joining every old-epoch actor drops the old signing material. The public Engine has no
        // trusted import or used-key registry, so deployment must not reinterpret an empty prefix
        // as recovery under this key.
        old.crash(OFFLINE).await;
        for peer in peers {
            old.crash(peer).await;
        }
        drop(old);

        let mut new = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                view_retention: Some(ViewDelta::new(RETENTION)),
                ..options(99, NODES as u32)
            },
        )
        .await;
        let fixture = new.fixture();
        let new_epoch = fixture.config.epoch();
        assert_ne!(new_epoch, old_epoch);
        assert_ne!(new.identities(), old_identities);

        new.start_all().await;
        for node in all {
            let inspection = new.inspect(node).await.expect("new engine remains live");
            assert_eq!(inspection.epoch(), new_epoch);
            assert_eq!(inspection.finality_floor(), View::zero());
            assert_eq!(inspection.produced_blocks(), 0);
            assert!(
                inspection
                    .chain_progress()
                    .iter()
                    .all(|progress| progress.finalized() == Height::zero())
            );
        }

        new.produce_once();
        new.wait_finalized(&all, &[0, 1, 2, 3, 4, 5], 1, 2400).await;
        new.observe_finality(&all).await;
    });
}

#[test_traced]
fn resolver_recovers_exact_view_proof_after_rearmed_restart() {
    let executor = DeterministicRunner::timed(Duration::from_secs(600));
    executor.start(|context| async move {
        const SERVER: usize = 0;
        const TARGET: usize = 5;
        const EXTRA: usize = 6;
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                extras: 1,
                view_retention: Some(ViewDelta::new(128)),
                ..options(96, 6)
            },
        )
        .await;
        cluster.start_one(SERVER).await;
        cluster.start_one(TARGET).await;
        cluster.await_ready(&[SERVER, TARGET]).await;
        cluster.set_node_success_rate(TARGET, 0.0).await;
        cluster.block_certificates(SERVER, TARGET);

        let before = cluster.inspect(TARGET).await.expect("engine remains live");
        let crashed_view = before.view();
        let finality_floor_before = before.finality_floor();
        let key = crashed_view;
        let fixture = cluster.fixture();
        let epoch = fixture.config.epoch();
        let certificate = fixture.vqc(crashed_view.get());
        let (mut sender, _receiver) = cluster.tap(EXTRA, 2).await;
        let _ = sender.send(
            Recipients::One(cluster.identity(SERVER)),
            Envelope::new(epoch, CertificateMessage::Vqc(certificate.clone())).encode(),
            true,
        );
        let mut server_retained = false;
        for _ in 0..200 {
            if matches!(
                cluster.serve(SERVER, key).await,
                Some(Served::Vqc(proof)) if proof.as_ref() == &certificate
            ) {
                server_retained = true;
                break;
            }
            context.sleep(Duration::from_millis(25)).await;
        }
        assert!(
            server_retained,
            "serving engine retained the exact view proof"
        );

        cluster.crash(TARGET).await;
        cluster.restart(TARGET).await;
        assert_eq!(
            cluster
                .inspect(TARGET)
                .await
                .expect("restarted engine remains live")
                .finality_floor(),
            finality_floor_before
        );
        assert!(cluster.serve(TARGET, key).await.is_none());
        for _ in 0..40 {
            context.sleep(Duration::from_millis(25)).await;
        }

        cluster.heal_node(TARGET).await;
        let mut recovered = false;
        for _ in 0..800 {
            if let Some(Served::Vqc(proof)) = cluster.serve(TARGET, key).await
                && proof.as_ref() == &certificate
            {
                recovered = true;
                break;
            }
            context.sleep(Duration::from_millis(25)).await;
        }
        assert!(recovered, "restart recovers the exact requested view proof");
        for _ in 0..400 {
            let recovered = cluster
                .inspect(TARGET)
                .await
                .expect("restarted engine remains live");
            if recovered.view() > crashed_view {
                assert_eq!(recovered.finality_floor(), finality_floor_before);
                return;
            }
            context.sleep(Duration::from_millis(25)).await;
        }
        panic!("recovered exact view proof did not advance the restarted engine");
    });
}

#[test_traced]
fn authenticated_flood_services_engine_control_and_every_da_chain() {
    let executor = DeterministicRunner::timed(Duration::from_secs(600));
    executor.start(|context| async move {
        const SERVER: usize = 0;
        const TARGET: usize = 5;
        const EXTRA: usize = 6;

        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                extras: 1,
                view_retention: Some(ViewDelta::new(64)),
                ..options(100, 6)
            },
        )
        .await;
        for peer in 0..6 {
            if peer != TARGET {
                cluster.set_directed_success_rate(peer, TARGET, 0.0).await;
            }
        }
        cluster.start_one(TARGET).await;
        cluster.start_one(SERVER).await;
        cluster.await_ready(&[TARGET, SERVER]).await;

        let fixture = cluster.fixture();
        let epoch = fixture.config.epoch();
        let before = cluster.inspect(TARGET).await.expect("target is live");

        let (mut data, _) = cluster.tap(EXTRA, 0).await;
        let target = cluster.identity(TARGET);
        let flood = (0..5u32)
            .flat_map(|chain| {
                (0..8u64).map({
                    let fixture = &fixture;
                    move |variant| {
                        let commitment = Sha256::hash(&[
                            b"authenticated validation flood".as_slice(),
                            chain.to_be_bytes().as_slice(),
                            variant.to_be_bytes().as_slice(),
                        ]);
                        Envelope::new(
                            epoch,
                            crate::multimmit::actors::wire::DataMessage::Block(
                                fixture.signed_block(chain, commitment),
                            ),
                        )
                        .encode()
                    }
                })
            })
            .collect::<Vec<_>>();
        let flood_task = context
            .child("authenticated_flood")
            .spawn(move |context| async move {
                for _ in 0..200 {
                    for message in &flood {
                        let _ = data.send(Recipients::One(target.clone()), message.clone(), false);
                    }
                    context.sleep(Duration::from_millis(10)).await;
                }
            });

        let timeout_before = metric_total(&context.encode(), "_voter_view_timeouts_total");
        cluster.produce();

        let mut serviced = false;
        for _ in 0..400 {
            let inspection = cluster.inspect(TARGET).await.expect("target is live");
            let remote_chains_validated = inspection.chain_progress()[..5]
                .iter()
                .all(|chain| chain.known().get() >= 1);
            let timer_serviced =
                metric_total(&context.encode(), "_voter_view_timeouts_total") > timeout_before;
            if inspection.produced_blocks() >= 1
                && inspection.cursor() > before.cursor()
                && remote_chains_validated
                && timer_serviced
            {
                serviced = true;
                break;
            }
            context.sleep(Duration::from_millis(10)).await;
        }
        assert!(serviced, "flood starved an Engine service class");

        for peer in 0..6 {
            if peer != TARGET {
                cluster.set_directed_success_rate(peer, TARGET, 1.0).await;
            }
        }

        for node in 1..5 {
            cluster.start_one(node).await;
        }
        cluster.await_ready(&[1, 2, 3, 4]).await;
        flood_task.await.expect("bounded flood task completes");

        let all = [0usize, 1, 2, 3, 4, 5];
        let chains = [0u32, 1, 2, 3, 4, 5];
        cluster.wait_finalized(&all, &chains, 1, 2400).await;
        cluster.observe_finality(&all).await;
    });
}

#[test_traced]
fn finality_keeps_pace_with_production() {
    let executor = DeterministicRunner::timed(Duration::from_secs(900));
    executor.start(|context| async move {
        const NODES: usize = 6;
        const WINDOWS: usize = 5;
        const POLLS: usize = 10;

        // Deployment-shaped links: real one-way latency and a per-plane rate limit. Multimmit
        // exits a view as soon as its V-QC forms, so its message rate follows the network rather
        // than a timer, and both of these bound how fast finality can advance.
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                n: NODES as u32,
                seed: 88,
                extras: 0,
                leaders: None,
                quota: Some(Quota::per_second(
                    NonZeroU32::new(1024).expect("quota is non-zero"),
                )),
                latency: Some(Duration::from_millis(25)),
                jitter: Some(Duration::from_millis(25)),
                production: Some(Duration::from_millis(250)),
                view_retention: Some(ViewDelta::new(64)),
            },
        )
        .await;
        cluster.start_all().await;
        cluster.produce_every(1);

        // A node that keeps producing while finality stalls looks alive from the outside: its own
        // chain grows, its logs move, and nothing fails. Every window here therefore measures
        // finality progress, not liveness of the producers.
        let all = (0..NODES).collect::<Vec<_>>();
        let mut previous_finality_floors = [0u64; NODES];
        let mut previous_progress = vec![BTreeMap::new(); NODES];
        for window in 0..WINDOWS {
            for _ in 0..POLLS {
                cluster.refresh();
                context.sleep(Duration::from_millis(100)).await;
            }
            for node in 0..NODES {
                let inspection = cluster
                    .inspect(node)
                    .await
                    .unwrap_or_else(|| panic!("engine {node} is still running in window {window}"));
                let finality_floor = inspection.finality_floor().get();
                let progress = inspection
                    .chain_progress()
                    .iter()
                    .map(|progress| {
                        let chain = progress.chain().get();
                        (
                            chain,
                            (
                                progress.known().get(),
                                progress.certified().get(),
                                progress.finalized().get(),
                            ),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();
                assert_eq!(
                    progress.len(),
                    NODES,
                    "node {node} does not track every chain: {progress:?}"
                );
                if window == 0 {
                    previous_finality_floors[node] = finality_floor;
                    previous_progress[node] = progress;
                    continue;
                }

                assert!(
                    finality_floor > previous_finality_floors[node],
                    "node {node} advanced no finality floor in window {window}: floor={finality_floor} view={} produced={} resolutions={} progress={progress:?}",
                    inspection.view().get(),
                    inspection.produced_blocks(),
                    inspection.resolution_jobs(),
                );
                previous_finality_floors[node] = finality_floor;

                // Sustained operation, not a single round: every producer chain must keep
                // extending, not just the ones whose producer happens to lead often.
                for (chain, (_, _, finalized)) in &progress {
                    let previous_finalized = previous_progress[node][chain].2;
                    assert!(
                        *finalized > previous_finalized,
                        "node {node} finalized nothing from chain {chain} in window {window}: previous={previous_finalized} current={finalized} view={} floor={finality_floor} progress={progress:?}",
                        inspection.view().get(),
                    );
                }
                previous_progress[node] = progress.clone();
                if window + 1 == WINDOWS {
                    assert!(
                        progress
                            .values()
                            .all(|(_, _, finalized)| *finalized >= 2),
                        "node {node} has a chain that stopped extending: {progress:?}"
                    );
                }

                // Production cannot outrun its DA-certified frontier by more than the configured
                // pipeline depth. Measure this separately from finality so stalled finality
                // cannot hide behind continued producer progress.
                let (_, certified, _) = progress[&(node as u32)];
                let produced = inspection.produced_blocks();
                assert!(
                    produced.saturating_sub(certified) <= 2,
                    "node {node} produced {produced} but its chain is only certified to {certified}: view={} floor={finality_floor} progress={progress:?}",
                    inspection.view().get(),
                );
            }
            cluster.observe_finality(&all).await;
        }
    });
}

#[test_traced]
fn seed_swept_jittered_cluster_stays_live() {
    // Vary the runtime schedule as well as link delivery so the sweep covers distinct completion
    // orders rather than distinct committee keys under one schedule.
    for seed in 0..8u64 {
        let executor = DeterministicRunner::new(
            DeterministicConfig::new()
                .with_seed(seed)
                .with_timeout(Some(Duration::from_secs(600))),
        );
        executor.start(|context| async move {
            let mut cluster = Cluster::<MinPk>::new(
                &context,
                ClusterOptions {
                    n: 6,
                    seed: 900,
                    extras: 0,
                    leaders: None,
                    quota: None,
                    latency: Some(Duration::from_millis(200)),
                    jitter: Some(Duration::from_millis(150)),
                    production: Some(Duration::from_millis(100)),
                    view_retention: None,
                },
            )
            .await;
            let fixture = cluster.fixture();
            let bounds = Profile::new(
                fixture.config.clone(),
                Role::Validator(Participant::new(0)),
                Tuning {
                    view_timeout: Duration::from_millis(500),
                    production_interval: Duration::from_millis(100),
                    view_retention: ViewDelta::new(16),
                    ..Tuning::default()
                },
            )
            .expect("cluster profile is valid");
            cluster.start_all().await;
            cluster.produce();
            cluster
                .wait_finalized(&[0, 1, 2, 3, 4, 5], &[0, 1, 2, 3, 4, 5], 2, 2400)
                .await;
            for node in [0, 1, 2, 3, 4, 5] {
                let inspection = cluster.inspect(node).await.expect("engine remains live");
                assert_profile_resource_bounds(&inspection, &bounds);
            }
            cluster.observe_finality(&[0, 1, 2, 3, 4, 5]).await;
        });
    }
}

#[test_traced]
fn minsig_cluster_smoke() {
    let executor = DeterministicRunner::timed(Duration::from_secs(600));
    executor.start(|context| async move {
        let mut cluster = Cluster::<MinSig>::new(&context, options(83, 6)).await;
        cluster.start_all().await;
        cluster.produce();
        cluster
            .wait_finalized(&[0, 1, 2, 3, 4, 5], &[0, 1, 2, 3, 4, 5], 1, 1200)
            .await;
    });
}

#[test_traced]
fn larger_smoke_topology_reaches_finality() {
    let executor = DeterministicRunner::timed(Duration::from_secs(1200));
    executor.start(|context| async move {
        let mut cluster = Cluster::<MinPk>::new(&context, options(84, 16)).await;
        cluster.start_all().await;
        cluster.produce_once();
        let all = (0..16usize).collect::<Vec<_>>();
        let chains = (0..16u32).collect::<Vec<_>>();
        cluster.wait_finalized(&all, &chains, 1, 2400).await;
    });
}

#[test_traced]
fn three_sequential_committees_rotate() {
    let executor = DeterministicRunner::timed(Duration::from_secs(1800));
    executor.start(|context| async move {
        // Rotation is external: each committee is one complete cluster that makes durable
        // progress on its own epoch label and partitions, and is then stopped by the deployment
        // before the next one starts.
        for epoch_index in 0..3u64 {
            let seed = 86 + epoch_index;
            let options = ClusterOptions {
                n: 6,
                seed,
                extras: 0,
                leaders: None,
                quota: None,
                latency: None,
                jitter: None,
                production: None,
                view_retention: None,
            };
            let mut cluster = Cluster::<MinPk>::new(&context, options).await;
            cluster.start_all().await;
            cluster.produce();

            let all = [0usize, 1, 2, 3, 4, 5];
            cluster
                .wait_finalized(&all, &[0, 1, 2, 3, 4, 5], 1, 3600)
                .await;

            for node in all {
                cluster.crash(node).await;
            }
        }
    });
}
