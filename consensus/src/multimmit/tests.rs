//! Deterministic multi-node Multimmit integration tests.
//!
//! Every scenario runs complete engines, each with its own marshal, through
//! [`mocks::cluster::Cluster`](super::mocks::cluster::Cluster). Two oracles check every scenario:
//! all nodes resolve each view to one tips-history commitment, and all marshals deliver one
//! ordered stream (contiguous indices, per-chain height order, the same block at every index).
//! Schedules are deterministic per seed; failures replay exactly.

use super::{
    DeclarationRule, Planes, ViewEnd,
    config::Tuning,
    mocks::cluster::{
        CERTIFICATE_CHANNEL, CONSENSUS_CHANNEL, Cluster, ClusterOptions, DATA_CHANNEL, LaunchSpec,
        Plane, RESOLVER_CHANNEL,
    },
    types::{BlockRef, Window},
};
use crate::types::{Participant, View, ViewDelta};
use commonware_cryptography::{bls12381::primitives::variant::MinPk, ed25519, sha256::Digest};
use commonware_macros::{test_group, test_traced};
use commonware_p2p::{
    Recipients,
    simulated::{SplitForwarder, SplitOrigin, SplitRouter, SplitTarget},
};
use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic, iobuf::IoBuf};
use std::{sync::Arc, time::Duration};

mod wan;

/// Generous simulated-time budget for one wait.
const WAIT: Duration = Duration::from_secs(120);

fn runner(seconds: u64) -> deterministic::Runner {
    deterministic::Runner::timed(Duration::from_secs(seconds))
}

/// Builds a cluster and starts every committee engine.
async fn started(context: &deterministic::Context, options: ClusterOptions) -> Cluster<MinPk> {
    let mut cluster = Cluster::new(context, options).await;
    cluster.start_all().await;
    cluster
}

/// Asserts both cluster oracles over `nodes` and that nobody was blamed for equivocation.
async fn assert_agreement(cluster: &Cluster<MinPk>, nodes: &[usize]) -> Vec<BlockRef<Digest>> {
    cluster.assert_resolutions_agree(nodes);
    assert_eq!(
        cluster.blocked_peers().await,
        Vec::new(),
        "no peer equivocated"
    );
    cluster.assert_deliveries_agree(nodes)
}

/// Returns the highest output every listed node delivered.
fn delivered(cluster: &Cluster<MinPk>, nodes: &[usize]) -> u64 {
    nodes
        .iter()
        .map(|&node| {
            cluster
                .deliveries(node)
                .last()
                .map_or(0, |index| index.get())
        })
        .min()
        .unwrap_or(0)
}

#[test_traced]
fn n6_f1_finalizes_and_delivers_one_ordered_stream() {
    runner(300).start(|context| async move {
        let mut cluster = started(&context, ClusterOptions::new(1, 6)).await;
        cluster.produce();
        let all = cluster.all_nodes();
        cluster.wait_finalized_all(20, WAIT).await;
        cluster.wait_delivered(&all, 100, WAIT).await;

        for &node in &all {
            let facts = cluster.facts(node);
            let views = facts.resolved.keys().copied().collect::<Vec<_>>();
            let expected = (1..=views.len() as u64).map(View::new).collect::<Vec<_>>();
            assert_eq!(
                views, expected,
                "node {node} resolves every view from the first"
            );
            assert!(
                !facts.finalized.is_empty(),
                "node {node} finalizes leader blocks"
            );
            assert!(facts.sweeps > 0, "node {node} reports open-view sweeps");
            assert!(facts.verified > 0, "node {node} verifies blocks");
            let first = cluster.deliveries(node).outputs()[0].0;
            assert_eq!(first.get(), 1, "node {node} delivers from the first output");
        }
        let stream = assert_agreement(&cluster, &all).await;
        assert!(stream.len() >= 100);
    });
}

#[test_traced]
fn crashed_validator_recovers_and_resumes_delivery_without_gaps() {
    runner(600).start(|context| async move {
        let mut cluster = started(&context, ClusterOptions::new(2, 6)).await;
        cluster.produce();
        let all = cluster.all_nodes();
        let rest = [0, 1, 2, 3, 4];
        cluster.wait_delivered(&all, 50, WAIT).await;

        // The remaining n - f validators keep finalizing and delivering without node five.
        cluster.crash(5).await;
        let target = delivered(&cluster, &rest) + 100;
        cluster.wait_delivered(&rest, target, WAIT).await;

        // Node five recovers from its journal and checkpoint, catches up, and continues.
        cluster.restart(5).await;
        let target = delivered(&cluster, &rest) + 100;
        cluster.wait_delivered(&all, target, WAIT).await;
        cluster.observe_finality(&all).await;
        assert_agreement(&cluster, &all).await;
    });
}

#[test_traced]
fn stalled_producer_does_not_block_other_chains() {
    runner(600).start(|context| async move {
        let mut cluster = started(&context, ClusterOptions::new(3, 6)).await;
        // Producer five never builds; every other chain keeps finalizing and delivering.
        cluster.produce_except(&[5]);
        let all = cluster.all_nodes();
        let start = cluster.inspect(0).await.expect("engine is live").view();
        cluster
            .wait_finalized(&all, &[0, 1, 2, 3, 4], 10, WAIT)
            .await;
        cluster
            .wait_view(&all, View::new(start.get() + 12), WAIT)
            .await;
        cluster.wait_delivered(&all, 50, WAIT).await;

        for &node in &all {
            let inspection = cluster.inspect(node).await.expect("engine is live");
            let stalled = inspection.chain_progress()[5];
            assert_eq!(stalled.accepted().get(), 0);
            assert_eq!(stalled.finalized().get(), 0);
        }
        assert_eq!(cluster.app(5).log().lock().built, 0);
        let stream = assert_agreement(&cluster, &all).await;
        assert!(stream.iter().all(|block| block.chain().get() != 5));
    });
}

#[test_traced]
fn view_timers_follow_the_measured_link_delay_and_production_rate() {
    runner(300).start(|context| async move {
        // Links of 30 ms, well below the 100 ms delay seed.
        let latency = Duration::from_millis(30);
        let options = ClusterOptions {
            latency,
            ..ClusterOptions::new(15, 6)
        };
        let mut cluster = started(&context, options).await;
        let start = context.current();
        cluster.produce();
        let all = cluster.all_nodes();
        cluster.wait_finalized_all(20, WAIT).await;
        let view = cluster.inspect(0).await.expect("engine is live").view();
        cluster
            .wait_view(&all, View::new(view.get() + 2), WAIT)
            .await;
        let elapsed = context.current().duration_since(start).unwrap();

        for &node in &all {
            let inspection = cluster.inspect(node).await.expect("engine is live");
            // An endorsement round trip is two link delays, the processing on either end, and up
            // to one vote interval, which the estimate removes before halving.
            let delay = inspection.delay_millis();
            assert!(
                (20..=60).contains(&delay),
                "node {node} estimates a {delay} ms delay over {latency:?} links"
            );
            // The estimate is a typical gap between heights, which pauses between views only
            // lengthen on average (up to rounding).
            let heights = inspection
                .chain_progress()
                .iter()
                .map(|chain| chain.accepted().get())
                .min()
                .expect("the committee has chains");
            let average = elapsed.as_millis() as u64 / heights;
            let production = inspection.production_millis();
            assert!(
                production > 0 && production <= average + average / 10,
                "node {node} estimates {production} ms per block, {average} ms on average"
            );
        }
        assert_agreement(&cluster, &all).await;
    });
}

#[test_traced]
fn views_led_by_a_crashed_leader_resolve_without_it() {
    runner(600).start(|context| async move {
        let mut cluster = started(&context, ClusterOptions::new(4, 6)).await;
        cluster.produce();
        let all = cluster.all_nodes();
        cluster.wait_delivered(&all, 30, WAIT).await;

        let crashed = 2;
        cluster.crash(crashed).await;
        let rest = [0, 1, 3, 4, 5];
        let crashed_at = cluster.inspect(0).await.expect("engine is live").view();
        // Several leader rotations pass; the crashed leader's views end leaderless.
        cluster
            .wait_view(&rest, View::new(crashed_at.get() + 18), WAIT)
            .await;
        let target = delivered(&cluster, &rest) + 50;
        cluster.wait_delivered(&rest, target, WAIT).await;

        let fixture = cluster.fixture();
        let leader = Participant::new(crashed as u32);
        for &node in &rest {
            let facts = cluster.facts(node);
            let skipped = facts
                .resolved
                .keys()
                .filter(|view| {
                    **view > crashed_at.next() && fixture.config.leader(**view) == leader
                })
                .count();
            assert!(
                skipped >= 2,
                "node {node} resolved the crashed leader's views"
            );
            assert!(
                facts
                    .finalized
                    .iter()
                    .filter(|view| **view > crashed_at.next())
                    .all(|view| fixture.config.leader(*view) != leader),
                "node {node} finalized a block of the crashed leader"
            );
        }
        assert_agreement(&cluster, &rest).await;
    });
}

#[test_group("slow")]
#[test_traced]
fn n11_f2_keeps_majority_chains_live_under_partition_and_heals() {
    runner(900).start(|context| async move {
        let mut cluster = started(&context, ClusterOptions::new(5, 11)).await;
        cluster.produce_every(2);
        let all = cluster.all_nodes();
        cluster.wait_delivered(&all, 50, WAIT).await;

        // A two-node minority is cut off; the nine-node majority is exactly n - f and keeps
        // finalizing its own chains.
        let majority = (0..9).collect::<Vec<_>>();
        let minority = [9, 10];
        cluster.partition(&majority, &minority).await;
        let target = delivered(&cluster, &majority) + 100;
        cluster.wait_delivered(&majority, target, WAIT).await;

        // After healing, the minority catches up and every node delivers one stream.
        cluster.heal().await;
        let target = delivered(&cluster, &majority) + 50;
        cluster.wait_delivered(&all, target, WAIT).await;
        assert_agreement(&cluster, &all).await;
    });
}

#[test_traced]
fn a_validator_missing_bodies_adopts_and_fetches_them() {
    runner(600).start(|context| async move {
        let mut cluster = started(&context, ClusterOptions::new(6, 6)).await;
        cluster.produce();
        let all = cluster.all_nodes();
        cluster.wait_delivered(&all, 30, WAIT).await;

        // Node five stops receiving block bodies by broadcast. It still sees every header and
        // vote, so it adopts headers from alpha endorsers and its marshal fetches the bodies.
        let starved = 5;
        for peer in 0..starved {
            cluster.block(Plane::Bodies, peer, starved);
        }
        let target = delivered(&cluster, &all) + 100;
        cluster.wait_delivered(&all, target, WAIT).await;
        assert!(
            cluster.facts(starved).adopted > 0,
            "node five adopts headers"
        );

        for peer in 0..starved {
            cluster.unblock(Plane::Bodies, peer, starved);
        }
        let target = delivered(&cluster, &all) + 50;
        cluster.wait_delivered(&all, target, WAIT).await;
        assert_agreement(&cluster, &all).await;
    });
}

#[test_traced]
fn every_validator_recovers_from_a_simultaneous_crash() {
    runner(600).start(|context| async move {
        let mut cluster = started(&context, ClusterOptions::new(7, 6)).await;
        cluster.produce();
        let all = cluster.all_nodes();
        cluster.wait_delivered(&all, 50, WAIT).await;

        for &node in &all {
            cluster.crash(node).await;
        }
        for &node in &all {
            cluster.restart(node).await;
        }
        let target = delivered(&cluster, &all) + 100;
        cluster.wait_delivered(&all, target, WAIT).await;
        assert_agreement(&cluster, &all).await;
    });
}

#[test_traced]
fn a_restarted_validator_rejoins_after_missing_views() {
    runner(900).start(|context| async move {
        let mut cluster = started(&context, ClusterOptions::new(8, 6)).await;
        cluster.produce();
        let all = cluster.all_nodes();
        cluster.wait_delivered(&all, 50, WAIT).await;

        // Node five misses eight views. On restart it fetches the certificates of the views it
        // missed while its peers' vote updates of those views wait on earlier ones it never saw.
        let rest = [0, 1, 2, 3, 4];
        cluster.crash(5).await;
        let start = cluster.inspect(0).await.expect("engine is live").view();
        cluster
            .wait_view(&rest, View::new(start.get() + 8), WAIT)
            .await;
        cluster.restart(5).await;
        let ahead = cluster.inspect(0).await.expect("engine is live").view();
        cluster
            .wait_view(&all, View::new(ahead.get() + 8), WAIT)
            .await;
        let target = delivered(&cluster, &rest) + 50;
        cluster.wait_delivered(&all, target, WAIT).await;
        assert_agreement(&cluster, &all).await;
    });
}

#[test_traced]
fn a_validator_behind_its_peers_retention_rejoins_by_anchoring() {
    runner(900).start(|context| async move {
        let window = 4;
        let mut cluster = started(
            &context,
            ClusterOptions {
                view_retention: ViewDelta::new(window),
                ..ClusterOptions::new(10, 6)
            },
        )
        .await;
        cluster.produce();
        let all = cluster.all_nodes();
        cluster.wait_delivered(&all, 50, WAIT).await;

        // Node five stays down while its peers finalize and retire many retention windows of
        // views, so none of them can serve the views it missed. On restart it anchors on a peer's
        // floor, and its marshal backfills the history the floor's finalization skips.
        let late = 5;
        let rest = [0, 1, 2, 3, 4];
        cluster.crash(late).await;
        let stopped = cluster.inspect(0).await.expect("engine is live").view();
        cluster
            .wait_view(&rest, View::new(stopped.get() + 8 * window), WAIT)
            .await;
        let retired = cluster
            .inspect(0)
            .await
            .expect("engine is live")
            .retired_view();
        assert!(
            retired > stopped,
            "the peers retired every view node five held"
        );
        cluster.restart(late).await;
        let ahead = cluster.inspect(0).await.expect("engine is live").view();
        cluster
            .wait_view(&all, View::new(ahead.get() + 8), WAIT)
            .await;
        let anchored = cluster.inspect(late).await.expect("engine is live");
        assert!(
            anchored.retired_view() > stopped,
            "node five anchored above the views it missed"
        );
        let facts = cluster.facts(late);
        assert!(
            (stopped.get()..anchored.retired_view().get())
                .any(|view| !facts.resolved.contains_key(&View::new(view))),
            "node five skipped the views below its anchor"
        );
        let target = delivered(&cluster, &rest) + 50;
        cluster.wait_delivered(&all, target, WAIT).await;
        assert_agreement(&cluster, &all).await;
    });
}

#[test_group("slow")]
#[test_traced]
fn retained_state_plateaus_over_a_long_run() {
    runner(1800).start(|context| async move {
        let window = 8;
        let mut cluster = started(
            &context,
            ClusterOptions {
                view_retention: ViewDelta::new(window),
                ..ClusterOptions::new(9, 6)
            },
        )
        .await;
        cluster.produce();
        let all = cluster.all_nodes();

        // Sample retained state after a warm-up and again many retention windows later.
        let mut samples = Vec::new();
        for round in 0..2u64 {
            let start = cluster.inspect(0).await.expect("engine is live").view();
            let span = if round == 0 { 4 * window } else { 16 * window };
            cluster
                .wait_view(&all, View::new(start.get() + span), WAIT * 4)
                .await;
            let mut sample = Vec::new();
            for &node in &all {
                let inspection = cluster.inspect(node).await.expect("engine is live");
                assert!(
                    inspection.view().get() - inspection.retired_view().get() <= 4 * window,
                    "node {node} retires views behind the finalized one"
                );
                sample.push((
                    inspection.cached_artifacts(),
                    inspection.local_artifacts(),
                    cluster.journal_sections(node).await.len(),
                ));
            }
            samples.push(sample);
        }
        for (node, (warm, late)) in samples[0].iter().zip(&samples[1]).enumerate() {
            assert!(
                late.0 <= 2 * warm.0.max(16)
                    && late.1 <= 2 * warm.1.max(16)
                    && late.2 <= 2 * warm.2.max(4),
                "node {node} retained state grew from {warm:?} to {late:?}"
            );
        }
        assert_agreement(&cluster, &all).await;
    });
}

/// Producers that build many blocks per view keep every chain's accepted headers of the whole
/// retention window durable. The artifact cache must hold that plateau, or the engines park
/// before finality lets retention advance.
#[test_traced]
fn fast_producers_with_a_wide_window_stay_live_through_retention() {
    runner(600).start(|context| async move {
        let options = ClusterOptions {
            view_retention: ViewDelta::new(8),
            window: Window::new(32).expect("window is valid"),
            ..ClusterOptions::new(10, 6)
        };
        let retention = options.view_retention.get();
        let mut cluster = started(&context, options).await;
        cluster.produce();
        let all = cluster.all_nodes();
        cluster
            .wait_view(&all, View::new(retention + 8), WAIT)
            .await;
        for &node in &all {
            let inspection = cluster.inspect(node).await.expect("engine is live");
            assert!(
                inspection.retired_view().get() > 0,
                "node {node} retires views once finality passes the retention window"
            );
        }
        assert_agreement(&cluster, &all).await;
    });
}

/// Returns the routes of one equivocating participant's two halves: half `h` sends only to, and
/// receives only from, the correct engines in `sides[h]`.
fn twin_routes(
    sides: Arc<[Vec<ed25519::PublicKey>; 2]>,
) -> (
    impl SplitForwarder<ed25519::PublicKey>,
    impl SplitRouter<ed25519::PublicKey>,
) {
    let forward = Arc::clone(&sides);
    let forwarder =
        move |origin: SplitOrigin, recipients: &Recipients<ed25519::PublicKey>, _: &IoBuf| {
            let side = match origin {
                SplitOrigin::Primary => &forward[0],
                SplitOrigin::Secondary => &forward[1],
            };
            let reached = match recipients {
                Recipients::All => side.clone(),
                Recipients::One(peer) => vec![peer.clone()],
                Recipients::Some(peers) => peers.clone(),
            }
            .into_iter()
            .filter(|peer| side.contains(peer))
            .collect::<Vec<_>>();
            (!reached.is_empty()).then_some(Recipients::Some(reached))
        };
    let router = move |(sender, _): &(ed25519::PublicKey, IoBuf)| {
        if sides[0].contains(sender) {
            SplitTarget::Primary
        } else if sides[1].contains(sender) {
            SplitTarget::Secondary
        } else {
            SplitTarget::Both
        }
    };
    (forwarder, router)
}

#[test_traced]
fn an_equivocating_producer_split_between_the_engines_leaves_one_ordered_stream() {
    runner(600).start(|context| async move {
        let mut cluster = Cluster::<MinPk>::new(&context, ClusterOptions::new(12, 6)).await;
        let correct = [1, 2, 3, 4, 5];
        for node in correct {
            cluster.start_one(node).await;
        }
        cluster.await_ready(&correct).await;

        // Participant zero runs as two halves that share its identity and build different blocks
        // at every height: one half reaches engines one to three, the other four and five.
        let identities = cluster.identities();
        let sides = Arc::new([identities[1..4].to_vec(), identities[4..6].to_vec()]);
        let mut halves = [Vec::new(), Vec::new()];
        for channel in [
            DATA_CHANNEL,
            CONSENSUS_CHANNEL,
            CERTIFICATE_CHANNEL,
            RESOLVER_CHANNEL,
        ] {
            let (sender, receiver) = cluster.tap(0, channel).await;
            let (forwarder, router) = twin_routes(Arc::clone(&sides));
            let (primary, secondary) = sender.split_with(forwarder);
            let (inbound, outbound) = receiver.split_with(
                context.child("twin").with_attribute("channel", channel),
                router,
            );
            halves[0].push((primary, inbound));
            halves[1].push((secondary, outbound));
        }
        for (salt, planes) in ["left", "right"].into_iter().zip(halves) {
            let [data, consensus, certificates, resolver] =
                <[_; 4]>::try_from(planes).expect("four planes");
            let slot = cluster.reserve_slot(salt);
            cluster
                .launch_over(
                    LaunchSpec::new(slot),
                    0,
                    Planes {
                        data,
                        consensus,
                        certificates,
                        resolver,
                    },
                )
                .await;
        }

        // The correct engines resolve views alike, deliver one ordered stream, and block only the
        // equivocating participant. The halves run no marshal, so their blocks' bodies never
        // reach the correct engines: chain zero stays at genesis there, and the split of a chain
        // across its branches is exercised by the machine-level twins campaigns instead.
        cluster.produce();
        cluster.wait_delivered(&correct, 100, WAIT).await;
        cluster.assert_resolutions_agree(&correct);
        cluster.assert_deliveries_agree(&correct);
        let blocked = cluster.blocked_peers().await;
        assert!(!blocked.is_empty(), "the equivocation is detected");
        assert!(blocked.iter().all(|(_, peer)| *peer == identities[0]));
    });
}

/// Records the deepest span scope opened under it.
#[derive(Clone, Default)]
struct DeepestScope(Arc<std::sync::atomic::AtomicUsize>);

impl<S> tracing_subscriber::Layer<S> for DeepestScope
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        _: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let depth = context.span(id).map_or(0, |span| span.scope().count());
        self.0
            .fetch_max(depth, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Every local build, custody check, signature, and journal barrier is issued from the
/// completion of earlier local work. Their spans must not nest under that completion: a producer
/// never stops building, so the chain of spans would grow with every block, and closing it
/// recurses once per link until the stack overflows.
#[test]
fn local_work_spans_stay_shallow_however_many_blocks_producers_build() {
    let deepest = DeepestScope::default();
    let subscriber = tracing_subscriber::layer::SubscriberExt::with(
        tracing_subscriber::registry(),
        deepest.clone(),
    );
    tracing::subscriber::with_default(subscriber, || {
        runner(300).start(|context| async move {
            let options = ClusterOptions {
                window: Window::new(32).expect("window is valid"),
                ..ClusterOptions::new(83, 6)
            };
            let mut cluster = started(&context, options).await;
            cluster.produce();
            let all = cluster.all_nodes();
            cluster.wait_view(&all, View::new(12), WAIT).await;
        });
    });
    // The deepest fixed request chains (marshal's router through a catalog read) are ten spans.
    let depth = deepest.0.load(std::sync::atomic::Ordering::Relaxed);
    assert!(depth <= 16, "a span scope reached depth {depth}");
}

/// Returns the window cap of `cluster`'s committee.
fn cap(cluster: &Cluster<MinPk>) -> u64 {
    u64::from(cluster.fixture().config.window().cap())
}

/// Producers that build every `theta` fill each chain's window, so healthy views end on count:
/// every chain advances by the cap per view, and no chain is declared stopped.
#[test_traced]
fn healthy_views_end_on_count_with_every_chain_advancing_a_window_per_view() {
    runner(600).start(|context| async move {
        let options = ClusterOptions::new(84, 6);
        let mut cluster = started(&context, options).await;
        let cap = cap(&cluster);
        cluster.produce();
        let all = cluster.all_nodes();
        let reached = cluster
            .wait_until(&all, WAIT, Duration::from_millis(20), |inspection| {
                inspection.last_resolved() >= View::new(30)
            })
            .await;
        assert!(reached, "the cluster resolved thirty views");

        for &node in &all {
            let inspection = cluster.inspect(node).await.expect("engine is live");
            let ends = inspection.view_ends();
            assert!(
                ends.get(ViewEnd::Count) * 10 >= ends.total() * 8,
                "node {node} ended too few views on count: {ends:?} {:?}",
                inspection.declarations()
            );
            assert_eq!(ends.get(ViewEnd::Bound), 0, "node {node}: {ends:?}");
            assert_eq!(
                inspection.declarations().get(DeclarationRule::Stopped),
                0,
                "node {node} declared a healthy chain stopped"
            );
            // A view ending on count raises every chain's base by the cap.
            let resolved = inspection.last_resolved().get();
            for chain in inspection.chain_progress() {
                assert!(
                    chain.finalized().get() >= cap * (resolved - 3),
                    "node {node} finalized {} of {:?} after {resolved} views",
                    chain.finalized(),
                    chain.chain()
                );
            }
        }
        assert_agreement(&cluster, &all).await;
    });
}

/// A producer whose blocks take longer than `theta` does not fill its window in a view, so rule
/// (ii) declares it `t_late` after the other chains cap, while every other chain still advances a
/// window per view.
#[test_traced]
fn a_slow_producer_is_declared_without_stalling_the_others() {
    runner(600).start(|context| async move {
        let mut cluster = started(&context, ClusterOptions::new(85, 6)).await;
        let cap = cap(&cluster);
        cluster.produce();
        cluster.app(5).delay_builds(Duration::from_millis(20));
        let all = cluster.all_nodes();
        cluster.wait_view(&all, View::new(30), WAIT).await;

        for &node in &all {
            let inspection = cluster.inspect(node).await.expect("engine is live");
            let declarations = inspection.declarations();
            assert!(
                declarations.get(DeclarationRule::Late) > 0,
                "node {node} never declared the slow chain late: {declarations:?}"
            );
            let resolved = inspection.last_resolved().get();
            let chains = inspection.chain_progress();
            for chain in &chains[..5] {
                assert!(
                    chain.finalized().get() >= cap * (resolved - 3),
                    "node {node}: chain {:?} finalized {} after {resolved} views",
                    chain.chain(),
                    chain.finalized()
                );
            }
            assert!(
                chains[5].finalized().get() > 0,
                "the slow chain still finalizes"
            );
        }
        assert_agreement(&cluster, &all).await;
    });
}

/// Over 50 ms links a view lasts at most about `N theta_hat + 2 delta_hat + eta` (the window's
/// blocks, a round trip for the final votes, and a vote interval) and at least the round trip.
/// Producers build the next window while the current one finalizes, so a view usually takes less
/// than the bound's `N theta_hat`.
#[test_traced]
fn views_last_about_the_window_of_blocks_plus_a_round_trip_over_slow_links() {
    runner(600).start(|context| async move {
        let options = ClusterOptions {
            latency: Duration::from_millis(50),
            ..ClusterOptions::new(86, 6)
        };
        let mut cluster = started(&context, options).await;
        let cap = cap(&cluster);
        for node in cluster.all_nodes() {
            cluster.app(node).delay_builds(Duration::from_millis(10));
        }
        cluster.produce();
        let all = cluster.all_nodes();
        cluster.wait_view(&all, View::new(25), WAIT).await;

        let vote = u64::try_from(Tuning::new().vote_interval.as_millis()).unwrap();
        for &node in &all {
            let inspection = cluster.inspect(node).await.expect("engine is live");
            let ends = inspection.view_ends();
            let mean = ends.total_millis() / ends.total();
            let expected =
                cap * inspection.production_millis() + 2 * inspection.delay_millis() + vote;
            let round_trip = 2 * 50;
            assert!(
                (round_trip..=expected).contains(&mean),
                "node {node}: views last {mean} ms, expected about {expected} ms ({ends:?}, \
                 theta {} ms, delta {} ms)",
                inspection.production_millis(),
                inspection.delay_millis()
            );
        }
        assert_agreement(&cluster, &all).await;
    });
}
