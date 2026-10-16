//! The whole-engine profile: a committee of complete engines delivers a fixed amount of work.
//!
//! Every node runs the cluster harness's engine and marshal wiring: the consensus actors over the
//! production machine, a marshal fed by their activity, and an application that stages its blocks
//! through that marshal; every delivered output is acknowledged at once. The simulated network
//! and storage run on the deterministic runtime, so a run's protocol schedule replays exactly; the
//! benchmark target times its regions on the host.

use crate::{
    Reporter,
    multimmit::{
        config::Tuning,
        engine::{Config as EngineConfig, Engine, Planes, Running},
        marshal::{OutputIndex, Update},
        mocks::{
            Committee, MockApplication,
            cluster::{
                BACKFILL_CHANNEL, BODIES_CHANNEL, CERTIFICATE_CHANNEL, CONSENSUS_CHANNEL,
                DATA_CHANNEL, QUOTA, RESOLVER_CHANNEL, link_all_with, start_network,
            },
            marshaled::{ClusterApplication, ClusterBlock, Marshaled},
        },
        types::BlockRef,
    },
    types::Participant,
};
use commonware_actor::Feedback;
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, ed25519, sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated::Oracle;
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Runner as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic::{self, Config as RuntimeConfig, Runner as DeterministicRunner},
};
use commonware_utils::{Acknowledgement as _, NZUsize, sync::Mutex};
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

/// Engines in the profile's committee, each producing one chain.
pub const ENGINE_NODES: usize = 6;
/// Blocks of every producer chain each node must deliver during the block region.
pub const ENGINE_BLOCKS_PER_CHAIN: u64 = 4;
/// Views every engine advances during the view region.
pub const ENGINE_VIEW_ADVANCE: u64 = 12;

const NETWORK_LATENCY: Duration = Duration::from_millis(15);
const NETWORK_JITTER: Duration = Duration::from_millis(5);
const TIMER_CEILING: Duration = Duration::from_secs(5);
const RUNTIME_SEED: u64 = 0x5eed_cafe;
const COMMITTEE_SEED: u64 = 0xface_feed;
const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
const MAX_MESSAGE_BYTES: u32 = 4 * 1024 * 1024;
const PROGRESS_POLL: Duration = Duration::from_millis(10);
/// Deterministic time a region may take before the run is declared stalled.
const REGION_DEADLINE: Duration = Duration::from_secs(60);

/// Deterministic outcomes of one profile run.
#[derive(Clone, Copy, Debug)]
pub struct EngineReport {
    /// Outputs the slowest node delivered across the whole run.
    pub delivered: u64,
    /// Views the slowest engine advanced during the view region.
    pub views: u64,
    /// Deterministic time the view region took.
    pub view_time: Duration,
}

/// One profile run: its deterministic report and the host time of its measured regions.
#[derive(Clone, Copy, Debug)]
pub struct EngineRun {
    /// The run's deterministic outcomes.
    pub report: EngineReport,
    /// Host time until every node delivered the fixed blocks.
    pub block_elapsed: Duration,
    /// Host time spent advancing the fixed views.
    pub view_elapsed: Duration,
}

/// Returns the profile's parameters as a `key=value` benchmark label suffix.
pub fn engine_parameters() -> String {
    format!(
        "n={ENGINE_NODES} bpc={ENGINE_BLOCKS_PER_CHAIN} views={ENGINE_VIEW_ADVANCE} latency_ms={}",
        NETWORK_LATENCY.as_millis()
    )
}

/// Runs the profile once.
///
/// # Panics
///
/// Panics if a region misses its deadline or any node's delivered stream breaks the output
/// contract: indices consecutive from one, each block extending the previous block of its chain,
/// and every node delivering the same stream.
pub fn run_engine_profile() -> EngineRun {
    let runtime = DeterministicRunner::new(
        RuntimeConfig::default()
            .with_seed(RUNTIME_SEED)
            .with_timeout(Some(REGION_DEADLINE * 4)),
    );
    runtime.start(|context| async move {
        let profile = Box::pin(Profile::start(&context)).await;

        let started = Instant::now();
        profile
            .wait("blocks", |progress| {
                progress.lowest_chain >= ENGINE_BLOCKS_PER_CHAIN
            })
            .await;
        let block_elapsed = started.elapsed();

        let initial = profile.progress().await;
        let target = initial.iter().map(|node| node.view).max().unwrap() + ENGINE_VIEW_ADVANCE;
        let started = Instant::now();
        let simulated = context.current();
        profile
            .wait("views", |progress| progress.view >= target)
            .await;
        let view_elapsed = started.elapsed();
        let view_time = context.current().duration_since(simulated).unwrap();
        let last = profile.progress().await;

        let delivered = profile.check_delivery();
        let views = initial
            .iter()
            .zip(&last)
            .map(|(initial, last)| last.view - initial.view)
            .min()
            .unwrap();
        profile.stop().await;
        EngineRun {
            report: EngineReport {
                delivered,
                views,
                view_time,
            },
            block_elapsed,
            view_elapsed,
        }
    })
}

/// One running node: its engine and marshal.
struct Node {
    engine: Running<Sha256Digest>,
    marshal: Marshaled<MinPk>,
    delivered: Arc<Mutex<Vec<Delivered>>>,
}

/// One output a node's marshal delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Delivered {
    index: OutputIndex,
    block: BlockRef<Sha256Digest>,
    parent: Sha256Digest,
}

/// One node's progress, as of one poll.
#[derive(Clone, Copy, Debug)]
struct Progress {
    view: u64,
    /// The lowest height any producer chain has delivered.
    lowest_chain: u64,
}

/// The running committee.
struct Profile {
    context: deterministic::Context,
    nodes: Vec<Node>,
}

impl Profile {
    /// Starts every node over a fully linked network and waits until each engine is ready.
    async fn start(context: &deterministic::Context) -> Self {
        let committee = Committee::<MinPk>::builder(COMMITTEE_SEED, ENGINE_NODES as u32).build();
        let oracle = start_network(context, committee.identities.clone(), MAX_MESSAGE_BYTES).await;
        link_all_with(
            &oracle,
            &committee.identities,
            NETWORK_LATENCY,
            NETWORK_JITTER,
        )
        .await;
        let mut nodes = Vec::with_capacity(ENGINE_NODES);
        for index in 0..ENGINE_NODES {
            nodes.push(Box::pin(start_node(context, &oracle, &committee, index)).await);
        }
        for node in &mut nodes {
            node.engine.ready().await.expect("engine becomes ready");
        }
        Self {
            context: context.child("profile"),
            nodes,
        }
    }

    async fn progress(&self) -> Vec<Progress> {
        let mut progress = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let inspection = node
                .engine
                .inspector()
                .inspect()
                .await
                .expect("engine remains live");
            let mut heights = [0; ENGINE_NODES];
            for delivered in node.delivered.lock().iter() {
                let chain = &mut heights[delivered.block.chain().get() as usize];
                *chain = (*chain).max(delivered.block.height().get());
            }
            progress.push(Progress {
                view: inspection.view().get(),
                lowest_chain: heights.into_iter().min().unwrap(),
            });
        }
        progress
    }

    /// Polls until every node satisfies `done`.
    ///
    /// # Panics
    ///
    /// Panics with every node's progress if the region misses its deadline.
    async fn wait(&self, region: &str, done: impl Fn(&Progress) -> bool) {
        let started = self.context.current();
        loop {
            let progress = self.progress().await;
            if progress.iter().all(&done) {
                return;
            }
            let waited = self
                .context
                .current()
                .duration_since(started)
                .unwrap_or_default();
            assert!(
                waited < REGION_DEADLINE,
                "{region} region stalled after {waited:?}: {progress:?}"
            );
            self.context.sleep(PROGRESS_POLL).await;
        }
    }

    /// Checks every node's delivered stream and returns the shortest stream's length.
    fn check_delivery(&self) -> u64 {
        let streams = self
            .nodes
            .iter()
            .map(|node| node.delivered.lock().clone())
            .collect::<Vec<_>>();
        for (node, stream) in streams.iter().enumerate() {
            let mut tips = vec![None; ENGINE_NODES];
            for (position, delivered) in stream.iter().enumerate() {
                assert_eq!(
                    delivered.index.get(),
                    position as u64 + 1,
                    "node {node} delivered out of order"
                );
                let tip: &mut Option<BlockRef<Sha256Digest>> =
                    &mut tips[delivered.block.chain().get() as usize];
                let expected_height = tip.map_or(1, |tip| tip.height().get() + 1);
                assert_eq!(
                    delivered.block.height().get(),
                    expected_height,
                    "node {node} skipped a height on chain {}",
                    delivered.block.chain()
                );
                if let Some(tip) = tip {
                    assert_eq!(
                        delivered.parent,
                        tip.digest(),
                        "node {node} delivered a block off its chain's delivered branch"
                    );
                }
                *tip = Some(delivered.block);
            }
        }
        let shortest = streams.iter().map(Vec::len).min().unwrap();
        for (node, stream) in streams.iter().enumerate() {
            assert_eq!(
                stream[..shortest],
                streams[0][..shortest],
                "node {node} delivered a different stream"
            );
        }
        shortest as u64
    }

    async fn stop(self) {
        for mut node in self.nodes {
            node.engine.abort();
            let _ = node.engine.join().await;
            node.marshal.abort();
            let _ = node.marshal.join().await;
        }
    }
}

/// Starts node `index`: its marshal first, then the engine that reports to it.
async fn start_node(
    context: &deterministic::Context,
    oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
    committee: &Committee<MinPk>,
    index: usize,
) -> Node {
    let context = context.child("node").with_attribute("index", index);
    let identity = committee.identities[index].clone();
    let control = oracle.control(identity.clone());
    let register = async |channel| control.register(channel, QUOTA).await.unwrap();

    let chain = committee
        .config
        .producer_chain(Participant::new(index as u32));
    let delivered = Arc::<Mutex<Vec<Delivered>>>::default();
    let marshal = Marshaled::start(
        context.child("delivery"),
        committee,
        oracle,
        identity,
        chain,
        format!("bench_marshal_{index}"),
        register(BODIES_CHANNEL).await,
        register(BACKFILL_CHANNEL).await,
        Acknowledging(Arc::clone(&delivered)),
    )
    .await;

    let config: EngineConfig<Sha256, _, _, _, _, _, _, _, _> = EngineConfig {
        scheme: committee.signers[index].clone(),
        genesis: committee.genesis().clone(),
        tuning: Tuning {
            timer_ceiling: TIMER_CEILING,
            ..Tuning::new()
        },
        automaton: ClusterApplication::marshaled(
            MockApplication::new(),
            context.child("application"),
            marshal.mailbox.clone(),
        ),
        relay: marshal.relay.clone(),
        reporter: marshal.mailbox.clone(),
        strategy: Sequential,
        critical_strategy: Sequential,
        blocker: control.clone(),
        partition_prefix: format!("bench_engine_{index}"),
        page_cache: CacheRef::from_pooler(&context, paged::page_size(4_096), NZUsize!(64)),
        mailbox_size: MAILBOX_SIZE,
    };
    let engine = Engine::open(context.child("engine"), config)
        .await
        .expect("engine opens");
    let planes = Planes {
        data: register(DATA_CHANNEL).await,
        consensus: register(CONSENSUS_CHANNEL).await,
        certificates: register(CERTIFICATE_CHANNEL).await,
        resolver: register(RESOLVER_CHANNEL).await,
    };
    Node {
        engine: engine.start(planes),
        marshal,
        delivered,
    }
}

/// Records every delivered output and acknowledges it at once.
#[derive(Clone)]
struct Acknowledging(Arc<Mutex<Vec<Delivered>>>);

impl Reporter for Acknowledging {
    type Activity = Update<ClusterBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update {
            index,
            block,
            acknowledgement,
        } = activity;
        self.0.lock().push(Delivered {
            index,
            block: block.reference(),
            parent: block.header().context().parent(),
        });
        acknowledgement.acknowledge();
        Feedback::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engines_advance_views_and_deliver_every_chain_in_order() {
        let run = run_engine_profile();
        eprintln!("{run:?}");
        assert!(run.report.delivered >= ENGINE_BLOCKS_PER_CHAIN * ENGINE_NODES as u64);
        assert!(run.report.views >= ENGINE_VIEW_ADVANCE);
    }
}
