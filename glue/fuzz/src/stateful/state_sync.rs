//! The state-sync driver: a late joiner over the cluster of correct nodes.
//!
//! Three correct identities start at genesis; the fourth starts only after
//! they have finalized a tape-selected number of heights, and requests peer
//! state sync. Its probe collects a finalized floor from the running nodes,
//! its database set syncs from their resolvers through the real p2p sync
//! source, and the stateful actor hands the synced set over to marshal-driven
//! processing. The restart schedule may crash any node, the joiner included,
//! so a sync can be interrupted and resumed from its persisted floor, and a
//! joiner restarted after completing its sync must recover through marshal
//! rather than sync again.
//!
//! The chain, database-state, and verdict invariants apply as in the restart
//! driver: a joiner that hands off wrong state shows up as a database-state
//! disagreement at the first height it applies. I10 holds the joiner to a
//! single sync with a durable, monotone completion. Pruning on the serving
//! nodes is fuzz-controlled, so the joiner may find the operations its
//! targets need already pruned; a sync that then stalls is a healthy timeout,
//! not a failure.

use super::{
    JOINER_CRASH_STEP, NUM_IDENTITIES, RUN_TIMEOUT,
    backend::Any,
    input::{PruneControls, StatefulStateSyncFuzzInput},
    invariants::EngineObservations,
    marshal::Standard,
    runner::{self, CorrectEngine, NodeConfig, Outcome, RunReport},
    stack::round_robin,
};
use commonware_consensus::types::View;
use commonware_glue::stateful::db::SyncEngineConfig;
use commonware_macros::select;
use commonware_runtime::{Clock, Runner as _, deterministic};
use commonware_utils::{FuzzRng, NZUsize};
use futures::future::join_all;

/// Label this driver reports under.
const TARGET: &str = "glue-stateful-state-sync";

/// The engine index of the late joiner.
const JOINER: usize = NUM_IDENTITIES as usize - 1;

/// libFuzzer entry point.
pub fn fuzz_stateful_cert_mock_state_sync(input: StatefulStateSyncFuzzInput) {
    let raw_bytes = input.raw_bytes.clone();
    runner::report(&raw_bytes, || run_stateful_state_sync(input));
}

/// Run one late-joiner schedule and return what it measured.
///
/// A run is fully determined by its input bytes.
pub fn run_stateful_state_sync(input: StatefulStateSyncFuzzInput) -> RunReport {
    let entropy = input.raw_bytes.clone();
    let config = deterministic::Config::new().with_rng(FuzzRng::new(entropy.clone()));
    deterministic::Runner::new(config).start(|context| run(context, input, entropy))
}

async fn run(
    mut context: deterministic::Context,
    input: StatefulStateSyncFuzzInput,
    entropy: Vec<u8>,
) -> RunReport {
    let cluster = runner::setup::<Any, Standard>(&mut context).await;
    let elector = round_robin(input.term_length);
    let prune = input.prune.map(PruneControls::config);
    let sync = SyncEngineConfig {
        fetch_batch_size: input.sync_batch,
        apply_batch_size: input.sync_batch,
        max_outstanding_requests: 4,
        update_channel_size: NZUsize!(16),
        max_retained_roots: 8,
    };
    let serving = NodeConfig {
        elector: elector.clone(),
        prune,
        sync,
        state_sync: false,
    };
    let joining = NodeConfig {
        elector,
        prune,
        sync,
        state_sync: true,
    };

    let observations: Vec<EngineObservations> = (0..NUM_IDENTITIES as usize)
        .map(|_| EngineObservations::new())
        .collect();

    // The serving nodes start at genesis.
    let mut correct = Vec::with_capacity(observations.len());
    for (index, node) in observations.iter().enumerate().take(JOINER) {
        correct.push(
            CorrectEngine::<Any, Standard, _>::start(
                &context,
                &cluster,
                index,
                serving.clone(),
                node.clone(),
            )
            .await,
        );
    }

    // The joiner starts once the serving nodes have applied the heights it
    // must catch up on, then the restart schedule runs over every node, and
    // the run ends when every node, the joiner included, has applied the
    // required heights. The joiner counts only heights it applied itself,
    // above its sync.
    let mut restart_rng = FuzzRng::new(entropy);
    let events = runner::restart_schedule(&mut restart_rng, input.restarts, observations.len());
    let outcome = {
        let run = async {
            let mut ahead = runner::waiters(
                &context,
                &correct[..1],
                usize::from(input.join_after),
                View::zero(),
            );
            ahead.remove(0).await.expect("waiter must not be aborted");
            correct.push(
                CorrectEngine::<Any, Standard, _>::start(
                    &context,
                    &cluster,
                    JOINER,
                    joining,
                    observations[JOINER].clone(),
                )
                .await,
            );
            let waiters = runner::waiters(
                &context,
                &correct,
                usize::from(input.required_heights),
                View::zero(),
            );
            if let Some(steps) = input.joiner_crash {
                context.sleep(JOINER_CRASH_STEP * u32::from(steps)).await;
                correct[JOINER]
                    .restart(&context, &cluster, runner::downtime())
                    .await;
            }
            for (delay, victim) in events {
                context.sleep(delay).await;
                correct[victim]
                    .restart(&context, &cluster, runner::downtime())
                    .await;
            }
            join_all(waiters).await;
        };
        select! {
            _ = context.sleep(RUN_TIMEOUT) => Outcome::Timeout,
            _ = run => Outcome::Suffix,
        }
    };

    runner::measure(
        TARGET,
        outcome,
        &correct,
        &observations,
        &cluster.genesis,
        prune,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::types::TermLength;
    use commonware_utils::{NZU32, NZU64};

    fn tape(seed: u8) -> Vec<u8> {
        (0..96u8)
            .map(|byte| byte.wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn input(
        required_heights: u8,
        join_after: u8,
        sync_batch: u64,
        restarts: u8,
        prune: Option<PruneControls>,
        seed: u8,
    ) -> StatefulStateSyncFuzzInput {
        StatefulStateSyncFuzzInput {
            required_heights,
            term_length: TermLength::new(NZU32!(1)),
            join_after,
            sync_batch: NZU64!(sync_batch),
            joiner_crash: None,
            restarts,
            prune,
            raw_bytes: tape(seed),
        }
    }

    /// Runs one fixed input and asserts the checks were not vacuous: the
    /// joiner synced and then applied heights on its own.
    fn synced(input: StatefulStateSyncFuzzInput) -> RunReport {
        let report = run_stateful_state_sync(input);
        println!("{report}");
        assert!(
            report.measured(),
            "run measured nothing and must not be counted as passing: {report}"
        );
        assert!(
            report.counts.synced_nodes == 1,
            "the joiner did not sync and apply on its own: {report}"
        );
        report
    }

    #[test]
    fn late_joiner_syncs_and_hands_off() {
        synced(input(3, 4, 16, 0, None, 0));
    }

    /// The smallest batches make the joiner chase the serving nodes' tip
    /// while it syncs.
    #[test]
    fn slow_sync_chases_the_tip() {
        synced(input(3, 6, 1, 0, None, 1));
    }

    /// Restarts, the joiner's included, hold the invariants; a joiner
    /// restarted after completing its sync recovers through marshal (I10).
    #[test]
    fn restarts_around_the_sync_hold_invariants() {
        let report = synced(input(4, 3, 2, 3, None, 2));
        assert!(report.counts.restarts > 0, "{report}");
    }

    /// A joiner crashed while its sync is in flight resumes it from the
    /// persisted floor on restart (I10), and still hands off cleanly.
    #[test]
    fn interrupted_sync_resumes() {
        let mut input = input(3, 4, 1, 0, None, 7);
        input.joiner_crash = Some(10);
        let report = synced(input);
        assert_eq!(
            report.counts.sync_starts, 2,
            "the joiner did not resume an interrupted sync: {report}"
        );
    }

    /// A joiner crashed after its sync completed recovers through marshal
    /// rather than syncing again (I10).
    #[test]
    fn restart_after_completion_recovers_through_marshal() {
        let mut input = input(3, 4, 1, 0, None, 7);
        input.joiner_crash = Some(35);
        let report = synced(input);
        assert_eq!(report.counts.sync_starts, 1, "{report}");
        assert_eq!(report.counts.restarts, 1, "{report}");
    }

    /// Serving nodes that prune still let the joiner sync when they retain
    /// enough history.
    #[test]
    fn syncing_from_pruning_nodes_holds_invariants() {
        synced(input(
            3,
            4,
            4,
            1,
            Some(PruneControls {
                maintenance_interval: 2,
                retained_marshal_blocks: 4,
                retained_qmdb_blocks: 4,
            }),
            3,
        ));
    }

    /// I6: a replayed input fails, or passes, identically.
    #[test]
    fn replay_is_reproducible() {
        let first = run_stateful_state_sync(input(3, 3, 2, 2, None, 5));
        let second = run_stateful_state_sync(input(3, 3, 2, 2, None, 5));
        assert_eq!(first, second, "replaying an input changed what it measured");
    }

    /// P5: the byte tape never reaches `Debug` output; its length may.
    #[test]
    fn debug_elides_the_tape() {
        let mut input = input(1, 1, 1, 0, None, 0);
        input.raw_bytes = vec![0xAB; 1024];
        let rendered = format!("{input:?}");
        assert!(rendered.contains("raw_bytes_len: 1024"));
        assert!(!rendered.contains("171"));
    }
}
