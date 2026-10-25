//! TS-9007 on marshal_scenario_standard_deferred_cert_mock
//! Shape: B
//! Knobs: raw_bytes[0..0]: none
//! Stages: E1 construction report_finalization; E2 exact delivered (polled); E3 construction
//!     report_finalization; E4 exact delivered (polled); E5 construction report_finalization;
//!     E6 exact delivered, tip, fetch_count, subscriptions, targeted
//! Control: withholds E5
//! Injections: the three reported quorum finalizations at or below the floor, as the
//!     scenario reports them (no campaign ghost state exists in this crate)
//! Missing: none

// Source: `test_standard_get_block_by_height_and_latest`
// (consensus/src/marshal/standard/mod.rs, body in
// consensus/src/marshal/mocks/harness.rs), as
// `scenarios::StandardGetBlockByHeightAndLatest@392b116687` drives it. Each harness
// event's durable `verified` reply is raced and recorded before the finalization report,
// which is the stage's action. The source's trailing `get_block` queries run after the
// mark as oracles, when the prefix was reached.

use super::{Prefix, Twist, attack_above, poll, race, round};
use crate::record::Recorder;
use commonware_consensus::{Heightable as _, marshal::Identifier, simplex::Floor, types::Height};
use commonware_consensus_fuzz_core::simplex::Simplex;
use commonware_consensus_fuzz_marshal::{
    marshal::end_to_end::twins::stack::TwinsMarshal,
    scenarios::{
        environment::{Expectation, Mb, Node, NodeExpectation, QUORUM_SIGNERS, ScenarioHandoff},
        harness::{App, FuzzScenarioStandardHarness},
    },
};
use commonware_cryptography::Digestible as _;
use commonware_runtime::deterministic;
use statelens_differential_shim::target_states::{Stages, Witness, control};
use std::cell::Cell;

pub const CARD: &str = "TS-9007";
pub const STAGES: u32 = 6;

/// E6: height 3 delivered and the tip at it, with no fetch, no local wait and no targeted
/// fetch.
fn e6(recorder: &Recorder, bind: &str, d: &str) -> Option<Witness> {
    let delivered = recorder.replica_exact("delivered", &format!(",h=3,d={d}"), "block")?;
    let tip = recorder.replica_exact("tip", &format!(",h=3,d={d}"), "v3")?;
    let count = recorder.replica_exact("fetch_count", "", "0")?;
    let waits = recorder.replica_exact("subscriptions", "", "0")?;
    let targeted = recorder.replica_exact("targeted", "", "0")?;
    Some(Witness::exact(
        bind,
        &[
            delivered.read(),
            tip.read(),
            count.read(),
            waits.read(),
            targeted.read(),
        ],
    ))
}

pub async fn prefix<P: Simplex, M: TwinsMarshal<P, App<P>>>(
    context: &deterministic::Context,
    stages: &mut Stages,
    recorder: &Recorder,
    harness: &mut FuzzScenarioStandardHarness<P, M>,
    mailbox: &Mb<P>,
    twist: Twist,
) -> Prefix<P> {
    harness.begin("test_standard_get_block_by_height_and_latest");
    // Initially, no blocks: the source's leading queries, side-effect-free.
    if harness.get_block(Node::B, Height::new(1)).await.is_some()
        || harness
            .get_block(Node::B, Identifier::Latest)
            .await
            .is_some()
    {
        stages.missed(1, "a fresh marshal holds a block");
    }
    let withheld = control() || twist == Twist::Withhold(5);
    let misroute = twist == Twist::MisrouteFirstFinalization;

    let mut blocks = Vec::new();
    let mut floor_finalization = None;
    for i in 1..=3u64 {
        let harness_event = 2 * i as u32 - 1;
        let replica_event = harness_event + 1;
        // Block i: height i at view i on the previous block (genesis for the first), led
        // by B, with the source's derived parent view (i - 1) and timestamp (i).
        let block = harness.block(Node::B, i);
        let digest = block.digest();
        let d = digest.to_string();
        let bind_harness = if i == 1 {
            format!("B=1@E1,v=1@E1,d={d}@E1")
        } else {
            format!("B=1@E1,v={i}@E{harness_event},d={d}@E{harness_event}")
        };
        let bind_replica = format!("B=1@E1,h={i}@E{replica_event},d={d}@E{harness_event}");

        // E1, E3, E5. harness: persists b_i through the durability handshake, waits one
        // barrier, and reports its quorum finalization.
        if stages.open() {
            if withheld && harness_event == 5 {
                stages.withheld(harness_event);
            } else {
                let durable = match race(context, mailbox.verified(round(i), block.clone())).await {
                    Some(true) => {
                        recorder.reply("verified", &format!(",v={i},d={d}"), "durable");
                        true
                    }
                    Some(false) => {
                        recorder.reply("verified", &format!(",v={i},d={d}"), "rejected");
                        stages.missed(harness_event, "verified was not durable");
                        false
                    }
                    None => {
                        stages.missed(harness_event, "verified did not reply by the deadline");
                        false
                    }
                };
                if durable {
                    // The source sleeps `LINK.latency` before reporting; the mailbox
                    // barrier is the harness equivalent.
                    let _ = harness.barrier(Node::B).await;
                    let finalization = harness.finalization_of(&block, &QUORUM_SIGNERS);
                    let target = if misroute && i == 1 { Node::C } else { Node::B };
                    let ((), witness) = Witness::act(
                        &bind_harness,
                        &format!("report_finalization[B=1,v={i},d={d}]"),
                        || harness.report_finalization(target, finalization.clone()),
                    );
                    stages.held(harness_event, witness);
                    floor_finalization = Some(finalization);
                }
            }
        }
        blocks.push((digest, block));

        // E2, E4, E6. B: finalizes b_i: delivers height i.
        if stages.open() {
            let found = poll(context, harness, Node::B, || {
                recorder.replica_exact("delivered", &format!(",h={i},d={d}"), "block")
            })
            .await;
            if replica_event < STAGES {
                match found {
                    Some(entry) => {
                        stages.held(
                            replica_event,
                            Witness::exact(&bind_replica, &[entry.read()]),
                        );
                    }
                    None => stages.missed(replica_event, "height not delivered by the deadline"),
                }
            }
        }
    }
    let (digest_3, _) = &blocks[2];
    let d3 = digest_3.to_string();
    let bind_last = format!("B=1@E1,h=3@E6,d={d3}@E5");
    let reached = Cell::new(false);
    stages.handoff(|| {
        let witness = e6(recorder, &bind_last, &d3);
        reached.set(witness.is_some());
        witness
    });

    // After the mark, the source's trailing queries as oracles.
    if reached.get() && !control() {
        for (i, (digest, _)) in blocks.iter().enumerate() {
            let height = Height::new(i as u64 + 1);
            let fetched = harness
                .get_block(Node::B, height)
                .await
                .expect("finalized height must retrieve its block");
            assert_eq!(fetched.digest(), *digest, "wrong block at {height}");
            assert_eq!(fetched.height(), height, "wrong height at {height}");
        }
        let latest = harness
            .get_block(Node::B, Identifier::Latest)
            .await
            .expect("latest must retrieve the last finalized block");
        assert_eq!(latest.digest(), blocks[2].0, "latest must be block 3");
        assert_eq!(latest.height(), Height::new(3), "latest must be height 3");
        assert!(
            harness.get_block(Node::B, Height::new(10)).await.is_none(),
            "an unfinalized height must have no block"
        );
    }

    let handoff = floor_finalization
        .filter(|finalization| finalization.proposal.payload == *digest_3)
        .map(|floor_finalization| ScenarioHandoff {
            engine_floor: Floor::Finalized(floor_finalization),
            engine_journal: Vec::new(),
            attack_anchor: attack_above::<P>(&blocks[2].1),
            reference_chain: blocks.iter().map(|(_, block)| block.clone()).collect(),
            node_fetches: vec![
                (Node::A, Vec::new()),
                (Node::B, Vec::new()),
                (Node::C, Vec::new()),
                (Node::D, Vec::new()),
            ],
            node_active_fetches: vec![
                (Node::A, Vec::new()),
                (Node::B, Vec::new()),
                (Node::C, Vec::new()),
                (Node::D, Vec::new()),
            ],
            expected_nodes: vec![
                NodeExpectation::new(Node::A)
                    .lacks(blocks[0].0)
                    .lacks(blocks[1].0)
                    .lacks(blocks[2].0),
                NodeExpectation::new(Node::B)
                    .holds(blocks[0].0)
                    .holds(blocks[1].0)
                    .holds(blocks[2].0),
                NodeExpectation::new(Node::C)
                    .lacks(blocks[0].0)
                    .lacks(blocks[1].0)
                    .lacks(blocks[2].0),
                NodeExpectation::new(Node::D)
                    .lacks(blocks[0].0)
                    .lacks(blocks[1].0)
                    .lacks(blocks[2].0),
            ],
            expectation: Expectation::genesis_rooted(),
        });
    Prefix {
        handoff,
        reached: reached.get(),
    }
}
