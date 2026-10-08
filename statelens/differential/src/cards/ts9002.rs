//! TS-9002 on marshal_scenario_standard_deferred_cert_mock
//! Shape: B
//! Knobs: raw_bytes[0..0]: none
//! Stages: E1 exact verified; E2 construction wrapper_verify; E3 exact verify; E4
//!     construction wrapper_certify; E5 exact certify, fetch_count, targeted, subscriptions
//! Control: withholds E1
//! Injections: none (the verified write is the source's own durability handshake)
//! Missing: none

// Source: `test_standard_certify_first_block_fetches_genesis_parent`
// (consensus/src/marshal/standard/mod.rs), as
// `scenarios::StandardCertifyFirstBlockFetchesGenesisParent@392b116687` drives it.
// Limitation: block presence is an async mailbox read, so it is not an `En` item;
// `finish` and the digest check it right after the mark.

use super::{Prefix, Twist, attack_above, race, round, verdict};
use crate::record::Recorder;
use bytes::Bytes;
use commonware_consensus::{
    simplex::Floor,
    types::{Height, View},
};
use commonware_consensus_fuzz_core::simplex::Simplex;
use commonware_consensus_fuzz_marshal::{
    marshal::end_to_end::twins::{B, stack::TwinsMarshal},
    scenarios::{
        environment::{Expectation, Mb, Node, NodeExpectation, ScenarioHandoff},
        harness::{App, FuzzScenarioStandardHarness},
    },
};
use commonware_cryptography::{Digestible as _, Sha256};
use commonware_runtime::deterministic;
use statelens_differential_shim::target_states::{Stages, Witness, control};
use std::cell::Cell;

pub const CARD: &str = "TS-9002";
pub const STAGES: u32 = 5;

/// E5: certified, with no fetch, no targeted fetch and no local wait.
fn e5(recorder: &Recorder, bind: &str, d: &str) -> Option<Witness> {
    let certify = recorder.replica_exact("certify", &format!(",v=1,d={d}"), "true")?;
    let count = recorder.replica_exact("fetch_count", "", "0")?;
    let targeted = recorder.replica_exact("targeted", "", "0")?;
    let waits = recorder.replica_exact("subscriptions", "", "0")?;
    Some(Witness::exact(
        bind,
        &[certify.read(), count.read(), targeted.read(), waits.read()],
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
    harness.begin("test_standard_certify_first_block_fetches_genesis_parent");
    // The first block: a height-1 block at view 1 on genesis, led by B.
    let genesis_digest = harness.genesis().digest();
    let round_one = round(1);
    let block_context = harness.context(round_one, Node::B, View::zero(), genesis_digest);
    let block = B::<P>::new::<Sha256>(block_context.clone(), genesis_digest, Height::new(1), 100);
    let digest = block.digest();

    let d = digest.to_string();
    let g = genesis_digest.to_string();
    let bind = format!("B=1@E1,v=1@E1,d={d}@E1");
    let bind_parent = format!("B=1@E1,v=1@E1,d={d}@E1,g={g}@E2");
    let reply = format!(",v=1,d={d}");
    let withheld = control() || twist == Twist::Withhold(1);

    // E1. harness: persists d as verified at v on B.
    if withheld {
        stages.withheld(1);
    } else {
        match race(context, mailbox.verified(round_one, block.clone())).await {
            Some(true) => {
                let entry = recorder.reply("verified", &reply, "durable");
                stages.held(1, Witness::exact(&bind, &[entry.read()]));
            }
            Some(false) => {
                recorder.reply("verified", &reply, "rejected");
                stages.missed(1, "verified was not durable");
            }
            None => stages.missed(1, "verified did not reply by the deadline"),
        }
        // The source sleeps 10ms between `verified` and `verify`; the mailbox
        // barrier is the harness equivalent.
        let _ = harness.barrier(Node::B).await;
    }

    // E2. harness: calls verify for d at v under the context naming parent g.
    let mut verify = None;
    if stages.open() {
        let (receiver, witness) = Witness::act_async(
            &bind_parent,
            &format!("wrapper_verify[B=1,v=1,d={d},g={g}]"),
            || harness.wrapper_verify(Node::B, block_context.clone(), digest),
        )
        .await;
        stages.held(2, witness);
        recorder.reply("verify", &reply, "pending");
        verify = Some(receiver);
    }

    // E3. B: verifies d at v: true.
    if stages.open() {
        let outcome = match verify.take() {
            Some(receiver) => race(context, receiver).await,
            None => None,
        };
        match outcome {
            Some(Ok(true)) => {
                let entry = recorder.reply("verify", &reply, "true");
                stages.held(3, Witness::exact(&bind, &[entry.read()]));
            }
            Some(Ok(false)) => {
                recorder.reply("verify", &reply, "false");
                stages.missed(3, "verify rejected the height-1 block");
            }
            Some(Err(_)) => {
                recorder.reply("verify", &reply, "dropped");
                stages.missed(3, "the verify reply was dropped");
            }
            None => stages.missed(3, "verify did not resolve by the deadline"),
        }
    }

    // The negative control arms a delivery no fetch of this prefix consumes.
    if twist == Twist::ArmGarbage {
        harness.respond_to_next_fetch(Node::B, Bytes::from_static(b"garbage"));
    }

    // E4. harness: calls certify for d at v.
    let mut certify = None;
    if stages.open() {
        let (receiver, witness) =
            Witness::act_async(&bind, &format!("wrapper_certify[B=1,v=1,d={d}]"), || {
                harness.wrapper_certify(Node::B, round_one, digest)
            })
            .await;
        stages.held(4, witness);
        recorder.reply("certify", &reply, "pending");
        certify = Some(receiver);
    }

    // E5. B: certifies d at v with no fetch and no local wait.
    if stages.open()
        && let Some(receiver) = certify.take()
    {
        match race(context, receiver).await {
            Some(Ok(value)) => {
                recorder.reply("certify", &reply, verdict(value));
            }
            Some(Err(_)) => {
                recorder.reply("certify", &reply, "dropped");
            }
            None => {}
        }
    }
    let reached = Cell::new(false);
    // The negative control builds the witness before the handoff call.
    let stale = (twist == Twist::StaleHandoffRead).then(|| e5(recorder, &bind, &d));
    stages.handoff(|| {
        let witness = match stale {
            Some(witness) => witness,
            None => e5(recorder, &bind, &d),
        };
        reached.set(witness.is_some());
        witness
    });

    Prefix {
        handoff: Some(ScenarioHandoff {
            engine_floor: Floor::Genesis(genesis_digest),
            engine_journal: Vec::new(),
            attack_anchor: attack_above::<P>(harness.genesis()),
            reference_chain: Vec::new(),
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
                NodeExpectation::new(Node::A).lacks(digest),
                NodeExpectation::new(Node::B).holds(digest),
                NodeExpectation::new(Node::C).lacks(digest),
                NodeExpectation::new(Node::D).lacks(digest),
            ],
            expectation: Expectation::genesis_rooted(),
        }),
        reached: reached.get(),
    }
}
