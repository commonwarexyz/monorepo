//! TS-9001 on marshal_scenario_standard_deferred_cert_mock
//! Shape: B
//! Knobs: raw_bytes[0..0]: none
//! Stages: E1 construction arm_delivery; E2 construction wrapper_certify; E3 exact fetch,
//!     fetch_count, subscription, targeted (polled); E4 exact certify, delivery, fetch,
//!     subscription, targeted
//! Control: withholds E1
//! Injections: the armed resolver delivery of the fabricated view-1 notarization and its
//!     block, as the scenario arms it (no campaign ghost state exists in this crate)
//! Missing: none

// Source: `test_standard_certify_missing_candidate_fetches_by_round`
// (consensus/src/marshal/standard/mod.rs), as
// `scenarios::StandardCertifyMissingCandidateFetchesByRound@392b116687` drives it.
// Limitation: block presence is an async mailbox read, so it is not an `En` item;
// `finish` and the digest check it right after the mark.

use super::{Prefix, Twist, attack_above, poll, race, round, verdict};
use crate::record::Recorder;
use commonware_codec::Encode as _;
use commonware_consensus::{
    simplex::Floor,
    types::{Height, View},
};
use commonware_consensus_fuzz_core::simplex::Simplex;
use commonware_consensus_fuzz_marshal::{
    marshal::end_to_end::twins::{B, stack::TwinsMarshal},
    scenarios::{
        environment::{
            Expectation, FetchMatch, Mb, Node, NodeExpectation, QUORUM_SIGNERS, ScenarioHandoff,
        },
        harness::{App, FuzzScenarioStandardHarness},
    },
};
use commonware_cryptography::{Digestible as _, Sha256};
use commonware_runtime::deterministic;
use statelens_differential_shim::target_states::{Stages, Witness, control};
use std::cell::Cell;

pub const CARD: &str = "TS-9001";
pub const STAGES: u32 = 4;

/// E3: one round-bound notarized fetch for v, a local wait for d, no targeted fetch.
fn e3(recorder: &Recorder, bind: &str, d: &str) -> Option<Witness> {
    let fetch = recorder.replica_exact("fetch", ",v=1", "active")?;
    let count = recorder.replica_exact("fetch_count", "", "1")?;
    let wait = recorder.replica_nonzero("subscription", &format!(",d={d}"))?;
    let targeted = recorder.replica_exact("targeted", "", "0")?;
    Some(Witness::exact(
        bind,
        &[fetch.read(), count.read(), wait.read(), targeted.read()],
    ))
}

/// E4: the certify verdict and the delivery verdict, with the fetch still active, the
/// wait registered and no targeted fetch.
fn e4(recorder: &Recorder, bind: &str, d: &str) -> Option<Witness> {
    let certify = recorder.replica_exact("certify", &format!(",v=1,d={d}"), "true")?;
    let delivery = recorder.replica_exact("delivery", ",v=1", "valid")?;
    let fetch = recorder.replica_exact("fetch", ",v=1", "active")?;
    let wait = recorder.replica_nonzero("subscription", &format!(",d={d}"))?;
    let targeted = recorder.replica_exact("targeted", "", "0")?;
    Some(Witness::exact(
        bind,
        &[
            certify.read(),
            delivery.read(),
            fetch.read(),
            wait.read(),
            targeted.read(),
        ],
    ))
}

pub async fn prefix<P: Simplex, M: TwinsMarshal<P, App<P>>>(
    context: &deterministic::Context,
    stages: &mut Stages,
    recorder: &Recorder,
    harness: &mut FuzzScenarioStandardHarness<P, M>,
    _mailbox: &Mb<P>,
    twist: Twist,
) -> Prefix<P> {
    harness.begin("test_standard_certify_missing_candidate_fetches_by_round");
    // The missing candidate: a height-1 block at view 1 on genesis, led by B.
    let genesis_digest = harness.genesis().digest();
    let round_one = round(1);
    let block_context = harness.context(round_one, Node::B, View::zero(), genesis_digest);
    let block = B::<P>::new::<Sha256>(block_context, genesis_digest, Height::new(1), 100);
    let digest = block.digest();
    let notarization = harness.make_notarization(round_one, View::zero(), digest, &QUORUM_SIGNERS);

    let d = digest.to_string();
    let bind = format!("B=1@E1,v=1@E1,d={d}@E1");
    let entities = format!("B=1,v=1,d={d}");
    let withheld = control() || twist == Twist::Withhold(1);

    // E1. harness: arms B's next backfill fetch with the notarization of d.
    if withheld {
        stages.withheld(1);
    } else {
        let ((), witness) = Witness::act(&bind, &format!("arm_delivery[{entities}]"), || {
            harness.respond_to_next_fetch(Node::B, (notarization.clone(), block.clone()).encode())
        });
        stages.held(1, witness);
    }
    // The negative control also reports the certificate to C, which has no
    // block for it: C caches it and fetches nothing.
    if twist == Twist::NotarizationToC {
        harness.report_notarization(Node::C, notarization.clone());
    }

    // E2. harness: calls B's wrapper certify for d at v.
    let mut certify = None;
    if stages.open() {
        let (receiver, witness) =
            Witness::act_async(&bind, &format!("wrapper_certify[{entities}]"), || {
                harness.wrapper_certify(Node::B, round_one, digest)
            })
            .await;
        stages.held(2, witness);
        recorder.reply("certify", &format!(",v=1,d={d}"), "pending");
        certify = Some(receiver);
    }

    // E3. B: issues one round-bound fetch for v, registers a local wait for d.
    if stages.open() {
        match poll(context, harness, Node::B, || e3(recorder, &bind, &d)).await {
            Some(witness) => {
                stages.held(3, witness);
            }
            None => stages.missed(
                3,
                "no round-bound fetch with a local wait and no targeted fetch by the deadline",
            ),
        }
    }

    // E4. B: certifies d through the armed delivery: the two verdicts.
    if stages.open() {
        if let Some(receiver) = certify.take() {
            match race(context, receiver).await {
                Some(Ok(value)) => {
                    recorder.reply("certify", &format!(",v=1,d={d}"), verdict(value));
                }
                Some(Err(_)) => {
                    recorder.reply("certify", &format!(",v=1,d={d}"), "dropped");
                }
                None => {}
            }
        }
        if !withheld && recorder.replica_entry("fetch", ",v=1").is_some() {
            if let Some(valid) = race(context, harness.wait_for_delivery_response(Node::B)).await {
                recorder.reply("delivery", ",v=1", if valid { "valid" } else { "invalid" });
            }
        }
    }
    let reached = Cell::new(false);
    stages.handoff(|| {
        let witness = e4(recorder, &bind, &d);
        reached.set(witness.is_some());
        witness
    });

    Prefix {
        handoff: Some(ScenarioHandoff {
            engine_floor: Floor::Genesis(genesis_digest),
            engine_journal: vec![notarization],
            attack_anchor: attack_above::<P>(&block),
            reference_chain: vec![block],
            node_fetches: vec![
                (Node::A, Vec::new()),
                (Node::B, vec![FetchMatch::NotarizedRound(round_one)]),
                (Node::C, Vec::new()),
                (Node::D, Vec::new()),
            ],
            node_active_fetches: vec![
                (Node::A, Vec::new()),
                (Node::B, vec![FetchMatch::NotarizedRound(round_one)]),
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
