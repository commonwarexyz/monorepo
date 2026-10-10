//! TS-9003 on marshal_scenario_standard_deferred_cert_mock
//! Shape: B
//! Knobs: raw_bytes[0..0]: none
//! Stages: E1 exact verified; E2 construction wrapper_verify; E3 exact fetch, fetch_count,
//!     subscription (polled); E4 exact verified; E5 exact verify; E6 construction
//!     wrapper_certify; E7 exact certify, fetch, targeted
//! Control: withholds E4
//! Injections: none (both verified writes are the source's own durability handshake)
//! Missing: none

// Source: `test_standard_verify_height_lie_parent_fetch_is_round_bound`
// (consensus/src/marshal/standard/mod.rs), the Deferred tail, as
// `scenarios::StandardVerifyHeightLieParentFetchIsRoundBound@392b116687` drives it. The
// source's tail differs per wrapper kind, so TS-9004 is the Inline card; [`height_lie`]
// drives both. Limitation: that B holds both blocks is an async mailbox read, so it is not
// an `En` item; `finish` and the digest check it right after the mark.

use super::{Prefix, Twist, attack_above, poll, race, round, verdict};
use crate::record::Recorder;
use commonware_consensus::{
    simplex::Floor,
    types::{Height, View},
};
use commonware_consensus_fuzz_core::simplex::Simplex;
use commonware_consensus_fuzz_marshal::{
    marshal::end_to_end::twins::{B, stack::TwinsMarshal},
    scenarios::{
        environment::{Expectation, FetchMatch, Mb, Node, NodeExpectation, ScenarioHandoff},
        harness::{App, FuzzScenarioStandardHarness},
    },
};
use commonware_cryptography::{Digestible as _, Sha256};
use commonware_runtime::deterministic;
use statelens_differential_shim::target_states::{Stages, Witness, control};
use std::cell::Cell;

pub const CARD: &str = "TS-9003";
pub const STAGES: u32 = 7;

/// The wrapper variant a card fixes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// TS-9003: verify passes optimistically, certify rejects (seven events).
    Deferred,
    /// TS-9004: verify rejects (five events).
    Inline,
}

/// E3: one round-bound notarized fetch for v and a local wait for p.
fn e3(recorder: &Recorder, bind: &str, p: &str) -> Option<Witness> {
    let fetch = recorder.replica_exact("fetch", ",v=1", "active")?;
    let count = recorder.replica_exact("fetch_count", "", "1")?;
    let wait = recorder.replica_nonzero("subscription", &format!(",p={p}"))?;
    Some(Witness::exact(
        bind,
        &[fetch.read(), count.read(), wait.read()],
    ))
}

/// En: the rejecting verdict (`verify` for Inline, `certify` for Deferred), the
/// round-bound fetch still active, no targeted fetch.
fn last(recorder: &Recorder, bind: &str, observable: &str, c: &str) -> Option<Witness> {
    let rejected = recorder.replica_exact(observable, &format!(",w=2,c={c}"), "false")?;
    let fetch = recorder.replica_exact("fetch", ",v=1", "active")?;
    let targeted = recorder.replica_exact("targeted", "", "0")?;
    Some(Witness::exact(
        bind,
        &[rejected.read(), fetch.read(), targeted.read()],
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
    height_lie(
        context,
        stages,
        recorder,
        harness,
        mailbox,
        twist,
        Variant::Deferred,
    )
    .await
}

/// The height-lie History under `variant`.
pub async fn height_lie<P: Simplex, M: TwinsMarshal<P, App<P>>>(
    context: &deterministic::Context,
    stages: &mut Stages,
    recorder: &Recorder,
    harness: &mut FuzzScenarioStandardHarness<P, M>,
    mailbox: &Mb<P>,
    twist: Twist,
    variant: Variant,
) -> Prefix<P> {
    harness.begin("test_standard_verify_height_lie_parent_fetch_is_round_bound");
    // The honest parent: a height-1 block at view 1 on genesis, led by B.
    let genesis_digest = harness.genesis().digest();
    let parent_round = round(1);
    let parent_context = harness.context(parent_round, Node::B, View::zero(), genesis_digest);
    let parent = B::<P>::new::<Sha256>(parent_context, genesis_digest, Height::new(1), 100);
    let parent_digest = parent.digest();
    // The height lie: a child at view 2 naming the height-1 parent but claiming height 3.
    let child_round = round(2);
    let child_context = harness.context(child_round, Node::B, View::new(1), parent_digest);
    let child = B::<P>::new::<Sha256>(child_context.clone(), parent_digest, Height::new(3), 200);
    let child_digest = child.digest();
    recorder.alias_digest(child_digest, "c");
    recorder.alias_digest(parent_digest, "p");
    recorder.alias_view(2, "w");

    let c = child_digest.to_string();
    let p = parent_digest.to_string();
    let bind_child = format!("B=1@E1,w=2@E1,c={c}@E1");
    let bind_parent = format!("B=1@E1,v=1@E3,p={p}@E3");
    let bind_last = format!("B=1@E1,w=2@E1,c={c}@E1,v=1@E3");
    let child_reply = format!(",w=2,c={c}");
    let withheld = control() || twist == Twist::Withhold(4);

    // E1. harness: persists the child c as verified on B.
    match race(context, mailbox.verified(child_round, child.clone())).await {
        Some(true) => {
            let entry = recorder.reply("verified", &child_reply, "durable");
            stages.held(1, Witness::exact(&bind_child, &[entry.read()]));
        }
        Some(false) => {
            recorder.reply("verified", &child_reply, "rejected");
            stages.missed(1, "verified was not durable");
        }
        None => stages.missed(1, "verified did not reply by the deadline"),
    }

    // E2. harness: calls verify for c at w.
    let mut verify = None;
    if stages.open() {
        let (receiver, witness) = Witness::act_async(
            &bind_child,
            &format!("wrapper_verify[B=1,w=2,c={c}]"),
            || harness.wrapper_verify(Node::B, child_context.clone(), child_digest),
        )
        .await;
        stages.held(2, witness);
        recorder.reply("verify", &child_reply, "pending");
        verify = Some(receiver);
    }

    // E3. B: issues one round-bound fetch for v and registers a local wait for p.
    if stages.open() {
        match poll(context, harness, Node::B, || e3(recorder, &bind_parent, &p)).await {
            Some(witness) => {
                stages.held(3, witness);
            }
            None => stages.missed(
                3,
                "no round-bound parent fetch with a local wait by the deadline",
            ),
        }
    }

    // E4. harness: persists the parent p as verified on B.
    if stages.open() {
        if withheld {
            stages.withheld(4);
        } else {
            match race(context, mailbox.verified(parent_round, parent.clone())).await {
                Some(true) => {
                    let entry = recorder.reply("verified", &format!(",v=1,p={p}"), "durable");
                    stages.held(4, Witness::exact(&bind_parent, &[entry.read()]));
                }
                Some(false) => {
                    recorder.reply("verified", &format!(",v=1,p={p}"), "rejected");
                    stages.missed(4, "verified was not durable");
                }
                None => stages.missed(4, "verified did not reply by the deadline"),
            }
        }
    }

    // E5. B: resolves the verify of c.
    let mut verdict_seen = None;
    if stages.open() {
        let outcome = match verify.take() {
            Some(receiver) => race(context, receiver).await,
            None => None,
        };
        match outcome {
            Some(Ok(value)) => {
                recorder.reply("verify", &child_reply, verdict(value));
                verdict_seen = Some(value);
            }
            Some(Err(_)) => {
                recorder.reply("verify", &child_reply, "dropped");
            }
            None => {}
        }
    }
    let rejecting = match variant {
        Variant::Inline => "verify",
        Variant::Deferred => {
            if stages.open() {
                match verdict_seen {
                    Some(true) => {
                        let entry = recorder
                            .replica_entry("verify", &child_reply)
                            .expect("recorded above");
                        stages.held(5, Witness::exact(&bind_child, &[entry.read()]));
                    }
                    Some(false) => stages.missed(5, "the Deferred verify rejected the child"),
                    None => stages.missed(5, "verify did not resolve by the deadline"),
                }
            }
            // E6. harness: calls certify for c at w.
            let mut certify = None;
            if stages.open() {
                let (receiver, witness) = Witness::act_async(
                    &bind_child,
                    &format!("wrapper_certify[B=1,w=2,c={c}]"),
                    || harness.wrapper_certify(Node::B, child_round, child_digest),
                )
                .await;
                stages.held(6, witness);
                recorder.reply("certify", &child_reply, "pending");
                certify = Some(receiver);
            }
            // E7. B: rejects the certify.
            if stages.open()
                && let Some(receiver) = certify.take()
            {
                match race(context, receiver).await {
                    Some(Ok(value)) => {
                        recorder.reply("certify", &child_reply, verdict(value));
                    }
                    Some(Err(_)) => {
                        recorder.reply("certify", &child_reply, "dropped");
                    }
                    None => {}
                }
            }
            "certify"
        }
    };
    let reached = Cell::new(false);
    stages.handoff(|| {
        let witness = last(recorder, &bind_last, rejecting, &c);
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
                (Node::B, vec![FetchMatch::NotarizedRound(parent_round)]),
                (Node::C, Vec::new()),
                (Node::D, Vec::new()),
            ],
            node_active_fetches: vec![
                (Node::A, Vec::new()),
                (Node::B, vec![FetchMatch::NotarizedRound(parent_round)]),
                (Node::C, Vec::new()),
                (Node::D, Vec::new()),
            ],
            expected_nodes: vec![
                NodeExpectation::new(Node::A)
                    .lacks(child_digest)
                    .lacks(parent_digest),
                NodeExpectation::new(Node::B)
                    .holds(child_digest)
                    .holds(parent_digest),
                NodeExpectation::new(Node::C)
                    .lacks(child_digest)
                    .lacks(parent_digest),
                NodeExpectation::new(Node::D)
                    .lacks(child_digest)
                    .lacks(parent_digest),
            ],
            expectation: Expectation::genesis_rooted(),
        }),
        reached: reached.get(),
    }
}
