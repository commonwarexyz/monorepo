//! TS-9005 on marshal_scenario_standard_deferred_cert_mock
//! Shape: B
//! Knobs: raw_bytes[0..0]: none
//! Stages: E1 construction wrapper_verify; E2 exact subscription, fetch_count, verify
//!     (polled); E3 construction arm_delivery; E4 construction wrapper_certify; E5 exact
//!     verify, certify, fetch, fetch_count, targeted
//! Control: withholds E3
//! Injections: the armed resolver delivery of the fabricated view-1 notarization and its
//!     block, as the scenario arms it (no campaign ghost state exists in this crate)
//! Missing: none

// Source: `test_standard_certify_bumps_notarized_fetch_for_pending_verify`
// (consensus/src/marshal/standard/mod.rs), as
// `scenarios::StandardCertifyBumpsNotarizedFetchForPendingVerify@392b116687` drives it.
// The scenario does not wait between verify and certify; E2 polls for the local wait,
// which the actor registers before it processes certify (FIFO), so the end state is the
// same. E2 reads the verify receiver with `try_recv`, a side-effect-free local query, and
// stamps `verify=pending` only on `Empty`, so the pending part of its Check is observed,
// not asserted. Limitation: block presence is an async mailbox read, so it is not an `En`
// item; `finish` and the digest check it right after the mark.

use super::{Prefix, Twist, attack_above, poll, race, round, verdict};
use crate::record::{Entry, Recorder};
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
use commonware_utils::channel::oneshot::error::TryRecvError;
use statelens_differential_shim::target_states::{Stages, Witness, control};
use std::cell::Cell;

pub const CARD: &str = "TS-9005";
pub const STAGES: u32 = 5;

/// E2's recorded parts: a local wait for d and no fetch. Its third part, the pending
/// verification, is read from the receiver at the stage and stamped then.
fn e2_recorded(recorder: &Recorder, d: &str) -> Option<(Entry, Entry)> {
    let wait = recorder.replica_nonzero("subscription", &format!(",d={d}"))?;
    let count = recorder.replica_exact("fetch_count", "", "0")?;
    Some((wait, count))
}

/// E5: both verdicts true, exactly one round-bound fetch for v, still active, no
/// targeted fetch.
fn e5(recorder: &Recorder, bind: &str, d: &str) -> Option<Witness> {
    let verify = recorder.replica_exact("verify", &format!(",v=1,d={d}"), "true")?;
    let certify = recorder.replica_exact("certify", &format!(",v=1,d={d}"), "true")?;
    let fetch = recorder.replica_exact("fetch", ",v=1", "active")?;
    let count = recorder.replica_exact("fetch_count", "", "1")?;
    let targeted = recorder.replica_exact("targeted", "", "0")?;
    Some(Witness::exact(
        bind,
        &[
            verify.read(),
            certify.read(),
            fetch.read(),
            count.read(),
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
    harness.begin("test_standard_certify_bumps_notarized_fetch_for_pending_verify");
    // The missing candidate: a height-1 block at view 1 on genesis, led by B.
    let genesis_digest = harness.genesis().digest();
    let round_one = round(1);
    let block_context = harness.context(round_one, Node::B, View::zero(), genesis_digest);
    let block = B::<P>::new::<Sha256>(block_context.clone(), genesis_digest, Height::new(1), 100);
    let digest = block.digest();

    let d = digest.to_string();
    let bind = format!("B=1@E1,v=1@E1,d={d}@E1");
    let reply = format!(",v=1,d={d}");
    let withheld = control() || twist == Twist::Withhold(3);
    let swap = twist == Twist::SwapArmAndVerify && !withheld;

    // The negative control arms before verify: the notarization first, then E3's action,
    // recorded as E3 after E1 and E2.
    let mut notarization = None;
    let mut early_arm = None;
    if swap {
        let certificate =
            harness.make_notarization(round_one, View::zero(), digest, &QUORUM_SIGNERS);
        let ((), witness) = Witness::act(&bind, &format!("arm_delivery[B=1,v=1,d={d}]"), || {
            harness.respond_to_next_fetch(Node::B, (certificate.clone(), block.clone()).encode())
        });
        notarization = Some(certificate);
        early_arm = Some(witness);
    }

    // E1. harness: calls verify for d at v (d held nowhere).
    let (verify, witness) =
        Witness::act_async(&bind, &format!("wrapper_verify[B=1,v=1,d={d}]"), || {
            harness.wrapper_verify(Node::B, block_context.clone(), digest)
        })
        .await;
    stages.held(1, witness);
    let mut verify = Some(verify);

    // E2. B: registers a local wait for d and issues no fetch; the verification stays
    // pending. `try_recv` on an empty channel leaves the receiver awaitable for E5; on
    // a verdict or a closed channel it consumes the receiver, which E5 then skips.
    if stages.open() {
        match poll(context, harness, Node::B, || e2_recorded(recorder, &d)).await {
            Some((wait, count)) => match verify.as_mut().map(|receiver| receiver.try_recv()) {
                Some(Err(TryRecvError::Empty)) => {
                    let pending = recorder.reply("verify", &reply, "pending");
                    stages.held(
                        2,
                        Witness::exact(&bind, &[wait.read(), count.read(), pending.read()]),
                    );
                }
                Some(Ok(value)) => {
                    verify = None;
                    recorder.reply("verify", &reply, verdict(value));
                    stages.missed(2, "the verification of d did not stay pending");
                }
                _ => {
                    verify = None;
                    recorder.reply("verify", &reply, "dropped");
                    stages.missed(2, "the verification of d did not stay pending");
                }
            },
            None => stages.missed(2, "no local wait without a fetch by the deadline"),
        }
    }

    // E3. harness: arms the notarized delivery (c, d) for v.
    if stages.open() {
        if withheld {
            stages.withheld(3);
        } else if let Some(witness) = early_arm.take() {
            stages.held(3, witness);
        } else {
            let certificate =
                harness.make_notarization(round_one, View::zero(), digest, &QUORUM_SIGNERS);
            let ((), witness) =
                Witness::act(&bind, &format!("arm_delivery[B=1,v=1,d={d}]"), || {
                    harness.respond_to_next_fetch(
                        Node::B,
                        (certificate.clone(), block.clone()).encode(),
                    )
                });
            notarization = Some(certificate);
            stages.held(3, witness);
        }
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

    // E5. B: bumps one round-bound fetch, resolved by the armed delivery; both verdicts.
    if stages.open() {
        for (observable, receiver) in [("verify", verify.take()), ("certify", certify.take())] {
            let Some(receiver) = receiver else {
                continue;
            };
            match race(context, receiver).await {
                Some(Ok(value)) => {
                    recorder.reply(observable, &reply, verdict(value));
                }
                Some(Err(_)) => {
                    recorder.reply(observable, &reply, "dropped");
                }
                None => {}
            }
        }
    }
    let reached = Cell::new(false);
    stages.handoff(|| {
        let witness = e5(recorder, &bind, &d);
        reached.set(witness.is_some());
        witness
    });

    // The handoff names the recovered notarization; without one (the control run
    // withheld the arming) the floor has nothing to recover and the test skips `finish`.
    let handoff = notarization.map(|notarization| ScenarioHandoff {
        engine_floor: Floor::Genesis(genesis_digest),
        engine_journal: vec![notarization],
        attack_anchor: attack_above::<P>(&block),
        reference_chain: vec![block.clone()],
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
    });
    Prefix {
        handoff,
        reached: reached.get(),
    }
}
