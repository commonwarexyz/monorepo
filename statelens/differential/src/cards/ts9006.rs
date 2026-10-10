//! TS-9006 on marshal_scenario_standard_deferred_cert_mock
//! Shape: B
//! Knobs: raw_bytes[0..0]: none
//! Stages: E1 construction wrapper_verify; E2 exact subscription, fetch_count, targeted,
//!     verify (polled); E3 construction drop_verify; E4 exact subscription, fetch_count,
//!     targeted, verify
//! Control: withholds E1
//! Injections: none
//! Missing: none

// Source: `test_standard_verify_missing_candidate_waits_without_fetching`
// (consensus/src/marshal/standard/mod.rs), as
// `scenarios::StandardVerifyMissingCandidateWaitsWithoutFetching@392b116687` drives it.
// The wait counter counts registrations, so E4's `subscription` entry with the count E2
// observed, and the empty fetch count, is the post-drop state. E2 reads the verify
// receiver with `try_recv`, a side-effect-free local query, and stamps `verify=pending`
// only on `Empty`, so the pending part of its Check is observed, not asserted; the
// dropped receiver is recorded by the prefix as it drops it.

use super::{Prefix, Twist, attack_above, poll, round};
use crate::record::{Entry, Recorder};
use commonware_consensus::{simplex::Floor, types::View};
use commonware_consensus_fuzz_core::simplex::Simplex;
use commonware_consensus_fuzz_marshal::{
    marshal::end_to_end::twins::stack::TwinsMarshal,
    scenarios::{
        environment::{Expectation, Mb, Node, NodeExpectation, ScenarioHandoff},
        harness::{App, FuzzScenarioStandardHarness},
    },
};
use commonware_cryptography::{Digestible as _, Hasher as _, Sha256};
use commonware_runtime::deterministic;
use commonware_utils::channel::oneshot::error::TryRecvError;
use statelens_differential_shim::target_states::{Stages, Witness, control};
use std::cell::Cell;

pub const CARD: &str = "TS-9006";
pub const STAGES: u32 = 4;

/// E2's and E4's recorded parts: a local wait for m, no fetch of any kind and no targeted
/// fetch. With `count`, the wait's registration count must be that value; without, any
/// wait does. The verify entry is the stage's own: E2 stamps it after `try_recv`, E3 as
/// it drops the receiver.
fn waiting(recorder: &Recorder, m: &str, count: Option<&str>) -> Option<[Entry; 3]> {
    let rest = format!(",m={m}");
    let wait = match count {
        None => recorder.replica_nonzero("subscription", &rest)?,
        Some(count) => recorder.replica_exact("subscription", &rest, count)?,
    };
    let fetches = recorder.replica_exact("fetch_count", "", "0")?;
    let targeted = recorder.replica_exact("targeted", "", "0")?;
    Some([wait, fetches, targeted])
}

/// The witness of E2 or E4: the recorded parts and the verify entry.
fn witness(bind: &str, parts: &[Entry; 3], verify: &Entry) -> Witness {
    Witness::exact(
        bind,
        &[
            parts[0].read(),
            parts[1].read(),
            parts[2].read(),
            verify.read(),
        ],
    )
}

pub async fn prefix<P: Simplex, M: TwinsMarshal<P, App<P>>>(
    context: &deterministic::Context,
    stages: &mut Stages,
    recorder: &Recorder,
    harness: &mut FuzzScenarioStandardHarness<P, M>,
    _mailbox: &Mb<P>,
    twist: Twist,
) -> Prefix<P> {
    harness.begin("test_standard_verify_missing_candidate_waits_without_fetching");
    // The unknown candidate: a digest that names no block, in a view-1 context on
    // genesis led by B.
    let genesis_digest = harness.genesis().digest();
    let round_one = round(1);
    let consensus_context = harness.context(round_one, Node::B, View::zero(), genesis_digest);
    let missing = Sha256::hash(&[b"missing candidate"]);
    recorder.alias_digest(missing, "m");

    let m = missing.to_string();
    let bind = format!("B=1@E1,v=1@E1,m={m}@E1");
    let reply = format!(",v=1,m={m}");
    let withheld = control() || twist == Twist::Withhold(1);

    // E1. harness: calls verify for the unknown digest m at v.
    let mut verify = None;
    if withheld {
        stages.withheld(1);
    } else {
        let (receiver, witness) =
            Witness::act_async(&bind, &format!("wrapper_verify[B=1,v=1,m={m}]"), || {
                harness.wrapper_verify(Node::B, consensus_context, missing)
            })
            .await;
        stages.held(1, witness);
        verify = Some(receiver);
    }

    // E2. B: registers a local wait for m, issues no fetch; the verify stays pending,
    // read from the receiver with `try_recv` (an empty channel stays awaitable) and
    // stamped only then. The registration count E2 observes is what E4 requires: the
    // counter counts registrations, so a cancel-triggered re-subscription would raise it.
    let mut registered = None;
    if stages.open() {
        match poll(context, harness, Node::B, || waiting(recorder, &m, None)).await {
            Some(parts) => match verify.as_mut().map(|receiver| receiver.try_recv()) {
                Some(Err(TryRecvError::Empty)) => {
                    let pending = recorder.reply("verify", &reply, "pending");
                    registered = Some(parts[0].value.clone());
                    stages.held(2, witness(&bind, &parts, &pending));
                }
                _ => stages.missed(2, "the verify of the unknown digest did not stay pending"),
            },
            None => stages.missed(2, "no local wait without a fetch by the deadline"),
        }
    }

    // E3. harness: drops the pending verify receiver.
    if stages.open() {
        let ((), witness) = Witness::act(&bind, &format!("drop_verify[B=1,v=1,m={m}]"), || {
            drop(verify.take());
            recorder.reply("verify", &reply, "dropped");
        });
        stages.held(3, witness);
        // The source sleeps 10ms after the drop; the mailbox barrier is the harness
        // equivalent.
        let _ = harness.barrier(Node::B).await;
    }

    // E4. B: keeps the wait count and issues no fetch. Without E2's count (the control
    // run withheld E1) E4 is missed by construction.
    let reached = Cell::new(false);
    stages.handoff(|| {
        let count = registered.as_deref()?;
        let parts = waiting(recorder, &m, Some(count))?;
        let dropped = recorder.replica_exact("verify", &reply, "dropped")?;
        reached.set(true);
        Some(witness(&bind, &parts, &dropped))
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
                NodeExpectation::new(Node::A).lacks(missing),
                NodeExpectation::new(Node::B).lacks(missing),
                NodeExpectation::new(Node::C).lacks(missing),
                NodeExpectation::new(Node::D).lacks(missing),
            ],
            expectation: Expectation::genesis_rooted(),
        }),
        reached: reached.get(),
    }
}
