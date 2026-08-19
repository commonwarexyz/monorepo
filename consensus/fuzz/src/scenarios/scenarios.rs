//! Faithful copy of one standard-marshal test prefix.
//!
//! [`StandardCertifyMissingCandidateFetchesByRound`] reproduces
//! `test_standard_certify_missing_candidate_fetches_by_round`
//! (consensus/src/marshal/standard/mod.rs:2489) through its handoff point and
//! composes it with a live Simplex cluster through certification recovery:
//!
//! - The prefix replays the source trace on the victim: the resolver response
//!   is armed before `certify`, so the round-bound notarized fetch resolves
//!   through the injected `(notarization, block)` delivery and certification
//!   succeeds, having registered a local wait and no targeted fetch.
//! - The fabricated view-1 notarization is then seeded as an
//!   `Artifact::Notarization` into every honest engine's voter journal before
//!   `Engine::new`, with the engine floor kept at genesis. Startup replay
//!   installs the recovered proposal before the live loop (so no engine can
//!   produce a competing view-1 proposal), re-drives `automaton.certify` for
//!   it, and advances only after success: the recovery path Simplex itself
//!   tests in `cancelled_certification_recertifies_after_restart`
//!   (consensus/src/simplex/actors/voter/mod.rs:7259).
//! - Composition soundness (I1) admits the above-floor notarization because
//!   every above-floor prefix certificate must match a recovered journal entry
//!   exactly; nothing else above the floor is fabricated.
//!
//! The first attackable live view is view 2 over the recovered source block.

use super::{
    environment::{
        AttackAnchor, Expectation, FetchMatch, Node, NodeExpectation, QUORUM_SIGNERS,
        ScenarioHandoff,
    },
    harness::{App, FuzzScenarioStandardHarness},
    input::ScenarioKind,
};
use crate::{
    marshal::end_to_end::twins::{B, stack::TwinsMarshal},
    simplex::Simplex,
};
use commonware_codec::Encode as _;
use commonware_consensus::{
    Heightable as _,
    simplex::Floor,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digestible as _, Sha256};

/// A scripted prefix that drives the cluster to a source-defined marshal state.
pub(crate) trait Scenario {
    /// Drive the live prefix and return the verified handoff.
    async fn drive<P: Simplex, M: TwinsMarshal<P, App<P>>>(
        &self,
        harness: &mut FuzzScenarioStandardHarness<P, M>,
    ) -> ScenarioHandoff<P>
    where
        M::Wrapper: Clone;
}

/// Dispatch to the concrete scenario's live prefix.
pub(crate) async fn drive<P: Simplex, M: TwinsMarshal<P, App<P>>>(
    kind: ScenarioKind,
    harness: &mut FuzzScenarioStandardHarness<P, M>,
) -> ScenarioHandoff<P>
where
    M::Wrapper: Clone,
{
    match kind {
        ScenarioKind::MissingCandidate => {
            StandardCertifyMissingCandidateFetchesByRound
                .drive(harness)
                .await
        }
    }
}

fn round(view: u64) -> Round {
    Round::new(Epoch::zero(), View::new(view))
}

/// The first live view above `block`: the adversary attacks the next view and
/// height, extending the block.
fn attack_above<P: Simplex>(block: &B<P>) -> AttackAnchor {
    AttackAnchor {
        height: Height::new(block.height().get() + 1),
        view: View::new(block.context.round.view().get() + 1),
        digest: block.digest(),
    }
}

/// Source: consensus/src/marshal/standard/mod.rs::test_standard_certify_missing_candidate_fetches_by_round
///
/// Handoff: after `certify` of a locally missing candidate resolved to success
/// through the armed `(notarization, block)` resolver delivery, having issued
/// exactly one round-bound notarized fetch, registered a local wait, and
/// issued no targeted fetch.
///
/// Node mapping (the node-addressing divergence S6 permits): one permutation
/// applied uniformly to every role, source participant `i` -> {0: B, 1: C,
/// 2: D, 3: A}. The source's `me = participants[0]` therefore maps wholly to
/// [`Node::B`]: the marshal actor under test, its scheme provider, the
/// candidate block's leader, and the first quorum signer. B is always honest,
/// holds a marshal in both modes, and is the round-robin leader of view 1, so
/// the recovered proposal's leader matches the live elector. The source's
/// `schemes[0..QUORUM]` signers map to [`QUORUM_SIGNERS`] (B, C, D); source
/// participant 3, which the source never exercises, maps to [`Node::A`], the
/// byzantine slot in the adversarial mode.
///
/// Only the victim holds the candidate at handoff, as in the source (which
/// starts with no durable block anywhere). The other engines' replayed
/// certification finds the candidate missing and fetches it by round over the
/// live network from the victim, so the fuzzing phase drives forward from the
/// missing-candidate state itself rather than from locally re-certified
/// copies.
pub(crate) struct StandardCertifyMissingCandidateFetchesByRound;

impl Scenario for StandardCertifyMissingCandidateFetchesByRound {
    async fn drive<P: Simplex, M: TwinsMarshal<P, App<P>>>(
        &self,
        harness: &mut FuzzScenarioStandardHarness<P, M>,
    ) -> ScenarioHandoff<P>
    where
        M::Wrapper: Clone,
    {
        harness.begin("test_standard_certify_missing_candidate_fetches_by_round");
        // The missing candidate: a height-1 block at view 1 on genesis, led by
        // the source's `me` (Node::B under the participant permutation), built
        // as in the source.
        let genesis_digest = harness.genesis().digest();
        let round_one = round(1);
        let block_context = harness.context(round_one, Node::B, View::zero(), genesis_digest);
        let block = B::<P>::new::<Sha256>(block_context, genesis_digest, Height::new(1), 100);
        let digest = block.digest();
        let notarization =
            harness.make_notarization(round_one, View::zero(), digest, &QUORUM_SIGNERS);

        // Source order: the resolver response is armed before certify, so the
        // round-bound fetch resolves immediately.
        harness.respond_to_next_fetch(Node::B, (notarization.clone(), block.clone()).encode());
        let certify = harness.wrapper_certify(Node::B, round_one, digest).await;
        assert!(
            harness
                .await_wrapper(certify, "missing-candidate certify")
                .await,
            "fetched notarized candidate should certify"
        );
        assert!(
            harness.wait_for_delivery_response(Node::B).await,
            "notarized delivery should validate"
        );
        assert!(
            harness.buffer_subscription_count(Node::B) > 0,
            "unavailable candidate certification must register a local wait"
        );
        assert!(
            harness.targeted_is_empty(Node::B),
            "certification must not issue targeted fetches"
        );

        ScenarioHandoff {
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
            // The victim is the sole holder of the fetched candidate: every
            // other honest marshal must lack it, so replayed certification
            // finds it missing and fetches it over the live network.
            expected_nodes: vec![
                NodeExpectation::new(Node::A).lacks(digest),
                NodeExpectation::new(Node::B).holds(digest),
                NodeExpectation::new(Node::C).lacks(digest),
                NodeExpectation::new(Node::D).lacks(digest),
            ],
            expectation: Expectation::genesis_rooted(),
        }
    }
}
