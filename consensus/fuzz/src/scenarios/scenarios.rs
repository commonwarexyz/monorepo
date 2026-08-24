//! Faithful copies of standard-marshal test prefixes.
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
//!
//! [`StandardCertifyFirstBlockFetchesGenesisParent`] reproduces
//! `test_standard_certify_first_block_fetches_genesis_parent`
//! (consensus/src/marshal/standard/mod.rs:2341) through its handoff point: the
//! victim persists the height-1 candidate as verified, then the real wrapper
//! `verify` and `certify` both succeed against the genesis parent with no
//! fetch. The prefix fabricates no certificate and the source leaves nothing
//! to recover, so the engines start bare from the genesis floor and the first
//! attackable live view is view 1 over genesis.
//!
//! [`StandardVerifyHeightLieParentFetchIsRoundBound`] reproduces
//! `test_standard_verify_height_lie_parent_fetch_is_round_bound`
//! (consensus/src/marshal/standard/mod.rs:2747) through its handoff point:
//! the victim persists a height-lying child (height 3 at view 2 naming a
//! height-1 parent), the real wrapper `verify` of the child issues exactly
//! one round-bound notarized fetch for the parent round and no
//! height-derived fetch, and the parent then arrives as verified; the
//! non-contiguous ancestry is rejected through the resolved in-flight verify
//! (Inline) or at certify (Deferred), so no certification succeeds. The prefix
//! fabricates no certificate and the source leaves nothing to recover, so
//! the engines start bare from the genesis floor, the first attackable live
//! view is view 1 over genesis, and the round-bound parent fetch stays
//! outstanding into the fuzzing phase.
//!
//! [`StandardCertifyBumpsNotarizedFetchForPendingVerify`] reproduces
//! `test_standard_certify_bumps_notarized_fetch_for_pending_verify`
//! (consensus/src/marshal/standard/mod.rs:2571) through its handoff point:
//! the victim's `verify` of a locally missing candidate parks an in-progress
//! certification gate on a local-only block wait, and `certify` then takes
//! that gate and bumps a round-bound notarized fetch that resolves through
//! the armed `(notarization, block)` delivery, so both the pending verify and
//! the certify succeed with exactly one notarized fetch issued. The
//! fabricated view-1 notarization is seeded into every honest engine's voter
//! journal exactly as in [`StandardCertifyMissingCandidateFetchesByRound`],
//! so the same composition argument applies and the first attackable live
//! view is view 2 over the recovered source block.
//!
//! [`StandardVerifyMissingCandidateWaitsWithoutFetching`] reproduces
//! `test_standard_verify_missing_candidate_waits_without_fetching`
//! (consensus/src/marshal/standard/mod.rs:2413) through its handoff point:
//! the real wrapper `verify` of an unknown digest registers a local wait,
//! issues no fetch of any kind, and remains pending; the source then drops
//! the verify receiver, canceling the wait's consumer. Cancellation must not
//! convert the wait into a fetch or register a new wait (the marshal prunes
//! a canceled wait; it never falls back to fetching). The prefix fabricates
//! no certificate and the source leaves nothing to recover, so the engines
//! start bare from the genesis floor, the first attackable live view is
//! view 1 over genesis, and the handoff fetch multiset is explicitly empty
//! on every node.

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
use commonware_cryptography::{Digestible as _, Hasher as _, Sha256};
use commonware_utils::channel::oneshot::error::TryRecvError;

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
        ScenarioKind::StandardCertifyMissingCandidateFetchesByRound => {
            StandardCertifyMissingCandidateFetchesByRound
                .drive(harness)
                .await
        }
        ScenarioKind::StandardCertifyFirstBlockFetchesGenesisParent => {
            StandardCertifyFirstBlockFetchesGenesisParent
                .drive(harness)
                .await
        }
        ScenarioKind::StandardVerifyHeightLieParentFetchIsRoundBound => {
            StandardVerifyHeightLieParentFetchIsRoundBound
                .drive(harness)
                .await
        }
        ScenarioKind::StandardCertifyBumpsNotarizedFetchForPendingVerify => {
            StandardCertifyBumpsNotarizedFetchForPendingVerify
                .drive(harness)
                .await
        }
        ScenarioKind::StandardVerifyMissingCandidateWaitsWithoutFetching => {
            StandardVerifyMissingCandidateWaitsWithoutFetching
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

/// Source: consensus/src/marshal/standard/mod.rs::test_standard_certify_first_block_fetches_genesis_parent
///
/// Handoff: after `verified` persisted the height-1 candidate and the real
/// wrapper `verify` then `certify` both returned true against the genesis
/// parent, having issued no fetch of any kind and registered no local wait.
/// The source iterates both wrapper kinds in one test body; per R2 the
/// variant is fixed per fuzz target, so each target runs this prefix under
/// its own variant.
///
/// Node mapping (the node-addressing divergence S6 permits): the same uniform
/// permutation as [`StandardCertifyMissingCandidateFetchesByRound`], source
/// participant `i` -> {0: B, 1: C, 2: D, 3: A}. The source's
/// `me = participants[0]` maps wholly to [`Node::B`]: the marshal actor under
/// test, its scheme provider, and the candidate block's leader.
///
/// Composition soundness (I5): the prefix fabricates no certificate and the
/// source leaves nothing for an engine to recover, so the ledger and journal
/// are empty, the engines start bare from the genesis floor, and the attack
/// anchor is the first live view above it (view 1, height 1, over genesis).
/// The certified candidate is invisible to the engines: no certificate
/// references it, so nothing the live run notarizes, finalizes, or delivers
/// at view 1 can conflict with a prefix artifact. On the victim it remains a
/// same-round verified sibling of the live view-1 candidate, a state the
/// marshal tolerates by design (source
/// `test_standard_certify_persists_equivocated_block`).
pub(crate) struct StandardCertifyFirstBlockFetchesGenesisParent;

impl Scenario for StandardCertifyFirstBlockFetchesGenesisParent {
    async fn drive<P: Simplex, M: TwinsMarshal<P, App<P>>>(
        &self,
        harness: &mut FuzzScenarioStandardHarness<P, M>,
    ) -> ScenarioHandoff<P>
    where
        M::Wrapper: Clone,
    {
        harness.begin("test_standard_certify_first_block_fetches_genesis_parent");
        // The first block: a height-1 block at view 1 on genesis, led by the
        // source's `me` (Node::B under the participant permutation), built as
        // in the source.
        let genesis_digest = harness.genesis().digest();
        let round_one = round(1);
        let block_context = harness.context(round_one, Node::B, View::zero(), genesis_digest);
        let block =
            B::<P>::new::<Sha256>(block_context.clone(), genesis_digest, Height::new(1), 100);
        let digest = block.digest();
        harness.verified(Node::B, 1, &block).await;

        // The source sleeps 10ms between `verified` and `verify`; the
        // deterministic mailbox barrier is the harness equivalent (an S6
        // plumbing divergence).
        let _ = harness.barrier(Node::B).await;

        let verify = harness.wrapper_verify(Node::B, block_context, digest).await;
        assert!(
            harness.await_wrapper(verify, "first-block verify").await,
            "height-1 block should verify with genesis as parent"
        );
        let certify = harness.wrapper_certify(Node::B, round_one, digest).await;
        assert!(
            harness.await_wrapper(certify, "first-block certify").await,
            "height-1 block should certify with genesis as parent"
        );
        // S3 handoff checks: the locally present candidate and its genesis
        // parent resolve without a targeted fetch or a local wait (the empty
        // handoff multisets below cover the backfill fetches).
        assert!(
            harness.targeted_is_empty(Node::B),
            "genesis-parent certification must not issue targeted fetches"
        );
        assert_eq!(
            harness.buffer_subscription_count(Node::B),
            0,
            "genesis-parent certification must not register a local wait"
        );

        ScenarioHandoff {
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
            // Only the victim holds the certified candidate at handoff, as in
            // the source (a single validator with no peers holding anything).
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

/// Source: consensus/src/marshal/standard/mod.rs::test_standard_verify_height_lie_parent_fetch_is_round_bound
///
/// Handoff: after `verified` persisted the height-lying child (height 3 at
/// view 2, naming a height-1 parent at view 1), the real wrapper `verify` of
/// the child issued exactly one round-bound notarized fetch for the parent
/// round with no digest- or height-derived fetch, and `verified` then
/// delivered the parent. The non-contiguous ancestry is then rejected,
/// through the resolved in-flight verify (Inline) or at certify (Deferred),
/// so no certification succeeds: the victim holds both blocks as uncertified
/// candidates and the round-bound parent fetch remains outstanding into the
/// fuzzing phase. The source iterates both wrapper kinds in one test body;
/// per R2 the variant is fixed per fuzz target, so each target runs this
/// prefix under its own variant.
///
/// Node mapping (the node-addressing divergence S6 permits): the same uniform
/// permutation as [`StandardCertifyMissingCandidateFetchesByRound`], source
/// participant `i` -> {0: B, 1: C, 2: D, 3: A}. The source's
/// `me = participants[0]` maps wholly to [`Node::B`]: the marshal actor under
/// test, its scheme provider, and the leader of both blocks.
///
/// Harness divergences (S6 plumbing):
/// - The source's `wait_until` polls the recording resolver for the
///   round-bound parent fetch before releasing the parent. The harness
///   exposes no fetch accessor to prefixes, so the prefix barrier-polls the
///   victim's buffer-subscription count instead: the actor registers the
///   parent's local wait in the same mailbox-message processing step that
///   issues the round-bound fetch, so the observed wait orders the fetch
///   before the parent delivery. The fetch itself is asserted by the handoff
///   multiset, whose exactly-one `NotarizedRound` entry also covers the
///   source's negative assertions (no digest-keyed and no height-annotated
///   fetch).
/// - The source branches its verdict assertions on the wrapper kind, which
///   is fixed per fuzz target (R2) but not observable through the scenario
///   surface. The prefix therefore branches on the observed verify verdict:
///   an optimistic pass (the Deferred shape) replays the source's `certify`
///   and asserts it rejects the non-contiguous ancestry; a rejection (the
///   Inline shape) ends the prefix as the source does. Each variant's
///   operation sequence and handoff state are preserved; the per-variant
///   verdict values themselves are not asserted, since binding them to the
///   variant would require plumbing the marshal choice into scenarios.
///
/// Composition soundness (I5): the prefix fabricates no certificate and the
/// source leaves nothing for an engine to recover, so the ledger and journal
/// are empty, the engines start bare from the genesis floor, and the attack
/// anchor is the first live view above it (view 1, height 1, over genesis).
/// No certificate references either prefix block, so nothing the live run
/// notarizes, finalizes, or delivers can conflict with a prefix artifact.
/// Under the honest elector B leads view 1 and its propose finds the
/// verified parent: Deferred re-broadcasts it as its own proposal (the
/// embedded context equals the live view-1 context), so the parent becomes
/// the live height-1 block, while Inline skips the proposal and the view
/// nullifies by timeout. Both outcomes are conflict-free: the parent is
/// either the single view-1 proposal or absent from the live chain, never
/// in competition with one. The adversarial elector gives view 1 to the
/// byzantine node, so neither occurs there. The child is never proposed
/// (view 2's leader is C under both electors), so on the victim it remains
/// a same-round verified sibling of the live view-2 candidate, a state the
/// marshal tolerates by design (source
/// `test_standard_certify_persists_equivocated_block`), and the outstanding
/// round-bound fetch can only resolve to a valid round-1 notarization.
pub(crate) struct StandardVerifyHeightLieParentFetchIsRoundBound;

impl Scenario for StandardVerifyHeightLieParentFetchIsRoundBound {
    async fn drive<P: Simplex, M: TwinsMarshal<P, App<P>>>(
        &self,
        harness: &mut FuzzScenarioStandardHarness<P, M>,
    ) -> ScenarioHandoff<P>
    where
        M::Wrapper: Clone,
    {
        harness.begin("test_standard_verify_height_lie_parent_fetch_is_round_bound");
        // The honest parent: a height-1 block at view 1 on genesis, led by the
        // source's `me` (Node::B under the participant permutation), built as
        // in the source.
        let genesis_digest = harness.genesis().digest();
        let parent_round = round(1);
        let parent_context = harness.context(parent_round, Node::B, View::zero(), genesis_digest);
        let parent = B::<P>::new::<Sha256>(parent_context, genesis_digest, Height::new(1), 100);
        let parent_digest = parent.digest();

        // The height lie: a child at view 2 naming the height-1 parent but
        // claiming height 3, built as in the source.
        let child_round = round(2);
        let child_context = harness.context(child_round, Node::B, View::new(1), parent_digest);
        let child =
            B::<P>::new::<Sha256>(child_context.clone(), parent_digest, Height::new(3), 200);
        let child_digest = child.digest();
        harness.verified(Node::B, 2, &child).await;

        let verify = harness
            .wrapper_verify(Node::B, child_context, child_digest)
            .await;

        // Source order: the parent is released only after the round-bound
        // parent fetch is out. The source waits on the recorded fetch; the
        // harness equivalent waits on the victim's local parent wait, which
        // the actor registers in the same processing step that issues the
        // fetch (the handoff multiset asserts the fetch itself).
        let waits_before = harness.buffer_subscription_count(Node::B);
        let mut rounds_waited = 0;
        while harness.buffer_subscription_count(Node::B) == waits_before {
            rounds_waited += 1;
            assert!(
                rounds_waited <= 64,
                "verify never registered the parent wait that carries the round-bound fetch"
            );
            let _ = harness.barrier(Node::B).await;
        }

        harness.verified(Node::B, 1, &parent).await;
        // Source tail: Inline resolves the in-flight verify against the
        // delivered parent and rejects the non-contiguous ancestry; Deferred
        // passes verify optimistically and rejects at certify. The optimistic
        // pass selects the source's Deferred tail (see the S6 divergences
        // above).
        if harness.await_wrapper(verify, "height-lie verify").await {
            let certify = harness
                .wrapper_certify(Node::B, child_round, child_digest)
                .await;
            assert!(
                !harness.await_wrapper(certify, "height-lie certify").await,
                "certify must reject non-contiguous ancestry"
            );
        }

        ScenarioHandoff {
            engine_floor: Floor::Genesis(genesis_digest),
            engine_journal: Vec::new(),
            attack_anchor: attack_above::<P>(harness.genesis()),
            reference_chain: Vec::new(),
            // Exactly one round-bound notarized fetch for the parent round:
            // the source's positive wait and its negative assertions (no
            // digest-keyed and no height-annotated fetch) in one multiset.
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
            // Only the victim holds the two blocks at handoff, as in the
            // source (a single validator with no peers holding anything).
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
        }
    }
}

/// Source: consensus/src/marshal/standard/mod.rs::test_standard_certify_bumps_notarized_fetch_for_pending_verify
///
/// Handoff: after `verify` of a locally missing candidate registered an
/// in-progress certification gate parked on a local-only block wait, and
/// `certify` then took that gate and bumped a round-bound notarized fetch,
/// resolved through the armed `(notarization, block)` delivery: both the
/// pending verify and the certify returned true. The source asserts that at
/// least one round-bound notarized fetch was issued; the handoff multiset
/// strengthens this to exactly one, so a second fetch for the round fails
/// handoff, not just a missing one.
///
/// Node mapping (the node-addressing divergence S6 permits): the same uniform
/// permutation as [`StandardCertifyMissingCandidateFetchesByRound`], source
/// participant `i` -> {0: B, 1: C, 2: D, 3: A}. The source's
/// `me = participants[0]` maps wholly to [`Node::B`]: the marshal actor under
/// test, its scheme provider, the candidate block's leader, and the first
/// quorum signer. The source iterates both wrapper kinds in one test body;
/// per R2 the variant is fixed per fuzz target, so each target runs this
/// prefix under its own variant.
///
/// Harness divergence (S6 plumbing): the source awaits each wrapper verdict
/// in a `select!` against a 5-second sleep that panics on timeout; the
/// harness `await_wrapper` is that same race behind one name.
///
/// Composition soundness (I5): identical to
/// [`StandardCertifyMissingCandidateFetchesByRound`]. The fabricated view-1
/// notarization is seeded as an `Artifact::Notarization` into every honest
/// engine's voter journal with the engine floor kept at genesis, so startup
/// replay installs the recovered proposal and no engine can produce a
/// competing view-1 certificate. Only the victim holds the fetched candidate
/// at handoff, and the first attackable live view is view 2 over it.
pub(crate) struct StandardCertifyBumpsNotarizedFetchForPendingVerify;

impl Scenario for StandardCertifyBumpsNotarizedFetchForPendingVerify {
    async fn drive<P: Simplex, M: TwinsMarshal<P, App<P>>>(
        &self,
        harness: &mut FuzzScenarioStandardHarness<P, M>,
    ) -> ScenarioHandoff<P>
    where
        M::Wrapper: Clone,
    {
        harness.begin("test_standard_certify_bumps_notarized_fetch_for_pending_verify");
        // The missing candidate: a height-1 block at view 1 on genesis, led by
        // the source's `me` (Node::B under the participant permutation), built
        // as in the source.
        let genesis_digest = harness.genesis().digest();
        let round_one = round(1);
        let block_context = harness.context(round_one, Node::B, View::zero(), genesis_digest);
        let block =
            B::<P>::new::<Sha256>(block_context.clone(), genesis_digest, Height::new(1), 100);
        let digest = block.digest();

        // `verify` registers a pending certification gate whose block wait is
        // local-only, so it stays parked until something delivers the block.
        let verify = harness.wrapper_verify(Node::B, block_context, digest).await;

        // Stage the notarized response so the bump's fetch can resolve.
        let notarization =
            harness.make_notarization(round_one, View::zero(), digest, &QUORUM_SIGNERS);
        harness.respond_to_next_fetch(Node::B, (notarization.clone(), block.clone()).encode());

        // `certify` takes the in-progress gate and bumps a round-bound
        // notarized fetch; the armed delivery stores the block and wakes the
        // pending verify, which resolves the gate certify awaits.
        let certify = harness.wrapper_certify(Node::B, round_one, digest).await;

        assert!(
            harness.await_wrapper(verify, "bumped-fetch verify").await,
            "verify should accept the fetched block"
        );
        assert!(
            harness.await_wrapper(certify, "bumped-fetch certify").await,
            "certify should succeed via the shared gate"
        );

        ScenarioHandoff {
            engine_floor: Floor::Genesis(genesis_digest),
            engine_journal: vec![notarization],
            attack_anchor: attack_above::<P>(&block),
            reference_chain: vec![block],
            // Exactly one notarized fetch for the candidate's round: the
            // multiset's one-to-one correspondence fails a second fetch for
            // the round, not just a missing one.
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
            // The victim is the sole holder of the fetched candidate at
            // handoff, as in the source (a single validator with no peers
            // holding anything).
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

/// Source: consensus/src/marshal/standard/mod.rs::test_standard_verify_missing_candidate_waits_without_fetching
///
/// Handoff: after the real wrapper `verify` of an unknown digest (naming no
/// block anywhere) registered a local wait, issued no fetch of any kind, and
/// remained pending, the source dropped the verify receiver. Canceling the
/// wait's consumer must not convert the local wait into a fetch or register
/// a new wait: the marshal prunes a canceled wait (the wrapper task exits on
/// the closed receiver and the actor retains only open subscribers) rather
/// than escalating it, so the handoff fetch multiset is explicitly empty on
/// every node. The source iterates both wrapper kinds in one test body; per
/// R2 the variant is fixed per fuzz target, so each target runs this prefix
/// under its own variant.
///
/// Node mapping (the node-addressing divergence S6 permits): the same uniform
/// permutation as [`StandardCertifyMissingCandidateFetchesByRound`], source
/// participant `i` -> {0: B, 1: C, 2: D, 3: A}. The source's
/// `me = participants[0]` maps wholly to [`Node::B`]: the marshal actor under
/// test, its scheme provider, and the leader named by the verify context.
///
/// Harness divergences (S6 plumbing):
/// - The source sleeps 50ms before observing the local wait; the harness
///   equivalent barrier-polls the victim's buffer-subscription count, as in
///   [`StandardVerifyHeightLieParentFetchIsRoundBound`].
/// - The source sleeps 10ms after dropping the receiver before re-checking
///   the resolver; the harness equivalent is one mailbox barrier.
/// - The source's `resolver.fetches().is_empty()` assertions (both before
///   and after the drop) are carried by the handoff multiset, whose empty
///   lists require that no fetch was issued at all.
/// - The wait counter (like the source's `RecordingBuffer` count) counts
///   registrations and cannot observe the prune, so the post-drop check is
///   that no new wait registered, alongside the multiset's no-fetch lists.
///
/// Composition soundness (I5): the prefix fabricates no certificate and the
/// source leaves nothing for an engine to recover, so the ledger and journal
/// are empty, the engines start bare from the genesis floor, and the attack
/// anchor is the first live view above it (view 1, height 1, over genesis).
/// The canceled state is invisible to the engines: the unknown digest is the
/// hash of a literal, not of any block encoding, the marshal prunes the
/// canceled wait, and any certification gate the pending verify parked is
/// keyed by (round, digest), so no live `certify` at view 1 can take it.
/// Nothing the fuzzing phase produces can conflict with prefix state.
pub(crate) struct StandardVerifyMissingCandidateWaitsWithoutFetching;

impl Scenario for StandardVerifyMissingCandidateWaitsWithoutFetching {
    async fn drive<P: Simplex, M: TwinsMarshal<P, App<P>>>(
        &self,
        harness: &mut FuzzScenarioStandardHarness<P, M>,
    ) -> ScenarioHandoff<P>
    where
        M::Wrapper: Clone,
    {
        harness.begin("test_standard_verify_missing_candidate_waits_without_fetching");
        // The unknown candidate: a digest that names no block, in a view-1
        // context on genesis led by the source's `me` (Node::B under the
        // participant permutation), built as in the source.
        let genesis_digest = harness.genesis().digest();
        let round_one = round(1);
        let consensus_context = harness.context(round_one, Node::B, View::zero(), genesis_digest);
        let missing = Sha256::hash(&[b"missing candidate"]);

        // Source order: `verify` first, then the local wait is observed. The
        // wait count is captured before `verify` so the barrier-poll below
        // cannot race the wrapper's registration.
        let waits_before = harness.buffer_subscription_count(Node::B);
        let mut verify = harness
            .wrapper_verify(Node::B, consensus_context, missing)
            .await;
        let mut rounds_waited = 0;
        while harness.buffer_subscription_count(Node::B) == waits_before {
            rounds_waited += 1;
            assert!(
                rounds_waited <= 64,
                "unavailable candidate verification never registered a local wait"
            );
            let _ = harness.barrier(Node::B).await;
        }
        assert!(
            harness.targeted_is_empty(Node::B),
            "unavailable candidate verification must not issue targeted fetches"
        );
        assert!(
            matches!(verify.try_recv(), Err(TryRecvError::Empty)),
            "unavailable candidate verification must remain pending"
        );

        // The source drops the pending verify receiver: cancellation must
        // not convert the local wait into a fetch or register a new wait
        // (the counter counts registrations, so equality rules out a
        // cancel-triggered re-subscription; the handoff multiset carries the
        // source's post-drop no-fetch assertion).
        let registered_waits = harness.buffer_subscription_count(Node::B);
        drop(verify);
        let _ = harness.barrier(Node::B).await;
        assert_eq!(
            harness.buffer_subscription_count(Node::B),
            registered_waits,
            "canceling a missing candidate wait must not register a new wait"
        );
        assert!(
            harness.targeted_is_empty(Node::B),
            "canceling a missing candidate wait must not issue targeted fetches"
        );

        ScenarioHandoff {
            engine_floor: Floor::Genesis(genesis_digest),
            engine_journal: Vec::new(),
            attack_anchor: attack_above::<P>(harness.genesis()),
            reference_chain: Vec::new(),
            // Explicitly empty multisets: the defining state is that no fetch
            // of any kind was issued, before or after the receiver drop.
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
            // The unknown digest names no block: every node lacks it, as in
            // the source (which stores nothing anywhere).
            expected_nodes: vec![
                NodeExpectation::new(Node::A).lacks(missing),
                NodeExpectation::new(Node::B).lacks(missing),
                NodeExpectation::new(Node::C).lacks(missing),
                NodeExpectation::new(Node::D).lacks(missing),
            ],
            expectation: Expectation::genesis_rooted(),
        }
    }
}
