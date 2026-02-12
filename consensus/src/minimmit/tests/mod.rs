//! Test harness and scenarios for the Minimmit state machine.

use crate::{
    elector::{Config as ElectorConfig, RoundRobin, RoundRobinElector},
    minimmit::{
        scheme::ed25519,
        state::{Action, State},
        types::{
            Certificate, Finalization, MNotarization, Notarize, Nullification, Nullify, Proposal,
        },
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    certificate::{mocks::Fixture, Scheme as CertificateScheme},
    sha256::Digest as Sha256Digest,
    Sha256,
};
use commonware_parallel::Sequential;
use commonware_utils::{test_rng, Participant};
use rand::rngs::StdRng;
use std::collections::{BTreeMap, VecDeque};

const NAMESPACE: &[u8] = b"minimmit_tests";
const GENESIS: Sha256Digest = Sha256Digest([0u8; 32]);

type Digest = Sha256Digest;
type Scheme = ed25519::Scheme;

type ActionQueue = VecDeque<Action<Scheme, Digest>>;

struct Harness {
    state: State<Scheme, Digest, RoundRobinElector<Scheme>>,
    schemes: Vec<Scheme>,
    verifier: Scheme,
    actions: ActionQueue,
    proposals: BTreeMap<View, Proposal<Digest>>,
    rng: StdRng,
}

impl Harness {
    fn new(n: u32) -> Self {
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, NAMESPACE, n);
        let elector = RoundRobin::<Sha256>::default().build(schemes[0].participants());
        let state = State::new(
            Epoch::new(1),
            schemes[0].clone(),
            elector,
            Digest::from([0u8; 32]),
        );
        Self {
            state,
            schemes,
            verifier,
            actions: VecDeque::new(),
            proposals: BTreeMap::new(),
            rng,
        }
    }

    fn view(&self) -> View {
        self.state.view()
    }

    fn next_actions(&mut self, actions: Vec<Action<Scheme, Digest>>) {
        self.actions.extend(actions);
    }

    fn drain_actions(&mut self) -> Vec<Action<Scheme, Digest>> {
        self.actions.drain(..).collect()
    }

    fn handle_timeout(&mut self) {
        let result = self.state.handle_timeout();
        let mut actions = Vec::new();
        if let Some(nullify) = result.nullify {
            actions.push(Action::BroadcastNullify(nullify));
        }
        if let Some(cert) = result.entry_certificate {
            actions.push(Action::BroadcastCertificate(cert));
        }
        // Track retry state if needed for tests
        let _ = result.is_retry;
        self.next_actions(actions);
    }

    fn receive_proposal(&mut self, proposal: Proposal<Digest>) {
        let view = proposal.round.view();
        self.proposals.insert(view, proposal.clone());
        // Pass the correct leader as sender
        let sender = self.state.leader(view, None);
        let actions = self.state.receive_proposal(sender, proposal);
        self.next_actions(actions);
    }

    fn verify_proposal(&mut self, view: View, valid: bool) {
        let proposal = self.proposals.get(&view).expect("proposal missing").clone();
        let actions = self.state.proposal_verified(proposal, valid);
        self.next_actions(actions);
    }

    fn deliver_notarizes(&mut self, view: View, payload: Digest, from: &[Participant]) {
        let proposal = self.proposal(view, payload);
        let schemes: Vec<_> = from
            .iter()
            .map(|participant| self.schemes[usize::from(*participant)].clone())
            .collect();
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
            .collect();
        for vote in votes {
            let actions = self
                .state
                .receive_notarize(&mut self.rng, vote, &Sequential);
            self.next_actions(actions);
        }
    }

    fn deliver_nullifies(&mut self, view: View, from: &[Participant]) {
        for participant in from {
            let scheme = &self.schemes[usize::from(*participant)];
            let vote =
                Nullify::sign::<Digest>(scheme, Round::new(Epoch::new(1), view)).expect("nullify");
            let actions = self.state.receive_nullify(&mut self.rng, vote, &Sequential);
            self.next_actions(actions);
        }
    }

    fn deliver_m_notarization(&mut self, view: View, payload: Digest, from: &[Participant]) {
        let proposal = self.proposal(view, payload);
        let votes: Vec<_> = from
            .iter()
            .map(|participant| {
                Notarize::sign(&self.schemes[usize::from(*participant)], proposal.clone())
                    .expect("notarize")
            })
            .collect();
        let m_notarization =
            MNotarization::from_notarizes(&self.verifier, votes.iter(), &Sequential)
                .expect("m-notarization");
        let actions = self
            .state
            .receive_certificate(Certificate::MNotarization(m_notarization));
        self.next_actions(actions);
    }

    fn deliver_finalization(&mut self, view: View, payload: Digest, from: &[Participant]) {
        let proposal = self.proposal(view, payload);
        let votes: Vec<_> = from
            .iter()
            .map(|participant| {
                Notarize::sign(&self.schemes[usize::from(*participant)], proposal.clone())
                    .expect("notarize")
            })
            .collect();
        let finalization = Finalization::from_notarizes(&self.verifier, votes.iter(), &Sequential)
            .expect("finalization");
        let actions = self
            .state
            .receive_certificate(Certificate::Finalization(finalization));
        self.next_actions(actions);
    }

    fn deliver_nullification(&mut self, view: View, from: &[Participant]) {
        let votes: Vec<_> = from
            .iter()
            .map(|participant| {
                Nullify::sign::<Digest>(
                    &self.schemes[usize::from(*participant)],
                    Round::new(Epoch::new(1), view),
                )
                .expect("nullify")
            })
            .collect();
        let nullification =
            Nullification::from_nullifies(&self.verifier, votes.iter(), &Sequential)
                .expect("nullification");
        let actions = self
            .state
            .receive_certificate(Certificate::Nullification(nullification));
        self.next_actions(actions);
    }

    fn proposal(&mut self, view: View, payload: Digest) -> Proposal<Digest> {
        if let Some(existing) = self.proposals.get(&view) {
            return existing.clone();
        }
        let parent = self.parent_view(view);
        let parent_payload = self.parent_payload(parent);
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), view),
            parent,
            parent_payload,
            payload,
        );
        self.proposals.insert(view, proposal.clone());
        proposal
    }

    fn parent_view(&self, view: View) -> View {
        if view == View::new(1) {
            View::zero()
        } else {
            view.previous().unwrap_or(View::zero())
        }
    }

    fn parent_payload(&self, parent_view: View) -> Digest {
        if parent_view == View::zero() {
            // Genesis payload
            Digest::from([0u8; 32])
        } else if let Some(parent_proposal) = self.proposals.get(&parent_view) {
            parent_proposal.payload
        } else {
            // Fallback: deterministic payload based on parent view
            Digest::from([parent_view.get() as u8; 32])
        }
    }
}

#[test]
fn harness_happy_path_finalizes() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);
    let proposal = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload,
    );
    harness.receive_proposal(proposal);
    harness.verify_proposal(view, true);

    harness.deliver_notarizes(
        view,
        payload,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    let actions = harness.drain_actions();
    assert!(actions
        .iter()
        .any(|action| matches!(action, Action::Advanced(v) if *v == View::new(2))));
}

#[test]
fn harness_view_skipping_on_future_cert() {
    let mut harness = Harness::new(6);
    let view = View::new(3);
    let payload = Digest::from([22u8; 32]);
    harness.deliver_m_notarization(
        view,
        payload,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    let actions = harness.drain_actions();
    assert!(actions
        .iter()
        .any(|action| matches!(action, Action::Advanced(v) if *v == View::new(4))));
}

#[test]
fn harness_finalization_blocks_nullification() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([33u8; 32]);
    harness.deliver_finalization(
        view,
        payload,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
            Participant::new(4),
        ],
    );
    let actions = harness.drain_actions();
    assert!(actions
        .iter()
        .any(|action| matches!(action, Action::Finalized(_))));

    harness.deliver_nullification(
        view,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    assert!(harness.drain_actions().is_empty());
}

// =============================================================================
// Regression tests for bugs found in review
// =============================================================================

/// Regression test: Finalized views should ignore contradiction-based nullify.
///
/// Once a view is finalized, receiving conflicting votes for that view must not
/// trigger a new nullify broadcast.
#[test]
fn finalized_view_rejects_contradiction_nullify() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([0xFA; 32]);

    harness.deliver_finalization(
        view,
        payload,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
            Participant::new(4),
        ],
    );
    harness.drain_actions();

    let conflicting_payload = Digest::from([0xFB; 32]);
    let proposal = harness.proposal(view, conflicting_payload);

    let votes: Vec<_> = [1, 2, 3]
        .iter()
        .map(|&i| Notarize::sign(&harness.schemes[i], proposal.clone()).expect("sign"))
        .collect();

    let mut broadcasted = false;
    for vote in votes {
        let actions = harness
            .state
            .receive_notarize(&mut harness.rng, vote, &Sequential);
        if actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastNullify(_)))
        {
            broadcasted = true;
        }
    }

    assert!(
        !broadcasted,
        "finalized view should not emit contradiction nullify"
    );
}

// Regression tests for bugs found in review
// =============================================================================

/// Regression test: Invalid signatures on votes must be rejected.
///
/// This test creates a vote signed by participant 1 but claims to be from
/// participant 2 (by modifying the signer field). The state machine should
/// reject this vote because the signature won't verify.
///
/// To verify rejection, we:
/// 1. Deliver a forged vote (claiming to be participant 2)
/// 2. Deliver 2 legitimate votes from participants 0 and 1
/// 3. If forged vote was tracked: 3 votes = M-quorum = certificate
/// 4. If forged vote was rejected: 2 votes = no certificate
#[test]
fn invalid_signature_vote_rejected() {
    use commonware_cryptography::certificate::Attestation;

    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);
    let proposal = harness.proposal(view, payload);

    // Create a valid vote from participant 1
    let scheme_1 = &harness.schemes[1];
    let valid_vote = Notarize::sign(scheme_1, proposal.clone()).expect("sign");

    // Create a forged vote: sign with participant 1's key but claim to be participant 2
    let forged_vote = Notarize {
        proposal: proposal.clone(),
        attestation: Attestation {
            signer: Participant::new(2), // Lie about the signer
            signature: valid_vote.attestation.signature,
        },
    };

    // Deliver the forged vote - it should be rejected but currently isn't
    harness
        .state
        .receive_notarize(&mut harness.rng, forged_vote, &Sequential);

    // Now deliver 2 legitimate votes from participants 0 and 1
    let vote_0 = Notarize::sign(&harness.schemes[0], proposal.clone()).expect("sign");
    let vote_1 = Notarize::sign(&harness.schemes[1], proposal).expect("sign");

    harness
        .state
        .receive_notarize(&mut harness.rng, vote_0, &Sequential);
    let actions = harness
        .state
        .receive_notarize(&mut harness.rng, vote_1, &Sequential);

    // With n=6, f=1, M-quorum = 2f+1 = 3
    // If forged vote was tracked: we'd have 3 votes (forged + 0 + 1) = certificate
    // If forged vote was rejected: we'd have 2 votes (0 + 1) = no certificate
    //
    // After the fix, this should NOT produce a certificate because only 2 valid votes exist
    let has_certificate = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastCertificate(_)));

    assert!(
        !has_certificate,
        "Forged vote should have been rejected, but it was counted toward quorum. Got: {:?}",
        actions
    );
}

/// Regression test: Proposals from non-leaders must be rejected.
///
/// Epoch 1, View 1's leader is participant 2: (epoch + view) % n = (1 + 1) % 6 = 2.
/// A proposal from participant 0 for view 1 should be rejected.
#[test]
fn non_leader_proposal_rejected() {
    let mut harness = Harness::new(6);
    let view = harness.view(); // View 1

    // Epoch 1, View 1's leader is Participant 2: (1 + 1) % 6 = 2
    // We'll send a proposal claiming to be from participant 0 (non-leader)
    let non_leader = Participant::new(0);

    let payload = Digest::from([99u8; 32]);
    let proposal = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload,
    );

    // Receive the proposal from a non-leader - it should be rejected
    let actions = harness.state.receive_proposal(non_leader, proposal);

    // After the fix, this should NOT emit a VerifyProposal action because
    // the proposal doesn't come from the leader
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::VerifyProposal(_))),
        "Proposal from non-leader should be rejected, but got: {:?}",
        actions
    );
}

/// Regression test: Section 6.1 - Vote on past-view M-notarization.
///
/// Per Section 6.1 of the paper:
/// > If v'' < v and a correct processor p_i in view v receives an
/// > M-notarisation for some view v'' block b, and if p_i has not voted
/// > for any view v'' block and has not sent a nullify(v'') message,
/// > then p_i must vote for b.
///
/// This ensures correct leaders can finalize after async periods.
#[test]
fn vote_on_past_view_m_notarization() {
    let mut harness = Harness::new(6);

    // Advance to view 5 by delivering nullifications for views 1-4
    for v in 1..=4 {
        harness.deliver_nullification(
            View::new(v),
            &[
                Participant::new(0),
                Participant::new(1),
                Participant::new(2),
            ],
        );
    }
    harness.drain_actions();
    assert_eq!(harness.view(), View::new(5), "Should be at view 5");

    // Now receive an M-notarization for view 2 (a past view we never voted in)
    // We should emit a notarize vote for this block.
    //
    // IMPORTANT: The proposal must have VALID ancestry. Since view 1 was nullified
    // (not notarized), the proposal at view 2 must claim parent = genesis (view 0).
    let past_view = View::new(2);
    let payload = Digest::from([22u8; 32]);

    // Create a proposal with valid ancestry: parent = genesis
    let proposal = Proposal::new(
        Round::new(Epoch::new(1), past_view),
        View::zero(), // Parent is genesis since view 1 was nullified
        GENESIS,      // Parent payload is genesis
        payload,
    );
    harness.proposals.insert(past_view, proposal.clone());

    // Create M-notarization for this proposal
    let votes: Vec<_> = [
        Participant::new(0),
        Participant::new(1),
        Participant::new(2),
    ]
    .iter()
    .map(|participant| {
        Notarize::sign(
            &harness.schemes[usize::from(*participant)],
            proposal.clone(),
        )
        .expect("notarize")
    })
    .collect();
    let m_notarization =
        MNotarization::from_notarizes(&harness.verifier, votes.iter(), &Sequential)
            .expect("m-notarization");
    let actions = harness
        .state
        .receive_certificate(Certificate::MNotarization(m_notarization));
    harness.next_actions(actions);

    let actions = harness.drain_actions();

    // We should see a BroadcastNotarize for the past view's proposal
    let has_notarize_for_past_view = actions.iter().any(|a| {
        if let Action::BroadcastNotarize(vote) = a {
            vote.proposal.round.view() == past_view
        } else {
            false
        }
    });

    assert!(
        has_notarize_for_past_view,
        "Should vote on past-view M-notarization per Section 6.1, but got: {:?}",
        actions
    );
}

/// Regression test: past-view M-notarizations should not trigger nullify.
#[test]
fn past_view_m_notarization_does_not_nullify() {
    let mut harness = Harness::new(6);
    let view = harness.view();

    // Vote for proposal A in the current view.
    let payload_a = Digest::from([0xAA; 32]);
    let proposal_a = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload_a,
    );
    harness.receive_proposal(proposal_a);
    harness.verify_proposal(view, true);
    harness.drain_actions();

    // Advance to the next view via an M-notarization for proposal A.
    harness.deliver_m_notarization(
        view,
        payload_a,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    harness.drain_actions();
    assert_eq!(harness.view(), view.next());

    // Deliver a conflicting M-notarization for the past view.
    let payload_b = Digest::from([0xBB; 32]);
    harness.deliver_m_notarization(
        view,
        payload_b,
        &[
            Participant::new(3),
            Participant::new(4),
            Participant::new(5),
        ],
    );
    let actions = harness.drain_actions();

    let nullified_past_view = actions.iter().any(|action| match action {
        Action::BroadcastNullify(nullify) => nullify.round.view() == view,
        _ => false,
    });
    assert!(
        !nullified_past_view,
        "Should not nullify a past view when receiving a conflicting M-notarization"
    );
}

// =============================================================================
// Core Axiom Tests (Lemmas from the paper)
// =============================================================================

/// Lemma 4.1: One vote per view.
///
/// Correct processors vote for at most one block in each view. After voting
/// for a block, the processor must not vote for any other block in the same view.
#[test]
fn one_vote_per_view_lemma_4_1() {
    let mut harness = Harness::new(6);
    let view = harness.view();

    // First proposal - should trigger a vote
    let payload1 = Digest::from([1u8; 32]);
    let proposal1 = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload1,
    );
    harness.receive_proposal(proposal1);
    harness.verify_proposal(view, true);

    let actions = harness.drain_actions();
    let voted = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastNotarize(_)));
    assert!(voted, "Should vote for first proposal");

    // Second proposal with different payload - should NOT trigger a vote
    let payload2 = Digest::from([2u8; 32]);
    let proposal2 = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload2,
    );

    // Manually insert and verify the second proposal
    harness.proposals.insert(view, proposal2.clone());
    let leader = harness.state.leader(view, None);
    harness
        .state
        .receive_proposal(leader, proposal2.clone())
        .into_iter()
        .for_each(|a| harness.actions.push_back(a));
    harness
        .state
        .proposal_verified(proposal2, true)
        .into_iter()
        .for_each(|a| harness.actions.push_back(a));

    let actions = harness.drain_actions();
    let voted_again = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastNotarize(_)));
    assert!(
        !voted_again,
        "Should NOT vote for second proposal in same view (Lemma 4.1)"
    );
}

/// Lemma 4.2 (X1): If a block receives an L-notarization, no other block
/// for the same view can receive an M-notarization.
///
/// This test verifies that once we've seen enough votes for finalization,
/// no other block can accumulate an M-quorum.
#[test]
fn x1_l_notarization_blocks_other_m_notarizations() {
    let mut harness = Harness::new(6);
    let view = harness.view();

    // Create block A and get it finalized (L-notarization = n-f = 5 votes)
    let payload_a = Digest::from([0xAA; 32]);
    harness.deliver_finalization(
        view,
        payload_a,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
            Participant::new(4),
        ],
    );
    let actions = harness.drain_actions();
    assert!(
        actions.iter().any(|a| matches!(a, Action::Finalized(_))),
        "Block A should be finalized"
    );

    // Now try to deliver an M-notarization for a different block B
    // This represents a Byzantine scenario that should be impossible
    // if correct processors follow the protocol (they voted for A, not B)
    let payload_b = Digest::from([0xBB; 32]);

    // Since L-quorum (5) intersects with any M-quorum (3) by at least f+1 = 2 correct nodes,
    // and correct nodes only vote once, it's impossible to get 3 votes for B
    // when 5 already voted for A. The protocol should handle receiving such
    // a certificate by ignoring it (it's for a finalized view).

    harness.deliver_m_notarization(
        view,
        payload_b,
        &[
            // These would need to be different participants, but even if Byzantine
            // nodes forge votes, the view is already finalized
            Participant::new(3),
            Participant::new(4),
            Participant::new(5),
        ],
    );

    // The M-notarization for B should not cause any state change since
    // view 1 is already finalized
    let actions = harness.drain_actions();
    let advanced_again = actions.iter().any(|a| matches!(a, Action::Advanced(_)));
    assert!(
        !advanced_again,
        "Should not process M-notarization for finalized view"
    );
}

/// Lemma 4.3 (X2): If a block receives an L-notarization for view v,
/// then view v does not receive a nullification.
///
/// This is tested by `harness_finalization_blocks_nullification` above,
/// but we add another test to verify the vote-level property.
#[test]
fn x2_finalization_prevents_nullification_votes() {
    let mut harness = Harness::new(6);
    let view = harness.view();

    // Finalize a block
    let payload = Digest::from([0xFF; 32]);
    harness.deliver_finalization(
        view,
        payload,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
            Participant::new(4),
        ],
    );
    harness.drain_actions();

    // Now deliver individual nullify votes for the finalized view
    // These should not cause any certificate to be formed
    harness.deliver_nullifies(
        view,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );

    let actions = harness.drain_actions();

    // No nullification certificate should be broadcast
    let has_nullification_cert = actions.iter().any(|a| {
        matches!(
            a,
            Action::BroadcastCertificate(Certificate::Nullification(_))
        )
    });
    assert!(
        !has_nullification_cert,
        "Should not form nullification certificate for finalized view (X2)"
    );
}

/// Test: No vote after nullify.
///
/// Once a processor has sent a nullify(v) message, it must not vote
/// for any block in view v.
#[test]
fn no_vote_after_nullify() {
    let mut harness = Harness::new(6);
    let view = harness.view();

    // Trigger timeout to send nullify
    harness.handle_timeout();
    let actions = harness.drain_actions();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastNullify(_))),
        "Should broadcast nullify on timeout"
    );

    // Now try to receive and verify a proposal - should NOT vote
    let payload = Digest::from([1u8; 32]);
    let proposal = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload,
    );
    harness.receive_proposal(proposal);
    harness.verify_proposal(view, true);

    let actions = harness.drain_actions();
    let voted = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastNotarize(_)));
    assert!(!voted, "Should NOT vote after sending nullify in same view");
}

/// Test: Nullify after vote only via condition (b).
///
/// A processor that has voted in view v can only send nullify(v) if it
/// receives 2f+1 messages that are either nullify(v) or votes for a
/// different block than what it voted for.
#[test]
fn nullify_after_vote_only_via_condition_b() {
    let mut harness = Harness::new(6);
    let view = harness.view();

    // Vote for block A
    let payload_a = Digest::from([0xAA; 32]);
    let proposal_a = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload_a,
    );
    harness.receive_proposal(proposal_a);
    harness.verify_proposal(view, true);
    harness.drain_actions();

    // Timeout should NOT trigger nullify since we already voted
    harness.handle_timeout();
    let actions = harness.drain_actions();
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastNullify(_))),
        "Should NOT nullify via timeout after voting"
    );

    // Now deliver 3 votes (M-quorum) for a DIFFERENT block B
    // This triggers condition (b): we see proof that our block won't get L-notarization
    let payload_b = Digest::from([0xBB; 32]);
    let proposal_b = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload_b,
    );
    harness.proposals.insert(view, proposal_b.clone());

    let votes_b: Vec<_> = [1, 2, 3]
        .iter()
        .map(|&i| Notarize::sign(&harness.schemes[i], proposal_b.clone()).expect("sign"))
        .collect();

    let mut saw_nullify = false;
    for vote in votes_b {
        let actions = harness
            .state
            .receive_notarize(&mut harness.rng, vote, &Sequential);
        if actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastNullify(_)))
        {
            saw_nullify = true;
        }
    }

    assert!(
        saw_nullify,
        "Should nullify via condition (b) after seeing M-quorum for different block"
    );
}

/// Regression test: Condition (b) should trigger even if votes are split.
///
/// This simulates an equivocation where no single proposal reaches M-quorum,
/// but combined conflicting votes + nullify evidence reaches M.
#[test]
fn nullify_on_split_votes_condition_b() {
    let mut harness = Harness::new(6);
    let view = harness.view();

    // Vote for block A
    let payload_a = Digest::from([0xAC; 32]);
    let proposal_a = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload_a,
    );
    harness.receive_proposal(proposal_a);
    harness.verify_proposal(view, true);
    harness.drain_actions();

    let payload_b = Digest::from([0xBC; 32]);
    let proposal_b = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload_b,
    );
    harness.proposals.insert(view, proposal_b.clone());

    let notarize_b1 = Notarize::sign(&harness.schemes[1], proposal_b.clone()).expect("sign");
    let notarize_b2 = Notarize::sign(&harness.schemes[2], proposal_b).expect("sign");
    let nullify_3 = Nullify::sign::<Digest>(&harness.schemes[3], Round::new(Epoch::new(1), view))
        .expect("nullify");

    harness
        .state
        .receive_notarize(&mut harness.rng, notarize_b1, &Sequential);
    harness
        .state
        .receive_nullify(&mut harness.rng, nullify_3, &Sequential);
    let actions = harness
        .state
        .receive_notarize(&mut harness.rng, notarize_b2, &Sequential);

    let saw_nullify = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastNullify(_)));

    assert!(
        saw_nullify,
        "Split votes should trigger nullify via condition (b)"
    );
}

// =============================================================================
// Proposal Validity Tests
// =============================================================================

/// Test: Valid proposal requires parent M-notarization.
///
/// A proposal for view v with parent view v' is only valid if we have
/// an M-notarization for the parent block.
#[test]
fn proposal_requires_parent_m_notarization() {
    let mut harness = Harness::new(6);

    // Advance to view 2 via nullification
    harness.deliver_nullification(
        View::new(1),
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    harness.drain_actions();
    assert_eq!(harness.view(), View::new(2));

    // Try to vote for a view 2 proposal that claims a non-genesis parent
    // WITHOUT having the M-notarization for that parent
    let payload = Digest::from([1u8; 32]);
    let fake_parent_view = View::new(1);
    // Claim a parent_payload for view 1 that we don't have notarized
    let fake_parent_payload = Digest::from([99u8; 32]);
    let proposal = Proposal::new(
        Round::new(Epoch::new(1), View::new(2)),
        fake_parent_view,
        fake_parent_payload,
        payload,
    );

    let leader = harness.state.leader(View::new(2), None);
    harness
        .state
        .receive_proposal(leader, proposal.clone())
        .into_iter()
        .for_each(|a| harness.actions.push_back(a));
    harness
        .state
        .proposal_verified(proposal, true)
        .into_iter()
        .for_each(|a| harness.actions.push_back(a));

    let actions = harness.drain_actions();
    let voted = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastNotarize(_)));

    // Should NOT vote because we don't have M-notarization for the parent
    // (view 1 was nullified, not notarized)
    assert!(
        !voted,
        "Should NOT vote for proposal with unnotarized parent"
    );
}

/// Test: Valid proposal requires nullifications for intervening views.
///
/// A proposal for view v with parent view v' requires nullifications for
/// all views in the open interval (v', v).
#[test]
fn proposal_requires_intervening_nullifications() {
    let mut harness = Harness::new(6);

    // Get M-notarization for view 1
    let payload_v1 = Digest::from([1u8; 32]);
    harness.deliver_m_notarization(
        View::new(1),
        payload_v1,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    harness.drain_actions();

    // Skip to view 4 via future nullification (simulating async period)
    harness.deliver_nullification(
        View::new(3),
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    harness.drain_actions();
    assert_eq!(harness.view(), View::new(4));

    // Try to propose in view 4 with parent view 1
    // This requires nullifications for views 2 and 3
    // We have nullification for view 3 but NOT view 2
    let payload = Digest::from([4u8; 32]);
    let proposal = Proposal::new(
        Round::new(Epoch::new(1), View::new(4)),
        View::new(1), // Parent view
        payload_v1,   // Parent payload from view 1
        payload,
    );

    let leader = harness.state.leader(View::new(4), None);
    harness
        .state
        .receive_proposal(leader, proposal.clone())
        .into_iter()
        .for_each(|a| harness.actions.push_back(a));
    harness
        .state
        .proposal_verified(proposal, true)
        .into_iter()
        .for_each(|a| harness.actions.push_back(a));

    let actions = harness.drain_actions();
    let voted = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastNotarize(_)));

    // Should NOT vote because we're missing nullification for view 2
    assert!(
        !voted,
        "Should NOT vote for proposal missing intervening nullification"
    );
}

// =============================================================================
// Quorum Threshold Tests
// =============================================================================

/// Test: M-quorum boundary - exactly 2f+1 votes forms M-notarization.
///
/// With n=6, f=1: M-quorum = 2f+1 = 3
#[test]
fn m_quorum_boundary() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);

    // Deliver 2 votes - should NOT form certificate
    harness.deliver_notarizes(view, payload, &[Participant::new(0), Participant::new(1)]);
    let actions = harness.drain_actions();
    let has_cert = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastCertificate(_)));
    assert!(!has_cert, "2 votes should NOT form M-notarization");

    // Deliver 3rd vote - should form M-notarization
    harness.deliver_notarizes(view, payload, &[Participant::new(2)]);
    let actions = harness.drain_actions();
    let has_m_not = actions.iter().any(|a| {
        matches!(
            a,
            Action::BroadcastCertificate(Certificate::MNotarization(_))
        )
    });
    assert!(has_m_not, "3 votes (M-quorum) should form M-notarization");
}

/// Test: L-quorum boundary - exactly n-f votes forms finalization.
///
/// With n=6, f=1: L-quorum = n-f = 5
#[test]
fn l_quorum_boundary() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);

    // Deliver 4 votes - should form M-notarization but NOT finalization
    harness.deliver_notarizes(
        view,
        payload,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
        ],
    );
    let actions = harness.drain_actions();
    let has_finalization = actions.iter().any(|a| matches!(a, Action::Finalized(_)));
    assert!(!has_finalization, "4 votes should NOT finalize");

    // Deliver 5th vote - should finalize
    harness.deliver_notarizes(view, payload, &[Participant::new(4)]);
    let actions = harness.drain_actions();
    let has_finalization = actions.iter().any(|a| matches!(a, Action::Finalized(_)));
    assert!(has_finalization, "5 votes (L-quorum) should finalize");
}

/// Test: Nullification quorum - exactly 2f+1 nullify votes.
///
/// With n=6, f=1: nullification quorum = 2f+1 = 3
#[test]
fn nullification_quorum_boundary() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    assert_eq!(view, View::new(1));

    // Deliver 2 nullify votes - should NOT advance view
    harness.deliver_nullifies(view, &[Participant::new(0), Participant::new(1)]);
    let actions = harness.drain_actions();
    let advanced = actions.iter().any(|a| matches!(a, Action::Advanced(_)));
    assert!(!advanced, "2 nullifies should NOT advance view");
    assert_eq!(harness.view(), View::new(1), "Should still be at view 1");

    // Deliver 3rd nullify - should form nullification and advance view
    harness.deliver_nullifies(view, &[Participant::new(2)]);
    let actions = harness.drain_actions();
    let advanced = actions
        .iter()
        .any(|a| matches!(a, Action::Advanced(v) if *v == View::new(2)));
    assert!(advanced, "3 nullifies (M-quorum) should advance view");
    assert_eq!(harness.view(), View::new(2), "Should be at view 2");
}

// =============================================================================
// Edge Cases and Boundary Conditions
// =============================================================================

/// Test: Wrong epoch votes are rejected.
#[test]
fn wrong_epoch_vote_rejected() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);

    // Create a vote for the WRONG epoch
    let wrong_epoch = Epoch::new(99);
    let proposal = Proposal::new(
        Round::new(wrong_epoch, view),
        View::zero(),
        GENESIS,
        payload,
    );
    let vote = Notarize::sign(&harness.schemes[0], proposal).expect("sign");

    let actions = harness
        .state
        .receive_notarize(&mut harness.rng, vote, &Sequential);
    assert!(actions.is_empty(), "Wrong epoch vote should be rejected");
}

/// Test: Wrong epoch proposal is rejected.
#[test]
fn wrong_epoch_proposal_rejected() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);

    let wrong_epoch = Epoch::new(99);
    let proposal = Proposal::new(
        Round::new(wrong_epoch, view),
        View::zero(),
        GENESIS,
        payload,
    );
    let leader = harness.state.leader(view, None);

    let actions = harness.state.receive_proposal(leader, proposal);
    assert!(
        actions.is_empty(),
        "Wrong epoch proposal should be rejected"
    );
}

/// Test: Duplicate vote handling - same vote received twice.
#[test]
fn duplicate_vote_ignored() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);
    let proposal = harness.proposal(view, payload);

    let vote = Notarize::sign(&harness.schemes[0], proposal).expect("sign");

    // First delivery
    let actions1 = harness
        .state
        .receive_notarize(&mut harness.rng, vote.clone(), &Sequential);

    // Second delivery of same vote
    let actions2 = harness
        .state
        .receive_notarize(&mut harness.rng, vote, &Sequential);

    // Second delivery should produce no actions (duplicate)
    assert!(
        actions2.is_empty(),
        "Duplicate vote should be ignored, got: {:?}",
        actions2
    );
    // First delivery was processed (it may or may not produce actions depending on state,
    // but what matters is that the second one is empty)
    let _ = actions1;
}

/// Test: Finalization received after view change still triggers Finalized action.
#[test]
fn finalization_after_view_change() {
    let mut harness = Harness::new(6);

    // Get M-notarization for view 1 and advance to view 2
    let payload_v1 = Digest::from([1u8; 32]);
    harness.deliver_m_notarization(
        View::new(1),
        payload_v1,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    harness.drain_actions();
    assert_eq!(harness.view(), View::new(2), "Should be at view 2");

    // Now receive finalization for view 1 (we've already moved on)
    harness.deliver_finalization(
        View::new(1),
        payload_v1,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
            Participant::new(4),
        ],
    );

    let actions = harness.drain_actions();
    let finalized = actions.iter().any(|a| matches!(a, Action::Finalized(_)));
    assert!(finalized, "Should still process finalization for past view");
}

/// Test: View progression via consecutive nullifications.
#[test]
fn view_progression_via_nullifications() {
    let mut harness = Harness::new(6);
    assert_eq!(harness.view(), View::new(1));

    // Advance through views 1-5 via nullifications
    for v in 1..=5 {
        harness.deliver_nullification(
            View::new(v),
            &[
                Participant::new(0),
                Participant::new(1),
                Participant::new(2),
            ],
        );
        harness.drain_actions();
        assert_eq!(
            harness.view(),
            View::new(v + 1),
            "Should advance to view {}",
            v + 1
        );
    }
}

/// Test: Certificate deduplication - same certificate received twice.
#[test]
fn certificate_deduplication() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);
    let proposal = harness.proposal(view, payload);

    let votes: Vec<_> = [0, 1, 2]
        .iter()
        .map(|&i| Notarize::sign(&harness.schemes[i], proposal.clone()).expect("sign"))
        .collect();
    let m_notarization =
        MNotarization::from_notarizes(&harness.verifier, votes.iter(), &Sequential)
            .expect("m-notarization");

    // First delivery
    let actions1 = harness
        .state
        .receive_certificate(Certificate::MNotarization(m_notarization.clone()));

    // Second delivery of same certificate
    let actions2 = harness
        .state
        .receive_certificate(Certificate::MNotarization(m_notarization));

    // First should advance view
    let advanced1 = actions1.iter().any(|a| matches!(a, Action::Advanced(_)));
    assert!(advanced1, "First certificate should advance view");

    // Second should be ignored (no view advance since already at view 2)
    let advanced2 = actions2.iter().any(|a| matches!(a, Action::Advanced(_)));
    assert!(
        !advanced2,
        "Duplicate certificate should not advance view again"
    );
}

/// Test: Vote on M-notarization at current view before explicit voting.
///
/// When we receive an M-notarization for our current view before we've voted,
/// we should vote for that block before advancing.
#[test]
fn vote_on_current_view_m_notarization() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);

    // Receive M-notarization for current view BEFORE voting
    harness.deliver_m_notarization(
        view,
        payload,
        &[
            Participant::new(1), // Not us (participant 0)
            Participant::new(2),
            Participant::new(3),
        ],
    );

    let actions = harness.drain_actions();

    // Should vote for the block
    let voted = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastNotarize(_)));
    assert!(
        voted,
        "Should vote on M-notarization for current view before advancing"
    );

    // And should advance
    let advanced = actions
        .iter()
        .any(|a| matches!(a, Action::Advanced(v) if *v == View::new(2)));
    assert!(advanced, "Should advance after voting");
}

/// Test: Vote on future-view M-notarization before advancing.
#[test]
fn vote_before_advancing_on_higher_view_m_notarization() {
    let mut harness = Harness::new(6);

    let target_view = View::new(3);
    let payload = Digest::from([1u8; 32]);

    harness.deliver_m_notarization(
        target_view,
        payload,
        &[
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
        ],
    );

    let actions = harness.drain_actions();
    let voted_target_view = actions.iter().any(
        |a| matches!(a, Action::BroadcastNotarize(v) if v.proposal.round.view() == target_view),
    );
    let advanced_to_next = actions
        .iter()
        .any(|a| matches!(a, Action::Advanced(v) if *v == target_view.next()));

    assert!(
        voted_target_view,
        "Should vote on future-view M-notarization before advancing"
    );
    assert!(
        advanced_to_next,
        "Should advance on future-view M-notarization"
    );
}

/// Integration test: one-shot future-view M-notarization should contribute local vote
/// so L-quorum finalization can complete without certificate redelivery.
#[test]
fn higher_view_m_notarization_enables_finalization_without_redelivery() {
    let mut harness = Harness::new(6);

    let target_view = View::new(3);
    let payload = Digest::from([1u8; 32]);

    // Simulate one-shot certificate delivery (batcher suppresses duplicates).
    harness.deliver_m_notarization(
        target_view,
        payload,
        &[
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
        ],
    );
    let first_actions = harness.drain_actions();

    // Later, observe only four notarize votes from peers. With our local Vote2,
    // this reaches L=5 at n=6 and finalizes view 3.
    harness.deliver_notarizes(
        target_view,
        payload,
        &[
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
            Participant::new(4),
        ],
    );
    let second_actions = harness.drain_actions();

    let voted_target_view = first_actions.iter().any(
        |a| matches!(a, Action::BroadcastNotarize(v) if v.proposal.round.view() == target_view),
    );
    let finalized_target_view = second_actions
        .iter()
        .any(|a| matches!(a, Action::Finalized(f) if f.proposal.round.view() == target_view));

    assert!(
        voted_target_view,
        "Should emit local Vote2 on one-shot future-view M-notarization"
    );
    assert!(
        finalized_target_view,
        "Local Vote2 should allow L-quorum finalization without certificate redelivery"
    );
}

/// Test: Invalid proposal verification does not trigger vote.
#[test]
fn invalid_proposal_no_vote() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);
    let proposal = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload,
    );

    harness.receive_proposal(proposal);
    // Mark as INVALID
    harness.verify_proposal(view, false);

    let actions = harness.drain_actions();
    let voted = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastNotarize(_)));
    assert!(!voted, "Should NOT vote for invalid proposal");
}

/// Test: Genesis parent is valid for view 1.
#[test]
fn genesis_parent_valid_for_view_1() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    assert_eq!(view, View::new(1), "Should start at view 1");

    let payload = Digest::from([1u8; 32]);
    let proposal = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload,
    );

    harness.receive_proposal(proposal);
    harness.verify_proposal(view, true);

    let actions = harness.drain_actions();
    let voted = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastNotarize(_)));
    assert!(voted, "Should vote for view 1 proposal with genesis parent");
}

/// Test: Contradictory nullify votes trigger nullification (mixed nullify and conflicting notarize).
#[test]
fn nullify_by_mixed_contradiction() {
    let mut harness = Harness::new(6);
    let view = harness.view();

    // Vote for block A
    let payload_a = Digest::from([0xAA; 32]);
    let proposal_a = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload_a,
    );
    harness.receive_proposal(proposal_a);
    harness.verify_proposal(view, true);
    harness.drain_actions();

    // Deliver 1 nullify vote
    let nullify_vote =
        Nullify::sign::<Digest>(&harness.schemes[3], Round::new(Epoch::new(1), view))
            .expect("nullify");
    harness
        .state
        .receive_nullify(&mut harness.rng, nullify_vote, &Sequential);

    // Deliver 2 votes for different block B
    let payload_b = Digest::from([0xBB; 32]);
    let proposal_b = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload_b,
    );
    harness.proposals.insert(view, proposal_b.clone());

    let vote_b1 = Notarize::sign(&harness.schemes[1], proposal_b.clone()).expect("sign");
    let vote_b2 = Notarize::sign(&harness.schemes[2], proposal_b).expect("sign");

    harness
        .state
        .receive_notarize(&mut harness.rng, vote_b1, &Sequential);
    let actions = harness
        .state
        .receive_notarize(&mut harness.rng, vote_b2, &Sequential);

    // Total contradiction evidence: 1 nullify + 2 conflicting notarizes = 3 = M-quorum
    let nullified = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastNullify(_)));
    assert!(
        nullified,
        "Should nullify via mixed contradiction (1 nullify + 2 conflicting votes)"
    );
}

// =============================================================================
// Verified Vote Tests (simulating batcher -> voter flow)
// =============================================================================

/// Test: Verified notarize votes are processed correctly.
///
/// This simulates the flow from batcher to voter where votes have already
/// been signature-verified.
#[test]
fn verified_notarize_flow() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);
    let proposal = harness.proposal(view, payload);

    // Create verified votes (simulating batcher output)
    let votes: Vec<_> = [0, 1, 2]
        .iter()
        .map(|&i| Notarize::sign(&harness.schemes[i], proposal.clone()).expect("sign"))
        .collect();

    // Deliver via verified path
    for vote in votes {
        let actions = harness.state.receive_verified_notarize(vote, &Sequential);
        harness.next_actions(actions);
    }

    let actions = harness.drain_actions();

    // Should form M-notarization (3 votes = 2f+1 for n=6, f=1)
    let has_m_not = actions.iter().any(|a| {
        matches!(
            a,
            Action::BroadcastCertificate(Certificate::MNotarization(_))
        )
    });
    assert!(
        has_m_not,
        "Verified notarizes should form M-notarization, got: {:?}",
        actions
    );
}

/// Test: Verified nullify votes are processed correctly.
#[test]
fn verified_nullify_flow() {
    let mut harness = Harness::new(6);
    let view = harness.view();

    // First trigger our own nullify so we're in nullifying state
    harness.handle_timeout();
    harness.drain_actions();

    // Create verified nullify votes (simulating batcher output).
    // Include our own vote (0) since in the real system the batcher sends it back
    // as VerifiedNullify after we broadcast it.
    // For n=6, f=1: M-quorum = 2f+1 = 3
    let votes: Vec<_> = [0, 1, 2]
        .iter()
        .map(|&i| {
            Nullify::sign::<Digest>(&harness.schemes[i], Round::new(Epoch::new(1), view))
                .expect("sign")
        })
        .collect();

    // Deliver via verified path
    for vote in votes {
        let actions = harness.state.receive_verified_nullify(vote, &Sequential);
        harness.next_actions(actions);
    }

    let actions = harness.drain_actions();

    // Should form nullification and advance view
    let has_nullification = actions.iter().any(|a| {
        matches!(
            a,
            Action::BroadcastCertificate(Certificate::Nullification(_))
        )
    });
    let advanced = actions
        .iter()
        .any(|a| matches!(a, Action::Advanced(v) if *v == View::new(2)));

    assert!(
        has_nullification,
        "Verified nullifies should form nullification"
    );
    assert!(advanced, "Should advance to view 2");
}

// =============================================================================
// Select Parent Tests
// =============================================================================

/// Test: select_parent returns genesis for view 1.
#[test]
fn select_parent_returns_genesis_for_view_1() {
    let harness = Harness::new(6);

    // At view 1, parent should be genesis (view 0)
    let parent = harness.state.select_parent(View::new(1));
    assert!(
        parent.is_some(),
        "View 1 should have a valid parent (genesis)"
    );
    let (parent_view, _) = parent.unwrap();
    assert_eq!(
        parent_view,
        View::zero(),
        "Parent of view 1 should be view 0"
    );
}

/// Test: select_parent requires M-notarization for non-genesis parent.
#[test]
fn select_parent_requires_m_notarization() {
    let mut harness = Harness::new(6);

    // Advance to view 3 via nullifications (no M-notarizations)
    for v in 1..=2 {
        harness.deliver_nullification(
            View::new(v),
            &[
                Participant::new(0),
                Participant::new(1),
                Participant::new(2),
            ],
        );
    }
    harness.drain_actions();
    assert_eq!(harness.view(), View::new(3));

    // select_parent for view 3 should return genesis since views 1-2 were nullified
    let parent = harness.state.select_parent(View::new(3));
    assert!(parent.is_some());
    let (parent_view, _) = parent.unwrap();
    assert_eq!(
        parent_view,
        View::zero(),
        "Parent should be genesis when intervening views are nullified"
    );
}

/// Test: select_parent returns highest M-notarization.
#[test]
fn select_parent_returns_highest_m_notarization() {
    let mut harness = Harness::new(6);
    let payload_v1 = Digest::from([1u8; 32]);
    let payload_v2 = Digest::from([2u8; 32]);

    // Get M-notarization for view 1
    harness.deliver_m_notarization(
        View::new(1),
        payload_v1,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    harness.drain_actions();

    // Get M-notarization for view 2
    harness.deliver_m_notarization(
        View::new(2),
        payload_v2,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    harness.drain_actions();
    assert_eq!(harness.view(), View::new(3));

    // select_parent for view 3 should return view 2's M-notarization
    let parent = harness.state.select_parent(View::new(3));
    assert!(parent.is_some());
    let (parent_view, parent_payload) = parent.unwrap();
    assert_eq!(parent_view, View::new(2), "Parent should be view 2");
    assert_eq!(parent_payload, payload_v2, "Parent payload should match");
}

/// Test: multiple M-notarizations for the same view are retained.
#[test]
fn multiple_m_notarizations_per_view_are_retained() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload_a = Digest::from([0xA1; 32]);
    let payload_b = Digest::from([0xB2; 32]);

    let proposal_a = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload_a,
    );
    let proposal_b = Proposal::new(
        Round::new(Epoch::new(1), view),
        View::zero(),
        GENESIS,
        payload_b,
    );

    let votes_a: Vec<_> = [0, 1, 2]
        .iter()
        .map(|&i| Notarize::sign(&harness.schemes[i], proposal_a.clone()).expect("notarize"))
        .collect();
    let m_not_a = MNotarization::from_notarizes(&harness.verifier, votes_a.iter(), &Sequential)
        .expect("m-notarization A");
    let actions = harness
        .state
        .receive_certificate(Certificate::MNotarization(m_not_a));
    harness.next_actions(actions);
    harness.drain_actions();

    let votes_b: Vec<_> = [3, 4, 5]
        .iter()
        .map(|&i| Notarize::sign(&harness.schemes[i], proposal_b.clone()).expect("notarize"))
        .collect();
    let m_not_b = MNotarization::from_notarizes(&harness.verifier, votes_b.iter(), &Sequential)
        .expect("m-notarization B");
    let actions = harness
        .state
        .receive_certificate(Certificate::MNotarization(m_not_b));
    harness.next_actions(actions);
    harness.drain_actions();

    let proposal_next = Proposal::new(
        Round::new(Epoch::new(1), view.next()),
        view,
        payload_b,
        Digest::from([0xC3; 32]),
    );
    let parent = harness.state.parent_payload(&proposal_next);
    assert_eq!(
        parent,
        Some((view, payload_b)),
        "Parent payload should be resolved for the second M-notarization"
    );
}

// =============================================================================
// Leader Election Tests
// =============================================================================

/// Test: Leader is determined consistently.
#[test]
fn leader_election_deterministic() {
    let mut harness = Harness::new(6);

    // Leader for view 1 should be consistent across calls
    let leader1 = harness.state.leader(View::new(1), None);
    let leader2 = harness.state.leader(View::new(1), None);
    assert_eq!(leader1, leader2, "Leader election should be deterministic");

    // Leader should be in range [0, n)
    assert!(leader1.get() < 6, "Leader should be a valid participant");
}

/// Test: is_leader returns correct result.
#[test]
fn is_leader_check() {
    let mut harness = Harness::new(6);

    let leader = harness.state.leader(View::new(1), None);

    // The first scheme (index 0) is "us" in the state machine
    let we_are_leader = harness.state.is_leader(View::new(1), None);

    if leader == Participant::new(0) {
        assert!(
            we_are_leader,
            "We should be leader if leader is participant 0"
        );
    } else {
        assert!(
            !we_are_leader,
            "We should not be leader if leader is not participant 0"
        );
    }
}

// =============================================================================
// Multi-View Scenario Tests
// =============================================================================

/// Test: Complex multi-view scenario with mixed certificates.
#[test]
fn multi_view_mixed_certificates() {
    let mut harness = Harness::new(6);

    // View 1: M-notarization
    let payload_v1 = Digest::from([1u8; 32]);
    harness.deliver_m_notarization(
        View::new(1),
        payload_v1,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    harness.drain_actions();
    assert_eq!(harness.view(), View::new(2));

    // View 2: Nullification
    harness.deliver_nullification(
        View::new(2),
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    harness.drain_actions();
    assert_eq!(harness.view(), View::new(3));

    // View 3: Finalization
    let payload_v3 = Digest::from([3u8; 32]);
    harness.deliver_finalization(
        View::new(3),
        payload_v3,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
            Participant::new(4),
        ],
    );
    let actions = harness.drain_actions();

    // Should have finalized
    assert!(
        actions.iter().any(|a| matches!(a, Action::Finalized(_))),
        "Should finalize view 3"
    );
    assert_eq!(harness.view(), View::new(4));
}

/// Test: Rapid view progression via certificates.
#[test]
fn rapid_view_progression() {
    let mut harness = Harness::new(6);

    // Deliver certificates for views 1-10 in rapid succession
    for v in 1..=10 {
        let payload = Digest::from([v as u8; 32]);
        harness.deliver_m_notarization(
            View::new(v),
            payload,
            &[
                Participant::new(0),
                Participant::new(1),
                Participant::new(2),
            ],
        );
    }
    harness.drain_actions();

    assert_eq!(harness.view(), View::new(11), "Should be at view 11");
}

// =============================================================================
// Edge Cases and Stress Tests
// =============================================================================

/// Test: Handle votes from all participants.
#[test]
fn all_participants_vote() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);

    // All 6 participants vote
    harness.deliver_notarizes(
        view,
        payload,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
            Participant::new(4),
            Participant::new(5),
        ],
    );

    let actions = harness.drain_actions();

    // Should have both M-notarization and finalization
    let has_m_not = actions.iter().any(|a| {
        matches!(
            a,
            Action::BroadcastCertificate(Certificate::MNotarization(_))
        )
    });
    let has_finalization = actions.iter().any(|a| matches!(a, Action::Finalized(_)));

    assert!(has_m_not, "Should form M-notarization");
    assert!(has_finalization, "Should finalize with all votes");
}

/// Test: Interleaved notarize and nullify votes.
#[test]
fn interleaved_notarize_nullify_votes() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);
    let proposal = harness.proposal(view, payload);

    // Interleave: notarize, nullify, notarize, nullify, notarize
    let notarize_0 = Notarize::sign(&harness.schemes[0], proposal.clone()).expect("sign");
    let nullify_1 = Nullify::sign::<Digest>(&harness.schemes[1], Round::new(Epoch::new(1), view))
        .expect("sign");
    let notarize_2 = Notarize::sign(&harness.schemes[2], proposal.clone()).expect("sign");
    let nullify_3 = Nullify::sign::<Digest>(&harness.schemes[3], Round::new(Epoch::new(1), view))
        .expect("sign");
    let notarize_4 = Notarize::sign(&harness.schemes[4], proposal).expect("sign");

    harness
        .state
        .receive_notarize(&mut harness.rng, notarize_0, &Sequential);
    harness
        .state
        .receive_nullify(&mut harness.rng, nullify_1, &Sequential);
    harness
        .state
        .receive_notarize(&mut harness.rng, notarize_2, &Sequential);
    harness
        .state
        .receive_nullify(&mut harness.rng, nullify_3, &Sequential);
    let actions = harness
        .state
        .receive_notarize(&mut harness.rng, notarize_4, &Sequential);

    // With 3 notarizes and 2 nullifies:
    // - M-quorum for notarize is 3 (2f+1 for n=6)
    // - M-quorum for nullify is 3 (2f+1 for n=6)
    // We have 3 notarizes -> should form M-notarization
    let has_m_not = actions.iter().any(|a| {
        matches!(
            a,
            Action::BroadcastCertificate(Certificate::MNotarization(_))
        )
    });
    assert!(has_m_not, "Should form M-notarization with 3 notarizes");
}

/// Test: Vote tracking across view boundaries.
#[test]
fn votes_isolated_per_view() {
    let mut harness = Harness::new(6);

    // Deliver 2 notarize votes for view 1
    let payload_v1 = Digest::from([1u8; 32]);
    harness.deliver_notarizes(
        View::new(1),
        payload_v1,
        &[Participant::new(0), Participant::new(1)],
    );
    harness.drain_actions();

    // Advance via nullification
    harness.deliver_nullification(
        View::new(1),
        &[
            Participant::new(2),
            Participant::new(3),
            Participant::new(4),
        ],
    );
    harness.drain_actions();
    assert_eq!(harness.view(), View::new(2));

    // Now deliver 2 notarize votes for view 2
    let payload_v2 = Digest::from([2u8; 32]);
    harness.deliver_notarizes(
        View::new(2),
        payload_v2,
        &[Participant::new(0), Participant::new(1)],
    );
    let actions = harness.drain_actions();

    // Should NOT form certificate (only 2 votes for view 2, view 1 votes don't count)
    let has_cert = actions
        .iter()
        .any(|a| matches!(a, Action::BroadcastCertificate(_)));
    assert!(
        !has_cert,
        "Votes from previous view should not count toward new view"
    );
}

/// Test: Minimum quorum scenarios.
///
/// With n=6, f=1:
/// - M-quorum = 2f+1 = 3
/// - L-quorum = n-f = 5
/// - Nullification quorum = 2f+1 = 3
#[test]
fn minimum_quorum_n6() {
    let mut harness = Harness::new(6);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);

    // Exactly M-quorum (3) notarizes -> M-notarization but no finalization
    harness.deliver_notarizes(
        view,
        payload,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
        ],
    );
    let actions = harness.drain_actions();

    let has_m_not = actions.iter().any(|a| {
        matches!(
            a,
            Action::BroadcastCertificate(Certificate::MNotarization(_))
        )
    });
    let has_fin = actions.iter().any(|a| matches!(a, Action::Finalized(_)));

    assert!(has_m_not, "Exactly M-quorum should form M-notarization");
    assert!(!has_fin, "M-quorum alone should not finalize");

    // Add 2 more votes (total 5 = L-quorum) -> finalization
    harness.deliver_notarizes(view, payload, &[Participant::new(3), Participant::new(4)]);
    let actions = harness.drain_actions();

    let has_fin = actions.iter().any(|a| matches!(a, Action::Finalized(_)));
    assert!(has_fin, "L-quorum should finalize");
}

/// Test: Large participant set (n=11, f=2).
///
/// With n=11, f=2:
/// - M-quorum = 2f+1 = 5
/// - L-quorum = n-f = 9
#[test]
fn quorum_with_larger_n() {
    let mut harness = Harness::new(11);
    let view = harness.view();
    let payload = Digest::from([1u8; 32]);

    // With n=11, f=2, M-quorum = 5, L-quorum = 9

    // 4 votes should NOT form M-notarization
    harness.deliver_notarizes(
        view,
        payload,
        &[
            Participant::new(0),
            Participant::new(1),
            Participant::new(2),
            Participant::new(3),
        ],
    );
    let actions = harness.drain_actions();
    let has_m_not = actions.iter().any(|a| {
        matches!(
            a,
            Action::BroadcastCertificate(Certificate::MNotarization(_))
        )
    });
    assert!(
        !has_m_not,
        "4 votes should not form M-notarization for n=11"
    );

    // 5th vote should form M-notarization
    harness.deliver_notarizes(view, payload, &[Participant::new(4)]);
    let actions = harness.drain_actions();
    let has_m_not = actions.iter().any(|a| {
        matches!(
            a,
            Action::BroadcastCertificate(Certificate::MNotarization(_))
        )
    });
    assert!(has_m_not, "5 votes should form M-notarization for n=11");

    // 8 votes should NOT finalize
    harness.deliver_notarizes(
        view,
        payload,
        &[
            Participant::new(5),
            Participant::new(6),
            Participant::new(7),
        ],
    );
    let actions = harness.drain_actions();
    let has_fin = actions.iter().any(|a| matches!(a, Action::Finalized(_)));
    assert!(!has_fin, "8 votes should not finalize for n=11");

    // 9th vote should finalize
    harness.deliver_notarizes(view, payload, &[Participant::new(8)]);
    let actions = harness.drain_actions();
    let has_fin = actions.iter().any(|a| matches!(a, Action::Finalized(_)));
    assert!(has_fin, "9 votes (L-quorum) should finalize for n=11");
}

// =============================================================================
// Engine Integration Tests
// =============================================================================
//
// These tests exercise the full consensus engine with simulated networks,
// testing liveness and safety under various conditions including:
// - All nodes online (happy path)
// - Network partitions
// - Byzantine twins (equivocation)
// - Slow/lossy network conditions

mod engine_tests {
    use crate::{
        elector::{Config as Elector, RoundRobin},
        minimmit::{
            config::Config,
            engine::Engine,
            mocks::{application, relay, reporter, twins::Strategy},
            scheme::{bls12381_multisig, bls12381_threshold, ed25519, secp256r1, Scheme},
            types::{Certificate, Vote},
        },
        types::{Epoch, View, ViewDelta},
        Monitor, Viewable,
    };
    use commonware_codec::{Decode, DecodeExt};
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::PublicKey,
        sha256::Digest as D,
        Sha256,
    };
    use commonware_macros::{test_group, test_traced};
    use commonware_p2p::{
        simulated::{
            Config as NetworkConfig, Link, Network, Oracle, Receiver, Sender, SplitOrigin,
            SplitTarget,
        },
        Recipients,
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, IoBuf, Metrics, Quota, Runner, Spawner,
    };
    use commonware_utils::{Faults, M5f1, NZUsize, NZU16};
    use futures::future::join_all;
    use std::{
        collections::{BTreeMap, HashMap},
        num::{NonZeroU16, NonZeroU32, NonZeroUsize},
        sync::Arc,
        time::Duration,
    };
    use tracing::info;

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
    const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

    /// Register a validator with the oracle.
    async fn register_validator(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        validator: PublicKey,
    ) -> (
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
        (
            Sender<PublicKey, deterministic::Context>,
            Receiver<PublicKey>,
        ),
    ) {
        let control = oracle.control(validator.clone());
        let (vote_sender, vote_receiver) = control.register(0, TEST_QUOTA).await.unwrap();
        let (certificate_sender, certificate_receiver) =
            control.register(1, TEST_QUOTA).await.unwrap();
        let (resolver_sender, resolver_receiver) = control.register(2, TEST_QUOTA).await.unwrap();
        (
            (vote_sender, vote_receiver),
            (certificate_sender, certificate_receiver),
            (resolver_sender, resolver_receiver),
        )
    }

    /// Registers all validators using the oracle.
    async fn register_validators(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        validators: &[PublicKey],
    ) -> HashMap<
        PublicKey,
        (
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
            (
                Sender<PublicKey, deterministic::Context>,
                Receiver<PublicKey>,
            ),
        ),
    > {
        let mut registrations = HashMap::new();
        for validator in validators.iter() {
            let registration = register_validator(oracle, validator.clone()).await;
            registrations.insert(validator.clone(), registration);
        }
        registrations
    }

    /// Enum to describe the action to take when linking validators.
    #[allow(dead_code)]
    enum LinkAction {
        Link(Link),
        Unlink,
    }

    /// Links (or unlinks) validators using the oracle.
    async fn link_validators(
        oracle: &mut Oracle<PublicKey, deterministic::Context>,
        validators: &[PublicKey],
        action: LinkAction,
        restrict_to: Option<fn(usize, usize, usize) -> bool>,
    ) {
        for (i1, v1) in validators.iter().enumerate() {
            for (i2, v2) in validators.iter().enumerate() {
                if v2 == v1 {
                    continue;
                }

                if let Some(f) = restrict_to {
                    if !f(validators.len(), i1, i2) {
                        continue;
                    }
                }

                match action {
                    LinkAction::Unlink => {
                        oracle.remove_link(v1.clone(), v2.clone()).await.unwrap();
                    }
                    LinkAction::Link(ref link) => {
                        oracle
                            .add_link(v1.clone(), v2.clone(), link.clone())
                            .await
                            .unwrap();
                    }
                }
            }
        }
    }

    // =========================================================================
    // all_online: Happy path test with all validators online and connected
    // =========================================================================

    fn all_online<S, F, L>(mut fixture: F)
    where
        S: Scheme<D, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        let n = 6; // n >= 5f+1, so f=1
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"minimmit_engine_test".to_vec();
        let executor = deterministic::Runner::timed(Duration::from_secs(300));
        executor.start(|mut context| async move {
            // Create simulated network
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            // Register participants
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Link all validators with good network conditions
            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(1),
                success_rate: 1.0,
            };
            link_validators(&mut oracle, &participants, LinkAction::Link(link), None).await;

            // Create engines
            let elector = L::default();
            let relay = Arc::new(relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                let context = context.with_label(&format!("validator_{}", *validator));

                let reporter_config = reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());

                let application_cfg = application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: application::Certifier::Sometimes,
                };
                let (actor, application) = application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();

                let blocker = oracle.control(validator.clone());
                let cfg = Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                let (vote, certificate, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(vote, certificate, resolver));
            }

            // Wait for all engines to reach required finalization
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Verify no faults and no invalid signatures
            let _latest_complete = required_containers.saturating_sub(activity_timeout);
            for reporter in reporters.iter() {
                {
                    let faults = reporter.faults.lock().unwrap();
                    assert!(faults.is_empty(), "no faults expected in happy path");
                }
                {
                    let invalid = reporter.invalid.lock().unwrap();
                    assert_eq!(*invalid, 0, "no invalid signatures expected");
                }
            }

            // Verify safety: no conflicting finalizations
            let mut finalized_at_view: BTreeMap<View, D> = BTreeMap::new();
            for reporter in reporters.iter() {
                let finalizations = reporter.finalizations.lock().unwrap();
                for (view, finalization) in finalizations.iter() {
                    let digest = finalization.proposal.payload;
                    if let Some(existing) = finalized_at_view.get(view) {
                        assert_eq!(
                            existing, &digest,
                            "safety violation: conflicting finalizations at view {view}"
                        );
                    } else {
                        finalized_at_view.insert(*view, digest);
                    }
                }
            }

            info!(
                "all_online test passed: {} views finalized",
                finalized_at_view.len()
            );
        });
    }

    #[test_traced]
    fn test_all_online_ed25519_round_robin() {
        all_online::<ed25519::Scheme, _, RoundRobin>(ed25519::fixture);
    }

    #[test_traced]
    fn test_all_online_bls12381_threshold_min_pk() {
        all_online::<bls12381_threshold::Scheme<PublicKey, MinPk>, _, RoundRobin>(
            bls12381_threshold::fixture::<MinPk, _>,
        );
    }

    #[test_traced]
    fn test_all_online_bls12381_threshold_min_sig() {
        all_online::<bls12381_threshold::Scheme<PublicKey, MinSig>, _, RoundRobin>(
            bls12381_threshold::fixture::<MinSig, _>,
        );
    }

    #[test_traced]
    fn test_all_online_bls12381_multisig_min_pk() {
        all_online::<bls12381_multisig::Scheme<PublicKey, MinPk>, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
    }

    #[test_traced]
    fn test_all_online_bls12381_multisig_min_sig() {
        all_online::<bls12381_multisig::Scheme<PublicKey, MinSig>, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
    }

    #[test_traced]
    fn test_all_online_secp256r1() {
        all_online::<secp256r1::Scheme<PublicKey>, _, RoundRobin>(secp256r1::fixture);
    }

    // =========================================================================
    // slow_lossy: Tests with degraded network conditions
    // =========================================================================

    fn slow_lossy<S, F, L>(seed: u64, mut fixture: F)
    where
        S: Scheme<D, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        let n = 6;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"minimmit_slow_lossy".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(600)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;

            // Degraded network: high latency, jitter, and packet loss
            let link = Link {
                latency: Duration::from_millis(200),
                jitter: Duration::from_millis(150),
                success_rate: 0.75, // 25% packet loss
            };
            link_validators(&mut oracle, &participants, LinkAction::Link(link), None).await;

            let elector = L::default();
            let relay = Arc::new(relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                let context = context.with_label(&format!("validator_{}", *validator));

                let reporter_config = reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());

                let application_cfg = application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (50.0, 25.0),
                    verify_latency: (50.0, 25.0),
                    certify_latency: (50.0, 25.0),
                    should_certify: application::Certifier::Sometimes,
                };
                let (actor, application) = application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();

                let blocker = oracle.control(validator.clone());
                let cfg = Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    leader_timeout: Duration::from_secs(2),
                    notarization_timeout: Duration::from_secs(4),
                    nullify_retry: Duration::from_secs(15),
                    fetch_timeout: Duration::from_secs(2),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                let (vote, certificate, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(vote, certificate, resolver));
            }

            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Verify safety
            let mut finalized_at_view: BTreeMap<View, D> = BTreeMap::new();
            for reporter in reporters.iter() {
                let finalizations = reporter.finalizations.lock().unwrap();
                for (view, finalization) in finalizations.iter() {
                    let digest = finalization.proposal.payload;
                    if let Some(existing) = finalized_at_view.get(view) {
                        assert_eq!(
                            existing, &digest,
                            "safety violation: conflicting finalizations at view {view}"
                        );
                    } else {
                        finalized_at_view.insert(*view, digest);
                    }
                }
            }

            info!(
                "slow_lossy test passed: {} views finalized",
                finalized_at_view.len()
            );
        });
    }

    #[test_traced]
    fn test_slow_lossy_ed25519() {
        slow_lossy::<ed25519::Scheme, _, RoundRobin>(0, ed25519::fixture);
    }

    #[test_traced]
    fn test_slow_lossy_bls12381_threshold() {
        slow_lossy::<bls12381_threshold::Scheme<PublicKey, MinPk>, _, RoundRobin>(
            0,
            bls12381_threshold::fixture::<MinPk, _>,
        );
    }

    #[test_traced]
    fn test_slow_lossy_bls12381_multisig() {
        slow_lossy::<bls12381_multisig::Scheme<PublicKey, MinPk>, _, RoundRobin>(
            0,
            bls12381_multisig::fixture::<MinPk, _>,
        );
    }

    #[test_traced]
    fn test_slow_lossy_secp256r1() {
        slow_lossy::<secp256r1::Scheme<PublicKey>, _, RoundRobin>(0, secp256r1::fixture);
    }

    // =========================================================================
    // twins: Byzantine equivocation tests using the Twins methodology
    // https://arxiv.org/abs/2004.10617
    // =========================================================================

    fn twins<S, F, L>(seed: u64, n: u32, strategy: Strategy, link: Link, mut fixture: F)
    where
        S: Scheme<D, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        let faults = M5f1::max_faults(n);
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"minimmit_twins".to_vec();
        // Minimmit with n=6 and Strategy::View hits 50/50 partitions at views
        // 3, 9, 15, 21, 27, 33, 39, 45 (every 6th view where view % 6 = 3).
        // Each partition requires multiple retries to resolve, so we need a
        // longer timeout than simplex (which uses n=5 and avoids 50/50 splits).
        let cfg = deterministic::Config::new().with_seed(seed);
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: false,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let participants: Arc<[_]> = participants.into();
            let mut registrations = register_validators(&mut oracle, &participants).await;
            link_validators(&mut oracle, &participants, LinkAction::Link(link), None).await;

            let elector = L::default();
            let relay = Arc::new(relay::Relay::new());
            let mut reporters = Vec::new();
            let mut engine_handlers = Vec::new();

            // Create twin engines (f Byzantine twins)
            for (idx, validator) in participants.iter().enumerate().take(faults as usize) {
                let (
                    (vote_sender, vote_receiver),
                    (certificate_sender, certificate_receiver),
                    (resolver_sender, resolver_receiver),
                ) = registrations
                    .remove(validator)
                    .expect("validator should be registered");

                // Create forwarder closures for votes
                let make_vote_forwarder = || {
                    let participants = participants.clone();
                    move |origin: SplitOrigin, _: &Recipients<_>, message: &IoBuf| {
                        let msg: Vote<S, D> = Vote::decode(message.clone()).unwrap();
                        let (primary, secondary) =
                            strategy.partitions(msg.view(), participants.as_ref());
                        match origin {
                            SplitOrigin::Primary => Some(Recipients::Some(primary)),
                            SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                        }
                    }
                };

                // Create forwarder closures for certificates
                let make_certificate_forwarder = || {
                    let codec = schemes[idx].certificate_codec_config();
                    let participants = participants.clone();
                    move |origin: SplitOrigin, _: &Recipients<_>, message: &IoBuf| {
                        let msg: Certificate<S, D> =
                            Certificate::decode_cfg(&mut message.as_ref(), &codec).unwrap();
                        let (primary, secondary) =
                            strategy.partitions(msg.view(), participants.as_ref());
                        match origin {
                            SplitOrigin::Primary => Some(Recipients::Some(primary)),
                            SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
                        }
                    }
                };

                let make_drop_forwarder =
                    || move |_: SplitOrigin, _: &Recipients<_>, _: &IoBuf| None;

                // Create router closures for votes
                let make_vote_router = || {
                    let participants = participants.clone();
                    move |(sender, message): &(_, IoBuf)| {
                        let msg: Vote<S, D> = Vote::decode(message.clone()).unwrap();
                        strategy.route(msg.view(), sender, participants.as_ref())
                    }
                };

                // Create router closures for certificates
                let make_certificate_router = || {
                    let codec = schemes[idx].certificate_codec_config();
                    let participants = participants.clone();
                    move |(sender, message): &(_, IoBuf)| {
                        let msg: Certificate<S, D> =
                            Certificate::decode_cfg(&mut message.as_ref(), &codec).unwrap();
                        strategy.route(msg.view(), sender, participants.as_ref())
                    }
                };

                let make_drop_router = || move |(_, _): &(_, _)| SplitTarget::None;

                // Apply view-based forwarder and router to channels
                let (vote_sender_primary, vote_sender_secondary) =
                    vote_sender.split_with(make_vote_forwarder());
                let (vote_receiver_primary, vote_receiver_secondary) = vote_receiver.split_with(
                    context.with_label(&format!("vote_split_{idx}")),
                    make_vote_router(),
                );
                let (certificate_sender_primary, certificate_sender_secondary) =
                    certificate_sender.split_with(make_certificate_forwarder());
                let (certificate_receiver_primary, certificate_receiver_secondary) =
                    certificate_receiver.split_with(
                        context.with_label(&format!("cert_split_{idx}")),
                        make_certificate_router(),
                    );

                // Drop resolver messages for twins (not cleanly mapped to a view)
                let (resolver_sender_primary, resolver_sender_secondary) =
                    resolver_sender.split_with(make_drop_forwarder());
                let (resolver_receiver_primary, resolver_receiver_secondary) = resolver_receiver
                    .split_with(
                        context.with_label(&format!("resolver_split_{idx}")),
                        make_drop_router(),
                    );

                for (twin_label, vote, certificate, resolver) in [
                    (
                        "primary",
                        (vote_sender_primary, vote_receiver_primary),
                        (certificate_sender_primary, certificate_receiver_primary),
                        (resolver_sender_primary, resolver_receiver_primary),
                    ),
                    (
                        "secondary",
                        (vote_sender_secondary, vote_receiver_secondary),
                        (certificate_sender_secondary, certificate_receiver_secondary),
                        (resolver_sender_secondary, resolver_receiver_secondary),
                    ),
                ] {
                    let label = format!("twin_{idx}_{twin_label}");
                    let context = context.with_label(&label);

                    let reporter_config = reporter::Config {
                        participants: participants.as_ref().try_into().unwrap(),
                        scheme: schemes[idx].clone(),
                        elector: elector.clone(),
                    };
                    let reporter =
                        reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                    reporters.push(reporter.clone());

                    let application_cfg = application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: application::Certifier::Sometimes,
                    };
                    let (actor, application) = application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();

                    let blocker = oracle.control(validator.clone());
                    let cfg = Config {
                        scheme: schemes[idx].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition: label,
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_concurrent: 4,
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);
                    engine_handlers.push(engine.start(vote, certificate, resolver));
                }
            }

            // Create honest engines
            for (idx, validator) in participants.iter().enumerate().skip(faults as usize) {
                let label = format!("honest_{idx}");
                let context = context.with_label(&label);

                let reporter_config = reporter::Config {
                    participants: participants.as_ref().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());

                let application_cfg = application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: application::Certifier::Sometimes,
                };
                let (actor, application) = application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();

                let blocker = oracle.control(validator.clone());
                let cfg = Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: label,
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                let (vote, certificate, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine_handlers.push(engine.start(vote, certificate, resolver));
            }

            // Wait for progress (liveness check)
            // Only check honest reporters - twin reporters in partitioned networks may not
            // see enough votes to build finalizations locally (finalizations aren't broadcast
            // per the Minimmit paper, so partitioned twins won't receive them).
            let honest_start = faults as usize * 2; // Each twin produces 2 reporters
            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut().skip(honest_start) {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Verify safety: no conflicting finalizations across honest reporters
            let mut finalized_at_view: BTreeMap<View, D> = BTreeMap::new();
            for reporter in reporters.iter().skip(honest_start) {
                let finalizations = reporter.finalizations.lock().unwrap();
                for (view, finalization) in finalizations.iter() {
                    let digest = finalization.proposal.payload;
                    if let Some(existing) = finalized_at_view.get(view) {
                        assert_eq!(
                            existing, &digest,
                            "safety violation: conflicting finalizations at view {view}"
                        );
                    } else {
                        finalized_at_view.insert(*view, digest);
                    }
                }
            }

            // Verify no invalid signatures were observed by honest nodes
            for reporter in reporters.iter().skip(honest_start) {
                let invalid = reporter.invalid.lock().unwrap();
                assert_eq!(*invalid, 0, "invalid signatures detected");
            }

            // Ensure faults are attributable to twins
            let twin_identities: Vec<_> = participants.iter().take(faults as usize).collect();
            for reporter in reporters.iter().skip(honest_start) {
                let faults = reporter.faults.lock().unwrap();
                for (faulter, _) in faults.iter() {
                    assert!(
                        twin_identities.contains(&faulter),
                        "fault from non-twin participant"
                    );
                }
            }

            // Ensure blocked connections are attributable to twins
            let blocked = oracle.blocked().await.unwrap();
            for (_, faulter) in blocked.iter() {
                assert!(
                    twin_identities.contains(&faulter),
                    "blocked connection from non-twin participant"
                );
            }

            info!(
                "twins test passed: {} views finalized, {} blocked connections",
                finalized_at_view.len(),
                blocked.len()
            );
        });
    }

    fn test_twins<S, F, L>(mut fixture: F)
    where
        S: Scheme<D, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        for strategy in [
            Strategy::View,
            Strategy::Fixed(3),
            Strategy::Isolate(4),
            Strategy::Broadcast,
            Strategy::Shuffle,
        ] {
            for link in [
                Link {
                    latency: Duration::from_millis(10),
                    jitter: Duration::from_millis(1),
                    success_rate: 1.0,
                },
                Link {
                    latency: Duration::from_millis(200),
                    jitter: Duration::from_millis(150),
                    success_rate: 0.75,
                },
            ] {
                twins::<S, _, L>(0, 10, strategy, link, |context, namespace, n| {
                    fixture(context, namespace, n)
                });
            }
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_ed25519() {
        test_twins::<ed25519::Scheme, _, RoundRobin>(ed25519::fixture);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_bls12381_threshold_min_pk() {
        test_twins::<bls12381_threshold::Scheme<PublicKey, MinPk>, _, RoundRobin>(
            bls12381_threshold::fixture::<MinPk, _>,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_bls12381_threshold_min_sig() {
        test_twins::<bls12381_threshold::Scheme<PublicKey, MinSig>, _, RoundRobin>(
            bls12381_threshold::fixture::<MinSig, _>,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_bls12381_multisig_min_pk() {
        test_twins::<bls12381_multisig::Scheme<PublicKey, MinPk>, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_bls12381_multisig_min_sig() {
        test_twins::<bls12381_multisig::Scheme<PublicKey, MinSig>, _, RoundRobin>(
            bls12381_multisig::fixture::<MinSig, _>,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_twins_secp256r1() {
        test_twins::<secp256r1::Scheme<PublicKey>, _, RoundRobin>(secp256r1::fixture);
    }

    #[test_traced]
    fn test_determinism_secp256r1() {
        let result1 = determinism_check::<secp256r1::Scheme<PublicKey>, _, RoundRobin>(
            42,
            secp256r1::fixture,
        );
        let result2 = determinism_check::<secp256r1::Scheme<PublicKey>, _, RoundRobin>(
            42,
            secp256r1::fixture,
        );
        assert_eq!(
            result1, result2,
            "same seed should produce identical results"
        );
    }

    // =========================================================================
    // Determinism tests: verify same seed produces same results
    // =========================================================================

    fn determinism_check<S, F, L>(seed: u64, mut fixture: F) -> BTreeMap<View, D>
    where
        S: Scheme<D, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        let n = 6;
        let required_containers = View::new(50);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"minimmit_determinism".to_vec();
        let cfg = deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(600)));
        let executor = deterministic::Runner::new(cfg);
        executor.start(|mut context| async move {
            let (network, mut oracle) = Network::new(
                context.with_label("network"),
                NetworkConfig {
                    max_size: 1024 * 1024,
                    disconnect_on_block: true,
                    tracked_peer_sets: None,
                },
            );
            network.start();

            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            let mut registrations = register_validators(&mut oracle, &participants).await;

            let link = Link {
                latency: Duration::from_millis(10),
                jitter: Duration::from_millis(5),
                success_rate: 0.95,
            };
            link_validators(&mut oracle, &participants, LinkAction::Link(link), None).await;

            let elector = L::default();
            let relay = Arc::new(relay::Relay::new());
            let mut reporters = Vec::new();
            for (idx, validator) in participants.iter().enumerate() {
                let context = context.with_label(&format!("validator_{}", *validator));

                let reporter_config = reporter::Config {
                    participants: participants.clone().try_into().unwrap(),
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                };
                let reporter =
                    reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                reporters.push(reporter.clone());

                let application_cfg = application::Config {
                    hasher: Sha256::default(),
                    relay: relay.clone(),
                    me: validator.clone(),
                    propose_latency: (10.0, 5.0),
                    verify_latency: (10.0, 5.0),
                    certify_latency: (10.0, 5.0),
                    should_certify: application::Certifier::Sometimes,
                };
                let (actor, application) = application::Application::new(
                    context.with_label("application"),
                    application_cfg,
                );
                actor.start();

                let blocker = oracle.control(validator.clone());
                let cfg = Config {
                    scheme: schemes[idx].clone(),
                    elector: elector.clone(),
                    blocker,
                    automaton: application.clone(),
                    relay: application.clone(),
                    reporter: reporter.clone(),
                    strategy: Sequential,
                    partition: validator.to_string(),
                    mailbox_size: 1024,
                    epoch: Epoch::new(333),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(10),
                    fetch_timeout: Duration::from_secs(1),
                    activity_timeout,
                    skip_timeout,
                    fetch_concurrent: 4,
                    replay_buffer: NZUsize!(1024 * 1024),
                    write_buffer: NZUsize!(1024 * 1024),
                    page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                };
                let engine = Engine::new(context.with_label("engine"), cfg);

                let (vote, certificate, resolver) = registrations
                    .remove(validator)
                    .expect("validator should be registered");
                engine.start(vote, certificate, resolver);
            }

            let mut finalizers = Vec::new();
            for reporter in reporters.iter_mut() {
                let (mut latest, mut monitor) = reporter.subscribe().await;
                finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                    while latest < required_containers {
                        latest = monitor.recv().await.expect("event missing");
                    }
                }));
            }
            join_all(finalizers).await;

            // Collect finalized state
            let mut finalized_at_view: BTreeMap<View, D> = BTreeMap::new();
            for reporter in reporters.iter() {
                let finalizations = reporter.finalizations.lock().unwrap();
                for (view, finalization) in finalizations.iter() {
                    finalized_at_view.insert(*view, finalization.proposal.payload);
                }
            }
            finalized_at_view
        })
    }

    #[test_traced]
    fn test_determinism_ed25519() {
        let result1 = determinism_check::<ed25519::Scheme, _, RoundRobin>(42, ed25519::fixture);
        let result2 = determinism_check::<ed25519::Scheme, _, RoundRobin>(42, ed25519::fixture);
        assert_eq!(
            result1, result2,
            "same seed should produce identical results"
        );
    }

    #[test_traced]
    fn test_determinism_bls12381_threshold() {
        let result1 = determinism_check::<
            bls12381_threshold::Scheme<PublicKey, MinPk>,
            _,
            RoundRobin,
        >(42, bls12381_threshold::fixture::<MinPk, _>);
        let result2 = determinism_check::<
            bls12381_threshold::Scheme<PublicKey, MinPk>,
            _,
            RoundRobin,
        >(42, bls12381_threshold::fixture::<MinPk, _>);
        assert_eq!(
            result1, result2,
            "same seed should produce identical results"
        );
    }

    #[test_traced]
    fn test_determinism_bls12381_multisig() {
        let result1 = determinism_check::<bls12381_multisig::Scheme<PublicKey, MinPk>, _, RoundRobin>(
            42,
            bls12381_multisig::fixture::<MinPk, _>,
        );
        let result2 = determinism_check::<bls12381_multisig::Scheme<PublicKey, MinPk>, _, RoundRobin>(
            42,
            bls12381_multisig::fixture::<MinPk, _>,
        );
        assert_eq!(
            result1, result2,
            "same seed should produce identical results"
        );
    }

    // =========================================================================
    // unclean_shutdown: Crash recovery test with random restarts
    // =========================================================================

    /// Tests crash recovery by randomly restarting all engines during consensus.
    ///
    /// This test verifies:
    /// 1. No double-voting after crash (safety)
    /// 2. Progress continues after restart (liveness)
    /// 3. No Byzantine faults are detected (honest nodes behave correctly)
    ///
    /// The test randomly restarts all engines at unpredictable times, simulating
    /// crash scenarios. The journal-based crash recovery ensures that:
    /// - Votes made before crash are replayed, preventing double-voting
    /// - View state is restored correctly
    /// - Consensus can continue making progress after restart via nullifications
    fn unclean_shutdown<S, F, L>(mut fixture: F)
    where
        S: Scheme<D, PublicKey = PublicKey>,
        F: FnMut(&mut deterministic::Context, &[u8], u32) -> Fixture<S>,
        L: Elector<S>,
    {
        use commonware_runtime::Clock;
        use rand::Rng;
        use std::sync::Mutex;
        use tracing::debug;

        let n = 6;
        let required_containers = View::new(100);
        let activity_timeout = ViewDelta::new(10);
        let skip_timeout = ViewDelta::new(5);
        let namespace = b"minimmit_unclean_shutdown".to_vec();

        // Track restarts
        let shutdowns: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));

        // Relay is shared across restarts
        let relay = Arc::new(relay::Relay::new());

        // Create initial context to generate schemes
        let mut prev_checkpoint = None;

        // Create schemes outside the loop (persistent across restarts)
        let init_executor = deterministic::Runner::timed(Duration::from_secs(5));
        let (participants, schemes) = init_executor.start(|mut context| async move {
            let Fixture {
                participants,
                schemes,
                ..
            } = fixture(&mut context, &namespace, n);
            (participants, schemes)
        });

        loop {
            let participants = participants.clone();
            let schemes = schemes.clone();
            let shutdowns_inner = shutdowns.clone();
            let relay = relay.clone();
            relay.deregister_all(); // Clear all recipients from previous restart

            let f = |mut context: deterministic::Context| async move {
                let shutdowns = shutdowns_inner;
                // Create simulated network
                let (network, mut oracle) = Network::new(
                    context.with_label("network"),
                    NetworkConfig {
                        max_size: 1024 * 1024,
                        disconnect_on_block: true,
                        tracked_peer_sets: None,
                    },
                );
                network.start();

                // Register participants
                let mut registrations = register_validators(&mut oracle, &participants).await;

                // Link all validators
                let link = Link {
                    latency: Duration::from_millis(50),
                    jitter: Duration::from_millis(50),
                    success_rate: 1.0,
                };
                link_validators(&mut oracle, &participants, LinkAction::Link(link), None).await;

                // Create engines
                let elector = L::default();
                let mut reporters = Vec::new();
                let mut engine_handlers = Vec::new();
                for (idx, validator) in participants.iter().enumerate() {
                    let context = context.with_label(&format!("validator_{}", *validator));

                    let reporter_config = reporter::Config {
                        participants: participants.clone().try_into().unwrap(),
                        scheme: schemes[idx].clone(),
                        elector: elector.clone(),
                    };
                    let reporter =
                        reporter::Reporter::new(context.with_label("reporter"), reporter_config);
                    reporters.push(reporter.clone());

                    let application_cfg = application::Config {
                        hasher: Sha256::default(),
                        relay: relay.clone(),
                        me: validator.clone(),
                        propose_latency: (10.0, 5.0),
                        verify_latency: (10.0, 5.0),
                        certify_latency: (10.0, 5.0),
                        should_certify: application::Certifier::Sometimes,
                    };
                    let (actor, application) = application::Application::new(
                        context.with_label("application"),
                        application_cfg,
                    );
                    actor.start();

                    let blocker = oracle.control(validator.clone());
                    let cfg = Config {
                        scheme: schemes[idx].clone(),
                        elector: elector.clone(),
                        blocker,
                        automaton: application.clone(),
                        relay: application.clone(),
                        reporter: reporter.clone(),
                        strategy: Sequential,
                        partition: validator.to_string(),
                        mailbox_size: 1024,
                        epoch: Epoch::new(333),
                        leader_timeout: Duration::from_secs(1),
                        notarization_timeout: Duration::from_secs(2),
                        nullify_retry: Duration::from_secs(10),
                        fetch_timeout: Duration::from_secs(1),
                        activity_timeout,
                        skip_timeout,
                        fetch_concurrent: 4,
                        replay_buffer: NZUsize!(1024 * 1024),
                        write_buffer: NZUsize!(1024 * 1024),
                        page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
                    };
                    let engine = Engine::new(context.with_label("engine"), cfg);

                    let (vote, certificate, resolver) = registrations
                        .remove(validator)
                        .expect("validator should be registered");
                    engine_handlers.push(engine.start(vote, certificate, resolver));
                }

                // Create finalizer handles
                let mut finalizers = Vec::new();
                for reporter in reporters.iter_mut() {
                    let (mut latest, mut monitor) = reporter.subscribe().await;
                    finalizers.push(context.with_label("finalizer").spawn(move |_| async move {
                        while latest < required_containers {
                            latest = monitor.recv().await.expect("event missing");
                        }
                    }));
                }

                // Exit at random points for unclean shutdown
                let wait =
                    context.gen_range(Duration::from_millis(100)..Duration::from_millis(2_000));
                let result = commonware_macros::select! {
                    _ = context.sleep(wait) => {
                        // Random restart - check faults before restart
                        for reporter in reporters.iter() {
                            let faults = reporter.faults.lock().unwrap();
                            assert!(faults.is_empty(), "unexpected faults before restart");
                        }
                        {
                            let mut shutdowns = shutdowns.lock().unwrap();
                            debug!(shutdowns = *shutdowns, elapsed = ?wait, "restarting");
                            *shutdowns += 1;
                        }
                        false
                    },
                    _ = join_all(finalizers) => {
                        // Completed! Check all reporters for faults
                        for reporter in reporters.iter() {
                            let faults = reporter.faults.lock().unwrap();
                            assert!(faults.is_empty(), "unexpected faults in final run");
                        }
                        true
                    }
                };

                // Ensure no blocked connections
                let blocked = oracle.blocked().await.unwrap();
                assert!(blocked.is_empty());

                result
            };

            let (complete, checkpoint) = prev_checkpoint
                .map_or_else(
                    || deterministic::Runner::timed(Duration::from_secs(180)),
                    deterministic::Runner::from,
                )
                .start_and_recover(f);

            if complete {
                let shutdowns = shutdowns.lock().unwrap();
                info!("unclean_shutdown test passed after {} restarts", *shutdowns);
                break;
            }

            prev_checkpoint = Some(checkpoint);
        }
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_unclean_shutdown_ed25519() {
        unclean_shutdown::<ed25519::Scheme, _, RoundRobin>(ed25519::fixture);
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_unclean_shutdown_bls12381_threshold() {
        unclean_shutdown::<bls12381_threshold::Scheme<PublicKey, MinPk>, _, RoundRobin>(
            bls12381_threshold::fixture::<MinPk, _>,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_unclean_shutdown_bls12381_multisig() {
        unclean_shutdown::<bls12381_multisig::Scheme<PublicKey, MinPk>, _, RoundRobin>(
            bls12381_multisig::fixture::<MinPk, _>,
        );
    }

    #[test_group("slow")]
    #[test_traced]
    fn test_unclean_shutdown_secp256r1() {
        unclean_shutdown::<secp256r1::Scheme<PublicKey>, _, RoundRobin>(secp256r1::fixture);
    }
}
