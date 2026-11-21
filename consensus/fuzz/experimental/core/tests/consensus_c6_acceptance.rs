use commonware_consensus::{
    simplex::{
        mocks::scheme as certificate_mock,
        types::{Activity, Attributable, Finalization, Finalize, Notarize, Nullify, Proposal},
    },
    types::{Epoch, Participant, Round, TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    EPOCH,
    simplex_audit::{Event, RecordedEvent},
    state_bounds::{self, CURRENT_VIEW, PeerVote, TRACKED_VIEWS, VoteKind},
};
use commonware_cryptography::{ed25519, sha256::Digest as Sha256Digest};
use commonware_parallel::Sequential;
use commonware_utils::{NZU32, non_empty, test_rng};
use std::panic::{self, AssertUnwindSafe};

type MockScheme = certificate_mock::Scheme<ed25519::PublicKey>;

fn term_length(value: u32) -> TermLength {
    TermLength::new(NZU32!(value))
}

fn panic_text(f: impl FnOnce()) -> String {
    let payload = panic::catch_unwind(AssertUnwindSafe(f)).expect_err("the control must panic");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&'static str>()
                .map(|s| (*s).to_owned())
        })
        .unwrap_or_else(|| "<non-string panic>".to_owned())
}

fn round(view: u64) -> Round {
    Round::new(Epoch::new(EPOCH), View::new(view))
}

fn proposal(view: u64, payload: u8) -> Proposal<Sha256Digest> {
    Proposal::new(
        round(view),
        View::new(view.saturating_sub(1)),
        Sha256Digest::from([payload; 32]),
    )
}

fn recorded(
    sequence: u64,
    activity: Activity<MockScheme, Sha256Digest>,
) -> RecordedEvent<MockScheme, Sha256Digest> {
    RecordedEvent {
        sequence,
        generation: 0,
        event: Event::Activity {
            valid: true,
            activity,
        },
    }
}

fn finalization(schemes: &[MockScheme], view: u64) -> Finalization<MockScheme, Sha256Digest> {
    let proposal = proposal(view, view as u8);
    let votes: Vec<_> = schemes[..3]
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("mock signing succeeds"))
        .collect();
    Finalization::from_finalizes(&schemes[0], non_empty![@&votes], &Sequential)
        .expect("three of four votes form a finalization")
}

#[test]
fn c6_t1_t4_gauge_reader_and_admission_bound() {
    let metrics = r#"
test_engine_voter_state_current_view{public_key="a",role="engine"} 0
test_engine_voter_state_tracked_views{public_key="a",role="engine"} 7
test_engine_voter_state_current_view{public_key="b",role="engine"} 9
test_engine_voter_state_tracked_views{public_key="b",role="engine"} 11
twins_engine_voter_state_current_view{index="1",public_key="shared"} 12
twins_engine_voter_state_current_view{index="2",public_key="shared"} 13
"#;
    let a = state_bounds::Node::public_key(&"a");
    assert_eq!(state_bounds::gauge(metrics, CURRENT_VIEW, &a), 0);
    assert_eq!(state_bounds::gauge(metrics, TRACKED_VIEWS, &a), 7);
    assert_eq!(
        state_bounds::gauge(metrics, CURRENT_VIEW, &state_bounds::Node::index(1)),
        12
    );
    assert_eq!(
        state_bounds::gauge(metrics, CURRENT_VIEW, &state_bounds::Node::index(2)),
        13
    );
    let missing = panic_text(|| {
        state_bounds::gauge(metrics, "engine_missing_gauge", &a);
    });
    assert!(missing.contains("engine_missing_gauge"), "{missing}");

    let examples = [
        (10, 20, 2, 24),
        (19, 20, 2, 24),
        (5, 1, 0, 8),
        (6, 5, 0, 13),
        (1, 5, 0, 8),
    ];
    for (g, l, k, expected) in examples {
        assert_eq!(
            state_bounds::admission_bound(View::new(g), term_length(l), ViewDelta::new(k)),
            View::new(expected)
        );
    }
    for l in 1u32..=7 {
        for k in 0..=u64::from(l) + 2 {
            let mut previous = None;
            for g in 0u64..60 {
                let next_term_start = if g == 0 {
                    1
                } else {
                    ((g - 1) / u64::from(l) * u64::from(l)) + u64::from(l) + 1
                };
                let expected = next_term_start + k.max(1).min(u64::from(l)) + 1;
                let actual =
                    state_bounds::admission_bound(View::new(g), term_length(l), ViewDelta::new(k));
                assert_eq!(actual, View::new(expected), "g={g} L={l} k={k}");
                if let Some(previous) = previous {
                    assert!(actual >= previous, "bound decreased at g={g} L={l} k={k}");
                }
                previous = Some(actual);
            }
        }
    }
}

#[test]
fn c6_export_log_and_second_finalization() {
    let fixture = certificate_mock::fixture(&mut test_rng(), b"c6-acceptance-log", 4);
    let schemes = fixture.schemes;
    let self_vote = Notarize::sign(&schemes[0], proposal(2, 1)).unwrap();
    let peer_notarize = Notarize::sign(&schemes[1], proposal(3, 2)).unwrap();
    let peer_nullify = Nullify::<MockScheme>::sign::<Sha256Digest>(&schemes[2], round(4)).unwrap();
    let peer_finalize = Finalize::sign(&schemes[3], proposal(5, 3)).unwrap();
    let me = self_vote.signer();
    let events = vec![
        recorded(0, Activity::Notarize(self_vote)),
        recorded(1, Activity::Finalization(finalization(&schemes, 1))),
        recorded(2, Activity::Nullify(peer_nullify.clone())),
        recorded(3, Activity::Notarize(peer_notarize.clone())),
        recorded(4, Activity::Finalize(peer_finalize.clone())),
    ];
    let peers = state_bounds::peer_votes(&events, me);
    assert_eq!(peers.len(), 3);
    assert_eq!(
        peers.iter().map(|vote| vote.kind).collect::<Vec<_>>(),
        vec![VoteKind::Nullify, VoteKind::Notarize, VoteKind::Finalize]
    );
    assert_eq!(peers[0].signer, peer_nullify.signer());
    assert_eq!(peers[1].signer, peer_notarize.signer());
    assert_eq!(peers[2].signer, peer_finalize.signer());

    let no_finalizations = vec![recorded(0, Activity::Finalize(peer_finalize.clone()))];
    assert_eq!(
        state_bounds::second_finalization(&no_finalizations),
        View::zero()
    );
    let one = vec![recorded(
        0,
        Activity::Finalization(finalization(&schemes, 5)),
    )];
    assert_eq!(state_bounds::second_finalization(&one), View::zero());
    let mixed = vec![
        recorded(0, Activity::Finalization(finalization(&schemes, 5))),
        recorded(1, Activity::Finalize(peer_finalize)),
        recorded(2, Activity::Finalization(finalization(&schemes, 12))),
        recorded(3, Activity::Nullify(peer_nullify)),
        recorded(4, Activity::Finalization(finalization(&schemes, 9))),
    ];
    assert_eq!(state_bounds::second_finalization(&mixed), View::new(9));
    let bound = state_bounds::check_retention(
        10,
        View::new(20),
        term_length(5),
        ViewDelta::zero(),
        state_bounds::second_finalization(&mixed),
    )
    .unwrap();
    assert_eq!(
        bound,
        state_bounds::retained_bound(
            state_bounds::admission_bound(View::new(20), term_length(5), ViewDelta::zero()),
            View::new(9),
        )
    );
}

#[test]
fn c6_n1_n2_n3_checker_boundaries() {
    let signer = Participant::new(1);
    let other = Participant::new(2);
    let payload_a = Sha256Digest::from([1; 32]);
    let payload_b = Sha256Digest::from([2; 32]);
    let vote = |kind, view, signer, payload| PeerVote {
        kind,
        view: View::new(view),
        signer,
        payload,
    };
    let bound = View::new(24);
    assert!(
        state_bounds::check_admission(
            &[vote(VoteKind::Notarize, 24, signer, Some(payload_a))],
            bound
        )
        .is_ok()
    );
    let error = state_bounds::check_admission(
        &[vote(VoteKind::Notarize, 25, signer, Some(payload_a))],
        bound,
    )
    .unwrap_err();
    assert!(error.starts_with("C6-I1"));

    assert!(
        state_bounds::check_uniqueness(&[vote(VoteKind::Notarize, 7, signer, Some(payload_a))])
            .is_ok()
    );
    for pair in [
        vec![
            vote(VoteKind::Notarize, 7, signer, Some(payload_a)),
            vote(VoteKind::Notarize, 7, signer, Some(payload_a)),
        ],
        vec![
            vote(VoteKind::Notarize, 7, signer, Some(payload_a)),
            vote(VoteKind::Notarize, 7, signer, Some(payload_b)),
        ],
    ] {
        assert!(
            state_bounds::check_uniqueness(&pair)
                .unwrap_err()
                .starts_with("C6-I2")
        );
    }
    assert!(
        state_bounds::check_uniqueness(&[
            vote(VoteKind::Notarize, 7, signer, Some(payload_a)),
            vote(VoteKind::Finalize, 7, signer, Some(payload_a)),
        ])
        .is_ok()
    );
    assert!(
        state_bounds::check_uniqueness(&[
            vote(VoteKind::Notarize, 7, signer, Some(payload_a)),
            vote(VoteKind::Notarize, 7, other, Some(payload_a)),
        ])
        .is_ok()
    );

    for (g, l, k, f2) in [(0, 1, 0, 0), (10, 20, 2, 0), (50, 5, 7, 42)] {
        let admission =
            state_bounds::admission_bound(View::new(g), term_length(l), ViewDelta::new(k));
        let expected = state_bounds::retained_bound(admission, View::new(f2));
        assert_eq!(
            state_bounds::check_retention(
                expected,
                View::new(g),
                term_length(l),
                ViewDelta::new(k),
                View::new(f2),
            ),
            Ok(expected)
        );
        let error = state_bounds::check_retention(
            expected + 1,
            View::new(g),
            term_length(l),
            ViewDelta::new(k),
            View::new(f2),
        )
        .unwrap_err();
        assert!(error.starts_with("C6-I3"));
    }
    assert_eq!(state_bounds::retained_bound(View::new(8), View::zero()), 8);
}
