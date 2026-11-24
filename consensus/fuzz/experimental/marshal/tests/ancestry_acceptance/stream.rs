use super::*;
use arbitrary::Unstructured;
use commonware_consensus::types::{Epoch, Height, Round, View};

fn input(
    top: u8,
    initial: u8,
    answers: &[(usize, Answer)],
    ops: Vec<StreamOp>,
    bound: Option<u64>,
) -> AncestryStreamInput {
    let mut plan = [Answer::Now; CHAIN_LEN];
    for (height, answer) in answers {
        plan[*height] = *answer;
    }
    AncestryStreamInput {
        raw_bytes: Vec::new(),
        top,
        initial,
        plan,
        ops,
        bound,
    }
}

fn polls(events: &[StreamEvent], kind: StreamKind) -> Vec<PollOutcome> {
    events
        .iter()
        .filter_map(|event| match event {
            StreamEvent::Poll { stream, outcome } if *stream == kind => Some(*outcome),
            _ => None,
        })
        .collect()
}

fn peeks(events: &[StreamEvent], kind: StreamKind) -> Vec<Option<u64>> {
    events
        .iter()
        .filter_map(|event| match event {
            StreamEvent::Peek { stream, height } if *stream == kind => {
                Some(height.map(Height::get))
            }
            _ => None,
        })
        .collect()
}

fn yielded(heights: &[u64]) -> Vec<PollOutcome> {
    heights
        .iter()
        .map(|height| PollOutcome::Yielded(Height::new(*height)))
        .collect()
}

fn then_ended(mut outcomes: Vec<PollOutcome>, len: usize) -> Vec<PollOutcome> {
    outcomes.resize(len, PollOutcome::Ended);
    outcomes
}

#[test]
fn at_030_leading_bytes_seed_deterministic_runs_without_consumption() {
    let bytes = [7, 4, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5, 1, 0, 9, 8, 7];
    let decode = || AncestryStreamInput::arbitrary(&mut Unstructured::new(&bytes)).unwrap();
    let decoded = decode();
    assert_eq!(decoded.raw_bytes, bytes[..bytes.len().min(MAX_RAW_BYTES)]);
    assert_eq!((decoded.top, decoded.initial), (1, 1));
    let first = run_ancestry_stream(decode()).0;
    let second = run_ancestry_stream(decode()).0;
    assert_eq!(first, second);
    assert_eq!(
        first
            .iter()
            .filter(|event| matches!(event, StreamEvent::TimedRegistered { label: "ancestry" }))
            .count(),
        1,
    );
}

#[test]
fn at_031_initial_sequences_and_bounds() {
    for top in 1..CHAIN_LEN as u8 {
        for initial in 1..=top + 1 {
            for bound in [None, Some(37)] {
                let events =
                    run_ancestry_stream(input(top, initial, &[], vec![StreamOp::Next], bound)).0;
                let expected: Vec<_> = (0..u64::from(initial))
                    .map(|offset| PollOutcome::Yielded(Height::new(u64::from(top) - offset)))
                    .collect();
                assert_eq!(
                    &polls(&events, StreamKind::Original)[..usize::from(initial)],
                    expected.as_slice(),
                    "top={top} initial={initial} bound={bound:?}",
                );
                let want = bound.map(|view| Round::new(Epoch::zero(), View::new(view)));
                let calls = events.iter().find_map(|event| match event {
                    StreamEvent::ProviderCalls(calls) => Some(calls),
                    _ => None,
                });
                assert!(calls.unwrap().iter().all(|(_, seen)| *seen == want));
            }
        }
    }
}

#[test]
fn at_032_immediate_and_pending_polls_cover_original_and_clone() {
    let immediate = run_ancestry_stream(input(
        2,
        1,
        &[],
        vec![StreamOp::Clone, StreamOp::Next, StreamOp::NextClone],
        None,
    ))
    .0;
    assert!(matches!(
        polls(&immediate, StreamKind::Original)[0],
        PollOutcome::Yielded(_)
    ));
    assert!(matches!(
        polls(&immediate, StreamKind::Clone)[0],
        PollOutcome::Yielded(_)
    ));

    let pending = run_ancestry_stream(input(
        2,
        1,
        &[(2, Answer::Never)],
        vec![
            StreamOp::Next,
            StreamOp::Clone,
            StreamOp::Next,
            StreamOp::NextClone,
        ],
        None,
    ))
    .0;
    assert!(polls(&pending, StreamKind::Original).contains(&PollOutcome::Pending));
    assert!(polls(&pending, StreamKind::Clone).contains(&PollOutcome::Pending));
}

#[test]
fn at_033_release_completes_only_matching_receivers() {
    let blocks = std::sync::Arc::new(chain());
    let provider = ScriptedProvider {
        chain: blocks.clone(),
        plan: [Answer::Later; CHAIN_LEN],
        state: std::sync::Arc::default(),
    };
    let mut first = Box::pin(provider.subscribe_parent(&blocks[5], None));
    let mut second = Box::pin(provider.subscribe_parent(&blocks[5], None));
    let mut other = Box::pin(provider.subscribe_parent(&blocks[4], None));
    assert!(first.as_mut().now_or_never().is_none());
    assert!(second.as_mut().now_or_never().is_none());
    assert!(other.as_mut().now_or_never().is_none());
    assert_eq!(provider.release(Height::new(13 % 8)), 2);
    assert_eq!(first.as_mut().now_or_never().unwrap().unwrap(), blocks[4]);
    assert_eq!(second.as_mut().now_or_never().unwrap().unwrap(), blocks[4]);
    assert!(other.as_mut().now_or_never().is_none());
}

#[test]
fn at_034_prefix_formula_and_streams_are_total() {
    for blocks in u8::MIN..=u8::MAX {
        let n = usize::from(blocks) % 3 + 1;
        let k = (usize::from(blocks) / 3) % (CHAIN_LEN - n);
        assert!(k + n < CHAIN_LEN);
        let events =
            run_ancestry_stream(input(1, 1, &[], vec![StreamOp::Prefix { blocks }], None)).0;
        let prefix: Vec<_> = (k + 1..=k + n).rev().map(|height| height as u64).collect();
        let mut prefixed = prefix.clone();
        prefixed.extend((0..=k as u64).rev());
        assert_eq!(
            polls(&events, StreamKind::Prefixed)
                .into_iter()
                .filter_map(|outcome| match outcome {
                    PollOutcome::Yielded(height) => Some(height.get()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            prefixed,
        );
        assert_eq!(
            polls(&events, StreamKind::FromIter)
                .into_iter()
                .filter_map(|outcome| match outcome {
                    PollOutcome::Yielded(height) => Some(height.get()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            prefix,
        );
    }
}

#[test]
fn at_035_037_ready_chains_reach_genesis_for_every_initial_count() {
    for initial in 1..=4 {
        let events = run_ancestry_stream(input(3, initial, &[], vec![StreamOp::Next], None)).0;
        assert_eq!(
            polls(&events, StreamKind::Original),
            then_ended(yielded(&[3, 2, 1, 0]), 1 + FINAL_WALK),
        );
    }
}

#[test]
fn at_039_041_wrong_or_missing_parent_ends_without_yielding_it() {
    for answer in [Answer::WrongHeight, Answer::WrongDigest, Answer::End] {
        let events = run_ancestry_stream(input(3, 1, &[(3, answer)], vec![StreamOp::Next], None)).0;
        assert_eq!(
            polls(&events, StreamKind::Original),
            then_ended(yielded(&[3]), 1 + FINAL_WALK),
        );
    }
}

#[test]
fn at_043_never_and_unreleased_later_stay_pending() {
    for answer in [Answer::Never, Answer::Later] {
        let events = run_ancestry_stream(input(
            3,
            1,
            &[(3, answer)],
            vec![StreamOp::Next, StreamOp::Next, StreamOp::Next],
            None,
        ))
        .0;
        let outcomes = polls(&events, StreamKind::Original);
        assert_eq!(outcomes[0], PollOutcome::Yielded(Height::new(3)));
        assert!(
            outcomes[1..]
                .iter()
                .all(|outcome| *outcome == PollOutcome::Pending)
        );
    }
}

#[test]
fn at_045_released_parent_is_the_next_yield() {
    let events = run_ancestry_stream(input(
        3,
        1,
        &[(3, Answer::Later)],
        vec![
            StreamOp::Next,
            StreamOp::Next,
            StreamOp::Release { height: 3 },
            StreamOp::Next,
        ],
        None,
    ))
    .0;
    let outcomes = polls(&events, StreamKind::Original);
    assert_eq!(
        &outcomes[..3],
        &[
            PollOutcome::Yielded(Height::new(3)),
            PollOutcome::Pending,
            PollOutcome::Yielded(Height::new(2)),
        ]
    );
}

#[test]
fn at_047_peek_tracks_buffer_wait_release_and_end() {
    let events = run_ancestry_stream(input(
        3,
        2,
        &[(2, Answer::Later)],
        vec![
            StreamOp::Peek,
            StreamOp::Next,
            StreamOp::Peek,
            StreamOp::Next,
            StreamOp::Peek,
            StreamOp::Release { height: 2 },
            StreamOp::Next,
            StreamOp::Peek,
        ],
        None,
    ))
    .0;
    assert_eq!(
        peeks(&events, StreamKind::Original),
        vec![Some(3), Some(2), None, Some(0)],
    );
}

#[test]
fn at_049_clone_sequences_match_from_both_clone_points() {
    let buffered = run_ancestry_stream(input(
        3,
        2,
        &[],
        vec![StreamOp::Clone, StreamOp::Next, StreamOp::NextClone],
        None,
    ))
    .0;
    assert!(buffered.iter().any(|event| matches!(
        event,
        StreamEvent::Sequences {
            original,
            original_ended: true,
            clone: Some((cloned, true)),
        } if original == cloned && original.iter().map(|height| height.get()).collect::<Vec<_>>() == [3, 2, 1, 0]
    )));

    let waiting = run_ancestry_stream(input(
        3,
        1,
        &[(3, Answer::Later)],
        vec![
            StreamOp::Next,
            StreamOp::Clone,
            StreamOp::Release { height: 3 },
            StreamOp::Next,
        ],
        None,
    ))
    .0;
    assert!(waiting.iter().any(|event| matches!(
        event,
        StreamEvent::Sequences {
            original,
            original_ended: true,
            clone: Some((cloned, true)),
        } if original == cloned && original.iter().map(|height| height.get()).collect::<Vec<_>>() == [2, 1, 0]
    )));
}

#[test]
fn at_051_053_prefix_and_from_iter_orders() {
    let events =
        run_ancestry_stream(input(1, 1, &[], vec![StreamOp::Prefix { blocks: 3 }], None)).0;
    assert_eq!(
        polls(&events, StreamKind::Prefixed),
        then_ended(yielded(&[2, 1, 0]), 4),
    );
    assert_eq!(
        peeks(&events, StreamKind::Prefixed),
        vec![Some(2), Some(1), Some(0), None],
    );
    assert_eq!(
        polls(&events, StreamKind::FromIter),
        then_ended(yielded(&[2]), 2),
    );

    let fixed = run_ancestry_stream(input(1, 1, &[], vec![StreamOp::Prefix { blocks: 5 }], None)).0;
    assert_eq!(
        polls(&fixed, StreamKind::FromIter),
        then_ended(yielded(&[4, 3, 2]), 4),
    );
}

#[test]
fn at_056_empty_and_zero_inputs_reach_genesis() {
    for bytes in [&[][..], &[0][..]] {
        let decoded = AncestryStreamInput::arbitrary(&mut Unstructured::new(bytes)).unwrap();
        assert_eq!((decoded.top, decoded.initial), (1, 1));
        assert_eq!(decoded.plan, [Answer::Now; CHAIN_LEN]);
        assert_eq!(decoded.ops, vec![StreamOp::Next]);
        let events = run_ancestry_stream(decoded).0;
        assert_eq!(
            polls(&events, StreamKind::Original),
            then_ended(yielded(&[1, 0]), 1 + FINAL_WALK),
        );
    }
}

#[test]
fn at_058_every_answer_and_operation_is_deterministic() {
    let make = || AncestryStreamInput {
        raw_bytes: vec![1, 2, 3],
        top: 7,
        initial: 2,
        plan: [
            Answer::Now,
            Answer::Now,
            Answer::Later,
            Answer::Never,
            Answer::End,
            Answer::WrongHeight,
            Answer::WrongDigest,
            Answer::Now,
        ],
        ops: vec![
            StreamOp::Next,
            StreamOp::Peek,
            StreamOp::Release { height: 2 },
            StreamOp::Clone,
            StreamOp::NextClone,
            StreamOp::Prefix { blocks: 3 },
        ],
        bound: Some(37),
    };
    assert_eq!(run_ancestry_stream(make()).0, run_ancestry_stream(make()).0);
}

#[test]
fn at_059_all_six_provider_answers_are_legal_inputs() {
    for answer in [
        Answer::Now,
        Answer::Later,
        Answer::Never,
        Answer::End,
        Answer::WrongHeight,
        Answer::WrongDigest,
    ] {
        let _ = run_ancestry_stream(input(3, 1, &[(3, answer)], vec![StreamOp::Next], None));
    }
}

#[test]
fn at_066_public_driver_entry_is_usable() {
    let public_input = input(1, 1, &[], vec![StreamOp::Next], None);
    crate::marshal::fuzz_marshal_ancestry_stream(public_input);
}
