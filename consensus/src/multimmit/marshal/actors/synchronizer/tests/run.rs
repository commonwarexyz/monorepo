//! Synchronization run-loop hint coalescing and overflow tests.

use super::*;

/// Returns the first `n - f` participants.
fn quorum(committee: &Committee<MinPk>) -> std::ops::Range<usize> {
    0..committee.codec().view_quorum()
}

/// Returns the L-QC of view `view + 1`, which pins `records[view - 1]`.
fn pinning(
    committee: &Committee<MinPk>,
    records: &[Arc<HistoryRecord<Sha256Digest>>],
    view: usize,
) -> Arc<Lqc<MinPk, Sha256Digest>> {
    lqc(
        committee,
        view as u64 + 1,
        records[view - 1].commitment::<Sha256>(),
        quorum(committee),
    )
}

#[rstest]
#[case(true, true)]
#[case(true, false)]
#[case(false, true)]
#[case(false, false)]
fn synchronization_hints_link_only_distinct_spans(#[case] queued: bool, #[case] shared_span: bool) {
    let recorder = SpanRecorder::default();
    with_default(registry().with(recorder.clone()), || {
        deterministic::Runner::default().start(|context| async move {
            let committee = committee(17, 2);
            let proof = genesis_lqc(&committee, quorum(&committee));
            let id = proof.id::<Sha256>();
            let actor = genesis_actor(&context, &committee, 4).await;
            let first = info_span!(parent: None, "test.first_origin");
            let second = if shared_span {
                first.clone()
            } else {
                info_span!(parent: None, "test.second_origin")
            };
            let first_id = first.id().unwrap().into_u64();
            let second_id = second.id().unwrap().into_u64();
            let hints = [first, second].map(|span| Message::Synchronize {
                span,
                target: Target::finalized(id, Arc::clone(&proof), None, 2),
            });
            let (commands, receiver) =
                mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());
            if queued {
                for hint in hints {
                    assert_eq!(commands.enqueue(hint), Feedback::Ok);
                }
                drop(commands);
                actor.into_running(receiver).run(&context).await.unwrap();
            } else {
                let mut actor = actor.into_running(receiver);
                for hint in hints {
                    actor.inbox.defer(hint).unwrap();
                }
            }
            let recorded = recorder.links();
            assert!(recorded.iter().all(|(span, cause)| span != cause));
            assert_eq!(
                recorded
                    .iter()
                    .filter(|(span, cause)| { *span == first_id && *cause == second_id })
                    .count(),
                usize::from(!shared_span),
            );
        });
    });
}

#[test]
fn run_coalesces_queued_synchronization_hints() {
    deterministic::Runner::default().start(|context| async move {
        const HINTS: usize = 64;
        let committee = committee(17, 2);
        let proof = genesis_lqc(&committee, quorum(&committee));
        let actor = genesis_actor(&context, &committee, 4).await;
        let commit_calls = Arc::clone(&actor.catalog.commit_calls);
        let (commands, receiver) = mailbox::new(
            context.child("mailbox"),
            NonZeroUsize::new(HINTS).expect("the hint count is non-zero"),
        );
        for _ in 0..HINTS {
            assert_eq!(commands.enqueue(finalize_message(&proof)), Feedback::Ok);
        }
        drop(commands);

        actor.into_running(receiver).run(&context).await.unwrap();

        assert_eq!(commit_calls.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn run_merges_queued_targets_into_the_highest_view_before_fetching_history() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(18, 2);
        let records = genesis_views(&committee, 3);
        let lower = pinning(&committee, &records, 1);
        let higher = pinning(&committee, &records, 3);
        let actor = genesis_actor(&context, &committee, 4).await;
        let commit_calls = Arc::clone(&actor.catalog.commit_calls);
        let history_calls = Arc::clone(&actor.fetcher.history_calls);
        let selected = Arc::clone(&actor.catalog.selected_calls);
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());
        assert_eq!(commands.enqueue(finalize_message(&lower)), Feedback::Ok);
        assert_eq!(commands.enqueue(finalize_message(&higher)), Feedback::Ok);
        drop(commands);

        actor.into_running(receiver).run(&context).await.unwrap();

        // One pass opens views one through three with one history fetch, and selects each proof
        // as the opening it pins is recorded: the lower one's commit names view one's history.
        assert_eq!(commit_calls.load(Ordering::Relaxed), 2);
        assert_eq!(history_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            *selected.lock(),
            vec![lower.id::<Sha256>(), higher.id::<Sha256>()]
        );
    });
}

#[test]
fn run_pipelines_commit_across_live_synchronization_passes() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(22, 2);
        let records = genesis_views(&committee, 2);
        let first = pinning(&committee, &records, 1);
        let second = pinning(&committee, &records, 2);
        let mut actor = genesis_actor(&context, &committee, 4).await;
        let waiters = Arc::new(Mutex::new(VecDeque::new()));
        actor.catalog.commit_waiters = Some(Arc::clone(&waiters));
        let commit_calls = Arc::clone(&actor.catalog.commit_calls);
        let (started, first_started) = oneshot::channel();
        let (release_first, release) = oneshot::channel();
        actor.catalog.commit_start_gate = Some((started, release));
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());

        let driver = async move {
            assert_eq!(commands.enqueue(finalize_message(&first)), Feedback::Ok);
            first_started.await.unwrap();
            assert_eq!(commands.enqueue(finalize_message(&second)), Feedback::Ok);
            release_first.send(()).unwrap();

            futures::future::poll_fn(|cx| {
                if commit_calls.load(Ordering::Relaxed) == 2 {
                    std::task::Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            })
            .await;
            assert_eq!(commit_calls.load(Ordering::Relaxed), 2);
            assert_eq!(waiters.lock().len(), 2);

            let first = waiters.lock().pop_front().unwrap();
            first.send(Ok(())).unwrap();
            let second = waiters.lock().pop_front().unwrap();
            second.send(Ok(())).unwrap();
            drop(commands);
        };

        let (result, ()) = futures::join!(actor.into_running(receiver).run(&context), driver);
        result.unwrap();
    });
}

#[test]
fn run_preserves_distinct_lqcs_pinning_one_view() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(21, 2);
        let first = genesis_lqc(&committee, 0..5);
        let second = genesis_lqc(&committee, 1..6);
        let first_id = first.id::<Sha256>();
        let second_id = second.id::<Sha256>();
        assert_ne!(first_id, second_id);
        let actor = genesis_actor(&context, &committee, 4).await;
        let selected = Arc::clone(&actor.catalog.selected_calls);
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());
        for proof in [&first, &second] {
            assert_eq!(commands.enqueue(finalize_message(proof)), Feedback::Ok);
        }
        drop(commands);

        actor.into_running(receiver).run(&context).await.unwrap();

        // L-QCs pinning one view are selected together in certificate-id order.
        let mut expected = vec![first_id, second_id];
        expected.sort();
        assert_eq!(*selected.lock(), expected);
    });
}

#[test]
fn live_synchronization_uses_the_reported_proof_without_refetching_it() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(19, 2);
        let proof = genesis_lqc(&committee, quorum(&committee));
        let id = proof.id::<Sha256>();
        let mut actor = genesis_actor(&context, &committee, 4).await;
        let history_calls = Arc::clone(&actor.fetcher.history_calls);

        actor
            .synchronize_target(Target::finalized(id, proof, None, 2))
            .await
            .unwrap();

        assert_eq!(history_calls.load(Ordering::Relaxed), 1);
        assert_eq!(actor.catalog.selected, vec![id]);
    });
}

#[test]
fn recovery_synchronizes_the_latest_proof_without_refetching_it() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(19, 2);
        let genesis = committee.config.genesis();
        let proof = genesis_lqc(&committee, quorum(&committee));
        let id = proof.id::<Sha256>();
        let history = genesis_record(&committee);
        let mut catalog = mock_catalog(
            checkpoint(
                committee.config.epoch(),
                0,
                genesis.history(),
                genesis.tips().to_vec(),
                genesis.tips().to_vec(),
            ),
            MockBlocks::default(),
        );
        catalog.latest = Some(proof);
        // The fetcher serves the history but no L-QC, so recovery must use the catalog's proof.
        let fetcher = MockFetcher {
            histories: vec![(history.commitment::<Sha256>(), history)],
            blocks: Arc::new(vec![Vec::new(), Vec::new()]),
            ..MockFetcher::default()
        };

        let actor = recover(&context, catalog, fetcher, committee.codec(), 4, 32)
            .await
            .unwrap();

        assert_eq!(actor.catalog.selected, vec![id]);
        assert_eq!(actor.floor, id);
        assert_eq!(actor.state.view(), View::new(1));
    });
}

#[test]
fn synchronization_overflow_coalesces_to_the_highest_view() {
    let committee = committee(20, 2);
    let proof = genesis_lqc(&committee, quorum(&committee));
    let mut overflow = VecDeque::new();
    for value in (0..1_000).rev() {
        let id = CertificateId::new(digest(b"overflow target", value));
        let mut target = Target::finalized(id, Arc::clone(&proof), None, 1);
        target.view = View::new(value);
        Message::<MinPk, Sha256Digest>::handle(
            &mut overflow,
            Message::Synchronize {
                span: Span::none(),
                target,
            },
        );
    }

    assert_eq!(overflow.len(), 1);
    let Some(Message::Synchronize { target, .. }) = overflow.pop_front() else {
        panic!("coalesced synchronization target missing");
    };
    assert_eq!(target.view, View::new(999));
    assert!(
        target
            .proofs
            .contains_key(&CertificateId::new(digest(b"overflow target", 999)))
    );
}

#[test]
fn synchronization_overflow_bounds_adversarial_same_view_proofs() {
    let committee = committee(24, 2);
    let proof = genesis_lqc(&committee, quorum(&committee));
    let mut overflow = VecDeque::new();
    for value in 0..1_000 {
        Message::<MinPk, Sha256Digest>::handle(
            &mut overflow,
            Message::Synchronize {
                span: Span::none(),
                target: Target::finalized(
                    CertificateId::new(digest(b"same-view target", value)),
                    Arc::clone(&proof),
                    None,
                    2,
                ),
            },
        );
    }

    let Some(Message::Synchronize { target, .. }) = overflow.pop_front() else {
        panic!("coalesced synchronization target missing");
    };
    assert_eq!(target.proofs.len(), 2);
    assert!(!target.conflict);
    assert!(overflow.is_empty());
}

#[test]
fn targets_of_one_view_with_different_histories_conflict() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(25, 2);
        let records = genesis_views(&committee, 1);
        let mut target = Target::resolved(
            View::new(1),
            records[0].commitment::<Sha256>(),
            Arc::clone(&records[0]),
            2,
        );
        let other = Arc::new(
            HistoryRecord::new(digest(b"other parent", 0), records[0].tips().to_vec()).unwrap(),
        );
        target.merge(Target::resolved(
            View::new(1),
            other.commitment::<Sha256>(),
            other,
            2,
        ));
        assert!(target.conflict);

        let mut actor = genesis_actor(&context, &committee, 4).await;
        assert!(matches!(
            actor.synchronize_target(target).await,
            Err(Error::Invalid(_))
        ));
    });
}

#[test]
fn deferred_floor_install_runs_before_deferred_synchronization() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(21, 2);
        let first = genesis_lqc(&committee, 0..5);
        let second = genesis_lqc(&committee, 1..6);
        let mut actor = genesis_actor(&context, &committee, 4).await;
        // The floor reaches verification, which rejects it, so the floor leaves a mark in the call
        // log without replacing the state.
        actor.verifier.valid = false;
        actor.verifier.calls = Arc::clone(&actor.catalog.calls);
        let calls = Arc::clone(&actor.catalog.calls);
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());
        let mut actor = actor.into_running(receiver);

        // A pass deferred a target and then a floor install; a second target of the same view is
        // queued behind the floor.
        let floor = Floor::new(Arc::clone(&first), genesis_record(&committee));
        let (reply, installed) = oneshot::channel();
        for message in [
            finalize_message(&first),
            Message::InstallFloor {
                span: Span::none(),
                checkpoint: floor,
                reply,
            },
        ] {
            actor.inbox.defer(message).unwrap();
        }
        assert_eq!(commands.enqueue(finalize_message(&second)), Feedback::Ok);
        drop(commands);

        actor.run(&context).await.unwrap();

        // The floor install ran first, and then the deferred target, which took in the target
        // queued behind the floor.
        assert!(matches!(installed.await, Ok(Err(Error::Verify(_)))));
        assert_eq!(*calls.lock(), ["verify", "commit"]);
    });
}

#[test]
fn run_stops_ahead_of_deferred_passes() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(27, 2);
        let proof = genesis_lqc(&committee, quorum(&committee));
        let actor = genesis_actor(&context, &committee, 4).await;
        let commit_calls = Arc::clone(&actor.catalog.commit_calls);
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());
        let mut actor = actor.into_running(receiver);
        actor.inbox.defer(finalize_message(&proof)).unwrap();

        let handle = context
            .child("synchronizer")
            .spawn(move |context| async move { actor.run(&context).await });
        context.stop(0, Some(Duration::from_secs(1))).await.unwrap();

        assert!(matches!(handle.await, Ok(Ok(()))));
        assert_eq!(commit_calls.load(Ordering::Relaxed), 0);
        drop(commands);
    });
}

#[test]
fn deferred_floor_install_stops_intake() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(26, 2);
        let records = genesis_views(&committee, 2);
        let first = pinning(&committee, &records, 1);
        let second = pinning(&committee, &records, 2);
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(4).unwrap());
        let mut inbox = TestInbox::new(receiver);
        let (reply, _installed) = oneshot::channel();
        let floor = Floor::new(Arc::clone(&first), Arc::clone(&records[0]));
        for message in [
            finalize_message(&first),
            Message::InstallFloor {
                span: Span::none(),
                checkpoint: floor,
                reply,
            },
            finalize_message(&second),
        ] {
            assert_eq!(commands.enqueue(message), Feedback::Ok);
        }

        assert!(inbox.absorb().await.unwrap().is_none());
        assert!(inbox.absorb().await.unwrap().is_none());
        assert!(!inbox.can_receive());
        assert!(inbox.try_recv().is_none());

        assert!(matches!(
            inbox.next_deferred(),
            Some(Message::InstallFloor { .. })
        ));
        let Some(Message::Synchronize { target, .. }) = inbox.next_deferred() else {
            panic!("deferred synchronization missing");
        };
        assert_eq!(target.view, View::new(1));
        assert!(inbox.can_receive());
        let Some(Message::Synchronize { target, .. }) = inbox.try_recv() else {
            panic!("queued synchronization missing");
        };
        assert_eq!(target.view, View::new(2));
    });
}
