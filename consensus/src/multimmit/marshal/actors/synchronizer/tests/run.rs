//! Synchronization run-loop hint coalescing and overflow tests.

use super::*;
use crate::types::Participant;

#[rstest]
#[case(true, true)]
#[case(true, false)]
#[case(false, true)]
#[case(false, false)]
fn synchronization_hints_link_only_distinct_spans(#[case] queued: bool, #[case] shared_span: bool) {
    let recorder = SpanRecorder::default();
    with_default(registry().with(recorder.clone()), || {
        deterministic::Runner::default().start(|context| async move {
            let committee = committee(17, 2, PathLimits::new(2, 1).unwrap());
            let proof = Arc::new(committee.lqc(View::new(1)));
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
                batch: FinalityBatch::new(id, Arc::clone(&proof), 2),
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
        let committee = committee(17, 2, PathLimits::new(2, 1).unwrap());
        let proof = Arc::new(committee.lqc(View::new(1)));
        let id = proof.id::<Sha256>();
        let actor = genesis_actor(&context, &committee, 4).await;
        let commit_calls = Arc::clone(&actor.catalog.commit_calls);
        let (commands, receiver) = mailbox::new(
            context.child("mailbox"),
            NonZeroUsize::new(HINTS).expect("the hint count is non-zero"),
        );
        for _ in 0..HINTS {
            assert_eq!(
                commands.enqueue(Message::Synchronize {
                    span: Span::none(),
                    batch: FinalityBatch::new(id, Arc::clone(&proof), HINTS,)
                }),
                Feedback::Ok
            );
        }
        drop(commands);

        actor.into_running(receiver).run(&context).await.unwrap();

        assert_eq!(commit_calls.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn run_batches_distinct_queued_synchronization_hints() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(18, 2, PathLimits::new(2, 1).unwrap());
        let first = Arc::new(committee.lqc(View::new(1)));
        let second = Arc::new(committee.lqc(View::new(2)));
        let first_id = first.id::<Sha256>();
        let second_id = second.id::<Sha256>();
        let actor = genesis_actor(&context, &committee, 4).await;
        let commit_calls = Arc::clone(&actor.catalog.commit_calls);
        let history_calls = Arc::clone(&actor.fetcher.history_calls);
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());
        assert_eq!(
            commands.enqueue(Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(first_id, first, 2,)
            }),
            Feedback::Ok
        );
        assert_eq!(
            commands.enqueue(Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(second_id, second, 2)
            }),
            Feedback::Ok
        );
        drop(commands);

        actor.into_running(receiver).run(&context).await.unwrap();

        assert_eq!(commit_calls.load(Ordering::Relaxed), 1);
        assert_eq!(history_calls.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn run_coalesces_finality_before_fetching_history() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(23, 2, PathLimits::new(2, 1).unwrap());
        let genesis = committee.config.genesis();
        let lower = Arc::new(committee.lqc(View::new(1)));
        let parent = committee.vqc(View::new(2));
        let leader = committee.leader_block_with_parent(View::new(3), &parent);
        let votes = (0..committee.codec().view_quorum())
            .map(|signer| committee.vote(Participant::from_usize(signer), &leader))
            .collect::<Vec<_>>();
        let higher = Arc::new(
            committee
                .verifier
                .assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential)
                .unwrap(),
        );
        let parent_record = Arc::new(
            TipRecord::at_tips(parent.leader().history(), genesis.tips().to_vec()).unwrap(),
        );
        assert_eq!(
            parent_record.commitment::<Sha256>(),
            higher.leader().history()
        );
        let mut actor = genesis_actor(&context, &committee, 4).await;
        actor
            .fetcher
            .histories
            .push((parent_record.commitment::<Sha256>(), parent_record));
        let selected = Arc::clone(&actor.catalog.selected_calls);
        let history_calls = Arc::clone(&actor.fetcher.history_calls);
        let higher_id = higher.id::<Sha256>();
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());
        assert_eq!(
            commands.enqueue(Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(lower.id::<Sha256>(), lower, 2,)
            }),
            Feedback::Ok
        );
        assert_eq!(
            commands.enqueue(Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(higher_id, higher, 2)
            }),
            Feedback::Ok
        );
        drop(commands);

        actor.into_running(receiver).run(&context).await.unwrap();

        assert_eq!(*selected.lock(), vec![higher_id]);
        assert_eq!(history_calls.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn run_classifies_drained_finality_against_the_merged_pass_view() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(24, 2, PathLimits::new(2, 1).unwrap());
        let tips = committee.config.genesis().tips().to_vec();
        let first = Arc::new(committee.lqc(View::new(1)));
        let second = Arc::new(committee.lqc(View::new(2)));
        let second_fact = pool_fact(&committee, &second, tips.clone());
        let third_fact = pool_fact(&committee, &committee.lqc(View::new(3)), tips);
        let actor = genesis_actor(&context, &committee, 4).await;
        let proofs = Arc::clone(&actor.catalog.selected_calls);
        let sweeps = actor.metrics.final_sweeps.clone();

        // The pass to view one drains the rest of the queue: the view-two target raises it to view
        // two, so the view-two fact must stay usable while the view-three fact waits.
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(4).unwrap());
        for message in [
            Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(first.id::<Sha256>(), first, 2),
            },
            Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(second.id::<Sha256>(), Arc::clone(&second), 2),
            },
            Message::Finality {
                span: Span::none(),
                fact: second_fact,
            },
            Message::Finality {
                span: Span::none(),
                fact: third_fact,
            },
        ] {
            assert_eq!(commands.enqueue(message), Feedback::Ok);
        }
        drop(commands);

        actor.into_running(receiver).run(&context).await.unwrap();

        assert_eq!(proofs.lock().last(), Some(&second.id::<Sha256>()));
        assert_eq!(sweeps.get(), 1, "the view-two fact emits its final sweep");
    });
}

#[test]
fn run_pipelines_commit_across_live_synchronization_passes() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(22, 2, PathLimits::new(2, 1).unwrap());
        let first = Arc::new(committee.lqc(View::new(1)));
        let second = Arc::new(committee.lqc(View::new(2)));
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
            assert_eq!(
                commands.enqueue(Message::Synchronize {
                    span: Span::none(),
                    batch: FinalityBatch::new(first.id::<Sha256>(), first, 2,)
                }),
                Feedback::Ok
            );
            first_started.await.unwrap();
            assert_eq!(
                commands.enqueue(Message::Synchronize {
                    span: Span::none(),
                    batch: FinalityBatch::new(second.id::<Sha256>(), second, 2,)
                }),
                Feedback::Ok
            );
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
fn run_preserves_distinct_same_view_finality() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(21, 2, PathLimits::new(2, 1).unwrap());
        let first = lqc(&committee, 1, 0..5);
        let second = lqc(&committee, 1, 1..6);
        let first_id = first.id::<Sha256>();
        let second_id = second.id::<Sha256>();
        assert_ne!(first_id, second_id);
        let actor = genesis_actor(&context, &committee, 4).await;
        let selected = Arc::clone(&actor.catalog.selected_calls);
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());
        for (id, proof) in [(first_id, first), (second_id, second)] {
            assert_eq!(
                commands.enqueue(Message::Synchronize {
                    span: Span::none(),
                    batch: FinalityBatch::new(id, proof, 2)
                }),
                Feedback::Ok
            );
        }
        drop(commands);

        actor.into_running(receiver).run(&context).await.unwrap();

        // Same-view proofs are resolved together in certificate-id order.
        let mut expected = vec![first_id, second_id];
        expected.sort();
        assert_eq!(*selected.lock(), expected);
    });
}

#[test]
fn live_synchronization_uses_the_reported_proof_without_refetching_it() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(19, 2, PathLimits::new(2, 1).unwrap());
        let genesis = committee.config.genesis();
        let proof = Arc::new(committee.lqc(View::new(1)));
        let id = proof.id::<Sha256>();
        let history = genesis_record(&committee);
        assert_eq!(history.commitment::<Sha256>(), proof.leader().history());
        let mut actor = actor(
            &context,
            checkpoint(
                committee.config.epoch(),
                genesis_history::<Sha256>(genesis),
                genesis.tips().to_vec(),
                genesis.tips().to_vec(),
            ),
            vec![Vec::new(), Vec::new()],
            committee.codec(),
            4,
        )
        .await;
        let history_calls = Arc::clone(&actor.fetcher.history_calls);
        actor
            .fetcher
            .histories
            .push((history.commitment::<Sha256>(), history));

        actor
            .synchronize_proofs(BTreeMap::from([(id, proof)]))
            .await
            .unwrap();

        assert_eq!(history_calls.load(Ordering::Relaxed), 1);
        assert_eq!(actor.catalog.selected, vec![id]);
    });
}

#[test]
fn recovery_synchronizes_the_latest_proof_without_refetching_it() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(19, 2, PathLimits::new(2, 1).unwrap());
        let genesis = committee.config.genesis();
        let proof = Arc::new(committee.lqc(View::new(1)));
        let id = proof.id::<Sha256>();
        let history = genesis_record(&committee);
        assert_eq!(history.commitment::<Sha256>(), proof.leader().history());
        let mut catalog = mock_catalog(
            checkpoint(
                committee.config.epoch(),
                genesis_history::<Sha256>(genesis),
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
    });
}

#[test]
fn synchronization_overflow_coalesces_to_the_highest_view() {
    let committee = committee(20, 2, PathLimits::new(2, 1).unwrap());
    let proof = Arc::new(committee.lqc(View::new(1)));
    let mut overflow = VecDeque::new();
    for value in (0..1_000).rev() {
        let id = CertificateId::new(digest(b"overflow target", value));
        let mut batch = FinalityBatch::new(id, Arc::clone(&proof), 1);
        batch.view = View::new(value);
        Message::<MinPk, Sha256Digest>::handle(
            &mut overflow,
            Message::Synchronize {
                span: Span::none(),
                batch,
            },
        );
    }

    assert_eq!(overflow.len(), 1);
    let Some(Message::Synchronize { batch, .. }) = overflow.pop_front() else {
        panic!("coalesced synchronization target missing");
    };
    assert_eq!(batch.view, View::new(999));
    assert!(
        batch
            .proofs
            .contains_key(&CertificateId::new(digest(b"overflow target", 999)))
    );
}

#[test]
fn synchronization_overflow_bounds_adversarial_same_view_proofs() {
    let committee = committee(24, 2, PathLimits::new(2, 1).unwrap());
    let proof = Arc::new(committee.lqc(View::new(1)));
    let mut overflow = VecDeque::new();
    for value in 0..1_000 {
        Message::<MinPk, Sha256Digest>::handle(
            &mut overflow,
            Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(
                    CertificateId::new(digest(b"same-view target", value)),
                    Arc::clone(&proof),
                    2,
                ),
            },
        );
    }

    let Some(Message::Synchronize { batch, .. }) = overflow.pop_front() else {
        panic!("coalesced synchronization target missing");
    };
    assert_eq!(batch.proofs.len(), 2);
    assert!(overflow.is_empty());
}

#[test]
fn deferred_floor_install_holds_back_later_synchronization() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(21, 2, PathLimits::new(2, 1).unwrap());
        let first = lqc(&committee, 1, 0..5);
        let second = lqc(&committee, 1, 1..6);
        let first_id = first.id::<Sha256>();
        let second_id = second.id::<Sha256>();
        let mut actor = genesis_actor(&context, &committee, 4).await;
        // The floor anchor reaches verification, which rejects it, so the floor leaves a mark in
        // the call log without replacing the state.
        actor.verifier.valid = false;
        actor.verifier.calls = Arc::clone(&actor.catalog.calls);
        let calls = Arc::clone(&actor.catalog.calls);
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());
        let mut actor = actor.into_running(receiver);

        // A pass deferred a same-view target and then a floor install; a second same-view target
        // is queued behind the floor.
        let anchor = lqc(&committee, 2, 0..5);
        let floor = Floor::new(
            anchor,
            genesis_record(&committee),
            committee.config.genesis().tips().to_vec(),
        );
        let (reply, installed) = oneshot::channel();
        for message in [
            Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(first_id, first, 2),
            },
            Message::InstallFloor {
                span: Span::none(),
                checkpoint: floor,
                reply,
            },
        ] {
            actor.inbox.defer(message).unwrap();
        }
        assert_eq!(
            commands.enqueue(Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(second_id, second, 2),
            }),
            Feedback::Ok
        );
        drop(commands);

        actor.run(&context).await.unwrap();

        // The queued target did not merge into the deferred pass: it ran on its own, after the
        // floor install.
        assert!(matches!(installed.await, Ok(Err(Error::Verify(_)))));
        assert_eq!(*calls.lock(), ["commit", "verify", "commit"]);
    });
}

#[test]
fn run_stops_ahead_of_deferred_passes() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(27, 2, PathLimits::new(2, 1).unwrap());
        let proof = Arc::new(committee.lqc(View::new(1)));
        let actor = genesis_actor(&context, &committee, 4).await;
        let commit_calls = Arc::clone(&actor.catalog.commit_calls);
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(2).unwrap());
        let mut actor = actor.into_running(receiver);
        actor
            .inbox
            .defer(Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(proof.id::<Sha256>(), proof, 2),
            })
            .unwrap();

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
        let committee = committee(26, 2, PathLimits::new(2, 1).unwrap());
        let first = Arc::new(committee.lqc(View::new(1)));
        let second = Arc::new(committee.lqc(View::new(2)));
        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(4).unwrap());
        let mut inbox = TestInbox::new(receiver);
        let (reply, _installed) = oneshot::channel();
        let floor = Floor::new(
            Arc::clone(&first),
            genesis_record(&committee),
            committee.config.genesis().tips().to_vec(),
        );
        for message in [
            Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(first.id::<Sha256>(), first, 2),
            },
            Message::InstallFloor {
                span: Span::none(),
                checkpoint: floor,
                reply,
            },
            Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(second.id::<Sha256>(), second, 2),
            },
        ] {
            assert_eq!(commands.enqueue(message), Feedback::Ok);
        }

        assert!(inbox.absorb().await.unwrap().is_none());
        assert!(inbox.absorb().await.unwrap().is_none());
        assert!(!inbox.can_receive());
        assert!(inbox.try_recv().is_none());

        let Some(Message::Synchronize { batch, .. }) = inbox.next_deferred() else {
            panic!("deferred synchronization missing");
        };
        assert_eq!(batch.view, View::new(1));
        assert!(matches!(
            inbox.next_deferred(),
            Some(Message::InstallFloor { .. })
        ));
        assert!(inbox.can_receive());
        let Some(Message::Synchronize { batch, .. }) = inbox.try_recv() else {
            panic!("queued synchronization missing");
        };
        assert_eq!(batch.view, View::new(2));
    });
}
