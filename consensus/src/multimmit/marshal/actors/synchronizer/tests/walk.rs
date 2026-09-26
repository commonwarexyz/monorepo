//! Producer-walk ordering, header input, and history-window tests.

use super::*;
use crate::multimmit::testing::expect_within;

#[test]
fn full_commit_window_consumes_header_input_before_durability() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(6, 1, PathLimits::new(1, 0).unwrap());
        let epoch = committee.config.epoch();
        let base = base(0, 0);
        let blocks = chain(epoch, base, 1);
        let history = digest(b"pipeline history", 0);
        let mut actor = actor(
            &context,
            checkpoint(epoch, history, vec![base], vec![base]),
            vec![blocks.clone()],
            committee.codec(),
            8,
        )
        .await;
        actor
            .catalog
            .blocks
            .lock()
            .insert(blocks[0].reference(), Arc::clone(&blocks[0]));
        let waiters = Arc::new(Mutex::new(VecDeque::new()));
        actor.catalog.commit_waiters = Some(Arc::clone(&waiters));

        actor
            .commit(publication(vec![planned(0, &blocks[0])]))
            .await
            .unwrap();
        assert_eq!(waiters.lock().len(), 1);
        actor
            .commit(publication(vec![planned(1, &blocks[0])]))
            .await
            .unwrap();
        assert_eq!(waiters.lock().len(), 2);

        let record = Arc::new(TipRecord::at_tips(history, vec![tip(&blocks)]).unwrap());
        let commitment = record.commitment::<Sha256>();
        let mut batch = PublicationBatch::new(actor.bounds.max_commit_outputs, 0);
        let mut opening = Box::pin(actor.open(HistoryLink { commitment, record }, &mut batch));
        expect_within(
            &context,
            std::time::Duration::from_millis(1),
            &mut opening,
            "full commit window blocked bounded output planning",
        )
        .await
        .unwrap();
        drop(opening);
        assert_eq!(batch.outputs.len(), 1);
        assert_eq!(actor.pending_commits.len(), COMMIT_WINDOW);

        let (commands, receiver) =
            mailbox::new(context.child("mailbox"), NonZeroUsize::new(1).unwrap());
        let mut actor = actor.into_running(receiver);
        let reference = blocks[0].reference();
        assert_eq!(
            commands.enqueue(Message::Header {
                span: Span::none(),
                header: blocks[0].header().clone()
            }),
            Feedback::Ok
        );
        let mut third = Box::pin(actor.commit(publication(vec![planned(2, &blocks[0])])));
        assert_eq!(waiters.lock().len(), COMMIT_WINDOW);
        let release = async {
            commonware_runtime::utils::reschedule().await;
            let first = waiters.lock().pop_front().unwrap();
            first.send(Ok(())).unwrap();
        };
        let (result, ()) = futures::join!(&mut third, release);
        result.unwrap();
        drop(third);
        assert!(actor.headers.get(&reference).is_some());
        assert_eq!(waiters.lock().len(), 2);

        let second = waiters.lock().pop_front().unwrap();
        let _ = second.send(Ok(()));
        let third = waiters.lock().pop_front().unwrap();
        let _ = third.send(Ok(()));
        actor.finish_commits().await.unwrap();
        assert!(actor.pending_commits.is_empty());
    });
}

#[test]
fn paper_order_is_offset_major_across_producers() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(7, 3, PathLimits::new(3, 1).unwrap());
        let epoch = committee.config.epoch();
        let bases = vec![base(0, 0), base(1, 0), base(2, 0)];
        let blocks = vec![
            chain(epoch, bases[0], 2),
            chain(epoch, bases[1], 2),
            chain(epoch, bases[2], 2),
        ];
        let tips = blocks.iter().map(|blocks| tip(blocks)).collect();
        let history = digest(b"history", 0);
        let record = Arc::new(TipRecord::at_tips(history, tips).unwrap());
        let commitment = record.commitment::<Sha256>();
        let mut actor = actor(
            &context,
            checkpoint(epoch, history, bases.clone(), bases),
            blocks,
            committee.codec(),
            8,
        )
        .await;
        let gates = Arc::new(FetchGates::new());
        actor.fetcher.gates = Some(Arc::clone(&gates));
        actor.bounds.backfill_concurrency = 2;

        commit_opening(&mut actor, HistoryLink { commitment, record }).await;
        let coordinates = actor
            .catalog
            .outputs
            .iter()
            .map(|reference| (reference.chain().get(), reference.height().get()))
            .collect::<Vec<_>>();
        assert_eq!(
            coordinates,
            vec![(0, 1), (1, 1), (2, 1), (0, 2), (1, 2), (2, 2)]
        );
        let state = gates.0.lock();
        assert_eq!(state.peak, 2);
        assert_eq!(state.peak_by_chain, [1, 1, 1]);
        assert_eq!(&state.starts[..2], &[0, 1]);
        assert!(state.progressed_around_straggler);
    });
}

#[test]
fn producer_walk_uses_local_headers_before_resolving_missing_body() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(18, 3, PathLimits::new(3, 1).unwrap());
        let epoch = committee.config.epoch();
        let bases = vec![base(0, 0), base(1, 0), base(2, 0)];
        let blocks = vec![
            chain(epoch, bases[0], 3),
            chain(epoch, bases[1], 3),
            chain(epoch, bases[2], 3),
        ];
        let record = Arc::new(
            TipRecord::at_tips(
                digest(b"local batch history", 0),
                blocks.iter().map(|blocks| tip(blocks)).collect(),
            )
            .unwrap(),
        );
        let commitment = record.commitment::<Sha256>();
        let mut actor = actor(
            &context,
            checkpoint(
                epoch,
                digest(b"local batch history", 0),
                bases.clone(),
                bases,
            ),
            blocks.clone(),
            committee.codec(),
            8,
        )
        .await;
        actor.catalog.blocks.lock().extend(
            blocks[0]
                .iter()
                .chain(&blocks[1][..2])
                .chain(&blocks[2])
                .map(|block| (block.reference(), Arc::clone(block))),
        );
        actor.fetcher.catalog_block_calls = Some(Arc::clone(&actor.catalog.block_calls));
        actor.bounds.backfill_concurrency = 3;

        commit_opening(&mut actor, HistoryLink { commitment, record }).await;

        assert_eq!(&*actor.catalog.header_limits.lock(), &[vec![3, 3, 3]]);
        assert!(
            actor
                .catalog
                .block_batches
                .lock()
                .iter()
                .all(|batch| batch.len() <= actor.bounds.custody_batch_outputs)
        );
        for block in blocks.iter().flatten() {
            let lookups = actor
                .catalog
                .block_batches
                .lock()
                .iter()
                .flatten()
                .filter(|reference| **reference == block.reference())
                .count();
            assert_eq!(lookups, 1);
        }
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 1);
        assert!(
            actor.fetcher.fetch_batch_starts.lock()[0] > 0,
            "network backfill started before its local custody lookup"
        );
        assert_eq!(
            actor
                .catalog
                .outputs
                .iter()
                .map(|reference| (reference.chain().get(), reference.height().get()))
                .collect::<Vec<_>>(),
            vec![
                (0, 1),
                (1, 1),
                (2, 1),
                (0, 2),
                (1, 2),
                (2, 2),
                (0, 3),
                (1, 3),
                (2, 3),
            ]
        );
    });
}

#[rstest]
#[case::catalog(true, false)]
#[case::resolver(false, false)]
#[case::partial_catalog_reply(true, true)]
fn authenticated_header_wakes_active_producer_walk(#[case] local: bool, #[case] partial: bool) {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let chains = if partial { 2 } else { 1 };
        let committee = committee(59, chains, PathLimits::new(1, 1).unwrap());
        let epoch = committee.config.epoch();
        let bases = (0..chains).map(|index| base(index, 0)).collect::<Vec<_>>();
        let blocks = bases
            .iter()
            .map(|base| chain(epoch, *base, 1))
            .collect::<Vec<_>>();
        let tips = blocks.iter().map(|chain| tip(chain)).collect::<Vec<_>>();
        let reference = tips[0];
        let history = digest(b"live header history", 0);
        let record = Arc::new(TipRecord::at_tips(history, tips.clone()).unwrap());
        let commitment = record.commitment::<Sha256>();
        let mut actor = actor(
            &context,
            checkpoint(epoch, history, bases.clone(), bases.clone()),
            blocks.clone(),
            committee.codec(),
            8,
        )
        .await;
        if partial {
            actor.catalog.blocks.lock().extend(
                blocks
                    .iter()
                    .flatten()
                    .map(|block| (block.reference(), Arc::clone(block))),
            );
        }
        actor.fetcher.catalog_block_calls = Some(Arc::clone(&actor.catalog.block_calls));
        let (started, blocked) = oneshot::channel();
        let (release, response) = oneshot::channel();
        let mut release = Some(release);
        let gate = if local {
            &actor.catalog.header_gate
        } else {
            &actor.fetcher.header_gate
        };
        *gate.lock() = Some(HeaderGate {
            started,
            release: response,
        });
        let (commands, receiver) =
            mailbox::new(context.child("commands"), NonZeroUsize::new(2).unwrap());
        let mut actor = actor.into_running(receiver);
        let mut opening = Box::pin(commit_opening(
            &mut actor,
            HistoryLink { commitment, record },
        ));
        commonware_macros::select! {
            _ = &mut opening => panic!("producer walk completed before the header response"),
            result = blocked => result.unwrap(),
            _ = context.sleep(Duration::from_secs(1)) => {
                panic!("producer walk never requested its missing header")
            },
        }

        let mismatched = TransactionBlockHeader::new(
            epoch,
            reference.chain(),
            reference.height(),
            bases[0].digest(),
            digest(b"other authenticated body", 0),
        )
        .unwrap();
        let [mismatched, matching] = [mismatched, blocks[0][0].header().clone()].map(|header| {
            let signed = committee.signers[0].sign_transaction_block(header).unwrap();
            assert!(committee.verifier.verify_transaction_block(&signed));
            signed.header().clone()
        });
        assert_ne!(mismatched.block_ref::<Sha256>(), reference);
        assert_eq!(
            commands.enqueue(Message::Header {
                span: Span::none(),
                header: mismatched
            }),
            Feedback::Ok
        );
        commonware_macros::select! {
            _ = &mut opening => panic!("a mismatched header advanced the producer walk"),
            _ = context.sleep(Duration::from_millis(10)) => {},
        }
        assert_eq!(
            commands.enqueue(Message::Header {
                span: Span::none(),
                header: matching
            }),
            Feedback::Ok
        );
        if partial {
            commonware_macros::select! {
                _ = &mut opening => panic!("the unresolved chain did not retain its lookup"),
                _ = context.sleep(Duration::from_millis(10)) => {},
            }
            release.take().unwrap().send(()).unwrap();
        }
        expect_within(
            &context,
            Duration::from_millis(100),
            &mut opening,
            "matching authenticated header did not wake the active producer walk",
        )
        .await;
        drop(opening);
        if let Some(release) = release {
            assert!(
                release.is_closed(),
                "the obsolete header request was not canceled"
            );
        }

        assert_eq!(actor.catalog.outputs, tips);
        assert_eq!(actor.catalog.block_calls.load(Ordering::Relaxed), 1);
        if partial {
            assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 0);
            assert!(actor.catalog.handoff.is_empty());
        } else {
            assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 1);
            assert!(actor.fetcher.fetch_batch_starts.lock()[0] > 0);
            assert_eq!(actor.catalog.handoff, vec![reference]);
        }
        actor.finish_commits().await.unwrap();
    });
}

#[test]
fn ready_ancestry_completions_precede_optional_hints() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = committee(61, 1, PathLimits::new(2, 1).unwrap());
        let epoch = committee.config.epoch();
        let base = base(0, 0);
        let blocks = chain(epoch, base, 2);
        let history = digest(b"ready ancestry history", 0);
        let record = Arc::new(TipRecord::at_tips(history, vec![blocks[0].reference()]).unwrap());
        let commitment = record.commitment::<Sha256>();
        let actor = actor(
            &context,
            checkpoint(epoch, history, vec![base], vec![base]),
            vec![blocks.clone()],
            committee.codec(),
            8,
        )
        .await;
        actor
            .catalog
            .blocks
            .lock()
            .insert(blocks[0].reference(), Arc::clone(&blocks[0]));
        let signed = committee.signers[0]
            .sign_transaction_block(blocks[1].header().clone())
            .unwrap();
        assert!(committee.verifier.verify_transaction_block(&signed));
        let (commands, receiver) = mailbox::new(context.child("commands"), NonZeroUsize::MIN);
        let mut actor = actor.into_running(receiver);
        assert_eq!(
            commands.enqueue(Message::Header {
                span: Span::none(),
                header: signed.header().clone()
            }),
            Feedback::Ok
        );
        commit_opening(&mut actor, HistoryLink { commitment, record }).await;
        assert_eq!(actor.catalog.outputs, vec![blocks[0].reference()]);
        assert!(
            actor.headers.get(&blocks[1].reference()).is_none(),
            "an optional hint was processed before ready synchronization work"
        );
        actor.finish_commits().await.unwrap();
    });
}

#[rstest]
#[case(Some(0))]
#[case(Some(5))]
#[case(None)]
fn selected_commitments_bypass_only_known_ancestry(#[case] start: Option<usize>) {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = committee(63, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 0),
            40,
            digest(b"selected ancestry", 0),
        );
        let expected = blocks[0]
            .iter()
            .map(|block| block.reference())
            .collect::<Vec<_>>();
        let mut actor =
            actor_with_backfill(&context, current, blocks.clone(), committee.codec(), 8, 2).await;
        if let Some(start) = start {
            actor
                .commitments
                .insert(&selected(actor.epoch, &[blocks[0][start..].to_vec()]));
        }
        actor.fetcher.fetch_delay_by_height = true;
        commit_opening(&mut actor, opening).await;
        actor.finish_commits().await.unwrap();
        assert_eq!(actor.catalog.outputs, expected);
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 40);
        assert!(actor.fetcher.block_peak.load(Ordering::Relaxed) <= 2);
        if start == Some(0) {
            assert!(actor.catalog.header_limits.lock().is_empty());
            assert_eq!(actor.block_stack.writes_since_reset, 0);
        } else {
            assert_eq!(
                &*actor.catalog.header_limits.lock(),
                &[vec![start.unwrap_or(40)]]
            );
            assert_eq!(actor.block_stack.writes_since_reset, 40);
        }
    });
}

#[test]
fn adjacent_history_openings_share_bounded_commits() {
    deterministic::Runner::default().start(|context| async move {
        const OPENINGS: usize = 5;
        const BATCH: usize = 2;
        let committee = committee(15, 2, PathLimits::new(2, 1).unwrap());
        let genesis = committee.config.genesis();
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
            BATCH,
        )
        .await;
        let mut parent = genesis_history::<Sha256>(genesis);
        let mut batch = PublicationBatch::new(BATCH, 0);
        for _ in 0..OPENINGS {
            let record = Arc::new(TipRecord::at_tips(parent, genesis.tips().to_vec()).unwrap());
            let commitment = record.commitment::<Sha256>();
            actor
                .open(HistoryLink { commitment, record }, &mut batch)
                .await
                .unwrap();
            parent = commitment;
        }
        actor.commit(batch).await.unwrap();

        assert_eq!(actor.catalog.history_commits, OPENINGS);
        assert_eq!(actor.catalog.batches, vec![0, 0, 0]);
    });
}

#[rstest]
#[case(false)]
#[case(true)]
fn adjacent_history_openings_share_backfill_concurrency(#[case] known: bool) {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(34, 1, PathLimits::new(1, 1).unwrap());
        let epoch = committee.config.epoch();
        let base = base(0, 0);
        let blocks = vec![chain(epoch, base, 2)];
        let history = digest(b"cross-opening history", 0);
        let first = Arc::new(TipRecord::at_tips(history, vec![blocks[0][0].reference()]).unwrap());
        let first_id = first.commitment::<Sha256>();
        let second =
            Arc::new(TipRecord::at_tips(first_id, vec![blocks[0][1].reference()]).unwrap());
        let second_id = second.commitment::<Sha256>();
        let proof = lqc_with_history(&committee, 1, second_id, blocks[0][1].reference());
        let id = proof.id::<Sha256>();
        let mut actor = actor(
            &context,
            checkpoint(epoch, history, vec![base], vec![base]),
            blocks.clone(),
            committee.codec(),
            8,
        )
        .await;
        if known {
            actor.commitments.insert(&selected(actor.epoch, &blocks));
        }

        actor.fetcher.histories = vec![(first_id, first), (second_id, second)];
        actor.fetcher.fetch_requires = Some((blocks[0][0].reference(), 2));
        actor.bounds.backfill_concurrency = 2;

        actor
            .synchronize_proofs(BTreeMap::from([(id, proof)]))
            .await
            .unwrap();

        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 2);
        if known {
            assert!(actor.catalog.header_limits.lock().is_empty());
            assert_eq!(actor.block_stack.retired_segments, 0);
        } else {
            assert_eq!(&*actor.catalog.header_limits.lock(), &[vec![2]]);
        }
        assert_eq!(
            actor.catalog.outputs,
            vec![blocks[0][0].reference(), blocks[0][1].reference()]
        );
    });
}

#[rstest]
#[case(false)]
#[case(true)]
fn history_window_authenticates_intermediate_tips(#[case] known: bool) {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(36, 1, PathLimits::new(1, 1).unwrap());
        let epoch = committee.config.epoch();
        let base = base(0, 0);
        let blocks = vec![chain(epoch, base, 2)];
        let history = digest(b"boundary history", 0);
        let fork = BlockRef::new(ChainId::new(0), Height::new(1), digest(b"fork", 1));
        let first = Arc::new(TipRecord::at_tips(history, vec![fork]).unwrap());
        let first_id = first.commitment::<Sha256>();
        let second =
            Arc::new(TipRecord::at_tips(first_id, vec![blocks[0][1].reference()]).unwrap());
        let second_id = second.commitment::<Sha256>();
        let proof = lqc_with_history(&committee, 1, second_id, blocks[0][1].reference());
        let id = proof.id::<Sha256>();
        let mut actor = actor(
            &context,
            checkpoint(epoch, history, vec![base], vec![base]),
            blocks.clone(),
            committee.codec(),
            8,
        )
        .await;
        if known {
            actor.commitments.insert(&selected(actor.epoch, &blocks));
        }

        actor.fetcher.histories = vec![(first_id, first), (second_id, second)];

        assert!(matches!(
            actor
                .synchronize_proofs(BTreeMap::from([(id, proof)]))
                .await,
            Err(Error::Invalid(
                "producer ancestry conflicts with a history boundary"
            ))
        ));
        assert!(actor.catalog.outputs.is_empty());
    });
}

#[test]
fn block_stack_is_reset_when_the_next_walk_starts() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(64, 1, PathLimits::new(1, 1).unwrap());
        let epoch = committee.config.epoch();
        let base = base(0, 0);
        let blocks = chain(epoch, base, 2);
        let history = digest(b"scratch reset history", 0);
        let first = Arc::new(TipRecord::at_tips(history, vec![blocks[0].reference()]).unwrap());
        let first_id = first.commitment::<Sha256>();
        let second = Arc::new(TipRecord::at_tips(first_id, vec![blocks[1].reference()]).unwrap());
        let second_id = second.commitment::<Sha256>();
        let mut actor = actor(
            &context,
            checkpoint(epoch, history, vec![base], vec![base]),
            vec![blocks],
            committee.codec(),
            8,
        )
        .await;

        commit_opening(
            &mut actor,
            HistoryLink {
                commitment: first_id,
                record: first,
            },
        )
        .await;
        assert_eq!(actor.block_stack.retired_segments, 0);
        assert_eq!(actor.block_stack.writes_since_reset, 1);

        commit_opening(
            &mut actor,
            HistoryLink {
                commitment: second_id,
                record: second,
            },
        )
        .await;
        assert_eq!(actor.block_stack.retired_segments, 1);
        assert_eq!(actor.block_stack.writes_since_reset, 1);
        assert_eq!(actor.catalog.outputs.len(), 2);
    });
}
