//! Floor installation and floor-bound finality tests.

use super::*;

/// Returns the genesis checkpoint and the floor of view 2's L-QC, which opens view 1 at the
/// genesis tips.
fn floor_fixture(
    committee: &Committee<MinPk>,
) -> (Checkpoint<Sha256Digest>, Floor<MinPk, Sha256Digest>) {
    let genesis = committee.config.genesis();
    let current = checkpoint(
        genesis.epoch(),
        0,
        genesis.history(),
        genesis.tips().to_vec(),
        genesis.tips().to_vec(),
    );
    let floor = Floor::new(
        genesis_lqc(committee, 0..committee.codec().view_quorum()),
        genesis_record(committee),
    );
    (current, floor)
}

#[test]
fn floor_installs_at_the_view_its_lqc_pins() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(17, 2);
        let epoch = committee.config.epoch();
        let genesis = committee.config.genesis();
        let tips = genesis.tips().to_vec();
        let blocks = vec![chain(epoch, tips[0], 2), chain(epoch, tips[1], 1)];
        let opening = Arc::new(
            HistoryRecord::new(digest(b"view 4", 0), vec![tip(&blocks[0]), tip(&blocks[1])])
                .unwrap(),
        );
        let proof = lqc(
            &committee,
            6,
            opening.commitment::<Sha256>(),
            0..committee.codec().view_quorum(),
        );
        let mut actor = actor(
            &context,
            checkpoint(epoch, 0, genesis.history(), tips.clone(), tips),
            blocks,
            committee.codec(),
            4,
        )
        .await;

        actor
            .install_floor(Floor::new(Arc::clone(&proof), Arc::clone(&opening)))
            .await
            .unwrap();
        assert_eq!(actor.catalog.installed, 1);
        assert_eq!(actor.state.view(), View::new(5));
        assert_eq!(actor.state.history(), opening.commitment::<Sha256>());
        assert_eq!(actor.state.ordered(), opening.tips());
        assert_eq!(actor.state.emitted(), opening.tips());
        assert_eq!(actor.committed, OutputIndex::new(3));
        assert_eq!(actor.floor_view, View::new(6));

        // A floor pinning an earlier view cannot replace it.
        let (_, stale) = floor_fixture(&committee);
        assert!(matches!(
            actor.install_floor(stale).await,
            Err(Error::Invalid("floor is stale"))
        ));
    });
}

#[test]
fn incompatible_floor_resumes_without_installing() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(11, 2);
        let epoch = committee.config.epoch();
        let genesis = committee.config.genesis();
        let tips = genesis.tips().to_vec();
        let blocks = vec![chain(epoch, tips[0], 1), Vec::new()];
        // A sweep emitted chain 0's first block past the genesis tips.
        let current = checkpoint(
            epoch,
            0,
            genesis.history(),
            tips.clone(),
            vec![tip(&blocks[0]), tips[1]],
        );
        let (_, floor) = floor_fixture(&committee);
        let mut actor = actor(&context, current, blocks, committee.codec(), 4).await;

        assert!(matches!(
            actor.install_floor(floor).await,
            Err(Error::Floor(FloorError::EmittedRegression))
        ));
        assert_eq!(actor.catalog.installed, 0);
    });
}

#[test]
fn finalized_proofs_at_or_below_the_floor_are_idempotent() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(12, 2);
        let (current, _) = floor_fixture(&committee);
        let proof = lqc(
            &committee,
            1,
            committee.config.genesis().history(),
            0..committee.codec().view_quorum(),
        );
        let id = proof.id::<Sha256>();
        let mut actor = actor(
            &context,
            current,
            vec![Vec::new(), Vec::new()],
            committee.codec(),
            4,
        )
        .await;
        actor.floor = id;
        actor.floor_view = proof.view();

        actor
            .synchronize_target(Target::finalized(id, proof, None, 2))
            .await
            .unwrap();

        assert_eq!(actor.history_stack.high_water, 0);
        assert!(actor.catalog.selected.is_empty());
    });
}

#[test]
fn synchronization_overflow_discards_canceled_floor_installations() {
    let committee = committee(16, 2);
    let (_, first_floor) = floor_fixture(&committee);
    let (first_reply, first_receiver) = oneshot::channel();
    let mut overflow = VecDeque::new();
    Message::<MinPk, Sha256Digest>::handle(
        &mut overflow,
        Message::InstallFloor {
            span: Span::none(),
            checkpoint: first_floor,
            reply: first_reply,
        },
    );
    assert_eq!(overflow.len(), 1);
    drop(first_receiver);

    let (_, second_floor) = floor_fixture(&committee);
    let (second_reply, second_receiver) = oneshot::channel();
    drop(second_receiver);
    Message::<MinPk, Sha256Digest>::handle(
        &mut overflow,
        Message::InstallFloor {
            span: Span::none(),
            checkpoint: second_floor,
            reply: second_reply,
        },
    );

    assert!(overflow.is_empty());
}

#[test]
fn floor_installation_rejects_a_valid_frontier_rewind() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(13, 2);
        let epoch = committee.config.epoch();
        let genesis = committee.config.genesis();
        let blocks = vec![
            chain(epoch, genesis.tips()[0], 1),
            chain(epoch, genesis.tips()[1], 1),
        ];
        let advanced = blocks.iter().map(|chain| tip(chain)).collect::<Vec<_>>();
        let current = checkpoint(epoch, 0, genesis.history(), advanced.clone(), advanced);
        let (_, floor) = floor_fixture(&committee);
        let mut actor = actor(&context, current, blocks, committee.codec(), 4).await;

        assert!(matches!(
            actor.install_floor(floor).await,
            Err(Error::Floor(FloorError::OrderedRegression))
        ));
        assert_eq!(actor.catalog.installed, 0);
    });
}

#[rstest]
#[case::history(true)]
#[case::headers(false)]
fn floor_install_stops_a_pass_waiting_on_peers(#[case] history: bool) {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
        let committee = committee(66, 1);
        let epoch = committee.config.epoch();
        let (current, floor) = floor_fixture(&committee);
        let genesis = committee.config.genesis();
        let base = genesis.tips()[0];
        let blocks = vec![chain(epoch, base, 1)];
        let first = genesis_record(&committee);
        let second = Arc::new(
            HistoryRecord::new(first.commitment::<Sha256>(), vec![tip(&blocks[0])]).unwrap(),
        );
        let mut actor = actor(&context, current, blocks, committee.codec(), 8).await;
        actor.fetcher.histories = vec![(first.commitment::<Sha256>(), first)];

        // Peers never answer, as when they pruned what the pass needs.
        let (started, blocked) = oneshot::channel();
        let (_release, response) = oneshot::channel();
        let gate = if history {
            &actor.fetcher.history_gate
        } else {
            &actor.fetcher.header_gate
        };
        *gate.lock() = Some(StallGate {
            started,
            release: response,
        });
        let (commands, receiver) =
            mailbox::new(context.child("commands"), NonZeroUsize::new(4).unwrap());
        let actor = actor.into_running(receiver);
        let _synchronizer = context
            .child("synchronizer")
            .spawn(move |context| async move { actor.run(&context).await });
        assert_eq!(commands.enqueue(resolve_message(2, &second)), Feedback::Ok);
        blocked.await.unwrap();

        // The floor install stops the waiting pass and runs, instead of queueing behind it.
        let (reply, installed) = oneshot::channel();
        assert_eq!(
            commands.enqueue(Message::InstallFloor {
                span: Span::none(),
                checkpoint: floor,
                reply,
            }),
            Feedback::Ok
        );
        assert!(matches!(installed.await, Ok(Ok(()))));
    });
}
