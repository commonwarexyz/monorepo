//! Floor installation and floor-bound finality tests.

use super::*;
use crate::types::View;

fn floor_fixture(
    committee: &Committee<MinPk>,
) -> (Checkpoint<Sha256Digest>, Floor<MinPk, Sha256Digest>) {
    let genesis = committee.config.genesis();
    let parent = genesis_history::<Sha256>(genesis);
    let history = Arc::new(TipRecord::at_tips(parent, genesis.tips().to_vec()).unwrap());
    let anchor = Arc::new(committee.lqc(View::new(1)));
    let current = checkpoint(
        genesis.epoch(),
        parent,
        genesis.tips().to_vec(),
        genesis.tips().to_vec(),
    );
    let floor = Floor::new(anchor, history, genesis.tips().to_vec());
    (current, floor)
}

/// Returns an L-QC for `history` whose voters leave every chain at its anchor. Each chain proposes
/// `payloads`, so a chain with any falls short and halts the final sweep.
fn anchored_lqc(
    committee: &Committee<MinPk>,
    view: u64,
    history: Sha256Digest,
    anchors: Vec<BlockRef<Sha256Digest>>,
    payloads: Vec<Vec<Sha256Digest>>,
) -> Arc<Lqc<MinPk, Sha256Digest>> {
    let chains = anchors.len();
    let proposals = anchors
        .into_iter()
        .zip(payloads)
        .map(|(anchor, payloads)| {
            ChainProposal::new(
                anchor.chain(),
                Anchor::Tip(anchor),
                payloads,
                committee.codec().pipeline_depth(),
            )
            .unwrap()
        })
        .collect();
    let leader = LeaderBlock::new(
        Round::new(committee.config.epoch(), View::new(view)),
        committee.config.genesis().vqc(),
        history,
        proposals,
        committee.codec(),
    )
    .unwrap();
    let vote = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&leader),
        vec![Position::new(0); chains],
        vec![Extension::empty(); chains],
        committee.codec(),
    )
    .unwrap();
    let votes = (0..committee.codec().view_quorum())
        .map(|signer| committee.signers[signer].sign_vote(vote.clone()).unwrap())
        .collect::<Vec<_>>();
    Arc::new(
        committee
            .verifier
            .assemble_lqc::<Sha256, _>(leader, &votes, &Sequential)
            .unwrap(),
    )
}

#[test]
fn floor_installs_an_anchor_jump_from_an_unextended_ordered_tip() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(17, 2, PathLimits::new(2, 1).unwrap());
        let epoch = committee.config.epoch();
        let genesis = committee.config.genesis();
        let tips = genesis.tips().to_vec();
        let canonical = chain(epoch, tips[1], 1);
        let rival = branch(epoch, tips[1], 2, b"rival");
        let parent = genesis_history::<Sha256>(genesis);
        let history = Arc::new(TipRecord::at_tips(parent, vec![tips[0], tip(&canonical)]).unwrap());
        // Chain 0 falls short of its proposal, which halts the sweep before chain 1 jumps to the
        // rival. Nothing is emitted past the ordered tips.
        let anchor = anchored_lqc(
            &committee,
            1,
            history.commitment::<Sha256>(),
            vec![tips[0], tip(&rival)],
            vec![vec![digest(b"short payload", 0)], Vec::new()],
        );
        let emitted = history.tips().to_vec();
        let floor = Floor::new(anchor, history, emitted);
        let mut actor = actor(
            &context,
            checkpoint(epoch, parent, tips.clone(), tips),
            vec![
                Vec::new(),
                canonical.iter().chain(&rival).cloned().collect(),
            ],
            committee.codec(),
            4,
        )
        .await;

        actor.install_floor(floor).await.unwrap();
        assert_eq!(actor.catalog.installed, 1);
    });
}

#[test]
fn incompatible_floor_resumes_without_installing() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(11, 2, PathLimits::new(2, 1).unwrap());
        let (current, floor) = floor_fixture(&committee);
        let mut emitted = floor.emitted.clone();
        emitted[0] = BlockRef::new(emitted[0].chain(), emitted[0].height(), digest(b"fork", 0));
        let incompatible = Floor::new(floor.anchor, floor.history, emitted);
        let mut actor = actor(
            &context,
            current,
            vec![Vec::new(), Vec::new()],
            committee.codec(),
            4,
        )
        .await;

        assert!(matches!(
            actor.install_floor(incompatible).await,
            Err(Error::Floor(FloorError::EmittedRegression))
        ));
        assert_eq!(actor.catalog.installed, 0);
    });
}

#[test]
fn finalized_proofs_at_or_below_the_floor_are_idempotent() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(12, 2, PathLimits::new(2, 1).unwrap());
        let (current, _) = floor_fixture(&committee);
        let proof = Arc::new(committee.lqc(View::new(1)));
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
            .synchronize_proofs(BTreeMap::from([(id, proof)]))
            .await
            .unwrap();

        assert_eq!(actor.history_stack.high_water, 0);
        assert!(actor.catalog.selected.is_empty());
    });
}

#[test]
fn synchronization_overflow_discards_canceled_floor_installations() {
    let committee = committee(16, 2, PathLimits::new(2, 1).unwrap());
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
        let committee = committee(13, 2, PathLimits::new(2, 1).unwrap());
        let epoch = committee.config.epoch();
        let genesis = committee.config.genesis();
        let blocks = vec![
            chain(epoch, genesis.tips()[0], 1),
            chain(epoch, genesis.tips()[1], 1),
        ];
        let advanced = blocks.iter().map(|chain| tip(chain)).collect::<Vec<_>>();
        let current = checkpoint(
            epoch,
            genesis_history::<Sha256>(genesis),
            advanced.clone(),
            advanced,
        );
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
        let committee = committee(66, 1, PathLimits::new(1, 1).unwrap());
        let epoch = committee.config.epoch();
        let (current, floor) = floor_fixture(&committee);
        let genesis = committee.config.genesis();
        let base = genesis.tips()[0];
        let blocks = vec![chain(epoch, base, 1)];
        let record = Arc::new(
            TipRecord::at_tips(genesis_history::<Sha256>(genesis), vec![tip(&blocks[0])]).unwrap(),
        );
        let commitment = record.commitment::<Sha256>();
        let proof = lqc_with_history(&committee, 2, commitment, tip(&blocks[0]));
        let mut actor = actor(&context, current, blocks, committee.codec(), 8).await;
        actor.fetcher.histories = vec![(commitment, record)];

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
        assert_eq!(
            commands.enqueue(Message::Synchronize {
                span: Span::none(),
                batch: FinalityBatch::new(proof.id::<Sha256>(), proof, 2),
            }),
            Feedback::Ok
        );
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
