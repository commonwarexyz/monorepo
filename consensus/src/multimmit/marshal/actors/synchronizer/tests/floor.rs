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
