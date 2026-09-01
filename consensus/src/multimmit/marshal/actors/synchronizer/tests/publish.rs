//! Finalized publication batching and restart reconciliation tests.

use super::*;
use crate::types::View;

#[test]
fn finalized_publication_does_not_reload_custodied_bodies() {
    deterministic::Runner::default().start(|context| async move {
        const OPENINGS: usize = 5;
        const BATCH: usize = 8;
        let committee = committee(32, 1, PathLimits::new(1, 1).unwrap());
        let epoch = committee.config.epoch();
        let base = base(0, 0);
        let blocks = chain(epoch, base, OPENINGS);
        let history = digest(b"materialization history", 0);
        let mut actor = actor(
            &context,
            checkpoint(epoch, history, vec![base], vec![base]),
            vec![blocks.clone()],
            committee.codec(),
            BATCH,
        )
        .await;
        let mut parent = history;
        let mut batch = PublicationBatch::new(BATCH, 0);
        for block in &blocks {
            let record = Arc::new(TipRecord::at_tips(parent, vec![block.reference()]).unwrap());
            let commitment = record.commitment::<Sha256>();
            actor
                .open(HistoryLink { commitment, record }, &mut batch)
                .await
                .unwrap();
            parent = commitment;
        }
        actor.commit(batch).await.unwrap();

        assert_eq!(actor.catalog.outputs.len(), OPENINGS);
    });
}

#[test]
fn long_gap_uses_capped_dense_batches() {
    deterministic::Runner::default().start(|context| async move {
        const GAP: usize = 512;
        const BATCH: usize = 17;
        let committee = committee(8, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 10_000),
            GAP,
            digest(b"long history", 0),
        );
        let mut actor = actor(&context, current, blocks, committee.codec(), BATCH).await;

        commit_opening(&mut actor, opening).await;
        assert_eq!(actor.catalog.outputs.len(), GAP);
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), GAP);
        assert!(
            actor
                .fetcher
                .block_reasons
                .lock()
                .iter()
                .all(|reason| *reason == FetchReason::FinalizedBody),
            "producer discovery must not fetch complete bodies"
        );
        assert!(actor.catalog.batches.iter().all(|size| *size <= BATCH));
        assert_eq!(actor.catalog.batches.iter().sum::<usize>(), GAP);
        assert_eq!(
            actor.catalog.checkpoint.committed(),
            Some(OutputIndex::new(511))
        );
        assert_eq!(actor.block_stack.writes_since_reset, GAP);
    });
}

#[test]
fn publication_batches_respect_the_block_byte_bound() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(29, 1, PathLimits::new(1, 1).unwrap());
        let (current, blocks, opening) = single_chain_opening(
            committee.config.epoch(),
            base(0, 0),
            5,
            digest(b"byte bound history", 0),
        );
        let mut actor = actor(&context, current, blocks.clone(), committee.codec(), 8).await;
        let block_bytes = u64::try_from(blocks[0][0].encode_size()).unwrap();
        actor.bounds.max_commit_block_bytes = block_bytes * 2;

        commit_opening(&mut actor, opening).await;

        assert_eq!(actor.catalog.batches, vec![2, 2, 1]);
        assert_eq!(actor.catalog.outputs.len(), 5);
    });
}

#[test]
fn completed_synchronization_retires_consumed_history_scratch() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(14, 2, PathLimits::new(2, 1).unwrap());
        let genesis = committee.config.genesis();
        let parent = genesis_history::<Sha256>(genesis);
        let record = Arc::new(TipRecord::at_tips(parent, genesis.tips().to_vec()).unwrap());
        let commitment = record.commitment::<Sha256>();
        let proof = Arc::new(committee.lqc(View::new(1)));
        assert_eq!(proof.leader().history(), commitment);
        let id = proof.id::<Sha256>();
        let mut actor = actor(
            &context,
            checkpoint(
                committee.config.epoch(),
                parent,
                genesis.tips().to_vec(),
                genesis.tips().to_vec(),
            ),
            vec![Vec::new(), Vec::new()],
            committee.codec(),
            4,
        )
        .await;
        actor.fetcher.histories.push((commitment, record));

        actor
            .synchronize_proofs(BTreeMap::from([(id, proof)]))
            .await
            .unwrap();

        assert_eq!(actor.history_stack.retired_segments, 1);
        assert!(actor.history_stack.links.is_empty());
    });
}

#[test]
fn restart_reconciles_authenticated_duplicates_without_outputs() {
    deterministic::Runner::default().start(|context| async move {
        let committee = committee(9, 1, PathLimits::new(1, 1).unwrap());
        let epoch = committee.config.epoch();
        let base = base(0, 0);
        let blocks = vec![chain(epoch, base, 4)];
        let emitted = tip(&blocks[0]);
        let history = digest(b"restart history", 0);
        let record = Arc::new(TipRecord::at_tips(history, vec![emitted]).unwrap());
        let commitment = record.commitment::<Sha256>();
        let mut actor = actor(
            &context,
            checkpoint(epoch, history, vec![base], vec![emitted]),
            blocks,
            committee.codec(),
            2,
        )
        .await;

        commit_opening(&mut actor, HistoryLink { commitment, record }).await;
        assert!(actor.catalog.outputs.is_empty());
        assert_eq!(actor.catalog.history_commits, 1);
        assert_eq!(actor.fetcher.block_calls.load(Ordering::Relaxed), 0);
    });
}
