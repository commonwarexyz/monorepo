//! Request validation against the catalog's checkpoint and bounds.
//!
//! Each check reads only its inputs, so a rejected request leaves every store untouched.

use super::{actor::Bounds, mailbox::Error};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        marshal::{
            protocol::floor::pinned_view,
            storage::{
                catalog::{Admission, InstallRequest},
                catalog_state::Checkpoint,
                commit::{Commit, HistoryOpening, OutputRow, SelectedLqc},
            },
        },
        types::{BlockRef, Body},
    },
    types::Epoch,
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};

/// Checks that an admission names its artifact exactly and belongs to `epoch`.
pub(super) fn admission<H, V, B>(
    epoch: Epoch,
    chains: usize,
    max_block_bytes: usize,
    admission: &Admission<H, V, B>,
) -> Result<(), Error>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    match admission {
        Admission::Lqc(view, id, proof) => {
            if proof.view() != *view || proof.id::<H>() != *id || proof.epoch() != epoch {
                return Err(Error::Invalid("LQC identity or epoch mismatch"));
            }
        }
        Admission::History(_, commitment, record) => {
            if record.commitment::<H>() != *commitment {
                return Err(Error::Invalid("history commitment mismatch"));
            }
        }
        Admission::Block(reference, block) => {
            if block.encode_size() > max_block_bytes {
                return Err(Error::Invalid("producer block exceeds encoded-byte bound"));
            }
            if block.reference() != *reference
                || reference.chain().get() as usize >= chains
                || block.header().epoch() != epoch
            {
                return Err(Error::Invalid("producer-block identity or epoch mismatch"));
            }
        }
    }
    Ok(())
}

/// Checks that `batch` extends `current` exactly within `bounds`.
pub(super) fn commit<H, V>(
    current: &Checkpoint<H::Digest>,
    chains: usize,
    bounds: &Bounds,
    batch: &Commit<H, V>,
) -> Result<(), Error>
where
    H: Hasher,
    V: Variant,
{
    let next = &batch.checkpoint;
    context(current, next, chains, bounds, batch)?;
    selected::<H, V>(current, next, &batch.selected)?;
    history::<H>(current, next, &batch.history)?;
    outputs::<H>(current, next, chains, bounds, &batch.outputs)
}

/// Checks that a floor installation is a newer compatible generation established by its
/// artifacts: both of its frontiers are the floor opening's tips.
pub(super) fn install<H, V>(
    current: &Checkpoint<H::Digest>,
    chains: usize,
    request: &InstallRequest<V, H::Digest>,
) -> Result<(), Error>
where
    H: Hasher,
    V: Variant,
{
    let InstallRequest {
        checkpoint,
        floors,
        proof,
        history,
    } = request;
    let history_index = next_history_index(current.history_index(), 1)?;
    if checkpoint.chains() != chains
        || floors.blocks.len() != chains
        || checkpoint.history_index() != history_index
        || checkpoint.epoch() != current.epoch()
        || checkpoint.floor_generation() <= current.floor_generation()
        || checkpoint.archive_layout() != current.archive_layout()
        || checkpoint.floor_index() != checkpoint.committed()
        || !current.advances_to(checkpoint)
    {
        return Err(Error::Invalid(
            "floor installation is not a newer compatible generation",
        ));
    }
    if proof.id::<H>() != checkpoint.floor()
        || proof.epoch() != checkpoint.epoch()
        || pinned_view(proof) != checkpoint.view()
        || proof.leader().history() != checkpoint.history()
        || history.commitment::<H>() != checkpoint.history()
        || checkpoint.ordered() != history.tips()
        || checkpoint.emitted() != checkpoint.ordered()
    {
        return Err(Error::Invalid(
            "floor artifacts do not establish checkpoint",
        ));
    }
    Ok(())
}

/// Returns the history index after appending `count` openings to a chain ending at `current`.
fn next_history_index(current: Option<u64>, count: usize) -> Result<Option<u64>, Error> {
    if count == 0 {
        return Ok(current);
    }
    let count = u64::try_from(count).map_err(|_| Error::Invalid("history index overflow"))?;
    let next = current.map_or(Some(count - 1), |index| index.checked_add(count));
    next.map(Some)
        .ok_or(Error::Invalid("history index overflow"))
}

/// Checks the checkpoint context and batch sizes.
fn context<H, V>(
    current: &Checkpoint<H::Digest>,
    next: &Checkpoint<H::Digest>,
    chains: usize,
    bounds: &Bounds,
    batch: &Commit<H, V>,
) -> Result<(), Error>
where
    H: Hasher,
    V: Variant,
{
    if next.epoch() != current.epoch()
        || next.floor_generation() != current.floor_generation()
        || next.floor_index() != current.floor_index()
        || next.archive_layout() != current.archive_layout()
        || next.chains() != chains
        || batch.selected.len() > bounds.max_commit_outputs.get()
        || batch.outputs.len() > bounds.max_commit_outputs.get()
    {
        return Err(Error::Invalid("checkpoint context mismatch"));
    }
    Ok(())
}

/// Checks that the selected L-QCs belong to the epoch, establish the floor, and are canonical.
///
/// Every selected L-QC pins the checkpoint's history, so all share one view; ids strictly
/// increase, so no certificate takes two finalized ordinals.
fn selected<H, V>(
    current: &Checkpoint<H::Digest>,
    next: &Checkpoint<H::Digest>,
    selected: &[SelectedLqc<V, H>],
) -> Result<(), Error>
where
    H: Hasher,
    V: Variant,
{
    if selected.iter().any(|selected| {
        selected.proof.view() != selected.view
            || selected.proof.epoch() != current.epoch()
            || selected.proof.id::<H>() != selected.id
            || selected.proof.leader().history() != next.history()
    }) || selected
        .windows(2)
        .any(|pair| pair[0].view != pair[1].view || pair[0].id >= pair[1].id)
    {
        return Err(Error::Invalid("selected LQC does not establish checkpoint"));
    }
    match selected.last() {
        Some(selected) if next.floor() != selected.id => {
            Err(Error::Invalid("selected LQC does not establish checkpoint"))
        }
        None if next.floor() != current.floor() => {
            Err(Error::Invalid("intermediate commit changed the LQC floor"))
        }
        _ if !current.advances_to(next) => Err(Error::Invalid(
            "checkpoint frontier regressed or conflicted",
        )),
        _ => Ok(()),
    }
}

/// Checks that the history openings extend the current history to the checkpoint's.
fn history<H: Hasher>(
    current: &Checkpoint<H::Digest>,
    next: &Checkpoint<H::Digest>,
    openings: &[HistoryOpening<H>],
) -> Result<(), Error> {
    let mut history = current.history();
    for opening in openings {
        if opening.record.parent() != history
            || opening.record.commitment::<H>() != opening.commitment
        {
            return Err(Error::Invalid("history openings are not contiguous"));
        }
        history = opening.commitment;
    }
    if history != next.history() {
        return Err(Error::Invalid("history does not reach checkpoint"));
    }
    if next.history_index() != next_history_index(current.history_index(), openings.len())? {
        return Err(Error::Invalid("checkpoint history index is not contiguous"));
    }
    let view = u64::try_from(openings.len())
        .ok()
        .and_then(|count| current.view().get().checked_add(count));
    if view != Some(next.view().get()) {
        return Err(Error::Invalid(
            "checkpoint view does not follow its openings",
        ));
    }
    let ordered = openings
        .last()
        .map_or(current.ordered(), |opening| opening.record.tips());
    if next.ordered() != ordered {
        return Err(Error::Invalid("checkpoint ordering does not match history"));
    }
    Ok(())
}

/// Checks that the output rows are dense, exact, within the byte bound, and advance each
/// chain's emitted frontier one height at a time to the checkpoint's.
fn outputs<H: Hasher>(
    current: &Checkpoint<H::Digest>,
    next: &Checkpoint<H::Digest>,
    chains: usize,
    bounds: &Bounds,
    rows: &[OutputRow<H::Digest>],
) -> Result<(), Error> {
    let mut previous = current.committed();
    let mut emitted = current.emitted().to_vec();
    let mut output_bytes = 0usize;
    for (offset, row) in rows.iter().enumerate() {
        let encoded_len = usize::try_from(row.meta().encoded_len()).unwrap_or(usize::MAX);
        if offset > 0
            && output_bytes
                .checked_add(encoded_len)
                .is_none_or(|total| total > bounds.max_commit_block_bytes.get())
        {
            return Err(Error::Invalid("commit block bytes exceed bound"));
        }
        output_bytes = output_bytes.saturating_add(encoded_len);
        if row.index.previous() != Some(previous) || !exact::<H>(row, current.epoch(), chains) {
            return Err(Error::Invalid("output rows are not dense or exact"));
        }
        previous = row.index;
        advance::<H>(&mut emitted, row)?;
    }
    if next.committed() != previous {
        return Err(Error::Invalid("checkpoint does not cover output batch"));
    }
    if emitted != next.emitted() {
        return Err(Error::Invalid(
            "checkpoint emission does not match output rows",
        ));
    }
    Ok(())
}

/// Returns whether a row's reference matches its header, chain range, and epoch.
fn exact<H: Hasher>(row: &OutputRow<H::Digest>, epoch: Epoch, chains: usize) -> bool {
    let reference = row.reference();
    (reference.chain().get() as usize) < chains
        && row.meta().header().block_ref::<H>() == reference
        && row.meta().header().epoch() == epoch
}

/// Advances `row`'s chain frontier in `emitted` by exactly one height, to a child of the
/// frontier block.
fn advance<H: Hasher>(
    emitted: &mut [BlockRef<H::Digest>],
    row: &OutputRow<H::Digest>,
) -> Result<(), Error> {
    let reference = row.reference();
    let frontier = &mut emitted[reference.chain().get() as usize];
    let height = frontier
        .height()
        .get()
        .checked_add(1)
        .ok_or(Error::Invalid("output frontier overflow"))?;
    if reference.height().get() != height || row.meta().header().parent() != frontier.digest() {
        return Err(Error::Invalid(
            "output rows do not advance exact chain frontiers",
        ));
    }
    *frontier = reference;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        super::tests::{checkpoint, committee as seeded_committee, output_row, producer_block},
        *,
    };
    use crate::{
        multimmit::{
            marshal::{
                OutputIndex,
                storage::catalog_state::{CheckpointParts, PendingFloors},
            },
            mocks::Committee,
            testing::TestBody,
            types::{ChainId, HistoryRecord, Lqc, TransactionBlock},
        },
        types::{Height, View},
    };
    use commonware_cryptography::{
        Digestible as _, Sha256, bls12381::primitives::variant::MinPk,
        sha256::Digest as Sha256Digest,
    };
    use commonware_utils::NZUsize;
    use std::sync::Arc;

    fn committee() -> Committee<MinPk> {
        seeded_committee(7, b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_VALIDATE")
    }

    const fn bounds(max_commit_outputs: usize, max_commit_block_bytes: usize) -> Bounds {
        Bounds {
            max_commit_outputs: NZUsize!(max_commit_outputs),
            max_commit_block_bytes: NZUsize!(max_commit_block_bytes),
            max_block_bytes: NZUsize!(1 << 20),
        }
    }

    fn checkpoint_parts(checkpoint: &Checkpoint<Sha256Digest>) -> CheckpointParts<Sha256Digest> {
        CheckpointParts {
            epoch: checkpoint.epoch(),
            floor_generation: checkpoint.floor_generation(),
            archive_layout: checkpoint.archive_layout(),
            floor: checkpoint.floor(),
            view: checkpoint.view(),
            history: checkpoint.history(),
            history_index: checkpoint.history_index(),
            ordered: checkpoint.ordered().to_vec(),
            emitted: checkpoint.emitted().to_vec(),
            floor_index: checkpoint.floor_index(),
        }
    }

    #[test]
    fn admission_rejects_oversized_foreign_or_misnamed_blocks() {
        let committee = committee();
        let epoch = committee.config.epoch();
        let block = producer_block(&committee, 1, 10);
        let write =
            Admission::<Sha256, MinPk, TestBody>::Block(block.reference(), Arc::clone(&block));
        assert_eq!(admission(epoch, 4, 1 << 20, &write), Ok(()));
        assert_eq!(
            admission(epoch, 4, block.encode_size() - 1, &write),
            Err(Error::Invalid("producer block exceeds encoded-byte bound"))
        );
        assert_eq!(
            admission(epoch, 1, 1 << 20, &write),
            Err(Error::Invalid("producer-block identity or epoch mismatch"))
        );
        assert_eq!(
            admission(Epoch::new(epoch.get() + 1), 4, 1 << 20, &write),
            Err(Error::Invalid("producer-block identity or epoch mismatch"))
        );
        let other = producer_block(&committee, 2, 11);
        let misnamed = Admission::<Sha256, MinPk, TestBody>::Block(other.reference(), block);
        assert_eq!(
            admission(epoch, 4, 1 << 20, &misnamed),
            Err(Error::Invalid("producer-block identity or epoch mismatch"))
        );
    }

    #[test]
    fn commit_checks_context_size_density_and_emission() {
        let committee = committee();
        let genesis = committee.config.genesis();
        let current = checkpoint(
            &committee,
            0,
            genesis.vqc(),
            genesis.history(),
            0,
            genesis.tips().to_vec(),
            OutputIndex::zero(),
        );
        let blocks = [
            producer_block(&committee, 0, 10),
            producer_block(&committee, 1, 11),
        ];
        let mut emitted = genesis.tips().to_vec();
        emitted[0] = blocks[0].reference();
        emitted[1] = blocks[1].reference();
        let batch =
            |outputs: Vec<OutputRow<_>>, floor_generation, floor_index| Commit::<Sha256, MinPk> {
                selected: Vec::new(),
                history: Vec::new(),
                outputs,
                checkpoint: checkpoint(
                    &committee,
                    floor_generation,
                    genesis.vqc(),
                    genesis.history(),
                    0,
                    emitted.clone(),
                    floor_index,
                ),
            };
        let rows = || {
            vec![
                output_row(OutputIndex::new(1), &blocks[0]),
                output_row(OutputIndex::new(2), &blocks[1]),
            ]
        };
        let block_bytes = blocks[0].encode_size();
        let zero = OutputIndex::zero();
        assert_eq!(
            commit(
                &current,
                4,
                &bounds(2, 2 * block_bytes),
                &batch(rows(), 0, zero)
            ),
            Ok(())
        );
        assert_eq!(
            commit(
                &current,
                4,
                &bounds(2, 2 * block_bytes),
                &batch(rows(), 1, zero)
            ),
            Err(Error::Invalid("checkpoint context mismatch"))
        );
        assert_eq!(
            commit(
                &current,
                4,
                &bounds(2, 2 * block_bytes),
                &batch(rows(), 0, OutputIndex::new(1))
            ),
            Err(Error::Invalid("checkpoint context mismatch"))
        );
        assert_eq!(
            commit(
                &current,
                4,
                &bounds(1, 2 * block_bytes),
                &batch(rows(), 0, zero)
            ),
            Err(Error::Invalid("checkpoint context mismatch"))
        );
        assert_eq!(
            commit(
                &current,
                4,
                &bounds(2, block_bytes),
                &batch(rows(), 0, zero)
            ),
            Err(Error::Invalid("commit block bytes exceed bound"))
        );
        let mut sparse = rows();
        sparse[1] = output_row(OutputIndex::new(3), &blocks[1]);
        assert_eq!(
            commit(
                &current,
                4,
                &bounds(2, 2 * block_bytes),
                &batch(sparse, 0, zero)
            ),
            Err(Error::Invalid("output rows are not dense or exact"))
        );
        let mut short = rows();
        short.pop();
        assert_eq!(
            commit(
                &current,
                4,
                &bounds(2, 2 * block_bytes),
                &batch(short, 0, zero)
            ),
            Err(Error::Invalid("checkpoint does not cover output batch"))
        );
    }

    /// A valid commit from genesis: one selected L-QC, the genesis opening, and one output.
    struct Valid {
        committee: Committee<MinPk>,
        current: Checkpoint<Sha256Digest>,
        record: Arc<HistoryRecord<Sha256Digest>>,
        proof: Arc<Lqc<MinPk, Sha256Digest>>,
        block: Arc<TransactionBlock<Sha256, TestBody>>,
    }

    impl Valid {
        fn new() -> Self {
            let committee = committee();
            let genesis = committee.config.genesis();
            let current = Checkpoint::try_from(CheckpointParts {
                view: View::zero(),
                history_index: None,
                ..checkpoint_parts(&checkpoint(
                    &committee,
                    0,
                    genesis.vqc(),
                    genesis.history(),
                    0,
                    genesis.tips().to_vec(),
                    OutputIndex::zero(),
                ))
            })
            .unwrap();
            let record =
                Arc::new(HistoryRecord::new(genesis.history(), genesis.tips().to_vec()).unwrap());
            let proof = Arc::new(committee.lqc_with(
                View::new(3),
                genesis.vqc(),
                record.commitment::<Sha256>(),
            ));
            Self {
                block: producer_block(&committee, 0, 10),
                committee,
                current,
                record,
                proof,
            }
        }

        fn parts(&self) -> CheckpointParts<Sha256Digest> {
            let mut emitted = self.current.emitted().to_vec();
            emitted[0] = self.block.reference();
            CheckpointParts {
                floor: self.proof.id::<Sha256>(),
                view: View::new(1),
                history: self.record.commitment::<Sha256>(),
                history_index: Some(0),
                ordered: self.record.tips().to_vec(),
                emitted,
                ..checkpoint_parts(&self.current)
            }
        }

        /// Returns the valid commit with its checkpoint parts edited.
        fn commit(
            &self,
            edit: impl Fn(&mut CheckpointParts<Sha256Digest>),
        ) -> Commit<Sha256, MinPk> {
            let mut parts = self.parts();
            edit(&mut parts);
            Commit {
                selected: vec![selected(&self.proof)],
                history: vec![HistoryOpening {
                    commitment: self.record.commitment::<Sha256>(),
                    record: Arc::clone(&self.record),
                }],
                outputs: vec![output_row(OutputIndex::new(1), &self.block)],
                checkpoint: Checkpoint::try_from(parts).unwrap(),
            }
        }

        /// Returns a block of chain zero above `parent`.
        fn child(
            &self,
            parent: &BlockRef<Sha256Digest>,
            timestamp: u64,
        ) -> Arc<TransactionBlock<Sha256, TestBody>> {
            let body = TestBody::new(
                Sha256::hash(&[b"application parent"]),
                Height::new(9),
                timestamp,
            );
            let header = self.committee.header(parent, body.digest());
            Arc::new(TransactionBlock::new(header, body).unwrap())
        }
    }

    fn selected(proof: &Arc<Lqc<MinPk, Sha256Digest>>) -> SelectedLqc<MinPk, Sha256> {
        SelectedLqc {
            view: proof.view(),
            id: proof.id::<Sha256>(),
            proof: Arc::clone(proof),
        }
    }

    #[test]
    fn commit_rejects_each_broken_invariant() {
        let valid = Valid::new();
        let genesis = valid.committee.config.genesis();
        let bounds = bounds(4, 1 << 20);
        let check = |batch: &Commit<Sha256, MinPk>| commit(&valid.current, 4, &bounds, batch);
        assert_eq!(check(&valid.commit(|_| {})), Ok(()));
        let mut cases = Vec::new();

        // Selected L-QCs share one view, and each takes one ordinal.
        let mut batch = valid.commit(|_| {});
        batch.selected.push(selected(&valid.proof));
        cases.push(("selected LQC does not establish checkpoint", batch));
        let later = Arc::new(valid.committee.lqc_with(
            View::new(4),
            genesis.vqc(),
            valid.record.commitment::<Sha256>(),
        ));
        let mut batch = valid.commit(|parts| parts.floor = later.id::<Sha256>());
        batch.selected.push(selected(&later));
        cases.push(("selected LQC does not establish checkpoint", batch));
        let mut batch = valid.commit(|_| {});
        batch.selected.clear();
        cases.push(("intermediate commit changed the LQC floor", batch));

        // Openings chain from the current history to the checkpoint's, one view and index each.
        let mut batch = valid.commit(|_| {});
        batch.history[0].commitment = Sha256::hash(&[b"other"]);
        cases.push(("history openings are not contiguous", batch));
        let orphan =
            HistoryRecord::new(Sha256::hash(&[b"other"]), genesis.tips().to_vec()).unwrap();
        let mut batch = valid.commit(|_| {});
        batch.history[0] = HistoryOpening {
            commitment: orphan.commitment::<Sha256>(),
            record: Arc::new(orphan),
        };
        cases.push(("history openings are not contiguous", batch));
        let mut batch = valid.commit(|_| {});
        batch.history.clear();
        cases.push(("history does not reach checkpoint", batch));
        cases.push((
            "checkpoint history index is not contiguous",
            valid.commit(|parts| parts.history_index = Some(1)),
        ));
        cases.push((
            "checkpoint ordering does not match history",
            valid.commit(|parts| parts.ordered = parts.emitted.clone()),
        ));

        // Rows extend each chain's emitted block with its child.
        let conflicting = producer_block(&valid.committee, 0, 11);
        cases.push((
            "checkpoint emission does not match output rows",
            valid.commit(|parts| parts.emitted[0] = conflicting.reference()),
        ));
        let grandchild = valid.child(&valid.block.reference(), 12);
        let mut batch = valid.commit(|parts| parts.emitted[0] = grandchild.reference());
        batch.outputs = vec![output_row(OutputIndex::new(1), &grandchild)];
        cases.push(("output rows do not advance exact chain frontiers", batch));
        let unlinked = valid.child(
            &BlockRef::new(ChainId::new(0), Height::zero(), Sha256::hash(&[b"other"])),
            13,
        );
        let mut batch = valid.commit(|parts| parts.emitted[0] = unlinked.reference());
        batch.outputs = vec![output_row(OutputIndex::new(1), &unlinked)];
        cases.push(("output rows do not advance exact chain frontiers", batch));

        for (expected, batch) in cases {
            assert_eq!(check(&batch), Err(Error::Invalid(expected)), "{expected}");
        }

        // A checkpoint whose emission falls behind the current one regresses.
        let ahead = Checkpoint::try_from(CheckpointParts {
            emitted: valid.parts().emitted,
            ..checkpoint_parts(&valid.current)
        })
        .unwrap();
        let regressed = Commit::<Sha256, MinPk> {
            selected: Vec::new(),
            history: Vec::new(),
            outputs: Vec::new(),
            checkpoint: valid.current.clone(),
        };
        assert_eq!(
            commit(&ahead, 4, &bounds, &regressed),
            Err(Error::Invalid(
                "checkpoint frontier regressed or conflicted"
            ))
        );
    }

    #[test]
    fn checkpoint_view_follows_openings_and_floors() {
        let committee = committee();
        let genesis = committee.config.genesis();
        let parts = checkpoint_parts;
        let current = Checkpoint::try_from(CheckpointParts {
            view: View::zero(),
            history: genesis.history(),
            history_index: None,
            ..parts(&checkpoint(
                &committee,
                0,
                genesis.vqc(),
                genesis.history(),
                0,
                genesis.tips().to_vec(),
                OutputIndex::zero(),
            ))
        })
        .unwrap();
        let record =
            Arc::new(HistoryRecord::new(genesis.history(), genesis.tips().to_vec()).unwrap());
        let commitment = record.commitment::<Sha256>();
        let opening = |view: u64| Commit::<Sha256, MinPk> {
            selected: Vec::new(),
            history: vec![HistoryOpening {
                commitment,
                record: Arc::clone(&record),
            }],
            outputs: Vec::new(),
            checkpoint: Checkpoint::try_from(CheckpointParts {
                view: View::new(view),
                history: commitment,
                history_index: Some(0),
                ..parts(&current)
            })
            .unwrap(),
        };
        let bounds = bounds(2, 1 << 20);
        assert_eq!(commit(&current, 4, &bounds, &opening(1)), Ok(()));
        for view in [0, 2] {
            assert_eq!(
                commit(&current, 4, &bounds, &opening(view)),
                Err(Error::Invalid(
                    "checkpoint view does not follow its openings"
                ))
            );
        }

        // A floor resolves the view its L-QC pins, and never an earlier view.
        let installed = opening(1).checkpoint;
        let proof = Arc::new(committee.lqc_with(View::new(2), genesis.vqc(), commitment));
        let request = |current: &Checkpoint<_>, view: u64| InstallRequest {
            checkpoint: Checkpoint::try_from(CheckpointParts {
                floor_generation: 1,
                floor: proof.id::<Sha256>(),
                view: View::new(view),
                history_index: next_history_index(current.history_index(), 1).unwrap(),
                ..parts(&installed)
            })
            .unwrap(),
            floors: PendingFloors {
                lqc: View::new(3),
                history: View::new(3),
                blocks: vec![Height::zero(); 4],
            },
            proof: Arc::clone(&proof),
            history: Arc::clone(&record),
        };
        assert_eq!(
            install::<Sha256, MinPk>(&current, 4, &request(&current, 1)),
            Ok(())
        );
        assert_eq!(
            install::<Sha256, MinPk>(&current, 4, &request(&current, 2)),
            Err(Error::Invalid(
                "floor artifacts do not establish checkpoint"
            ))
        );
        let ahead = Checkpoint::try_from(CheckpointParts {
            view: View::new(2),
            ..parts(&current)
        })
        .unwrap();
        assert_eq!(
            install::<Sha256, MinPk>(&ahead, 4, &request(&ahead, 1)),
            Err(Error::Invalid(
                "floor installation is not a newer compatible generation"
            ))
        );

        // Both installed frontiers are the floor opening's tips.
        let mut beyond = genesis.tips().to_vec();
        beyond[0] = producer_block(&committee, 0, 10).reference();
        for (ordered, emitted) in [
            (beyond.clone(), beyond.clone()),
            (genesis.tips().to_vec(), beyond),
        ] {
            let mut request = request(&current, 1);
            request.checkpoint = Checkpoint::try_from(CheckpointParts {
                ordered,
                emitted,
                floor_index: OutputIndex::new(1),
                ..parts(&request.checkpoint)
            })
            .unwrap();
            assert_eq!(
                install::<Sha256, MinPk>(&current, 4, &request),
                Err(Error::Invalid(
                    "floor artifacts do not establish checkpoint"
                ))
            );
        }

        // An admitted opening must hash to the commitment it is admitted under.
        let misnamed = Admission::<Sha256, MinPk, TestBody>::History(
            View::new(1),
            Sha256::hash(&[b"other"]),
            Arc::clone(&record),
        );
        assert_eq!(
            admission(current.epoch(), 4, 1 << 20, &misnamed),
            Err(Error::Invalid("history commitment mismatch"))
        );
    }

    #[test]
    fn history_index_counts_appended_openings() {
        assert_eq!(next_history_index(None, 0), Ok(None));
        assert_eq!(next_history_index(Some(4), 0), Ok(Some(4)));
        assert_eq!(next_history_index(None, 1), Ok(Some(0)));
        assert_eq!(next_history_index(None, 3), Ok(Some(2)));
        assert_eq!(next_history_index(Some(4), 2), Ok(Some(6)));
        assert_eq!(
            next_history_index(Some(u64::MAX), 1),
            Err(Error::Invalid("history index overflow"))
        );
    }
}
