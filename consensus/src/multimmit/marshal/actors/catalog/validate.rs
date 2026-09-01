//! Request validation against the catalog's checkpoint and bounds.
//!
//! Each check reads only its inputs, so a rejected request leaves every store untouched.

use super::{actor::Bounds, mailbox::Error};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        marshal::{
            storage::{
                catalog::{Admission, InstallRequest},
                catalog_state::Checkpoint,
                commit::{Commit, HistoryOpening, OutputRow, SelectedLqc},
            },
            types::OutputIndex,
        },
        types::{BlockRef, Body},
    },
    types::Epoch,
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};

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
/// artifacts.
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
        || checkpoint.committed() != current.committed()
        || !current.advances_to(checkpoint)
    {
        return Err(Error::Invalid(
            "floor installation is not a newer compatible generation",
        ));
    }
    if proof.id::<H>() != checkpoint.floor()
        || proof.epoch() != checkpoint.epoch()
        || proof.leader().history() != checkpoint.history()
        || history.commitment::<H>() != checkpoint.history()
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
        || next.archive_layout() != current.archive_layout()
        || next.chains() != chains
        || batch.selected.len() > bounds.max_commit_outputs.get()
        || batch.outputs.len() > bounds.max_commit_outputs.get()
    {
        return Err(Error::Invalid("checkpoint context mismatch"));
    }
    Ok(())
}

/// Checks that the selected L-QCs are ordered, belong to the epoch, and establish the floor.
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
    }) || selected.windows(2).any(|pair| pair[0].view > pair[1].view)
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
    let mut expected =
        OutputIndex::after(current.committed()).ok_or(Error::Invalid("output index overflow"))?;
    let mut emitted = current.emitted().to_vec();
    let mut output_bytes = 0usize;
    for (position, row) in rows.iter().enumerate() {
        let encoded_len = usize::try_from(row.meta().encoded_len()).unwrap_or(usize::MAX);
        if position > 0
            && output_bytes
                .checked_add(encoded_len)
                .is_none_or(|total| total > bounds.max_commit_block_bytes.get())
        {
            return Err(Error::Invalid("commit block bytes exceed bound"));
        }
        output_bytes = output_bytes.saturating_add(encoded_len);
        let reference = row.reference();
        if position > 0 {
            expected = expected
                .next()
                .ok_or(Error::Invalid("output index overflow"))?;
        }
        if row.index != expected || !exact::<H>(row, current.epoch(), chains) {
            return Err(Error::Invalid("output rows are not dense or exact"));
        }
        advance(&mut emitted, reference)?;
    }
    let committed = rows
        .last()
        .map_or(current.committed(), |row| Some(row.index));
    if next.committed() != committed {
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

/// Advances `reference`'s chain frontier in `emitted` by exactly one height.
fn advance<D: Digest>(emitted: &mut [BlockRef<D>], reference: BlockRef<D>) -> Result<(), Error> {
    let frontier = &mut emitted[reference.chain().get() as usize];
    let height = frontier
        .height()
        .get()
        .checked_add(1)
        .ok_or(Error::Invalid("output frontier overflow"))?;
    if reference.height().get() != height {
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
        super::tests::{checkpoint, output_row, producer_block},
        *,
    };
    use crate::{
        multimmit::{
            mocks::Committee,
            testing::TestBody,
            types::{PathLimits, genesis_history},
        },
        types::Participant,
    };
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};
    use commonware_utils::NZUsize;
    use std::sync::Arc;

    fn committee() -> Committee<MinPk> {
        Committee::<MinPk>::builder(7, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_VALIDATE")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build()
    }

    const fn bounds(max_commit_outputs: usize, max_commit_block_bytes: usize) -> Bounds {
        Bounds {
            max_commit_outputs: NZUsize!(max_commit_outputs),
            max_commit_block_bytes: NZUsize!(max_commit_block_bytes),
            max_block_bytes: NZUsize!(1 << 20),
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
            genesis.lqc(),
            genesis_history::<Sha256>(genesis),
            0,
            genesis.tips().to_vec(),
            None,
        );
        let blocks = [
            producer_block(&committee, 0, 10),
            producer_block(&committee, 1, 11),
        ];
        let mut emitted = genesis.tips().to_vec();
        emitted[0] = blocks[0].reference();
        emitted[1] = blocks[1].reference();
        let batch = |outputs: Vec<OutputRow<_>>, floor_generation| Commit::<Sha256, MinPk> {
            selected: Vec::new(),
            history: Vec::new(),
            outputs,
            checkpoint: checkpoint(
                &committee,
                floor_generation,
                genesis.lqc(),
                genesis_history::<Sha256>(genesis),
                0,
                emitted.clone(),
                Some(OutputIndex::new(1)),
            ),
        };
        let rows = || {
            vec![
                output_row(OutputIndex::ZERO, &blocks[0]),
                output_row(OutputIndex::new(1), &blocks[1]),
            ]
        };
        let block_bytes = blocks[0].encode_size();
        assert_eq!(
            commit(&current, 4, &bounds(2, 2 * block_bytes), &batch(rows(), 0)),
            Ok(())
        );
        assert_eq!(
            commit(&current, 4, &bounds(2, 2 * block_bytes), &batch(rows(), 1)),
            Err(Error::Invalid("checkpoint context mismatch"))
        );
        assert_eq!(
            commit(&current, 4, &bounds(1, 2 * block_bytes), &batch(rows(), 0)),
            Err(Error::Invalid("checkpoint context mismatch"))
        );
        assert_eq!(
            commit(&current, 4, &bounds(2, block_bytes), &batch(rows(), 0)),
            Err(Error::Invalid("commit block bytes exceed bound"))
        );
        let mut sparse = rows();
        sparse[1] = output_row(OutputIndex::new(2), &blocks[1]);
        assert_eq!(
            commit(&current, 4, &bounds(2, 2 * block_bytes), &batch(sparse, 0)),
            Err(Error::Invalid("output rows are not dense or exact"))
        );
        let mut short = rows();
        short.pop();
        assert_eq!(
            commit(&current, 4, &bounds(2, 2 * block_bytes), &batch(short, 0)),
            Err(Error::Invalid("checkpoint does not cover output batch"))
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
