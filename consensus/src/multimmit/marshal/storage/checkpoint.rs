//! Bounded durable checkpoints for one Multimmit marshal epoch.

use crate::{
    multimmit::{
        marshal::types::OutputIndex,
        types::{BlockRef, CertificateId, ChainId, Height},
    },
    types::{Epoch, View},
};
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::Digest;

/// The on-disk checkpoint layout version.
const CHECKPOINT_VERSION: u8 = 1;

/// The on-disk catalog-state layout version.
const CATALOG_STATE_VERSION: u8 = 2;

/// Finalized archive backends bound to one storage namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ArchiveLayout {
    prunable: [bool; 3],
}

impl ArchiveLayout {
    pub(crate) const fn new(lqc: bool, history: bool, blocks: bool) -> Self {
        Self {
            prunable: [lqc, history, blocks],
        }
    }

    pub(crate) const fn blocks_prunable(self) -> bool {
        self.prunable[2]
    }
}

impl Write for ArchiveLayout {
    fn write(&self, buf: &mut impl BufMut) {
        for prunable in self.prunable {
            prunable.write(buf);
        }
    }
}

impl EncodeSize for ArchiveLayout {
    fn encode_size(&self) -> usize {
        self.prunable.iter().map(EncodeSize::encode_size).sum()
    }
}

impl Read for ArchiveLayout {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self::new(
            bool::read(buf)?,
            bool::read(buf)?,
            bool::read(buf)?,
        ))
    }
}

/// Immutable context needed to decode one epoch's checkpoint.
///
/// Chain counts are stored independently of the target architecture and converted to an
/// allocation size only after construction validates them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CheckpointCodecConfig {
    epoch: Epoch,
    chains: u32,
    max_state_bytes: usize,
}

impl CheckpointCodecConfig {
    /// Creates a codec configuration for one non-empty epoch.
    ///
    /// # Panics
    ///
    /// Panics if `chains` is zero or cannot be represented by [`ChainId`].
    pub(crate) fn new(epoch: Epoch, chains: usize, max_state_bytes: usize) -> Self {
        assert!(chains > 0, "checkpoint requires at least one chain");
        assert!(
            max_state_bytes > 0,
            "catalog state must permit at least one byte"
        );
        Self {
            epoch,
            chains: u32::try_from(chains).expect("checkpoint chain count exceeds u32::MAX"),
            max_state_bytes,
        }
    }

    const fn chains(self) -> usize {
        self.chains as usize
    }
}

/// Temporary archive floors authorized by one installed application snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::multimmit::marshal) struct Prune {
    pub(in crate::multimmit::marshal) pending_lqc: View,
    pub(in crate::multimmit::marshal) pending_history: View,
    pub(in crate::multimmit::marshal) pending_blocks: Vec<Height>,
}

impl Prune {
    fn read_cfg(buf: &mut impl Buf, config: &CheckpointCodecConfig) -> Result<Self, Error> {
        Ok(Self {
            pending_lqc: View::read(buf)?,
            pending_history: View::read(buf)?,
            pending_blocks: Vec::<Height>::read_cfg(buf, &(RangeCfg::exact(config.chains()), ()))?,
        })
    }
}

impl Write for Prune {
    fn write(&self, buf: &mut impl BufMut) {
        self.pending_lqc.write(buf);
        self.pending_history.write(buf);
        self.pending_blocks.write(buf);
    }
}

impl EncodeSize for Prune {
    fn encode_size(&self) -> usize {
        self.pending_lqc.encode_size()
            + self.pending_history.encode_size()
            + self.pending_blocks.encode_size()
    }
}

/// The complete durable ordering and delivery cut for one marshal epoch.
///
/// `floor` names the exact authenticated L-QC retained as the recovery anchor. `history` is the
/// authenticated tip-history commitment opened at that anchor. The ordered and emitted frontiers
/// contain one reference per chain in chain-index order. Emission contains the recursive ordering
/// frontier and may lead it because an LQC's final sweep can append beyond its parent's `Ord`.
/// Output indices are optional because index zero is valid and cannot double as the empty-prefix
/// sentinel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Checkpoint<D: Digest> {
    epoch: Epoch,
    generation: u64,
    archive_layout: ArchiveLayout,
    floor: CertificateId<D>,
    history: D,
    history_index: Option<u64>,
    ordered: Vec<BlockRef<D>>,
    emitted: Vec<BlockRef<D>>,
    committed: Option<OutputIndex>,
    acknowledged: Option<OutputIndex>,
}

impl<D: Digest> Checkpoint<D> {
    /// Creates a structurally valid restart checkpoint.
    ///
    /// Cryptographic authentication and ancestry checks belong to the floor installer. This
    /// constructor enforces the canonical relationships that are decidable from the checkpoint.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        epoch: Epoch,
        generation: u64,
        archive_layout: ArchiveLayout,
        floor: CertificateId<D>,
        history: D,
        history_index: Option<u64>,
        ordered: Vec<BlockRef<D>>,
        emitted: Vec<BlockRef<D>>,
        committed: Option<OutputIndex>,
        acknowledged: Option<OutputIndex>,
    ) -> Option<Self> {
        if ordered.is_empty()
            || ordered.len() != emitted.len()
            || u32::try_from(ordered.len()).is_err()
            || !canonical_frontier(&ordered)
            || !canonical_frontier(&emitted)
            || ordered.iter().zip(&emitted).any(|(ordered, emitted)| {
                emitted.height() < ordered.height()
                    || (emitted.height() == ordered.height() && emitted != ordered)
            })
            || acknowledged > committed
        {
            return None;
        }

        Some(Self {
            epoch,
            generation,
            archive_layout,
            floor,
            history,
            history_index,
            ordered,
            emitted,
            committed,
            acknowledged,
        })
    }

    /// Returns the checkpoint's epoch.
    pub(crate) const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the active floor generation.
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the finalized archive layout fixed for this namespace.
    pub(crate) const fn archive_layout(&self) -> ArchiveLayout {
        self.archive_layout
    }

    /// Returns the exact L-QC retained as the floor anchor.
    pub(crate) const fn floor(&self) -> CertificateId<D> {
        self.floor
    }

    /// Returns the authenticated tip-history commitment at the ordering frontier.
    pub(crate) const fn history(&self) -> D {
        self.history
    }

    /// Returns the local index of the latest finalized history opening.
    pub(crate) const fn history_index(&self) -> Option<u64> {
        self.history_index
    }

    /// Returns the highest ordered block on every chain, in chain-index order.
    pub(crate) fn ordered(&self) -> &[BlockRef<D>] {
        &self.ordered
    }

    /// Returns the highest emitted block on every chain, in chain-index order.
    pub(crate) fn emitted(&self) -> &[BlockRef<D>] {
        &self.emitted
    }

    /// Returns the dense committed high-water, if any output has been committed.
    pub(crate) const fn committed(&self) -> Option<OutputIndex> {
        self.committed
    }

    /// Returns the durably acknowledged output cursor, if any output has been acknowledged.
    pub(crate) const fn acknowledged(&self) -> Option<OutputIndex> {
        self.acknowledged
    }

    /// Replaces the delivery cursor with the catalog owner's current value.
    ///
    /// Ordering commits are prepared concurrently with delivery acknowledgements, so callers
    /// cannot authoritatively copy this field. The catalog applies it immediately before
    /// validating and persisting a new checkpoint.
    pub(crate) fn preserve_acknowledged(&mut self, acknowledged: Option<OutputIndex>) -> bool {
        if acknowledged > self.committed {
            return false;
        }
        self.acknowledged = acknowledged;
        true
    }
}

/// One recoverable floor installation bound to its exact checkpoint and cleanup floors.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InstallIntent<D: Digest> {
    checkpoint: Checkpoint<D>,
    prune: Prune,
    proof: Bytes,
    history: Bytes,
}

/// Cleanup still owed after one ordinary checkpoint-last commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommitCleanup {
    selected: Option<View>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CatalogPhase<D: Digest> {
    Ready,
    CommitCleanup(CommitCleanup),
    Install(Box<InstallIntent<D>>),
}

/// The catalog checkpoint and any recovery work that must finish before serving reads.
///
/// An install phase retains the old application frontier and owns everything recovery needs to
/// finish archive installation and temporary-data pruning. The candidate becomes current only
/// after both steps complete. A commit-cleanup phase instead marks an already-current ordinary
/// checkpoint whose exact temporary prune may have been interrupted. It records only the selected
/// LQC view because finalized body cleanup is independently derived from a durable immutable
/// promotion cursor or explicit application pruning. The LQC index is the inclusive high-water
/// mark of the finalized proof archive, whose ordinal indexing preserves distinct exact
/// certificates at the same view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::multimmit::marshal) struct CatalogState<D: Digest> {
    checkpoint: Checkpoint<D>,
    lqc_index: Option<u64>,
    phase: CatalogPhase<D>,
}

impl<D: Digest> CatalogState<D> {
    /// Creates an idle catalog state at a complete checkpoint.
    pub(in crate::multimmit::marshal) const fn ready(
        checkpoint: Checkpoint<D>,
        lqc_index: Option<u64>,
    ) -> Self {
        Self {
            checkpoint,
            lqc_index,
            phase: CatalogPhase::Ready,
        }
    }

    /// Publishes an ordinary checkpoint together with its replayable cleanup obligation.
    #[cfg(test)]
    pub(in crate::multimmit::marshal) const fn committed(
        checkpoint: Checkpoint<D>,
        lqc_index: Option<u64>,
        selected: Option<View>,
    ) -> Self {
        Self {
            checkpoint,
            lqc_index,
            phase: CatalogPhase::CommitCleanup(CommitCleanup { selected }),
        }
    }

    /// Advances an ordinary checkpoint while preserving unfinished cleanup.
    pub(in crate::multimmit::marshal) fn checkpointed(
        &self,
        checkpoint: Checkpoint<D>,
    ) -> Option<Self> {
        let phase = match &self.phase {
            CatalogPhase::Ready => CatalogPhase::Ready,
            CatalogPhase::CommitCleanup(cleanup) => CatalogPhase::CommitCleanup(*cleanup),
            CatalogPhase::Install(_) => return None,
        };
        Self::from_parts(checkpoint, self.lqc_index, phase)
    }

    /// Publishes an ordinary checkpoint and coalesces its cleanup obligation.
    pub(in crate::multimmit::marshal) fn publish_commit(
        &self,
        checkpoint: Checkpoint<D>,
        lqc_index: Option<u64>,
        selected: Option<View>,
    ) -> Option<Self> {
        if matches!(&self.phase, CatalogPhase::Install(_)) {
            return None;
        }
        let selected = self.commit_cleanup().flatten().max(selected);
        Self::from_parts(
            checkpoint,
            lqc_index,
            CatalogPhase::CommitCleanup(CommitCleanup { selected }),
        )
    }

    /// Binds an exact install candidate before finalized archives are changed.
    pub(in crate::multimmit::marshal) fn begin(
        &self,
        checkpoint: Checkpoint<D>,
        proof_view: View,
        prune: Prune,
        proof: Bytes,
        history: Bytes,
    ) -> Option<Self> {
        if matches!(self.phase, CatalogPhase::Install(_))
            || proof.is_empty()
            || history.is_empty()
            || !valid_install(&self.checkpoint, &checkpoint, &prune)
        {
            return None;
        }
        let lqc_index = next_lqc_index(self.lqc_index, proof_view)?;
        Some(Self {
            checkpoint: self.checkpoint.clone(),
            lqc_index: Some(lqc_index),
            phase: CatalogPhase::Install(Box::new(InstallIntent {
                checkpoint,
                prune,
                proof,
                history,
            })),
        })
    }

    /// Publishes the candidate after its finalized artifacts and cleanup are durable.
    pub(in crate::multimmit::marshal) fn finish(&self) -> Option<Self> {
        let CatalogPhase::Install(install) = &self.phase else {
            return None;
        };
        Some(Self::ready(install.checkpoint.clone(), self.lqc_index))
    }

    /// Returns the checkpoint visible to ordinary catalog operations.
    pub(in crate::multimmit::marshal) const fn checkpoint(&self) -> &Checkpoint<D> {
        &self.checkpoint
    }

    /// Returns the inclusive finalized LQC archive high-water mark.
    pub(in crate::multimmit::marshal) const fn lqc_index(&self) -> Option<u64> {
        self.lqc_index
    }

    /// Returns the exact pending install checkpoint, if any.
    pub(in crate::multimmit::marshal) const fn install_checkpoint(&self) -> Option<&Checkpoint<D>> {
        match &self.phase {
            CatalogPhase::Install(install) => Some(&install.checkpoint),
            _ => None,
        }
    }

    /// Returns the cleanup floors bound to the pending install, if any.
    pub(in crate::multimmit::marshal) const fn install_prune(&self) -> Option<&Prune> {
        match &self.phase {
            CatalogPhase::Install(install) => Some(&install.prune),
            _ => None,
        }
    }

    /// Returns the exact encoded proof bound by the first durable install record.
    pub(in crate::multimmit::marshal) const fn install_proof(&self) -> Option<&Bytes> {
        match &self.phase {
            CatalogPhase::Install(install) => Some(&install.proof),
            _ => None,
        }
    }

    /// Returns the exact encoded history bound by the first durable install record.
    pub(in crate::multimmit::marshal) const fn install_history(&self) -> Option<&Bytes> {
        match &self.phase {
            CatalogPhase::Install(install) => Some(&install.history),
            _ => None,
        }
    }

    /// Returns the selected LQC view bound to an interrupted ordinary cleanup.
    pub(in crate::multimmit::marshal) const fn commit_cleanup(&self) -> Option<Option<View>> {
        match &self.phase {
            CatalogPhase::CommitCleanup(cleanup) => Some(cleanup.selected),
            _ => None,
        }
    }

    fn from_parts(
        checkpoint: Checkpoint<D>,
        lqc_index: Option<u64>,
        phase: CatalogPhase<D>,
    ) -> Option<Self> {
        if let CatalogPhase::Install(install) = &phase
            && (install.proof.is_empty()
                || install.history.is_empty()
                || lqc_index.is_none()
                || !valid_install(&checkpoint, &install.checkpoint, &install.prune))
        {
            return None;
        }
        Some(Self {
            checkpoint,
            lqc_index,
            phase,
        })
    }
}

pub(in crate::multimmit::marshal) fn next_lqc_index(
    current: Option<u64>,
    view: View,
) -> Option<u64> {
    current.map_or(Some(view.get()), |index| {
        index.checked_add(1).map(|next| next.max(view.get()))
    })
}

impl<D: Digest> Write for CatalogState<D> {
    fn write(&self, buf: &mut impl BufMut) {
        CATALOG_STATE_VERSION.write(buf);
        self.checkpoint.write(buf);
        self.lqc_index.write(buf);
        match &self.phase {
            CatalogPhase::Ready => 0u8.write(buf),
            CatalogPhase::CommitCleanup(cleanup) => {
                1u8.write(buf);
                cleanup.selected.write(buf);
            }
            CatalogPhase::Install(install) => {
                2u8.write(buf);
                install.checkpoint.write(buf);
                install.prune.write(buf);
                install.proof.write(buf);
                install.history.write(buf);
            }
        }
    }
}

impl<D: Digest> EncodeSize for CatalogState<D> {
    fn encode_size(&self) -> usize {
        CATALOG_STATE_VERSION.encode_size()
            + self.checkpoint.encode_size()
            + self.lqc_index.encode_size()
            + 0u8.encode_size()
            + match &self.phase {
                CatalogPhase::Ready => 0,
                CatalogPhase::CommitCleanup(cleanup) => cleanup.selected.encode_size(),
                CatalogPhase::Install(install) => {
                    install.checkpoint.encode_size()
                        + install.prune.encode_size()
                        + install.proof.encode_size()
                        + install.history.encode_size()
                }
            }
    }
}

impl<D: Digest> Read for CatalogState<D> {
    type Cfg = CheckpointCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        let version = u8::read(buf)?;
        if version != CATALOG_STATE_VERSION {
            return Err(Error::InvalidEnum(version));
        }
        let checkpoint = Checkpoint::read_cfg(buf, config)?;
        let lqc_index = Option::<u64>::read(buf)?;
        let phase = match u8::read(buf)? {
            0 => CatalogPhase::Ready,
            1 => CatalogPhase::CommitCleanup(CommitCleanup {
                selected: Option::<View>::read(buf)?,
            }),
            2 => CatalogPhase::Install(Box::new(InstallIntent {
                checkpoint: Checkpoint::read_cfg(buf, config)?,
                prune: Prune::read_cfg(buf, config)?,
                proof: Bytes::read_cfg(buf, &RangeCfg::new(..=config.max_state_bytes))?,
                history: Bytes::read_cfg(buf, &RangeCfg::new(..=config.max_state_bytes))?,
            })),
            value => return Err(Error::InvalidEnum(value)),
        };
        Self::from_parts(checkpoint, lqc_index, phase).ok_or(Error::Invalid(
            "consensus::multimmit::marshal::CatalogState",
            "catalog recovery state is not canonical",
        ))
    }
}

fn valid_install<D: Digest>(
    current: &Checkpoint<D>,
    target: &Checkpoint<D>,
    prune: &Prune,
) -> bool {
    let next_history = current
        .history_index()
        .map_or(Some(0), |index| index.checked_add(1));
    target.epoch() == current.epoch()
        && target.generation() > current.generation()
        && target.archive_layout() == current.archive_layout()
        && target.history_index() == next_history
        && target.committed() == current.committed()
        && target.acknowledged() == target.committed()
        && prune.pending_blocks.len() == current.ordered().len()
        && frontier_advances(current.ordered(), target.ordered())
        && frontier_advances(current.emitted(), target.emitted())
}

fn frontier_advances<D: Digest>(current: &[BlockRef<D>], next: &[BlockRef<D>]) -> bool {
    current.len() == next.len()
        && current
            .iter()
            .zip(next)
            .all(|(current, next)| next.height() > current.height() || next == current)
}

impl<D: Digest> Write for Checkpoint<D> {
    fn write(&self, buf: &mut impl BufMut) {
        CHECKPOINT_VERSION.write(buf);
        self.epoch.write(buf);
        self.generation.write(buf);
        self.archive_layout.write(buf);
        self.floor.write(buf);
        self.history.write(buf);
        self.history_index.write(buf);
        self.ordered.write(buf);
        self.emitted.write(buf);
        self.committed.write(buf);
        self.acknowledged.write(buf);
    }
}

impl<D: Digest> EncodeSize for Checkpoint<D> {
    fn encode_size(&self) -> usize {
        CHECKPOINT_VERSION.encode_size()
            + self.epoch.encode_size()
            + self.generation.encode_size()
            + self.archive_layout.encode_size()
            + self.floor.encode_size()
            + self.history.encode_size()
            + self.history_index.encode_size()
            + self.ordered.encode_size()
            + self.emitted.encode_size()
            + self.committed.encode_size()
            + self.acknowledged.encode_size()
    }
}

impl<D: Digest> Read for Checkpoint<D> {
    type Cfg = CheckpointCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        let version = u8::read(buf)?;
        if version != CHECKPOINT_VERSION {
            return Err(Error::InvalidEnum(version));
        }

        let epoch = Epoch::read(buf)?;
        if epoch != config.epoch {
            return Err(Error::Invalid(
                "consensus::multimmit::marshal::Checkpoint",
                "checkpoint epoch does not match its codec context",
            ));
        }

        let generation = u64::read(buf)?;
        let archive_layout = ArchiveLayout::read(buf)?;
        let floor = CertificateId::read(buf)?;
        let history = D::read(buf)?;
        let history_index = Option::<u64>::read(buf)?;
        let frontier_cfg = (RangeCfg::exact(config.chains()), ());
        let ordered = Vec::<BlockRef<D>>::read_cfg(buf, &frontier_cfg)?;
        let emitted = Vec::<BlockRef<D>>::read_cfg(buf, &frontier_cfg)?;
        let committed = Option::<OutputIndex>::read(buf)?;
        let acknowledged = Option::<OutputIndex>::read(buf)?;

        Self::new(
            epoch,
            generation,
            archive_layout,
            floor,
            history,
            history_index,
            ordered,
            emitted,
            committed,
            acknowledged,
        )
        .ok_or(Error::Invalid(
            "consensus::multimmit::marshal::Checkpoint",
            "checkpoint state is not canonical",
        ))
    }
}

fn canonical_frontier<D: Digest>(frontier: &[BlockRef<D>]) -> bool {
    frontier
        .iter()
        .enumerate()
        .all(|(index, reference)| u32::try_from(index).map(ChainId::new) == Ok(reference.chain()))
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for Checkpoint<D>
where
    D: Digest + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        use crate::types::Height;

        let epoch = u.arbitrary()?;
        let generation = u.arbitrary()?;
        let archive_layout = ArchiveLayout::new(u.arbitrary()?, u.arbitrary()?, u.arbitrary()?);
        let floor = CertificateId::new(u.arbitrary()?);
        let history = u.arbitrary()?;
        let history_index = u.arbitrary()?;
        let chains = u.int_in_range(1..=8u32)?;
        let mut ordered = Vec::with_capacity(chains as usize);
        let mut emitted = Vec::with_capacity(chains as usize);
        for chain in 0..chains {
            let ordered_height: u64 = u.arbitrary()?;
            let delta = u.int_in_range(0..=u64::MAX - ordered_height)?;
            let emitted_height = ordered_height + delta;
            let ordered_digest = u.arbitrary()?;
            let emitted_digest = if delta == 0 {
                ordered_digest
            } else {
                u.arbitrary()?
            };
            let chain = ChainId::new(chain);
            emitted.push(BlockRef::new(
                chain,
                Height::new(emitted_height),
                emitted_digest,
            ));
            ordered.push(BlockRef::new(
                chain,
                Height::new(ordered_height),
                ordered_digest,
            ));
        }

        let (committed, acknowledged) = match u.int_in_range(0..=2u8)? {
            0 => (None, None),
            1 => (Some(OutputIndex::new(u.arbitrary()?)), None),
            _ => {
                let acknowledged: u64 = u.arbitrary()?;
                let delta = u.int_in_range(0..=u64::MAX - acknowledged)?;
                (
                    Some(OutputIndex::new(acknowledged + delta)),
                    Some(OutputIndex::new(acknowledged)),
                )
            }
        };

        Ok(Self::new(
            epoch,
            generation,
            archive_layout,
            floor,
            history,
            history_index,
            ordered,
            emitted,
            committed,
            acknowledged,
        )
        .expect("generated checkpoint is canonical"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Height;
    use bytes::BytesMut;
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{Hasher, Sha256, sha256::Digest as Sha256Digest};

    type TestCheckpoint = Checkpoint<Sha256Digest>;

    fn digest(label: &[u8]) -> Sha256Digest {
        Sha256::hash(&[label])
    }

    fn reference(chain: u32, height: u64, label: &[u8]) -> BlockRef<Sha256Digest> {
        BlockRef::new(ChainId::new(chain), Height::new(height), digest(label))
    }

    fn checkpoint() -> TestCheckpoint {
        TestCheckpoint::new(
            Epoch::new(7),
            3,
            ArchiveLayout::new(true, false, true),
            CertificateId::new(digest(b"floor")),
            digest(b"history"),
            Some(4),
            vec![reference(0, 5, b"ordered 0"), reference(1, 9, b"shared 1")],
            vec![reference(0, 7, b"emitted 0"), reference(1, 9, b"shared 1")],
            Some(OutputIndex::new(12)),
            Some(OutputIndex::new(10)),
        )
        .unwrap()
    }

    fn config() -> CheckpointCodecConfig {
        CheckpointCodecConfig::new(Epoch::new(7), 2, 1024 * 1024)
    }

    fn install_target(current: &TestCheckpoint) -> TestCheckpoint {
        TestCheckpoint::new(
            current.epoch(),
            current.generation() + 1,
            current.archive_layout(),
            CertificateId::new(digest(b"installed floor")),
            digest(b"installed history"),
            Some(current.history_index().unwrap() + 1),
            current.ordered().to_vec(),
            current.emitted().to_vec(),
            current.committed(),
            current.committed(),
        )
        .unwrap()
    }

    fn install_prune() -> Prune {
        Prune {
            pending_lqc: View::new(11),
            pending_history: View::new(11),
            pending_blocks: vec![Height::new(8), Height::new(10)],
        }
    }

    #[test]
    fn round_trip_preserves_restart_cut() {
        let checkpoint = checkpoint();
        let encoded = checkpoint.encode();
        assert_eq!(encoded.len(), checkpoint.encode_size());
        assert_eq!(
            TestCheckpoint::decode_cfg(encoded, &config()).unwrap(),
            checkpoint
        );
        assert_eq!(checkpoint.epoch(), Epoch::new(7));
        assert_eq!(checkpoint.generation(), 3);
        assert_eq!(checkpoint.floor(), CertificateId::new(digest(b"floor")));
        assert_eq!(checkpoint.history(), digest(b"history"));
        assert_eq!(checkpoint.history_index(), Some(4));
        assert_eq!(checkpoint.ordered().len(), 2);
        assert_eq!(checkpoint.emitted().len(), 2);
        assert_eq!(checkpoint.committed(), Some(OutputIndex::new(12)));
        assert_eq!(checkpoint.acknowledged(), Some(OutputIndex::new(10)));
    }

    #[test]
    fn catalog_state_round_trips_every_recovery_obligation() {
        let current = checkpoint();
        let target = install_target(&current);
        let ready = CatalogState::ready(current.clone(), Some(7));
        let intent = ready
            .begin(
                target.clone(),
                View::new(11),
                install_prune(),
                Bytes::from_static(b"proof"),
                Bytes::from_static(b"history"),
            )
            .expect("compatible install begins");
        let finished = intent.finish().expect("intent becomes ready");
        let cleanup = CatalogState::committed(current.clone(), Some(7), Some(View::new(11)));
        let block_cleanup = CatalogState::committed(current.clone(), Some(7), None);

        assert_eq!(intent.checkpoint(), &current);
        assert_eq!(finished, CatalogState::ready(target, Some(11)));

        for state in [ready, intent, finished, cleanup, block_cleanup] {
            let encoded = state.encode();
            assert_eq!(encoded.len(), state.encode_size());
            assert_eq!(
                CatalogState::<Sha256Digest>::decode_cfg(encoded, &config()).unwrap(),
                state
            );
        }
    }

    #[test]
    fn ordinary_transitions_preserve_and_coalesce_cleanup() {
        let current = checkpoint();
        let cleanup = CatalogState::committed(current.clone(), Some(7), Some(View::new(11)));

        let without_selection = cleanup
            .publish_commit(current.clone(), Some(8), None)
            .expect("ordinary publication follows cleanup");
        assert_eq!(
            without_selection.commit_cleanup(),
            Some(Some(View::new(11)))
        );

        let with_newer_selection = without_selection
            .publish_commit(current.clone(), Some(12), Some(View::new(12)))
            .expect("later publication coalesces cleanup");
        assert_eq!(
            with_newer_selection.commit_cleanup(),
            Some(Some(View::new(12)))
        );

        let mut acknowledged = current;
        assert!(acknowledged.preserve_acknowledged(Some(OutputIndex::new(11))));
        let acknowledged = with_newer_selection
            .checkpointed(acknowledged)
            .expect("acknowledgement preserves ordinary cleanup");
        assert_eq!(
            acknowledged.checkpoint().acknowledged(),
            Some(OutputIndex::new(11))
        );
        assert_eq!(acknowledged.commit_cleanup(), Some(Some(View::new(12))));
    }

    #[test]
    fn finalized_lqc_indices_preserve_views_and_same_view_multiplicity() {
        assert_eq!(next_lqc_index(None, View::new(7)), Some(7));
        assert_eq!(next_lqc_index(Some(7), View::new(7)), Some(8));
        assert_eq!(next_lqc_index(Some(8), View::new(12)), Some(12));
        assert_eq!(next_lqc_index(Some(u64::MAX), View::new(12)), None);
    }

    #[test]
    fn constructor_rejects_non_canonical_state() {
        let valid = checkpoint();

        let mut wrong_chain = valid.ordered.clone();
        wrong_chain[1] = reference(0, 9, b"wrong chain");
        assert!(
            TestCheckpoint::new(
                valid.epoch,
                valid.generation,
                valid.archive_layout,
                valid.floor,
                valid.history,
                valid.history_index,
                wrong_chain,
                valid.emitted.clone(),
                valid.committed,
                valid.acknowledged,
            )
            .is_none()
        );

        let conflicting_same_height =
            vec![reference(0, 5, b"conflict"), reference(1, 9, b"shared 1")];
        assert!(
            TestCheckpoint::new(
                valid.epoch,
                valid.generation,
                valid.archive_layout,
                valid.floor,
                valid.history,
                valid.history_index,
                valid.ordered.clone(),
                conflicting_same_height,
                valid.committed,
                valid.acknowledged,
            )
            .is_none()
        );

        let emitted_behind = vec![reference(0, 4, b"behind"), reference(1, 9, b"shared 1")];
        assert!(
            TestCheckpoint::new(
                valid.epoch,
                valid.generation,
                valid.archive_layout,
                valid.floor,
                valid.history,
                valid.history_index,
                valid.ordered.clone(),
                emitted_behind,
                valid.committed,
                valid.acknowledged,
            )
            .is_none()
        );

        assert!(
            TestCheckpoint::new(
                valid.epoch,
                valid.generation,
                valid.archive_layout,
                valid.floor,
                valid.history,
                valid.history_index,
                valid.ordered.clone(),
                valid.emitted.clone(),
                Some(OutputIndex::new(4)),
                Some(OutputIndex::new(5)),
            )
            .is_none()
        );
        assert!(
            TestCheckpoint::new(
                valid.epoch,
                valid.generation,
                valid.archive_layout,
                valid.floor,
                valid.history,
                valid.history_index,
                valid.ordered,
                valid.emitted,
                None,
                Some(OutputIndex::ZERO),
            )
            .is_none()
        );
    }

    #[test]
    fn decode_rejects_wrong_version_epoch_and_chain_count() {
        let encoded = checkpoint().encode();

        let mut wrong_version = encoded.to_vec();
        wrong_version[0] = CHECKPOINT_VERSION.wrapping_add(1);
        assert!(matches!(
            TestCheckpoint::decode_cfg(wrong_version.as_slice(), &config()),
            Err(Error::InvalidEnum(version)) if version == CHECKPOINT_VERSION.wrapping_add(1)
        ));

        assert!(matches!(
            TestCheckpoint::decode_cfg(
                encoded.clone(),
                &CheckpointCodecConfig::new(Epoch::new(8), 2, 1024 * 1024),
            ),
            Err(Error::Invalid(
                "consensus::multimmit::marshal::Checkpoint",
                "checkpoint epoch does not match its codec context"
            ))
        ));

        assert!(matches!(
            TestCheckpoint::decode_cfg(
                encoded,
                &CheckpointCodecConfig::new(Epoch::new(7), 3, 1024 * 1024),
            ),
            Err(Error::InvalidLength(_))
        ));
    }

    #[test]
    fn decode_rejects_adversarial_frontiers_and_cursors() {
        fn encode_parts(
            ordered: Vec<BlockRef<Sha256Digest>>,
            emitted: Vec<BlockRef<Sha256Digest>>,
            committed: Option<OutputIndex>,
            acknowledged: Option<OutputIndex>,
        ) -> Vec<u8> {
            let mut encoded = BytesMut::new();
            CHECKPOINT_VERSION.write(&mut encoded);
            Epoch::new(7).write(&mut encoded);
            3u64.write(&mut encoded);
            ArchiveLayout::new(true, false, true).write(&mut encoded);
            CertificateId::new(digest(b"floor")).write(&mut encoded);
            digest(b"history").write(&mut encoded);
            Some(4u64).write(&mut encoded);
            ordered.write(&mut encoded);
            emitted.write(&mut encoded);
            committed.write(&mut encoded);
            acknowledged.write(&mut encoded);
            encoded.to_vec()
        }

        let ordered = vec![reference(0, 5, b"ordered 0"), reference(1, 9, b"shared 1")];
        let emitted = vec![reference(0, 7, b"emitted 0"), reference(1, 9, b"shared 1")];

        let duplicate_chain = encode_parts(
            vec![reference(0, 5, b"ordered 0"), reference(0, 9, b"duplicate")],
            emitted.clone(),
            None,
            None,
        );
        assert!(matches!(
            TestCheckpoint::decode_cfg(duplicate_chain.as_slice(), &config()),
            Err(Error::Invalid(
                "consensus::multimmit::marshal::Checkpoint",
                "checkpoint state is not canonical"
            ))
        ));

        let conflicting_same_height = encode_parts(
            ordered.clone(),
            vec![reference(0, 5, b"conflict"), reference(1, 9, b"shared 1")],
            None,
            None,
        );
        assert!(TestCheckpoint::decode_cfg(conflicting_same_height.as_slice(), &config()).is_err());

        let regressing_cursor = encode_parts(
            ordered,
            emitted,
            Some(OutputIndex::new(2)),
            Some(OutputIndex::new(3)),
        );
        assert!(TestCheckpoint::decode_cfg(regressing_cursor.as_slice(), &config()).is_err());
    }

    #[test]
    fn decode_rejects_oversized_length_before_allocation() {
        let checkpoint = checkpoint();
        let mut encoded = BytesMut::new();
        CHECKPOINT_VERSION.write(&mut encoded);
        checkpoint.epoch.write(&mut encoded);
        checkpoint.generation.write(&mut encoded);
        checkpoint.archive_layout.write(&mut encoded);
        checkpoint.floor.write(&mut encoded);
        checkpoint.history.write(&mut encoded);
        checkpoint.history_index.write(&mut encoded);
        (u32::MAX as usize).write(&mut encoded);

        assert!(matches!(
            TestCheckpoint::decode_cfg(encoded.freeze(), &config()),
            Err(Error::InvalidLength(_))
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::generate_value;
        use commonware_conformance::Conformance;

        struct CheckpointConformance;
        struct ReadyCatalogStateConformance;
        struct CommitCleanupCatalogStateConformance;
        struct InstallCatalogStateConformance;

        fn catalog_state_bytes(state: CatalogState<Sha256Digest>) -> Vec<u8> {
            let checkpoint = state.checkpoint();
            let config = CheckpointCodecConfig::new(
                checkpoint.epoch(),
                checkpoint.ordered().len(),
                1024 * 1024,
            );
            let encoded = state.encode();
            assert_eq!(
                CatalogState::<Sha256Digest>::decode_cfg(encoded.clone(), &config).unwrap(),
                state
            );
            encoded.to_vec()
        }

        impl Conformance for CheckpointConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let checkpoint = generate_value::<TestCheckpoint>(seed);
                let config = CheckpointCodecConfig::new(
                    checkpoint.epoch(),
                    checkpoint.ordered().len(),
                    1024 * 1024,
                );
                let encoded = checkpoint.encode();
                assert_eq!(
                    TestCheckpoint::decode_cfg(encoded.clone(), &config).unwrap(),
                    checkpoint
                );
                encoded.to_vec()
            }
        }

        impl Conformance for ReadyCatalogStateConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                catalog_state_bytes(CatalogState::ready(
                    generate_value::<TestCheckpoint>(seed),
                    Some(seed),
                ))
            }
        }

        impl Conformance for CommitCleanupCatalogStateConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let selected = seed.is_multiple_of(2).then_some(View::new(seed));
                catalog_state_bytes(CatalogState::committed(
                    generate_value::<TestCheckpoint>(seed),
                    Some(seed),
                    selected,
                ))
            }
        }

        impl Conformance for InstallCatalogStateConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let mut current = generate_value::<TestCheckpoint>(seed);
                current.generation = seed % u64::MAX;
                current.history_index = None;
                let target = TestCheckpoint::new(
                    current.epoch(),
                    current.generation() + 1,
                    current.archive_layout(),
                    CertificateId::new(digest(b"conformance installed floor")),
                    digest(b"conformance installed history"),
                    Some(0),
                    current.ordered().to_vec(),
                    current.emitted().to_vec(),
                    current.committed(),
                    current.committed(),
                )
                .unwrap();
                let prune = Prune {
                    pending_lqc: View::new(seed),
                    pending_history: View::new(seed.wrapping_add(1)),
                    pending_blocks: current
                        .ordered()
                        .iter()
                        .map(|reference| reference.height())
                        .collect(),
                };
                let state = CatalogState::ready(current, Some(seed % u64::MAX))
                    .begin(
                        target,
                        View::new(seed),
                        prune,
                        Bytes::copy_from_slice(&seed.to_be_bytes()),
                        Bytes::copy_from_slice(&seed.wrapping_add(1).to_be_bytes()),
                    )
                    .unwrap();
                catalog_state_bytes(state)
            }
        }

        commonware_conformance::conformance_tests! {
            CheckpointConformance => 128,
            ReadyCatalogStateConformance => 128,
            CommitCleanupCatalogStateConformance => 128,
            InstallCatalogStateConformance => 128,
        }
    }
}
