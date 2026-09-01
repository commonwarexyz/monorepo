//! The catalog's durable record: the ordering checkpoint and the recovery work owed around it.
//!
//! [`CatalogState`] is stored as the catalog's only metadata row. It holds the published
//! [`Checkpoint`] and a [`CatalogPhase`] naming work that recovery must finish at open:
//!
//! ```text
//!                publish commit
//!   Ready ---------------------------> CommitCleanup --publish commit--> CommitCleanup
//!     |                                     |
//!     | begin install                       | begin install
//!     v                                     v
//!   Install --finish install (archives, pending prune)--> Ready
//! ```
//!
//! A commit-cleanup phase is replayed at every open until another state replaces it, because its
//! pending-archive prune is idempotent.

#[cfg(feature = "arbitrary")]
use crate::multimmit::types::ChainId;
use crate::{
    multimmit::{
        marshal::{
            config::{ArchiveMode, Retention},
            types::OutputIndex,
        },
        types::{BlockRef, CertificateId, Frontier, FrontierError},
    },
    types::{Epoch, Height, View},
};
use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::Digest;

/// Version byte leading every encoded [`CatalogState`].
const STATE_VERSION: u8 = 1;

/// Encoded width of the [`CatalogPhase`] tag.
const TAG_SIZE: usize = u8::SIZE;

/// Immutable context needed to decode one epoch's catalog state.
///
/// Chain counts are stored independently of the target architecture and converted to an
/// allocation size only after construction validates them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CheckpointCodecConfig {
    epoch: Epoch,
    chains: u32,
    max_install_artifact_bytes: usize,
}

/// Pending-archive floors installed with a state-sync floor.
///
/// Pending L-QCs and history below their view floors, and pending blocks below each chain's
/// height floor, are reclaimed when the installation finishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingFloors {
    /// Lowest pending L-QC view retained.
    pub(crate) lqc: View,
    /// Lowest pending history view retained.
    pub(crate) history: View,
    /// Lowest pending block height retained on each chain, in chain order.
    pub(crate) blocks: Vec<Height>,
}

/// The complete durable ordering cut for one marshal epoch.
///
/// `floor` names the authenticated L-QC retained as the recovery anchor, and `history` is the
/// tip-history commitment opened at that anchor. `ordered` holds the highest block ordered on each
/// chain. `emitted` holds the highest block handed to the application on each chain; it may be
/// ahead of `ordered` because an L-QC's final sweep emits blocks beyond the ordering its parent
/// established. The committed output index is optional because index zero is a valid output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Checkpoint<D: Digest> {
    epoch: Epoch,
    floor_generation: u64,
    archive_layout: Retention,
    floor: CertificateId<D>,
    history: D,
    history_index: Option<u64>,
    ordered: Frontier<D>,
    emitted: Frontier<D>,
    committed: Option<OutputIndex>,
}

/// The fields of a [`Checkpoint`] before validation.
pub(crate) struct CheckpointParts<D: Digest> {
    /// Epoch the checkpoint belongs to.
    pub(crate) epoch: Epoch,
    /// Active state-sync generation.
    pub(crate) floor_generation: u64,
    /// Finalized archive backends of the namespace.
    pub(crate) archive_layout: Retention,
    /// L-QC retained as the recovery anchor.
    pub(crate) floor: CertificateId<D>,
    /// Tip-history commitment at the ordering frontier.
    pub(crate) history: D,
    /// Local index of the latest finalized history opening.
    pub(crate) history_index: Option<u64>,
    /// Highest ordered block on every chain, in chain order.
    pub(crate) ordered: Vec<BlockRef<D>>,
    /// Highest emitted block on every chain, in chain order.
    pub(crate) emitted: Vec<BlockRef<D>>,
    /// Dense committed high-water, if any output has been committed.
    pub(crate) committed: Option<OutputIndex>,
}

/// A checkpoint's frontiers are not canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CheckpointError {
    /// A frontier is empty, out of chain order, behind, or conflicting.
    #[error("checkpoint frontier is not canonical: {0}")]
    Frontier(#[from] FrontierError),
}

/// A floor installation was rejected before any durable change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum InstallReject {
    /// Another installation has not finished.
    #[error("another floor installation is pending")]
    Pending,
    /// The encoded proof or history is empty.
    #[error("floor installation artifacts are empty")]
    EmptyArtifacts,
    /// The L-QC ordinal would move below the current one.
    #[error("floor L-QC ordinal regresses")]
    LqcIndex,
    /// The target belongs to another epoch.
    #[error("floor installation epoch differs")]
    Epoch,
    /// The target generation does not advance.
    #[error("floor generation does not advance")]
    Generation,
    /// The target names other finalized archive backends.
    #[error("floor archive layout differs")]
    Retention,
    /// The target history index does not follow the current one.
    #[error("floor history index is not the next index")]
    HistoryIndex,
    /// The target changes the committed output.
    #[error("floor installation changes the committed output")]
    Committed,
    /// The pending floors cover another chain count.
    #[error("pending floors cover another chain count")]
    Floors,
    /// A target frontier regresses or conflicts.
    #[error("floor frontier regresses or conflicts")]
    Frontier,
}

/// One recoverable floor installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstallIntent<D: Digest> {
    /// Checkpoint published once installation finishes.
    pub(crate) checkpoint: Checkpoint<D>,
    /// Pending-archive floors applied before publication.
    pub(crate) floors: PendingFloors,
    /// Encoded floor L-QC, archived before publication.
    pub(crate) proof: Bytes,
    /// Encoded floor history opening, archived before publication.
    pub(crate) history: Bytes,
}

/// Pending-archive cleanup owed after ordinary commits.
///
/// Only the selected L-QC view is recorded: finalized body cleanup follows the durable promotion
/// cursor or explicit application pruning instead.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommitCleanup {
    /// Highest L-QC view selected by the covered commits; pending L-QCs and history at or below
    /// it are reclaimed.
    pub(crate) selected: Option<View>,
}

/// Recovery work bound to a [`CatalogState`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CatalogPhase<D: Digest> {
    /// No recovery work is owed.
    Ready,
    /// The checkpoint is published; its pending-archive cleanup may have been interrupted.
    CommitCleanup(CommitCleanup),
    /// An installation is in progress. The stored checkpoint stays current until the intent's
    /// artifacts are archived and its pending floors applied.
    Install(Box<InstallIntent<D>>),
}

/// The catalog checkpoint and any recovery work that must finish before serving reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CatalogState<D: Digest> {
    checkpoint: Checkpoint<D>,
    /// Inclusive high-water ordinal of the finalized L-QC archive, attached to the published
    /// checkpoint or to a pending installation. Ordinals keep distinct certificates at one view.
    lqc_index: Option<u64>,
    phase: CatalogPhase<D>,
}

impl CheckpointCodecConfig {
    /// Creates a codec configuration for one non-empty epoch.
    ///
    /// # Panics
    ///
    /// Panics if `chains` is zero or exceeds `u32::MAX`, or if `max_install_artifact_bytes` is
    /// zero.
    pub(crate) fn new(epoch: Epoch, chains: usize, max_install_artifact_bytes: usize) -> Self {
        assert!(chains > 0, "checkpoint requires at least one chain");
        assert!(
            max_install_artifact_bytes > 0,
            "installation artifacts must permit at least one byte"
        );
        Self {
            epoch,
            chains: u32::try_from(chains).expect("checkpoint chain count exceeds u32::MAX"),
            max_install_artifact_bytes,
        }
    }

    const fn chains(self) -> usize {
        self.chains as usize
    }
}

impl<D: Digest> TryFrom<CheckpointParts<D>> for Checkpoint<D> {
    type Error = CheckpointError;

    /// Enforces the relationships decidable from the checkpoint alone: both frontiers are
    /// canonical and emission dominates ordering. Authentication belongs to the floor installer.
    fn try_from(parts: CheckpointParts<D>) -> Result<Self, CheckpointError> {
        let ordered = Frontier::new(parts.ordered)?;
        let emitted = Frontier::new(parts.emitted)?;
        emitted.dominates(&ordered)?;
        Ok(Self {
            epoch: parts.epoch,
            floor_generation: parts.floor_generation,
            archive_layout: parts.archive_layout,
            floor: parts.floor,
            history: parts.history,
            history_index: parts.history_index,
            ordered,
            emitted,
            committed: parts.committed,
        })
    }
}

impl<D: Digest> Checkpoint<D> {
    /// Returns the checkpoint's epoch.
    pub(crate) const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the active floor generation.
    pub(crate) const fn floor_generation(&self) -> u64 {
        self.floor_generation
    }

    /// Returns the finalized archive layout fixed for this namespace.
    pub(crate) const fn archive_layout(&self) -> Retention {
        self.archive_layout
    }

    /// Returns the L-QC retained as the floor anchor.
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

    /// Returns the number of producer chains.
    pub(crate) const fn chains(&self) -> usize {
        self.ordered.chains()
    }

    /// Returns the highest ordered block on every chain, in chain order.
    pub(crate) fn ordered(&self) -> &[BlockRef<D>] {
        self.ordered.references()
    }

    /// Returns the highest emitted block on every chain, in chain order.
    pub(crate) fn emitted(&self) -> &[BlockRef<D>] {
        self.emitted.references()
    }

    /// Returns the emitted frontier.
    pub(crate) const fn emitted_frontier(&self) -> &Frontier<D> {
        &self.emitted
    }

    /// Returns the dense committed high-water, if any output has been committed.
    pub(crate) const fn committed(&self) -> Option<OutputIndex> {
        self.committed
    }

    /// Returns whether both of `next`'s frontiers dominate this checkpoint's.
    pub(crate) fn advances_to(&self, next: &Self) -> bool {
        self.ordered.advances_to(&next.ordered) && self.emitted.advances_to(&next.emitted)
    }
}

impl CommitCleanup {
    /// Extends this cleanup through a later commit's.
    pub(crate) fn coalesce(&mut self, later: Self) {
        self.selected = self.selected.max(later.selected);
    }
}

impl<D: Digest> CatalogState<D> {
    /// Creates an idle catalog state at a complete checkpoint.
    pub(crate) const fn ready(checkpoint: Checkpoint<D>, lqc_index: Option<u64>) -> Self {
        Self {
            checkpoint,
            lqc_index,
            phase: CatalogPhase::Ready,
        }
    }

    /// Creates a published checkpoint that still owes the given cleanup.
    #[cfg(test)]
    pub(crate) const fn committed(
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

    /// Publishes an ordinary checkpoint and coalesces its cleanup with any cleanup still owed.
    ///
    /// Returns `None` while an installation is pending.
    pub(crate) fn publish_commit(
        &self,
        checkpoint: Checkpoint<D>,
        lqc_index: Option<u64>,
        cleanup: CommitCleanup,
    ) -> Option<Self> {
        let mut owed = match &self.phase {
            CatalogPhase::Install(_) => return None,
            CatalogPhase::Ready => CommitCleanup::default(),
            CatalogPhase::CommitCleanup(owed) => *owed,
        };
        owed.coalesce(cleanup);
        Some(Self {
            checkpoint,
            lqc_index,
            phase: CatalogPhase::CommitCleanup(owed),
        })
    }

    /// Binds an installation before finalized archives change.
    ///
    /// The floor L-QC takes the ordinal after `lqc_predecessor` (see [`next_lqc_index`]).
    pub(crate) fn begin(
        &self,
        checkpoint: Checkpoint<D>,
        proof_view: View,
        lqc_predecessor: Option<u64>,
        floors: PendingFloors,
        proof: Bytes,
        history: Bytes,
    ) -> Result<Self, InstallReject> {
        if matches!(self.phase, CatalogPhase::Install(_)) {
            return Err(InstallReject::Pending);
        }
        if lqc_predecessor < self.lqc_index {
            return Err(InstallReject::LqcIndex);
        }
        if proof.is_empty() || history.is_empty() {
            return Err(InstallReject::EmptyArtifacts);
        }
        validate_install(&self.checkpoint, &checkpoint, &floors)?;
        let lqc_index =
            next_lqc_index(lqc_predecessor, proof_view).ok_or(InstallReject::LqcIndex)?;
        Ok(Self {
            checkpoint: self.checkpoint.clone(),
            lqc_index: Some(lqc_index),
            phase: CatalogPhase::Install(Box::new(InstallIntent {
                checkpoint,
                floors,
                proof,
                history,
            })),
        })
    }

    /// Publishes the pending installation's checkpoint once its artifacts and floors are durable.
    pub(crate) fn finish(&self) -> Option<Self> {
        let CatalogPhase::Install(install) = &self.phase else {
            return None;
        };
        Some(Self::ready(install.checkpoint.clone(), self.lqc_index))
    }

    /// Returns the checkpoint visible to ordinary catalog operations.
    pub(crate) const fn checkpoint(&self) -> &Checkpoint<D> {
        &self.checkpoint
    }

    /// Returns the inclusive finalized L-QC archive high-water mark.
    pub(crate) const fn lqc_index(&self) -> Option<u64> {
        self.lqc_index
    }

    /// Returns the pending installation, if any.
    pub(crate) fn install(&self) -> Option<&InstallIntent<D>> {
        match &self.phase {
            CatalogPhase::Install(install) => Some(install),
            _ => None,
        }
    }

    /// Returns the cleanup owed by a published ordinary commit, if any.
    pub(crate) const fn commit_cleanup(&self) -> Option<CommitCleanup> {
        match &self.phase {
            CatalogPhase::CommitCleanup(cleanup) => Some(*cleanup),
            _ => None,
        }
    }
}

impl Read for PendingFloors {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, chains: &usize) -> Result<Self, Error> {
        Ok(Self {
            lqc: View::read(buf)?,
            history: View::read(buf)?,
            blocks: Vec::<Height>::read_cfg(buf, &(RangeCfg::exact(*chains), ()))?,
        })
    }
}

impl Write for PendingFloors {
    fn write(&self, buf: &mut impl BufMut) {
        self.lqc.write(buf);
        self.history.write(buf);
        self.blocks.write(buf);
    }
}

impl EncodeSize for PendingFloors {
    fn encode_size(&self) -> usize {
        self.lqc.encode_size() + self.history.encode_size() + self.blocks.encode_size()
    }
}

/// Each family is encoded as one byte that is set when the family is prunable.
impl Write for Retention {
    fn write(&self, buf: &mut impl BufMut) {
        for mode in [self.lqc, self.history, self.blocks] {
            (mode == ArchiveMode::Prunable).write(buf);
        }
    }
}

impl EncodeSize for Retention {
    fn encode_size(&self) -> usize {
        3 * bool::SIZE
    }
}

impl Read for Retention {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let mode = |prunable| {
            if prunable {
                ArchiveMode::Prunable
            } else {
                ArchiveMode::Immutable
            }
        };
        Ok(Self {
            lqc: mode(bool::read(buf)?),
            history: mode(bool::read(buf)?),
            blocks: mode(bool::read(buf)?),
        })
    }
}

impl<D: Digest> Write for Checkpoint<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.floor_generation.write(buf);
        self.archive_layout.write(buf);
        self.floor.write(buf);
        self.history.write(buf);
        self.history_index.write(buf);
        self.ordered().write(buf);
        self.emitted().write(buf);
        self.committed.write(buf);
    }
}

impl<D: Digest> EncodeSize for Checkpoint<D> {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size()
            + self.floor_generation.encode_size()
            + self.archive_layout.encode_size()
            + self.floor.encode_size()
            + self.history.encode_size()
            + self.history_index.encode_size()
            + self.ordered().encode_size()
            + self.emitted().encode_size()
            + self.committed.encode_size()
    }
}

impl<D: Digest> Read for Checkpoint<D> {
    type Cfg = CheckpointCodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &Self::Cfg) -> Result<Self, Error> {
        let epoch = Epoch::read(buf)?;
        if epoch != config.epoch {
            return Err(Error::Invalid(
                "consensus::multimmit::marshal::Checkpoint",
                "checkpoint epoch does not match its codec context",
            ));
        }
        let floor_generation = u64::read(buf)?;
        let archive_layout = Retention::read(buf)?;
        let floor = CertificateId::read(buf)?;
        let history = D::read(buf)?;
        let history_index = Option::<u64>::read(buf)?;
        let frontier = (RangeCfg::exact(config.chains()), ());
        let ordered = Vec::<BlockRef<D>>::read_cfg(buf, &frontier)?;
        let emitted = Vec::<BlockRef<D>>::read_cfg(buf, &frontier)?;
        let committed = Option::<OutputIndex>::read(buf)?;
        Self::try_from(CheckpointParts {
            epoch,
            floor_generation,
            archive_layout,
            floor,
            history,
            history_index,
            ordered,
            emitted,
            committed,
        })
        .map_err(|_| {
            Error::Invalid(
                "consensus::multimmit::marshal::Checkpoint",
                "checkpoint state is not canonical",
            )
        })
    }
}

impl<D: Digest> Write for CatalogState<D> {
    fn write(&self, buf: &mut impl BufMut) {
        STATE_VERSION.write(buf);
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
                install.floors.write(buf);
                install.proof.write(buf);
                install.history.write(buf);
            }
        }
    }
}

impl<D: Digest> EncodeSize for CatalogState<D> {
    fn encode_size(&self) -> usize {
        STATE_VERSION.encode_size()
            + self.checkpoint.encode_size()
            + self.lqc_index.encode_size()
            + TAG_SIZE
            + match &self.phase {
                CatalogPhase::Ready => 0,
                CatalogPhase::CommitCleanup(cleanup) => cleanup.selected.encode_size(),
                CatalogPhase::Install(install) => {
                    install.checkpoint.encode_size()
                        + install.floors.encode_size()
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
        if version != STATE_VERSION {
            return Err(Error::InvalidEnum(version));
        }
        let checkpoint = Checkpoint::read_cfg(buf, config)?;
        let lqc_index = Option::<u64>::read(buf)?;
        let artifact = RangeCfg::new(..=config.max_install_artifact_bytes);
        let phase = match u8::read(buf)? {
            0 => CatalogPhase::Ready,
            1 => CatalogPhase::CommitCleanup(CommitCleanup {
                selected: Option::<View>::read(buf)?,
            }),
            2 => {
                let install = InstallIntent {
                    checkpoint: Checkpoint::read_cfg(buf, config)?,
                    floors: PendingFloors::read_cfg(buf, &config.chains())?,
                    proof: Bytes::read_cfg(buf, &artifact)?,
                    history: Bytes::read_cfg(buf, &artifact)?,
                };
                if install.proof.is_empty()
                    || install.history.is_empty()
                    || lqc_index.is_none()
                    || validate_install(&checkpoint, &install.checkpoint, &install.floors).is_err()
                {
                    return Err(Error::Invalid(
                        "consensus::multimmit::marshal::CatalogState",
                        "catalog recovery state is not canonical",
                    ));
                }
                CatalogPhase::Install(Box::new(install))
            }
            value => return Err(Error::InvalidEnum(value)),
        };
        Ok(Self {
            checkpoint,
            lqc_index,
            phase,
        })
    }
}

/// Returns the finalized archive ordinal for the next selected L-QC.
///
/// The ordinal is `max(current + 1, view)`: it follows the previous ordinal so certificates at the
/// same view stay distinct, and it jumps to the view when the view is higher so ordinals track
/// views. Returns `None` on overflow.
pub(crate) fn next_lqc_index(current: Option<u64>, view: View) -> Option<u64> {
    current.map_or(Some(view.get()), |index| {
        index.checked_add(1).map(|next| next.max(view.get()))
    })
}

/// Checks that `target` can replace `current` through a floor installation.
fn validate_install<D: Digest>(
    current: &Checkpoint<D>,
    target: &Checkpoint<D>,
    floors: &PendingFloors,
) -> Result<(), InstallReject> {
    let next_history = current
        .history_index()
        .map_or(Some(0), |index| index.checked_add(1));
    if target.epoch() != current.epoch() {
        return Err(InstallReject::Epoch);
    }
    if target.floor_generation() <= current.floor_generation() {
        return Err(InstallReject::Generation);
    }
    if target.archive_layout() != current.archive_layout() {
        return Err(InstallReject::Retention);
    }
    if target.history_index() != next_history {
        return Err(InstallReject::HistoryIndex);
    }
    if target.committed() != current.committed() {
        return Err(InstallReject::Committed);
    }
    if floors.blocks.len() != current.chains() {
        return Err(InstallReject::Floors);
    }
    if !current.advances_to(target) {
        return Err(InstallReject::Frontier);
    }
    Ok(())
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for Checkpoint<D>
where
    D: Digest + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let mode = |prunable| {
            if prunable {
                ArchiveMode::Prunable
            } else {
                ArchiveMode::Immutable
            }
        };
        let epoch = u.arbitrary()?;
        let floor_generation = u.arbitrary()?;
        let archive_layout = Retention {
            lqc: mode(u.arbitrary()?),
            history: mode(u.arbitrary()?),
            blocks: mode(u.arbitrary()?),
        };
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
        let committed = u.arbitrary()?;
        Ok(Self::try_from(CheckpointParts {
            epoch,
            floor_generation,
            archive_layout,
            floor,
            history,
            history_index,
            ordered,
            emitted,
            committed,
        })
        .expect("generated checkpoint is canonical"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::types::ChainId;
    use bytes::BytesMut;
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{Hasher, Sha256, sha256::Digest as Sha256Digest};

    type TestCheckpoint = Checkpoint<Sha256Digest>;

    const LAYOUT: Retention = Retention {
        lqc: ArchiveMode::Prunable,
        history: ArchiveMode::Immutable,
        blocks: ArchiveMode::Prunable,
    };

    fn digest(label: &[u8]) -> Sha256Digest {
        Sha256::hash(&[label])
    }

    fn reference(chain: u32, height: u64, label: &[u8]) -> BlockRef<Sha256Digest> {
        BlockRef::new(ChainId::new(chain), Height::new(height), digest(label))
    }

    fn parts() -> CheckpointParts<Sha256Digest> {
        CheckpointParts {
            epoch: Epoch::new(7),
            floor_generation: 3,
            archive_layout: LAYOUT,
            floor: CertificateId::new(digest(b"floor")),
            history: digest(b"history"),
            history_index: Some(4),
            ordered: vec![reference(0, 5, b"ordered 0"), reference(1, 9, b"shared 1")],
            emitted: vec![reference(0, 7, b"emitted 0"), reference(1, 9, b"shared 1")],
            committed: Some(OutputIndex::new(12)),
        }
    }

    fn checkpoint() -> TestCheckpoint {
        TestCheckpoint::try_from(parts()).unwrap()
    }

    fn config() -> CheckpointCodecConfig {
        CheckpointCodecConfig::new(Epoch::new(7), 2, 1024 * 1024)
    }

    fn install_target(current: &TestCheckpoint) -> TestCheckpoint {
        TestCheckpoint::try_from(CheckpointParts {
            epoch: current.epoch(),
            floor_generation: current.floor_generation() + 1,
            archive_layout: current.archive_layout(),
            floor: CertificateId::new(digest(b"installed floor")),
            history: digest(b"installed history"),
            history_index: Some(current.history_index().unwrap() + 1),
            ordered: current.ordered().to_vec(),
            emitted: current.emitted().to_vec(),
            committed: current.committed(),
        })
        .unwrap()
    }

    fn install_floors() -> PendingFloors {
        PendingFloors {
            lqc: View::new(11),
            history: View::new(11),
            blocks: vec![Height::new(8), Height::new(10)],
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
        assert_eq!(checkpoint.floor_generation(), 3);
        assert_eq!(checkpoint.floor(), CertificateId::new(digest(b"floor")));
        assert_eq!(checkpoint.history(), digest(b"history"));
        assert_eq!(checkpoint.history_index(), Some(4));
        assert_eq!(checkpoint.chains(), 2);
        assert_eq!(checkpoint.ordered().len(), 2);
        assert_eq!(checkpoint.emitted().len(), 2);
        assert_eq!(checkpoint.committed(), Some(OutputIndex::new(12)));
    }

    #[test]
    fn archive_layout_keeps_one_prunable_flag_per_family() {
        let encoded = LAYOUT.encode();
        assert_eq!(encoded.as_ref(), &[1, 0, 1]);
        assert_eq!(Retention::decode_cfg(encoded, &()).unwrap(), LAYOUT);
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
                Some(7),
                install_floors(),
                Bytes::from_static(b"proof"),
                Bytes::from_static(b"history"),
            )
            .expect("compatible install begins");
        let finished = intent.finish().expect("intent becomes ready");
        let cleanup = CatalogState::committed(current.clone(), Some(7), Some(View::new(11)));
        let block_cleanup = CatalogState::committed(current.clone(), Some(7), None);

        assert_eq!(intent.checkpoint(), &current);
        assert_eq!(intent.install().unwrap().checkpoint, target);
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
    fn install_rejections_name_the_failed_invariant() {
        let current = checkpoint();
        let ready = CatalogState::ready(current.clone(), Some(7));
        let begin = |state: &CatalogState<Sha256Digest>,
                     target: TestCheckpoint,
                     predecessor: Option<u64>,
                     floors: PendingFloors| {
            state.begin(
                target,
                View::new(11),
                predecessor,
                floors,
                Bytes::from_static(b"proof"),
                Bytes::from_static(b"history"),
            )
        };
        let target = install_target(&current);
        let intent = begin(&ready, target.clone(), Some(7), install_floors()).unwrap();
        assert_eq!(
            begin(&intent, target.clone(), Some(11), install_floors()),
            Err(InstallReject::Pending)
        );
        assert_eq!(
            begin(&ready, target.clone(), Some(6), install_floors()),
            Err(InstallReject::LqcIndex)
        );
        assert_eq!(
            ready.begin(
                target.clone(),
                View::new(11),
                Some(7),
                install_floors(),
                Bytes::new(),
                Bytes::from_static(b"history"),
            ),
            Err(InstallReject::EmptyArtifacts)
        );
        assert_eq!(
            begin(&ready, current, Some(7), install_floors()),
            Err(InstallReject::Generation)
        );
        let mut floors = install_floors();
        floors.blocks.pop();
        assert_eq!(
            begin(&ready, target, Some(7), floors),
            Err(InstallReject::Floors)
        );
        let mut regressed = parts();
        regressed.floor_generation += 1;
        regressed.history_index = Some(5);
        regressed.ordered[0] = reference(0, 4, b"behind");
        regressed.emitted[0] = reference(0, 7, b"emitted 0");
        assert_eq!(
            begin(
                &ready,
                TestCheckpoint::try_from(regressed).unwrap(),
                Some(7),
                install_floors()
            ),
            Err(InstallReject::Frontier)
        );
    }

    #[test]
    fn ordinary_transitions_preserve_and_coalesce_cleanup() {
        let current = checkpoint();
        let cleanup = CatalogState::committed(current.clone(), Some(7), Some(View::new(11)));

        let without_selection = cleanup
            .publish_commit(current.clone(), Some(8), CommitCleanup::default())
            .expect("ordinary publication follows cleanup");
        assert_eq!(
            without_selection.commit_cleanup(),
            Some(CommitCleanup {
                selected: Some(View::new(11))
            })
        );

        let with_newer_selection = without_selection
            .publish_commit(
                current,
                Some(12),
                CommitCleanup {
                    selected: Some(View::new(12)),
                },
            )
            .expect("later publication coalesces cleanup");
        assert_eq!(
            with_newer_selection.commit_cleanup(),
            Some(CommitCleanup {
                selected: Some(View::new(12))
            })
        );
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
        let mut wrong_chain = parts();
        wrong_chain.ordered[1] = reference(0, 9, b"wrong chain");
        assert!(matches!(
            TestCheckpoint::try_from(wrong_chain),
            Err(CheckpointError::Frontier(FrontierError::Chain {
                index: 1,
                ..
            }))
        ));

        let mut conflicting_same_height = parts();
        conflicting_same_height.emitted =
            vec![reference(0, 5, b"conflict"), reference(1, 9, b"shared 1")];
        assert!(matches!(
            TestCheckpoint::try_from(conflicting_same_height),
            Err(CheckpointError::Frontier(FrontierError::Conflict(_)))
        ));

        let mut emitted_behind = parts();
        emitted_behind.emitted = vec![reference(0, 4, b"behind"), reference(1, 9, b"shared 1")];
        assert!(matches!(
            TestCheckpoint::try_from(emitted_behind),
            Err(CheckpointError::Frontier(FrontierError::Regression(_)))
        ));

        let mut empty = parts();
        empty.ordered.clear();
        empty.emitted.clear();
        assert!(TestCheckpoint::try_from(empty).is_err());
    }

    #[test]
    fn decode_rejects_wrong_version_epoch_and_chain_count() {
        let encoded = CatalogState::ready(checkpoint(), None).encode();
        let mut wrong_version = encoded.to_vec();
        wrong_version[0] = STATE_VERSION.wrapping_add(1);
        assert!(matches!(
            CatalogState::<Sha256Digest>::decode_cfg(wrong_version, &config()),
            Err(Error::InvalidEnum(version)) if version == STATE_VERSION.wrapping_add(1)
        ));

        let encoded = checkpoint().encode();
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
    fn decode_rejects_adversarial_frontiers() {
        fn encode_parts(
            ordered: Vec<BlockRef<Sha256Digest>>,
            emitted: Vec<BlockRef<Sha256Digest>>,
            committed: Option<OutputIndex>,
        ) -> Vec<u8> {
            let mut encoded = BytesMut::new();
            Epoch::new(7).write(&mut encoded);
            3u64.write(&mut encoded);
            LAYOUT.write(&mut encoded);
            CertificateId::new(digest(b"floor")).write(&mut encoded);
            digest(b"history").write(&mut encoded);
            Some(4u64).write(&mut encoded);
            ordered.write(&mut encoded);
            emitted.write(&mut encoded);
            committed.write(&mut encoded);
            encoded.to_vec()
        }

        let ordered = vec![reference(0, 5, b"ordered 0"), reference(1, 9, b"shared 1")];
        let emitted = vec![reference(0, 7, b"emitted 0"), reference(1, 9, b"shared 1")];

        let duplicate_chain = encode_parts(
            vec![reference(0, 5, b"ordered 0"), reference(0, 9, b"duplicate")],
            emitted,
            None,
        );
        assert!(matches!(
            TestCheckpoint::decode_cfg(duplicate_chain, &config()),
            Err(Error::Invalid(
                "consensus::multimmit::marshal::Checkpoint",
                "checkpoint state is not canonical"
            ))
        ));

        let conflicting_same_height = encode_parts(
            ordered,
            vec![reference(0, 5, b"conflict"), reference(1, 9, b"shared 1")],
            None,
        );
        assert!(TestCheckpoint::decode_cfg(conflicting_same_height, &config()).is_err());
    }

    #[test]
    fn decode_rejects_oversized_length_before_allocation() {
        let checkpoint = checkpoint();
        let mut encoded = BytesMut::new();
        checkpoint.epoch.write(&mut encoded);
        checkpoint.floor_generation.write(&mut encoded);
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
            let config =
                CheckpointCodecConfig::new(checkpoint.epoch(), checkpoint.chains(), 1024 * 1024);
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
                    checkpoint.chains(),
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
                current.floor_generation = seed % u64::MAX;
                current.history_index = None;
                let target = TestCheckpoint::try_from(CheckpointParts {
                    epoch: current.epoch(),
                    floor_generation: current.floor_generation() + 1,
                    archive_layout: current.archive_layout(),
                    floor: CertificateId::new(digest(b"conformance installed floor")),
                    history: digest(b"conformance installed history"),
                    history_index: Some(0),
                    ordered: current.ordered().to_vec(),
                    emitted: current.emitted().to_vec(),
                    committed: current.committed(),
                })
                .unwrap();
                let floors = PendingFloors {
                    lqc: View::new(seed),
                    history: View::new(seed.wrapping_add(1)),
                    blocks: current
                        .ordered()
                        .iter()
                        .map(|reference| reference.height())
                        .collect(),
                };
                let state = CatalogState::ready(current, Some(seed % u64::MAX))
                    .begin(
                        target,
                        View::new(seed),
                        Some(seed % u64::MAX),
                        floors,
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
