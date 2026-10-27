//! Codec bounds and path limits shared by every Multimmit protocol object.

use crate::multimmit::types::ChainId;
use commonware_utils::{Faults as _, N5f1};
use std::sync::Arc;

/// Bounds on the paths one producer chain carries in proposals and votes, immutable within an
/// epoch.
///
/// The pipeline depth `d` bounds the blocks one proposal appends to the chain above its base. A
/// producer builds, and a validator DA-votes, at most [`Self::pipeline_window`] blocks above the
/// chain's DA-certified anchor. The extension bound `e` caps the blocks one vote carries for the
/// chain above its proposal position.
///
/// `d = 0` places only DA-certified blocks: a proposal names the chain's highest held DA
/// certificate and nothing above it, and the producer builds one block at a time above its
/// certified anchor. `e = 0` disables vote extensions. A chain with both set places a block only
/// through its DA certificate, which validators forward to upcoming leaders until it is placed.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PathLimits {
    pipeline_depth: u32,
    extension_bound: u32,
}

impl PathLimits {
    /// Creates path limits with pipeline depth `d` and extension bound `e`.
    pub const fn new(pipeline_depth: u32, extension_bound: u32) -> Self {
        Self {
            pipeline_depth,
            extension_bound,
        }
    }

    /// Returns the pipeline depth `d`.
    pub const fn pipeline_depth(self) -> u32 {
        self.pipeline_depth
    }

    /// Returns the extension bound `e`.
    pub const fn extension_bound(self) -> u32 {
        self.extension_bound
    }

    /// Returns how many blocks above the DA-certified anchor a producer builds and a validator
    /// DA-votes: `d`, or one when `d = 0` so the chain still advances.
    pub const fn pipeline_window(self) -> u32 {
        if self.pipeline_depth == 0 {
            1
        } else {
            self.pipeline_depth
        }
    }

    /// Returns whether proposals place only DA-certified blocks on the chain, `d = 0`.
    pub const fn certified_only(self) -> bool {
        self.pipeline_depth == 0
    }

    /// Returns the larger of each bound in `self` and `other`.
    const fn max(self, other: Self) -> Self {
        Self {
            pipeline_depth: if self.pipeline_depth > other.pipeline_depth {
                self.pipeline_depth
            } else {
                other.pipeline_depth
            },
            extension_bound: if self.extension_bound > other.extension_bound {
                self.extension_bound
            } else {
                other.extension_bound
            },
        }
    }
}

/// The [`PathLimits`] of every producer chain in one epoch, in chain order.
///
/// Decoding bounds every chain by the largest limits of any chain ([`Self::max`]); validation
/// then holds each chain to its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainLimits {
    chains: Arc<[PathLimits]>,
    max: PathLimits,
}

impl ChainLimits {
    /// Returns `limits` for each of `chains` producer chains.
    pub fn uniform(limits: PathLimits, chains: usize) -> Self {
        Self {
            chains: vec![limits; chains].into(),
            max: limits,
        }
    }

    /// Returns the limits of each producer chain, in chain order.
    ///
    /// # Errors
    ///
    /// Returns an error if `limits` is empty.
    pub fn new(limits: Vec<PathLimits>) -> Result<Self, CodecConfigError> {
        let max = limits
            .iter()
            .copied()
            .reduce(PathLimits::max)
            .ok_or(CodecConfigError::ZeroChains)?;
        Ok(Self {
            chains: limits.into(),
            max,
        })
    }

    /// Returns the limits of `chain`, or `None` when it is not a producer chain.
    pub fn get(&self, chain: ChainId) -> Option<PathLimits> {
        self.chains.get(chain.get() as usize).copied()
    }

    /// Returns the largest pipeline depth and extension bound of any chain.
    pub const fn max(&self) -> PathLimits {
        self.max
    }

    /// Returns the number of producer chains.
    pub fn len(&self) -> usize {
        self.chains.len()
    }

    /// Returns whether no producer chain is configured, which validated limits never are.
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }

    /// Returns each chain's limits in chain order.
    pub fn iter(&self) -> impl Iterator<Item = PathLimits> + '_ {
        self.chains.iter().copied()
    }
}

/// How many DA shares recover a data-availability certificate.
///
/// The quorum is the threshold of the DA key sharing, so it is fixed when the epoch's keys are
/// dealt.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum DaQuorum {
    /// `n - 2f` shares, so at least `f + 1` correct signers hold the block.
    #[default]
    Available,
    /// `n - f` shares, from every correct validator when `f` are faulty.
    ///
    /// On a chain with `d = 0` and `e = 0`, where nothing uncertified is ever placed, such a
    /// certificate is a binding receipt: its block is eventually placed and ordered.
    Binding,
}

/// Bounded inputs used while decoding untrusted protocol objects, and the quorums they imply.
///
/// Counts are stored as `u32` so their meaning is independent of the target
/// architecture. Getters convert them to allocation and indexing sizes only
/// after construction has validated both counts. Path limits are the largest of any chain (see
/// [`ChainLimits::max`]).
///
/// # Quorums
///
/// A committee of `n` participants tolerates `f` Byzantine faults with `n >= 5f + 1`, where `f`
/// is the largest such count. A data-availability certificate needs the [`DaQuorum`]: `n - 2f`
/// shares by default, so at least `f + 1` of its signers are correct and hold the block, or
/// `n - f` for binding certificates. An L-QC needs exactly `n - f` votes and
/// a V-QC accounts for between `n - f` and `n` messages. A nullification and a V-QC designation
/// each need `2f + 1`: such a set holds at least `f + 1` correct participants and overlaps every
/// `n - f` set in at least `f + 1` members, at least one of them correct. That overlap is why
/// neither can coexist with a conflicting L-QC.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CodecConfig {
    participants: u32,
    chains: u32,
    limits: PathLimits,
    da_quorum: DaQuorum,
}

impl CodecConfig {
    /// Creates bounded codec configuration for an epoch with the default [`DaQuorum`].
    pub fn new(
        participants: usize,
        chains: usize,
        limits: PathLimits,
    ) -> Result<Self, CodecConfigError> {
        if participants == 0 {
            return Err(CodecConfigError::ZeroParticipants);
        }
        if chains == 0 {
            return Err(CodecConfigError::ZeroChains);
        }

        let participants = u32::try_from(participants)
            .map_err(|_| CodecConfigError::TooManyParticipants(participants))?;
        let chains = u32::try_from(chains).map_err(|_| CodecConfigError::TooManyChains(chains))?;

        Ok(Self {
            participants,
            chains,
            limits,
            da_quorum: DaQuorum::Available,
        })
    }

    /// Returns this configuration with `limits` as the largest path limits of any chain.
    pub(crate) const fn with_limits(mut self, limits: PathLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Returns this configuration with DA certificates recovered from `quorum` shares.
    pub const fn with_da_quorum(mut self, quorum: DaQuorum) -> Self {
        self.da_quorum = quorum;
        self
    }

    /// Returns the number of participants.
    pub const fn participants(self) -> usize {
        self.participants as usize
    }

    /// Returns the number of producer chains.
    pub const fn chains(self) -> usize {
        self.chains as usize
    }

    /// Returns every producer chain identifier in ascending order.
    pub fn chain_ids(self) -> impl Iterator<Item = ChainId> {
        (0..self.chains).map(ChainId::new)
    }

    /// Returns the largest path limits of any chain.
    pub const fn limits(self) -> PathLimits {
        self.limits
    }

    /// Returns the maximum number of blocks in one chain proposal on any chain.
    pub const fn pipeline_depth(self) -> usize {
        self.limits.pipeline_depth as usize
    }

    /// Returns the maximum number of blocks a producer builds, or a validator DA-votes, above a
    /// chain's DA-certified anchor on any chain. It is never zero.
    pub const fn pipeline_window(self) -> usize {
        self.limits.pipeline_window() as usize
    }

    /// Returns the maximum number of blocks in one vote extension on any chain.
    pub const fn extension_bound(self) -> usize {
        self.limits.extension_bound as usize
    }

    /// Returns the largest number of faulty participants tolerated, `f`.
    pub fn max_faults(self) -> usize {
        N5f1::max_faults(self.participants) as usize
    }

    /// Returns the proposal rank a V-QC safe tip must reach, `f + 1`.
    ///
    /// Any `f + 1` votes include at least one correct participant.
    pub fn safe_rank(self) -> usize {
        N5f1::safe_rank(self.participants) as usize
    }

    /// Returns the proposal rank a final tip must reach, `3f + 1`.
    pub fn final_rank(self) -> usize {
        N5f1::final_rank(self.participants) as usize
    }

    /// Returns which [`DaQuorum`] recovers DA certificates.
    pub const fn da_quorum_kind(self) -> DaQuorum {
        self.da_quorum
    }

    /// Returns the exact DA-certificate quorum: `n - 2f`, or `n - f` when certificates bind.
    pub fn da_quorum(self) -> usize {
        match self.da_quorum {
            DaQuorum::Available => N5f1::da_quorum(self.participants) as usize,
            DaQuorum::Binding => self.view_quorum(),
        }
    }

    /// Returns the exact nullification quorum, `2f + 1`.
    pub fn nullification_quorum(self) -> usize {
        self.two_f_plus_one()
    }

    /// Returns the minimum messages accounted by a V-QC and the exact L-QC quorum, `n - f`.
    pub fn view_quorum(self) -> usize {
        N5f1::quorum(self.participants) as usize
    }

    /// Returns the maximum number of messages accounted by a V-QC, `n`.
    pub const fn vqc_max_messages(self) -> usize {
        self.participants()
    }

    /// Returns the minimum votes required for a V-QC designation, `2f + 1`.
    pub fn designation_quorum(self) -> usize {
        self.two_f_plus_one()
    }

    /// Returns `2f + 1`, the smallest set that holds `f + 1` correct participants and overlaps
    /// every `n - f` set in at least one correct participant.
    fn two_f_plus_one(self) -> usize {
        N5f1::nullification_quorum(self.participants) as usize
    }
}

/// An invalid codec bound or path limit.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CodecConfigError {
    /// No participant was configured.
    #[error("participant count must be non-zero")]
    ZeroParticipants,
    /// The participant count cannot be represented by protocol identifiers.
    #[error("participant count {0} exceeds u32::MAX")]
    TooManyParticipants(usize),
    /// No producer chain was configured.
    #[error("producer chain count must be non-zero")]
    ZeroChains,
    /// The producer chain count cannot be represented by protocol identifiers.
    #[error("producer chain count {0} exceeds u32::MAX")]
    TooManyChains(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_extension_bound_is_valid() {
        let limits = PathLimits::new(1, 0);
        assert_eq!(limits.pipeline_depth(), 1);
        assert_eq!(limits.extension_bound(), 0);
        assert!(!limits.certified_only());

        let codec = CodecConfig::new(1, 1, limits).unwrap();
        assert_eq!(codec.pipeline_depth(), 1);
        assert_eq!(codec.pipeline_window(), 1);
        assert_eq!(codec.extension_bound(), 0);
    }

    #[test]
    fn zero_pipeline_depth_places_only_certified_blocks_and_still_advances() {
        let limits = PathLimits::new(0, 0);
        assert!(limits.certified_only());
        assert_eq!(limits.pipeline_depth(), 0);
        assert_eq!(limits.pipeline_window(), 1);
        assert_eq!(PathLimits::new(3, 0).pipeline_window(), 3);
    }

    #[test]
    fn chain_limits_decode_under_the_largest_bound_of_any_chain() {
        let limits = ChainLimits::new(vec![
            PathLimits::new(0, 0),
            PathLimits::new(4, 1),
            PathLimits::new(2, 3),
        ])
        .unwrap();
        assert_eq!(limits.len(), 3);
        assert_eq!(limits.max(), PathLimits::new(4, 3));
        assert_eq!(limits.get(ChainId::new(0)), Some(PathLimits::new(0, 0)));
        assert_eq!(limits.get(ChainId::new(3)), None);
        assert_eq!(ChainLimits::new(Vec::new()), Err(CodecConfigError::ZeroChains));

        let uniform = ChainLimits::uniform(PathLimits::new(2, 1), 2);
        assert_eq!(uniform.max(), PathLimits::new(2, 1));
        assert!(uniform.iter().all(|chain| chain == PathLimits::new(2, 1)));
    }

    #[test]
    fn rejects_zero_participants_and_chains() {
        assert_eq!(
            CodecConfig::new(0, 1, PathLimits::new(1, 0)),
            Err(CodecConfigError::ZeroParticipants)
        );
        assert_eq!(
            CodecConfig::new(1, 0, PathLimits::new(1, 0)),
            Err(CodecConfigError::ZeroChains)
        );
    }

    #[test]
    fn rejects_participant_count_above_u32() {
        let participants = u32::MAX as usize + 1;
        assert_eq!(
            CodecConfig::new(participants, 1, PathLimits::new(1, 0)),
            Err(CodecConfigError::TooManyParticipants(participants))
        );
        assert_eq!(
            CodecConfig::new(1, participants, PathLimits::new(1, 0)),
            Err(CodecConfigError::TooManyChains(participants))
        );
    }

    #[test]
    fn codec_config_derives_n5f1_quorums() {
        for (participants, chains) in [(1, 1), (5, 2), (6, 1), (10, 4), (11, 6), (16, 3)] {
            let codec =
                CodecConfig::new(participants as usize, chains as usize, PathLimits::new(4, 3))
                    .unwrap();

            assert_eq!(codec.participants(), participants as usize);
            assert_eq!(codec.chains(), chains as usize);
            assert_eq!(codec.da_quorum(), N5f1::da_quorum(participants) as usize);
            assert_eq!(
                codec.nullification_quorum(),
                N5f1::nullification_quorum(participants) as usize
            );
            assert_eq!(codec.view_quorum(), N5f1::quorum(participants) as usize);
            assert_eq!(
                codec.designation_quorum(),
                N5f1::nullification_quorum(participants) as usize
            );

            let binding = codec.with_da_quorum(DaQuorum::Binding);
            assert_eq!(binding.da_quorum_kind(), DaQuorum::Binding);
            assert_eq!(binding.da_quorum(), N5f1::quorum(participants) as usize);
        }
    }
}
