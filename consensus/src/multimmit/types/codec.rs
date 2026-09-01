//! Codec bounds and path limits shared by every Multimmit protocol object.

use crate::multimmit::types::ChainId;
use commonware_utils::{Faults as _, N5f1};

/// Bounds on the producer-chain paths one proposal or vote carries, immutable within an epoch.
///
/// The pipeline depth `d` bounds each producer chain above its DA-certified anchor: a producer
/// builds, and a validator DA-votes, at most `d` blocks above it, and one proposal appends at most
/// `d` blocks to the chain. The extension bound `e` caps the blocks one vote carries per chain above
/// its proposal position; `e = 0` disables vote extensions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PathLimits {
    pipeline_depth: u32,
    extension_bound: u32,
}

impl PathLimits {
    /// Creates protocol path limits.
    ///
    /// A pipeline must admit at least one block. An extension bound of zero is
    /// valid and disables vote extensions.
    pub const fn new(pipeline_depth: u32, extension_bound: u32) -> Result<Self, CodecConfigError> {
        if pipeline_depth == 0 {
            return Err(CodecConfigError::ZeroPipelineDepth);
        }

        Ok(Self {
            pipeline_depth,
            extension_bound,
        })
    }

    /// Returns the pipeline depth `d`.
    pub const fn pipeline_depth(self) -> u32 {
        self.pipeline_depth
    }

    /// Returns the extension bound `e`.
    pub const fn extension_bound(self) -> u32 {
        self.extension_bound
    }
}

/// Bounded inputs used while decoding untrusted protocol objects, and the quorums they imply.
///
/// Counts are stored as `u32` so their meaning is independent of the target
/// architecture. Getters convert them to allocation and indexing sizes only
/// after construction has validated both counts.
///
/// # Quorums
///
/// A committee of `n` participants tolerates `f` Byzantine faults with `n >= 5f + 1`, where `f`
/// is the largest such count. A data-availability certificate needs `n - 2f` shares, so at least
/// `f + 1` of its signers are correct and hold the block. An L-QC needs exactly `n - f` votes and
/// a V-QC accounts for between `n - f` and `n` messages. A nullification and a V-QC designation
/// each need `2f + 1`: such a set holds at least `f + 1` correct participants and overlaps every
/// `n - f` set in at least `f + 1` members, at least one of them correct. That overlap is why
/// neither can coexist with a conflicting L-QC.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CodecConfig {
    participants: u32,
    chains: u32,
    limits: PathLimits,
}

impl CodecConfig {
    /// Creates bounded codec configuration for an epoch.
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
        })
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

    /// Returns the path limits.
    pub const fn limits(self) -> PathLimits {
        self.limits
    }

    /// Returns the maximum number of blocks in one chain proposal.
    pub const fn pipeline_depth(self) -> usize {
        self.limits.pipeline_depth as usize
    }

    /// Returns the maximum number of blocks in one vote extension.
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

    /// Returns the exact DA-certificate quorum, `n - 2f`.
    pub fn da_quorum(self) -> usize {
        N5f1::da_quorum(self.participants) as usize
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
    /// The proposal pipeline cannot admit a block.
    #[error("pipeline depth must be non-zero")]
    ZeroPipelineDepth,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_extension_bound_is_valid() {
        let limits = PathLimits::new(1, 0).unwrap();
        assert_eq!(limits.pipeline_depth(), 1);
        assert_eq!(limits.extension_bound(), 0);

        let codec = CodecConfig::new(1, 1, limits).unwrap();
        assert_eq!(codec.pipeline_depth(), 1);
        assert_eq!(codec.extension_bound(), 0);
    }

    #[test]
    fn rejects_zero_pipeline_depth_and_participants() {
        assert_eq!(
            PathLimits::new(0, 0),
            Err(CodecConfigError::ZeroPipelineDepth)
        );
        assert_eq!(
            CodecConfig::new(0, 1, PathLimits::new(1, 0).unwrap()),
            Err(CodecConfigError::ZeroParticipants)
        );
        assert_eq!(
            CodecConfig::new(1, 0, PathLimits::new(1, 0).unwrap()),
            Err(CodecConfigError::ZeroChains)
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn rejects_participant_count_above_u32() {
        let participants = u32::MAX as usize + 1;
        assert_eq!(
            CodecConfig::new(participants, 1, PathLimits::new(1, 0).unwrap()),
            Err(CodecConfigError::TooManyParticipants(participants))
        );
        assert_eq!(
            CodecConfig::new(1, participants, PathLimits::new(1, 0).unwrap()),
            Err(CodecConfigError::TooManyChains(participants))
        );
    }

    #[test]
    fn codec_config_derives_n5f1_quorums() {
        for (participants, chains) in [(1, 1), (5, 2), (6, 1), (10, 4), (11, 6), (16, 3)] {
            let codec = CodecConfig::new(
                participants as usize,
                chains as usize,
                PathLimits::new(4, 3).unwrap(),
            )
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
        }
    }
}
