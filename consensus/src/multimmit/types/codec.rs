//! Codec bounds and quorums shared by every Multimmit protocol object.

use crate::multimmit::types::ChainId;
use commonware_utils::{Faults as _, N5f1};

/// The default number of payload hashes a vote update carries per chain.
pub const DEFAULT_DELTA_MAX: u32 = 8;

/// The default ceiling on one encoded V-QC.
pub const DEFAULT_MAX_VQC_BYTES: u32 = 4 * 1024 * 1024;

/// Per-chain heights a view's readers consider, immutable within an epoch.
///
/// The cap `N` is the window above a base that tips and the pool count. The flow bound `D` limits
/// how far a producer runs, and a validator accepts, above the greatest height `n - 2f` validators
/// endorse. A correct producer stops `N` plus its local slack above its chain's final height, so
/// the rest of `D` is how far a validator's final height and height quorum `h*` may lag the
/// producer's and the validator still accept the producer's blocks as they arrive. A correct
/// voter's endorsed tip stays within `D + 2N` of the view's base, which bounds the headers a
/// reader retains and a V-QC resolves.
/// `delta_max` caps the payload hashes one vote update carries per chain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Window {
    cap: u32,
    flow: u32,
    delta_max: u32,
}

impl Window {
    /// Creates a window with cap `N = cap`, flow bound `D = 6N`, and [`DEFAULT_DELTA_MAX`].
    ///
    /// `D = 6N` is the specification's sizing. With a production slack of one window, a correct
    /// producer runs at most `2N` above its final height, and a validator whose final height or
    /// `h*` lags the producer's by up to four windows still accepts its blocks as they arrive.
    pub const fn new(cap: u32) -> Result<Self, CodecConfigError> {
        let Some(flow) = cap.checked_mul(6) else {
            return Err(CodecConfigError::WindowOverflow);
        };
        Self::with_bounds(cap, flow, DEFAULT_DELTA_MAX)
    }

    /// Creates a window with explicit cap, flow bound, and update payload bound.
    ///
    /// The cap and the flow bound must admit a block, the flow bound must cover the cap, and the
    /// greatest tip lead `D + 2N` must fit a `u32`.
    pub const fn with_bounds(
        cap: u32,
        flow: u32,
        delta_max: u32,
    ) -> Result<Self, CodecConfigError> {
        if cap == 0 {
            return Err(CodecConfigError::ZeroCap);
        }
        if flow < cap {
            return Err(CodecConfigError::FlowBelowCap);
        }
        if delta_max == 0 {
            return Err(CodecConfigError::ZeroDeltaMax);
        }
        let Some(lead) = cap.checked_mul(2) else {
            return Err(CodecConfigError::WindowOverflow);
        };
        if flow.checked_add(lead).is_none() {
            return Err(CodecConfigError::WindowOverflow);
        }
        Ok(Self {
            cap,
            flow,
            delta_max,
        })
    }

    /// Returns the cap `N`.
    pub const fn cap(self) -> u32 {
        self.cap
    }

    /// Returns the flow bound `D`.
    pub const fn flow(self) -> u32 {
        self.flow
    }

    /// Returns the most payload hashes one vote update carries per chain.
    pub const fn delta_max(self) -> u32 {
        self.delta_max
    }

    /// Returns `D + 2N`, the greatest height above a view's base that a reader resolves.
    pub const fn max_tip_lead(self) -> u32 {
        self.flow + 2 * self.cap
    }
}

/// Bounded inputs used while decoding untrusted protocol objects, and the quorums they imply.
///
/// Counts are stored as `u32` so their meaning is independent of the target architecture.
///
/// # Quorums
///
/// A committee of `n` participants tolerates `f` Byzantine faults with `n >= 5f + 1`, where `f`
/// is the largest such count. A V-QC and an L-QC hold exactly `n - f` messages, and `n - f`
/// endorsers place a block in the pool's final tips. `n - 2f` endorsers of one block raise a
/// chain's flow-control height. `n - 3f` messages of one V-QC make a block its tip, or designate a
/// leader block; two such sets overlap in more than `f` messages of `n - f`. A chain is settled
/// once the endorsers that could still lift a V-QC tip above the pool's final tip number at most
/// `n - 4f - 1`. `alpha` endorsers, at least `f + 1` and at most `n - 2f`, let a validator adopt
/// a block it has not verified.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CodecConfig {
    participants: u32,
    chains: u32,
    window: Window,
    adoption: u32,
    max_vqc_bytes: u32,
}

impl CodecConfig {
    /// Creates bounded codec configuration for an epoch with adoption quorum `f + 1` and
    /// [`DEFAULT_MAX_VQC_BYTES`].
    pub fn new(
        participants: usize,
        chains: usize,
        window: Window,
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
            window,
            adoption: N5f1::max_faults(participants) + 1,
            max_vqc_bytes: DEFAULT_MAX_VQC_BYTES,
        })
    }

    /// Replaces the adoption quorum `alpha`, which must lie in `f + 1..=n - 2f`.
    pub const fn with_adoption(mut self, adoption: u32) -> Result<Self, CodecConfigError> {
        let faults = self.faults();
        if adoption <= faults || adoption > self.participants - 2 * faults {
            return Err(CodecConfigError::AdoptionRange(adoption));
        }
        self.adoption = adoption;
        Ok(self)
    }

    /// Replaces the ceiling on one encoded V-QC, which must be non-zero.
    pub const fn with_max_vqc_bytes(mut self, bytes: u32) -> Result<Self, CodecConfigError> {
        if bytes == 0 {
            return Err(CodecConfigError::ZeroVqcBytes);
        }
        self.max_vqc_bytes = bytes;
        Ok(self)
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

    /// Returns the epoch's window.
    pub const fn window(self) -> Window {
        self.window
    }

    /// Returns the ceiling on one encoded V-QC.
    pub const fn max_vqc_bytes(self) -> usize {
        self.max_vqc_bytes as usize
    }

    /// Returns the largest number of faulty participants tolerated, `f`.
    pub const fn max_faults(self) -> usize {
        self.faults() as usize
    }

    /// Returns the exact message count of a V-QC or L-QC and the final-tip quorum, `n - f`.
    pub fn view_quorum(self) -> usize {
        N5f1::quorum(self.participants) as usize
    }

    /// Returns the endorsers that raise a chain's flow-control height, `n - 2f`.
    pub const fn height_quorum(self) -> usize {
        (self.participants - 2 * self.faults()) as usize
    }

    /// Returns the V-QC messages that make a block a tip, `n - 3f`.
    pub const fn tip_quorum(self) -> usize {
        (self.participants - 3 * self.faults()) as usize
    }

    /// Returns the V-QC votes for one leader block that designate it, `n - 3f`.
    pub const fn designation_quorum(self) -> usize {
        self.tip_quorum()
    }

    /// Returns the settledness bound, `n - 4f - 1`.
    pub const fn settled_bound(self) -> usize {
        (self.participants - 4 * self.faults() - 1) as usize
    }

    /// Returns the endorsers that let a validator adopt a block it has not verified, `alpha`.
    pub const fn adoption_quorum(self) -> usize {
        self.adoption as usize
    }

    const fn faults(self) -> u32 {
        // Matches `N5f1::max_faults` and stays usable in const contexts.
        (self.participants - 1) / 5
    }
}

/// An invalid codec bound.
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
    /// The window cap admits no block.
    #[error("window cap must be non-zero")]
    ZeroCap,
    /// The flow bound is below the window cap.
    #[error("flow bound must be at least the window cap")]
    FlowBelowCap,
    /// A vote update could carry no payload hash.
    #[error("update payload bound must be non-zero")]
    ZeroDeltaMax,
    /// The window's greatest tip lead does not fit a `u32`.
    #[error("window bounds overflow")]
    WindowOverflow,
    /// The adoption quorum lies outside `f + 1..=n - 2f`.
    #[error("adoption quorum {0} outside f + 1..=n - 2f")]
    AdoptionRange(u32),
    /// The V-QC ceiling admits no certificate.
    #[error("V-QC byte ceiling must be non-zero")]
    ZeroVqcBytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window() -> Window {
        Window::new(4).unwrap()
    }

    #[test]
    fn window_defaults_and_bounds() {
        let window = window();
        assert_eq!(window.cap(), 4);
        assert_eq!(window.flow(), 24);
        assert_eq!(window.delta_max(), DEFAULT_DELTA_MAX);
        assert_eq!(window.max_tip_lead(), 32);

        assert_eq!(Window::new(0), Err(CodecConfigError::ZeroCap));
        assert_eq!(Window::new(u32::MAX), Err(CodecConfigError::WindowOverflow));
        assert_eq!(
            Window::with_bounds(4, 3, 1),
            Err(CodecConfigError::FlowBelowCap)
        );
        assert_eq!(
            Window::with_bounds(4, 4, 0),
            Err(CodecConfigError::ZeroDeltaMax)
        );
        assert_eq!(
            Window::with_bounds(2, u32::MAX - 3, 1),
            Err(CodecConfigError::WindowOverflow)
        );
    }

    #[test]
    fn rejects_empty_committees_and_chains() {
        assert_eq!(
            CodecConfig::new(0, 1, window()),
            Err(CodecConfigError::ZeroParticipants)
        );
        assert_eq!(
            CodecConfig::new(1, 0, window()),
            Err(CodecConfigError::ZeroChains)
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn rejects_counts_above_u32() {
        let count = u32::MAX as usize + 1;
        assert_eq!(
            CodecConfig::new(count, 1, window()),
            Err(CodecConfigError::TooManyParticipants(count))
        );
        assert_eq!(
            CodecConfig::new(1, count, window()),
            Err(CodecConfigError::TooManyChains(count))
        );
    }

    #[test]
    fn quorums_follow_n5f1() {
        for (n, f) in [
            (1usize, 0usize),
            (5, 0),
            (6, 1),
            (10, 1),
            (11, 2),
            (16, 3),
            (50, 9),
        ] {
            let codec = CodecConfig::new(n, 3, window()).unwrap();
            assert_eq!(codec.max_faults(), f);
            assert_eq!(codec.view_quorum(), n - f);
            assert_eq!(codec.height_quorum(), n - 2 * f);
            assert_eq!(codec.tip_quorum(), n - 3 * f);
            assert_eq!(codec.designation_quorum(), n - 3 * f);
            assert_eq!(codec.settled_bound(), n - 4 * f - 1);
            assert_eq!(codec.adoption_quorum(), f + 1);
            // Two tip quorums cannot fit in one certificate.
            assert!(2 * codec.tip_quorum() > codec.view_quorum());
        }
    }

    #[test]
    fn adoption_quorum_is_bounded() {
        let codec = CodecConfig::new(11, 3, window()).unwrap();
        assert_eq!(
            codec.with_adoption(2),
            Err(CodecConfigError::AdoptionRange(2))
        );
        assert_eq!(codec.with_adoption(3).unwrap().adoption_quorum(), 3);
        assert_eq!(codec.with_adoption(7).unwrap().adoption_quorum(), 7);
        assert_eq!(
            codec.with_adoption(8),
            Err(CodecConfigError::AdoptionRange(8))
        );
    }

    #[test]
    fn vqc_ceiling_is_configurable() {
        let codec = CodecConfig::new(6, 6, window()).unwrap();
        assert_eq!(codec.max_vqc_bytes(), DEFAULT_MAX_VQC_BYTES as usize);
        assert_eq!(codec.with_max_vqc_bytes(1).unwrap().max_vqc_bytes(), 1);
        assert_eq!(
            codec.with_max_vqc_bytes(0),
            Err(CodecConfigError::ZeroVqcBytes)
        );
    }
}
