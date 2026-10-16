//! Configuration for one Multimmit epoch.
//!
//! A [`Protocol`] holds what every participant must agree on: the epoch's [`Parameters`]
//! (committee shape, window, adoption quorum, producer assignment, leader schedule, and namespace)
//! and its genesis. A signing scheme holds the same parameters. [`Tuning`] holds what each operator
//! chooses locally, such as timeouts and the view retention window. The engine's root
//! [`Config`](crate::multimmit::Config) supplies the scheme, the genesis, and the tuning; the
//! engine pairs the scheme's parameters with the genesis, derives this node's role from the
//! scheme's key material, and derives every internal resource bound from the tuning, so the pieces
//! cannot disagree.

#[cfg(not(target_arch = "wasm32"))]
pub(super) mod profile;
mod protocol;

use crate::{
    multimmit::types::CodecConfigError,
    types::{Epoch, Participant},
};
#[cfg(not(target_arch = "wasm32"))]
pub use profile::Tuning;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use profile::{Profile, ResourceLimits, Role, max_outbox_effects};
pub use protocol::{LeaderSchedule, Parameters, Protocol};
use std::time::Duration;

/// An invalid protocol, tuning, or engine configuration.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A producer is not a validator in this epoch.
    #[error("producer {0} is outside the participant set")]
    ProducerOutOfRange(Participant),
    /// A validator was assigned more than one producer chain.
    #[error("participant {0} owns more than one producer chain")]
    DuplicateProducer(Participant),
    /// Genesis names another epoch than the parameters it is paired with.
    #[error("genesis epoch {actual} does not match configuration epoch {expected}")]
    GenesisEpoch {
        /// The parameters' epoch.
        expected: Epoch,
        /// The epoch genesis names.
        actual: Epoch,
    },
    /// The leader schedule does not match the epoch's participant set.
    #[error("invalid leader schedule")]
    LeaderSchedule,
    /// Genesis does not define exactly one tip per producer chain.
    #[error("genesis has {actual} tips but configuration requires {expected}")]
    GenesisTips {
        /// The number of producer chains.
        expected: usize,
        /// The number of tips genesis names.
        actual: usize,
    },
    /// The codec bounds are invalid.
    #[error(transparent)]
    Codec(#[from] CodecConfigError),
    /// The epoch's encoded maxima cannot be represented on this target.
    #[error("encoded protocol maximum exceeds usize")]
    EncodedSizeOverflow,
    /// The artifact byte limit cannot admit every bounded protocol artifact.
    #[error("artifact byte limit {actual} is below the required minimum {required}")]
    ArtifactByteLimitTooSmall {
        /// The largest artifact the epoch's codec bounds admit.
        required: usize,
        /// The configured limit.
        actual: usize,
    },
    /// The byte budgets derived from the artifact byte limit do not fit this target.
    #[error("artifact byte limit {actual} exceeds the largest supported limit {max}")]
    ArtifactByteLimitTooLarge {
        /// The largest limit whose derived byte budgets fit this target.
        max: usize,
        /// The configured limit.
        actual: usize,
    },
    /// Vote updates would be sent continuously.
    #[error("vote interval must be greater than zero")]
    ZeroVoteInterval,
    /// The delay estimate's bounds are empty or out of order.
    #[error(
        "delay bounds must satisfy 0 < min ({min:?}) <= initial ({initial:?}) <= timer ceiling \
         ({ceiling:?})"
    )]
    DelayBounds {
        /// The least delay estimate.
        min: Duration,
        /// The estimate before any sample.
        initial: Duration,
        /// The ceiling on every timer and estimate.
        ceiling: Duration,
    },
    /// The just-completed view must remain available for votes delivered within the synchrony
    /// bound.
    #[error("view retention must be greater than zero")]
    ZeroViewRetention,
    /// Vote updates of the previous view would not be read.
    #[error("vote window must be greater than zero")]
    ZeroVoteWindow,
    /// An anchor would not lie above every vote tag this node may have signed.
    #[error("anchor lag {0} is below two")]
    AnchorLagTooSmall(u64),
    /// The faulty senders' pending vote updates and the answers they await could hold every
    /// dependency waiter.
    #[error(
        "{pending_updates_per_sender} pending updates per sender let faulty senders hold all \
         {max_dependency_waiters} dependency waiters"
    )]
    PendingUpdatesExceedWaiters {
        /// The configured pending updates per sender.
        pending_updates_per_sender: usize,
        /// The dependency waiters the profile keeps.
        max_dependency_waiters: usize,
    },
    /// The validator identity is not in the configured ordered committee.
    #[error("validator participant {0} is outside the configured committee")]
    ValidatorOutOfRange(Participant),
    /// The artifact cache cannot retain live work and the retention window.
    #[error("artifact cache capacity {actual} is below the required minimum {required}")]
    ArtifactCacheTooSmall {
        /// The smallest capacity that holds live work and the retention window.
        required: usize,
        /// The configured capacity.
        actual: usize,
    },
    /// The retention window cannot be represented by the artifact cache.
    #[error("view retention {view_retention} exceeds artifact cache capacity {actual}")]
    RetentionExceedsArtifactCache {
        /// The configured view retention.
        view_retention: u64,
        /// The configured artifact cache capacity.
        actual: usize,
    },
    /// The forwarding history cannot retain both certificate classes for every retained view.
    #[error("forwarding history capacity {actual} is below the required minimum {required}")]
    ForwardingHistoryTooSmall {
        /// Two certificates per retained view.
        required: usize,
        /// The configured capacity.
        actual: usize,
    },
    /// A capacity the profile requires cannot be represented on this target.
    #[error("required profile capacity overflows usize")]
    Overflow,
    /// The storage partition prefix is empty or contains a character other than an ASCII
    /// alphanumeric or underscore.
    #[error("partition prefix must contain only ASCII alphanumeric characters or underscores")]
    InvalidPartitionPrefix,
    /// The production interval `theta` is zero.
    #[error("production interval must be non-zero")]
    ZeroProductionInterval,
}
