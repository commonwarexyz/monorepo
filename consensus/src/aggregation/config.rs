use super::{Recoverer, scheme, types::Certificate};
use crate::{
    Automaton, Reporter,
    types::{Epoch, Height},
};
use commonware_cryptography::{Digest, certificate::Verifier};
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_utils::NonZeroDuration;
use std::num::{NonZeroU64, NonZeroUsize};

/// Configuration for a fixed per-epoch [super::Engine].
pub struct Config<
    S: scheme::Scheme<D>,
    D: Digest,
    A: Automaton<Context = Height, Digest = D>,
    Z: Reporter<Activity = Certificate<S, D>>,
    B: Blocker<PublicKey = <S as Verifier>::PublicKey>,
    T: Strategy,
    R: Recoverer,
> {
    /// Epoch represented by this engine.
    pub epoch: Epoch,
    /// First mandatory global position, inclusive.
    pub first: Height,
    /// Last mandatory global position, inclusive.
    pub last: Height,
    /// Fixed signing scheme for `epoch`.
    pub scheme: S,
    /// Provides the canonical digest for each position.
    ///
    /// Every successful response for a position must return the same digest across clones and
    /// restarts. Closing a response declines the position for this engine instance. The position
    /// can still complete from a learned certificate or after restart.
    pub automaton: A,
    /// Receives certificates after the engine syncs them to its journal.
    pub reporter: Z,
    /// Blocker for invalid network messages.
    pub blocker: B,
    /// Whether acknowledgments are sent as priority messages.
    pub priority_acks: bool,
    /// How often an acknowledgment is rebroadcast until certification.
    pub rebroadcast_timeout: NonZeroDuration,
    /// Number of acknowledgment rebroadcast ticks before resolver recovery starts.
    pub recovery_after_rebroadcasts: NonZeroU64,
    /// Shared resolver recovery coordinator.
    pub recoverer: R,
    /// Maximum number of live positions.
    ///
    /// This value must remain unchanged while retaining the engine's journal.
    pub window: NonZeroU64,
    /// Journal partition.
    pub journal_partition: String,
    /// Journal write-buffer size.
    pub journal_write_buffer: NonZeroUsize,
    /// Journal replay-buffer size.
    pub journal_replay_buffer: NonZeroUsize,
    /// Number of positions assigned to each journal section.
    pub journal_heights_per_section: NonZeroU64,
    /// Journal compression level.
    pub journal_compression: Option<u8>,
    /// Journal page cache.
    pub journal_page_cache: CacheRef,
    /// Parallel verification strategy.
    pub strategy: T,
}
