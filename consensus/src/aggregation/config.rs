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
    /// restarts. Closing a response declines the position for this engine instance. The engine
    /// then starts recovery for the position without waiting for acknowledgments.
    pub automaton: A,
    /// Receives certificates after the engine syncs them to its journal.
    ///
    /// Certificates can arrive out of order. After a restart, every journaled certificate is
    /// reported again. Feedback is ignored.
    pub reporter: Z,
    /// Blocker for invalid network messages.
    pub blocker: B,
    /// Whether acknowledgments are sent as priority messages.
    pub priority_acks: bool,
    /// How often an acknowledgment is rebroadcast until certification.
    pub rebroadcast_timeout: NonZeroDuration,
    /// Number of rebroadcast ticks after a position enters the window before resolver recovery
    /// starts.
    ///
    /// Recovery starts immediately for the initial window after a restart and for a position
    /// whose digest the application declined.
    pub recovery_after_rebroadcasts: NonZeroU64,
    /// Shared resolver recovery coordinator.
    pub recoverer: R,
    /// Maximum number of live positions.
    ///
    /// Also bounds the certificate mailbox. Changing `window` across restarts is safe.
    pub window: NonZeroU64,
    /// Journal partition.
    ///
    /// Each engine scope needs its own partition.
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
