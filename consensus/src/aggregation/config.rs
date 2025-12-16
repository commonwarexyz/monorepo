use super::types::{Activity, Index};
use crate::{
    types::{Epoch, EpochDelta},
    Automaton, Monitor, Reporter,
};
use commonware_cryptography::{
    certificate::{Provider, Scheme},
    Digest,
};
use commonware_p2p::Blocker;
use commonware_runtime::buffer::PoolRef;
use commonware_utils::NonZeroDuration;
use std::num::{NonZeroU64, NonZeroUsize};

/// Configuration for the [super::Engine].
pub struct Config<
    P: Provider<Scope = Epoch>,
    D: Digest,
    A: Automaton<Context = Index, Digest = D>,
    Z: Reporter<Activity = Activity<P::Scheme, D>>,
    M: Monitor<Index = Epoch>,
    B: Blocker<PublicKey = <P::Scheme as Scheme>::PublicKey>,
> {
    /// Tracks the current state of consensus (to determine which participants should
    /// be involved in the current broadcast attempt).
    pub monitor: M,

    /// Provider for epoch-specific signing schemes.
    pub provider: P,

    /// Proposes and verifies [Digest]s.
    pub automaton: A,

    /// Notified when a chunk receives a quorum of [super::types::Ack]s.
    pub reporter: Z,

    /// Blocker for the network.
    ///
    /// Blocking is handled by [commonware_p2p].
    pub blocker: B,

    /// The application namespace used to sign over different types of messages.
    /// Used to prevent replay attacks on other applications.
    pub namespace: Vec<u8>,

    /// Whether acks are sent as priority.
    pub priority_acks: bool,

    /// How often an ack is rebroadcast to all validators if no quorum is reached.
    pub rebroadcast_timeout: NonZeroDuration,

    /// A tuple representing the epochs to keep in memory.
    /// The first element is the number of old epochs to keep.
    /// The second element is the number of future epochs to accept.
    ///
    /// For example, if the current epoch is 10, and the bounds are (1, 2), then
    /// epochs 9, 10, 11, and 12 are kept (and accepted);
    /// all others are pruned or rejected.
    pub epoch_bounds: (EpochDelta, EpochDelta),

    /// The number of chunks to process concurrently.
    pub window: NonZeroU64,

    /// Number of indices to track below the tip when collecting acks and/or pruning.
    pub activity_timeout: u64,

    /// Partition for the [commonware_storage::journal::segmented::variable::Journal].
    pub journal_partition: String,

    /// The size of the write buffer to use for each blob in the journal.
    pub journal_write_buffer: NonZeroUsize,

    /// Number of bytes to buffer when replaying a journal.
    pub journal_replay_buffer: NonZeroUsize,

    /// The number of entries to keep per journal section.
    pub journal_heights_per_section: NonZeroU64,

    /// Compression level for the journal.
    pub journal_compression: Option<u8>,

    /// Buffer pool for the journal.
    pub journal_buffer_pool: PoolRef,
}
