use super::types::{Activity, Context, SequencersProvider};
use crate::{
    types::{Epoch, EpochDelta},
    Automaton, Monitor, Relay, Reporter,
};
use commonware_cryptography::{certificate::Provider, Digest, Signer};
use commonware_runtime::buffer::PoolRef;
use std::{num::NonZeroUsize, time::Duration};

/// Configuration for the [super::Engine].
pub struct Config<
    C: Signer,
    S: SequencersProvider,
    P: Provider<Scope = Epoch>,
    D: Digest,
    A: Automaton<Context = Context<C::PublicKey>, Digest = D>,
    R: Relay<Digest = D>,
    Z: Reporter<Activity = Activity<C::PublicKey, P::Scheme, D>>,
    M: Monitor<Index = Epoch>,
> {
    /// The signer used when this engine acts as a sequencer.
    pub sequencer_signer: Option<C>,

    /// Provider for epoch-specific sequencers set.
    pub sequencers_provider: S,

    /// Provider for epoch-specific validator signing schemes.
    pub validators_provider: P,

    /// Proposes and verifies digests.
    pub automaton: A,

    /// Broadcasts the raw payload.
    pub relay: R,

    /// Notified when a chunk receives a quorum of acks.
    pub reporter: Z,

    /// Tracks the current state of consensus (to determine which participants should
    /// be involved in the current broadcast attempt).
    pub monitor: M,

    /// The application namespace used to sign over different types of messages.
    /// Used to prevent replay attacks on other applications.
    pub namespace: Vec<u8>,

    /// Whether proposals are sent as priority.
    pub priority_proposals: bool,

    /// Whether acks are sent as priority.
    pub priority_acks: bool,

    /// How often a proposal is rebroadcast to all validators if no quorum is reached.
    pub rebroadcast_timeout: Duration,

    /// A tuple representing the epochs to keep in memory.
    /// The first element is the number of old epochs to keep.
    /// The second element is the number of future epochs to accept.
    ///
    /// For example, if the current epoch is 10, and the bounds are (1, 2), then
    /// epochs 9, 10, 11, and 12 are kept (and accepted);
    /// all others are pruned or rejected.
    pub epoch_bounds: (EpochDelta, EpochDelta),

    /// The number of future heights to accept acks for.
    /// This is used to prevent spam of acks for arbitrary heights.
    ///
    /// For example, if the current tip for a sequencer is at height 100,
    /// and the height_bound is 10, then acks for heights 100-110 are accepted.
    pub height_bound: u64,

    /// A prefix for the journal names.
    /// The rest of the name is the hex-encoded public keys of the relevant sequencer.
    pub journal_name_prefix: String,

    /// The number of entries to keep per journal section.
    pub journal_heights_per_section: u64,

    /// The number of bytes to buffer when replaying a journal.
    pub journal_replay_buffer: NonZeroUsize,

    /// The size of the write buffer to use for each blob in the journal.
    pub journal_write_buffer: NonZeroUsize,

    /// Compression level for the journal.
    pub journal_compression: Option<u8>,

    /// Buffer pool for the journal.
    pub journal_buffer_pool: PoolRef,
}
