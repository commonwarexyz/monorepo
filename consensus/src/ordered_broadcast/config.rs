use super::{Context, Epoch, Epocher};
use crate::{Automaton, Committer, Relay, Supervisor, ThresholdSupervisor};
use commonware_cryptography::{Digest, Scheme};
use std::time::Duration;

/// Configuration for the [`Engine`](super::Engine).
pub struct Config<
    C: Scheme,
    D: Digest,
    A: Automaton<Context = Context<C::PublicKey>, Digest = D>,
    R: Relay<Digest = D>,
    Z: Committer<Digest = D>,
    Ep: Epocher,
    Su: Supervisor<Index = Epoch, PublicKey = C::PublicKey>,
    TSu: ThresholdSupervisor<Index = Epoch, PublicKey = C::PublicKey>,
> {
    /// The cryptographic scheme used if the engine is a sequencer.
    pub crypto: C,

    /// The epocher.
    pub epocher: Ep,

    /// Manages the set of validators and the group identity.
    /// Also manages the cryptographic partial share if the engine is a validator.
    pub validators: TSu,

    /// Manages the set of sequencers.
    pub sequencers: Su,

    /// Proposes and verifies digests.
    pub automaton: A,

    /// Broadcasts the raw payload.
    pub relay: R,

    /// Notified when a chunk receives a threshold of acks.
    pub committer: Z,

    /// The application namespace used to sign over different types of messages.
    /// Used to prevent replay attacks on other applications.
    pub namespace: Vec<u8>,

    /// Whether proposals are sent as priority.
    pub priority_proposals: bool,

    /// Whether acks are sent as priority.
    pub priority_acks: bool,

    /// How often the epoch is refreshed.
    pub refresh_epoch_timeout: Duration,

    /// How often a proposal is rebroadcast to all validators if no threshold is reached.
    pub rebroadcast_timeout: Duration,

    /// A tuple representing the epochs to keep in memory.
    /// The first element is the number of old epochs to keep.
    /// The second element is the number of future epochs to accept.
    ///
    /// For example, if the current epoch is 10, and the bounds are (1, 2), then
    /// epochs 9, 10, 11, and 12 are kept (and accepted);
    /// all others are pruned or rejected.
    pub epoch_bounds: (u64, u64),

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

    /// Upon replaying a journal, the number of entries to replay concurrently.
    pub journal_replay_concurrency: usize,
}
