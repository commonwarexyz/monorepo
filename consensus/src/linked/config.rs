use crate::{
    linked::{Context, Epoch},
    Automaton, Committer, Coordinator, Relay,
};
use commonware_cryptography::{
    bls12381::primitives::{group, poly},
    Scheme,
};
use commonware_utils::Array;
use std::time::Duration;

/// Configuration for the [`Engine`](super::Engine).
pub struct Config<
    C: Scheme,
    D: Array,
    A: Automaton<Context = Context<C::PublicKey>, Digest = D>,
    R: Relay<Digest = D>,
    Z: Committer<Digest = D>,
    S: Coordinator<
        Index = Epoch,
        Seed = group::Signature,
        Share = group::Share,
        Identity = poly::Public,
        PublicKey = C::PublicKey,
    >,
> {
    /// The cryptographic scheme used if the engine is a sequencer.
    pub crypto: C,

    /// Manages the set of sequencers and signers.
    /// Also manages the cryptographic partial share if the engine is a signer.
    pub coordinator: S,

    /// Proposes and verifies digests.
    pub automaton: A,

    /// Broadcasts the raw payload.
    pub relay: R,

    /// Notified when a chunk receives a threshold of acks.
    pub collector: Z,

    /// The application namespace used to sign over different types of messages.
    /// Used to prevent replay attacks on other applications.
    pub namespace: Vec<u8>,

    /// Whether proposals are sent as priority.
    pub priority_proposals: bool,

    /// Whether acks are sent as priority.
    pub priority_acks: bool,

    /// The maximum number of concurrent pending requests to the application.
    pub verify_concurrent: usize,

    /// How often the epoch is refreshed.
    pub refresh_epoch_timeout: Duration,

    /// How often the chunk is rebroadcast to all signers if no threshold is reached.
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
