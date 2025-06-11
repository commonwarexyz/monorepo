use super::types::{Activity, Epoch, Index};
use crate::{Automaton, Monitor, Reporter, ThresholdSupervisor};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Digest};
use commonware_utils::Array;
use std::time::Duration;

/// Configuration for the aggregation [`Engine`](super::Engine).
///
/// This structure contains all the required components and parameters needed to create
/// and run an aggregation engine. It defines the behavior, performance characteristics,
/// and integration points for the consensus system.
///
/// # Type Parameters
///
/// - `P`: Public key type for validator identification
/// - `V`: BLS signature variant (MinPk or MinSig)  
/// - `D`: Digest type for message hashing
/// - `A`: Automaton for proposing and verifying digests
/// - `Z`: Reporter for receiving consensus notifications
/// - `M`: Monitor for tracking epochs
/// - `TSu`: Threshold supervisor managing validators and cryptographic shares
pub struct Config<
    P: Array,
    V: Variant,
    D: Digest,
    A: Automaton<Context = Index, Digest = D>,
    Z: Reporter<Activity = Activity<V, D>>,
    M: Monitor<Index = Epoch>,
    TSu: ThresholdSupervisor<Index = Epoch, PublicKey = P>,
> {
    /// Tracks the current state of consensus (to determine which participants should
    /// be involved in the current broadcast attempt).
    pub monitor: M,

    /// Manages the set of validators and the group identity.
    /// Also manages the cryptographic partial share if the engine is a validator.
    pub validators: TSu,

    /// Proposes and verifies digests.
    pub automaton: A,

    /// Notified when a chunk receives a threshold of acks.
    pub reporter: Z,

    /// The application namespace used to sign over different types of messages.
    /// Used to prevent replay attacks on other applications.
    pub namespace: Vec<u8>,

    /// Whether acks are sent as priority.
    pub priority_acks: bool,

    /// How often an ack is rebroadcast to all validators if no threshold is reached.
    pub rebroadcast_timeout: Duration,

    /// A tuple representing the epochs to keep in memory.
    /// The first element is the number of old epochs to keep.
    /// The second element is the number of future epochs to accept.
    ///
    /// For example, if the current epoch is 10, and the bounds are (1, 2), then
    /// epochs 9, 10, 11, and 12 are kept (and accepted);
    /// all others are pruned or rejected.
    pub epoch_bounds: (u64, u64),

    /// The concurrent number of chunks to process.
    pub window: u64,

    /// A unique name for the journal.
    pub journal_name: String,

    /// The size of the write buffer to use for each blob in the journal.
    pub journal_write_buffer: usize,

    /// Number of bytes to buffer when replaying a journal.
    pub journal_replay_buffer: usize,

    /// The number of entries to keep per journal section.
    pub journal_heights_per_section: u64,

    /// Upon replaying a journal, the number of entries to replay concurrently.
    pub journal_replay_concurrency: usize,

    /// Compression level for the journal.
    pub journal_compression: Option<u8>,
}

impl<
        P: Array,
        V: Variant,
        D: Digest,
        A: Automaton<Context = Index, Digest = D>,
        Z: Reporter<Activity = Activity<V, D>>,
        M: Monitor<Index = Epoch>,
        TSu: ThresholdSupervisor<Index = Epoch, PublicKey = P>,
    > Config<P, V, D, A, Z, M, TSu>
{
    /// Validates that all configuration values are within acceptable ranges.
    ///
    /// This method performs runtime validation of configuration parameters to ensure
    /// they will not cause the engine to behave incorrectly or panic during operation.
    ///
    /// # Panics
    ///
    /// This method will panic if any of the following conditions are met:
    /// - `journal_heights_per_section` is zero
    /// - `journal_replay_concurrency` is zero  
    /// - `window` is zero
    /// - `rebroadcast_timeout` is zero or negative
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = Config { /* ... */ };
    /// config.assert(); // Validates all fields
    /// ```
    pub fn assert(&self) {
        assert!(
            self.journal_heights_per_section != 0,
            "journal_heights_per_section must be non-zero"
        );
        assert!(
            self.journal_replay_concurrency != 0,
            "journal_replay_concurrency must be non-zero"
        );
        assert!(self.window != 0, "window must be non-zero");
        assert!(
            self.rebroadcast_timeout > Duration::from_secs(0),
            "rebroadcast_timeout must be greater than 0"
        );
    }
}
