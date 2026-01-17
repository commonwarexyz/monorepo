//! Configuration for the Minimmit consensus engine.

use super::types::{Activity, Context};
use crate::{
    elector::Config as Elector,
    types::{Epoch, ViewDelta},
    Automaton, Relay, Reporter,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::buffer::paged::CacheRef;
use std::{num::NonZeroUsize, time::Duration};
use thiserror::Error;

/// Errors that can occur during configuration validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// No participants configured in the scheme.
    #[error("there must be at least one participant")]
    NoParticipants,

    /// Leader timeout must be greater than zero.
    #[error("leader timeout must be greater than zero")]
    ZeroLeaderTimeout,

    /// Notarization timeout must be greater than zero.
    #[error("notarization timeout must be greater than zero")]
    ZeroNotarizationTimeout,

    /// Leader timeout must be less than or equal to notarization timeout.
    #[error("leader timeout must be less than or equal to notarization timeout")]
    LeaderTimeoutExceedsNotarization,

    /// Nullify retry must be greater than zero.
    #[error("nullify retry broadcast must be greater than zero")]
    ZeroNullifyRetry,

    /// Activity timeout must be greater than zero.
    #[error("activity timeout must be greater than zero")]
    ZeroActivityTimeout,

    /// Skip timeout must be greater than zero.
    #[error("skip timeout must be greater than zero")]
    ZeroSkipTimeout,

    /// Skip timeout must be less than or equal to activity timeout.
    #[error("skip timeout must be less than or equal to activity timeout")]
    SkipTimeoutExceedsActivity,

    /// Fetch timeout must be greater than zero.
    #[error("fetch timeout must be greater than zero")]
    ZeroFetchTimeout,

    /// Fetch concurrent must be greater than zero.
    #[error("it must be possible to fetch from at least one peer at a time")]
    ZeroFetchConcurrent,
}

/// Configuration for the Minimmit consensus engine.
pub struct Config<S, L, B, D, A, R, F, T>
where
    S: Scheme,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: Automaton<Context = Context<D, S::PublicKey>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
    /// Signing scheme for the consensus engine.
    ///
    /// Consensus messages can be signed with a cryptosystem that differs from the static
    /// participant identity keys exposed in `participants`. For example, we can authenticate peers
    /// on the network with [commonware_cryptography::ed25519] keys while signing votes with shares distributed
    /// via [commonware_cryptography::bls12381::dkg] (which change each epoch). The scheme implementation is
    /// responsible for reusing the exact participant ordering carried by `participants` so that signer indices
    /// remain stable across both key spaces; if the order diverges, validators will reject votes as coming from
    /// the wrong validator.
    pub scheme: S,

    /// Leader election configuration.
    ///
    /// Determines how leaders are selected for each view. Built-in options include
    /// [`RoundRobin`](crate::elector::RoundRobin) for deterministic rotation and
    /// [`Random`](crate::elector::Random) for unpredictable selection using BLS
    /// threshold signatures.
    pub elector: L,

    /// Blocker for the network.
    ///
    /// Blocking is handled by [commonware_p2p].
    pub blocker: B,

    /// Automaton for the consensus engine.
    pub automaton: A,

    /// Relay for the consensus engine.
    pub relay: R,

    /// Reporter for the consensus engine.
    ///
    /// All activity is exported for downstream applications that benefit from total observability.
    pub reporter: F,

    /// Strategy for parallel operations.
    pub strategy: T,

    /// Partition for the consensus engine.
    pub partition: String,

    /// Maximum number of messages to buffer on channels inside the consensus
    /// engine before blocking.
    pub mailbox_size: usize,

    /// Epoch for the consensus engine. Each running engine should have a unique epoch.
    pub epoch: Epoch,

    /// Number of bytes to buffer when replaying during startup.
    pub replay_buffer: NonZeroUsize,

    /// The size of the write buffer to use for each blob in the journal.
    pub write_buffer: NonZeroUsize,

    /// Page cache for the journal.
    pub page_cache: CacheRef,

    /// Amount of time to wait for a leader to propose a payload in a view.
    pub leader_timeout: Duration,

    /// Amount of time to wait for view progress after receiving a valid proposal.
    /// If no M-notarization or nullification is received within this time, we
    /// broadcast a nullify vote. Per the spec, this should be 2*delta.
    pub notarization_timeout: Duration,

    /// Amount of time to wait before retrying a nullify broadcast if
    /// stuck in a view.
    pub nullify_retry: Duration,

    /// Number of views behind finalized tip to track and persist activity
    /// derived from validator messages.
    pub activity_timeout: ViewDelta,

    /// Move to nullify immediately if the selected leader has been inactive
    /// for this many recent known views (we ignore views we don't have data for).
    ///
    /// This number should be less than or equal to `activity_timeout` (how
    /// many views we are tracking below the finalized tip).
    pub skip_timeout: ViewDelta,

    /// Timeout to wait for a peer to respond to a request.
    pub fetch_timeout: Duration,

    /// Number of concurrent requests to make at once.
    pub fetch_concurrent: usize,
}

impl<S, L, B, D, A, R, F, T> Config<S, L, B, D, A, R, F, T>
where
    S: Scheme,
    L: Elector<S>,
    B: Blocker<PublicKey = S::PublicKey>,
    D: Digest,
    A: Automaton<Context = Context<D, S::PublicKey>, Digest = D>,
    R: Relay<Digest = D>,
    F: Reporter<Activity = Activity<S, D>>,
    T: Strategy,
{
    /// Validates that all configuration values are valid.
    ///
    /// # Errors
    ///
    /// Returns an error describing the first invalid configuration value found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.scheme.participants().is_empty() {
            return Err(ConfigError::NoParticipants);
        }
        if self.leader_timeout == Duration::default() {
            return Err(ConfigError::ZeroLeaderTimeout);
        }
        if self.notarization_timeout == Duration::default() {
            return Err(ConfigError::ZeroNotarizationTimeout);
        }
        if self.leader_timeout > self.notarization_timeout {
            return Err(ConfigError::LeaderTimeoutExceedsNotarization);
        }
        if self.nullify_retry == Duration::default() {
            return Err(ConfigError::ZeroNullifyRetry);
        }
        if self.activity_timeout.is_zero() {
            return Err(ConfigError::ZeroActivityTimeout);
        }
        if self.skip_timeout.is_zero() {
            return Err(ConfigError::ZeroSkipTimeout);
        }
        if self.skip_timeout > self.activity_timeout {
            return Err(ConfigError::SkipTimeoutExceedsActivity);
        }
        if self.fetch_timeout == Duration::default() {
            return Err(ConfigError::ZeroFetchTimeout);
        }
        if self.fetch_concurrent == 0 {
            return Err(ConfigError::ZeroFetchConcurrent);
        }
        Ok(())
    }
}
