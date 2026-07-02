//! Bootstrap and continuously reshare threshold secrets.
//!
//! This module wires threshold-key management into consensus without owning the
//! application's state machine or private-key policy. It provides two public
//! entry points:
//!
//! - [`bootstrap`] runs a contained, one-shot DKG chain that trustlessly creates
//!   an initial threshold secret.
//! - [`reshare`] runs alongside an application chain and continuously rotates
//!   threshold shares across epochs.
//!
//! Both paths produce or consume [`types::EpochInfo`], the public artifact that
//! describes the threshold output for an epoch. The application stores that
//! artifact in its own blocks and installs epoch-scoped schemes through a
//! [`Registrar`].
//!
//! # Application Contract
//!
//! Application blocks implement [`ReshareBlock`] and carry at most one
//! [`types::Payload`]. During a reshare epoch, the application is responsible for
//! connecting block production and verification to the reshare mailbox:
//!
//! - Include dealer logs in proposed non-final blocks by calling
//!   [`reshare::Mailbox::next_log`].
//! - In the final block of each epoch, proposers must include the ceremony
//!   outcome returned by [`reshare::Mailbox::epoch_info`].
//! - Verifiers must require the final block payload to be an
//!   [`types::Payload::EpochInfo`] and must check that it matches the
//!   independently constructed [`types::EpochInfo`].
//!
//! The protocol also requires the application to provide a [`SecretStore`].
//! Secret storage is intentionally user-owned: deployments differ on encryption,
//! access control, hardware isolation, backups, and pruning. Anything written to
//! this trait is private ceremony material and must be protected by the
//! application's security policy.
//!
//! # State Sync
//!
//! Reshare supports nodes that join through state sync. A syncing node can only
//! participate in a future ceremony if it syncs while it is a `next_player`.
//! Once the node becomes a `player`, it must already be online for the early
//! ceremony traffic. Syncing during that epoch is too late to receive a private
//! share, and the protocol will reveal that share instead.
//!
//! This timing makes it safe for [`ParticipantsProvider`] to be backed by chain
//! state (e.g., a staking contract). The chain can announce future players first,
//! giving those nodes an epoch to state sync and enter the next ceremony normally.
//!
//! # Marshal Retention
//!
//! DKG startup relies on marshal's local finalized block archive unless the node
//! is entering through one-time state sync. On an ordinary restart, the active
//! epoch is derived from marshal's processed height, and the public
//! [`types::EpochInfo`] for that epoch is loaded from the finalized boundary
//! block that introduced it.
//!
//! For epoch zero, that boundary is height zero. For later epochs, the boundary
//! is the final block of the previous epoch:
//!
//! ```text
//! boundary(current_epoch) = last_block(current_epoch - 1)
//! ```
//!
//! An operator running stateful pruning MUST keep marshal's finalized block
//! retention window at least one full epoch wide, so the previous epoch's
//! boundary block survives until the current epoch finishes. Concretely, the
//! marshal retention floor configured through the stateful
//! [`PruneConfig`](crate::stateful::PruneConfig)
//! (`max_pending_acks + 1 + retained_marshal_blocks` finalized blocks) MUST be
//! greater than or equal to the DKG epoch length (`blocks_per_epoch`). DKG does
//! not need blocks before that previous boundary for ordinary restart, but it
//! does need the boundary block itself to recover the epoch's public threshold
//! output, participant set, and Simplex floor commitment.
//!
//! This coupling is the operator's responsibility. The two knobs are configured
//! independently: `blocks_per_epoch` is a DKG configuration, while the marshal
//! retention floor is set on the stateful
//! [`PruneConfig`](crate::stateful::PruneConfig). The library cannot enforce the
//! relationship, and no runtime check couples them
//! ([`PruneConfig::assert_valid`](crate::stateful::PruneConfig::assert_valid)
//! only compares marshal and QMDB retention). Pruning the boundary before the
//! current epoch finishes leaves a restarting validator without the local public
//! material required for normal recovery, and the orchestrator panics on startup
//! with a `missing finalized boundary block` error.
//!
//! Nodes that serve `dkg::anchor` responses for other peers also need the
//! corresponding boundary finalization and boundary block for every epoch they
//! intend to serve.
//!
//! See [`anchor`], [`fence`], [`orchestrator`], [`reshare`], and [`types`] for
//! the detailed actors, synchronization points, and wire artifacts.

use crate::dkg::types::SchemeInfo;
use commonware_consensus::{types::Epoch, Block};
use commonware_cryptography::{
    bls12381::{
        dkg::feldman_desmedt::DealerPrivMsg,
        primitives::{group::Share, variant::Variant},
    },
    transcript::Summary,
    PublicKey, Signer,
};
use commonware_utils::ordered::Set;
use std::future::Future;

pub mod anchor;
pub mod bootstrap;
pub mod fence;
pub mod orchestrator;
pub mod reshare;
pub mod types;

#[cfg(test)]
mod tests;

/// A [`Block`] that may carry a reshare [`Payload`](types::Payload).
pub trait ReshareBlock: Block {
    /// BLS variant used by the DKG payload.
    type Variant: Variant;

    /// Signer type used by DKG payloads.
    type Signer: Signer;

    /// Retrieves the [`Payload`](types::Payload) carried by this block, if any.
    fn payload(&self) -> Option<types::Payload<Self::Variant, Self::Signer>>;
}

/// A registrar of signing schemes that supplies a [`Provider`] an [`Epoch`]-scoped
/// [`ThresholdScheme`] in preparation for a transition to the given [`Epoch`].
///
/// [`Provider`]: commonware_cryptography::certificate::Provider
/// [`ThresholdScheme`]: commonware_consensus::simplex::scheme::bls12381_threshold
pub trait Registrar: Send + Sync + 'static {
    /// BLS variant used by the DKG payload.
    type Variant: Variant;

    /// Participant public key type.
    type PublicKey: PublicKey;

    /// Hook for handling an epoch transition.
    fn register(
        &self,
        epoch: Epoch,
        info: SchemeInfo<Self::Variant, Self::PublicKey>,
    ) -> impl Future<Output = ()> + Send;
}

/// Interface for a secret store that persists and retrieves the private DKG/reshare
/// material for different [`Epoch`]s.
///
/// All material entrusted to this trait is secret and must be stored as such: it must
/// never be written to plaintext protocol storage, carried on-chain, or sent to peers.
/// This includes the dealer RNG seed, which seeds a dealer's sharing polynomial and so
/// reveals every share that dealer sends.
pub trait SecretStore: Send + Sync + 'static {
    /// Stores a [`Share`] for a given [`Epoch`].
    fn put_share(&mut self, epoch: Epoch, share: Share) -> impl Future<Output = ()> + Send;

    /// Retrieves a [`Share`] for a given [`Epoch`], if it exists.
    fn get_share(&mut self, epoch: Epoch) -> impl Future<Output = Option<Share>> + Send;

    /// Stores the dealer RNG seed for a given [`Epoch`].
    ///
    /// The seed deterministically replays this node's dealer randomness across a
    /// restart. It is secret: knowing it reveals every share the dealer distributes.
    fn put_seed(&mut self, epoch: Epoch, seed: Summary) -> impl Future<Output = ()> + Send;

    /// Retrieves the dealer RNG seed for a given [`Epoch`], if it exists.
    fn get_seed(&mut self, epoch: Epoch) -> impl Future<Output = Option<Summary>> + Send;

    /// Stores a private dealing received from `dealer` during `epoch`.
    fn put_dealing<P: PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: P,
        private: DealerPrivMsg,
    ) -> impl Future<Output = ()> + Send;

    /// Retrieves a private dealing received from `dealer` during `epoch`.
    fn get_dealing<P: PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: &P,
    ) -> impl Future<Output = Option<DealerPrivMsg>> + Send;

    /// Prunes secrets older than `min`.
    fn prune(&mut self, min: Epoch) -> impl Future<Output = ()> + Send;
}

/// Participant policy provider.
///
/// This is the only application hook on canonical epoch structure: it supplies
/// the intended participant set for a future `epoch`. The actor derives dealers,
/// current players, and ordinary epoch progression from finalized public truth,
/// and consults this only for the players of an epoch it cannot yet read from a
/// finalized boundary block.
///
/// [`participants`](Self::participants) must be deterministic at a given epoch
/// across all honest nodes (see its documentation for the exact contract).
pub trait ParticipantsProvider: Send + Sync + 'static {
    type PublicKey: PublicKey;

    /// Returns the intended participant set for `epoch`.
    ///
    /// This MUST be deterministic and stable: for a given `epoch`, every honest
    /// node MUST return an identical [`Set`], with the same membership AND the
    /// same ordering, and repeated calls MUST return the same `Set`.
    ///
    /// In continuous reshare, this hook is consulted while building or
    /// verifying an epoch's final block. That final block carries the
    /// [`types::EpochInfo`] for the next epoch, and this set is embedded
    /// verbatim as that epoch info's `next_players`.
    ///
    /// Therefore the result for `epoch` must be locked in before honest nodes
    /// propose or verify the final block that announces `epoch` as
    /// `next_players`. The proposer and every verifier independently rebuild
    /// and compare the value for equality. Because [`Set`] is order sensitive
    /// (both its equality and its encoding depend on element order), any
    /// divergence in membership or ordering between proposer and verifier
    /// rejects a valid final block and stalls the epoch boundary. Canonicalize
    /// (e.g. sort) the returned `Set` so it is identical regardless of how the
    /// underlying membership is stored or queried.
    fn participants(&mut self, epoch: Epoch) -> impl Future<Output = Set<Self::PublicKey>> + Send;
}
