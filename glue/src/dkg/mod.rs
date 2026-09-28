//! Threshold key generation and continuous resharing for epoch-based consensus.
//!
//! `dkg` creates a BLS12-381 threshold key with a one-shot [`bootstrap`] ceremony and
//! rotates its shares across application epochs with [`reshare`]. Both use
//! [Feldman-Desmedt](commonware_cryptography::bls12381::dkg::feldman_desmedt) DKG and resharing.
//!
//! # Overview
//!
//! Each epoch has _dealers_ who hold shares from the previous output, _players_ receiving
//! new shares, and _next players_ announced one epoch before their ceremony. A
//! [`types::EpochInfo`] describes the epoch's public output, participants, and transport
//! directory. Genesis carries epoch zero's info, and each epoch's final block carries
//! the next epoch's info.
//!
//! # Architecture
//!
//! - [`bootstrap::Engine`] creates the initial threshold output on a single-epoch chain.
//! - [`reshare::Actor`] runs each epoch's ceremony and registers its consensus scheme.
//! - [`orchestrator::Actor`] runs one Simplex engine per epoch and advances at finalized boundaries.
//! - [`probe::Actor`] discovers a state-sync floor and its epoch info, and serves them to peers.
//! - [`state_sync::Plan`] persists the shared startup decision for reshare and the orchestrator.
//! - [`fence::Fence`] gates epoch entry on scheme registration.
//!
//! # Application Contract
//!
//! Application blocks implement [`ReshareBlock`]. The [`reshare::Application`] wrapper selects
//! each proposal's payload and checks payload placement and final-block epoch info during
//! verification. The application includes the selected payload from [`reshare::Input`] in its
//! block. See the [reshare contract](reshare#application-contract) for the full rules.
//!
//! The application supplies a [`SecretStore`] for private ceremony material, a
//! [`ParticipantsProvider`] for future committees and directories, and a [`Registrar`] to
//! install consensus schemes.
//!
//! # State Sync
//!
//! [`probe`] discovers a finalized floor together with its epoch's [`types::EpochInfo`].
//! Pass any persisted floor through [`probe::Config::floor`] so discovery cannot select
//! epoch info older than the floor the node will use.
//! Start from the later of the persisted floor and [`probe::Artifact::floor`], ordered by
//! round, and pair it with [`probe::Artifact::info`].
//!
//! Before starting the actors, initialize one [`state_sync::Plan`] under a stable partition
//! prefix and clone it into the reshare and orchestrator configurations. It persists the
//! material until marshal recovers beyond the synced epoch and is independent of [`crate::stateful`].
//!
//! A floor at or before the epoch midpoint preserves the full dealer-log inclusion window,
//! allowing participation in that ceremony. With a later floor, the node follows the ceremony
//! and resumes resharing from the finalized outcome. A follower with a recovered share can
//! still sign ordinary blocks, but cannot propose or complete verification of the final block.
//! If the network has advanced to a later epoch, marshal delivers the intervening boundaries.
//!
//! Players that miss private dealings may recover through public reveals, which expose their
//! shares. To keep a share private, join while still a next player and be online before the
//! dealing window (see [Offline Players](reshare#offline-players)).
//!
//! # Peer Activation
//!
//! Peer identities are public keys. Each [`types::EpochInfo`] carries a [`network::Directory`]
//! with the transport data needed to reach its participants. [`network::Manager`] activates
//! peers from that artifact during normal operation, restart, and state sync. Bootstrap and
//! probe activate their configured peer snapshots.
//!
//! The P2P adapters use the epoch as the peer-set ID. New sets must advance the ID;
//! repeated IDs keep the existing peers and directory. Bootstrap uses epoch zero,
//! including on restart.
//!
//! # Marshal Delivery
//!
//! Marshal must deliver every finalized block above each actor's acknowledged tip in height
//! order. Redelivery is acknowledged without repeating effects. The reshare actor panics on a
//! block above its tip that does not extend it by one height, and the orchestrator panics on a
//! block beyond its active epoch. Only the startup floor may skip heights. Advancing a live
//! marshal floor must not skip unacknowledged blocks, including dealer logs and epoch boundaries.
//!
//! # Marshal Retention
//!
//! Ordinary restart loads the active epoch's [`types::EpochInfo`] from the boundary block
//! that introduced it: genesis for epoch zero, or the previous epoch's final block.
//!
//! With stateful pruning, retain at least one epoch of marshal blocks so this boundary survives:
//! `max_pending_acks + 1 + retained_marshal_blocks >= blocks_per_epoch`. Configure this through
//! [`PruneConfig`](crate::stateful::PruneConfig). The settings are independent and no runtime
//! check enforces their relationship. Without the boundary, the orchestrator cannot restart.
//!
//! Serving [`probe`] requests also requires the boundary finalization and block for every
//! epoch served.

use crate::dkg::{network::Directory, types::SchemeInfo};
use commonware_consensus::{Block, types::Epoch};
use commonware_cryptography::{
    PublicKey, Signer,
    bls12381::{
        dkg::feldman_desmedt::DealerPrivMsg,
        primitives::{group::Share, variant::Variant},
    },
    transcript::Summary,
};
use commonware_utils::ordered::Set;
use std::future::Future;

pub mod bootstrap;
pub mod fence;
pub mod network;
pub mod orchestrator;
pub mod probe;
pub mod reshare;
pub mod state_sync;
pub mod types;

#[cfg(test)]
mod tests;

/// A [`Block`] that may carry a reshare [`Payload`](types::Payload).
pub trait ReshareBlock: Block {
    /// BLS variant used by the DKG payload.
    type Variant: Variant;

    /// Signer type used by DKG payloads.
    type Signer: Signer;

    /// Transport directory type carried by this block's epoch artifacts.
    type Directory: Directory<<Self::Signer as Signer>::PublicKey>;

    /// Returns the [`Payload`](types::Payload) carried by this block, if any.
    fn payload(&self) -> Option<types::Payload<Self::Variant, Self::Signer, Self::Directory>>;
}

/// Installs epoch-scoped threshold schemes into the consensus [`Provider`].
///
/// [`Provider`]: commonware_cryptography::certificate::Provider
pub trait Registrar: Send + Sync + 'static {
    /// BLS variant used by the DKG payload.
    type Variant: Variant;

    /// Participant public key type.
    type PublicKey: PublicKey;

    /// Registers the threshold scheme described by `info` for `epoch`.
    ///
    /// When this future resolves, the consensus [`Provider`] must return the scheme for
    /// `epoch`. Repeated calls with the same `epoch` and `info` must be safe.
    ///
    /// [`Provider`]: commonware_cryptography::certificate::Provider
    fn register(
        &self,
        epoch: Epoch,
        info: SchemeInfo<Self::Variant, Self::PublicKey>,
    ) -> impl Future<Output = ()> + Send;
}

/// Application-owned storage for the secret material of DKG and reshare ceremonies.
///
/// All stored material must remain private, including dealer RNG seeds, which determine
/// every share a dealer sends. Keep it out of public protocol storage, blocks, and messages.
///
/// Writes must be durable when their futures resolve. Losing an acknowledged write can
/// cause a dealer to equivocate after restart or lose a share already in use.
pub trait SecretStore: Send + Sync + 'static {
    /// Stores this node's [`Share`] for `epoch`.
    fn put_share(&mut self, epoch: Epoch, share: Share) -> impl Future<Output = ()> + Send;

    /// Returns this node's [`Share`] for `epoch`, if stored.
    fn get_share(&mut self, epoch: Epoch) -> impl Future<Output = Option<Share>> + Send;

    /// Stores this node's dealer RNG seed for `epoch`.
    ///
    /// A restarted dealer replays the stored seed, so it deals the same shares it dealt
    /// before the restart.
    fn put_seed(&mut self, epoch: Epoch, seed: Summary) -> impl Future<Output = ()> + Send;

    /// Returns this node's dealer RNG seed for `epoch`, if stored.
    fn get_seed(&mut self, epoch: Epoch) -> impl Future<Output = Option<Summary>> + Send;

    /// Stores a private dealing received from `dealer` during `epoch`.
    fn put_dealing<P: PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: P,
        private: DealerPrivMsg,
    ) -> impl Future<Output = ()> + Send;

    /// Returns the private dealing received from `dealer` during `epoch`, if stored.
    fn get_dealing<P: PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: &P,
    ) -> impl Future<Output = Option<DealerPrivMsg>> + Send;

    /// Prunes secrets older than `min`.
    fn prune(&mut self, min: Epoch) -> impl Future<Output = ()> + Send;
}

/// Source of the participant sets and transport directories of future epochs.
///
/// Results are embedded in [`EpochInfo`](types::EpochInfo) when deriving an epoch's final
/// block. This provider may read application state, such as a staking contract. Startup
/// and peer activation use the finalized artifacts.
///
/// For the same inputs, repeated calls and all honest nodes must return the same value.
/// Divergence prevents agreement on the epoch's final block.
pub trait ParticipantsProvider: Send + Sync + 'static {
    type PublicKey: PublicKey;

    /// Transport directory type embedded in epoch artifacts.
    type Directory: Directory<Self::PublicKey>;

    /// Returns the intended participant set for `epoch`.
    ///
    /// Committed as `next_players` in the final block of epoch `epoch - 2`. The set must be
    /// fixed before any honest node proposes or verifies that block.
    ///
    /// The set must be non-empty and contain at most `max_participants` entries. Its
    /// `3f + 1` quorum (`n - f` of `n` members) must fit in one epoch's dealer-log inclusion
    /// window. The reshare actor panics on a violation.
    fn participants(&mut self, epoch: Epoch) -> impl Future<Output = Set<Self::PublicKey>> + Send;

    /// Returns the transport directory embedded in the [`EpochInfo`](types::EpochInfo)
    /// for `epoch`.
    ///
    /// The directory must contain exactly `peers`: the union of dealers, players, and
    /// next players, up to three times `max_participants`. The reshare actor panics on a
    /// mismatch.
    ///
    /// Committed in the final block of epoch `epoch - 1`. All reachability data must be
    /// fixed before any honest node proposes or verifies that block. Later updates must
    /// take effect in a future epoch's directory.
    fn directory(
        &mut self,
        epoch: Epoch,
        peers: Set<Self::PublicKey>,
    ) -> impl Future<Output = Self::Directory> + Send;
}
