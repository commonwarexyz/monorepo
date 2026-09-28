//! Threshold key generation and continuous resharing for epoch-based consensus.
//!
//! `dkg` creates a BLS12-381 threshold key with a one-shot [`bootstrap`] ceremony and
//! rotates its shares across the epochs of an application chain with [`reshare`], using
//! [Feldman-Desmedt](commonware_cryptography::bls12381::dkg::feldman_desmedt) DKG and
//! resharing. It does not own the application's state machine or its secret-key storage.
//!
//! # Overview
//!
//! Each epoch has _dealers_ (the players of the previous output, who hold its shares),
//! _players_ (the targets of the epoch's ceremony), and _next players_ (the players of the
//! following epoch, announced one epoch early). A [`types::EpochInfo`] describes an epoch:
//! its public threshold output, its participant sets, and its transport directory. Genesis
//! carries the [`types::EpochInfo`] for epoch zero, and the final block of each epoch
//! carries the one for the next epoch. The application stores these artifacts in its own
//! blocks and installs each epoch's scheme through a [`Registrar`].
//!
//! # Architecture
//!
//! - [`bootstrap::Engine`] is responsible for the one-shot ceremony that creates the
//!   initial threshold output on its own single-epoch chain.
//! - [`reshare::Actor`] is responsible for each epoch's dealings and dealer-log
//!   inclusion, for deriving the next [`types::EpochInfo`], and for registering each
//!   epoch's scheme with the [`Registrar`].
//! - [`orchestrator::Actor`] is responsible for running one Simplex engine per epoch and
//!   entering the next epoch when marshal delivers the final block.
//! - [`probe::Actor`] is responsible for discovering a state-sync floor and its epoch's
//!   [`types::EpochInfo`], and for serving that material to other joining nodes.
//! - [`state_sync::Plan`] is responsible for persisting that material and giving the
//!   reshare actor and the orchestrator one startup decision.
//! - [`fence::Fence`] is responsible for telling the orchestrator when an epoch's scheme
//!   is registered. Epochs at or below the one passed to [`fence::Fence::new`] count as
//!   registered.
//!
//! # Application Contract
//!
//! Application blocks implement [`ReshareBlock`] and carry at most one
//! [`types::Payload`]. Wrapping the application in [`reshare::Application`] selects the
//! payload for each proposal (handed over through [`reshare::Input`]), rejects a final
//! block whose payload differs from the locally derived [`types::EpochInfo`], and rejects
//! an earlier block that carries any payload except a dealer log from the epoch midpoint
//! onward. See the [reshare module docs](reshare#application-contract) for the full
//! contract.
//!
//! The application also supplies a [`SecretStore`], a [`ParticipantsProvider`], and a
//! [`Registrar`].
//!
//! # State Sync
//!
//! A node joining through application state sync starts its DKG actors from a
//! [`state_sync::StateSync`]: a finalized floor and the [`types::EpochInfo`] of the
//! floor's epoch.
//!
//! - [`probe`] supplies both: the floor is the highest finalization from an `f + 1`
//!   sample of the bootstrap snapshot's dealers, and the info is fetched for the floor's
//!   epoch.
//! - A node resuming an interrupted state sync must pass its persisted floor as
//!   [`probe::Config::floor`]. The probe then ignores replies below that floor's epoch,
//!   so the info describes the epoch of the newer of the two floors, which the node
//!   keeps.
//! - Before starting either actor, initialize one [`state_sync::Plan`] under a stable
//!   node-wide partition prefix and clone it into the orchestrator and reshare
//!   configurations. The material is durable before the actors start, so the node can
//!   restart immediately after state sync. Both actors resolve the same startup decision,
//!   and the plan deletes the material once marshal's recovered epoch is past the synced
//!   epoch. The plan does not depend on [`crate::stateful`].
//!
//! Upon starting in the synced epoch:
//!
//! - The reshare actor registers the epoch's consensus scheme, so a node with a
//!   recovered share can take part in consensus on the blocks before the final block.
//! - If the floor is at or before the epoch midpoint, marshal replays the complete
//!   dealer-log inclusion window and the node participates in the epoch's ceremony.
//! - Otherwise, the node follows the ceremony. It cannot derive the next
//!   [`types::EpochInfo`] locally, so it neither proposes the final block nor completes
//!   its verification, and it resumes resharing from that block's finalized outcome.
//! - If the network has crossed an epoch boundary since the floor, the node catches up
//!   through marshal delivery (see [Catching Up](orchestrator#catching-up)).
//!
//! A player that missed private dealings may need public reveals to recover its share
//! and must treat a revealed share as public. To keep its share private, a future player
//! should state sync while it is still a next player and be online before the epoch's
//! dealing window.
//!
//! # Peer Activation
//!
//! Peer identities are key-only in every ceremony artifact and wire message. Transports
//! that need more than a public key to dial a peer read the [`network::Directory`] that
//! each [`types::EpochInfo`] carries. The directory is agreed as part of the artifact, so
//! activation never consults application state: restart, state sync, and uninterrupted
//! operation activate an epoch's peers from the same finalized artifact.
//!
//! Peers are activated through a [`network::Manager`]:
//!
//! - Upon starting, the [`bootstrap`] engine activates epoch zero with its configured
//!   directory before registering its DKG channel.
//! - Upon its first subscriber, the [`probe`] actor activates the bootstrap snapshot with
//!   its configured directory before soliciting latest finalizations.
//! - Upon its gate reaching an epoch, the [`orchestrator`] activates that epoch from its
//!   [`types::EpochInfo`] before starting the epoch's Simplex engine and channels.
//!
//! The [`network`] adapters use the epoch as the peer set ID, and peer set IDs must increase
//! monotonically on a network (see [`commonware_p2p::Manager::track`]). The [`bootstrap`]
//! engine activates peer set zero on every start, so its manager MUST own the peer-set
//! lifecycle of a network on which no other component activates peers. A clone of another
//! component's manager shares that component's network and does not isolate the two.
//!
//! # Marshal Delivery
//!
//! Once started, the [`reshare::Actor`] and the [`orchestrator::Actor`] require marshal to
//! deliver every finalized block above the latest one they acknowledged in height order. Each
//! acknowledges a redelivered block without repeating its effects. The reshare actor panics
//! on a block above the latest one it acknowledged that skips heights or does not extend it,
//! and the orchestrator panics on a block above the active epoch's final block. The startup floor
//! from the [`state_sync::Plan`] is the only permitted jump, so a live marshal floor must not
//! leave a height below it that they have not acknowledged. A skipped block may carry a
//! dealer log or be an epoch's final block, which the actors need to derive the same
//! [`types::EpochInfo`] and to enter each epoch.
//!
//! # Marshal Retention
//!
//! Except when entering through state sync, a restarting node derives its active epoch
//! from marshal's processed height and loads that epoch's [`types::EpochInfo`] from the
//! finalized boundary block that introduced it: height zero for epoch zero, and the final
//! block of the previous epoch otherwise.
//!
//! ```text
//! boundary(current_epoch) = last_block(current_epoch - 1)
//! ```
//!
//! An operator running stateful pruning MUST keep marshal's finalized block retention at
//! least one epoch wide, so the previous epoch's boundary block survives until the current
//! epoch finishes. Concretely, the marshal retention configured through the stateful
//! [`PruneConfig`](crate::stateful::PruneConfig)
//! (`max_pending_acks + 1 + retained_marshal_blocks` finalized blocks) MUST be at least
//! the DKG epoch length (`blocks_per_epoch`). The two settings are configured separately,
//! and no runtime check couples them. If the boundary block is pruned before the current
//! epoch finishes, a restarting node cannot recover the epoch's public output,
//! participants, and Simplex root from marshal, and the orchestrator stops without
//! starting consensus.
//!
//! Nodes that serve [`probe`] requests also need the boundary finalization and boundary
//! block of every epoch they serve.

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
    /// When the returned future resolves, the [`Provider`] used by the
    /// [`orchestrator::Actor`] must return that scheme for `epoch`: the orchestrator may
    /// enter `epoch` immediately afterward and panics if the provider has no scheme for
    /// it. Implementations must tolerate repeated calls with the same `epoch` and `info`.
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
/// Everything written to this trait is secret, including the dealer RNG seed, which
/// determines a dealer's sharing polynomial and so reveals every share that dealer sends.
/// It MUST NOT be stored with public protocol state, carried on-chain, or sent to peers.
///
/// Writes MUST be durable when their returned future resolves. The reshare actor treats a
/// resolved write as durable and does not re-derive the material after a restart. A store
/// that resolves before the write is stable can let a dealer reseed with fresh randomness
/// and deal different shares for the same epoch (equivocation), or lose a share the node
/// has already relied upon.
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
/// The reshare actor derives each epoch's dealers and players from finalized
/// [`EpochInfo`](types::EpochInfo) artifacts and consults this provider only when it
/// derives the [`EpochInfo`](types::EpochInfo) carried by an epoch's final block (to
/// propose it, verify it, or process its finalization). Implementations may therefore be
/// backed by application state (for example, a staking or address-registry contract).
/// Startup and peer activation read the results embedded in finalized artifacts instead of
/// calling the provider.
///
/// For the same inputs, every honest node MUST return the same value, and repeated calls
/// MUST return the same value. The proposer and every verifier of a final block derive its
/// [`EpochInfo`](types::EpochInfo) independently and compare for equality, so a divergence
/// rejects a valid final block and stalls the epoch boundary.
pub trait ParticipantsProvider: Send + Sync + 'static {
    type PublicKey: PublicKey;

    /// Transport directory type embedded in epoch artifacts.
    type Directory: Directory<Self::PublicKey>;

    /// Returns the intended participant set for `epoch`.
    ///
    /// The reshare actor calls this while deriving the [`EpochInfo`](types::EpochInfo)
    /// carried by the final block of epoch `epoch - 2`, which embeds the returned set as
    /// `next_players`. The result for `epoch` MUST therefore be fixed before any honest node
    /// proposes or verifies that block. [`Set`] is sorted and deduplicated by construction,
    /// so membership alone determines the value.
    ///
    /// The returned set MUST be non-empty, contain at most the actor's configured
    /// `max_participants` entries, and its quorum under the `3f + 1` fault model (`n - f` of
    /// `n` members) MUST NOT exceed the number of dealer logs one epoch of `blocks_per_epoch`
    /// can include. The reshare actor panics on a violation.
    fn participants(&mut self, epoch: Epoch) -> impl Future<Output = Set<Self::PublicKey>> + Send;

    /// Returns the transport directory embedded in the [`EpochInfo`](types::EpochInfo)
    /// for `epoch`.
    ///
    /// `peers` is the union of the epoch's dealers, players, and next players, so it may
    /// hold up to three times the actor's configured `max_participants` entries. The
    /// returned directory MUST contain exactly these peers, and the reshare actor panics
    /// otherwise.
    ///
    /// The reshare actor calls this while deriving the [`EpochInfo`](types::EpochInfo)
    /// carried by the final block of epoch `epoch - 1`. The result, including each peer's
    /// reachability data, MUST therefore be fixed before any honest node proposes or
    /// verifies that block. An update submitted during an epoch MUST take effect only in a
    /// later epoch's directory, never retroactively.
    fn directory(
        &mut self,
        epoch: Epoch,
        peers: Set<Self::PublicKey>,
    ) -> impl Future<Output = Self::Directory> + Send;
}
