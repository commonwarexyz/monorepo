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
//! - [`state_sync::Plan`] keeps state-sync material and epoch checkpoints for restart and serving.
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
//! Before starting the actors, initialize one [`state_sync::Plan`] under a stable partition prefix.
//! Clone it into the reshare and orchestrator configurations and pass a clone to
//! [`probe::Mailbox::attach`]. It persists the material until marshal recovers beyond the synced
//! epoch and is independent of [`crate::stateful`].
//!
//! A floor at or before the epoch midpoint preserves the full dealer-log inclusion window,
//! allowing participation in that ceremony. With a later floor, the node follows the ceremony
//! and resumes resharing from the finalized outcome. A follower with a recovered share can
//! still sign ordinary blocks, but cannot propose or complete verification of the final block.
//! If the network has advanced to a later epoch, marshal delivers the intervening boundaries.
//!
//! A validator that holds a share for the current epoch takes part in its ceremony and must stay
//! online for the whole epoch. If it follows the ceremony, it counts as a faulty validator at the
//! final block, so that block finalizes only if `2f + 1` other validators vote to finalize it.
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
//! # Reconfiguration
//!
//! The [`ParticipantsProvider`] may change the committee arbitrarily between epochs, and
//! consensus allows consecutive committees to be disjoint. Under the `3f + 1` model, up to `f`
//! members of each committee may be faulty (Byzantine or offline), and departed members may go
//! offline.
//!
//! As [Catching Up](orchestrator#catching-up) describes, a lagging node catches up only from
//! peers it tracks. Each epoch's tracked peers include the next two committees, so a node one
//! or two epochs behind still tracks the current committee, however much it changed, and any
//! of its honest members can serve the final block and every block the node is missing below
//! it. A node further behind needs a tracked peer that is still in the current committee or
//! still follows the chain and relays its certificates. Without one, it must be restarted
//! through [state sync](#state-sync).
//!
//! A peer serves the lagging node only while the two stay connected and the peer still holds
//! the missing blocks. Current-epoch nodes keep dialing lagging members of the current
//! committee. They disconnect other lagging nodes once those nodes fall out of their
//! `tracked_peer_sets` most recent peer sets, except for configured bootstrap peers in
//! authenticated discovery. [Marshal retention](#marshal-retention) is a window behind each
//! peer's processed height, so a lagging node must finish catching up before its peers prune
//! the blocks it is missing.
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
//! Each epoch starts from a boundary block that carries its [`types::EpochInfo`]. Epoch zero starts
//! from genesis, and every later epoch from the previous epoch's final block. Both DKG actors need
//! the epoch's info, and the orchestrator starts the epoch's Simplex engine from the boundary
//! block's commitment.
//!
//! Restarted actors recover the epoch `e` containing the height after marshal's processed height
//! `P`, or epoch zero if marshal has processed nothing. While the plan keeps state-sync material,
//! they start in its floor's epoch `f`, and the orchestrator starts Simplex from the floor
//! finalization the material holds.
//!
//! The DKG actors store what a later restart or a joining peer needs while they process each block,
//! so marshal may prune finalized blocks below `P` without waiting on them.
//!
//! The [`state_sync::Plan`] keeps a _checkpoint_ for each epoch the orchestrator enters from its
//! boundary block. The checkpoint holds that block and marshal's finalization of it, when marshal
//! has one. At each boundary, the orchestrator records the next epoch's checkpoint before it
//! acknowledges the final block, so `P` cannot pass a boundary whose epoch is not durable. With `F`
//! the final block of epoch `e`:
//!
//! ```text
//!   ...  | F - 1 |   F   | F + 1 |  ...
//!   ----- epoch e ------>|<---- epoch e + 1 ----
//!                    ^
//!                    '-- final block of epoch e, carries EpochInfo(e + 1)
//!
//!  orchestrator, on delivery of F:
//!
//!         +--------------------+     +-------------+     +---------------+
//!   ----->| record and sync    |---->| enter e + 1 |---->| acknowledge F |----> P = F once every
//!         | checkpoint e + 1   |     | stop e      |     |               |      reporter acked
//!         +--------------------+     +-------------+     +---------------+
//!      ^                          ^                                         ^
//!   crash 1                    crash 2                                   crash 3
//!
//!   crash | checkpoints | P                        | restart loads
//!   ------+-------------+--------------------------+------------------------------------
//!     1   | e           | below F                  | checkpoint e, then F is redelivered
//!     2   | e, e + 1    | below F                  | checkpoint e, then F is redelivered
//!     3   | e, e + 1    | below F (ack unrecorded) | checkpoint e, then F is redelivered
//!         |             | F                        | checkpoint e + 1
//! ```
//!
//! Marshal delivers up to its pending acknowledgement window ahead of `P`, so while another
//! reporter lags the orchestrator can cross several boundaries before `P` does. Recording a
//! checkpoint therefore keeps every checkpoint from the epoch recovered from `P` onward and drops
//! older ones, so every epoch a later restart can recover keeps its checkpoint.
//!
//! Restart takes the active epoch from the first of these sources that applies:
//!
//! 1. the plan's state-sync material, while `e` is at or before `f`
//! 2. the plan's checkpoint for `e`
//! 3. `e`'s boundary block in marshal
//!
//! Startup deletes state-sync material once `e` passes `f`, and the orchestrator records a boundary
//! block read in step 3 as checkpoint `e`. With no source, the orchestrator exits and the reshare
//! actor follows `e`. With `L` blocks per epoch:
//!
//! ```text
//!   plan partitions, outside marshal
//!   +------------------------+-----------------------------+
//!   | 1. state-sync material | 2. checkpoint e             |
//!   |    EpochInfo(f)        |    boundary block           |------------.
//!   |    floor finalization  |    its finalization, when   |            |
//!   |    floor height h      |    marshal had one          |            v
//!   +------------------------+-----------------------------+     probe serves joiners
//!                                       ^                                 ^
//!                                       | copied when entering e          | latest finalization
//!                                       |                                 |
//!   marshal's archive                   |                                 |
//!   xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| e*L - 1 | e*L | ... |   P   | ... | tip |
//!   pruned, advancing ------------>|    ^    |<---------- epoch e -----------
//!                                       |
//!                                       3. boundary block (genesis when e is 0)
//! ```
//!
//! A new node starts epoch zero from genesis through step 3, and a restart reaches step 3 for any
//! epoch without kept material or a checkpoint. Initialize the plan with [`state_sync::Plan::init`]
//! on every node, with or without state-sync material. A [`state_sync::Plan::disabled`] plan
//! records no checkpoints, so each restart reads the boundary block from marshal and the probe
//! serves no epoch.
//!
//! Material passed to [`state_sync::Plan::init`] replaces any stored material and its recorded
//! floor height but leaves checkpoints in place. If startup then deletes the material as stale,
//! restart continues from step 2.
//!
//! The reshare actor also needs the height `h` of the floor block to decide whether it participates
//! in `f`'s ceremony or follows it, as [State Sync](reshare#state-sync) describes. A startup that
//! lacks `h` or finds the floor block unprocessed waits for the block from marshal and records its
//! height with the material if the plan has none. Once the plan has `h` and marshal has processed
//! the floor block, a restart takes `h` from the plan and resumes from marshal's processed position
//! without reading the block, so marshal may prune it:
//!
//! ```text
//!         never delivered     floor block h             delivered from h onward
//!   --------------------------|-------|-------|-----|-------|-------|------>
//!                             |   h   | h + 1 | ... | P - 1 |   P   |
//!                             ^
//!   first startup             | marshal fetches h, the reshare actor waits for it and
//!                             | records h with the material
//!   restart, P >= h           |xxxxxxx| h may be pruned, so resume at P with h from the plan
//!   restart, P = h - 1        |   h   | the floor was just installed, so h is marshal's
//!                             |       | anchor and is read locally
//! ```
//!
//! A restart from a checkpoint never reads the boundary block. A restart with `h` in the plan reads
//! the floor block only before marshal has processed it, and until then marshal is either fetching
//! that block for its floor or stores it as the anchor of its processed position.
//!
//! Material passed to [`state_sync::Plan::init`] has no `h`, so the next startup reads its floor
//! block even if marshal has already processed it. Marshal skips a configured floor that its
//! persisted round floor already covers and does not fetch the floor block. A node must therefore
//! only be given material whose floor block its marshal still stores or will fetch, or its reshare
//! actor may wait forever for a block that marshal has already pruned.
//!
//! [`Stateful`](crate::stateful::Stateful) does not prune marshal before [`crate::stateful`] state
//! sync completes, so an application that passes material only until then meets this rule. Under
//! this rule, marshal retention does not limit restart.
//!
//! The [`probe`] answers latest-finalization requests from marshal. It answers a request for epoch
//! `e`'s boundary finalization or block from the node's checkpoint for `e`, and only when that
//! checkpoint holds the finalization. A joining node can therefore discover an epoch from any peer
//! that entered it through its boundary with the finalization, however far that peer's marshal has
//! pruned.
//!
//! A peer that entered an epoch by state sync has no checkpoint for it, and a peer whose marshal
//! repaired the boundary block by walking back from a later block may hold no finalization for it.
//! Neither serves the epoch. Since recording a checkpoint drops older ones, a peer serves only its
//! recent epochs. Discovery asks every peer for the boundary, so one peer that can serve it
//! suffices.
//!
//! Under stateful pruning, [`PruneConfig::retained_marshal_blocks`] sets marshal's retention.
//! Retention bounds how far behind a lagging peer can fall and still catch up, as
//! [Reconfiguration](#reconfiguration) describes. With an initialized plan, restart and probe
//! serving do not depend on it.
//!
//! The reshare actor treats every block marshal has processed as applied, and its journal stores
//! dealer logs but not the last block it applied, so a node's marshal, application, and reshare
//! partitions must be restored from the same point. If chain storage is restored ahead of the
//! reshare journal, the actor derives the next epoch from an incomplete set of dealer logs and
//! rejects the valid final block. Restore the plan's partitions from that point too, since a plan
//! from another point may lack the active epoch's checkpoint.
//!
//! [`PruneConfig::retained_marshal_blocks`]: crate::stateful::PruneConfig::retained_marshal_blocks
//!
//! # Message Sizes
//!
//! The reshare [`Actor`](reshare::Actor) sends each dealing and acknowledgement as a
//! [`Message`](types::Message) on the subchannel of its epoch. Dealer logs and epoch artifacts
//! travel in application blocks as a [`Payload`](types::Payload).
//!
//! ```text
//! Every message is prefixed by its epoch:
//! +---------------------------------+
//! | epoch subchannel (varint, 1-10) |
//! +---------------------------------+
//!
//! Dealing (tag 0):
//! +---------+---------------------+--------------------------------------+------------+
//! | tag (1) | count (varint, 1-5) | commitment (count x V::Public::SIZE) | share (32) |
//! +---------+---------------------+--------------------------------------+------------+
//!
//! Acknowledgement (tag 1):
//! +---------+--------------------------------+
//! | tag (1) | signature (P::Signature::SIZE) |
//! +---------+--------------------------------+
//!
//! Payload with a dealer log (tag 0):
//! +---------+------------------+---------------------+--------------------------------------+
//! | tag (1) | dealer (P::SIZE) | count (varint, 1-5) | commitment (count x V::Public::SIZE) |
//! +---------+------------------+---------------------+--------------------------------------+
//! | results | signature (P::Signature::SIZE)                                                |
//! +---------+-------------------------------------------------------------------------------+
//!
//! Results, one entry per player (tag 0):
//! +---------+---------------+---------------------+-------------------------+
//! | tag (1) | players (set) | count (varint, 1-5) | entries (count x entry) |
//! +---------+---------------+---------------------+-------------------------+
//!
//! Results with too many reveals (tag 1):
//! +---------+
//! | tag (1) |
//! +---------+
//!
//! Entry with an acknowledgement (tag 0):
//! +---------+--------------------------------+
//! | tag (1) | signature (P::Signature::SIZE) |
//! +---------+--------------------------------+
//!
//! Entry with a revealed share (tag 1):
//! +---------+------------+
//! | tag (1) | share (32) |
//! +---------+------------+
//!
//! Payload with an epoch artifact (tag 1):
//! +---------+-------------+----------------------+-------------+
//! | tag (1) | outcome (1) | epoch (varint, 1-10) | output      |
//! +---------+-----+-------+------------+---------+-------------+
//! | players (set) | next players (set) | directory (encoded D) |
//! +---------------+--------------------+-----------------------+
//!
//! Output:
//! +--------------+----------+------------+-------------------------------------------------+
//! | summary (32) | mode (1) | total (4)  | count (varint, 1-5)                             |
//! +--------------+----------+------------+---------------+---------------+-----------------+
//! | commitment (count x V::Public::SIZE) | dealers (set) | players (set) | revealed (set)  |
//! +--------------------------------------+---------------+---------------+-----------------+
//!
//! Set:
//! +---------------------+------------------------+
//! | count (varint, 1-5) | keys (count x P::SIZE) |
//! +---------------------+------------------------+
//! ```
//!
//! `V` is the BLS variant, `P` the participant key, and `D` the epoch's [`Directory`]. Every
//! `count` is at most the participant bound given to [`max_payload_size`] or
//! [`Payload::max_encode_size`](types::Payload::max_encode_size). [`max_payload_size`] is the
//! larger of the dealing and acknowledgement bounds plus the widest epoch subchannel prefix.
//! [`Payload::max_encode_size`](types::Payload::max_encode_size) is the larger of the two payload
//! bounds, with the directory bound of the payload's type.
//!
//! Size application blocks to carry [`Payload::max_encode_size`](types::Payload::max_encode_size).
//! [`orchestrator::max_payload_size`] covers Simplex on epoch subchannels,
//! [`probe::max_payload_size`] the probe, and [`bootstrap::max_payload_size`] the one-shot engine.

use crate::dkg::{network::Directory, types::SchemeInfo};
use commonware_consensus::{Block, types::Epoch};
use commonware_cryptography::{
    PublicKey,
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
mod limits;
pub use limits::max_payload_size;
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

    /// Participant public key type carried by DKG payloads.
    type PublicKey: PublicKey;

    /// Transport directory type carried by this block's epoch artifacts.
    type Directory: Directory<Self::PublicKey>;

    /// Returns the [`Payload`](types::Payload) carried by this block, if any.
    fn payload(&self) -> Option<types::Payload<Self::Variant, Self::PublicKey, Self::Directory>>;
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
    /// The set must be non-empty and contain at most `max_participants` entries. The reshare
    /// actor panics on a violation. Ceremonies with this set succeed only if enough of its
    /// members lead a block in each [inclusion window](reshare#liveness).
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
