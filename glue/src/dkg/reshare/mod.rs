//! Continuous BLS threshold-key resharing for an application chain.
//!
//! `reshare` rotates the holders of an existing threshold key across the epochs
//! of an application chain. Each epoch runs a Feldman-Desmedt reshare ceremony
//! that preserves the group public key without exposing the group secret or
//! needing a trusted party to redistribute private shares. The ceremony's public
//! outcome is carried in finalized application blocks.
//!
//! # Overview
//!
//! In each epoch, the _dealers_ (the players of the previous threshold output)
//! reshare their shares to the epoch's _players_. A participating node in
//! neither role _observes_ the ceremony and derives the same public outcome.
//!
//! - [`Actor`]: Runs the protocol for one node and registers each epoch's signer
//!   or verifier scheme through the application's
//!   [`Registrar`](crate::dkg::Registrar).
//! - [`Mailbox`]: Supplies reshare payloads for proposals and verification, and
//!   receives finalized blocks from marshal.
//! - [`Application`]: Wraps a consensus application to implement the
//!   [application contract](#application-contract).
//!
//! # Epoch Artifacts
//!
//! Every epoch is described by an [`EpochInfo`](crate::dkg::types::EpochInfo)
//! carried in a finalized boundary block. For epoch zero this artifact is part
//! of genesis. For later epochs it is carried in the final block of the previous
//! epoch.
//!
//! An epoch artifact is a lookahead:
//!
//! - `output` is the public threshold output whose players are the dealers for
//!   the described epoch.
//! - `players` are the share holders targeted by the ceremony in the described
//!   epoch.
//! - `next_players` are announced one epoch early so future players can connect
//!   and state sync before they must receive private dealings.
//! - `outcome` records whether the ceremony that produced this boundary
//!   artifact succeeded or failed.
//!
//! On success, the artifact contains the newly generated output. On failure,
//! the artifact carries the previous output forward, advances `players` to the
//! previously announced `next_players`, and refreshes `next_players` from the
//! [`ParticipantsProvider`](crate::dkg::ParticipantsProvider).
//!
//! # Protocol Flow
//!
//! Each epoch has three logical windows:
//!
//! 1. **Setup** loads the epoch's [`EpochInfo`](crate::dkg::types::EpochInfo),
//!    registers its scheme, and restores this node's dealer and player state.
//! 2. **Dealing** runs in the first half of the epoch. Dealers send private
//!    dealings directly to players, and players verify them and return signed
//!    acknowledgements.
//! 3. **Inclusion** runs from the midpoint through the final block. Dealers
//!    publish signed dealer logs, the application includes them in blocks, and
//!    the final block carries the next epoch's
//!    [`EpochInfo`](crate::dkg::types::EpochInfo).
//!
//! ```text
//! boundary EpochInfo(E)
//!          |
//!          v
//! setup and scheme registration
//!          |
//!          v
//! early epoch: private dealings and acknowledgements over P2P
//!          |
//!          v
//! midpoint onward: dealer logs are posted on-chain
//!          |
//!          v
//! final block: EpochInfo(E + 1)
//! ```
//!
//! Finalized application blocks are the source of truth. Private P2P traffic may
//! be retried or recovered locally, but dealer logs and epoch artifacts affect
//! durable protocol state only once they are finalized:
//!
//! - Record the first correctly signed log per signer from finalized inclusion-window
//!   blocks. During resharing, ignore non-dealers before recording. Ceremony verification
//!   excludes non-dealers and unusable logs.
//! - Upon the finalized final block of an epoch, commit its
//!   [`EpochInfo`](crate::dkg::types::EpochInfo) and register the next epoch's
//!   signer or verifier scheme. A participating node keeps the share it derived
//!   only if its locally derived artifact matches the finalized one.
//!
//! # Application Contract
//!
//! Application blocks implement [`ReshareBlock`](crate::dkg::ReshareBlock) and
//! carry at most one [`Payload`](crate::dkg::types::Payload). [`Application`]
//! implements the following rules. An application that calls [`Mailbox`]
//! directly must follow them itself:
//!
//! - Before the midpoint, blocks carry no payload, and verifiers reject a block
//!   that carries one.
//! - From the midpoint until the final block, proposers call
//!   [`Mailbox::next_log`], include the returned dealer log (if any), and call
//!   [`LogReservation::included`] only after a block is built with it.
//!   Verifiers reject a block that carries a payload other than a dealer log but
//!   do not check dealer logs: an invalid dealer log in a finalized block is
//!   ignored.
//! - At the final block, proposers call [`Mailbox::epoch_info`], include the
//!   payload from [`EpochInfoResponse::Available`], and do not propose on any
//!   other response. Verifiers call it too and must reject a block whose
//!   payload differs. [`Application`] also rejects on
//!   [`EpochInfoResponse::Unavailable`] and leaves verification unresolved on
//!   [`EpochInfoResponse::Pending`] or [`EpochInfoResponse::Following`].
//!
//! The final-block call receives the unfinalized ancestry between the finalized
//! tip and the block under construction or verification. Dealer logs in that
//! ancestry count toward the derived [`EpochInfo`](crate::dkg::types::EpochInfo),
//! but they become durable only when their blocks finalize.
//!
//! Marshal must report finalized blocks to [`Mailbox`], which implements
//! [`Reporter`](commonware_consensus::Reporter). The actor acknowledges a
//! finalized block only after any protocol state, secret state, registrar
//! update, and epoch [`Fence`](crate::dkg::fence::Fence) update required by that
//! block is complete.
//!
//! # Secret Material
//!
//! The protocol deliberately does not prescribe secret storage. Applications
//! provide a [`SecretStore`](crate::dkg::SecretStore) that matches their security
//! policy.
//!
//! The store contains private shares, private dealings, and dealer randomness
//! seeds. These values must not be placed in public protocol storage or
//! application state. The actor uses them for restart recovery, including
//! carrying a valid share forward when a ceremony fails and the previous
//! threshold output remains active.
//!
//! # Offline Players
//!
//! A validator that is selected as a `player` must be online and reachable
//! during the early dealing window if it expects its new secret share to remain
//! private.
//!
//! Feldman-Desmedt resharing preserves liveness by allowing dealers to publish
//! reveal evidence for players that do not return valid acknowledgements. If a
//! validator is offline while it is a `player`, the ceremony can still succeed,
//! but the validator's secret share for the new output will be revealed in the
//! public dealer logs. The resulting output is valid, and the actor does not
//! reject outputs that carry reveals.
//!
//! Operationally, an offline player should treat the affected secret share as
//! public. It must not assume that coming back online later restores the
//! privacy of that share. Applications that require every active signing share
//! to remain unrevealed must enforce that policy outside this protocol.
//!
//! # State Sync
//!
//! A certified floor at or before an epoch's midpoint preserves the complete
//! dealer-log inclusion window, so the actor can participate in that epoch. A
//! floor after the midpoint has skipped part of that history, so the actor
//! follows the reshare ceremony for the remainder of the epoch and resumes at
//! the next boundary.
//!
//! State-sync startup registers the certified current-epoch consensus scheme
//! before entering follower mode. A follower with a recovered share may sign
//! ordinary non-boundary blocks, but cannot locally derive the next
//! [`EpochInfo`](crate::dkg::types::EpochInfo) needed to propose or complete
//! verification of the final block. It learns that outcome from external
//! finalization instead.
//!
//! A `player` that missed private dealings may need public reveals to reconstruct
//! its share, but a revealed share is no longer private. Announcing a node as a
//! `next_player` one epoch early gives it time to state sync and be online for the
//! private dealing window before its share is needed.
//!
//! # Persistence and Recovery
//!
//! Public protocol messages (dealer public messages, player acknowledgements,
//! and finalized dealer logs) are journaled under [`Config::partition_prefix`].
//! Secret material is held only in the [`SecretStore`](crate::dkg::SecretStore).
//! The current epoch's [`EpochInfo`](crate::dkg::types::EpochInfo) is not
//! journaled: after a restart it is read from the finalized boundary block, or
//! from the [`state_sync::Plan`](crate::dkg::state_sync::Plan) after state sync.
//! If neither is available locally, the actor follows that epoch.
//!
//! A player records a dealing before acknowledging it. Before acknowledging a
//! finalized inclusion-window block, a participating actor records any dealer log
//! it accepts and, at an epoch's final block, stores the next epoch's share and
//! dealer seed. A dealer reuses its persisted seed, so dealings regenerated after
//! a restart match those sent before it. A node missing its share does not deal,
//! and a node missing a private dealing that a finalized log acknowledges
//! continues the epoch without its player role.
//!
//! Within a run, the actor has _applied_ every finalized block at or below the
//! latest one it acknowledged, its _applied tip_. At startup it treats
//! marshal's processed position and every block below a state-sync floor as
//! applied.
//!
//! Once started, the actor requires marshal to deliver every finalized block
//! above its applied tip in height order. It acknowledges a redelivered block
//! at or below the tip without repeating its effects and panics on a block
//! above the tip that skips heights or whose parent is not the tip. The
//! startup state-sync floor is the only permitted jump, so a live marshal
//! floor must not leave an unapplied height below it. The actor has no state
//! for skipped blocks, which may include dealer logs or an epoch's final block.
//!
//! # Failures
//!
//! The actor exits without error when the runtime stops, when its mailbox
//! closes, or when its P2P channel closes during a dealing window. It panics on
//! recovery-journal failures, on a boundary or final block without a valid
//! [`EpochInfo`](crate::dkg::types::EpochInfo) for the expected epoch, on a
//! finalized block that conflicts with its applied tip or sits above it without
//! extending it, on
//! [`ParticipantsProvider`](crate::dkg::ParticipantsProvider) contract
//! violations, on a P2P channel that closed outside a dealing window (when it
//! registers the next epoch it participates in), and on otherwise inconsistent
//! recovered local state.
//!
//! # One-Shot DKG
//!
//! Initial threshold-secret generation is exposed through
//! [`bootstrap`](crate::dkg::bootstrap). It runs the same ceremony on a
//! dedicated one-epoch chain and, on success, returns an
//! [`EpochInfo`](crate::dkg::types::EpochInfo) from which to build the genesis
//! block of a reshare-enabled chain. Once it reports the ceremony's outcome,
//! the actor acknowledges each further finalized block of that chain without
//! effects or checks and answers each final-block request with
//! [`EpochInfoResponse::Following`].

mod mailbox;
pub use mailbox::{EpochInfoResponse, LogReservation, Mailbox, Message};

mod actor;
pub(crate) use actor::DkgConfig;
pub use actor::{Actor, Config};

mod application;
pub use application::{Application, Input};

mod metrics;
pub(crate) mod store;
