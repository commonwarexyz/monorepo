//! Continuous BLS threshold-key resharing for an application chain.
//!
//! This module runs the ongoing reshare protocol after a chain already has an
//! initial threshold output. It lets an application rotate the set of threshold
//! share holders over time without exposing the aggregate signing key and
//! without requiring a trusted party to redistribute private shares.
//!
//! The reshare actor is a protocol companion that:
//!
//! - reads finalized [`EpochInfo`](crate::dkg::types::EpochInfo) artifacts from
//!   application blocks,
//! - exchanges private Feldman-Desmedt dealings with peers during each epoch,
//! - asks the application to include public dealer logs on-chain,
//! - derives the next epoch's [`EpochInfo`](crate::dkg::types::EpochInfo), and
//! - registers signer or verifier schemes through the application-provided
//!   [`Registrar`](crate::dkg::Registrar).
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
//! - `round` advances only after a successful ceremony.
//! - `outcome` records whether the ceremony that produced this boundary
//!   artifact succeeded or failed.
//!
//! On success, the artifact contains the newly generated output and the round is
//! incremented. On failure, the artifact carries the previous output forward,
//! keeps the round unchanged, advances `players` to the previously announced
//! `next_players`, and refreshes `next_players` from the
//! [`ParticipantsProvider`](crate::dkg::ParticipantsProvider).
//!
//! # Protocol Flow
//!
//! Each epoch has three logical windows:
//!
//! 1. **Setup** loads the finalized boundary artifact, recovers durable protocol
//!    state, registers the current epoch's scheme, and determines whether this
//!    node is a dealer, player, both, or only an observer.
//! 2. **Dealing** runs in the early half of the epoch. Dealers send private
//!    shares directly to players over the DKG P2P channel. Players verify those
//!    shares and return signed acknowledgements.
//! 3. **Inclusion** runs from the midpoint through the final block. Dealers with
//!    enough acknowledgements construct public dealer logs. The application
//!    includes those logs in blocks, and the final block carries the next
//!    epoch's [`EpochInfo`](crate::dkg::types::EpochInfo).
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
//! durable protocol state only after they are finalized on-chain.
//!
//! # Application Contract
//!
//! Application blocks implement [`ReshareBlock`](crate::dkg::ReshareBlock) and
//! carry at most one [`Payload`](crate::dkg::types::Payload). The application is
//! responsible for wiring proposal and verification to [`Mailbox`]:
//!
//! - Before the final block of an epoch, proposers call [`Mailbox::next_log`]
//!   and include the returned dealer log, if any.
//! - Before the final block of an epoch, verifiers treat dealer logs as ordinary
//!   optional payloads and rely on finalized delivery to update the reshare
//!   actor.
//! - At the final block of an epoch, proposers call [`Mailbox::epoch_info`] and
//!   include the returned [`EpochInfo`](crate::dkg::types::EpochInfo).
//! - At the final block of an epoch, verifiers also call [`Mailbox::epoch_info`]
//!   and must reject any block whose payload is not the same
//!   [`EpochInfo`](crate::dkg::types::EpochInfo).
//!
//! The final-block call receives the pending ancestry between the finalized tip
//! and the block under construction or verification. This matters because the
//! application may be proposing or verifying above the finalized tip; dealer logs
//! in that pending ancestry can change the ceremony outcome, but they must not be
//! written durably until the corresponding blocks finalize.
//!
//! Marshal must report finalized blocks to the reshare actor. The actor
//! acknowledges a finalized block only after any protocol state, secret state,
//! registrar update, and epoch fence update required by that block is complete.
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
//! # State Sync
//!
//! Reshare is compatible with application state sync, but timing matters. A node
//! that joins through state sync can participate in epoch `E` only if it was
//! already announced as a `next_player` in epoch `E - 1`. That announcement gives
//! the node time to discover the boundary artifact, state sync, start consensus,
//! and be online for the early private dealings of epoch `E`.
//!
//! If a node state syncs during the epoch in which it is already a `player`, it
//! has missed non-replayable private dealings. The actor enters follower mode for
//! that partial epoch and will not participate in the ceremony. If the ceremony
//! needs that node's share, the share can be revealed as part of the public
//! outcome.
//!
//! This is why [`ParticipantsProvider`](crate::dkg::ParticipantsProvider) can be
//! backed by chain state: the chain announces future players one epoch before
//! their shares are needed.
//!
//! # One-Shot DKG
//!
//! Initial threshold-secret generation is exposed through
//! [`bootstrap`](crate::dkg::bootstrap). That engine reuses the same actor in a
//! crate-private DKG mode, runs it on a contained one-epoch consensus chain, and
//! returns an [`EpochInfo`](crate::dkg::types::EpochInfo) suitable for the
//! genesis artifact of a later reshare-enabled application chain.

use commonware_cryptography::bls12381::primitives::sharing::ModeVersion;

/// The max supported [`ModeVersion`] of this reshare protocol implementation.
#[cfg(not(any(
    commonware_stability_BETA,
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
)))]
pub const MAX_SUPPORTED_MODE: ModeVersion = ModeVersion::v1();

/// The max supported [`ModeVersion`] of this reshare protocol implementation.
#[cfg(any(
    commonware_stability_BETA,
    commonware_stability_GAMMA,
    commonware_stability_DELTA,
    commonware_stability_EPSILON,
    commonware_stability_RESERVED
))]
pub const MAX_SUPPORTED_MODE: ModeVersion = ModeVersion::v0();

mod mailbox;
pub use mailbox::{Mailbox, Message};

mod actor;
pub(crate) use actor::DkgConfig;
pub use actor::{Actor, Config};

mod metrics;
pub(crate) mod store;
