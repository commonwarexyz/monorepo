//! Feldman/Desmedt Distributed Key Generation (DKG) and Resharing for BLS12-381.
//!
//! This module implements a Feldman/Desmedt-style DKG and Resharing protocol. Unlike other
//! constructions, this construction does not require encrypted shares to be publicly broadcast to
//! complete a DKG/Reshare. Shares, instead, are sent directly between dealers and players over an
//! encrypted channel (which can be instantiated with
//! [commonware-p2p](https://docs.rs/commonware-p2p)).
//!
//! The DKG is based on the "Joint-Feldman" construction from "Secure Distributed Key
//! Generation for Discrete-Log Based Cryptosystems" (GJKR99) and Resharing is based
//! on the construction described in "Redistributing secret shares to new access structures
//! and its applications" (Desmedt97).
//!
//! # Overview
//!
//! The protocol involves _dealers_ and _players_. The dealers are trying to jointly create a shared
//! key, and then distribute it among the players. The dealers may have pre-existing shares of a key
//! from a previous round, in which case the goal is to re-distribute that key among the players,
//! with fresh randomness.
//!
//! The protocol is also designed such that an external observer can figure out whether the protocol
//! succeeded or failed, and learn of the public outputs of the protocol. This includes
//! the participants in the protocol, and the public polynomial committing to the key
//! and its sharing.
//!
//! # Usage
//!
//! ## Core Types
//!
//! * [`Info`]: Configuration for a DKG/Reshare round, containing the dealers, players, and optional previous output
//! * [`Output`]: The public result of a successful DKG round, containing the public polynomial and player list
//! * [`Share`]: A player's final private share of the distributed key (from `primitives::group`)
//! * [`Dealer`]: State machine for a dealer participating in the protocol
//! * [`Player`]: State machine for a player receiving dealings
//! * [`SignedDealerLog`]: A dealer's signed transcript of their interactions with players
//!
//! ## Message Types
//!
//! * [`DealerPubMsg`]: Public commitment polynomial sent from dealer to all players
//! * [`DealerPrivMsg`]: Private dealing sent from dealer to a specific player
//! * [`PlayerAck`]: Acknowledgement sent from player back to dealer
//! * [`DealerLog`]: Complete log of a dealer's interactions (commitments and acks/reveals)
//!
//! ## Protocol Flow
//!
//! ### Step 1: Initialize Round
//!
//! Create a [`Info`] using [`Info::new`] with:
//! - Round number (should increment sequentially, including for failed rounds)
//! - Optional previous [`Output`] (for resharing)
//! - List of dealers (must be >= quorum of previous round if resharing)
//! - List of players who will receive dealings
//!
//! ### Step 2: Dealer Phase
//!
//! Each dealer calls [`Dealer::start`] which returns:
//! - A [`Dealer`] instance for tracking state
//! - A [`DealerPubMsg`] containing the polynomial commitment to broadcast
//! - A vector of `(player_id, DealerPrivMsg)` pairs to send privately
//!
//! The [`DealerPubMsg`] contains a public polynomial commitment of degree `2f` where `f = max_faults(n)`.
//! Each [`DealerPrivMsg`] contains a scalar evaluation of the dealer's private polynomial at the player's index.
//!
//! ### Step 3: Player Verification
//!
//! Each player creates a [`Player`] instance via [`Player::new`], then for each dealer message:
//! - Call [`Player::dealer_message`] with the [`DealerPubMsg`] and [`DealerPrivMsg`]
//! - If valid, this returns a [`PlayerAck`] containing a signature over `(dealer, commitment)`
//! - The player verifies that the private dealing matches the public commitment evaluation
//!
//! ### Step 4: Dealer Collection
//!
//! Each dealer:
//! - Calls [`Dealer::receive_player_ack`] for each acknowledgement received
//! - After timeout, calls [`Dealer::finalize`] to produce a [`SignedDealerLog`]
//! - The log contains the commitment and either acks or reveals for each player
//!
//! ### Step 5: Finalization
//!
//! With collected [`SignedDealerLog`]s:
//! - Call [`SignedDealerLog::check`] to verify and extract [`DealerLog`]s
//! - Players call [`Player::finalize`] with all logs to compute their [`Share`] and [`Output`]
//! - Observers call [`observe`] with all logs to compute just the [`Output`]
//!
//! The [`Output`] contains:
//! - The final public polynomial (sum of dealer polynomials for DKG, interpolation for reshare),
//! - The list of dealers who distributed dealings,
//! - The list of players who received shares,
//! - The set of players whose shares may have been revealed,
//! - A digest of the round's [`Info`] (including the counter, and the list of dealers and players).
//!
//! ## Trusted Dealing Functions
//!
//! As a convenience (for tests, etc.), this module also provides functions for
//! generating shares using a trusted dealer.
//!
//! - [`deal`]: given a list of players, generates an [`Output`] like the DKG would,
//! - [`deal_anonymous`]: a lower-level version that produces a polynomial directly,
//!   and doesn't require public keys for the players.
//!
//! ## State
//!
//! The structs in this module are stateful and they assume that they exist from the
//! start of the DKG to the end of the DKG.
//!
//! During restart, state should be restored by replaying all messages that
//! dealers and players previously processed. For the dealer, it's important to use a
//! seeded form of randomness, so that way the same messages can be generated on a second run.
//! For the player, using [`Player::resume`] is more robust than just [`Player::new`], because it
//! checks the integrity of the replayed messages against the publicly committed transcript (so far).
//! This can detect some recoverable operator errors, like storage misconfiguration (where a player has publicly
//! acknowledged a private message but has no record of it in storage).
//!
//! ## Errors and Failures
//!
//! [`enum@Error`] reports invalid caller input or incomplete local state.
//! [`DealerMessageError`] and [`PlayerAckError`] explain why live messages were
//! rejected without attributing the failure to a participant. [`FaultReason`]
//! describes invalid content in a configured dealer's signed log. [`Failure`]
//! reports that the protocol round did not produce the requested result.
//!
//! These categories reflect the evidence available to each operation. A
//! live-message error explains why input was rejected but does not establish who
//! caused it. A [`FaultReason`] supports dealer attribution only for invalid
//! content in a configured dealer's log authenticated by [`SignedDealerLog::check`].
//!
//! [`Failure::InsufficientLogs`] separates those faults from configured dealers
//! with no usable log. A safe [`DealerLogSummary::TooManyReveals`] log is
//! unavailable because it intentionally omits its results.
//!
//! [`Player::finalize`] can encounter either kind of problem, so it returns
//! [`FinalizeError`] to distinguish a local [`enum@Error`] from a protocol [`Failure`].
//!
//! # Caveats
//!
//! ## Share Reveals
//!
//! In order to prevent malicious dealers from withholding shares from players, we
//! require the dealers reveal the shares for which they did not receive acks.
//!
//! Under synchrony (as discussed below), this will only happen if either:
//! - the dealer is malicious, not sending a share, but honestly revealing,
//! - or, the player is malicious, not sending an ack when they should.
//!
//! ### Up to `f` Reveals Under Synchrony
//!
//! Under synchrony (where `t` is the maximum amount of time it takes for a message to be sent between any two participants),
//! this construction will not result in more than `f` reveals from honest dealers, and none of those reveals are for honest players
//! (`2f + 1` commitments with at most `f` players are Byzantine).
//!
//! To see how this is true, first consider that in any successful round there must exist `2f + 1` commitments each with at most `f`
//! reveals. This implies that all players must have acknowledged or have access to a reveal for each of the `2f + 1` selected commitments
//! (allowing them to derive their share). Next, consider that when the network is synchronous that all `2f + 1` honest players send
//! acknowledgements to honest dealers before `2t`. Because `2f + 1` commitments must be chosen, at least `f + 1` commitments
//! must be from honest dealers (where no honest player dealing is revealed...recall, a Byzantine dealer can opt to reveal any
//! player's dealing even if they sent an acknowledgement).
//!
//! Even if the remaining `f` commitments are from Byzantine dealers, there will not be enough dealings to recover the derived share
//! of any honest player (at most `f` of `2f + 1` points for a linear combination publicly revealed). Given all `2f + 1`
//! honest players have access to their shares and it is not possible for a Byzantine player to derive any honest player's share, this claim holds.
//!
//! ### Up to `2f` Reveals Under Asynchrony
//!
//! If the network is asynchronous, Byzantine players may obtain up to `2f` revealed shares (`f` from Byzantine players
//! and `f` from honest players).
//!
//! To see how this could be, consider a network where `f` honest participants are in one partition and (`f + 1` honest and
//! `f` Byzantine participants) are in another. All `f` Byzantine players acknowledge dealings from the `f + 1` honest dealers.
//! Participants in the second partition will complete a round and all the reveals will belong to the same set of `f`
//! honest players (that are in the first partition). A colluding Byzantine adversary will then have access to their acknowledged `f`
//! shares and the revealed `f` shares. If the Byzantine adversary reveals all of their (still private) shares at this time, each of the
//! `f + 1` honest players that were in the second partition will be able to derive the shared secret without collusion (using their private share
//! and the `2f` revealed shares). **It will not be possible for any external observer (or a Byzantine adversary), however, to recover the shared secret.**
//!
//! While not entirely revealed, a secret with more than `f` revealed shares may no longer be safe for some applications (like when used to
//! form threshold certificates for consensus). Consider an equivocating leader (one of the `f` Byzantine players) that sends one block `B_1` to `f`
//! honest players and another block `B_2` to `f + 1` other honest players. Normally, it would only be possible to create one quorum of `2f + 1` (for `B_2`),
//! however, with `h` other shares revealed another quorum of `2f + h` can be formed for `B_1`.
//!
//! #### Dropping the Synchrony Assumption for `f` Bounded Reveals?
//!
//! It is possible to design a DKG/Resharing scheme that maintains a shared secret where at least `f + 1` honest players
//! must participate to recover the shared secret that doesn't require a synchrony assumption (`2f + 1` threshold
//! where at most `f` players are Byzantine) by combining encryption and ZK Proofs. We have an implementation of one
//! such protocol, [Golden](https://eprint.iacr.org/2025/1924), in [`crate::bls12381::dkg::golden`].
//!
//! ## Handling Complaints
//!
//! This crate does not provide an integrated mechanism for tracking complaints from players (of malicious dealers). However, it is
//! possible to implement your own mechanism and to manually disqualify dealers from a given round in the arbiter. This decision was made
//! because the mechanism for communicating commitments/shares/acknowledgements is highly dependent on the context in which this
//! construction is used.
//!
//! In practice:
//! - [`Player::dealer_message`] returns [`DealerMessageError`] for an invalid
//!   message and `Ok(None)` for a benign duplicate
//! - [`Dealer::receive_player_ack`] returns [`PlayerAckError`] when an
//!   acknowledgement cannot be used
//! - Other custom mechanisms can exclude dealers before calling [`observe`] or [`Player::finalize`],
//!   to enforce other rules for "misbehavior" beyond what the DKG does already.
//!
//! ## Aggregate Degree
//!
//! For `n` players and at most `f` faults, the configured quorum is `n - f`, so dealer polynomials
//! have degree `d = n - f - 1`. The aggregate must retain that exact degree; otherwise, fewer than
//! `n - f` participants could recover the shared secret or produce a threshold signature.
//!
//! Every accepted dealer commitment has exact degree `d`, and a usable dealer log records one
//! result for every player. At most `f` results can be Byzantine acknowledgements issued without
//! verifying their shares. Every other result is either an honest acknowledgement of a verified
//! share or a reveal verified against the commitment. The log therefore contains at least
//! `n - f = d + 1` valid scalar evaluations, enough to determine the dealer's polynomial and the
//! scalar behind every coefficient commitment.
//!
//! Whether selected commitments are summed during initial key generation or combined with non-zero
//! Lagrange weights during resharing, the leading coefficient includes an independently sampled
//! contribution from at least one honest dealer. Although
//! [a rushing adversary](https://decentralizedthoughts.github.io/2019-06-07-modeling-the-adversary/#rushing)
//! may observe the honest commitments before choosing its own, it must know every Byzantine
//! coefficient scalar before those commitments can be selected. Choosing those scalars so their
//! combined leading term cancels the honest contribution would require solving the discrete
//! logarithm of the honest leading commitment (preventing any efficient adversary from forcing the
//! aggregate below degree `d`).
//!
//! ## Non-Uniform Distribution
//!
//! The Joint-Feldman DKG protocol does not guarantee a uniformly random secret key is generated. An adversary
//! can introduce `O(lg N)` bits of bias into the key with `O(poly(N))` amount of computation. For uses
//! like signing, threshold encryption, where the security of the scheme reduces to that of
//! the underlying assumption that cryptographic constructions using the curve are secure (i.e.
//! that the Discrete Logarithm Problem, or stronger variants, are hard), then this caveat does
//! not affect the security of the scheme. This must be taken into account when integrating this
//! component into more esoteric schemes.
//!
//! This choice was explicitly made, because the best known protocols guaranteeing a uniform output
//! require an extra round of broadcast ([GJKR02](https://www.researchgate.net/publication/2558744_Revisiting_the_Distributed_Key_Generation_for_Discrete-Log_Based_Cryptosystems),
//! [BK25](https://eprint.iacr.org/2025/819)).
//!
//! # Example
//!
//! ```
//! use commonware_cryptography::bls12381::{
//!     dkg::feldman_desmedt::{
//!         Dealer, Info, Logs, Player, Reveal, SignedDealerLog, observe,
//!     },
//!     primitives::{variant::MinSig, sharing::Mode},
//! };
//! use commonware_cryptography::{ed25519, Signer};
//! use commonware_math::algebra::Random;
//! use commonware_utils::{ordered::Set, TryCollect, N3f1};
//! use std::collections::BTreeMap;
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha8Rng;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut rng = ChaCha8Rng::seed_from_u64(42);
//!
//! // Generate 4 Ed25519 private keys for participants
//! let mut private_keys = Vec::new();
//! for _ in 0..4 {
//!     let private_key = ed25519::PrivateKey::random(&mut rng);
//!     private_keys.push(private_key);
//! }
//!
//! // All 4 participants are both dealers and players in initial DKG
//! let dealer_set: Set<ed25519::PublicKey> = private_keys.iter()
//!     .map(|k| k.public_key())
//!     .try_collect()?;
//! let player_set = dealer_set.clone();
//!
//! // Step 1: Create round info for initial DKG
//! let info = Info::<MinSig, ed25519::PublicKey>::new::<N3f1>(
//!     b"application-namespace",
//!     0,                        // round number
//!     None,                     // no previous output (initial DKG)
//!     Mode::NonZeroCounter,     // sharing mode
//!     Reveal::V1,               // revealed-share calculation
//!     dealer_set.clone(),       // dealers
//!     player_set.clone(),       // players
//! )?;
//!
//! // Step 2: Initialize players
//! let mut players = BTreeMap::new();
//! for private_key in &private_keys {
//!     let player = Player::<MinSig, ed25519::PrivateKey>::new(
//!         info.clone(),
//!         private_key.clone(),
//!     )?;
//!     players.insert(private_key.public_key(), player);
//! }
//!
//! // Step 3: Run dealer protocol for each participant
//! let mut logs = Logs::<MinSig, ed25519::PublicKey, N3f1>::new(info.clone());
//! for dealer_priv in &private_keys {
//!     // Each dealer generates messages for all players
//!     let (mut dealer, pub_msg, priv_msgs) = Dealer::start::<N3f1>(
//!         &mut rng,
//!         info.clone(),
//!         dealer_priv.clone(),
//!         None,  // no previous share for initial DKG
//!     )?;
//!
//!     // Distribute messages to players and collect acknowledgements
//!     for (player_pk, priv_msg) in priv_msgs {
//!         if let Some(player) = players.get_mut(&player_pk) {
//!             if let Some(ack) = player.dealer_message::<N3f1>(
//!                 dealer_priv.public_key(),
//!                 pub_msg.clone(),
//!                 priv_msg,
//!             )? {
//!                 dealer.receive_player_ack(player_pk, ack)?;
//!             }
//!         }
//!     }
//!
//!     // Finalize dealer and verify log
//!     let signed_log = dealer.finalize::<N3f1>();
//!     if let Some((dealer_pk, log)) = signed_log.check(&info) {
//!         logs.record(dealer_pk, log);
//!     }
//! }
//!
//! // Step 4: Players finalize to get their shares
//! let mut player_shares = BTreeMap::new();
//! for (player_pk, player) in players {
//!     let (output, share) = player.finalize::<N3f1, ed25519::Batch>(
//!       &mut rng,
//!       logs.clone(),
//!       &commonware_parallel::Sequential,
//!     )?;
//!     println!("Player {:?} got share at index {}", player_pk, share.index);
//!     player_shares.insert(player_pk, share);
//! }
//!
//! // Step 5: Observer can also compute the public output
//! let observer_output = observe::<MinSig, ed25519::PublicKey, N3f1, ed25519::Batch>(
//!     &mut rng,
//!     logs,
//!     &commonware_parallel::Sequential,
//! )?;
//! println!("DKG completed with threshold {}", observer_output.quorum::<N3f1>());
//! # Ok(())
//! # }
//! ```
//!
//! For a complete example with resharing, see [commonware-reshare](https://docs.rs/commonware-reshare).

use crate::{
    BatchVerifier, PublicKey, Secret, Signer,
    bls12381::primitives::{
        group::{Private, Scalar, ScalarReadCfg, Share},
        sharing::{Mode, ModeVersion, Sharing},
        variant::Variant,
    },
    transcript::{Summary, Transcript, Version},
};
use commonware_codec::{
    Encode, EncodeSize, Mode as CodecMode, RangeCfg, Read, ReadExt, Write, mode, modes,
};
use commonware_math::{
    algebra::{Additive, CryptoGroup, Random, Ring as _},
    poly::{Interpolator, Poly},
};
use commonware_parallel::{Sequential, Strategy};
#[cfg(feature = "arbitrary")]
use commonware_utils::N3f1;
use commonware_utils::{
    Faults, NZU32, Participant, TryCollect,
    ordered::{Map, Quorum, Set},
};
use core::num::NonZeroU32;
use rand_core::CryptoRng;
use std::{borrow::Cow, collections::BTreeMap, marker::PhantomData};
use thiserror::Error;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG";
const SIG_ACK: &[u8] = b"ack";
const SIG_LOG: &[u8] = b"log";
const NOISE_PRE_VERIFY: &[u8] = b"pre_verify";

// Feldman satisfies V0's fixed-schema requirements: its application namespace is fixed, and every
// later packet has a canonical encoding at a fixed position.
const TRANSCRIPT_VERSION: Version = Version::V0;

/// An error caused by invalid caller input or incomplete local state.
#[derive(Clone, Debug, Error)]
pub enum Error {
    #[error("missing dealer's share from the previous round")]
    MissingDealerShare,
    #[error("player is not present in the list of players")]
    PlayerNotInRound,
    #[error("dealer {0} is not present in the round")]
    DealerNotInRound(String),
    #[error("invalid number of dealers: {0}")]
    NumDealers(usize),
    #[error("invalid number of players: {0}")]
    NumPlayers(usize),
    /// The previous output is not internally consistent.
    #[error("invalid previous DKG output")]
    InvalidPreviousOutput,
    /// A persisted dealing is invalid or stale relative to the selected dealer log.
    #[error("invalid persisted dealing from dealer {dealer}")]
    InvalidPersistedDealing {
        /// Dealer associated with the invalid persisted dealing.
        dealer: String,
    },
    /// The supplied logs are bound to a different DKG round.
    #[error("logs are bound to a different dkg round")]
    MismatchedLogs,
    /// The player's state is missing a dealing it should have.
    ///
    /// This error is emitted when the player is missing dealings that it should
    /// otherwise have based on the flow of the protocol. This can only happen if
    /// the code in this module is used in a stateful way, restoring the
    /// state of the player from saved information. If this state is corrupted
    /// on disk, or missing, then this error can happen.
    #[error("missing player's dealing")]
    MissingPlayerDealing,
}

/// The reason a configured dealer's signed log proves a protocol fault.
#[derive(Clone, Debug, Error)]
pub enum FaultReason {
    #[error("dealer log contains an acknowledgement signature that does not verify")]
    InvalidAck,
    #[error("dealer reveal does not match its commitment")]
    InvalidReveal,
    #[error("invalid dealer commitment degree: expected {expected}, got {actual}")]
    InvalidCommitmentDegree {
        /// The commitment degree required by the round.
        expected: u32,
        /// The commitment degree supplied by the dealer.
        actual: u32,
    },
    #[error("dealer commitment does not match its previous share")]
    MismatchedReshareCommitment,
    #[error("dealer log player set does not match the round")]
    MismatchedLogPlayers,
    /// The dealer published explicit results containing too many reveals.
    ///
    /// A log that safely omits its results with [`DealerLogSummary::TooManyReveals`]
    /// is unavailable, not faulty.
    #[error("dealer log publishes too many reveals")]
    ExcessiveReveals,
}

/// The reason an initial dealer message was rejected.
///
/// Initial dealer messages carry no dealer signature in this construction, so
/// the caller is responsible for authenticating the `dealer` supplied to
/// [`Player::dealer_message`]. The dealer later signs the public message as part
/// of the [`SignedDealerLog`] produced by [`Dealer::finalize`].
#[derive(Clone, Debug, Error)]
pub enum DealerMessageError {
    #[error("participant is not a dealer in this round")]
    UnexpectedDealer,
    #[error("invalid dealer commitment degree: expected {expected}, got {actual}")]
    InvalidCommitmentDegree {
        /// The commitment degree required by the round.
        expected: u32,
        /// The commitment degree supplied by the dealer.
        actual: u32,
    },
    #[error("dealer commitment does not match its previous share")]
    MismatchedReshareCommitment,
    #[error("dealer share does not match its commitment")]
    InvalidDealerShare,
}

/// The reason a live player acknowledgement was rejected.
#[derive(Clone, Debug, Error)]
pub enum PlayerAckError {
    #[error("participant is not a player in this round")]
    UnexpectedPlayer,
    #[error("player acknowledgement signature does not match the dealer transcript")]
    InvalidAck,
}

/// Failures determined solely from a dealer's public message.
///
/// The shared validator returns exactly these cases. Each validation boundary
/// maps them into its operation-specific public error without widening that
/// error's reachable variants.
enum DealerPubMsgError {
    /// The commitment degree differs from the degree required by the round.
    InvalidCommitmentDegree { expected: u32, actual: u32 },
    /// The commitment constant does not preserve the dealer's previous share.
    MismatchedReshareCommitment,
}

// Live validation exposes the rejection without claiming signed-log evidence.
impl From<DealerPubMsgError> for DealerMessageError {
    fn from(error: DealerPubMsgError) -> Self {
        match error {
            DealerPubMsgError::InvalidCommitmentDegree { expected, actual } => {
                Self::InvalidCommitmentDegree { expected, actual }
            }
            DealerPubMsgError::MismatchedReshareCommitment => Self::MismatchedReshareCommitment,
        }
    }
}

// Signed-log validation records the same rejection as dealer-authenticated evidence.
impl From<DealerPubMsgError> for FaultReason {
    fn from(error: DealerPubMsgError) -> Self {
        match error {
            DealerPubMsgError::InvalidCommitmentDegree { expected, actual } => {
                Self::InvalidCommitmentDegree { expected, actual }
            }
            DealerPubMsgError::MismatchedReshareCommitment => Self::MismatchedReshareCommitment,
        }
    }
}

/// Non-fault outcome of checking a dealer log against a round.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DealerLogOutcome {
    /// The configured dealer's log contains verified results.
    Available,
    /// The configured dealer omitted results to avoid excessive reveals.
    Unavailable,
}

/// The reason a dealer log was rejected for a round.
#[derive(Clone, Debug)]
enum DealerLogError {
    /// The supplied identity is not a dealer in the round.
    UnexpectedDealer,
    /// The configured dealer's signed log proves a protocol fault.
    Fault(FaultReason),
}

/// A protocol round failure.
#[derive(Debug, Error)]
pub enum Failure<P> {
    /// Too few usable dealer logs remain to complete the DKG.
    #[error("insufficient usable dealer logs: required={required}, found={found}")]
    InsufficientLogs {
        /// Number of usable dealer logs required to complete the DKG.
        required: u32,
        /// Number of usable dealer logs found.
        found: u32,
        /// Configured dealers whose signed logs prove a protocol fault.
        ///
        /// Attribution assumes [`Logs::record`] receives only pairs returned by
        /// [`SignedDealerLog::check`].
        faults: Map<P, FaultReason>,
        /// Configured dealers for which no usable log was available.
        ///
        /// This includes missing logs and logs that safely omit their results
        /// because publishing them would reveal too many shares.
        unavailable: Set<P>,
    },
}

/// An error finalizing a player's DKG output and private share.
#[derive(Debug, Error)]
pub enum FinalizeError<P> {
    /// The caller supplied invalid input or incomplete local state.
    #[error(transparent)]
    Error(#[from] Error),
    /// The protocol round failed.
    #[error(transparent)]
    Failure(#[from] Failure<P>),
}

/// The output of a successful DKG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output<V: Variant, P> {
    summary: Summary,
    public: Sharing<V>,
    dealers: Set<P>,
    players: Set<P>,
    revealed: Set<P>,
}

impl<V: Variant, P: Ord> Output<V, P> {
    fn share_commitment(&self, player: &P) -> Option<V::Public> {
        self.public.partial_public(self.players.index(player)?).ok()
    }

    /// Return the quorum, i.e. the number of players needed to reconstruct the key.
    pub fn quorum<M: Faults>(&self) -> u32 {
        self.players.quorum::<M>()
    }

    /// Get the public polynomial associated with this output.
    ///
    /// This is useful for verifying partial signatures, with [crate::bls12381::primitives::ops::threshold::verify_message].
    pub const fn public(&self) -> &Sharing<V> {
        &self.public
    }

    /// Return the dealers who were selected in this round of the DKG.
    pub const fn dealers(&self) -> &Set<P> {
        &self.dealers
    }

    /// Return the players who participated in this round of the DKG, and should have shares.
    pub const fn players(&self) -> &Set<P> {
        &self.players
    }

    /// Return the set of players whose shares may have been revealed.
    ///
    /// These are players whose shares can be reconstructed from the selected dealer reveals.
    pub const fn revealed(&self) -> &Set<P> {
        &self.revealed
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for Output<V, P> {
    fn encode_size(&self) -> usize {
        self.summary.encode_size()
            + self.public.encode_size()
            + self.dealers.encode_size()
            + self.players.encode_size()
            + self.revealed.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for Output<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.summary.write(buf);
        self.public.write(buf);
        self.dealers.write(buf);
        self.players.write(buf);
        self.revealed.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for Output<V, P> {
    type Cfg = (NonZeroU32, ModeVersion);

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        (max_participants, max_supported_mode): &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let max_participants_usize = max_participants.get() as usize;
        Ok(Self {
            summary: ReadExt::read(buf)?,
            public: Read::read_cfg(buf, &(*max_participants, *max_supported_mode))?,
            dealers: Read::read_cfg(buf, &(RangeCfg::new(1..=max_participants_usize), ()))?, // at least one dealer must be part of a dealing
            players: Read::read_cfg(buf, &(RangeCfg::new(1..=max_participants_usize), ()))?, // at least one player must be part of a dealing
            revealed: Read::read_cfg(buf, &(RangeCfg::new(0..=max_participants_usize), ()))?, // there may not be any reveals
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, V: Variant> arbitrary::Arbitrary<'_> for Output<V, P>
where
    P: for<'a> arbitrary::Arbitrary<'a> + Ord,
    V::Public: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let summary = u.arbitrary()?;
        let public: Sharing<V> = u.arbitrary()?;
        let total = public.total().get() as usize;

        let num_dealers = u.int_in_range(1..=total * 2)?;
        let dealers = Set::try_from(
            u.arbitrary_iter::<P>()?
                .take(num_dealers)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| arbitrary::Error::IncorrectFormat)?;

        let players = Set::try_from(
            u.arbitrary_iter::<P>()?
                .take(total)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|_| arbitrary::Error::IncorrectFormat)?;

        let max_revealed = N3f1::max_faults(total) as usize;
        let revealed = Set::from_iter_dedup(
            players
                .iter()
                .filter(|_| u.arbitrary::<bool>().unwrap_or(false))
                .take(max_revealed)
                .cloned(),
        );

        Ok(Self {
            summary,
            public,
            dealers,
            players,
            revealed,
        })
    }
}

/// Revealed-share calculation used by a DKG ceremony.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Reveal {
    /// Original calculation based on the number of players in the new sharing.
    #[deprecated(note = "uses the new player set instead of the contributor set")]
    V0 = 0,
    /// Contributor-aware calculation based on the dealers or previous players.
    V1 = 1,
}

#[allow(deprecated)]
impl From<Reveal> for CodecMode {
    fn from(reveal: Reveal) -> Self {
        match reveal {
            Reveal::V0 => mode!(0),
            Reveal::V1 => mode!(1),
        }
    }
}

/// Information about the current round of the DKG.
///
/// This is used to bind signatures to the current round, and to provide the
/// information that dealers, players, and observers need to perform their actions.
/// Every operation using an [`Info`] must use the same [`Faults`] implementation
/// that constructed it. Reshares must retain that fault model across rounds.
#[derive(Debug, Clone)]
pub struct Info<V: Variant, P> {
    summary: Summary,
    round: u64,
    previous: Option<Output<V, P>>,
    mode: Mode,
    reveal: Reveal,
    dealers: Set<P>,
    players: Set<P>,
}

impl<V: Variant, P: PublicKey> PartialEq for Info<V, P> {
    fn eq(&self, other: &Self) -> bool {
        self.summary == other.summary
    }
}

impl<V: Variant, P: PublicKey> Info<V, P> {
    /// Figure out what the dealer share should be.
    ///
    /// If there's no previous round, we need a random value, hence `rng`.
    ///
    /// However, if there is a previous round, we expect a share, hence `Result`.
    fn unwrap_or_random_share(
        &self,
        mut rng: impl CryptoRng,
        share: Option<Scalar>,
    ) -> Result<Scalar, Error> {
        let out = match (self.previous.as_ref(), share) {
            (None, None) => Scalar::random(&mut rng),
            (_, Some(x)) => x,
            (Some(_), None) => return Err(Error::MissingDealerShare),
        };
        Ok(out)
    }

    const fn num_players(&self) -> NonZeroU32 {
        // Will not panic because we check that the number of players is non-empty in `new`
        NZU32!(self.players.len() as u32)
    }

    fn degree<M: Faults>(&self) -> u32 {
        self.players.quorum::<M>().saturating_sub(1)
    }

    fn required_commitments<M: Faults>(&self) -> u32 {
        let dealer_quorum = self.dealers.quorum::<M>();
        let prev_quorum = self
            .previous
            .as_ref()
            .map(Output::quorum::<M>)
            .unwrap_or(u32::MIN);
        dealer_quorum.max(prev_quorum)
    }

    fn max_reveals<M: Faults>(&self) -> u32 {
        self.players.max_faults::<M>()
    }

    fn reveal_threshold<M: Faults>(&self) -> u32 {
        #[allow(deprecated)]
        match self.reveal {
            Reveal::V0 => self.players.max_faults::<M>() + 1,
            Reveal::V1 => {
                let max_faults = self.previous.as_ref().map_or_else(
                    || self.dealers.max_faults::<M>(),
                    |previous| previous.players.max_faults::<M>(),
                );
                self.required_commitments::<M>()
                    .checked_sub(max_faults)
                    .expect("a quorum must contain more participants than max_faults")
            }
        }
    }

    fn player_index(&self, player: &P) -> Option<Participant> {
        self.players.index(player)
    }

    fn dealer_index(&self, dealer: &P) -> Option<Participant> {
        self.dealers.index(dealer)
    }

    fn player_scalar(&self, player: &P) -> Option<Scalar> {
        self.mode
            .scalar(self.num_players(), self.player_index(player)?)
    }

    fn check_dealer_pub_msg<M: Faults>(
        &self,
        dealer: &P,
        pub_msg: &DealerPubMsg<V>,
    ) -> Result<(), DealerPubMsgError> {
        let expected = self.degree::<M>();
        let actual = pub_msg.commitment.degree_exact();
        if expected != actual {
            return Err(DealerPubMsgError::InvalidCommitmentDegree { expected, actual });
        }
        if let Some(previous) = self.previous.as_ref() {
            let share_commitment = previous
                .share_commitment(dealer)
                .expect("Info::new validates previous output and dealer membership");
            if *pub_msg.commitment.constant() != share_commitment {
                return Err(DealerPubMsgError::MismatchedReshareCommitment);
            }
        }
        Ok(())
    }

    fn check_dealer_priv_msg(
        &self,
        player: Participant,
        pub_msg: &DealerPubMsg<V>,
        priv_msg: &DealerPrivMsg,
    ) -> bool {
        let scalar = self
            .mode
            .scalar(self.num_players(), player)
            .expect("Player::new validates the participant index");
        let expected = pub_msg.commitment.eval_msm(&scalar, &Sequential);
        priv_msg
            .share
            .expose(|share| expected == V::Public::generator() * share)
    }

    fn check_dealer_log<M: Faults, B: BatchVerifier<PublicKey = P>>(
        &self,
        rng: &mut impl CryptoRng,
        strategy: &impl Strategy,
        round_transcript: &Transcript,
        dealer: &P,
        log: &DealerLog<V, P>,
    ) -> Result<DealerLogOutcome, DealerLogError> {
        if self.dealer_index(dealer).is_none() {
            return Err(DealerLogError::UnexpectedDealer);
        }
        self.check_dealer_pub_msg::<M>(dealer, &log.pub_msg)
            .map_err(|error| DealerLogError::Fault(error.into()))?;
        let Some(results_iter) = log
            .zip_players(&self.players)
            .map_err(DealerLogError::Fault)?
        else {
            return Ok(DealerLogOutcome::Unavailable);
        };
        let ack_summary = transcript_for_ack(round_transcript, dealer, &log.pub_msg).summarize();
        let mut ack_batch = B::new(self.players.len());
        let mut reveal_count = 0;
        let max_reveals = self.max_reveals::<M>();
        let mut reveal_eval_points = Vec::new();
        let mut reveal_sum = Scalar::zero();
        for (player, result) in results_iter {
            match result {
                AckOrReveal::Ack(ack) => {
                    if !ack_summary.add_to_batch(&mut ack_batch, player, &ack.sig) {
                        return Err(DealerLogError::Fault(FaultReason::InvalidAck));
                    }
                }
                AckOrReveal::Reveal(priv_msg) => {
                    reveal_count += 1;
                    if reveal_count > max_reveals {
                        return Err(DealerLogError::Fault(FaultReason::ExcessiveReveals));
                    }
                    let player_scalar = self
                        .player_scalar(player)
                        .expect("log players were matched against the round");
                    let coeff = if reveal_count == 1 {
                        Scalar::one()
                    } else {
                        Scalar::random(&mut *rng)
                    };
                    reveal_eval_points.push((coeff.clone(), player_scalar));
                    priv_msg
                        .share
                        .expose(|share| reveal_sum += &(coeff * share));
                }
            }
        }
        if !ack_batch.verify(&mut *rng, strategy) {
            return Err(DealerLogError::Fault(FaultReason::InvalidAck));
        }
        let lhs = log.pub_msg.commitment.lin_comb_eval(
            reveal_eval_points
                .into_iter()
                .map(|(coeff, point)| (coeff, Cow::Owned(point))),
            strategy,
        );
        if lhs != V::Public::generator() * &reveal_sum {
            return Err(DealerLogError::Fault(FaultReason::InvalidReveal));
        }
        Ok(DealerLogOutcome::Available)
    }
}

impl<V: Variant, P: PublicKey> Info<V, P> {
    /// Create a new [`Info`].
    ///
    /// `namespace` must be provided to isolate different applications
    /// performing DKGs from each other. It must remain fixed across all rounds,
    /// epochs, restarts, and participants in the protocol's lifetime.
    /// `round` should be a counter, always incrementing, even for failed DKGs.
    /// `previous` should be the result of the previous successful DKG. Its public sharing must
    /// have a participant count matching its player set and an exact recovery threshold equal to
    /// the fault-model quorum.
    /// `reveal` selects the revealed-share calculation.
    /// `dealers` should be the list of public keys for the dealers. This MUST
    /// be a subset of the previous round's players.
    /// `players` should be the list of public keys for the players.
    pub fn new<M: Faults>(
        namespace: &[u8],
        round: u64,
        previous: Option<Output<V, P>>,
        mode: Mode,
        reveal: Reveal,
        dealers: Set<P>,
        players: Set<P>,
    ) -> Result<Self, Error> {
        let participant_range = 1..u32::MAX as usize;
        if !participant_range.contains(&dealers.len()) {
            return Err(Error::NumDealers(dealers.len()));
        }
        if !participant_range.contains(&players.len()) {
            return Err(Error::NumPlayers(players.len()));
        }
        if let Some(previous) = previous.as_ref() {
            if Some(previous.public.total().get()) != u32::try_from(previous.players.len()).ok()
                || previous.public.required() != previous.quorum::<M>()
            {
                return Err(Error::InvalidPreviousOutput);
            }
            if let Some(unknown) = dealers
                .iter()
                .find(|d| previous.players.position(d).is_none())
            {
                return Err(Error::DealerNotInRound(format!("{unknown:?}")));
            }
            if dealers.len() < previous.quorum::<M>() as usize {
                return Err(Error::NumDealers(dealers.len()));
            }
        }
        let summary = {
            let mut transcript = Transcript::new(NAMESPACE, TRANSCRIPT_VERSION);
            transcript
                .commit(namespace)
                .commit(round.encode())
                .commit(previous.encode())
                .commit(dealers.encode())
                .commit(players.encode());

            // Record the selected polynomial evaluation and revealed-share calculations.
            if let Some(modes) = modes![mode, reveal] {
                transcript.commit(modes.encode());
            }
            transcript.summarize()
        };
        Ok(Self {
            summary,
            round,
            previous,
            mode,
            reveal,
            dealers,
            players,
        })
    }

    /// Return the round number for this round.
    ///
    /// Round numbers should increase sequentially.
    pub const fn round(&self) -> u64 {
        self.round
    }
}

#[derive(Clone, Debug)]
pub struct DealerPubMsg<V: Variant> {
    commitment: Poly<V::Public>,
}

impl<V: Variant> PartialEq for DealerPubMsg<V> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment
    }
}

impl<V: Variant> Eq for DealerPubMsg<V> {}

impl<V: Variant> EncodeSize for DealerPubMsg<V> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size()
    }
}

impl<V: Variant> Write for DealerPubMsg<V> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.commitment.write(buf);
    }
}

impl<V: Variant> Read for DealerPubMsg<V> {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &max_size: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            commitment: Read::read_cfg(buf, &(RangeCfg::from(NZU32!(1)..=max_size), ()))?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant> arbitrary::Arbitrary<'_> for DealerPubMsg<V>
where
    V::Public: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let commitment = u.arbitrary()?;
        Ok(Self { commitment })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DealerPrivMsg {
    share: Secret<Scalar>,
}

impl DealerPrivMsg {
    /// Creates a new `DealerPrivMsg` with the given share.
    pub const fn new(share: Scalar) -> Self {
        Self {
            share: Secret::new(share),
        }
    }
}

impl EncodeSize for DealerPrivMsg {
    fn encode_size(&self) -> usize {
        self.share.expose(|share| share.encode_size())
    }
}

impl Write for DealerPrivMsg {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.share.expose(|share| share.write(buf));
    }
}

impl Read for DealerPrivMsg {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self::new(Scalar::read_cfg(
            buf,
            &ScalarReadCfg::RejectZero,
        )?))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for DealerPrivMsg {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary()?))
    }
}

#[derive(Clone, Debug)]
pub struct PlayerAck<P: PublicKey> {
    sig: P::Signature,
}

impl<P: PublicKey> PartialEq for PlayerAck<P> {
    fn eq(&self, other: &Self) -> bool {
        self.sig == other.sig
    }
}

impl<P: PublicKey> EncodeSize for PlayerAck<P> {
    fn encode_size(&self) -> usize {
        self.sig.encode_size()
    }
}

impl<P: PublicKey> Write for PlayerAck<P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.sig.write(buf);
    }
}

impl<P: PublicKey> Read for PlayerAck<P> {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            sig: ReadExt::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey> arbitrary::Arbitrary<'_> for PlayerAck<P>
where
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let sig = u.arbitrary()?;
        Ok(Self { sig })
    }
}

#[derive(Clone, PartialEq)]
enum AckOrReveal<P: PublicKey> {
    Ack(PlayerAck<P>),
    Reveal(DealerPrivMsg),
}

impl<P: PublicKey> AckOrReveal<P> {
    const fn is_reveal(&self) -> bool {
        matches!(*self, Self::Reveal(_))
    }
}

impl<P: PublicKey> std::fmt::Debug for AckOrReveal<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ack(x) => write!(f, "Ack({x:?})"),
            Self::Reveal(_) => write!(f, "Reveal(REDACTED)"),
        }
    }
}

impl<P: PublicKey> EncodeSize for AckOrReveal<P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Ack(x) => x.encode_size(),
            Self::Reveal(x) => x.encode_size(),
        }
    }
}

impl<P: PublicKey> Write for AckOrReveal<P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Ack(x) => {
                0u8.write(buf);
                x.write(buf);
            }
            Self::Reveal(x) => {
                1u8.write(buf);
                x.write(buf);
            }
        }
    }
}

impl<P: PublicKey> Read for AckOrReveal<P> {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Ack(ReadExt::read(buf)?)),
            1 => Ok(Self::Reveal(ReadExt::read(buf)?)),
            x => Err(commonware_codec::Error::InvalidEnum(x)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey> arbitrary::Arbitrary<'_> for AckOrReveal<P>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=1)?;
        match choice {
            0 => {
                let ack = u.arbitrary()?;
                Ok(Self::Ack(ack))
            }
            1 => {
                let reveal = u.arbitrary()?;
                Ok(Self::Reveal(reveal))
            }
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug)]
enum DealerResult<P: PublicKey> {
    Ok(Map<P, AckOrReveal<P>>),
    TooManyReveals,
}

impl<P: PublicKey> PartialEq for DealerResult<P> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ok(x), Self::Ok(y)) => x == y,
            (Self::TooManyReveals, Self::TooManyReveals) => true,
            _ => false,
        }
    }
}

impl<P: PublicKey> EncodeSize for DealerResult<P> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Ok(r) => r.encode_size(),
            Self::TooManyReveals => 0,
        }
    }
}

impl<P: PublicKey> Write for DealerResult<P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::Ok(r) => {
                0u8.write(buf);
                r.write(buf);
            }
            Self::TooManyReveals => {
                1u8.write(buf);
            }
        }
    }
}

impl<P: PublicKey> Read for DealerResult<P> {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &max_players: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Self::Ok(Read::read_cfg(
                buf,
                &(RangeCfg::from(0..=max_players.get() as usize), (), ()),
            )?)),
            1 => Ok(Self::TooManyReveals),
            x => Err(commonware_codec::Error::InvalidEnum(x)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey> arbitrary::Arbitrary<'_> for DealerResult<P>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=1)?;
        match choice {
            0 => {
                use commonware_utils::TryFromIterator;
                use std::collections::HashMap;

                let base: HashMap<P, AckOrReveal<P>> = u.arbitrary()?;
                let map =
                    Map::try_from_iter(base).map_err(|_| arbitrary::Error::IncorrectFormat)?;

                Ok(Self::Ok(map))
            }
            1 => Ok(Self::TooManyReveals),
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DealerLog<V: Variant, P: PublicKey> {
    pub_msg: DealerPubMsg<V>,
    results: DealerResult<P>,
}

impl<V: Variant, P: PublicKey> PartialEq for DealerLog<V, P> {
    fn eq(&self, other: &Self) -> bool {
        self.pub_msg == other.pub_msg && self.results == other.results
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for DealerLog<V, P> {
    fn encode_size(&self) -> usize {
        self.pub_msg.encode_size() + self.results.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for DealerLog<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.pub_msg.write(buf);
        self.results.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for DealerLog<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            pub_msg: Read::read_cfg(buf, cfg)?,
            results: Read::read_cfg(buf, cfg)?,
        })
    }
}

impl<V: Variant, P: PublicKey> DealerLog<V, P> {
    fn get_ack(&self, player: &P) -> Option<&PlayerAck<P>> {
        let DealerResult::Ok(results) = &self.results else {
            return None;
        };
        match results.get_value(player) {
            Some(AckOrReveal::Ack(ack)) => Some(ack),
            _ => None,
        }
    }

    fn get_reveal(&self, player: &P) -> Option<&DealerPrivMsg> {
        let DealerResult::Ok(results) = &self.results else {
            return None;
        };
        match results.get_value(player) {
            Some(AckOrReveal::Reveal(priv_msg)) => Some(priv_msg),
            _ => None,
        }
    }

    fn zip_players<'a, 'b>(
        &'a self,
        players: &'b Set<P>,
    ) -> Result<Option<impl Iterator<Item = (&'b P, &'a AckOrReveal<P>)>>, FaultReason> {
        match &self.results {
            DealerResult::TooManyReveals => Ok(None),
            DealerResult::Ok(results) => {
                // We don't check this on deserialization.
                if results.keys() != players {
                    return Err(FaultReason::MismatchedLogPlayers);
                }
                Ok(Some(players.iter().zip(results.values().iter())))
            }
        }
    }

    /// Return a [`DealerLogSummary`] of the results in this log.
    ///
    /// This can be useful for observing the progress of the DKG.
    pub fn summary(&self) -> DealerLogSummary<P> {
        match &self.results {
            DealerResult::TooManyReveals => DealerLogSummary::TooManyReveals,
            DealerResult::Ok(map) => {
                let (reveals, acks): (Vec<_>, Vec<_>) =
                    map.iter_pairs().partition(|(_, a_r)| a_r.is_reveal());
                DealerLogSummary::Ok {
                    acks: acks
                        .into_iter()
                        .map(|(p, _)| p.clone())
                        .try_collect()
                        .expect("map keys are deduped"),
                    reveals: reveals
                        .into_iter()
                        .map(|(p, _)| p.clone())
                        .try_collect()
                        .expect("map keys are deduped"),
                }
            }
        }
    }
}

/// Information about the reveals and acks in a [`DealerLog`].
// This exists to have a public interface we're happy maintaining, not leaking
// internal details about various things.
#[derive(Clone, Debug)]
pub enum DealerLogSummary<P> {
    /// The dealer is refusing to post any information, because they would have
    /// too many reveals otherwise.
    TooManyReveals,
    /// The dealer has some players who acked, and some players who didn't, that it's revealing.
    Ok { acks: Set<P>, reveals: Set<P> },
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, P: PublicKey> arbitrary::Arbitrary<'_> for DealerLog<V, P>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    V::Public: for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let pub_msg = u.arbitrary()?;
        let results = u.arbitrary()?;
        Ok(Self { pub_msg, results })
    }
}

/// A [`DealerLog`], but identified to and signed by a dealer.
///
/// The [`SignedDealerLog::check`] method allows extracting a public key (the dealer)
/// and a [`DealerLog`] from this struct.
///
/// This avoids having to trust some other party or process for knowing that a
/// dealer actually produced a log.
#[derive(Clone, Debug)]
pub struct SignedDealerLog<V: Variant, S: Signer> {
    dealer: S::PublicKey,
    log: DealerLog<V, S::PublicKey>,
    sig: S::Signature,
}

impl<V: Variant, S: Signer> PartialEq for SignedDealerLog<V, S> {
    fn eq(&self, other: &Self) -> bool {
        self.dealer == other.dealer && self.log == other.log && self.sig == other.sig
    }
}

impl<V: Variant, S: Signer> SignedDealerLog<V, S> {
    fn sign(sk: &S, info: &Info<V, S::PublicKey>, log: DealerLog<V, S::PublicKey>) -> Self {
        let sig = transcript_for_log(info, &log).sign(sk);
        Self {
            dealer: sk.public_key(),
            log,
            sig,
        }
    }

    /// Check this log for a particular round.
    ///
    /// This will produce the public key of the dealer that signed this log,
    /// and the underlying log that they signed.
    ///
    /// This will return [`Option::None`] if the check fails.
    #[allow(clippy::type_complexity)]
    pub fn check(
        self,
        info: &Info<V, S::PublicKey>,
    ) -> Option<(S::PublicKey, DealerLog<V, S::PublicKey>)> {
        if !transcript_for_log(info, &self.log).verify(&self.dealer, &self.sig) {
            return None;
        }
        Some((self.dealer, self.log))
    }
}

impl<V: Variant, S: Signer> EncodeSize for SignedDealerLog<V, S> {
    fn encode_size(&self) -> usize {
        self.dealer.encode_size() + self.log.encode_size() + self.sig.encode_size()
    }
}

impl<V: Variant, S: Signer> Write for SignedDealerLog<V, S> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.dealer.write(buf);
        self.log.write(buf);
        self.sig.write(buf);
    }
}

impl<V: Variant, S: Signer> Read for SignedDealerLog<V, S> {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            dealer: ReadExt::read(buf)?,
            log: Read::read_cfg(buf, cfg)?,
            sig: ReadExt::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<V: Variant, S: Signer> arbitrary::Arbitrary<'_> for SignedDealerLog<V, S>
where
    S::PublicKey: for<'a> arbitrary::Arbitrary<'a>,
    V::Public: for<'a> arbitrary::Arbitrary<'a>,
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let dealer = u.arbitrary()?;
        let log = u.arbitrary()?;
        let sig = u.arbitrary()?;
        Ok(Self { dealer, log, sig })
    }
}

fn transcript_for_round<V: Variant, P: PublicKey>(info: &Info<V, P>) -> Transcript {
    Transcript::resume(info.summary, TRANSCRIPT_VERSION)
}

fn transcript_for_ack<V: Variant, P: PublicKey>(
    transcript: &Transcript,
    dealer: &P,
    pub_msg: &DealerPubMsg<V>,
) -> Transcript {
    let mut out = transcript.fork(SIG_ACK);
    out.commit(dealer.encode());
    out.commit(pub_msg.encode());
    out
}

fn transcript_for_log<V: Variant, P: PublicKey>(
    info: &Info<V, P>,
    log: &DealerLog<V, P>,
) -> Transcript {
    let mut out = transcript_for_round(info).fork(SIG_LOG);
    out.commit(log.encode());
    out
}

/// Accumulates dealer logs for a DKG round and caches verification results so
/// `pre_verify` work can be reused until a dealer's log is replaced.
#[derive(Clone)]
pub struct Logs<V: Variant, P: PublicKey, M: Faults> {
    info: Info<V, P>,
    logs: BTreeMap<P, DealerLog<V, P>>,
    known: BTreeMap<P, Result<DealerLogOutcome, DealerLogError>>,
    phantom_m: PhantomData<M>,
}

// Selected logs stay paired with the round information against which they were validated.
type SelectedLogs<V, P> = (Info<V, P>, Map<P, DealerLog<V, P>>);

impl<V: Variant, P: PublicKey, M: Faults> Logs<V, P, M> {
    /// Create a log set bound to a particular DKG round.
    pub fn new(info: Info<V, P>) -> Self {
        Self {
            info,
            logs: Default::default(),
            known: Default::default(),
            phantom_m: Default::default(),
        }
    }

    fn check_dealers<B: BatchVerifier<PublicKey = P>>(
        rng: &mut impl CryptoRng,
        info: &Info<V, P>,
        strategy: &impl Strategy,
        transcript: &Transcript,
        dealers: &[(&P, &DealerLog<V, P>)],
    ) -> Vec<(P, Result<DealerLogOutcome, DealerLogError>)> {
        let checks: Vec<_> = dealers
            .iter()
            .map(|&(dealer, log)| {
                let seed = Summary::random(&mut *rng);
                ((*dealer).clone(), log, seed)
            })
            .collect();

        // This uses signature batch verification only for a particular dealer's
        // signatures. We could batch across all dealers, but in practice this starts
        // performing worse than just using parallelism with at least 4 threads,
        // and also introduces a slow path if any dealer has a bad sig. This slow
        // path can easily be exercised by an adversary.
        strategy.map_collect_vec(checks, |(dealer, log, seed)| {
            let mut local_rng =
                Transcript::resume(seed, TRANSCRIPT_VERSION).noise(NOISE_PRE_VERIFY);
            let result =
                info.check_dealer_log::<M, B>(&mut local_rng, strategy, transcript, &dealer, log);
            (dealer, result)
        })
    }

    /// Record the log for a particular dealer.
    ///
    /// Return `true` if the dealer was already present in the log, in which
    /// case its log will be replaced.
    ///
    /// This method does not authenticate the log. Faults reported by
    /// [`Failure::InsufficientLogs`] are attributable only when `dealer` and
    /// `log` are the pair returned by [`SignedDealerLog::check`].
    pub fn record(&mut self, dealer: P, log: DealerLog<V, P>) -> bool {
        self.known.remove(&dealer);
        self.logs.insert(dealer, log).is_some()
    }

    /// Verify the logs that we've received so far.
    ///
    /// This makes finalization faster, by doing some of
    /// the verification work now.
    ///
    /// This method can amortize work over a batch of items. It's more efficient
    /// to call it after several [`Self::record`], rather than after
    /// each call.
    pub fn pre_verify<B: BatchVerifier<PublicKey = P>>(
        &mut self,
        rng: &mut impl CryptoRng,
        strategy: &impl Strategy,
    ) {
        let required_commitments = self.info.required_commitments::<M>() as usize;
        let transcript = transcript_for_round(&self.info);

        // Create a pending batch, which we try and optimistically size as small as
        // possible, to avoid verifying more dealers than we need, if they're all
        // honest.
        let mut need = required_commitments;
        let mut pending = Vec::new();
        let mut iter = self.logs.iter();
        while need > 0 {
            let Some((dealer, log)) = iter.next() else {
                break;
            };
            match self.known.get(dealer) {
                Some(Ok(DealerLogOutcome::Available)) => need -= 1,
                Some(_) => {}
                None => {
                    need -= 1;
                    pending.push((dealer, log));
                }
            }
        }

        // Verify the batch and update the known usable dealers.
        let pending_results =
            Self::check_dealers::<B>(rng, &self.info, strategy, &transcript, &pending);
        let mut all_pending_usable = true;
        for (dealer, result) in pending_results {
            let is_usable = matches!(result, Ok(DealerLogOutcome::Available));
            self.known.insert(dealer, result);
            all_pending_usable &= is_usable;
        }
        if all_pending_usable {
            return;
        }

        // We could jump back to the start of the function to recalculate the minimal pending set,
        // hoping that they would all be valid again. However, in this case, we're
        // dealing with some dealers that are malicious, and they might be trying to
        // slow down verification as much as possible by making us waste our time with
        // undue optimism. We instead adopt a pessimistic approach, assuming the
        // worst: that we might need to check all of the remaining dealers
        // to find the honest ones we need.
        let remaining: Vec<_> = iter
            .filter(|(dealer, _)| !self.known.contains_key(*dealer))
            .collect();
        let results = Self::check_dealers::<B>(rng, &self.info, strategy, &transcript, &remaining);
        for (dealer, result) in results {
            self.known.insert(dealer, result);
        }
    }

    /// Given the logs we've received, determine which dealer logs to use, if any.
    ///
    /// This might return an error if there are not enough good logs that we can use.
    fn select<B: BatchVerifier<PublicKey = P>>(
        mut self,
        rng: &mut impl CryptoRng,
        strategy: &impl Strategy,
    ) -> Result<SelectedLogs<V, P>, Failure<P>> {
        self.pre_verify::<B>(rng, strategy);
        let required = self.info.required_commitments::<M>();
        let required_count =
            usize::try_from(required).expect("required commitments exceed usize::MAX");
        let out: Map<_, _> = self
            .logs
            .into_iter()
            .filter(|(dealer, _)| {
                matches!(
                    self.known.get(dealer),
                    Some(Ok(DealerLogOutcome::Available))
                )
            })
            .take(required_count)
            .try_collect()
            .expect("dealers should be unique");
        let found = u32::try_from(out.len()).expect("valid dealer count exceeds u32::MAX");
        if found < required {
            let unavailable =
                self.info
                    .dealers
                    .iter()
                    .filter(|dealer| match self.known.get(*dealer) {
                        None
                        | Some(Ok(DealerLogOutcome::Unavailable))
                        | Some(Err(DealerLogError::UnexpectedDealer)) => true,
                        Some(Ok(DealerLogOutcome::Available))
                        | Some(Err(DealerLogError::Fault(_))) => false,
                    })
                    .cloned()
                    .try_collect::<Set<_>>()
                    .expect("configured dealers are unique");
            let faults = self
                .known
                .into_iter()
                .filter_map(|(dealer, result)| match result {
                    Err(DealerLogError::Fault(fault)) => Some((dealer, fault)),
                    Ok(DealerLogOutcome::Available | DealerLogOutcome::Unavailable)
                    | Err(DealerLogError::UnexpectedDealer) => None,
                })
                .try_collect::<Map<_, _>>()
                .expect("checked dealers are unique");
            return Err(Failure::InsufficientLogs {
                required,
                found,
                faults,
                unavailable,
            });
        }
        Ok((self.info, out))
    }
}

pub struct Dealer<V: Variant, S: Signer> {
    me: S,
    info: Info<V, S::PublicKey>,
    pub_msg: DealerPubMsg<V>,
    results: Map<S::PublicKey, AckOrReveal<S::PublicKey>>,
    transcript: Transcript,
}

impl<V: Variant, S: Signer> Dealer<V, S> {
    /// Create a [`Dealer`].
    ///
    /// This needs randomness, to generate a dealing.
    ///
    /// We also need the dealer's private key, in order to produce the [`SignedDealerLog`].
    ///
    /// If we're doing a reshare, the dealer should have a share from the previous round.
    ///
    /// This will produce the [`Dealer`], a [`DealerPubMsg`] to send to every player,
    /// and a list of [`DealerPrivMsg`]s, along with which players those need to
    /// be sent to.
    ///
    /// The public message can be sent in the clear, but it's important that players
    /// know which dealer sent what public message. You MUST ensure that dealers
    /// cannot impersonate each-other when sending this message.
    ///
    /// The private message MUST be sent encrypted (or, in some other way, privately)
    /// to the target player. Similarly, that player MUST be convinced that this dealer
    /// sent it that message, without any possibility of impersonation. A simple way
    /// to provide both guarantees is through an authenticated channel, e.g. via
    /// [crate::handshake], or [commonware-p2p](https://docs.rs/commonware-p2p/latest/commonware_p2p/).
    #[allow(clippy::type_complexity)]
    pub fn start<M: Faults>(
        mut rng: impl CryptoRng,
        info: Info<V, S::PublicKey>,
        me: S,
        share: Option<Share>,
    ) -> Result<(Self, DealerPubMsg<V>, Vec<(S::PublicKey, DealerPrivMsg)>), Error> {
        // Check that this dealer is defined in the round.
        info.dealer_index(&me.public_key())
            .ok_or_else(|| Error::DealerNotInRound(format!("{:?}", me.public_key())))?;
        let share = info.unwrap_or_random_share(
            &mut rng,
            // We are extracting the private scalar from `Secret` protection because
            // `Poly::new_with_constant` requires an owned value. The extracted scalar is
            // scoped to this function and will be zeroized on drop (i.e. the secret is
            // only exposed for the duration of this function).
            share.map(|x| x.private.expose_unwrap()),
        )?;
        let my_poly = Poly::new_with_constant(&mut rng, info.degree::<M>(), share);
        let priv_msgs = info
            .players
            .iter()
            .map(|pk| {
                (
                    pk.clone(),
                    DealerPrivMsg::new(my_poly.eval_msm(
                        &info.player_scalar(pk).expect("player should exist"),
                        &Sequential,
                    )),
                )
            })
            .collect::<Vec<_>>();
        let results: Map<_, _> = priv_msgs
            .clone()
            .into_iter()
            .map(|(pk, priv_msg)| (pk, AckOrReveal::Reveal(priv_msg)))
            .try_collect()
            .expect("players are unique");
        let commitment = Poly::commit(my_poly);
        let pub_msg = DealerPubMsg { commitment };
        let transcript = {
            let t = transcript_for_round(&info);
            transcript_for_ack(&t, &me.public_key(), &pub_msg)
        };
        let this = Self {
            me,
            info,
            pub_msg: pub_msg.clone(),
            results,
            transcript,
        };
        Ok((this, pub_msg, priv_msgs))
    }

    /// Process an acknowledgement from a player.
    ///
    /// Acknowledgements should really only be processed once per player,
    /// but this method is idempotent nonetheless.
    ///
    /// A rejection is not attributed to `player`: a signature mismatch can also
    /// arise when a dealer equivocates and the player acknowledges a different
    /// public message.
    pub fn receive_player_ack(
        &mut self,
        player: S::PublicKey,
        ack: PlayerAck<S::PublicKey>,
    ) -> Result<(), PlayerAckError> {
        let Some(res_mut) = self.results.get_value_mut(&player) else {
            return Err(PlayerAckError::UnexpectedPlayer);
        };
        if !self.transcript.verify(&player, &ack.sig) {
            return Err(PlayerAckError::InvalidAck);
        }
        *res_mut = AckOrReveal::Ack(ack);
        Ok(())
    }

    /// Finalize the dealer, producing a signed log.
    ///
    /// This should be called at the point where no more acks will be processed.
    pub fn finalize<M: Faults>(self) -> SignedDealerLog<V, S> {
        let reveals = self
            .results
            .values()
            .iter()
            .filter(|x| x.is_reveal())
            .count() as u32;
        // Omit results if there are too many reveals.
        let results = if reveals > self.info.max_reveals::<M>() {
            DealerResult::TooManyReveals
        } else {
            DealerResult::Ok(self.results)
        };
        let log = DealerLog {
            pub_msg: self.pub_msg,
            results,
        };
        SignedDealerLog::sign(&self.me, &self.info, log)
    }
}

struct Observe<V: Variant, P: PublicKey> {
    output: Output<V, P>,
    weights: Option<Interpolator<P, Scalar>>,
}

impl<V: Variant, P: PublicKey> Observe<V, P> {
    fn reckon<M: Faults>(
        info: Info<V, P>,
        selected: Map<P, DealerLog<V, P>>,
        strategy: &impl Strategy,
    ) -> Self {
        // Logs::select validated the shape of each selected log. Track player
        // shares reconstructible from their dealer reveals.
        let reveal_threshold = info.reveal_threshold::<M>();
        let mut reveal_counts: BTreeMap<P, u32> = BTreeMap::new();
        let mut revealed = Vec::new();
        for log in selected.values() {
            let iter = log
                .zip_players(&info.players)
                .expect("selected dealer log should match the round's players")
                .expect("selected dealer log should contain usable results");
            for (player, result) in iter {
                if !result.is_reveal() {
                    continue;
                }
                let count = reveal_counts.entry(player.clone()).or_insert(0);
                *count += 1;
                if *count == reveal_threshold {
                    revealed.push(player.clone());
                }
            }
        }
        let revealed: Set<P> = revealed
            .into_iter()
            .try_collect()
            .expect("players are unique");

        // Extract dealers before consuming selected
        let dealers: Set<P> = selected
            .keys()
            .iter()
            .cloned()
            .try_collect()
            .expect("selected dealers are unique");

        // Recover the public polynomial
        let (public, weights) = if let Some(previous) = info.previous.as_ref() {
            let weights = previous
                .public()
                .mode()
                .subset_interpolator(previous.players(), selected.keys())
                .expect("the result of select should produce a valid subset");
            let commitments = selected
                .into_iter()
                .map(|(dealer, log)| (dealer, log.pub_msg.commitment))
                .try_collect::<Map<_, _>>()
                .expect("Map should have unique keys");
            let public = weights
                .interpolate(&commitments, strategy)
                .expect("select checks that enough points have been provided");

            // Public-message validation binds each commitment's constant term to the dealer's
            // previous public share, so interpolating a valid subset must preserve the public key.
            assert_eq!(
                previous.public().public(),
                public.constant(),
                "selected reshare commitments must preserve the previous public key",
            );
            (public, Some(weights))
        } else {
            let mut public = Poly::zero();
            for log in selected.values() {
                public += &log.pub_msg.commitment;
            }
            (public, None)
        };
        let n = info.players.len() as u32;
        let output = Output {
            summary: info.summary,
            public: Sharing::new(info.mode, NZU32!(n), public),
            dealers,
            players: info.players,
            revealed,
        };
        Self { output, weights }
    }
}

/// Observe the result of a DKG, using the public results.
///
/// The log mapping dealers to their log is the shared piece of information
/// that the participants (players, observers) of the DKG must all agree on.
///
/// From this log, we can (potentially, as the DKG can fail) compute the public output.
///
/// Returns [`Failure::InsufficientLogs`] if too few usable dealer logs remain.
pub fn observe<V: Variant, P: PublicKey, M: Faults, B: BatchVerifier<PublicKey = P>>(
    rng: &mut impl CryptoRng,
    logs: Logs<V, P, M>,
    strategy: &impl Strategy,
) -> Result<Output<V, P>, Failure<P>> {
    let (info, selected) = logs.select::<B>(rng, strategy)?;
    Ok(Observe::<V, P>::reckon::<M>(info, selected, strategy).output)
}

/// Represents a player in the DKG / reshare process.
///
/// The player is attempting to get a share of the key.
///
/// They need not have participated in prior rounds.
pub struct Player<V: Variant, S: Signer> {
    me: S,
    me_pub: S::PublicKey,
    info: Info<V, S::PublicKey>,
    index: Participant,
    transcript: Transcript,
    view: BTreeMap<S::PublicKey, (DealerPubMsg<V>, DealerPrivMsg)>,
}

impl<V: Variant, S: Signer> Player<V, S> {
    /// Create a new [`Player`].
    ///
    /// We need the player's private key in order to sign messages.
    pub fn new(info: Info<V, S::PublicKey>, me: S) -> Result<Self, Error> {
        let me_pub = me.public_key();
        Ok(Self {
            index: info.player_index(&me_pub).ok_or(Error::PlayerNotInRound)?,
            me,
            me_pub,
            transcript: transcript_for_round(&info),
            info,
            view: BTreeMap::new(),
        })
    }

    /// Resume a [`Player`], given some existing public state.
    ///
    /// This is equivalent to calling [`Self::new`] and then [`Self::dealer_message`]
    /// with the appropriate messages, but includes extra safeguards to detect
    /// missing / corrupted state.
    ///
    /// It's imperative that the `logs` passed in have been verified. This is done
    /// naturally when converting from a [`SignedDealerLog`] to a [`DealerLog`],
    /// but this function, like [`Player::finalize`], assumes that this check has
    /// been done.
    ///
    /// All messages the player should have received must be passed into this method,
    /// and if any messages which should be present based on this player's actions
    /// in the log are missing, this method will return [`Error::MissingPlayerDealing`].
    ///
    /// For example, if no private message from a dealer is present in `msgs`, but
    /// we've already acknowledged one, and this has been included in a public log,
    /// then this method will fail.
    ///
    /// This method cannot catch all cases where state has been corrupted. In
    /// particular, if a dealer has not posted their log publicly yet, but has
    /// already received an ack, then this method cannot help in that case,
    /// but the issue still remains.
    ///
    /// The returned map contains the acknowledgements generated while replaying
    /// `msgs`, keyed by dealer. Invalid replayed messages return
    /// [`Error::InvalidPersistedDealing`], because `msgs` is caller-supplied
    /// persisted state rather than a live authenticated channel.
    #[allow(clippy::type_complexity)]
    pub fn resume<M: Faults>(
        info: Info<V, S::PublicKey>,
        me: S,
        logs: &BTreeMap<S::PublicKey, DealerLog<V, S::PublicKey>>,
        msgs: impl IntoIterator<Item = (S::PublicKey, DealerPubMsg<V>, DealerPrivMsg)>,
    ) -> Result<(Self, BTreeMap<S::PublicKey, PlayerAck<S::PublicKey>>), Error> {
        // Record all acks we've emitted (by dealer).
        let mut this = Self::new(info, me)?;
        let mut acks = BTreeMap::new();
        for (dealer, pub_msg, priv_msg) in msgs {
            match this.dealer_message::<M>(dealer.clone(), pub_msg, priv_msg) {
                Ok(Some(ack)) => {
                    acks.insert(dealer, ack);
                }
                Ok(None) => {}
                Err(_) => {
                    return Err(Error::InvalidPersistedDealing {
                        dealer: format!("{dealer:?}"),
                    });
                }
            }
        }

        // Have we emitted any valid acks, publicly recorded, for which we do
        // not have a private message from the dealer?
        if logs.iter().any(|(dealer, log)| {
            let Some(ack) = log.get_ack(&this.me_pub) else {
                return false;
            };
            // Only trust this ack if the signature is valid for this round.
            transcript_for_ack(&this.transcript, dealer, &log.pub_msg)
                .verify(&this.me_pub, &ack.sig)
                && !this.view.contains_key(dealer)
        }) {
            // If so, we have a problem, because we're missing a dealing that we're
            // supposed to have, and that we publicly committed to having.
            return Err(Error::MissingPlayerDealing);
        }

        Ok((this, acks))
    }

    /// Process a message from a dealer.
    ///
    /// It's important that nobody can impersonate the dealer, and that the
    /// private message was not exposed to anyone else. A convenient way to
    /// provide this is by using an authenticated channel, e.g. via
    /// [crate::handshake], or [commonware-p2p](https://docs.rs/commonware-p2p/latest/commonware_p2p/).
    ///
    /// Returns [`DealerMessageError`] if the message is invalid, `Ok(None)` if a
    /// message from this dealer was already processed, and `Ok(Some(_))` with
    /// the acknowledgement otherwise. The error carries no attribution. A
    /// transport-aware caller can apply its own attribution policy to `dealer`.
    pub fn dealer_message<M: Faults>(
        &mut self,
        dealer: S::PublicKey,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) -> Result<Option<PlayerAck<S::PublicKey>>, DealerMessageError> {
        if self.view.contains_key(&dealer) {
            return Ok(None);
        }
        if self.info.dealer_index(&dealer).is_none() {
            return Err(DealerMessageError::UnexpectedDealer);
        }
        self.info
            .check_dealer_pub_msg::<M>(&dealer, &pub_msg)
            .map_err(DealerMessageError::from)?;
        if !self
            .info
            .check_dealer_priv_msg(self.index, &pub_msg, &priv_msg)
        {
            return Err(DealerMessageError::InvalidDealerShare);
        }
        let sig = transcript_for_ack(&self.transcript, &dealer, &pub_msg).sign(&self.me);
        self.view.insert(dealer, (pub_msg, priv_msg));
        Ok(Some(PlayerAck { sig }))
    }

    /// Finalize the player, producing an output, and a share.
    ///
    /// This should agree with [`observe`], in terms of `Ok` vs `Err` (with one exception)
    /// and the public output, so long as the logs agree. It's crucial that the players
    /// come to agreement, in some way, on exactly which logs they need to use
    /// for finalize.
    ///
    /// The exception is that if this function returns [`FinalizeError::Error`]
    /// containing [`Error::MissingPlayerDealing`] or
    /// [`Error::InvalidPersistedDealing`], then [`observe`] will return `Ok`,
    /// because these errors indicate that this player's state has been corrupted,
    /// but the DKG has otherwise succeeded. However, this player's share is not
    /// recoverable without external intervention.
    ///
    /// Otherwise, this function returns [`FinalizeError::Failure`] if the agreed
    /// dealer logs cannot produce a DKG output, or
    /// [`FinalizeError::Error`] containing [`Error::MismatchedLogs`] if `logs` are
    /// bound to a different DKG round.
    #[allow(clippy::type_complexity)]
    pub fn finalize<M: Faults, B: BatchVerifier<PublicKey = S::PublicKey>>(
        self,
        rng: &mut impl CryptoRng,
        logs: Logs<V, S::PublicKey, M>,
        strategy: &impl Strategy,
    ) -> Result<(Output<V, S::PublicKey>, Share), FinalizeError<S::PublicKey>> {
        if logs.info != self.info {
            return Err(Error::MismatchedLogs.into());
        }
        let (_, selected) = logs.select::<B>(rng, strategy)?;

        // We are extracting the private scalars from `Secret` protection
        // because interpolation/summation needs owned scalars for polynomial
        // arithmetic. The extracted scalars are scoped to this function and
        // will be zeroized on drop (i.e. the secrets are only exposed for the
        // duration of this function).
        let dealings = selected
            .iter_pairs()
            .map(|(dealer, log)| {
                // A selected ack carries no share and requires the exact persisted
                // dealing. A validated reveal can replace missing or stale local state.
                let persisted = self.view.get(dealer);
                let share = match persisted {
                    Some((pub_msg, priv_msg)) if pub_msg == &log.pub_msg => {
                        priv_msg.share.clone().expose_unwrap()
                    }
                    _ => match log.get_reveal(&self.me_pub) {
                        Some(priv_msg) => priv_msg.share.clone().expose_unwrap(),
                        None if persisted.is_some() => {
                            return Err(Error::InvalidPersistedDealing {
                                dealer: format!("{dealer:?}"),
                            });
                        }
                        None => return Err(Error::MissingPlayerDealing),
                    },
                };
                Ok((dealer.clone(), share))
            })
            .collect::<Result<Vec<_>, Error>>()?
            .into_iter()
            .try_collect::<Map<_, _>>()
            .expect("Logs::select produces at most one entry per dealer");
        let Observe { output, weights } =
            Observe::<V, S::PublicKey>::reckon::<M>(self.info, selected, strategy);
        let private = weights.map_or_else(
            || {
                let mut out = <Scalar as Additive>::zero();
                for s in dealings.values() {
                    out += s;
                }
                out
            },
            |weights| {
                weights
                    .interpolate(&dealings, strategy)
                    .expect("Logs::select ensures that we can recover")
            },
        );
        let share = Share::new(self.index, Private::new(private));
        Ok((output, share))
    }
}

/// The result of dealing shares to players.
pub type DealResult<V, P> = Result<(Output<V, P>, Map<P, Share>), Error>;

/// Simply distribute shares at random, instead of performing a distributed protocol.
pub fn deal<V: Variant, P: Clone + Ord, M: Faults>(
    mut rng: impl CryptoRng,
    mode: Mode,
    players: Set<P>,
) -> DealResult<V, P> {
    if players.is_empty() {
        return Err(Error::NumPlayers(0));
    }
    let n = NZU32!(players.len() as u32);
    let t = players.quorum::<M>();
    let private = Poly::new(&mut rng, t - 1);
    let shares: Map<_, _> = players
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let participant = Participant::from_usize(i);
            let eval = private.eval_msm(
                &mode
                    .scalar(n, participant)
                    .expect("player index should be valid"),
                &Sequential,
            );
            let share = Share::new(participant, Private::new(eval));
            (p.clone(), share)
        })
        .try_collect()
        .expect("players are unique");
    let output = Output {
        summary: Summary::random(&mut rng),
        public: Sharing::new(mode, n, Poly::commit(private)),
        dealers: players.clone(),
        players,
        revealed: Set::default(),
    };
    Ok((output, shares))
}

/// Like [`deal`], but without linking the result to specific public keys.
///
/// This can be more convenient for testing, where you don't want to go through
/// the trouble of generating signing keys. The downside is that the result isn't
/// compatible with subsequent DKGs, which need an [`Output`].
pub fn deal_anonymous<V: Variant, M: Faults>(
    rng: impl CryptoRng,
    mode: Mode,
    n: NonZeroU32,
) -> (Sharing<V>, Vec<Share>) {
    let players = (0..n.get()).try_collect().unwrap();
    let (output, shares) = deal::<V, _, M>(rng, mode, players).unwrap();
    (output.public().clone(), shares.values().to_vec())
}

#[cfg(any(feature = "arbitrary", test))]
mod test_plan {
    use super::*;
    use crate::{
        PublicKey,
        bls12381::primitives::{
            ops::{self, threshold},
            variant::Variant,
        },
        ed25519,
    };
    use anyhow::anyhow;
    use bytes::BytesMut;
    use commonware_utils::{Faults, N3f1, TestRng, TryCollect};
    use core::num::NonZeroI32;
    use std::collections::BTreeSet;

    /// Apply a mask to some bytes, returning whether or not a modification happened
    fn apply_mask(bytes: &mut BytesMut, mask: &[u8]) -> bool {
        let mut modified = false;
        for (l, &r) in bytes.iter_mut().zip(mask.iter()) {
            modified |= r != 0;
            *l ^= r;
        }
        modified
    }

    #[derive(Clone, Default, Debug)]
    pub struct Masks {
        pub info_summary: Vec<u8>,
        pub dealer: Vec<u8>,
        pub pub_msg: Vec<u8>,
        pub log: Vec<u8>,
    }

    impl Masks {
        fn modifies_player_ack(&self) -> bool {
            self.info_summary.iter().any(|&b| b != 0)
                || self.dealer.iter().any(|&b| b != 0)
                || self.pub_msg.iter().any(|&b| b != 0)
        }

        fn transcript_for_round<V: Variant, P: PublicKey>(
            &self,
            info: &Info<V, P>,
        ) -> anyhow::Result<(bool, Transcript)> {
            let mut summary_bs = info.summary.encode_mut();
            let modified = apply_mask(&mut summary_bs, &self.info_summary);
            let summary = Summary::read(&mut summary_bs)?;
            Ok((modified, Transcript::resume(summary, TRANSCRIPT_VERSION)))
        }

        fn transcript_for_player_ack<V: Variant, P: PublicKey>(
            &self,
            info: &Info<V, P>,
            dealer: &P,
            pub_msg: &DealerPubMsg<V>,
        ) -> anyhow::Result<(bool, Transcript)> {
            let (mut modified, transcript) = self.transcript_for_round(info)?;
            let mut transcript = transcript.fork(SIG_ACK);

            let mut dealer_bs = dealer.encode_mut();
            modified |= apply_mask(&mut dealer_bs, &self.dealer);
            transcript.commit(&mut dealer_bs);

            let mut pub_msg_bs = pub_msg.encode_mut();
            modified |= apply_mask(&mut pub_msg_bs, &self.pub_msg);
            transcript.commit(&mut pub_msg_bs);

            Ok((modified, transcript))
        }

        fn transcript_for_signed_dealer_log<V: Variant, P: PublicKey>(
            &self,
            info: &Info<V, P>,
            log: &DealerLog<V, P>,
        ) -> anyhow::Result<(bool, Transcript)> {
            let (mut modified, transcript) = self.transcript_for_round(info)?;
            let mut transcript = transcript.fork(SIG_LOG);

            let mut log_bs = log.encode_mut();
            modified |= apply_mask(&mut log_bs, &self.log);
            transcript.commit(&mut log_bs);

            Ok((modified, transcript))
        }
    }

    /// A round in the DKG test plan.
    #[derive(Debug, Default)]
    pub struct Round {
        dealers: Vec<u32>,
        players: Vec<u32>,
        crash_resume_players: BTreeSet<(u32, u32)>,
        resume_missing_dealer_msg_fails: BTreeSet<(u32, u32)>,
        finalize_missing_dealer_msg_fails: BTreeSet<u32>,
        no_acks: BTreeSet<(u32, u32)>,
        bad_shares: BTreeSet<(u32, u32)>,
        bad_player_sigs: BTreeMap<(u32, u32), Masks>,
        bad_reveals: BTreeSet<(u32, u32)>,
        bad_dealer_sigs: BTreeMap<u32, Masks>,
        replace_shares: BTreeSet<u32>,
        shift_degrees: BTreeMap<u32, NonZeroI32>,
    }

    impl Round {
        pub fn new(dealers: Vec<u32>, players: Vec<u32>) -> Self {
            Self {
                dealers,
                players,
                ..Default::default()
            }
        }

        pub fn no_ack(mut self, dealer: u32, player: u32) -> Self {
            self.no_acks.insert((dealer, player));
            self
        }

        pub fn crash_resume_player(mut self, after_dealer: u32, player: u32) -> Self {
            self.crash_resume_players.insert((after_dealer, player));
            self
        }

        pub fn resume_missing_dealer_msg_fails(
            mut self,
            after_dealer: u32,
            missing_dealer: u32,
        ) -> Self {
            self.resume_missing_dealer_msg_fails
                .insert((after_dealer, missing_dealer));
            self
        }

        pub fn finalize_missing_dealer_msg_fails(mut self, player: u32) -> Self {
            self.finalize_missing_dealer_msg_fails.insert(player);
            self
        }

        pub fn bad_share(mut self, dealer: u32, player: u32) -> Self {
            self.bad_shares.insert((dealer, player));
            self
        }

        pub fn bad_player_sig(mut self, dealer: u32, player: u32, masks: Masks) -> Self {
            self.bad_player_sigs.insert((dealer, player), masks);
            self
        }

        pub fn bad_reveal(mut self, dealer: u32, player: u32) -> Self {
            self.bad_reveals.insert((dealer, player));
            self
        }

        pub fn bad_dealer_sig(mut self, dealer: u32, masks: Masks) -> Self {
            self.bad_dealer_sigs.insert(dealer, masks);
            self
        }

        pub fn replace_share(mut self, dealer: u32) -> Self {
            self.replace_shares.insert(dealer);
            self
        }

        pub fn shift_degree(mut self, dealer: u32, shift: NonZeroI32) -> Self {
            self.shift_degrees.insert(dealer, shift);
            self
        }

        /// Validate that this round is well-formed given the number of participants
        /// and the previous successful round's players.
        pub fn validate(
            &self,
            num_participants: u32,
            previous_players: Option<&[u32]>,
        ) -> anyhow::Result<()> {
            if self.dealers.is_empty() {
                return Err(anyhow!("dealers is empty"));
            }
            if self.players.is_empty() {
                return Err(anyhow!("players is empty"));
            }
            // Check dealer/player ranges
            for &d in &self.dealers {
                if d >= num_participants {
                    return Err(anyhow!("dealer {d} out of range [1, {num_participants}]"));
                }
            }
            for &p in &self.players {
                if p >= num_participants {
                    return Err(anyhow!("player {p} out of range [1, {num_participants}]"));
                }
            }
            // Crash/resume checkpoints must reference in-round dealers/players.
            for &(after_dealer, player) in &self.crash_resume_players {
                if !self.dealers.contains(&after_dealer) {
                    return Err(anyhow!("crash_resume dealer {after_dealer} not in round"));
                }
                if !self.players.contains(&player) {
                    return Err(anyhow!("crash_resume player {player} not in round"));
                }
            }
            let dealer_positions: BTreeMap<u32, usize> = self
                .dealers
                .iter()
                .enumerate()
                .map(|(idx, &dealer)| (dealer, idx))
                .collect();
            let previous_successful_round = previous_players.is_some();
            for &(after_dealer, missing_dealer) in &self.resume_missing_dealer_msg_fails {
                if !self.dealers.contains(&after_dealer) {
                    return Err(anyhow!("resume_missing dealer {after_dealer} not in round"));
                }
                if !self.dealers.contains(&missing_dealer) {
                    return Err(anyhow!(
                        "resume_missing missing_dealer {missing_dealer} not in round"
                    ));
                }
                let after_pos = dealer_positions[&after_dealer];
                let missing_pos = dealer_positions[&missing_dealer];
                if missing_pos > after_pos {
                    return Err(anyhow!(
                        "resume_missing missing_dealer {missing_dealer} appears after {after_dealer}"
                    ));
                }
                if self.bad(previous_successful_round, missing_dealer) {
                    return Err(anyhow!(
                        "resume_missing_dealer_msg_fails requires dealer {missing_dealer} to be good"
                    ));
                }
                let any_valid_ack = self.players.iter().any(|&player| {
                    let ack_corrupted = self.no_acks.contains(&(missing_dealer, player))
                        || self.bad_shares.contains(&(missing_dealer, player))
                        || self
                            .bad_player_sigs
                            .get(&(missing_dealer, player))
                            .is_some_and(Masks::modifies_player_ack);
                    !ack_corrupted
                });
                if !any_valid_ack {
                    return Err(anyhow!(
                        "resume_missing_dealer_msg_fails requires dealer {missing_dealer} to ack at least one player"
                    ));
                }
            }
            for &player in &self.finalize_missing_dealer_msg_fails {
                if !self.players.contains(&player) {
                    return Err(anyhow!("finalize_missing player {player} not in round"));
                }
            }

            // If there's a previous round, check dealer constraints
            if let Some(prev_players) = previous_players {
                // Every dealer must have been a player in the previous round
                for &d in &self.dealers {
                    if !prev_players.contains(&d) {
                        return Err(anyhow!("dealer {d} was not a player in previous round"));
                    }
                }
                // Must have >= quorum(prev_players) dealers
                let required = N3f1::quorum(prev_players.len());
                if (self.dealers.len() as u32) < required {
                    return Err(anyhow!(
                        "not enough dealers: have {}, need {} (quorum of {} previous players)",
                        self.dealers.len(),
                        required,
                        prev_players.len()
                    ));
                }
            }

            Ok(())
        }

        fn bad(&self, previous_successful_round: bool, dealer: u32) -> bool {
            if self.replace_shares.contains(&dealer) && previous_successful_round {
                return true;
            }
            if let Some(shift) = self.shift_degrees.get(&dealer) {
                let degree = N3f1::quorum(self.players.len()) as i32 - 1;
                // We shift the degree, but saturate at 0, so it's possible
                // that the shift isn't actually doing anything.
                //
                // This is effectively the same as checking degree == 0 && shift < 0,
                // but matches what ends up happening a bit better.
                if (degree + shift.get()).max(0) != degree {
                    return true;
                }
            }
            if self.bad_reveals.iter().any(|&(d, _)| d == dealer) {
                return true;
            }
            let revealed_players = self
                .bad_shares
                .iter()
                .copied()
                .chain(self.no_acks.iter().copied())
                .filter_map(|(d, p)| if d == dealer { Some(p) } else { None })
                .collect::<BTreeSet<_>>();
            revealed_players.len() as u32 > N3f1::max_faults(self.players.len())
        }

        /// Determine if this round is expected to fail.
        fn expect_failure(&self, previous_successful_round: Option<u32>) -> bool {
            let good_dealer_count = self
                .dealers
                .iter()
                .filter(|&&d| !self.bad(previous_successful_round.is_some(), d))
                .count();
            let required = previous_successful_round
                .map(N3f1::quorum)
                .unwrap_or_default()
                .max(N3f1::quorum(self.dealers.len())) as usize;
            good_dealer_count < required
        }
    }

    /// A DKG test plan consisting of multiple rounds.
    #[derive(Debug)]
    pub struct Plan {
        num_participants: NonZeroU32,
        rounds: Vec<Round>,
    }

    impl Plan {
        pub const fn new(num_participants: NonZeroU32) -> Self {
            Self {
                num_participants,
                rounds: Vec::new(),
            }
        }

        pub fn with(mut self, round: Round) -> Self {
            self.rounds.push(round);
            self
        }

        /// Validate the entire plan.
        pub(crate) fn validate(&self) -> anyhow::Result<()> {
            let mut last_successful_players: Option<Vec<u32>> = None;

            for round in &self.rounds {
                round.validate(
                    self.num_participants.get(),
                    last_successful_players.as_deref(),
                )?;

                // If this round is expected to succeed, update last_successful_players
                if !round.expect_failure(last_successful_players.as_ref().map(|x| x.len() as u32)) {
                    last_successful_players = Some(round.players.clone());
                }
            }
            Ok(())
        }

        /// Run the test plan with a given seed.
        pub fn run<V: Variant>(self, seed: u64) -> anyhow::Result<()> {
            self.validate()?;

            let mut rng = TestRng::new(seed);

            // Generate keys for all participants (1-indexed to num_participants)
            let keys = (0..self.num_participants.get())
                .map(|_| ed25519::PrivateKey::random(&mut rng))
                .collect::<Vec<_>>();

            // Precompute mapping from public key to key index to avoid confusion
            // between key indices and positions in sorted Sets.
            let pk_to_key_idx: BTreeMap<ed25519::PublicKey, u32> = keys
                .iter()
                .enumerate()
                .map(|(i, k)| (k.public_key(), i as u32))
                .collect();

            // The max_read_size needs to account for shifted polynomial degrees.
            // Find the maximum positive shift across all rounds.
            let max_shift = self
                .rounds
                .iter()
                .flat_map(|r| r.shift_degrees.values())
                .map(|s| s.get())
                .max()
                .unwrap_or(0)
                .max(0) as u32;
            let max_read_size =
                NonZeroU32::new(self.num_participants.get() + max_shift).expect("non-zero");

            let mut previous_output: Option<Output<V, ed25519::PublicKey>> = None;
            let mut shares: BTreeMap<ed25519::PublicKey, Share> = BTreeMap::new();
            let mut threshold_public_key: Option<V::Public> = None;

            for (i_round, round) in self.rounds.into_iter().enumerate() {
                let previous_successful_round =
                    previous_output.as_ref().map(|o| o.players.len() as u32);

                let dealer_set = round
                    .dealers
                    .iter()
                    .map(|&i| keys[i as usize].public_key())
                    .try_collect::<Set<_>>()
                    .unwrap();
                let player_set: Set<ed25519::PublicKey> = round
                    .players
                    .iter()
                    .map(|&i| keys[i as usize].public_key())
                    .try_collect()
                    .unwrap();

                // Create round info
                let info = Info::new::<N3f1>(
                    b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_TEST",
                    i_round as u64,
                    previous_output.clone(),
                    Mode::NonZeroCounter,
                    Reveal::V1,
                    dealer_set.clone(),
                    player_set.clone(),
                )?;

                let mut players: Map<_, _> = round
                    .players
                    .iter()
                    .map(|&i| {
                        let sk = keys[i as usize].clone();
                        let pk = sk.public_key();
                        let player = Player::new(info.clone(), sk)?;
                        Ok((pk, player))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?
                    .try_into()
                    .unwrap();
                let mut acked_dealings: BTreeMap<
                    ed25519::PublicKey,
                    Vec<(ed25519::PublicKey, DealerPubMsg<V>, DealerPrivMsg)>,
                > = player_set
                    .iter()
                    .cloned()
                    .map(|pk| (pk, Vec::new()))
                    .collect();
                let mut crash_resume_by_dealer: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
                for &(after_dealer, player) in &round.crash_resume_players {
                    crash_resume_by_dealer
                        .entry(after_dealer)
                        .or_default()
                        .push(player);
                }
                let mut resume_missing_msg_by_dealer: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
                for &(after_dealer, missing_dealer) in &round.resume_missing_dealer_msg_fails {
                    resume_missing_msg_by_dealer
                        .entry(after_dealer)
                        .or_default()
                        .push(missing_dealer);
                }

                // Run dealer protocol
                let mut dealer_logs = BTreeMap::new();
                for &i_dealer in &round.dealers {
                    let sk = keys[i_dealer as usize].clone();
                    let pk = sk.public_key();
                    let share = match (shares.get(&pk), round.replace_shares.contains(&i_dealer)) {
                        (None, _) => None,
                        (Some(s), false) => Some(s.clone()),
                        (Some(_), true) => Some(Share::new(
                            Participant::new(i_dealer),
                            Private::random(&mut rng),
                        )),
                    };

                    // Start dealer (with potential modifications)
                    let (mut dealer, pub_msg, mut priv_msgs) =
                        if let Some(shift) = round.shift_degrees.get(&i_dealer) {
                            // Create dealer with shifted degree
                            let degree = u32::try_from(info.degree::<N3f1>() as i32 + shift.get())
                                .unwrap_or_default();

                            // Manually create the dealer with adjusted polynomial
                            let share = info
                                .unwrap_or_random_share(
                                    &mut rng,
                                    share.map(|s| s.private.expose_unwrap()),
                                )
                                .expect("Failed to generate dealer share");

                            let my_poly = Poly::new_with_constant(&mut rng, degree, share);
                            let priv_msgs = info
                                .players
                                .iter()
                                .map(|pk| {
                                    (
                                        pk.clone(),
                                        DealerPrivMsg::new(my_poly.eval_msm(
                                            &info.player_scalar(pk).expect("player should exist"),
                                            &Sequential,
                                        )),
                                    )
                                })
                                .collect::<Vec<_>>();
                            let results: Map<_, _> = priv_msgs
                                .iter()
                                .map(|(pk, pm)| (pk.clone(), AckOrReveal::Reveal(pm.clone())))
                                .try_collect()
                                .unwrap();
                            let commitment = Poly::commit(my_poly);
                            let pub_msg = DealerPubMsg { commitment };
                            let transcript = {
                                let t = transcript_for_round(&info);
                                transcript_for_ack(&t, &pk, &pub_msg)
                            };
                            let dealer = Dealer {
                                me: sk.clone(),
                                info: info.clone(),
                                pub_msg: pub_msg.clone(),
                                results,
                                transcript,
                            };
                            (dealer, pub_msg, priv_msgs)
                        } else {
                            Dealer::start::<N3f1>(&mut rng, info.clone(), sk.clone(), share)?
                        };

                    // Apply BadShare perturbations
                    for (player, priv_msg) in &mut priv_msgs {
                        let player_key_idx = pk_to_key_idx[player];
                        if round.bad_shares.contains(&(i_dealer, player_key_idx)) {
                            *priv_msg = DealerPrivMsg::new(Scalar::random(&mut rng));
                        }
                    }
                    assert_eq!(priv_msgs.len(), players.len());

                    // Process player acks
                    let mut num_reveals = players.len() as u32;
                    for (player_pk, priv_msg) in priv_msgs {
                        // Check priv msg encoding.
                        assert_eq!(priv_msg, ReadExt::read(&mut priv_msg.encode())?);

                        let i_player = players
                            .index(&player_pk)
                            .ok_or_else(|| anyhow!("unknown player: {:?}", player_pk))?;
                        let player_key_idx = pk_to_key_idx[&player_pk];
                        let player = &mut players.values_mut()[usize::from(i_player)];
                        let persisted = priv_msg.clone();

                        let ack = player
                            .dealer_message::<N3f1>(pk.clone(), pub_msg.clone(), priv_msg)
                            .ok()
                            .flatten();
                        assert_eq!(ack, ReadExt::read(&mut ack.encode())?);
                        if let Some(ack) = ack {
                            acked_dealings
                                .get_mut(&player_pk)
                                .expect("player should be present")
                                .push((pk.clone(), pub_msg.clone(), persisted));
                            let masks = round
                                .bad_player_sigs
                                .get(&(i_dealer, player_key_idx))
                                .cloned()
                                .unwrap_or_default();
                            let (modified, transcript) =
                                masks.transcript_for_player_ack(&info, &pk, &pub_msg)?;
                            assert_eq!(transcript.verify(&player_pk, &ack.sig), !modified);

                            // Skip receiving ack if NoAck perturbation
                            if !round.no_acks.contains(&(i_dealer, player_key_idx)) {
                                dealer.receive_player_ack(player_pk, ack)?;
                                num_reveals -= 1;
                            }
                        } else {
                            assert!(
                                round.bad_shares.contains(&(i_dealer, player_key_idx))
                                    || round.bad(previous_successful_round.is_some(), i_dealer)
                            );
                        }
                    }

                    // Finalize dealer
                    let signed_log = dealer.finalize::<N3f1>();
                    assert_eq!(
                        signed_log,
                        Read::read_cfg(&mut signed_log.encode(), &max_read_size)?
                    );

                    // Check for BadDealerSig
                    let masks = round
                        .bad_dealer_sigs
                        .get(&i_dealer)
                        .cloned()
                        .unwrap_or_default();
                    let (modified, transcript) =
                        masks.transcript_for_signed_dealer_log(&info, &signed_log.log)?;
                    assert_eq!(transcript.verify(&pk, &signed_log.sig), !modified);
                    let (found_pk, mut log) = signed_log
                        .check(&info)
                        .ok_or_else(|| anyhow!("signed log should verify"))?;
                    assert_eq!(pk, found_pk);
                    // Apply BadReveal perturbations
                    match &mut log.results {
                        DealerResult::TooManyReveals => {
                            assert!(num_reveals > info.max_reveals::<N3f1>());
                        }
                        DealerResult::Ok(results) => {
                            assert_eq!(results.len(), players.len());
                            for &i_player in &round.players {
                                if !round.bad_reveals.contains(&(i_dealer, i_player)) {
                                    continue;
                                }
                                let player_pk = keys[i_player as usize].public_key();
                                *results
                                    .get_value_mut(&player_pk)
                                    .ok_or_else(|| anyhow!("unknown player: {:?}", player_pk))? =
                                    AckOrReveal::Reveal(DealerPrivMsg::new(Scalar::random(
                                        &mut rng,
                                    )));
                            }
                        }
                    }
                    dealer_logs.insert(pk, log);

                    // For selected checkpoints, omit a good dealer's private message and
                    // ensure resume reports corruption. Do not mutate player state.
                    for &missing_dealer in resume_missing_msg_by_dealer
                        .get(&i_dealer)
                        .into_iter()
                        .flatten()
                    {
                        assert!(
                            !round.bad(previous_successful_round.is_some(), missing_dealer),
                            "resume_missing_dealer_msg_fails requires dealer {missing_dealer} to be good"
                        );
                        let missing_pk = keys[missing_dealer as usize].public_key();
                        let missing_log = dealer_logs
                            .get(&missing_pk)
                            .unwrap_or_else(|| panic!("missing dealer log for {:?}", missing_pk));
                        for &i_player in &round.players {
                            let player_pk = keys[i_player as usize].public_key();
                            let was_acked = missing_log.get_ack(&player_pk).is_some();

                            let replay = acked_dealings
                                .get(&player_pk)
                                .cloned()
                                .expect("player should be present");
                            let replay_without = replay
                                .into_iter()
                                .filter(|(dealer, _, _)| dealer != &missing_pk);
                            let player_sk = keys[i_player as usize].clone();
                            let resumed = Player::resume::<N3f1>(
                                info.clone(),
                                player_sk,
                                &dealer_logs,
                                replay_without,
                            );
                            if was_acked {
                                assert!(
                                    matches!(resumed, Err(Error::MissingPlayerDealing)),
                                    "resume without dealer {missing_dealer} message should report MissingPlayerDealing for player {i_player}"
                                );
                            } else {
                                assert!(
                                    resumed.is_ok(),
                                    "resume without dealer {missing_dealer} message should succeed for unacked player {i_player}"
                                );
                            }
                        }
                    }

                    // Crash/resume selected players after this dealer has finalized.
                    for &i_player in crash_resume_by_dealer.get(&i_dealer).into_iter().flatten() {
                        let player_pk = keys[i_player as usize].public_key();
                        let player_sk = keys[i_player as usize].clone();
                        let replay = acked_dealings
                            .get(&player_pk)
                            .cloned()
                            .expect("player should be present");
                        let (resumed, _) =
                            Player::resume::<N3f1>(info.clone(), player_sk, &dealer_logs, replay)
                                .expect("player resume perturbation should succeed");
                        *players
                            .get_value_mut(&player_pk)
                            .expect("player should be present") = resumed;
                    }
                }

                // Make sure that bad dealers are not selected.
                let mut logs = Logs::<_, _, N3f1>::new(info.clone());
                for (dealer, log) in &dealer_logs {
                    logs.record(dealer.clone(), log.clone());
                }
                let selection = logs.clone().select::<ed25519::Batch>(&mut rng, &Sequential);
                if let Ok(ref selection) = selection {
                    let good_pks = selection
                        .1
                        .iter_pairs()
                        .map(|(pk, _)| pk.clone())
                        .collect::<BTreeSet<_>>();
                    for &i_dealer in &round.dealers {
                        if round.bad(previous_successful_round.is_some(), i_dealer) {
                            assert!(!good_pks.contains(&keys[i_dealer as usize].public_key()));
                        }
                    }
                }
                // Run observer
                let observe_result =
                    observe::<_, _, N3f1, ed25519::Batch>(&mut rng, logs.clone(), &Sequential);
                if round.expect_failure(previous_successful_round) {
                    assert!(
                        observe_result.is_err(),
                        "Round {i_round} should have failed but succeeded",
                    );
                    continue;
                }
                let observer_output = observe_result?;
                let selection = selection.expect("select should succeed if observe succeeded");

                // Compute expected dealers: good dealers up to required_commitments
                // The select function iterates dealer_logs (BTreeMap) in public key order
                let required_commitments = info.required_commitments::<N3f1>() as usize;
                let expected_dealers: Set<ed25519::PublicKey> = dealer_set
                    .iter()
                    .filter(|pk| {
                        let i = keys.iter().position(|k| &k.public_key() == *pk).unwrap() as u32;
                        !round.bad(previous_successful_round.is_some(), i)
                    })
                    .take(required_commitments)
                    .cloned()
                    .try_collect()
                    .expect("dealers are unique");
                let expected_dealer_indices: BTreeSet<u32> = expected_dealers
                    .iter()
                    .filter_map(|pk| {
                        keys.iter()
                            .position(|k| &k.public_key() == pk)
                            .map(|i| i as u32)
                    })
                    .collect();
                assert_eq!(
                    observer_output.dealers(),
                    &expected_dealers,
                    "Output dealers should match expected good dealers"
                );

                // Map selected dealers to their key indices (for later use)
                let selected_dealers: BTreeSet<u32> = selection
                    .1
                    .keys()
                    .iter()
                    .filter_map(|pk| {
                        keys.iter()
                            .position(|k| &k.public_key() == pk)
                            .map(|i| i as u32)
                    })
                    .collect();
                assert_eq!(
                    selected_dealers, expected_dealer_indices,
                    "Selection should match expected dealers"
                );
                let selected_players: Set<ed25519::PublicKey> = round
                    .players
                    .iter()
                    .map(|&i| keys[i as usize].public_key())
                    .try_collect()
                    .expect("players are unique");
                for &i_player in &round.finalize_missing_dealer_msg_fails {
                    let player_pk = keys[i_player as usize].public_key();
                    let player_sk = keys[i_player as usize].clone();
                    let mut tested = 0u32;
                    for &dealer_idx in &selected_dealers {
                        if round.bad(previous_successful_round.is_some(), dealer_idx) {
                            continue;
                        }
                        let dealer_pk = keys[dealer_idx as usize].public_key();
                        let dealer_log = dealer_logs
                            .get(&dealer_pk)
                            .unwrap_or_else(|| panic!("missing dealer log for {:?}", dealer_pk));
                        if dealer_log.get_ack(&player_pk).is_none() {
                            continue;
                        }
                        let replay = acked_dealings
                            .get(&player_pk)
                            .cloned()
                            .expect("player should be present");
                        let replay_without = replay
                            .into_iter()
                            .filter(|(dealer, _, _)| dealer != &dealer_pk);
                        let resume_logs: BTreeMap<_, _> = dealer_logs
                            .iter()
                            .filter(|(dealer, _)| *dealer != &dealer_pk)
                            .map(|(dealer, log)| (dealer.clone(), log.clone()))
                            .collect();
                        let (resumed, _) = Player::resume::<N3f1>(
                            info.clone(),
                            player_sk.clone(),
                            &resume_logs,
                            replay_without,
                        )
                        .expect("resume should succeed with stale logs");
                        let finalize_res = resumed.finalize::<N3f1, ed25519::Batch>(
                            &mut rng,
                            logs.clone(),
                            &Sequential,
                        );
                        assert!(
                            matches!(
                                finalize_res,
                                Err(FinalizeError::Error(Error::MissingPlayerDealing))
                            ),
                            "finalize without dealer {dealer_idx} message should return MissingPlayerDealing for player {i_player}"
                        );
                        tested += 1;
                    }
                    assert!(
                        tested > 0,
                        "finalize_missing_dealer_msg_fails for player {i_player} tested no dealers"
                    );
                }

                // Compute expected reveals
                //
                // Note: We use union of no_acks and bad_shares since each (dealer, player) pair
                // results in at most one reveal in the protocol, regardless of whether the player
                // didn't ack, got a bad share, or both.
                let mut expected_reveals: BTreeMap<ed25519::PublicKey, u32> = BTreeMap::new();
                for &(dealer_idx, player_key_idx) in round.no_acks.union(&round.bad_shares) {
                    if !selected_dealers.contains(&dealer_idx) {
                        continue;
                    }
                    let pk = keys[player_key_idx as usize].public_key();
                    if selected_players.position(&pk).is_none() {
                        continue;
                    }
                    *expected_reveals.entry(pk).or_insert(0) += 1;
                }

                // Verify each player's revealed status
                let reveal_threshold = info.reveal_threshold::<N3f1>();
                for player in player_set.iter() {
                    let expected =
                        expected_reveals.get(player).copied().unwrap_or(0) >= reveal_threshold;
                    let actual = observer_output.revealed().position(player).is_some();
                    assert_eq!(
                        expected, actual,
                        "Unexpected outcome for player {player:?} (expected={expected}, actual={actual})"
                    );
                }

                // Finalize each player
                for (player_pk, player) in players.into_iter() {
                    let (player_output, share) = player
                        .finalize::<N3f1, ed25519::Batch>(&mut rng, logs.clone(), &Sequential)
                        .expect("Player finalize should succeed");

                    assert_eq!(
                        player_output, observer_output,
                        "Player output should match observer output"
                    );

                    // Verify share matches public polynomial
                    let expected_public = observer_output
                        .public
                        .partial_public(share.index)
                        .expect("share index should be valid");
                    let actual_public = share.public::<V>();
                    assert_eq!(
                        expected_public, actual_public,
                        "Share should match public polynomial"
                    );

                    shares.insert(player_pk.clone(), share);
                }

                // Initialize or verify threshold public key
                let current_public = *observer_output.public().public();
                match threshold_public_key {
                    None => threshold_public_key = Some(current_public),
                    Some(tpk) => {
                        assert_eq!(
                            tpk, current_public,
                            "Public key should remain constant across reshares"
                        );
                    }
                }

                // Generate and verify threshold signature
                let test_message = format!("test message round {i_round}").into_bytes();
                let namespace = b"test";

                let mut partial_sigs = Vec::new();
                for &i_player in &round.players {
                    let share = &shares[&keys[i_player as usize].public_key()];
                    let partial_sig = threshold::sign_message::<V>(share, namespace, &test_message);

                    threshold::verify_message::<V>(
                        &observer_output.public,
                        namespace,
                        &test_message,
                        &partial_sig,
                    )
                    .expect("Partial signature verification should succeed");

                    partial_sigs.push(partial_sig);
                }

                let threshold = observer_output.quorum::<N3f1>();
                let threshold_sig = threshold::recover(
                    &observer_output.public,
                    &partial_sigs[0..threshold as usize],
                    &Sequential,
                )
                .expect("Should recover threshold signature");

                // Verify against the saved public key
                ops::verify_message::<V>(
                    threshold_public_key.as_ref().unwrap(),
                    namespace,
                    &test_message,
                    &threshold_sig,
                )
                .expect("Threshold signature verification should succeed");

                // Update state for next round
                previous_output = Some(observer_output);
            }
            Ok(())
        }
    }

    #[cfg(feature = "arbitrary")]
    mod impl_arbitrary {
        use super::*;
        use arbitrary::{Arbitrary, Unstructured};
        use core::ops::ControlFlow;

        const MAX_NUM_PARTICIPANTS: u32 = 20;
        const MAX_ROUNDS: u32 = 10;

        fn arbitrary_masks<'a>(u: &mut Unstructured<'a>) -> arbitrary::Result<Masks> {
            Ok(Masks {
                info_summary: Arbitrary::arbitrary(u)?,
                dealer: Arbitrary::arbitrary(u)?,
                pub_msg: Arbitrary::arbitrary(u)?,
                log: Arbitrary::arbitrary(u)?,
            })
        }

        /// Pick at most `num` elements at random from `data`, returning them.
        ///
        /// This needs mutable access to perform a shuffle.
        ///
        fn pick<'a, T>(
            u: &mut Unstructured<'a>,
            num: usize,
            mut data: Vec<T>,
        ) -> arbitrary::Result<Vec<T>> {
            let len = data.len();
            let num = num.min(len);
            // Invariant: 0..start is a random subset of data.
            for start in 0..num {
                data.swap(start, u.int_in_range(start..=len - 1)?);
            }
            data.truncate(num);
            Ok(data)
        }

        fn arbitrary_round<'a>(
            u: &mut Unstructured<'a>,
            num_participants: u32,
            last_successful_players: Option<&Set<u32>>,
        ) -> arbitrary::Result<Round> {
            let dealers = if let Some(players) = last_successful_players {
                let to_pick = u.int_in_range(players.quorum::<N3f1>() as usize..=players.len())?;
                pick(u, to_pick, players.into_iter().copied().collect())?
            } else {
                let to_pick = u.int_in_range(1..=num_participants as usize)?;
                pick(u, to_pick, (0..num_participants).collect())?
            };
            let players = {
                let to_pick = u.int_in_range(1..=num_participants as usize)?;
                pick(u, to_pick, (0..num_participants).collect())?
            };
            let pairs = dealers
                .iter()
                .flat_map(|d| players.iter().map(|p| (*d, *p)))
                .collect::<Vec<_>>();
            let pick_pair_set = |u: &mut Unstructured<'a>| {
                let num = u.int_in_range(0..=pairs.len())?;
                if num == 0 {
                    return Ok(BTreeSet::new());
                }
                Ok(pick(u, num, pairs.clone())?.into_iter().collect())
            };
            let pick_dealer_set = |u: &mut Unstructured<'a>| {
                let num = u.int_in_range(0..=dealers.len())?;
                if num == 0 {
                    return Ok(BTreeSet::new());
                }
                Ok(pick(u, num, dealers.clone())?.into_iter().collect())
            };
            let round = Round {
                crash_resume_players: BTreeSet::new(),
                resume_missing_dealer_msg_fails: BTreeSet::new(),
                finalize_missing_dealer_msg_fails: BTreeSet::new(),
                no_acks: pick_pair_set(u)?,
                bad_shares: pick_pair_set(u)?,
                bad_player_sigs: {
                    let indices = pick_pair_set(u)?;
                    indices
                        .into_iter()
                        .map(|k| Ok((k, arbitrary_masks(u)?)))
                        .collect::<arbitrary::Result<_>>()?
                },
                bad_reveals: pick_pair_set(u)?,
                bad_dealer_sigs: {
                    let indices = pick_dealer_set(u)?;
                    indices
                        .into_iter()
                        .map(|k| Ok((k, arbitrary_masks(u)?)))
                        .collect::<arbitrary::Result<_>>()?
                },
                replace_shares: pick_dealer_set(u)?,
                shift_degrees: {
                    let indices = pick_dealer_set(u)?;
                    indices
                        .into_iter()
                        .map(|k| {
                            let expected = N3f1::quorum(players.len()) as i32 - 1;
                            let shift = u.int_in_range(1..=expected.max(1))?;
                            let shift = if bool::arbitrary(u)? { -shift } else { shift };
                            Ok((k, NonZeroI32::new(shift).expect("checked to not be zero")))
                        })
                        .collect::<arbitrary::Result<_>>()?
                },
                dealers,
                players,
            };
            Ok(round)
        }

        impl<'a> Arbitrary<'a> for Plan {
            fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
                let num_participants = u.int_in_range(1..=MAX_NUM_PARTICIPANTS)?;
                let mut rounds = Vec::new();
                let mut last_successful_players: Option<Set<u32>> = None;
                u.arbitrary_loop(None, Some(MAX_ROUNDS), |u| {
                    let round =
                        arbitrary_round(u, num_participants, last_successful_players.as_ref())?;
                    if !round
                        .expect_failure(last_successful_players.as_ref().map(|x| x.len() as u32))
                    {
                        last_successful_players =
                            Some(round.players.iter().copied().try_collect().unwrap());
                    }
                    rounds.push(round);
                    Ok(ControlFlow::Continue(()))
                })?;
                let plan = Self {
                    num_participants: NZU32!(num_participants),
                    rounds,
                };
                plan.validate()
                    .map_err(|_| arbitrary::Error::IncorrectFormat)?;
                Ok(plan)
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
pub use test_plan::Plan as FuzzPlan;

#[cfg(test)]
mod test {
    use super::{test_plan::*, *};
    use crate::{bls12381::primitives::variant::MinPk, ed25519};
    use anyhow::anyhow;
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_invariants::minifuzz;
    use commonware_utils::{N3f1, TestRng, test_rng};
    use core::num::NonZeroI32;

    const PRE_VERIFY_DEALERS: usize = 8;
    type PreVerifyLog = DealerLog<MinPk, ed25519::PublicKey>;
    type PreVerifyLogs = Logs<MinPk, ed25519::PublicKey, N3f1>;

    fn check_pre_verify_log(
        info: &Info<MinPk, ed25519::PublicKey>,
        dealer: &ed25519::PublicKey,
        log: &PreVerifyLog,
    ) -> Result<DealerLogOutcome, DealerLogError> {
        let transcript = transcript_for_round(info);
        PreVerifyLogs::check_dealers::<ed25519::Batch>(
            &mut test_rng(),
            info,
            &Sequential,
            &transcript,
            &[(dealer, log)],
        )
        .pop()
        .expect("one dealer should produce one check")
        .1
    }

    fn reshare_info(seed: u64) -> Info<MinPk, ed25519::PublicKey> {
        let participants = (seed..seed + 4)
            .map(ed25519::PrivateKey::from_seed)
            .map(|key| key.public_key())
            .try_collect::<Set<_>>()
            .expect("participants must be unique");
        let (previous, _) = deal::<MinPk, _, N3f1>(
            TestRng::new(seed + 4),
            Mode::NonZeroCounter,
            participants.clone(),
        )
        .expect("previous dealing must succeed");
        Info::new::<N3f1>(
            b"specific-reshare-error-test",
            1,
            Some(previous),
            Mode::NonZeroCounter,
            Reveal::V1,
            participants.clone(),
            participants,
        )
        .expect("reshare info must be valid")
    }

    fn pub_msg_with_different_constant(
        info: &Info<MinPk, ed25519::PublicKey>,
        expected: &<MinPk as Variant>::Public,
        seed: u64,
    ) -> DealerPubMsg<MinPk> {
        let degree = info.degree::<N3f1>();
        let mut pub_msg = DealerPubMsg::<MinPk> {
            commitment: Poly::commit(Poly::new_with_constant(
                TestRng::new(seed),
                degree,
                Scalar::zero(),
            )),
        };
        if pub_msg.commitment.constant() == expected {
            pub_msg.commitment = Poly::commit(Poly::new_with_constant(
                TestRng::new(seed),
                degree,
                Scalar::one(),
            ));
        }
        assert_eq!(pub_msg.commitment.degree_exact(), degree);
        assert_ne!(pub_msg.commitment.constant(), expected);
        pub_msg
    }

    #[test]
    fn info_rejects_inconsistent_previous_output() {
        let participants = (0..4)
            .map(ed25519::PrivateKey::from_seed)
            .map(|key| key.public_key())
            .try_collect::<Set<_>>()
            .expect("participants must be unique");
        let (previous, _) =
            deal::<MinPk, _, N3f1>(TestRng::new(4), Mode::NonZeroCounter, participants.clone())
                .expect("previous dealing must succeed");

        let mut wrong_total = previous.clone();
        wrong_total.public = Sharing::<MinPk>::new(
            Mode::NonZeroCounter,
            NZU32!(1),
            Poly::commit(Poly::<Scalar>::new(TestRng::new(5), 2)),
        );

        let mut excessive_degree = previous;
        excessive_degree.public = Sharing::<MinPk>::new(
            Mode::NonZeroCounter,
            NZU32!(4),
            Poly::commit(Poly::<Scalar>::new(TestRng::new(6), 3)),
        );

        // Matching the participant count is insufficient when the recovery threshold does not
        // match the configured fault model.
        let mut lower_threshold = excessive_degree.clone();
        lower_threshold.public = Sharing::<MinPk>::new(
            Mode::NonZeroCounter,
            NZU32!(4),
            Poly::commit(Poly::<Scalar>::new(TestRng::new(7), 1)),
        );
        assert_eq!(lower_threshold.public.required(), 2);
        assert_eq!(lower_threshold.quorum::<N3f1>(), 3);

        for previous in [wrong_total, excessive_degree, lower_threshold] {
            assert!(matches!(
                Info::<MinPk, _>::new::<N3f1>(
                    b"invalid-previous-output-test",
                    1,
                    Some(previous),
                    Mode::NonZeroCounter,
                    Reveal::V1,
                    participants.clone(),
                    participants.clone(),
                ),
                Err(Error::InvalidPreviousOutput)
            ));
        }
    }

    fn is_revealed_after(
        reveal: Reveal,
        dealer_count: usize,
        player_count: usize,
        reveal_count: usize,
    ) -> bool {
        let keys: Vec<_> = (0..dealer_count + player_count)
            .map(|seed| ed25519::PrivateKey::from_seed(seed as u64 + 1_000))
            .collect();
        let dealer_keys = &keys[..dealer_count];
        let player_keys = &keys[dealer_count..];
        let dealers: Set<_> = dealer_keys
            .iter()
            .map(|key| key.public_key())
            .try_collect()
            .expect("dealers must be unique");
        let players: Set<_> = player_keys
            .iter()
            .map(|key| key.public_key())
            .try_collect()
            .expect("players must be unique");
        let info = Info::<MinPk, _>::new::<N3f1>(
            b"reveal-threshold-test",
            0,
            None,
            Mode::NonZeroCounter,
            reveal,
            dealers,
            players,
        )
        .expect("info must be valid");
        let target = player_keys[0].public_key();
        let player_keys: BTreeMap<_, _> = player_keys
            .iter()
            .cloned()
            .map(|key| (key.public_key(), key))
            .collect();

        let required = usize::try_from(info.required_commitments::<N3f1>())
            .expect("required commitments exceed usize::MAX");
        let mut selected = Vec::new();
        for (dealer_number, dealer_key) in dealer_keys.iter().take(required).enumerate() {
            let (mut dealer, pub_msg, priv_msgs) = Dealer::start::<N3f1>(
                TestRng::new(dealer_number as u64),
                info.clone(),
                dealer_key.clone(),
                None,
            )
            .expect("dealer must start");
            for (player, priv_msg) in priv_msgs {
                if dealer_number < reveal_count && player == target {
                    continue;
                }
                let mut receiver = Player::<MinPk, _>::new(
                    info.clone(),
                    player_keys.get(&player).expect("player must exist").clone(),
                )
                .expect("player must initialize");
                let ack = receiver
                    .dealer_message::<N3f1>(dealer_key.public_key(), pub_msg.clone(), priv_msg)
                    .expect("dealing must be valid")
                    .expect("dealing must be new");
                dealer
                    .receive_player_ack(player, ack)
                    .expect("ack must be valid");
            }
            selected.push(
                dealer
                    .finalize::<N3f1>()
                    .check(&info)
                    .expect("dealer log must verify"),
            );
        }
        let selected = selected
            .into_iter()
            .try_collect::<Map<_, _>>()
            .expect("dealers must be unique");
        let output = Observe::reckon::<N3f1>(info, selected, &Sequential).output;

        output.revealed().position(&target).is_some()
    }

    #[test]
    fn reveal_threshold_uses_dealer_set_when_dealers_are_fewer() {
        assert!(is_revealed_after(Reveal::V1, 4, 10, 2));
    }

    #[test]
    fn reveal_threshold_uses_dealer_set_when_dealers_are_more() {
        assert!(!is_revealed_after(Reveal::V1, 13, 4, 4));
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_reveal_threshold_uses_player_set() {
        assert!(!is_revealed_after(Reveal::V0, 4, 10, 2));
    }

    #[test]
    #[allow(deprecated)]
    fn reveal_v1_is_committed_to_summary() {
        // Exercise both sharing modes so each non-legacy selector combination must
        // identify a distinct ceremony.
        let participants = (0..4)
            .map(ed25519::PrivateKey::from_seed)
            .map(|key| key.public_key())
            .try_collect::<Set<_>>()
            .expect("participants must be unique");
        let info = |mode, reveal| {
            Info::<MinPk, _>::new::<N3f1>(
                b"reveal-version-transcript-test",
                0,
                None,
                mode,
                reveal,
                participants.clone(),
                participants.clone(),
            )
            .expect("info must be valid")
        };
        let v0_non_zero = info(Mode::NonZeroCounter, Reveal::V0);
        let v0_roots = info(Mode::RootsOfUnity, Reveal::V0);
        let v1_non_zero = info(Mode::NonZeroCounter, Reveal::V1);
        let v1_roots = info(Mode::RootsOfUnity, Reveal::V1);

        // Every selector combination identifies a distinct ceremony. The cross-pair
        // checks prevent the compact selector encodings from aliasing.
        assert_ne!(v0_non_zero.summary, v0_roots.summary);
        assert_ne!(v0_non_zero.summary, v1_non_zero.summary);
        assert_ne!(v0_non_zero.summary, v1_roots.summary);
        assert_ne!(v0_roots.summary, v1_non_zero.summary);
        assert_ne!(v0_roots.summary, v1_roots.summary);
        assert_ne!(v1_non_zero.summary, v1_roots.summary);

        // Info identity follows the ceremony summary.
        assert_ne!(v0_non_zero, v1_non_zero);
        assert_ne!(v0_roots, v1_roots);
    }

    #[test]
    #[allow(deprecated)]
    fn reveals_reject_cross_configured_logs() {
        // Hold every other ceremony input constant and vary only the revealed-share
        // calculation.
        let dealer = ed25519::PrivateKey::from_seed(0);
        let participants: Set<ed25519::PublicKey> = vec![dealer.public_key()]
            .try_into()
            .expect("participant must be unique");
        let info = |reveal| {
            Info::<MinPk, _>::new::<N3f1>(
                b"reveal-version-signature-test",
                0,
                None,
                Mode::NonZeroCounter,
                reveal,
                participants.clone(),
                participants.clone(),
            )
            .expect("info must be valid")
        };
        let v0 = info(Reveal::V0);
        let v1 = info(Reveal::V1);

        // A V0 log remains valid in its ceremony but cannot enter a V1 ceremony.
        let (dealer, _, _) = Dealer::start::<N3f1>(TestRng::new(0), v0.clone(), dealer, None)
            .expect("dealer must start");
        let log = dealer.finalize::<N3f1>();

        assert!(log.clone().check(&v0).is_some());
        assert!(log.check(&v1).is_none());
    }

    #[test]
    #[allow(deprecated)]
    fn observers_match_players_for_each_reveal_calculation() {
        fn outputs(
            reveal: Reveal,
        ) -> (
            Output<MinPk, ed25519::PublicKey>,
            Output<MinPk, ed25519::PublicKey>,
            ed25519::PublicKey,
        ) {
            const DEALER_COUNT: usize = 4;
            const PLAYER_COUNT: usize = 10;
            const SELECTED_DEALERS: usize = 3;
            const TARGET_REVEALS: usize = 2;

            // Two revealed dealings cross V1's dealer threshold but not V0's player
            // threshold, making the selected calculation observable in the output.
            let keys: Vec<_> = (0..DEALER_COUNT + PLAYER_COUNT)
                .map(|seed| ed25519::PrivateKey::from_seed(seed as u64 + 3_000))
                .collect();
            let dealer_keys = &keys[..DEALER_COUNT];
            let player_keys = &keys[DEALER_COUNT..];
            let dealers = dealer_keys
                .iter()
                .map(|key| key.public_key())
                .try_collect()
                .expect("dealers must be unique");
            let players = player_keys
                .iter()
                .map(|key| key.public_key())
                .try_collect()
                .expect("players must be unique");
            let info = Info::<MinPk, _>::new::<N3f1>(
                b"public-reveal-calculation-test",
                0,
                None,
                Mode::NonZeroCounter,
                reveal,
                dealers,
                players,
            )
            .expect("info must be valid");
            let target = player_keys[0].public_key();
            let finalizer_key = player_keys[1].clone();
            let finalizer = finalizer_key.public_key();
            let player_keys: BTreeMap<_, _> = player_keys
                .iter()
                .cloned()
                .map(|key| (key.public_key(), key))
                .collect();
            let mut verified_logs = BTreeMap::new();
            let mut logs = Logs::<MinPk, _, N3f1>::new(info.clone());
            let mut persisted = Vec::new();

            // Build quorum logs while withholding the target's dealing from two dealers.
            // Retain the finalizer's dealings so its player path can resume from the same logs.
            for (dealer_number, dealer_key) in dealer_keys.iter().take(SELECTED_DEALERS).enumerate()
            {
                let dealer_pk = dealer_key.public_key();
                let (mut dealer, pub_msg, priv_msgs) = Dealer::start::<N3f1>(
                    TestRng::new(dealer_number as u64 + 4_000),
                    info.clone(),
                    dealer_key.clone(),
                    None,
                )
                .expect("dealer must start");
                for (player, priv_msg) in priv_msgs {
                    if dealer_number < TARGET_REVEALS && player == target {
                        continue;
                    }
                    if player == finalizer {
                        persisted.push((dealer_pk.clone(), pub_msg.clone(), priv_msg.clone()));
                    }
                    let mut receiver = Player::<MinPk, _>::new(
                        info.clone(),
                        player_keys.get(&player).expect("player must exist").clone(),
                    )
                    .expect("player must initialize");
                    let ack = receiver
                        .dealer_message::<N3f1>(dealer_pk.clone(), pub_msg.clone(), priv_msg)
                        .expect("dealing must be valid")
                        .expect("dealing must be new");
                    dealer
                        .receive_player_ack(player, ack)
                        .expect("ack must be valid");
                }
                let (dealer, log) = dealer
                    .finalize::<N3f1>()
                    .check(&info)
                    .expect("dealer log must verify");
                verified_logs.insert(dealer.clone(), log.clone());
                logs.record(dealer, log);
            }

            // Run the selected logs through both the recovered-player and public-observer paths.
            let (player, _) =
                Player::resume::<N3f1>(info, finalizer_key, &verified_logs, persisted)
                    .expect("player must resume");
            let observed = observe::<MinPk, _, N3f1, ed25519::Batch>(
                &mut test_rng(),
                logs.clone(),
                &Sequential,
            )
            .expect("observation must succeed");
            let (finalized, _) = player
                .finalize::<N3f1, ed25519::Batch>(&mut test_rng(), logs, &Sequential)
                .expect("finalization must succeed");
            (finalized, observed, target)
        }

        // Each calculation agrees across both paths, while target membership proves the
        // configured threshold rule changes the result.
        let (v1_finalized, v1_observed, v1_target) = outputs(Reveal::V1);
        let (v0_finalized, v0_observed, v0_target) = outputs(Reveal::V0);

        assert_eq!(v1_finalized, v1_observed);
        assert_eq!(v0_finalized, v0_observed);
        assert!(v1_finalized.revealed().position(&v1_target).is_some());
        assert!(v0_finalized.revealed().position(&v0_target).is_none());
    }

    #[test]
    fn reveal_threshold_uses_previous_players_during_reshare() {
        let keys: Vec<_> = (0..14)
            .map(|seed| ed25519::PrivateKey::from_seed(seed + 2_000))
            .collect();
        let previous_players = keys[..10]
            .iter()
            .map(|key| key.public_key())
            .try_collect::<Set<_>>()
            .expect("previous players must be unique");
        let (previous, _) = deal::<MinPk, _, N3f1>(
            TestRng::new(0),
            Mode::NonZeroCounter,
            previous_players.clone(),
        )
        .expect("previous dealing must succeed");
        let dealers = previous_players
            .iter()
            .take(7)
            .cloned()
            .try_collect::<Set<_>>()
            .expect("dealers must be unique");
        let players = keys[10..]
            .iter()
            .map(|key| key.public_key())
            .try_collect::<Set<_>>()
            .expect("players must be unique");
        let info = Info::new::<N3f1>(
            b"reshare-reveal-threshold-test",
            1,
            Some(previous),
            Mode::NonZeroCounter,
            Reveal::V1,
            dealers,
            players,
        )
        .expect("reshare info must be valid");

        assert_eq!(info.required_commitments::<N3f1>(), 7);
        assert_eq!(info.reveal_threshold::<N3f1>(), 4);
    }

    struct PreVerifyDealer {
        key: ed25519::PublicKey,
        valid: PreVerifyLog,
        invalid: PreVerifyLog,
    }

    struct PreVerifyFixture {
        info: Info<MinPk, ed25519::PublicKey>,
        wrong_info: Info<MinPk, ed25519::PublicKey>,
        dealers: Vec<PreVerifyDealer>,
    }

    impl PreVerifyFixture {
        fn new() -> Self {
            fn pre_verify_test_keys() -> Vec<ed25519::PrivateKey> {
                (0..PRE_VERIFY_DEALERS as u64)
                    .map(ed25519::PrivateKey::from_seed)
                    .collect()
            }

            fn pre_verify_test_info(
                keys: &[ed25519::PrivateKey],
                round: u64,
            ) -> Info<MinPk, ed25519::PublicKey> {
                let dealers: Set<_> = keys
                    .iter()
                    .map(|sk| sk.public_key())
                    .try_collect()
                    .expect("dealers must be unique");
                Info::<MinPk, _>::new::<N3f1>(
                    b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_TEST",
                    round,
                    None,
                    Mode::NonZeroCounter,
                    Reveal::V1,
                    dealers.clone(),
                    dealers,
                )
                .expect("info must be valid")
            }

            fn generate_dealer_log(
                info: &Info<MinPk, ed25519::PublicKey>,
                keys: &[ed25519::PrivateKey],
                dealer_index: usize,
                seed: u64,
            ) -> DealerLog<MinPk, ed25519::PublicKey> {
                let mut players: BTreeMap<_, _> = keys
                    .iter()
                    .cloned()
                    .map(|sk| {
                        let pk = sk.public_key();
                        (
                            pk,
                            Player::<MinPk, _>::new(info.clone(), sk)
                                .expect("player initialization must succeed"),
                        )
                    })
                    .collect();

                let dealer_sk = keys[dealer_index].clone();
                let dealer_pk = dealer_sk.public_key();
                let mut rng = TestRng::new(seed);
                let (mut dealer, pub_msg, priv_msgs) =
                    Dealer::start::<N3f1>(&mut rng, info.clone(), dealer_sk, None)
                        .expect("dealer initialization must succeed");
                for (player_pk, priv_msg) in priv_msgs {
                    let ack = players
                        .get_mut(&player_pk)
                        .expect("player should exist")
                        .dealer_message::<N3f1>(dealer_pk.clone(), pub_msg.clone(), priv_msg)
                        .expect("dealer message must succeed")
                        .expect("dealer message must be new");
                    dealer
                        .receive_player_ack(player_pk, ack)
                        .expect("ack handling must succeed");
                }
                dealer
                    .finalize::<N3f1>()
                    .check(info)
                    .expect("signed dealer log must verify against its own info")
                    .1
            }

            let keys = pre_verify_test_keys();
            let info = pre_verify_test_info(&keys, 0);
            let wrong_info = pre_verify_test_info(&keys, 1);
            let mut logs_by_key: BTreeMap<_, _> = keys
                .iter()
                .enumerate()
                .map(|(dealer_index, sk)| {
                    let key = sk.public_key();
                    let seed = dealer_index as u64;
                    let valid = generate_dealer_log(&info, &keys, dealer_index, seed);
                    let invalid = generate_dealer_log(&wrong_info, &keys, dealer_index, seed);
                    assert_eq!(
                        valid.pub_msg, invalid.pub_msg,
                        "wrong-info log generation should only change transcript-bound signatures"
                    );
                    (key, (valid, invalid))
                })
                .collect();
            let dealers = info
                .dealers
                .iter()
                .cloned()
                .map(|key| {
                    let (valid, invalid) = logs_by_key
                        .remove(&key)
                        .expect("fixture should include every dealer");
                    PreVerifyDealer {
                        key,
                        valid,
                        invalid,
                    }
                })
                .collect();
            Self {
                info,
                wrong_info,
                dealers,
            }
        }

        fn required_commitments(&self) -> usize {
            usize::try_from(self.info.required_commitments::<N3f1>())
                .expect("required commitments exceed usize::MAX")
        }

        fn expected(&self, valid: &[bool]) -> Set<ed25519::PublicKey> {
            assert_eq!(
                valid.len(),
                self.dealers.len(),
                "fixture size should match case"
            );
            self.dealers
                .iter()
                .zip(valid.iter().copied())
                .filter(|(_, is_valid)| *is_valid)
                .take(self.required_commitments())
                .map(|(dealer, _)| dealer.key.clone())
                .try_collect()
                .expect("dealers must be unique")
        }

        fn record(&self, logs: &mut PreVerifyLogs, dealer_index: usize, is_valid: bool) {
            let dealer = &self.dealers[dealer_index];
            let log = if is_valid {
                dealer.valid.clone()
            } else {
                dealer.invalid.clone()
            };
            logs.record(dealer.key.clone(), log);
        }

        fn logs_for(
            &self,
            info: &Info<MinPk, ed25519::PublicKey>,
            valid: &[bool],
        ) -> PreVerifyLogs {
            assert_eq!(
                valid.len(),
                self.dealers.len(),
                "fixture size should match case"
            );
            let mut logs = PreVerifyLogs::new(info.clone());
            for (dealer_index, &is_valid) in valid.iter().enumerate() {
                self.record(&mut logs, dealer_index, is_valid);
            }
            logs
        }
    }

    #[derive(Debug)]
    struct IncrementalPreVerifyCase {
        valid: [bool; PRE_VERIFY_DEALERS],
        batches: Vec<Vec<usize>>,
    }

    impl<'a> Arbitrary<'a> for IncrementalPreVerifyCase {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let mut valid = [false; PRE_VERIFY_DEALERS];
            for is_valid in &mut valid {
                *is_valid = u.arbitrary()?;
            }

            let mut order: Vec<_> = (0..valid.len()).collect();
            for index in 0..valid.len() {
                let last = order.len() - 1;
                order.swap(index, u.int_in_range(index..=last)?);
            }

            let mut batches = Vec::new();
            let mut start = 0;
            while start < order.len() {
                let batch_size = u.int_in_range(1..=order.len() - start)?;
                batches.push(order[start..start + batch_size].to_vec());
                start += batch_size;
            }

            Ok(Self { valid, batches })
        }
    }

    impl IncrementalPreVerifyCase {
        fn run(self, fixture: &PreVerifyFixture) -> arbitrary::Result<()> {
            let required_commitments = fixture.required_commitments();
            let expected = fixture.expected(&self.valid);
            let fresh = fixture.logs_for(&fixture.info, &self.valid);

            let mut incremental = PreVerifyLogs::new(fixture.info.clone());
            let mut incremental_rng = test_rng();
            for batch in &self.batches {
                for &dealer_index in batch {
                    fixture.record(&mut incremental, dealer_index, self.valid[dealer_index]);
                }
                incremental.pre_verify::<ed25519::Batch>(&mut incremental_rng, &Sequential);
            }

            let mut fresh_rng = test_rng();
            let fresh_selected = fresh
                .select::<ed25519::Batch>(&mut fresh_rng, &Sequential)
                .map(|(_, selection)| selection.keys().clone());
            let incremental_selected = incremental
                .select::<ed25519::Batch>(&mut incremental_rng, &Sequential)
                .map(|(_, selection)| selection.keys().clone());

            match &fresh_selected {
                Ok(selected) => assert_eq!(
                    selected, &expected,
                    "all-at-once selection disagreed with validity mask: {:?}",
                    self
                ),
                Err(_) => assert!(
                    expected.len() < required_commitments,
                    "all-at-once selection failed despite quorum-sized expected set: {:?}",
                    self
                ),
            }

            match (fresh_selected, incremental_selected) {
                (Err(_), Err(_)) => {}
                (Ok(fresh_selected), Ok(incremental_selected)) => assert_eq!(
                    incremental_selected, fresh_selected,
                    "incremental selection disagreed with all-at-once selection: {:?}",
                    self
                ),
                (Ok(fresh_selected), Err(err)) => panic!(
                    "incremental selection failed with {err:?} but all-at-once selected {fresh_selected:?}: {self:?}"
                ),
                (Err(err), Ok(incremental_selected)) => panic!(
                    "incremental selection returned {incremental_selected:?} but all-at-once failed with {err:?}: {self:?}"
                ),
            }

            Ok(())
        }
    }

    #[test]
    fn incremental_pre_verify_preserves_dealer_order() {
        let fixture = PreVerifyFixture::new();
        minifuzz::test(move |u| u.arbitrary::<IncrementalPreVerifyCase>()?.run(&fixture));
    }

    #[test]
    fn check_dealers_reports_invalid_reveal() {
        let fixture = PreVerifyFixture::new();
        let dealer = &fixture.dealers[0];
        let mut log = dealer.valid.clone();
        let DealerResult::Ok(results) = &mut log.results else {
            panic!("valid fixture should contain player results");
        };
        let player = fixture.info.players.iter().next().unwrap().clone();
        *results.get_value_mut(&player).unwrap() =
            AckOrReveal::Reveal(DealerPrivMsg::new(Scalar::zero()));

        let result = check_pre_verify_log(&fixture.info, &dealer.key, &log);
        assert!(matches!(
            result,
            Err(DealerLogError::Fault(FaultReason::InvalidReveal))
        ));
    }

    #[test]
    fn dealer_log_identifies_unexpected_dealer() {
        let fixture = PreVerifyFixture::new();
        let dealer = &fixture.dealers[0];
        let stranger = ed25519::PrivateKey::from_seed(u64::MAX).public_key();
        assert!(fixture.info.dealer_index(&stranger).is_none());
        assert!(matches!(
            check_pre_verify_log(&fixture.info, &stranger, &dealer.valid),
            Err(DealerLogError::UnexpectedDealer)
        ));
    }

    #[test]
    fn dealer_public_message_distinguishes_fault_reasons() {
        let fixture = PreVerifyFixture::new();
        let dealer = &fixture.dealers[0];
        let expected = fixture.info.degree::<N3f1>();
        let actual = 0;
        assert_ne!(expected, actual);
        let log = DealerLog {
            pub_msg: DealerPubMsg::<MinPk> {
                commitment: Poly::commit(Poly::new_with_constant(
                    TestRng::new(10_000),
                    actual,
                    Scalar::one(),
                )),
            },
            results: dealer.valid.results.clone(),
        };
        assert!(matches!(
            check_pre_verify_log(&fixture.info, &dealer.key, &log),
            Err(DealerLogError::Fault(
                FaultReason::InvalidCommitmentDegree {
                    expected: error_expected,
                    actual: error_actual,
                }
            )) if error_expected == expected && error_actual == actual
        ));

        let info = reshare_info(20_000);
        let dealer = info.dealers.iter().next().unwrap().clone();
        let expected = info
            .previous
            .as_ref()
            .unwrap()
            .share_commitment(&dealer)
            .unwrap();
        let pub_msg = pub_msg_with_different_constant(&info, &expected, 20_005);
        let log = DealerLog {
            pub_msg,
            results: DealerResult::TooManyReveals,
        };
        assert!(matches!(
            check_pre_verify_log(&info, &dealer, &log),
            Err(DealerLogError::Fault(
                FaultReason::MismatchedReshareCommitment
            ))
        ));
    }

    #[test]
    fn dealer_public_message_distinguishes_live_errors() -> anyhow::Result<()> {
        // Initial-round validation preserves the exact degree mismatch.
        let fixture = PreVerifyFixture::new();
        let dealer = fixture.dealers[0].key.clone();
        let expected = fixture.info.degree::<N3f1>();
        let actual = 0;
        assert_ne!(expected, actual);
        let pub_msg = DealerPubMsg::<MinPk> {
            commitment: Poly::commit(Poly::new_with_constant(
                TestRng::new(10_000),
                actual,
                Scalar::one(),
            )),
        };
        let mut player = Player::new(fixture.info, ed25519::PrivateKey::from_seed(0))?;
        assert!(matches!(
            player.dealer_message::<N3f1>(
                dealer,
                pub_msg,
                DealerPrivMsg::new(Scalar::zero()),
            ),
            Err(DealerMessageError::InvalidCommitmentDegree {
                expected: error_expected,
                actual: error_actual,
            }) if error_expected == expected && error_actual == actual
        ));

        // Reshare validation preserves the previous-share mismatch.
        let info = reshare_info(20_000);
        let dealer = info.dealers.iter().next().unwrap().clone();
        let expected = info
            .previous
            .as_ref()
            .unwrap()
            .share_commitment(&dealer)
            .unwrap();
        let pub_msg = pub_msg_with_different_constant(&info, &expected, 20_005);
        let mut player = Player::new(info, ed25519::PrivateKey::from_seed(20_000))?;
        assert!(matches!(
            player.dealer_message::<N3f1>(dealer, pub_msg, DealerPrivMsg::new(Scalar::zero()),),
            Err(DealerMessageError::MismatchedReshareCommitment)
        ));

        Ok(())
    }

    #[test]
    fn dealer_log_distinguishes_unavailable_and_faulty_outcomes() {
        let fixture = PreVerifyFixture::new();
        let dealer = &fixture.dealers[0];

        assert!(matches!(
            check_pre_verify_log(&fixture.info, &dealer.key, &dealer.valid),
            Ok(DealerLogOutcome::Available)
        ));

        let mut log = dealer.valid.clone();
        let DealerResult::Ok(results) = &mut log.results else {
            panic!("valid fixture should contain player results");
        };
        results.truncate(results.len() - 1);
        assert!(matches!(
            check_pre_verify_log(&fixture.info, &dealer.key, &log),
            Err(DealerLogError::Fault(FaultReason::MismatchedLogPlayers))
        ));

        let mut log = dealer.valid.clone();
        log.results = DealerResult::TooManyReveals;
        assert!(matches!(
            check_pre_verify_log(&fixture.info, &dealer.key, &log),
            Ok(DealerLogOutcome::Unavailable)
        ));

        let mut log = dealer.valid.clone();
        let DealerResult::Ok(results) = &mut log.results else {
            panic!("valid fixture should contain player results");
        };
        let excessive_reveals = usize::try_from(fixture.info.max_reveals::<N3f1>())
            .expect("maximum reveals exceed usize::MAX")
            + 1;
        for result in results.values_mut().iter_mut().take(excessive_reveals) {
            *result = AckOrReveal::Reveal(DealerPrivMsg::new(Scalar::one()));
        }
        assert!(matches!(
            check_pre_verify_log(&fixture.info, &dealer.key, &log),
            Err(DealerLogError::Fault(FaultReason::ExcessiveReveals))
        ));
    }

    #[test]
    fn logs_are_bound_to_constructor_info() {
        let fixture = PreVerifyFixture::new();
        let mut logs = fixture.logs_for(&fixture.info, &[false; PRE_VERIFY_DEALERS]);
        let mut wrong_logs = fixture.logs_for(&fixture.wrong_info, &[false; PRE_VERIFY_DEALERS]);
        let mut rng = test_rng();

        logs.pre_verify::<ed25519::Batch>(&mut rng, &Sequential);
        wrong_logs.pre_verify::<ed25519::Batch>(&mut rng, &Sequential);
        assert!(
            wrong_logs
                .select::<ed25519::Batch>(&mut rng, &Sequential)
                .is_ok(),
            "control check: logs should verify when bound to the round they were created for"
        );
        let Err(Failure::InsufficientLogs {
            required,
            found,
            faults,
            unavailable,
        }) = observe::<MinPk, _, N3f1, ed25519::Batch>(&mut rng, logs, &Sequential)
        else {
            panic!("logs bound to a different round must fail reconciliation");
        };
        assert_eq!(
            usize::try_from(required).expect("required commitments exceed usize::MAX"),
            fixture.required_commitments()
        );
        assert_eq!(found, 0);
        assert_eq!(faults.len(), PRE_VERIFY_DEALERS);
        assert!(unavailable.is_empty());
        for dealer in &fixture.dealers {
            assert!(matches!(
                faults.get_value(&dealer.key),
                Some(FaultReason::InvalidAck)
            ));
        }
    }

    #[test]
    fn pre_verify_preserves_classifications_and_invalidates_replacements() {
        let fixture = PreVerifyFixture::new();
        let mut logs = fixture.logs_for(&fixture.info, &[true; PRE_VERIFY_DEALERS]);
        fixture.record(&mut logs, 0, false);

        let mut too_many_reveals = fixture.dealers[1].valid.clone();
        too_many_reveals.results = DealerResult::TooManyReveals;
        logs.record(fixture.dealers[1].key.clone(), too_many_reveals);

        let mut wrong_players = fixture.dealers[2].valid.clone();
        let DealerResult::Ok(results) = &mut wrong_players.results else {
            panic!("valid fixture should contain player results");
        };
        results.truncate(results.len() - 1);
        logs.record(fixture.dealers[2].key.clone(), wrong_players);
        logs.pre_verify::<ed25519::Batch>(&mut test_rng(), &Sequential);

        let Err(Failure::InsufficientLogs {
            required,
            found,
            faults,
            unavailable,
        }) = observe::<MinPk, _, N3f1, ed25519::Batch>(&mut test_rng(), logs.clone(), &Sequential)
        else {
            panic!("three rejected logs must prevent reconciliation");
        };
        assert_eq!(
            usize::try_from(required).expect("required commitments exceed usize::MAX"),
            fixture.required_commitments()
        );
        assert_eq!(
            usize::try_from(found).expect("valid dealer count exceeds usize::MAX"),
            PRE_VERIFY_DEALERS - 3
        );
        assert_eq!(faults.len(), 2);
        assert!(matches!(
            faults.get_value(&fixture.dealers[0].key),
            Some(FaultReason::InvalidAck)
        ));
        assert_eq!(unavailable.len(), 1);
        assert!(unavailable.position(&fixture.dealers[1].key).is_some());
        assert!(faults.get_value(&fixture.dealers[1].key).is_none());
        assert!(matches!(
            faults.get_value(&fixture.dealers[2].key),
            Some(FaultReason::MismatchedLogPlayers)
        ));

        fixture.record(&mut logs, 0, true);
        assert!(
            observe::<MinPk, _, N3f1, ed25519::Batch>(&mut test_rng(), logs, &Sequential).is_ok(),
            "replacing one rejected log must restore the exact quorum"
        );
    }

    #[test]
    fn missing_logs_report_dealers_as_unavailable() {
        let fixture = PreVerifyFixture::new();
        let logs = PreVerifyLogs::new(fixture.info.clone());
        let Err(Failure::InsufficientLogs {
            required,
            found,
            faults,
            unavailable,
        }) = observe::<MinPk, _, N3f1, ed25519::Batch>(&mut test_rng(), logs, &Sequential)
        else {
            panic!("missing logs must fail reconciliation");
        };
        assert_eq!(
            usize::try_from(required).expect("required commitments exceed usize::MAX"),
            fixture.required_commitments()
        );
        assert_eq!(found, 0);
        assert!(faults.is_empty());
        assert_eq!(unavailable, fixture.info.dealers);
    }

    #[test]
    fn finalize_wraps_reconciliation_failure() {
        let fixture = PreVerifyFixture::new();
        let player =
            Player::<MinPk, _>::new(fixture.info.clone(), ed25519::PrivateKey::from_seed(0))
                .expect("player initialization must succeed");
        let logs = PreVerifyLogs::new(fixture.info);

        assert!(matches!(
            player.finalize::<N3f1, ed25519::Batch>(&mut test_rng(), logs, &Sequential),
            Err(FinalizeError::Failure(Failure::InsufficientLogs { .. }))
        ));
    }

    #[test]
    fn finalize_rejects_logs_bound_to_different_round() {
        let fixture = PreVerifyFixture::new();
        let player =
            Player::<MinPk, _>::new(fixture.info.clone(), ed25519::PrivateKey::from_seed(0))
                .expect("player initialization must succeed");
        let wrong_logs = fixture.logs_for(&fixture.wrong_info, &[false; PRE_VERIFY_DEALERS]);

        let result =
            player.finalize::<N3f1, ed25519::Batch>(&mut test_rng(), wrong_logs, &Sequential);

        assert!(
            matches!(result, Err(FinalizeError::Error(Error::MismatchedLogs))),
            "finalize should reject logs bound to a different round"
        );
    }

    fn replaced_dealing_fixture(
        replacement_ack: bool,
    ) -> (
        Player<MinPk, ed25519::PrivateKey>,
        Logs<MinPk, ed25519::PublicKey, N3f1>,
    ) {
        let mut keys: Vec<_> = (0..4).map(ed25519::PrivateKey::from_seed).collect();
        keys.sort_by_key(|key| key.public_key());
        let participants: Set<_> = keys
            .iter()
            .map(|key| key.public_key())
            .try_collect()
            .expect("participants must be unique");
        let info = Info::<MinPk, _>::new::<N3f1>(
            b"stale-dealing-test",
            0,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            participants.clone(),
            participants,
        )
        .expect("info must be valid");
        let malicious = keys[0].clone();
        let malicious_pk = malicious.public_key();
        let target_key = keys[3].clone();
        let target = target_key.public_key();

        let (_, stale_pub_msg, stale_priv_msgs) =
            Dealer::start::<N3f1>(TestRng::new(100), info.clone(), malicious, None)
                .expect("dealer must start");
        let stale_priv_msg = stale_priv_msgs
            .into_iter()
            .find_map(|(player, priv_msg)| (player == target).then_some(priv_msg))
            .expect("target dealing must exist");

        let mut verified_logs = BTreeMap::new();
        let mut logs = Logs::<MinPk, _, N3f1>::new(info.clone());
        let mut persisted = vec![(malicious_pk, stale_pub_msg.clone(), stale_priv_msg)];
        for (dealer_number, dealer_key) in keys.iter().take(3).enumerate() {
            let seed = 200 + dealer_number as u64;
            let dealer_pk = dealer_key.public_key();
            let (mut dealer, pub_msg, priv_msgs) =
                Dealer::start::<N3f1>(TestRng::new(seed), info.clone(), dealer_key.clone(), None)
                    .expect("dealer must start");
            if dealer_number == 0 {
                assert_ne!(pub_msg, stale_pub_msg);
            }

            for (player, priv_msg) in priv_msgs {
                if dealer_number == 0 && player == target && !replacement_ack {
                    continue;
                }
                if dealer_number != 0 && player == target {
                    persisted.push((dealer_pk.clone(), pub_msg.clone(), priv_msg.clone()));
                }
                let receiver_key = keys
                    .iter()
                    .find(|key| key.public_key() == player)
                    .expect("receiver must exist")
                    .clone();
                let mut receiver = Player::<MinPk, _>::new(info.clone(), receiver_key)
                    .expect("player must initialize");
                let ack = receiver
                    .dealer_message::<N3f1>(dealer_pk.clone(), pub_msg.clone(), priv_msg)
                    .expect("dealing must be valid")
                    .expect("dealing must be new");
                dealer
                    .receive_player_ack(player, ack)
                    .expect("ack must be valid");
            }

            let (dealer, log) = dealer
                .finalize::<N3f1>()
                .check(&info)
                .expect("dealer log must verify");
            if dealer_number == 0 {
                assert_eq!(log.get_reveal(&target).is_some(), !replacement_ack);
            }
            verified_logs.insert(dealer.clone(), log.clone());
            logs.record(dealer, log);
        }

        let (target_player, _) =
            Player::resume::<N3f1>(info, target_key, &verified_logs, persisted)
                .expect("target must resume");
        (target_player, logs)
    }

    #[test]
    fn stale_dealing_is_not_reused_for_replaced_log() {
        let (target_player, logs) = replaced_dealing_fixture(false);
        let (output, share) = target_player
            .finalize::<N3f1, ed25519::Batch>(&mut test_rng(), logs, &Sequential)
            .expect("target must finalize");
        assert_eq!(
            share.public::<MinPk>(),
            output
                .public()
                .partial_public(share.index)
                .expect("share index must be valid")
        );
    }

    #[test]
    fn replacement_ack_rejects_stale_persisted_dealing() {
        let (target_player, logs) = replaced_dealing_fixture(true);
        assert!(matches!(
            target_player.finalize::<N3f1, ed25519::Batch>(&mut test_rng(), logs, &Sequential),
            Err(FinalizeError::Error(Error::InvalidPersistedDealing { .. }))
        ));
    }

    #[test]
    fn single_round() -> anyhow::Result<()> {
        Plan::new(NZU32!(4))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]))
            .run::<MinPk>(0)
    }

    #[test]
    fn multiple_rounds() -> anyhow::Result<()> {
        Plan::new(NZU32!(4))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]))
            .run::<MinPk>(0)
    }

    #[test]
    fn player_crash_resume_after_dealer() -> anyhow::Result<()> {
        Plan::new(NZU32!(4))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]).crash_resume_player(1, 2))
            .run::<MinPk>(0)
    }

    #[test]
    fn resume_missing_good_dealer_message_fails_after_checkpoint() -> anyhow::Result<()> {
        Plan::new(NZU32!(4))
            .with(
                Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3])
                    .resume_missing_dealer_msg_fails(2, 1),
            )
            .run::<MinPk>(0)
    }

    #[test]
    fn resume_missing_good_dealer_message_skips_unacked_players() -> anyhow::Result<()> {
        Plan::new(NZU32!(4))
            .with(
                Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3])
                    .no_ack(1, 0)
                    .resume_missing_dealer_msg_fails(2, 1),
            )
            .run::<MinPk>(0)
    }

    #[test]
    fn finalize_fails_after_resume_without_good_dealer_message() -> anyhow::Result<()> {
        Plan::new(NZU32!(4))
            .with(
                Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3])
                    .no_ack(0, 1)
                    .finalize_missing_dealer_msg_fails(0),
            )
            .run::<MinPk>(0)
    }

    #[test]
    fn invalid_checkpoint_configs_fail_validation() {
        assert!(
            Plan::new(NZU32!(4))
                .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]).crash_resume_player(4, 2))
                .validate()
                .is_err()
        );
        assert!(
            Plan::new(NZU32!(4))
                .with(
                    Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3])
                        .resume_missing_dealer_msg_fails(1, 2),
                )
                .validate()
                .is_err()
        );
        assert!(
            Plan::new(NZU32!(4))
                .with(
                    Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3])
                        .bad_reveal(1, 0)
                        .resume_missing_dealer_msg_fails(2, 1),
                )
                .validate()
                .is_err()
        );
    }

    #[test]
    fn changing_committee() -> anyhow::Result<()> {
        Plan::new(NonZeroU32::new(5).unwrap())
            .with(Round::new(vec![0, 1, 2], vec![1, 2, 3]))
            .with(Round::new(vec![1, 2, 3], vec![2, 3, 4]))
            .with(Round::new(vec![2, 3, 4], vec![3, 4, 0]))
            .with(Round::new(vec![3, 4, 0], vec![4, 0, 1]))
            .run::<MinPk>(0)
    }

    #[test]
    fn missing_ack() -> anyhow::Result<()> {
        // With 4 players, max_faults = 1, so 1 missing ack per dealer is OK
        Plan::new(NonZeroU32::new(4).unwrap())
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]).no_ack(0, 0))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]).no_ack(0, 1))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]).no_ack(0, 2))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]).no_ack(0, 3))
            .run::<MinPk>(0)
    }

    #[test]
    fn increasing_decreasing_committee() -> anyhow::Result<()> {
        Plan::new(NonZeroU32::new(5).unwrap())
            .with(Round::new(vec![0, 1], vec![0, 1, 2]))
            .with(Round::new(vec![0, 1, 2], vec![0, 1, 2, 3]))
            .with(Round::new(vec![0, 1, 2], vec![0, 1]))
            .with(Round::new(vec![0, 1], vec![0, 1, 2, 3, 4]))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1]))
            .run::<MinPk>(0)
    }

    #[test]
    fn bad_reveal_fails() -> anyhow::Result<()> {
        Plan::new(NonZeroU32::new(4).unwrap())
            .with(Round::new(vec![0], vec![0, 1, 2, 3]).bad_reveal(0, 1))
            .run::<MinPk>(0)
    }

    #[test]
    fn bad_share() -> anyhow::Result<()> {
        Plan::new(NonZeroU32::new(4).unwrap())
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]).bad_share(0, 1))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]).bad_share(0, 2))
            .run::<MinPk>(0)
    }

    #[test]
    fn shift_degree_fails() -> anyhow::Result<()> {
        Plan::new(NonZeroU32::new(4).unwrap())
            .with(Round::new(vec![0], vec![0, 1, 2, 3]).shift_degree(
                0,
                NonZeroI32::new(1).ok_or_else(|| anyhow!("invalid NZI32"))?,
            ))
            .run::<MinPk>(0)
    }

    #[test]
    fn replace_share_fails() -> anyhow::Result<()> {
        Plan::new(NonZeroU32::new(4).unwrap())
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]))
            .with(Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3]).replace_share(0))
            .run::<MinPk>(0)
    }

    #[test]
    fn too_many_reveals_dealer() -> anyhow::Result<()> {
        Plan::new(NonZeroU32::new(4).unwrap())
            .with(
                Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3])
                    .no_ack(0, 0)
                    .no_ack(0, 1),
            )
            .run::<MinPk>(0)
    }

    #[test]
    fn too_many_reveals_player() -> anyhow::Result<()> {
        Plan::new(NonZeroU32::new(4).unwrap())
            .with(
                Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3])
                    .no_ack(0, 0)
                    .no_ack(1, 0)
                    .no_ack(3, 0),
            )
            .run::<MinPk>(0)
    }

    #[test]
    fn bad_sigs() -> anyhow::Result<()> {
        Plan::new(NonZeroU32::new(4).unwrap())
            .with(
                Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3])
                    .bad_dealer_sig(
                        0,
                        Masks {
                            log: vec![0xFF; 8],
                            ..Default::default()
                        },
                    )
                    .bad_player_sig(
                        0,
                        1,
                        Masks {
                            pub_msg: vec![0xFF; 8],
                            ..Default::default()
                        },
                    ),
            )
            .run::<MinPk>(0)
    }

    #[test]
    fn issue_2745_regression() -> anyhow::Result<()> {
        Plan::new(NonZeroU32::new(6).unwrap())
            .with(
                Round::new(vec![0], vec![5, 1, 3, 0, 4])
                    .no_ack(0, 5)
                    .bad_share(0, 5),
            )
            .with(Round::new(vec![0, 1, 3, 4], vec![0]))
            .with(Round::new(vec![0], vec![0]))
            .run::<MinPk>(0)
    }

    #[test]
    fn signed_dealer_log_commitment() -> anyhow::Result<()> {
        let sk = ed25519::PrivateKey::from_seed(0);
        let pk = sk.public_key();
        let info = Info::<MinPk, _>::new::<N3f1>(
            b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_TEST",
            0,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            vec![sk.public_key()].try_into().unwrap(),
            vec![sk.public_key()].try_into().unwrap(),
        )?;
        let mut log0 = {
            let (dealer, _, _) =
                Dealer::start::<N3f1>(&mut test_rng(), info.clone(), sk.clone(), None)?;
            dealer.finalize::<N3f1>()
        };
        let mut log1 = {
            let (mut dealer, pub_msg, priv_msgs) =
                Dealer::start::<N3f1>(&mut test_rng(), info.clone(), sk.clone(), None)?;
            let mut player = Player::new(info.clone(), sk)?;
            let ack = player
                .dealer_message::<N3f1>(pk.clone(), pub_msg, priv_msgs[0].1.clone())?
                .expect("dealer message must be new");
            dealer.receive_player_ack(pk, ack)?;
            dealer.finalize::<N3f1>()
        };
        std::mem::swap(&mut log0.log, &mut log1.log);
        assert!(log0.check(&info).is_none());
        assert!(log1.check(&info).is_none());

        Ok(())
    }

    #[test]
    fn dealer_message_reports_errors_and_skips_duplicates() -> anyhow::Result<()> {
        let a = ed25519::PrivateKey::from_seed(0);
        let b = ed25519::PrivateKey::from_seed(1);
        let stranger = ed25519::PrivateKey::from_seed(2);
        let (a_pk, b_pk, stranger_pk) = (a.public_key(), b.public_key(), stranger.public_key());
        let members: Set<ed25519::PublicKey> = vec![a_pk.clone(), b_pk.clone()].try_into().unwrap();
        let info = Info::<MinPk, _>::new::<N3f1>(
            b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_TEST",
            0,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            members.clone(),
            members,
        )?;

        // Dealer A produces one private message per player.
        let (_, pub_msg, priv_msgs) =
            Dealer::start::<N3f1>(&mut test_rng(), info.clone(), a, None)?;
        let priv_for_a = priv_msgs
            .iter()
            .find(|(player, _)| *player == a_pk)
            .map(|(_, msg)| msg.clone())
            .expect("share for a");
        let priv_for_b = priv_msgs
            .iter()
            .find(|(player, _)| *player == b_pk)
            .map(|(_, msg)| msg.clone())
            .expect("share for b");

        // Persisted invalid input is reported as local state corruption.
        assert!(matches!(
            Player::resume::<N3f1>(
                info.clone(),
                b.clone(),
                &BTreeMap::new(),
                [(a_pk.clone(), pub_msg.clone(), priv_for_a.clone())],
            ),
            Err(Error::InvalidPersistedDealing { .. })
        ));
        let mut player = Player::new(info, b)?;
        assert!(matches!(
            player.dealer_message::<N3f1>(a_pk.clone(), pub_msg.clone(), priv_for_a),
            Err(DealerMessageError::InvalidDealerShare)
        ));

        // Live message errors expose the rejection reason without attributing it.
        assert!(matches!(
            player.dealer_message::<N3f1>(stranger_pk, pub_msg.clone(), priv_for_b.clone(),),
            Err(DealerMessageError::UnexpectedDealer)
        ));

        // A correct dealing validates.
        assert!(
            player
                .dealer_message::<N3f1>(a_pk.clone(), pub_msg.clone(), priv_for_b.clone())?
                .is_some()
        );

        // Replaying a dealer's message is a benign skip.
        assert!(matches!(
            player.dealer_message::<N3f1>(a_pk, pub_msg, priv_for_b),
            Ok(None)
        ));

        Ok(())
    }

    #[test]
    fn receive_player_ack_reports_non_attributable_errors() -> anyhow::Result<()> {
        let a = ed25519::PrivateKey::from_seed(0);
        let stranger = ed25519::PrivateKey::from_seed(1);
        let (a_pk, stranger_pk) = (a.public_key(), stranger.public_key());
        let members: Set<ed25519::PublicKey> = vec![a_pk.clone()].try_into().unwrap();
        let info = Info::<MinPk, _>::new::<N3f1>(
            b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_TEST",
            0,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            members.clone(),
            members,
        )?;

        let (mut dealer, pub_msg, priv_msgs) =
            Dealer::start::<N3f1>(TestRng::new(0), info.clone(), a.clone(), None)?;
        let (_, alternate_pub_msg, alternate_priv_msgs) =
            Dealer::start::<N3f1>(TestRng::new(1), info.clone(), a.clone(), None)?;
        assert_ne!(pub_msg, alternate_pub_msg);

        let mut player = Player::new(info.clone(), a.clone())?;
        let ack = player
            .dealer_message::<N3f1>(a_pk.clone(), pub_msg, priv_msgs[0].1.clone())?
            .expect("valid ack");

        // An honest player can acknowledge an alternate public message from an
        // equivocating dealer. A signature mismatch therefore cannot identify a
        // faulty player.
        let mut alternate_player = Player::new(info, a)?;
        let alternate_ack = alternate_player
            .dealer_message::<N3f1>(
                a_pk.clone(),
                alternate_pub_msg,
                alternate_priv_msgs[0].1.clone(),
            )?
            .expect("valid ack for alternate message");
        assert!(matches!(
            dealer.receive_player_ack(a_pk.clone(), alternate_ack),
            Err(PlayerAckError::InvalidAck)
        ));

        // Out-of-round identities produce the precise non-attributed error.
        assert!(matches!(
            dealer.receive_player_ack(stranger_pk, ack.clone()),
            Err(PlayerAckError::UnexpectedPlayer)
        ));

        // The genuine ack is still accepted.
        assert!(dealer.receive_player_ack(a_pk, ack).is_ok());

        Ok(())
    }

    #[test]
    fn info_with_different_mode_is_not_equal() -> Result<(), Error> {
        let sk = ed25519::PrivateKey::from_seed(0);
        let pk = sk.public_key();
        let dealers: Set<ed25519::PublicKey> = vec![pk.clone()].try_into().unwrap();
        let players: Set<ed25519::PublicKey> = vec![pk].try_into().unwrap();

        let non_zero_counter_info = Info::<MinPk, _>::new::<N3f1>(
            b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_TEST",
            0,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            dealers.clone(),
            players.clone(),
        )?;
        let roots_of_unity_mode_info = Info::<MinPk, _>::new::<N3f1>(
            b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_TEST",
            0,
            None,
            Mode::RootsOfUnity,
            Reveal::V1,
            dealers,
            players,
        )?;

        assert_ne!(non_zero_counter_info, roots_of_unity_mode_info);
        Ok(())
    }

    #[test]
    fn resume_ignores_invalid_logged_ack_signature() -> Result<(), Error> {
        let dealer_sk = ed25519::PrivateKey::from_seed(11);
        let dealer_pk = dealer_sk.public_key();
        let player_sk = ed25519::PrivateKey::from_seed(22);
        let player_pk = player_sk.public_key();
        let dealers: Set<ed25519::PublicKey> = vec![dealer_pk.clone()].try_into().unwrap();
        let players: Set<ed25519::PublicKey> = vec![player_pk.clone()].try_into().unwrap();
        let info = Info::<MinPk, _>::new::<N3f1>(
            b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_TEST",
            0,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            dealers.clone(),
            players.clone(),
        )?;
        let wrong_round_info = Info::<MinPk, _>::new::<N3f1>(
            b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_TEST",
            1,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            dealers,
            players,
        )?;
        let (_, pub_msg, _) =
            Dealer::start::<N3f1>(&mut test_rng(), info.clone(), dealer_sk, None)?;
        let bad_ack = PlayerAck {
            sig: transcript_for_ack(
                &transcript_for_round(&wrong_round_info),
                &dealer_pk,
                &pub_msg,
            )
            .sign(&player_sk),
        };
        let results: Map<_, _> = vec![(player_pk, AckOrReveal::Ack(bad_ack))]
            .into_iter()
            .try_collect()
            .unwrap();
        let mut logs = BTreeMap::new();
        logs.insert(
            dealer_pk,
            DealerLog {
                pub_msg,
                results: DealerResult::Ok(results),
            },
        );

        let resumed = Player::resume::<N3f1>(info, player_sk, &logs, []);
        assert!(resumed.is_ok());
        let (_, acks) = resumed.unwrap();
        assert!(acks.is_empty());

        Ok(())
    }

    #[test]
    fn test_dealer_priv_msg_redacted() {
        let mut rng = test_rng();
        let msg = DealerPrivMsg::new(Scalar::random(&mut rng));
        let debug = format!("{:?}", msg);
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_dealer_priv_msg_decode_rejects_zero_scalar() {
        let mut encoded = Scalar::zero().encode();
        let decoded = DealerPrivMsg::read_cfg(&mut encoded, &());
        assert!(decoded.is_err());
    }

    #[test]
    fn test_dealer_pub_msg_decode_rejects_zero_commitment() {
        let mut rng = test_rng();
        let commitment = Poly::commit(Poly::new_with_constant(&mut rng, 0, Scalar::zero()));
        let mut encoded = DealerPubMsg::<MinPk> { commitment }.encode();
        let decoded = DealerPubMsg::<MinPk>::read_cfg(&mut encoded, &NZU32!(1));
        assert!(decoded.is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_conformance::Conformance;

        fn feldman_transcript(seed: u64, mode: Mode, reveal: Reveal) -> Vec<u8> {
            const APPLICATION_NAMESPACE: &[u8] =
                b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG_CONFORMANCE";
            let dealer_sk = ed25519::PrivateKey::from_seed(11);
            let dealer_pk = dealer_sk.public_key();
            let player_sk = ed25519::PrivateKey::from_seed(22);
            let player_pk = player_sk.public_key();
            let dealers: Set<ed25519::PublicKey> = vec![dealer_pk.clone()].try_into().unwrap();
            let players: Set<ed25519::PublicKey> = vec![player_pk].try_into().unwrap();
            let info = Info::<MinPk, _>::new::<N3f1>(
                APPLICATION_NAMESPACE,
                seed,
                None,
                mode,
                reveal,
                dealers,
                players,
            )
            .unwrap();

            let (_, pub_msg, _) = Dealer::start::<N3f1>(
                &mut TestRng::new(seed),
                info.clone(),
                dealer_sk.clone(),
                None,
            )
            .unwrap();

            let round_transcript = transcript_for_round(&info);
            let ack = transcript_for_ack(&round_transcript, &dealer_pk, &pub_msg);
            let ack_summary = ack.summarize();
            let ack_signature = ack.sign(&player_sk);

            let log = DealerLog {
                pub_msg,
                results: DealerResult::TooManyReveals,
            };
            let log_summary = transcript_for_log(&info, &log).summarize();
            let signed_log = SignedDealerLog::sign(&dealer_sk, &info, log);

            let mut output = info.summary.encode().to_vec();
            output.extend(ack_summary.encode());
            output.extend(ack_signature.encode());
            output.extend(log_summary.encode());
            output.extend(signed_log.encode());
            output
        }

        /// Pins the full transcript for one polynomial/reveal mode tag pair.
        struct FeldmanTranscript<const POLYNOMIAL_MODE: u8, const REVEAL_MODE: u8>;

        impl<const POLYNOMIAL_MODE: u8, const REVEAL_MODE: u8> Conformance
            for FeldmanTranscript<POLYNOMIAL_MODE, REVEAL_MODE>
        {
            #[allow(deprecated)]
            async fn commit(seed: u64) -> Vec<u8> {
                let (mode, reveal) = match (POLYNOMIAL_MODE, REVEAL_MODE) {
                    (0, 0) => (Mode::NonZeroCounter, Reveal::V0),
                    (0, 1) => (Mode::NonZeroCounter, Reveal::V1),
                    (1, 0) => (Mode::RootsOfUnity, Reveal::V0),
                    (1, 1) => (Mode::RootsOfUnity, Reveal::V1),
                    _ => panic!("unsupported Feldman transcript mode"),
                };
                feldman_transcript(seed, mode, reveal)
            }
        }

        commonware_conformance::conformance_tests! {
            FeldmanTranscript<0, 0> => 16,
            FeldmanTranscript<0, 1> => 16,
            FeldmanTranscript<1, 0> => 16,
            FeldmanTranscript<1, 1> => 16,
            CodecConformance<Output<MinPk, ed25519::PublicKey>>,
            CodecConformance<DealerPubMsg<MinPk>>,
            CodecConformance<DealerPrivMsg>,
            CodecConformance<PlayerAck<ed25519::PublicKey>>,
            CodecConformance<AckOrReveal<ed25519::PublicKey>>,
            CodecConformance<DealerResult<ed25519::PublicKey>>,
            CodecConformance<DealerLog<MinPk, ed25519::PublicKey>>,
            CodecConformance<SignedDealerLog<MinPk, ed25519::PrivateKey>>,
        }
    }
}
