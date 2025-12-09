//! Distributed Key Generation (DKG) and Resharing protocol for the BLS12-381 curve.
//!
//! This module implements an interactive Distributed Key Generation (DKG) and Resharing protocol
//! for the BLS12-381 curve. Unlike other constructions, this construction does not require encrypted
//! shares to be publicly broadcast to complete a DKG/Reshare. Shares, instead, are sent directly
//! between dealers and players over an encrypted channel (which can be instantiated
//! with [commonware-p2p](https://docs.rs/commonware-p2p)).
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
//! * [`Share`]: A player's private share of the distributed key (from `primitives::group`)
//! * [`Dealer`]: State machine for a dealer participating in the protocol
//! * [`Player`]: State machine for a player receiving shares
//! * [`SignedDealerLog`]: A dealer's signed transcript of their interactions with players
//!
//! ## Message Types
//!
//! * [`DealerPubMsg`]: Public commitment polynomial sent from dealer to all players
//! * [`DealerPrivMsg`]: Private share sent from dealer to a specific player
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
//! - List of players who will receive shares
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
//! - The player verifies that the private share matches the public commitment evaluation
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
//! - The list of players who received shares,
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
//! # Caveats
//!
//! ## Synchrony Assumption
//!
//! Under synchrony (where `t` is the maximum amount of time it takes for a message to be sent between any two participants),
//! this construction can be used to maintain a shared secret where at least `f + 1` honest players must participate to
//! recover the shared secret (`2f + 1` threshold where at most `f` players are Byzantine). To see how this is true,
//! first consider that in any successful round there must exist `2f + 1` commitments with at most `f` reveals. This implies
//! that all players must have acknowledged or have access to a reveal for each of the `2f + 1` selected commitments (allowing
//! them to derive their share). Next, consider that when the network is synchronous that all `2f + 1` honest players send
//! acknowledgements to honest dealers before `2t`. Because `2f + 1` commitments must be chosen, at least `f + 1` commitments
//! must be from honest dealers (where no honest player dealing is revealed). Even if the remaining `f` commitments are from
//! Byzantine dealers, there will not be enough dealings to recover the derived share of any honest player (at most `f` of
//! `2f + 1` dealings publicly revealed). Given all `2f + 1` honest players have access to their shares and it is not possible
//! for a Byzantine player to derive any honest player's share, this claim holds.
//!
//! If the network is not synchronous, however, Byzantine players can collude to recover a shared secret with the
//! participation of a single honest player (rather than `f + 1`) and `f + 1` honest players will each be able to derive
//! the shared secret (if the Byzantine players reveal their shares). To see how this could be, consider a network where
//! `f` honest participants are in one partition and (`f + 1` honest and `f` Byzantine participants) are in another. All
//! `f` Byzantine players acknowledge dealings from the `f + 1` honest dealers. Participants in the second partition will
//! complete a round and all the reveals will belong to the same set of `f` honest players (that are in the first partition).
//! A colluding Byzantine adversary will then have access to their acknowledged `f` shares and the revealed `f` shares
//! (requiring only the participation of a single honest player that was in their partition to recover the shared secret).
//! If the Byzantine adversary reveals all of their (still private) shares at this time, each of the `f + 1` honest players
//! that were in the second partition will be able to derive the shared secret without collusion (using their private share
//! and the `2f` public shares). It will not be possible for any external observer, however, to recover the shared secret.
//!
//! ### Future Work: Dropping the Synchrony Assumption?
//!
//! It is possible to design a DKG/Resharing scheme that maintains a shared secret where at least `f + 1` honest players
//! must participate to recover the shared secret that doesn't require a synchrony assumption (`2f + 1` threshold
//! where at most `f` players are Byzantine). However, known constructions that satisfy this requirement require both
//! broadcasting encrypted dealings publicly and employing Zero-Knowledge Proofs (ZKPs) to attest that encrypted dealings
//! were generated correctly ([Groth21](https://eprint.iacr.org/2021/339), [Kate23](https://eprint.iacr.org/2023/451)).
//!
//! As of January 2025, these constructions are still considered novel (2-3 years in production), require stronger
//! cryptographic assumptions, don't scale to hundreds of participants (unless dealers have powerful hardware), and provide
//! observers the opportunity to brute force decrypt shares (even if honest players are online).
//!
//! ## Handling Complaints
//!
//! This crate does not provide an integrated mechanism for tracking complaints from players (of malicious dealers). However, it is
//! possible to implement your own mechanism and to manually disqualify dealers from a given round in the arbiter. This decision was made
//! because the mechanism for communicating commitments/shares/acknowledgements is highly dependent on the context in which this
//! construction is used.
//!
//! In practice:
//! - [`Player::dealer_message`] returns `None` for invalid messages (implicit complaint)
//! - [`Dealer::receive_player_ack`] validates acknowledgements
//! - Other custom mechanisms can exclude dealers before calling [`observe`] or [`Player::finalize`],
//!   to enforce other rules for "misbehavior" beyond what the DKG does already.
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
//! ## Share Reveals
//!
//! In order to prevent malicious dealers from withholding shares from players, we
//! require the dealers reveal the shares for which they did not receive acks.
//! Because of the synchrony assumption above, this will only happen if either:
//! - the dealer is malicious, not sending a share, but honestly revealing,
//! - or, the player is malicious, not sending an ack when they should.
//!
//! Thus, for honest players, in the worst case, `f` reveals get created, because
//! they correctly did not ack the `f` malicious dealers who failed to send them
//! a share. In that case, their final share remains secret, because it is the linear
//! combination of at least `f + 1` shares received from dealers.
//!
//! # Example
//!
//! ```
//! use commonware_cryptography::bls12381::{
//!     dkg2::{Dealer, Player, Info, SignedDealerLog, observe},
//!     primitives::variant::MinSig,
//! };
//! use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
//! use commonware_utils::{ordered::Set, TryCollect};
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
//!     let private_key = ed25519::PrivateKey::from_rng(&mut rng);
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
//! let info = Info::<MinSig, ed25519::PublicKey>::new(
//!     b"application-namespace",
//!     0,                    // round number
//!     None,                 // no previous output (initial DKG)
//!     dealer_set.clone(),   // dealers
//!     player_set.clone(),   // players
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
//! let mut dealer_logs = BTreeMap::new();
//! for dealer_priv in &private_keys {
//!     // Each dealer generates messages for all players
//!     let (mut dealer, pub_msg, priv_msgs) = Dealer::start(
//!         &mut rng,
//!         info.clone(),
//!         dealer_priv.clone(),
//!         None,  // no previous share for initial DKG
//!     )?;
//!
//!     // Distribute messages to players and collect acknowledgements
//!     for (player_pk, priv_msg) in priv_msgs {
//!         if let Some(player) = players.get_mut(&player_pk) {
//!             if let Some(ack) = player.dealer_message(
//!                 dealer_priv.public_key(),
//!                 pub_msg.clone(),
//!                 priv_msg,
//!             ) {
//!                 dealer.receive_player_ack(player_pk, ack)?;
//!             }
//!         }
//!     }
//!
//!     // Finalize dealer and verify log
//!     let signed_log = dealer.finalize();
//!     if let Some((dealer_pk, log)) = signed_log.check(&info) {
//!         dealer_logs.insert(dealer_pk, log);
//!     }
//! }
//!
//! // Step 4: Players finalize to get their shares
//! let mut player_shares = BTreeMap::new();
//! for (player_pk, player) in players {
//!     let (output, share) = player.finalize(
//!       dealer_logs.clone(),
//!       1 // Increase this for parallelism.
//!     )?;
//!     println!("Player {:?} got share at index {}", player_pk, share.index);
//!     player_shares.insert(player_pk, share);
//! }
//!
//! // Step 5: Observer can also compute the public output
//! let observer_output = observe::<MinSig, ed25519::PublicKey>(
//!     info,
//!     dealer_logs,
//!     1 // Increase this for parallelism.
//! )?;
//! println!("DKG completed with threshold {}", observer_output.quorum());
//! # Ok(())
//! # }
//! ```
//!
//! For a complete example with resharing, see [commonware-reshare](https://docs.rs/commonware-reshare).
use super::primitives::group::Share;
use crate::{
    bls12381::primitives::{
        group::{Element, Scalar},
        ops::msm_interpolate,
        poly::{self, new_with_constant, Eval, Poly, Public, Weight},
        variant::Variant,
    },
    transcript::{Summary, Transcript},
    Digest, PublicKey, Signer,
};
use commonware_codec::{Encode, EncodeSize, RangeCfg, Read, ReadExt, Write};
use commonware_utils::{
    ordered::{Map, Quorum, Set},
    quorum, TryCollect, NZU32,
};
use core::num::NonZeroU32;
use rand_core::CryptoRngCore;
use rayon::{
    iter::{IntoParallelIterator, ParallelIterator as _},
    ThreadPoolBuilder,
};
use std::collections::BTreeMap;
use thiserror::Error;

const NAMESPACE: &[u8] = b"_COMMONWARE_BLS12381_DKG";
const SIG_ACK: &[u8] = b"ack";
const SIG_LOG: &[u8] = b"log";

/// The error type for the DKG protocol.
///
/// The only error which can happen through no fault of your own is
/// [`Error::DkgFailed`]. Everything else only happens if you use a configuration
/// for [`Info`] or [`Dealer`] which is invalid in some way.
#[derive(Debug, Error)]
pub enum Error {
    #[error("missing dealer's share from the previous round")]
    MissingDealerShare,
    #[error("player is not present in the list of players")]
    UnknownPlayer,
    #[error("dealer is not present in the previous list of players")]
    UnknownDealer(String),
    #[error("invalid number of dealers: {0}")]
    NumDealers(usize),
    #[error("invalid number of players: {0}")]
    NumPlayers(usize),
    #[error("duplicate players")]
    DuplicatePlayers,
    #[error("dkg failed for some reason")]
    DkgFailed,
}

/// Recover public polynomial by interpolating coefficient-wise all
/// polynomials using precomputed Barycentric Weights.
///
/// It is assumed that the required number of commitments are provided.
fn recover_public_with_weights<V: Variant>(
    commitments: &BTreeMap<u32, poly::Public<V>>,
    weights: &BTreeMap<u32, poly::Weight>,
    threshold: u32,
    concurrency: usize,
) -> poly::Public<V> {
    let work = |coeff| {
        // Extract evaluations for this coefficient from all commitments
        let evals = commitments
            .iter()
            .map(|(dealer, commitment)| poly::Eval {
                index: *dealer,
                value: commitment.get(coeff),
            })
            .collect::<Vec<_>>();

        // Use precomputed weights for interpolation
        msm_interpolate(weights, &evals).expect("interpolation should not fail")
    };
    let range = 0..threshold;
    if concurrency <= 1 || threshold <= 1 {
        range.map(work).collect()
    } else {
        // Build a thread pool with the specified concurrency
        let pool = ThreadPoolBuilder::new()
            .num_threads(concurrency)
            .build()
            .expect("Unable to build thread pool");

        // Recover signatures
        pool.install(move || {
            range
                .into_par_iter()
                .map(work)
                .collect::<Vec<_>>()
                .into_iter()
                .collect()
        })
    }
}

/// The output of a successful DKG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output<V: Variant, P> {
    summary: Summary,
    players: Set<P>,
    public: Public<V>,
}

impl<V: Variant, P: Ord> Output<V, P> {
    fn share_commitment(&self, player: &P) -> Option<V::Public> {
        Some(self.public.evaluate(self.players.index(player)?).value)
    }

    /// Return the quorum, i.e. the number of players needed to reconstruct the key.
    pub fn quorum(&self) -> u32 {
        self.players.quorum()
    }

    /// Get the public polynomial associated with this output.
    ///
    /// This is useful for verifying partial signatures, with [crate::bls12381::primitives::ops::partial_verify_message].
    pub const fn public(&self) -> &Public<V> {
        &self.public
    }

    /// Return the players who participated in this round of the DKG, and should have shares.
    pub const fn players(&self) -> &Set<P> {
        &self.players
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for Output<V, P> {
    fn encode_size(&self) -> usize {
        self.summary.encode_size() + self.players.encode_size() + self.public.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for Output<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.summary.write(buf);
        self.players.write(buf);
        self.public.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for Output<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &max_players: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            summary: ReadExt::read(buf)?,
            players: Read::read_cfg(buf, &(RangeCfg::new(1..=max_players.get() as usize), ()))?,
            public: Read::read_cfg(buf, &RangeCfg::from(NZU32!(1)..=max_players))?,
        })
    }
}

/// Information about the current round of the DKG.
///
/// This is used to bind signatures to the current round, and to provide the
/// information that dealers, players, and observers need to perform their actions.
#[derive(Debug, Clone)]
pub struct Info<V: Variant, P: PublicKey> {
    round: u64,
    previous: Option<Output<V, P>>,
    dealers: Set<P>,
    players: Set<P>,
    summary: Summary,
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
        mut rng: impl CryptoRngCore,
        share: Option<Scalar>,
    ) -> Result<Scalar, Error> {
        let out = match (self.previous.as_ref(), share) {
            (None, None) => Scalar::from_rand(&mut rng),
            (_, Some(x)) => x,
            (Some(_), None) => return Err(Error::MissingDealerShare),
        };
        Ok(out)
    }

    fn degree(&self) -> u32 {
        self.players.quorum().saturating_sub(1)
    }

    fn threshold(&self) -> u32 {
        self.degree() + 1
    }

    fn required_commitments(&self) -> u32 {
        let dealer_quorum = self.dealers.quorum();
        let prev_quorum = self
            .previous
            .as_ref()
            .map(Output::quorum)
            .unwrap_or(u32::MIN);
        dealer_quorum.max(prev_quorum)
    }

    fn max_reveals(&self) -> u32 {
        self.players.max_faults()
    }

    fn player_index(&self, player: &P) -> Result<u32, Error> {
        self.players.index(player).ok_or(Error::UnknownPlayer)
    }

    fn dealer_index(&self, dealer: &P) -> Result<u32, Error> {
        self.dealers
            .index(dealer)
            .ok_or(Error::UnknownDealer(format!("{dealer:?}")))
    }

    #[must_use]
    fn check_dealer_pub_msg(&self, dealer: &P, pub_msg: &DealerPubMsg<V>) -> bool {
        if self.degree() != pub_msg.commitment.degree() {
            return false;
        }
        if let Some(previous) = self.previous.as_ref() {
            let Some(share_commitment) = previous.share_commitment(dealer) else {
                return false;
            };
            if *pub_msg.commitment.constant() != share_commitment {
                return false;
            }
        }
        true
    }

    #[must_use]
    fn check_dealer_priv_msg(
        &self,
        player: &P,
        pub_msg: &DealerPubMsg<V>,
        priv_msg: &DealerPrivMsg,
    ) -> bool {
        let Ok(index) = self.player_index(player) else {
            return false;
        };
        pub_msg.check_share(&Share {
            index,
            private: priv_msg.share.clone(),
        })
    }
}

impl<V: Variant, P: PublicKey> Info<V, P> {
    /// Create a new [`Info`].
    ///
    /// `namespace` must be provided to isolate different applications
    /// performing DKGs from each other.
    /// `round` should be a counter, always incrementing, even for failed DKGs.
    /// `previous` should be the result of the previous successful DKG.
    /// `dealers` should be the list of public keys for the dealers. This MUST
    /// be a subset of the previous round's players.
    /// `players` should be the list of public keys for the players.
    pub fn new(
        namespace: &[u8],
        round: u64,
        previous: Option<Output<V, P>>,
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
            if let Some(unknown) = dealers
                .iter()
                .find(|d| previous.players.position(d).is_none())
            {
                return Err(Error::UnknownDealer(format!("{unknown:?}")));
            }
            if dealers.len() < previous.quorum() as usize {
                return Err(Error::NumDealers(dealers.len()));
            }
        }
        let summary = Transcript::new(NAMESPACE)
            .commit(namespace)
            .commit(round.encode())
            .commit(previous.encode())
            .commit(dealers.encode())
            .commit(players.encode())
            .summarize();
        Ok(Self {
            round,
            previous,
            dealers,
            players,
            summary,
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
    commitment: Public<V>,
}

impl<V: Variant> PartialEq for DealerPubMsg<V> {
    fn eq(&self, other: &Self) -> bool {
        self.commitment == other.commitment
    }
}

impl<V: Variant> Eq for DealerPubMsg<V> {}

impl<V: Variant> DealerPubMsg<V> {
    fn check_share(&self, share: &Share) -> bool {
        self.commitment.evaluate(share.index).value == share.public::<V>()
    }
}

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
            commitment: Read::read_cfg(buf, &RangeCfg::from(NZU32!(1)..=max_size))?,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DealerPrivMsg {
    share: Scalar,
}

impl std::fmt::Debug for DealerPrivMsg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DealerPrivMsg(REDACTED)")
    }
}

impl EncodeSize for DealerPrivMsg {
    fn encode_size(&self) -> usize {
        self.share.encode_size()
    }
}

impl Write for DealerPrivMsg {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.share.write(buf);
    }
}

impl Read for DealerPrivMsg {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            share: ReadExt::read(buf)?,
        })
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
    ) -> Option<impl Iterator<Item = (&'b P, &'a AckOrReveal<P>)>> {
        match &self.results {
            DealerResult::TooManyReveals => None,
            DealerResult::Ok(results) => {
                // We don't check this on deserialization.
                if results.keys() != players {
                    return None;
                }
                Some(players.iter().zip(results.values().iter()))
            }
        }
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

fn transcript_for_round<V: Variant, P: PublicKey>(info: &Info<V, P>) -> Transcript {
    Transcript::resume(info.summary)
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
    pub fn start(
        mut rng: impl CryptoRngCore,
        info: Info<V, S::PublicKey>,
        me: S,
        share: Option<Share>,
    ) -> Result<(Self, DealerPubMsg<V>, Vec<(S::PublicKey, DealerPrivMsg)>), Error> {
        // Check that this dealer is defined in the round.
        info.dealer_index(&me.public_key())?;
        let share = info.unwrap_or_random_share(&mut rng, share.map(|x| x.private))?;
        let my_poly = new_with_constant(info.degree(), &mut rng, share);
        let priv_msgs = info
            .players
            .iter()
            .enumerate()
            .map(|(i, pk)| {
                (
                    pk.clone(),
                    DealerPrivMsg {
                        share: my_poly.evaluate(i as u32).value,
                    },
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
    pub fn receive_player_ack(
        &mut self,
        player: S::PublicKey,
        ack: PlayerAck<S::PublicKey>,
    ) -> Result<(), Error> {
        let res_mut = self
            .results
            .get_value_mut(&player)
            .ok_or(Error::UnknownPlayer)?;
        if self.transcript.verify(&player, &ack.sig) {
            *res_mut = AckOrReveal::Ack(ack);
        }
        Ok(())
    }

    /// Finalize the dealer, producing a signed log.
    ///
    /// This should be called at the point where no more acks will be processed.
    pub fn finalize(self) -> SignedDealerLog<V, S> {
        let reveals = self
            .results
            .values()
            .iter()
            .filter(|x| x.is_reveal())
            .count() as u32;
        // Omit results if there are too many reveals.
        let results = if reveals > self.info.max_reveals() {
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

#[allow(clippy::type_complexity)]
fn select<V: Variant, P: PublicKey>(
    info: &Info<V, P>,
    logs: BTreeMap<P, DealerLog<V, P>>,
) -> Result<Vec<(P, DealerLog<V, P>)>, Error> {
    let required_commitments = info.required_commitments() as usize;
    let transcript = transcript_for_round(info);
    let out = logs
        .into_iter()
        .filter_map(|(dealer, log)| {
            info.dealer_index(&dealer).ok()?;
            if !info.check_dealer_pub_msg(&dealer, &log.pub_msg) {
                return None;
            }
            let results_iter = log.zip_players(&info.players)?;
            let transcript = transcript_for_ack(&transcript, &dealer, &log.pub_msg);
            let mut reveal_count = 0;
            let max_reveals = info.max_reveals();
            for (player, result) in results_iter {
                match result {
                    AckOrReveal::Ack(ack) => {
                        if !transcript.verify(player, &ack.sig) {
                            return None;
                        }
                    }
                    AckOrReveal::Reveal(priv_msg) => {
                        reveal_count += 1;
                        if reveal_count > max_reveals {
                            return None;
                        }
                        if !info.check_dealer_priv_msg(player, &log.pub_msg, priv_msg) {
                            return None;
                        }
                    }
                }
            }
            Some((dealer, log))
        })
        .take(required_commitments)
        .collect::<Vec<_>>();
    if out.len() < required_commitments {
        return Err(Error::DkgFailed);
    }
    Ok(out)
}

struct ObserveInner<V: Variant, P: PublicKey> {
    output: Output<V, P>,
    weights: Option<BTreeMap<u32, Weight>>,
}

impl<V: Variant, P: PublicKey> ObserveInner<V, P> {
    fn reckon(
        info: Info<V, P>,
        selected: Vec<(P, DealerLog<V, P>)>,
        concurrency: usize,
    ) -> Result<Self, Error> {
        let (public, weights) = if let Some(previous) = info.previous.as_ref() {
            let (indices, commitments) = selected
                .into_iter()
                .map(|(dealer, log)| {
                    let index = previous
                        .players()
                        .index(&dealer)
                        .expect("select checks that dealer exists, via our signature");
                    (index, (index, log.pub_msg.commitment))
                })
                .collect::<(Vec<_>, BTreeMap<_, _>)>();

            let weights =
                poly::compute_weights(indices).expect("should be able to compute weights");
            let public = recover_public_with_weights::<V>(
                &commitments,
                &weights,
                info.threshold(),
                concurrency,
            );
            if previous.public().constant() != public.constant() {
                return Err(Error::DkgFailed);
            }
            (public, Some(weights))
        } else {
            let mut public = Poly::zero();
            for (_, log) in selected.iter() {
                public.add(&log.pub_msg.commitment);
            }
            (public, None)
        };
        let output = Output {
            summary: info.summary,
            players: info.players,
            public,
        };
        Ok(Self { output, weights })
    }
}

/// Observe the result of a DKG, using the public results.
///
/// The log mapping dealers to their log is the shared piece of information
/// that the participants (players, observers) of the DKG must all agree on.
///
/// From this log, we can (potentially, as the DKG can fail) compute the public output.
///
/// This will only ever return [`Error::DkgFailed`].
pub fn observe<V: Variant, P: PublicKey>(
    info: Info<V, P>,
    logs: BTreeMap<P, DealerLog<V, P>>,
    concurrency: usize,
) -> Result<Output<V, P>, Error> {
    let selected = select(&info, logs)?;
    ObserveInner::<V, P>::reckon(info, selected, concurrency).map(|x| x.output)
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
    index: u32,
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
            index: info.player_index(&me_pub)?,
            me,
            me_pub,
            transcript: transcript_for_round(&info),
            info,
            view: BTreeMap::new(),
        })
    }

    /// Process a message from a dealer.
    ///
    /// It's important that nobody can impersonate the dealer, and that the
    /// private message was not exposed to anyone else. A convenient way to
    /// provide this is by using an authenticated channel, e.g. via
    /// [crate::handshake], or [commonware-p2p](https://docs.rs/commonware-p2p/latest/commonware_p2p/).
    pub fn dealer_message(
        &mut self,
        dealer: S::PublicKey,
        pub_msg: DealerPubMsg<V>,
        priv_msg: DealerPrivMsg,
    ) -> Option<PlayerAck<S::PublicKey>> {
        if self.view.contains_key(&dealer) {
            return None;
        }
        self.info.dealer_index(&dealer).ok()?;
        if !self.info.check_dealer_pub_msg(&dealer, &pub_msg) {
            return None;
        }
        if !self
            .info
            .check_dealer_priv_msg(&self.me_pub, &pub_msg, &priv_msg)
        {
            return None;
        }
        let sig = transcript_for_ack(&self.transcript, &dealer, &pub_msg).sign(&self.me);
        self.view.insert(dealer, (pub_msg, priv_msg));
        Some(PlayerAck { sig })
    }

    /// Finalize the player, producing an output, and a share.
    ///
    /// This should agree with [`observe`], in terms of `Ok` vs `Err` and the
    /// public output, so long as the logs agree. It's crucial that the players
    /// come to agreement, in some way, on exactly which logs they need to use
    /// for finalize.
    ///
    /// This will only ever return [`Error::DkgFailed`].
    pub fn finalize(
        self,
        logs: BTreeMap<S::PublicKey, DealerLog<V, S::PublicKey>>,
        concurrency: usize,
    ) -> Result<(Output<V, S::PublicKey>, Share), Error> {
        let selected = select(&self.info, logs)?;
        let dealings = selected
            .iter()
            .map(|(dealer, log)| {
                let share = self
                    .view
                    .get(dealer)
                    .map(|(_, priv_msg)| priv_msg.share.clone())
                    .unwrap_or_else(|| {
                        log.get_reveal(&self.me_pub).map_or_else(
                            || {
                                unreachable!(
                                    "select didn't check dealer reveal, or we're not a player?"
                                )
                            },
                            |priv_msg| priv_msg.share.clone(),
                        )
                    });
                let index = if let Some(previous) = self.info.previous.as_ref() {
                    previous
                        .players
                        .index(dealer)
                        .expect("select should check dealer")
                } else {
                    self.info
                        .dealer_index(dealer)
                        .expect("select should check dealer")
                };
                Eval {
                    index,
                    value: share,
                }
            })
            .collect::<Vec<_>>();
        let ObserveInner { output, weights } =
            ObserveInner::<V, S::PublicKey>::reckon(self.info, selected, concurrency)?;
        let private = if let Some(weights) = weights {
            poly::Private::recover_with_weights(&weights, dealings.iter())
                .expect("should be able to recover share")
        } else {
            let mut out = Scalar::zero();
            for s in dealings {
                out.add(&s.value);
            }
            out
        };
        let share = Share {
            index: self.index,
            private,
        };
        Ok((output, share))
    }
}

/// The result of dealing shares to players.
pub type DealResult<V, P> = Result<(Output<V, P>, Map<P, Share>), Error>;

/// Simply distribute shares at random, instead of performing a distributed protocol.
pub fn deal<V: Variant, P: Clone + Ord>(
    mut rng: impl CryptoRngCore,
    players: impl IntoIterator<Item = P>,
) -> DealResult<V, P> {
    let players: Set<_> = players
        .into_iter()
        .try_collect()
        .map_err(|_| Error::DuplicatePlayers)?;
    if players.is_empty() {
        return Err(Error::NumPlayers(0));
    }
    let t = quorum(players.len() as u32);
    let private = poly::new_from(t - 1, &mut rng);
    let shares: Map<_, _> = players
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let eval = private.evaluate(i as u32);
            let share = Share {
                index: eval.index,
                private: eval.value,
            };
            (p.clone(), share)
        })
        .try_collect()
        .expect("players are unique");
    let output = Output {
        summary: Summary::random(&mut rng),
        players,
        public: Poly::commit(private),
    };
    Ok((output, shares))
}

/// Like [`deal`], but without linking the result to specific public keys.
///
/// This can be more convenient for testing, where you don't want to go through
/// the trouble of generating signing keys. The downside is that the result isn't
/// compatible with subsequent DKGs, which need an [`Output`].
pub fn deal_anonymous<V: Variant>(
    rng: impl CryptoRngCore,
    n: NonZeroU32,
) -> (Poly<V::Public>, Vec<Share>) {
    let (output, shares) = deal::<V, _>(rng, 0..n.get()).expect("players is > 0");
    (output.public().clone(), shares.values().to_vec())
}

#[cfg(any(feature = "fuzz", test))]
mod test_plan {
    use super::*;
    use crate::{
        bls12381::primitives::{
            ops::{
                partial_sign_message, partial_verify_message, threshold_signature_recover,
                verify_message,
            },
            variant::Variant,
        },
        ed25519, PrivateKeyExt as _, PublicKey,
    };
    use anyhow::anyhow;
    use bytes::BytesMut;
    use commonware_utils::{max_faults, TryCollect};
    use core::num::NonZeroI32;
    use rand::{rngs::StdRng, SeedableRng as _};
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
        fn transcript_for_round<V: Variant, P: PublicKey>(
            &self,
            info: &Info<V, P>,
        ) -> anyhow::Result<(bool, Transcript)> {
            let mut summary_bs = info.summary.encode();
            let modified = apply_mask(&mut summary_bs, &self.info_summary);
            let summary = Summary::read(&mut summary_bs)?;
            Ok((modified, Transcript::resume(summary)))
        }

        fn transcript_for_player_ack<V: Variant, P: PublicKey>(
            &self,
            info: &Info<V, P>,
            dealer: &P,
            pub_msg: &DealerPubMsg<V>,
        ) -> anyhow::Result<(bool, Transcript)> {
            let (mut modified, transcript) = self.transcript_for_round(info)?;
            let mut transcript = transcript.fork(SIG_ACK);

            let mut dealer_bs = dealer.encode();
            modified |= apply_mask(&mut dealer_bs, &self.dealer);
            transcript.commit(&mut dealer_bs);

            let mut pub_msg_bs = pub_msg.encode();
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

            let mut log_bs = log.encode();
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

            // If there's a previous round, check dealer constraints
            if let Some(prev_players) = previous_players {
                // Every dealer must have been a player in the previous round
                for &d in &self.dealers {
                    if !prev_players.contains(&d) {
                        return Err(anyhow!("dealer {d} was not a player in previous round"));
                    }
                }
                // Must have >= quorum(prev_players) dealers
                let required = quorum(prev_players.len() as u32);
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
                let degree = quorum(self.players.len() as u32) as i32 - 1;
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
            revealed_players.len() as u32 > max_faults(self.players.len() as u32)
        }

        /// Determine if this round is expected to fail.
        fn expect_failure(&self, previous_successful_round: Option<u32>) -> bool {
            let good_dealer_count = self
                .dealers
                .iter()
                .filter(|&&d| !self.bad(previous_successful_round.is_some(), d))
                .count();
            let required = previous_successful_round
                .map(quorum)
                .unwrap_or_default()
                .max(quorum(self.dealers.len() as u32)) as usize;
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
        fn validate(&self) -> anyhow::Result<()> {
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

            let mut rng = StdRng::seed_from_u64(seed);

            // Generate keys for all participants (1-indexed to num_participants)
            let keys = (0..self.num_participants.get())
                .map(|_| ed25519::PrivateKey::from_rng(&mut rng))
                .collect::<Vec<_>>();
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
                let info = Info::new(
                    &[],
                    i_round as u64,
                    previous_output.clone(),
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

                // Run dealer protocol
                let mut dealer_logs = BTreeMap::new();
                for &i_dealer in &round.dealers {
                    let sk = keys[i_dealer as usize].clone();
                    let pk = sk.public_key();
                    let share = match (shares.get(&pk), round.replace_shares.contains(&i_dealer)) {
                        (None, _) => None,
                        (Some(s), false) => Some(s.clone()),
                        (Some(_), true) => Some(Share {
                            index: i_dealer,
                            private: Scalar::from_rand(&mut rng),
                        }),
                    };

                    // Start dealer (with potential modifications)
                    let (mut dealer, pub_msg, mut priv_msgs) =
                        if let Some(shift) = round.shift_degrees.get(&i_dealer) {
                            // Create dealer with shifted degree
                            let degree = u32::try_from(info.degree() as i32 + shift.get())
                                .unwrap_or_default();

                            // Manually create the dealer with adjusted polynomial
                            let share = info
                                .unwrap_or_random_share(&mut rng, share.map(|s| s.private))
                                .expect("Failed to generate dealer share");

                            let my_poly = poly::new_with_constant(degree, &mut rng, share);
                            let priv_msgs = info
                                .players
                                .iter()
                                .enumerate()
                                .map(|(i, pk)| {
                                    (
                                        pk.clone(),
                                        DealerPrivMsg {
                                            share: my_poly.evaluate(i as u32).value,
                                        },
                                    )
                                })
                                .collect::<Vec<_>>();
                            let results: Map<_, _> = priv_msgs
                                .iter()
                                .map(|(pk, pm)| (pk.clone(), AckOrReveal::Reveal(pm.clone())))
                                .try_collect()
                                .unwrap();
                            let commitment = poly::Poly::commit(my_poly);
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
                            Dealer::start(&mut rng, info.clone(), sk.clone(), share)?
                        };

                    // Apply BadShare perturbations
                    for (player, priv_msg) in &mut priv_msgs {
                        if let Some(i_player) = players.index(player) {
                            // Convert position to key index
                            let player_key_idx = round.players[i_player as usize];
                            if round.bad_shares.contains(&(i_dealer, player_key_idx)) {
                                priv_msg.share = Scalar::from_rand(&mut rng);
                            }
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
                            .ok_or_else(|| anyhow!("unknown player: {:?}", &player_pk))?;
                        // Convert position to key index for set lookups
                        let player_key_idx = round.players[i_player as usize];
                        let player = &mut players.values_mut()[i_player as usize];

                        let ack = player.dealer_message(pk.clone(), pub_msg.clone(), priv_msg);
                        assert_eq!(ack, ReadExt::read(&mut ack.encode())?);
                        if let Some(ack) = ack {
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
                    let signed_log = dealer.finalize();
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
                            assert!(num_reveals > info.max_reveals());
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
                                    .ok_or_else(|| anyhow!("unknown player: {:?}", &player_pk))? =
                                    AckOrReveal::Reveal(DealerPrivMsg {
                                        share: Scalar::from_rand(&mut rng),
                                    });
                            }
                        }
                    }
                    dealer_logs.insert(pk, log);
                }

                // Make sure that bad dealers are not selected.
                if let Ok(selection) = select(&info, dealer_logs.clone()) {
                    let good_pks = selection
                        .iter()
                        .map(|(pk, _)| pk.clone())
                        .collect::<BTreeSet<_>>();
                    for &i_dealer in &round.dealers {
                        if round.bad(previous_successful_round.is_some(), i_dealer) {
                            assert!(!good_pks.contains(&keys[i_dealer as usize].public_key()));
                        }
                    }
                }
                // Run observer
                let observe_result = observe(info.clone(), dealer_logs.clone(), 1);
                if round.expect_failure(previous_successful_round) {
                    assert!(
                        observe_result.is_err(),
                        "Round {i_round} should have failed but succeeded"
                    );
                    continue;
                }
                let observer_output = observe_result?;

                // Verify bad dealers were not selected
                // (This is implicit - if a bad dealer was selected, the DKG would fail
                // or produce incorrect results which we'd catch later)

                // Finalize each player
                for (player_pk, player) in players.into_iter() {
                    let (player_output, share) = player
                        .finalize(dealer_logs.clone(), 1)
                        .expect("Player finalize should succeed");

                    assert_eq!(
                        player_output, observer_output,
                        "Player output should match observer output"
                    );

                    // Verify share matches public polynomial
                    let expected_public = observer_output.public.evaluate(share.index);
                    let actual_public = share.public::<V>();
                    assert_eq!(
                        expected_public.value, actual_public,
                        "Share should match public polynomial"
                    );

                    shares.insert(player_pk.clone(), share);
                }

                // Initialize or verify threshold public key
                let current_public = *poly::public::<V>(observer_output.public());
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
                let namespace = Some(&b"test"[..]);

                let mut partial_sigs = Vec::new();
                for &i_player in &round.players {
                    let share = &shares[&keys[i_player as usize].public_key()];
                    let partial_sig = partial_sign_message::<V>(share, namespace, &test_message);

                    partial_verify_message::<V>(
                        &observer_output.public,
                        namespace,
                        &test_message,
                        &partial_sig,
                    )
                    .expect("Partial signature verification should succeed");

                    partial_sigs.push(partial_sig);
                }

                let threshold = observer_output.quorum();
                let threshold_sig = threshold_signature_recover::<V, _>(
                    threshold,
                    &partial_sigs[0..threshold as usize],
                )
                .expect("Should recover threshold signature");

                // Verify against the saved public key
                verify_message::<V>(
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

    #[cfg(feature = "fuzz")]
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
                let to_pick = u.int_in_range(players.quorum() as usize..=players.len())?;
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
                            let expected = quorum(players.len() as u32) as i32 - 1;
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
                        last_successful_players = Some(round.players.iter().cloned().collect());
                    }
                    rounds.push(round);
                    Ok(ControlFlow::Continue(()))
                })?;
                let plan = Plan {
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

#[cfg(feature = "fuzz")]
pub use test_plan::Plan as FuzzPlan;

#[cfg(test)]
mod test {
    use super::{test_plan::*, *};
    use crate::{bls12381::primitives::variant::MinPk, ed25519, PrivateKeyExt};
    use anyhow::anyhow;
    use core::num::NonZeroI32;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

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
    fn too_many_reveals() -> anyhow::Result<()> {
        Plan::new(NonZeroU32::new(4).unwrap())
            .with(
                Round::new(vec![0, 1, 2, 3], vec![0, 1, 2, 3])
                    .no_ack(0, 0)
                    .no_ack(0, 1),
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
    fn signed_dealer_log_commitment() -> Result<(), Error> {
        let sk = ed25519::PrivateKey::from_seed(0);
        let pk = sk.public_key();
        let info = Info::<MinPk, _>::new(
            &[],
            0,
            None,
            vec![sk.public_key()].try_into().unwrap(),
            vec![sk.public_key()].try_into().unwrap(),
        )?;
        let mut log0 = {
            let (dealer, _, _) = Dealer::start(
                &mut ChaCha8Rng::seed_from_u64(0),
                info.clone(),
                sk.clone(),
                None,
            )?;
            dealer.finalize()
        };
        let mut log1 = {
            let (mut dealer, pub_msg, priv_msgs) = Dealer::start(
                &mut ChaCha8Rng::seed_from_u64(0),
                info.clone(),
                sk.clone(),
                None,
            )?;
            let mut player = Player::new(info.clone(), sk)?;
            let ack = player
                .dealer_message(pk.clone(), pub_msg, priv_msgs[0].1.clone())
                .unwrap();
            dealer.receive_player_ack(pk, ack)?;
            dealer.finalize()
        };
        std::mem::swap(&mut log0.log, &mut log1.log);
        assert!(log0.check(&info).is_none());
        assert!(log1.check(&info).is_none());

        Ok(())
    }
}
