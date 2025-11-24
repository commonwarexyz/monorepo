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
//! - The final public polynomial (sum of dealer polynomials for DKG, interpolation for reshare)
//! - The list of players who received shares
//! - A digest for verification
//!
//! ## Utility Functions
//!
//! * [`deal`]: Generate shares non-interactively for testing (returns [`Output`] and shares)
//! * [`deal_anonymous`]: Lower-level version returning just polynomial and share vector
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
//! - External arbiters can exclude misbehaving dealers before calling [`observe`] or [`Player::finalize`]
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
//!     dkg::{Dealer, Player, Info, SignedDealerLog, observe},
//!     primitives::variant::MinSig,
//! };
//! use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
//! use commonware_utils::set::Ordered;
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
//! let dealer_set: Ordered<ed25519::PublicKey> = private_keys.iter()
//!     .map(|k| k.public_key())
//!     .collect();
//! let player_set = dealer_set.clone();
//!
//! // Step 1: Create round info for initial DKG
//! let round_info = Info::<MinSig, ed25519::PublicKey>::new(
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
//!         round_info.clone(),
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
//!         round_info.clone(),
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
//!     if let Some((dealer_pk, log)) = signed_log.check(&round_info) {
//!         dealer_logs.insert(dealer_pk, log);
//!     }
//! }
//!
//! // Step 4: Players finalize to get their shares
//! let mut player_shares = BTreeMap::new();
//! for (player_pk, player) in players {
//!     let (output, share) = player.finalize(dealer_logs.clone())?;
//!     println!("Player {:?} got share at index {}", player_pk, share.index);
//!     player_shares.insert(player_pk, share);
//! }
//!
//! // Step 5: Observer can also compute the public output
//! let observer_output = observe::<MinSig, ed25519::PublicKey>(
//!     round_info,
//!     dealer_logs,
//! )?;
//! println!("DKG completed with threshold {}", observer_output.quorum());
//! # Ok(())
//! # }
//! ```
//!
//! For a complete production example with resharing, see [commonware-reshare](https://docs.rs/commonware-reshare).
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
    max_faults, quorum,
    set::{Ordered, OrderedAssociated},
    NZU32,
};
use core::num::NonZeroU32;
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;
use thiserror::Error;

const NAMESPACE: &[u8] = b"commonware-bls12381-dkg";

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
    #[error("not enough dealers: {0}")]
    InsufficientDealers(usize),
    #[error("not enough players: {0}")]
    InsufficientPlayers(usize),
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
) -> poly::Public<V> {
    // Perform interpolation over each coefficient using the precomputed weights
    (0..threshold)
        .map(|coeff| {
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
        })
        .collect()
}

/// The output of a successful DKG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output<V: Variant, P> {
    summary: Summary,
    players: Ordered<P>,
    public: Public<V>,
}

impl<V: Variant, P: Ord> Output<V, P> {
    fn share_commitment(&self, player: &P) -> Option<V::Public> {
        let index = self.players.position(player)?;
        Some(self.public.evaluate(index as u32).value)
    }

    /// Return the qourum, i.e. the number of players needed to reconstruct the key.
    pub fn quorum(&self) -> u32 {
        quorum(self.players.len() as u32)
    }

    /// Get the public polynomial associated with this output.
    ///
    /// This is useful to verify partial signatures, with [crate::bls12381::primitives::ops::partial_verify_message].
    pub fn public(&self) -> &Public<V> {
        &self.public
    }

    /// Return the players who participated in this round of the DKG, and should have shares.
    pub fn players(&self) -> &Ordered<P> {
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
    dealers: Ordered<P>,
    players: Ordered<P>,
    /// Never written when encoded, always computed from the previous fields.
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
    fn generate_dealer_share_if_necessary(
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
        quorum(self.players.len() as u32).saturating_sub(1)
    }

    fn threshold(&self) -> u32 {
        self.degree() + 1
    }

    fn required_commitments(&self) -> u32 {
        let dealer_quorum = quorum(self.dealers.len() as u32);
        let prev_quorum = self
            .previous
            .as_ref()
            .map(Output::quorum)
            .unwrap_or(u32::MIN);
        dealer_quorum.max(prev_quorum)
    }

    fn max_reveals(&self) -> u32 {
        max_faults(self.players.len() as u32)
    }

    fn player_index(&self, player: &P) -> Result<u32, Error> {
        self.players
            .position(player)
            .map(|x| x as u32)
            .ok_or(Error::UnknownPlayer)
    }

    fn dealer_index(&self, dealer: &P) -> Result<u32, Error> {
        self.dealers
            .position(dealer)
            .map(|x| x as u32)
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
        pub_msg.check_share(index, &priv_msg.share)
    }
}

impl<V: Variant, P: PublicKey> Info<V, P> {
    /// Create a new [`Info`].
    ///
    /// `round` should be a counter, always incrementing, even for failed DKGs.
    /// `previous` should be the result of the previous successful DKG.
    /// `dealers` should be the list of public keys for the dealers. This MUST
    /// be a subset of the previous round's players.
    /// `players` should be the list of public keys for the players.
    pub fn new(
        round: u64,
        previous: Option<Output<V, P>>,
        dealers: Ordered<P>,
        players: Ordered<P>,
    ) -> Result<Self, Error> {
        let participant_range = 1..u32::MAX as usize;
        if !participant_range.contains(&dealers.len()) {
            return Err(Error::InsufficientDealers(dealers.len()));
        }
        if !participant_range.contains(&players.len()) {
            return Err(Error::InsufficientPlayers(players.len()));
        }
        if let Some(previous) = previous.as_ref() {
            if let Some(unknown) = dealers
                .iter()
                .find(|d| previous.players.position(d).is_none())
            {
                return Err(Error::UnknownDealer(format!("{unknown:?}")));
            }
            if dealers.len() < previous.quorum() as usize {
                return Err(Error::InsufficientDealers(dealers.len()));
            }
        }
        let summary = Transcript::new(NAMESPACE)
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
    pub fn round(&self) -> u64 {
        self.round
    }
}

impl<V: Variant, P: PublicKey> EncodeSize for Info<V, P> {
    fn encode_size(&self) -> usize {
        self.round.encode_size()
            + self.previous.encode_size()
            + self.dealers.encode_size()
            + self.players.encode_size()
    }
}

impl<V: Variant, P: PublicKey> Write for Info<V, P> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.round.write(buf);
        self.previous.write(buf);
        self.dealers.write(buf);
        self.players.write(buf);
    }
}

impl<V: Variant, P: PublicKey> Read for Info<V, P> {
    type Cfg = NonZeroU32;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        &max_players: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Self::new(
            ReadExt::read(buf)?,
            Read::read_cfg(buf, &max_players)?,
            Read::read_cfg(buf, &(RangeCfg::new(1..=max_players.get() as usize), ()))?,
            Read::read_cfg(buf, &(RangeCfg::new(1..=max_players.get() as usize), ()))?,
        )
        .map_err(|_| commonware_codec::Error::Invalid("Info", "validation"))
    }
}

#[derive(Clone, Debug)]
pub struct DealerPubMsg<V: Variant> {
    commitment: Public<V>,
}

impl<V: Variant> DealerPubMsg<V> {
    pub fn check_share(&self, index: u32, share: &Scalar) -> bool {
        let expected_element = {
            let mut out = V::Public::one();
            out.mul(share);
            out
        };
        self.commitment.evaluate(index).value == expected_element
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

#[derive(Clone)]
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
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            share: Read::read_cfg(buf, cfg)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PlayerAck<P: PublicKey> {
    sig: P::Signature,
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

#[derive(Clone)]
enum AckOrReveal<P: PublicKey> {
    Ack(PlayerAck<P>),
    Reveal(DealerPrivMsg),
}

impl<P: PublicKey> std::fmt::Debug for AckOrReveal<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AckOrReveal::Ack(x) => write!(f, "Ack({:?})", x),
            AckOrReveal::Reveal(_) => write!(f, "Reveal(REDACTED)"),
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
                1u8.write(buf);
                x.write(buf);
            }
            Self::Reveal(x) => {
                2u8.write(buf);
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
            1 => Ok(Self::Ack(ReadExt::read(buf)?)),
            2 => Ok(Self::Reveal(ReadExt::read(buf)?)),
            x => Err(commonware_codec::Error::InvalidEnum(x)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DealerLog<V: Variant, P: PublicKey> {
    pub_msg: DealerPubMsg<V>,
    results: Vec<AckOrReveal<P>>,
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
        &max_players: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            pub_msg: Read::read_cfg(buf, &max_players)?,
            results: Read::read_cfg(buf, &(RangeCfg::from(0..=max_players.get() as usize), ()))?,
        })
    }
}

impl<V: Variant, P: PublicKey> DealerLog<V, P> {
    fn zip_players<'a, 'b>(
        &'a self,
        players: &'b Ordered<P>,
    ) -> Option<impl Iterator<Item = (&'b P, &'a AckOrReveal<P>)>> {
        if self.results.len() != players.len() {
            return None;
        }
        Some(players.iter().zip(self.results.iter()))
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

impl<V: Variant, S: Signer> SignedDealerLog<V, S> {
    fn sign(sk: &S, round_info: &Info<V, S::PublicKey>, log: DealerLog<V, S::PublicKey>) -> Self {
        let sig = transcript_for_round(round_info)
            .commit(log.encode())
            .sign(sk);
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
        round_info: &Info<V, S::PublicKey>,
    ) -> Option<(S::PublicKey, DealerLog<V, S::PublicKey>)> {
        if !transcript_for_round(round_info)
            .commit(self.log.encode())
            .verify(&self.dealer, &self.sig)
        {
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

fn transcript_for_round<V: Variant, P: PublicKey>(round_info: &Info<V, P>) -> Transcript {
    Transcript::resume(round_info.summary)
}

fn transcript_for_dealer<V: Variant, P: PublicKey>(
    transcript: &Transcript,
    dealer: &P,
    pub_msg: &DealerPubMsg<V>,
) -> Transcript {
    let mut out = transcript.fork(b"dealer");
    out.commit(dealer.encode());
    out.commit(pub_msg.encode());
    out
}

pub struct Dealer<V: Variant, S: Signer> {
    me: S,
    round_info: Info<V, S::PublicKey>,
    pub_msg: DealerPubMsg<V>,
    results: Vec<AckOrReveal<S::PublicKey>>,
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
        round_info: Info<V, S::PublicKey>,
        me: S,
        share: Option<Share>,
    ) -> Result<(Self, DealerPubMsg<V>, Vec<(S::PublicKey, DealerPrivMsg)>), Error> {
        let share =
            round_info.generate_dealer_share_if_necessary(&mut rng, share.map(|x| x.private))?;
        let my_poly = new_with_constant(round_info.degree(), &mut rng, share.clone());
        let reveals = round_info
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
            .collect::<BTreeMap<_, _>>();
        let results = reveals
            .values()
            .cloned()
            .map(AckOrReveal::Reveal)
            .collect::<Vec<_>>();
        let priv_msgs = reveals.into_iter().collect::<Vec<_>>();
        let commitment = Poly::commit(my_poly);
        let pub_msg = DealerPubMsg { commitment };
        let transcript = {
            let t = transcript_for_round(&round_info);
            transcript_for_dealer(&t, &me.public_key(), &pub_msg)
        };
        let this = Self {
            me,
            round_info,
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
        let index = self.round_info.player_index(&player)?;
        if self.transcript.verify(&player, &ack.sig) {
            self.results[index as usize] = AckOrReveal::Ack(ack);
        }
        Ok(())
    }

    /// Finalize the dealer, producing a signed log.
    ///
    /// This should be called at the point where no more acks will be processed.
    pub fn finalize(self) -> SignedDealerLog<V, S> {
        let log = DealerLog {
            pub_msg: self.pub_msg,
            results: self.results,
        };
        SignedDealerLog::sign(&self.me, &self.round_info, log)
    }
}

#[allow(clippy::type_complexity)]
fn select<V: Variant, P: PublicKey>(
    round_info: &Info<V, P>,
    logs: BTreeMap<P, DealerLog<V, P>>,
) -> Result<Vec<(P, DealerLog<V, P>)>, Error> {
    let required_commitments = round_info.required_commitments() as usize;
    let transcript = transcript_for_round(round_info);
    let out = logs
        .into_iter()
        .filter_map(|(dealer, log)| {
            round_info.dealer_index(&dealer).ok()?;
            if !round_info.check_dealer_pub_msg(&dealer, &log.pub_msg) {
                return None;
            }
            let results_iter = log.zip_players(&round_info.players)?;
            let transcript = transcript_for_dealer(&transcript, &dealer, &log.pub_msg);
            let mut reveal_count = 0;
            let max_reveals = round_info.max_reveals();
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
                        if !round_info.check_dealer_priv_msg(player, &log.pub_msg, priv_msg) {
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
    fn reckon(round_info: Info<V, P>, selected: Vec<(P, DealerLog<V, P>)>) -> Result<Self, Error> {
        let (public, weights) = if let Some(previous) = round_info.previous.as_ref() {
            let (indices, commitments) = selected
                .into_iter()
                .map(|(dealer, log)| {
                    let index = previous
                        .players()
                        .position(&dealer)
                        .expect("select checks that dealer exists, via our signature")
                        as u32;
                    (index, (index, log.pub_msg.commitment))
                })
                .collect::<(Vec<_>, BTreeMap<_, _>)>();

            let weights =
                poly::compute_weights(indices).expect("should be able to compute weights");
            let public =
                recover_public_with_weights::<V>(&commitments, &weights, round_info.threshold());
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
            summary: round_info.summary,
            players: round_info.players,
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
    round_info: Info<V, P>,
    logs: BTreeMap<P, DealerLog<V, P>>,
) -> Result<Output<V, P>, Error> {
    let selected = select(&round_info, logs)?;
    ObserveInner::<V, P>::reckon(round_info, selected).map(|x| x.output)
}

/// Represents a player in the DKG / reshare process.
///
/// The player is attempting to get a share of the key.
///
/// They need not have participated in prior rounds.
pub struct Player<V: Variant, S: Signer> {
    me: S,
    me_pub: S::PublicKey,
    round_info: Info<V, S::PublicKey>,
    index: u32,
    transcript: Transcript,
    view: BTreeMap<S::PublicKey, (DealerPubMsg<V>, DealerPrivMsg)>,
}

impl<V: Variant, S: Signer> Player<V, S> {
    /// Create a new [`Player`].
    ///
    /// We need the player's private key in order to sign messages.
    pub fn new(round_info: Info<V, S::PublicKey>, me: S) -> Result<Self, Error> {
        let me_pub = me.public_key();
        Ok(Self {
            index: round_info.player_index(&me_pub)?,
            me,
            me_pub,
            transcript: transcript_for_round(&round_info),
            round_info,
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
        self.round_info.dealer_index(&dealer).ok()?;
        if !self.round_info.check_dealer_pub_msg(&dealer, &pub_msg) {
            return None;
        }
        if !self
            .round_info
            .check_dealer_priv_msg(&self.me_pub, &pub_msg, &priv_msg)
        {
            return None;
        }
        let sig = transcript_for_dealer(&self.transcript, &dealer, &pub_msg).sign(&self.me);
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
    ) -> Result<(Output<V, S::PublicKey>, Share), Error> {
        let selected = select(&self.round_info, logs)?;
        let dealings = selected
            .iter()
            .map(|(dealer, log)| {
                let index = self
                    .round_info
                    .dealer_index(dealer)
                    .expect("select checks that dealer exists, via our signature");
                let share = self
                    .view
                    .get(dealer)
                    .map(|(_, priv_msg)| priv_msg.share.clone())
                    .unwrap_or_else(|| match log.results.get(self.index as usize) {
                        Some(AckOrReveal::Reveal(priv_msg)) => priv_msg.share.clone(),
                        _ => {
                            unreachable!(
                                "select didn't check dealer reveal, or we're not a player?"
                            )
                        }
                    });
                // Make sure to use the right index, to interpolate over the previous round.
                let index = if let Some(previous) = self.round_info.previous.as_ref() {
                    previous
                        .players
                        .position(dealer)
                        .expect("select checks that dealer exists, via our signature")
                        as u32
                } else {
                    index
                };
                Eval {
                    index,
                    value: share,
                }
            })
            .collect::<Vec<_>>();
        let ObserveInner { output, weights } =
            ObserveInner::<V, S::PublicKey>::reckon(self.round_info, selected)?;
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

/// Simply distribute shares at random, instead of performing a distributed protocol.
pub fn deal<V: Variant, P: Clone + Ord>(
    mut rng: impl CryptoRngCore,
    players: impl IntoIterator<Item = P>,
) -> (Output<V, P>, OrderedAssociated<P, Share>) {
    let players = Ordered::from_iter(players);
    let t = quorum(players.len() as u32);
    let private = poly::new_from(&mut rng, t - 1);
    let shares: OrderedAssociated<_, _> = players
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
        .collect();
    let output = Output {
        summary: Summary::random(&mut rng),
        players,
        public: Poly::commit(private),
    };
    (output, shares)
}

/// Like [`deal`], but without linking the result to specific public keys.
///
/// This can be more convenient for testing, where you don't want to go through
/// the trouble of generating signing keys. The downside is that the result isn't
/// compatible with subsequent DKGs, which need an [`Output`].
pub fn deal_anonymous<V: Variant>(
    rng: impl CryptoRngCore,
    n: u32,
) -> (Poly<V::Public>, Vec<Share>) {
    let (output, shares) = deal::<V, _>(rng, 0..n);
    (output.public().clone(), shares.values().to_vec())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bls12381::primitives::{
            ops::{partial_sign_message, partial_verify_message, threshold_signature_recover},
            variant::{MinPk, MinSig},
        },
        ed25519, PrivateKeyExt,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use std::collections::BTreeSet;

    const MAX_IDENTITIES: u32 = 1000;

    #[derive(Clone, Default)]
    struct Round {
        dealers: Vec<u32>,
        players: Vec<u32>,
        missing_acks: BTreeSet<u32>,
        bad_reveals: BTreeMap<u32, BTreeSet<u32>>,
        expect_failure: bool,
    }

    impl Round {
        fn with_missing_ack(mut self, player: u32) -> Self {
            self.missing_acks.insert(player);
            self
        }

        fn with_bad_reveal(mut self, dealer: u32, player: u32) -> Self {
            self.bad_reveals.entry(dealer).or_default().insert(player);
            self
        }

        fn expect_failure(mut self) -> Self {
            self.expect_failure = true;
            self
        }
    }

    impl From<(Vec<u32>, Vec<u32>)> for Round {
        fn from((dealers, players): (Vec<u32>, Vec<u32>)) -> Self {
            Self {
                dealers,
                players,
                ..Default::default()
            }
        }
    }

    struct Plan {
        rounds: Vec<Round>,
    }

    impl From<Vec<Round>> for Plan {
        fn from(rounds: Vec<Round>) -> Self {
            Self { rounds }
        }
    }

    impl Plan {
        fn run_with_seed(self, seed: u64) {
            // NOTE: we map the sections of this test to the documentation
            // in the "Protocol Flow" section of the module docs.
            let max_read_size: NonZeroU32 = self
                .rounds
                .iter()
                .map(|round| round.dealers.len().max(round.players.len()) as u32)
                .max()
                .unwrap_or_default()
                .try_into()
                .expect("failed to calculate max read size");
            // Create a single RNG from the seed
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            // 1. Figure out the maximum index between dealers and players across all rounds.
            // Also, check that the dealers in round N + 1 are players in round N.
            let max_index = self
                .rounds
                .iter()
                .map(|round| {
                    round
                        .dealers
                        .iter()
                        .copied()
                        .chain(round.players.iter().copied())
                        .max()
                        .unwrap_or_default()
                })
                .max()
                .unwrap_or_default();
            // 2. Make sure this is a reasonable value (<= MAX_IDENTITIES).
            assert!(max_index <= MAX_IDENTITIES, "too many players for test",);
            let mut previous_output: Option<Output<MinSig, ed25519::PublicKey>> = None;
            let mut shares: BTreeMap<ed25519::PublicKey, Share> = BTreeMap::new();

            // 3. Generate the Ed25519 keys for each index, using the RNG.
            let mut keys = BTreeMap::new();
            for i in 0..=max_index {
                let signing_key = ed25519_consensus::SigningKey::new(&mut rng);
                let private_key = ed25519::PrivateKey::from(signing_key);
                keys.insert(i, private_key);
            }

            // 4. For each round, run the DKG, using, if necessary the previous output.
            for (round_idx, round) in self.rounds.into_iter().enumerate() {
                // 4.1 Create round info.
                let dealer_set = round
                    .dealers
                    .iter()
                    .map(|&idx| keys[&idx].public_key())
                    .collect::<Ordered<_>>();
                let player_set = round
                    .players
                    .iter()
                    .map(|&idx| keys[&idx].public_key())
                    .collect::<Ordered<_>>();

                let round_info = {
                    let round_info = Info::<MinSig, ed25519::PublicKey>::new(
                        round_idx as u64,
                        std::mem::take(&mut previous_output),
                        dealer_set.clone(),
                        player_set.clone(),
                    )
                    .expect("Failed to create round info");
                    let out: Info<MinSig, ed25519::PublicKey> =
                        Read::read_cfg(&mut round_info.encode(), &max_read_size)
                            .expect("should be able to deserialize Info");
                    assert_eq!(&round_info, &out);
                    out
                };

                // 4.2 Initialize players
                let mut players = BTreeMap::new();
                for &player_idx in &round.players {
                    let player = Player::<MinSig, ed25519::PrivateKey>::new(
                        round_info.clone(),
                        keys[&player_idx].clone(),
                    )
                    .expect("Failed to create player");
                    players.insert(keys[&player_idx].public_key(), (player_idx, player));
                }

                // 4.3 For each dealer:
                let mut log = BTreeMap::new();

                for dealer_idx in &round.dealers {
                    // 4.3.1 Generate the messages intended for the other players
                    let dealer_priv = keys[dealer_idx].clone();
                    let dealer_pub = dealer_priv.public_key();
                    // Get share from previous round if this dealer was a player
                    let share = shares.get(&dealer_pub).cloned();
                    let (mut dealer, pub_msg, priv_msgs) =
                        Dealer::<MinSig, ed25519::PrivateKey>::start(
                            &mut rng,
                            round_info.clone(),
                            dealer_priv.clone(),
                            share,
                        )
                        .expect("Failed to start dealer");

                    // 4.3.2 Have each player process the message, and the dealer process the ack.
                    for (player_id, priv_msg) in priv_msgs {
                        let (player_idx, player) =
                            players.get_mut(&player_id).expect("player should exist");
                        let pub_roundtrip = Read::read_cfg(&mut pub_msg.encode(), &max_read_size)
                            .expect("should be able to read dealer pub");
                        let priv_roundtrip = ReadExt::read(&mut priv_msg.encode())
                            .expect("should be able to read dealer pub");
                        // Don't send an ack back to the dealer if the round is setup that way.
                        if round.missing_acks.contains(player_idx) {
                            continue;
                        }
                        let ack = player
                            .dealer_message(dealer_pub.clone(), pub_roundtrip, priv_roundtrip)
                            .expect("player should ack valid dealer message");
                        dealer
                            .receive_player_ack(
                                player_id,
                                ReadExt::read(&mut ack.encode())
                                    .expect("should be able to decode player ack"),
                            )
                            .expect("should be able to accept ack");
                    }

                    let (dealer_pub, mut checked_log) =
                        SignedDealerLog::<_, ed25519::PrivateKey>::read_cfg(
                            &mut dealer.finalize().encode(),
                            &max_read_size,
                        )
                        .expect("should be able to read dealer log")
                        .check(&round_info)
                        .expect("check should succeed");
                    for &bad_reveal in round
                        .bad_reveals
                        .get(dealer_idx)
                        .iter()
                        .flat_map(|x| x.iter())
                    {
                        let bad_share = Scalar::from_rand(&mut rng);
                        checked_log.results[bad_reveal as usize] =
                            AckOrReveal::Reveal(DealerPrivMsg { share: bad_share });
                    }
                    log.insert(dealer_pub, checked_log);
                }

                // 4.5 Run the observer to get an output.
                let observe_res =
                    observe::<MinSig, ed25519::PublicKey>(round_info.clone(), log.clone());
                if round.expect_failure {
                    assert!(observe_res.is_err(), "expected round to fail");
                    continue;
                }
                let observer_output = observe_res.expect("Observer failed");

                // 4.6 Finalize each player, checking that its output is the same as the observer,
                // and remember its shares.
                let mut player_ids = Vec::with_capacity(players.len());
                for (player_id, (_, player)) in players {
                    print!("checking player: {:?}\n", &player_id);
                    let (player_output, share) = player
                        .finalize(log.clone())
                        .expect("Player finalize failed");

                    // Check that player output matches observer output
                    assert_eq!(player_output, observer_output);

                    // Verify the share matches the public polynomial
                    let expected_public = observer_output.public.evaluate(share.index);
                    let actual_public = {
                        let mut g = <MinSig as Variant>::Public::one();
                        g.mul(&share.private);
                        g
                    };
                    assert_eq!(expected_public.value, actual_public);

                    shares.insert(player_id.clone(), share);
                    player_ids.push(player_id)
                }

                // 4.7 Generate a signature, by using each player's share, and then recover a group signature.
                let test_message = format!("test message {}", round_idx).into_bytes();
                let namespace = Some(&b"test"[..]);

                // Create partial signatures from each player's share
                let mut partial_sigs = Vec::new();
                for player_id in player_ids {
                    let share = &shares[&player_id];
                    let partial_sig =
                        partial_sign_message::<MinSig>(share, namespace, &test_message);

                    // Verify partial signature
                    partial_verify_message::<MinSig>(
                        &observer_output.public,
                        namespace,
                        &test_message,
                        &partial_sig,
                    )
                    .expect("Partial signature verification failed");

                    partial_sigs.push(partial_sig);
                }

                // Recover threshold signature
                let threshold = observer_output.quorum();
                let threshold_sig = threshold_signature_recover::<MinSig, _>(
                    threshold,
                    &partial_sigs[0..threshold as usize],
                )
                .expect("Failed to recover threshold signature");

                // 4.8 Check this signature
                let threshold_public = poly::public::<MinSig>(observer_output.public());
                crate::bls12381::primitives::ops::verify_message::<MinSig>(
                    threshold_public,
                    namespace,
                    &test_message,
                    &threshold_sig,
                )
                .expect("Threshold signature verification failed");

                // Update state for next round
                previous_output = Some(observer_output);
            }
        }
    }

    #[test]
    fn test_dkg_single_round() {
        Plan::from(vec![Round::from((vec![0, 1, 2, 3], vec![0, 1, 2, 3]))]).run_with_seed(0);
    }

    #[test]
    fn test_dkg_multiple_rounds() {
        Plan::from(vec![Round::from((vec![0, 1, 2, 3], vec![0, 1, 2, 3])); 4]).run_with_seed(0);
    }

    #[test]
    fn test_dkg_changing_committee() {
        Plan::from(vec![
            Round::from((vec![0, 1, 2], vec![1, 2, 3])),
            Round::from((vec![1, 2, 3], vec![2, 3, 4])),
            Round::from((vec![2, 3, 4], vec![0, 1, 2])),
            Round::from((vec![0, 1, 2], vec![0, 1, 2])),
        ])
        .run_with_seed(0);
    }

    #[test]
    fn test_dkg_changing_committee_missing_ack() {
        Plan::from(vec![
            Round::from((vec![0, 1, 2, 3], vec![1, 2, 3, 4])).with_missing_ack(4),
            Round::from((vec![1, 2, 3, 4], vec![2, 3, 4, 0])).with_missing_ack(0),
            Round::from((vec![2, 3, 4, 0], vec![3, 4, 0, 1])).with_missing_ack(1),
            Round::from((vec![3, 4, 0, 1], vec![4, 0, 1, 2])).with_missing_ack(2),
            Round::from((vec![4, 0, 1, 2], vec![0, 1, 2, 3])).with_missing_ack(3),
        ])
        .run_with_seed(0);
    }

    #[test]
    fn test_dkg_increasing_decreasing_committee() {
        Plan::from(vec![
            Round::from((vec![0, 1], vec![0, 1, 2])),
            Round::from((vec![0, 1, 2], vec![0, 1, 2, 3])),
            Round::from((vec![0, 1, 2], vec![0, 1])),
            Round::from((vec![0, 1], vec![0, 1, 2, 3, 4])),
            Round::from((vec![0, 1, 2, 3], vec![0, 1])),
        ])
        .run_with_seed(0);
    }

    #[test]
    fn test_dkg_bad_reveal_fails() {
        Plan::from(vec![Round::from((vec![0], vec![0, 1, 2, 3]))
            .with_bad_reveal(0, 0)
            .expect_failure()])
        .run_with_seed(0);
    }

    #[test]
    fn test_signed_dealer_log_commitment() -> Result<(), Error> {
        let sk = ed25519::PrivateKey::from_seed(0);
        let pk = sk.public_key();
        let round_info = Info::<MinPk, _>::new(
            0,
            None,
            Ordered::from(vec![sk.public_key()]),
            Ordered::from(vec![sk.public_key()]),
        )?;
        let mut log0 = {
            let (dealer, _, _) = Dealer::start(
                &mut ChaCha8Rng::seed_from_u64(0),
                round_info.clone(),
                sk.clone(),
                None,
            )?;
            dealer.finalize()
        };
        let mut log1 = {
            let (mut dealer, pub_msg, priv_msgs) = Dealer::start(
                &mut ChaCha8Rng::seed_from_u64(0),
                round_info.clone(),
                sk.clone(),
                None,
            )?;
            let mut player = Player::new(round_info.clone(), sk.clone())?;
            let ack = player
                .dealer_message(pk.clone(), pub_msg, priv_msgs[0].1.clone())
                .unwrap();
            dealer.receive_player_ack(pk, ack)?;
            dealer.finalize()
        };
        std::mem::swap(&mut log0.log, &mut log1.log);
        assert!(log0.check(&round_info).is_none());
        assert!(log1.check(&round_info).is_none());

        Ok(())
    }
}
