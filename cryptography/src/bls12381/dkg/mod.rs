//! Distributed Key Generation (DKG) and Resharing protocol for the BLS12-381 curve.
//!
//! This crate implements an interactive Distributed Key Generation (DKG) and Resharing protocol
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
//! The protocol has three types of participants: arbiters, dealers, and players. The arbiter
//! serves as an orchestrator that collects commitments, acknowledgements, and reveals from
//! dealers/players and replicates them to all dealers/players. The arbiter can be implemented as
//! a standalone process or by some consensus protocol. Dealers generate commitments/shares and collect
//! acknowledgements from players. Players receive shares from dealers, validate them, and send acknowledgements
//! back to dealers. It is possible to be both a dealer and a player in the protocol.
//!
//! Whether or not the protocol succeeds, the dealers that did not post valid commitments/acks/reveals are
//! identified and returned. If the protocol succeeds, any dealers that did not post valid commitments/acks/reveals
//! are identified (and still returned). It is expected that the set of participants would punish/exclude
//! "bad" dealers prior to a future round (to eventually make progress).
//!
//! # Specification
//!
//! ## Assumptions
//!
//! * Let `t` be the maximum amount of time it takes for a message to be sent between any two participants.
//! * Each participant has an encrypted channel to every other participant.
//! * There exist `3f + 1` participants and at most `f` static Byzantine faults.
//!
//! ## [Arbiter] Step 0: Start Round
//!
//! Send a message to all participants to start a round. If this is a reshare, include the group polynomial from
//! the last successful round.
//!
//! ## [Dealer] Step 1: Generate Commitment and Dealings
//!
//! Upon receiving start message from arbiter, generate commitment and dealings. If it is a DKG, the commitment is
//! a random polynomial of degree `2f`. If it is a reshare, the commitment must be consistent with the
//! previous group polynomial.
//!
//! ## [Dealer] Step 2: Distribute Commitment and Dealings
//!
//! Distribute generated commitment and corresponding dealings to each player over an encrypted channel.
//!
//! ## [Player] Step 3: Verify Dealing and Send Acknowledgement
//!
//! Verify incoming dealing against provided commitment (additionally comparing the commitment to the previous group
//! polynomial, if reshare). If the dealing is valid, send an acknowledgement back to the dealer.
//!
//! To protect against a dealer sending different commitments to different players, players must sign this
//! acknowledgement over `(dealer, commitment)`.
//!
//! ## [Dealer] Step 4: Collect Acknowledgements and Send to Arbiter
//!
//! Collect acknowledgements from players. After `2t` has elapsed since Step 1 (up to `3t` from Step 0), check to
//! see if at least `2f + 1` acknowledgements have been received (including self, if a player as well). If so, send the
//! commitment, acknowledgements, and unencrypted dealings of players that did not send an acknowledgement to the
//! arbiter. If not, exit.
//!
//! ## [Arbiter] Step 5: Select Commitments and Forward Reveals
//!
//! Select the first `2f + 1` commitments with at most `f` reveals. Forward these `2f + 1` commitments
//! (and any reveals associated with each) to all players. If there do not exist `2f + 1` commitments with
//! at most `f` reveals by time `4t`, exit.
//!
//! ## [Player] Step 6: Recover Group Polynomial and Derive Share
//!
//! If the round is successful, each player will receive `2f + 1` commitments and any dealings associated with said
//! commitments they did not acknowledge (or that the dealer said they didn't acknowledge). With this, they can recover
//! the new group polynomial and derive their share of the secret. If this distribution is not received by time `5t`, exit.
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
//! ## Tracking Complaints
//!
//! This crate does not provide an integrated mechanism for tracking complaints from players (of malicious dealers). However, it is
//! possible to implement your own mechanism and to manually disqualify dealers from a given round in the arbiter. This decision was made
//! because the mechanism for communicating commitments/shares/acknowledgements is highly dependent on the context in which this
//! construction is used.
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
//! For a complete example of how to instantiate this crate, check out [commonware-vrf](https://docs.rs/commonware-vrf).

pub mod arbiter;
pub use arbiter::Arbiter;
pub mod dealer;
pub use dealer::Dealer;
pub mod ops;
pub mod player;
pub use player::Player;
pub mod types;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unexpected polynomial")]
    UnexpectedPolynomial,
    #[error("commitment has wrong degree")]
    CommitmentWrongDegree,
    #[error("misdirected share")]
    MisdirectedShare,
    #[error("share does not on commitment")]
    ShareWrongCommitment,
    #[error("insufficient dealings")]
    InsufficientDealings,
    #[error("reshare mismatch")]
    ReshareMismatch,
    #[error("share interpolation failed")]
    ShareInterpolationFailed,
    #[error("public key interpolation failed")]
    PublicKeyInterpolationFailed,
    #[error("dealer is invalid")]
    DealerInvalid,
    #[error("player invalid")]
    PlayerInvalid,
    #[error("missing share")]
    MissingShare,
    #[error("missing commitment")]
    MissingCommitment,
    #[error("too many commitments")]
    TooManyCommitments,
    #[error("duplicate commitment")]
    DuplicateCommitment,
    #[error("duplicate share")]
    DuplicateShare,
    #[error("duplicate ack")]
    DuplicateAck,
    #[error("mismatched commitment")]
    MismatchedCommitment,
    #[error("mismatched share")]
    MismatchedShare,
    #[error("too many reveals")]
    TooManyReveals,
    #[error("incorrect active")]
    IncorrectActive,
    #[error("already active")]
    AlreadyActive,
    #[error("invalid commitments")]
    InvalidCommitments,
    #[error("dealer disqualified")]
    DealerDisqualified,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bls12381::primitives::{
            ops::{
                partial_sign_proof_of_possession, threshold_signature_recover,
                verify_proof_of_possession,
            },
            poly::{self, public},
            variant::{MinPk, MinSig, Variant},
        },
        ed25519::{PrivateKey, PublicKey},
        PrivateKeyExt as _, Signer as _,
    };
    use commonware_utils::{quorum, set::Set};
    use rand::{rngs::StdRng, SeedableRng};
    use std::collections::{BTreeMap, HashMap};

    #[test]
    fn test_invalid_commitment() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, _, shares) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create unrelated commitment of correct degree
        let t = quorum(n);
        let (public, _) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, t);

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send invalid commitment to player
        let result = player.share(contributors[0].clone(), public, shares[0].clone());
        assert!(matches!(result, Err(Error::ShareWrongCommitment)));
    }

    #[test]
    fn test_mismatched_commitment() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create unrelated commitment of correct degree
        let t = quorum(n);
        let (other_commitment, _) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, t);

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send valid commitment to player
        player
            .share(contributors[0].clone(), commitment, shares[0].clone())
            .unwrap();

        // Send alternative commitment to player
        let result = player.share(contributors[0].clone(), other_commitment, shares[0].clone());
        assert!(matches!(result, Err(Error::MismatchedCommitment)));
    }

    #[test]
    fn test_mismatched_share() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create unrelated commitment of correct degree
        let t = quorum(n);
        let (_, other_shares) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, t);

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send valid share to player
        player
            .share(
                contributors[0].clone(),
                commitment.clone(),
                shares[0].clone(),
            )
            .unwrap();

        // Send alternative share to player
        let result = player.share(contributors[0].clone(), commitment, other_shares[0].clone());
        assert!(matches!(result, Err(Error::MismatchedShare)));
    }

    #[test]
    fn test_duplicate_share() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send valid share to player
        player
            .share(
                contributors[0].clone(),
                commitment.clone(),
                shares[0].clone(),
            )
            .unwrap();

        // Send alternative share to player
        let result = player.share(contributors[0].clone(), commitment, shares[0].clone());
        assert!(matches!(result, Err(Error::DuplicateShare)));
    }

    #[test]
    fn test_misdirected_share() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send misdirected share to player
        let result = player.share(
            contributors[0].clone(),
            commitment.clone(),
            shares[1].clone(),
        );
        assert!(matches!(result, Err(Error::MisdirectedShare)));
    }

    #[test]
    fn test_invalid_dealer() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send share from invalid dealer
        let dealer = PrivateKey::from_seed(n as u64).public_key();
        let result = player.share(dealer.clone(), commitment.clone(), shares[0].clone());
        assert!(matches!(result, Err(Error::DealerInvalid)));

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Send commitment from invalid dealer
        let result = arb.commitment(dealer, commitment, vec![0, 1, 2, 3], Vec::new());
        assert!(matches!(result, Err(Error::DealerInvalid)));
    }

    #[test]
    fn test_invalid_commitment_degree() {
        // Initialize test
        let n = 5;
        let t = quorum(n);
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create invalid commitments
        let mut commitments = Vec::new();
        let (public, shares) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, 1);
        commitments.push((public, shares));
        let (public, shares) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, t - 1);
        commitments.push((public, shares));
        let (public, shares) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, t + 1);
        commitments.push((public, shares));

        // Check invalid commitments
        for (public, shares) in commitments {
            // Send invalid commitment to player
            let mut player = Player::<_, MinSig>::new(
                contributors[0].clone(),
                None,
                contributors.clone(),
                contributors.clone(),
                1,
            );
            let result = player.share(contributors[0].clone(), public.clone(), shares[0].clone());
            assert!(matches!(result, Err(Error::CommitmentWrongDegree)));

            // Create arbiter
            let mut arb =
                Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);
            let result = arb.commitment(
                contributors[0].clone(),
                public,
                vec![0, 1, 2, 3, 4],
                Vec::new(),
            );
            assert!(matches!(result, Err(Error::CommitmentWrongDegree)));
        }
    }

    #[test]
    fn test_reveal() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3],
            vec![shares[4].clone()],
        )
        .unwrap();
    }

    #[test]
    fn test_arbiter_reveals() {
        // Initialize test
        let n = 11;
        let q = quorum(n as u32) as usize;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Create dealers
        let mut commitments = Vec::with_capacity(n);
        let mut reveals = Vec::with_capacity(n);
        for con in &contributors {
            // Create dealer
            let (_, commitment, shares) =
                Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
            commitments.push(commitment.clone());
            reveals.push(shares[q].clone());

            // Add commitment to arbiter
            let acks: Vec<u32> = (0..q as u32).collect();
            let reveals = shares[q..n].to_vec();
            arb.commitment(con.clone(), commitment, acks, reveals)
                .unwrap();
        }

        // Finalize arbiter
        let (result, _) = arb.finalize();
        let output = result.unwrap();

        // Ensure commitments and reveals are correct
        assert_eq!(output.commitments.len(), q);
        for (dealer_idx, commitment) in commitments.iter().enumerate().take(q) {
            let dealer_idx = dealer_idx as u32;
            assert_eq!(output.commitments.get(&dealer_idx).unwrap(), commitment);
            assert_eq!(
                output.reveals.get(&dealer_idx).unwrap()[0],
                reveals[dealer_idx as usize]
            );
        }
    }

    #[test]
    fn test_duplicate_commitment() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        arb.commitment(
            contributors[0].clone(),
            commitment.clone(),
            vec![0, 1, 2, 3],
            vec![shares[4].clone()],
        )
        .unwrap();

        // Add commitment to arbiter (again)
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3],
            vec![shares[4].clone()],
        );
        assert!(matches!(result, Err(Error::DuplicateCommitment)));
    }

    #[test]
    fn test_reveal_duplicate_player() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3],
            vec![shares[3].clone()],
        );
        assert!(matches!(result, Err(Error::AlreadyActive)));
    }

    #[test]
    fn test_insufficient_active() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            commitment.clone(),
            vec![0, 1, 2, 3],
            Vec::new(),
        );
        assert!(matches!(result, Err(Error::IncorrectActive)));

        // Add valid commitment to arbiter after disqualified
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3, 4],
            Vec::new(),
        );
        assert!(matches!(result, Err(Error::DealerDisqualified)));
    }

    #[test]
    fn test_manual_disqualify() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Disqualify dealer
        arb.disqualify(contributors[0].clone());

        // Add valid commitment to arbiter after disqualified
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3, 4],
            Vec::new(),
        );
        assert!(matches!(result, Err(Error::DealerDisqualified)));
    }

    #[test]
    fn test_too_many_reveals() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2],
            vec![shares[3].clone(), shares[4].clone()],
        );
        assert!(matches!(result, Err(Error::TooManyReveals)));
    }

    #[test]
    fn test_incorrect_reveal() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create invalid shares
        let t = quorum(n);
        let (_, shares) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, t);

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3],
            vec![shares[4].clone()],
        );
        assert!(matches!(result, Err(Error::ShareWrongCommitment)));
    }

    #[test]
    fn test_reveal_corrupt_share() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Swap share value
        let mut share = shares[3].clone();
        share.index = 4;

        // Add commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3],
            vec![share],
        );
        assert!(matches!(result, Err(Error::ShareWrongCommitment)));
    }

    #[test]
    fn test_reveal_duplicate_ack() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 2],
            Vec::new(),
        );
        assert!(matches!(result, Err(Error::AlreadyActive)));
    }

    #[test]
    fn test_reveal_invalid_ack() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 10],
            Vec::new(),
        );
        assert!(matches!(result, Err(Error::PlayerInvalid)));
    }

    #[test]
    fn test_reveal_invalid_share() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb =
            Arbiter::<_, MinSig>::new(None, contributors.clone(), contributors.clone(), 1);

        // Swap share value
        let mut share = shares[3].clone();
        share.index = 10;

        // Add commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3],
            vec![share],
        );
        assert!(matches!(result, Err(Error::PlayerInvalid)));
    }

    #[test]
    fn test_dealer_acks() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (mut dealer, _, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Ack all players
        for player in &contributors {
            dealer.ack(player.clone()).unwrap();
        }

        // Finalize dealer
        let output = dealer.finalize().unwrap();
        assert_eq!(Vec::from(output.active), vec![0, 1, 2, 3, 4]);
        assert!(output.inactive.is_empty());
    }

    #[test]
    fn test_dealer_inactive() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (mut dealer, _, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Ack all players
        for player in contributors.iter().take(4) {
            dealer.ack(player.clone()).unwrap();
        }

        // Finalize dealer
        let output = dealer.finalize().unwrap();
        assert_eq!(Vec::from(output.active), vec![0, 1, 2, 3]);
        assert_eq!(Vec::from(output.inactive), vec![4]);
    }

    #[test]
    fn test_dealer_insufficient() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (mut dealer, _, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Ack all players
        for player in contributors.iter().take(2) {
            dealer.ack(player.clone()).unwrap();
        }

        // Finalize dealer
        assert!(dealer.finalize().is_none());
    }

    #[test]
    fn test_dealer_duplicate_ack() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (mut dealer, _, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Ack player
        let player = contributors[0].clone();
        dealer.ack(player.clone()).unwrap();

        // Ack player (again)
        let result = dealer.ack(player);
        assert!(matches!(result, Err(Error::DuplicateAck)));
    }

    #[test]
    fn test_dealer_invalid_player() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create dealer
        let (mut dealer, _, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());

        // Ack invalid player
        let player = PrivateKey::from_seed(n as u64).public_key();
        let result = dealer.ack(player);
        assert!(matches!(result, Err(Error::PlayerInvalid)));
    }

    #[test]
    fn test_player_reveals() {
        // Initialize test
        let n = 11;
        let q = quorum(n as u32) as usize;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = BTreeMap::new();
        for (i, con) in contributors.iter().enumerate().take(q - 1) {
            let (_, commitment, shares) =
                Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0].clone())
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let last = (q - 1) as u32;
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
        commitments.insert(last, commitment);
        let mut reveals = BTreeMap::new();
        reveals.insert(last, shares[0].clone());
        player.finalize(commitments, reveals).unwrap();
    }

    #[test]
    fn test_player_missing_reveal() {
        // Initialize test
        let n = 11;
        let q = quorum(n as u32) as usize;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = BTreeMap::new();
        for (i, con) in contributors.iter().enumerate().take(q - 1) {
            let (_, commitment, shares) =
                Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0].clone())
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let last = (q - 1) as u32;
        let (_, commitment, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
        commitments.insert(last, commitment);
        let result = player.finalize(commitments, BTreeMap::new());
        assert!(matches!(result, Err(Error::MissingShare)));
    }

    #[test]
    fn test_player_insufficient_commitments() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = BTreeMap::new();
        for (i, con) in contributors.iter().enumerate().take(2) {
            let (_, commitment, shares) =
                Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0].clone())
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let result = player.finalize(commitments, BTreeMap::new());
        assert!(matches!(result, Err(Error::InvalidCommitments)));
    }

    #[test]
    fn test_player_misdirected_reveal() {
        // Initialize test
        let n = 11;
        let q = quorum(n as u32) as usize;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = BTreeMap::new();
        for (i, con) in contributors.iter().enumerate().take(q - 1) {
            let (_, commitment, shares) =
                Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0].clone())
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let last = (q - 1) as u32;
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
        commitments.insert(last, commitment);
        let mut reveals = BTreeMap::new();
        reveals.insert(last, shares[1].clone());
        let result = player.finalize(commitments, reveals);
        assert!(matches!(result, Err(Error::MisdirectedShare)));
    }

    #[test]
    fn test_player_invalid_commitment() {
        // Initialize test
        let n = 11;
        let q = quorum(n as u32) as usize;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = BTreeMap::new();
        for (i, con) in contributors.iter().enumerate().take(q - 1) {
            let (_, commitment, shares) =
                Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0].clone())
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let last = (q - 1) as u32;
        let (commitment, shares) = ops::generate_shares::<_, MinSig>(&mut rng, None, n as u32, 1);
        commitments.insert(last, commitment);
        let mut reveals = BTreeMap::new();
        reveals.insert(last, shares[0].clone());
        let result = player.finalize(commitments, reveals);
        assert!(matches!(result, Err(Error::CommitmentWrongDegree)));
    }

    #[test]
    fn test_player_invalid_reveal() {
        // Initialize test
        let n = 11;
        let q = quorum(n as u32) as usize;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = BTreeMap::new();
        for (i, con) in contributors.iter().enumerate().take(q - 1) {
            let (_, commitment, shares) =
                Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0].clone())
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let last = (q - 1) as u32;
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
        commitments.insert(last, commitment);
        let mut reveals = BTreeMap::new();
        let mut share = shares[1].clone();
        share.index = 0;
        reveals.insert(last, share);
        let result = player.finalize(commitments, reveals);
        assert!(matches!(result, Err(Error::ShareWrongCommitment)));
    }

    #[test]
    fn test_player_dealer_equivocation() {
        // Initialize test
        let n = 11;
        let q = quorum(n as u32) as usize;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = BTreeMap::new();
        for (i, con) in contributors.iter().enumerate().take(q - 1) {
            let (_, commitment, shares) =
                Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0].clone())
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with equivocating reveal
        let last = (q - 1) as u32;
        let (_, commitment, shares) =
            Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
        commitments.insert(last, commitment);

        // Add commitments
        let mut public = poly::Public::<MinSig>::zero();
        for commitment in commitments.values() {
            public.add(commitment);
        }

        // Finalize player with equivocating reveal
        let mut reveals = BTreeMap::new();
        reveals.insert(last, shares[0].clone());
        let result = player.finalize(commitments, reveals).unwrap();
        assert_eq!(result.public, public);
    }

    #[test]
    fn test_player_dealer_equivocation_missing_reveal() {
        // Initialize test
        let n = 11;
        let q = quorum(n as u32) as usize;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let contributors = (0..n)
            .map(|i| PrivateKey::from_seed(i as u64).public_key())
            .collect::<Set<_>>();

        // Create player
        let mut player = Player::<_, MinSig>::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = BTreeMap::new();
        for (i, con) in contributors.iter().enumerate().take(q - 1) {
            let (_, commitment, shares) =
                Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0].clone())
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with equivocating reveal
        let last = (q - 1) as u32;
        let (_, commitment, _) = Dealer::<_, MinSig>::new(&mut rng, None, contributors.clone());
        commitments.insert(last, commitment);

        // Finalize player with equivocating reveal
        let result = player.finalize(commitments, BTreeMap::new());
        assert!(matches!(result, Err(Error::MissingShare)));
    }

    /// Configuration for a single DKG/Resharing round.
    #[derive(Clone)]
    struct Round {
        players: Vec<u64>,
        absent_dealers: Vec<u64>,
        absent_players: Vec<u64>,
    }

    impl From<Vec<u64>> for Round {
        fn from(players: Vec<u64>) -> Self {
            Self {
                players,
                absent_dealers: Vec::new(),
                absent_players: Vec::new(),
            }
        }
    }

    impl Round {
        fn with_absent_dealers(mut self, absent_dealers: Vec<u64>) -> Self {
            self.absent_dealers = absent_dealers;
            self
        }

        fn with_absent_players(mut self, absent_players: Vec<u64>) -> Self {
            self.absent_players = absent_players;
            self
        }
    }

    /// Configuration for a sequence of DKG/Resharing rounds.
    #[derive(Clone)]
    struct Plan {
        rounds: Vec<Round>,
        seed: u64,
        concurrency: usize,
    }

    impl Plan {
        fn from(rounds: Vec<Round>) -> Self {
            Self {
                rounds,
                seed: 0,
                concurrency: 1,
            }
        }

        fn with_concurrency(mut self, concurrency: usize) -> Self {
            self.concurrency = concurrency;
            self
        }

        fn with_seed(mut self, seed: u64) -> Self {
            self.seed = seed;
            self
        }

        fn run<V: Variant>(&self) -> V::Public {
            // We must have at least one round to execute
            assert!(
                !self.rounds.is_empty(),
                "plan must contain at least one round"
            );

            // Create seeded RNG (for determinism)
            let mut rng = StdRng::seed_from_u64(self.seed);
            let mut current_public: Option<poly::Public<V>> = None;
            let mut participant_states: HashMap<PublicKey, player::Output<V>> = HashMap::new();
            let mut share_holders: Option<Set<PublicKey>> = None;

            // Process rounds
            for (round_idx, round) in self.rounds.iter().enumerate() {
                // Materialize dealer/player sets
                assert!(
                    !round.players.is_empty(),
                    "round {round_idx} must include at least one player",
                );
                let player_set = participants(&round.players);
                let dealer_candidates = if let Some(ref registry) = share_holders {
                    registry.clone()
                } else {
                    // If no previous share holders, use all players as dealers
                    player_set.clone()
                };
                assert!(
                    !dealer_candidates.is_empty(),
                    "round {round_idx} must have at least one dealer",
                );

                // Configure absent dealers and players
                let absent_dealers = participants(&round.absent_dealers);
                for absent in absent_dealers.iter() {
                    assert!(
                        dealer_candidates.position(absent).is_some(),
                        "round {round_idx} absent dealer not in committee"
                    );
                }
                let dealer_registry = if let Some(ref registry) = share_holders {
                    for dealer in dealer_candidates.iter() {
                        assert!(
                            registry.position(dealer).is_some(),
                            "round {round_idx} dealer not in previous committee",
                        );
                    }
                    registry.clone()
                } else {
                    dealer_candidates.clone()
                };
                let mut active_dealers = Vec::new();
                for dealer in dealer_candidates.iter() {
                    if absent_dealers.position(dealer).is_some() {
                        continue;
                    }
                    active_dealers.push(dealer.clone());
                }
                let active_len = active_dealers.len();
                let min_dealers = match current_public.as_ref() {
                    None => quorum(player_set.len() as u32),
                    Some(previous) => previous.required(),
                } as usize;
                assert!(
                    active_len >= min_dealers,
                    "round {} requires at least {} active dealers for {} players, got {}",
                    round_idx,
                    min_dealers,
                    player_set.len(),
                    active_len
                );
                let absent_players = participants(&round.absent_players);
                for absent in absent_players.iter() {
                    assert!(
                        player_set.position(absent).is_some(),
                        "round {round_idx} absent player not in committee"
                    );
                }

                // Setup dealers
                let mut dealers = BTreeMap::new();
                let mut dealer_outputs = BTreeMap::new();
                let mut expected_reveals = BTreeMap::new();
                let expected_inactive: Set<u32> = absent_players
                    .iter()
                    .map(|player_pk| player_set.position(player_pk).unwrap() as u32)
                    .collect();
                for dealer_pk in active_dealers.iter() {
                    let previous_share = participant_states
                        .get(dealer_pk)
                        .map(|out| out.share.clone());
                    if current_public.is_some() && previous_share.is_none() {
                        panic!("dealer missing share required for reshare in round {round_idx}",);
                    }

                    let (dealer, commitment, shares) =
                        Dealer::<_, V>::new(&mut rng, previous_share, player_set.clone());
                    dealers.insert(dealer_pk.clone(), dealer);
                    dealer_outputs.insert(dealer_pk.clone(), (commitment, shares));
                }

                // Setup players
                let mut players = BTreeMap::new();
                for player_pk in player_set.iter() {
                    if absent_players.position(player_pk).is_some() {
                        continue;
                    }
                    let player = Player::<_, V>::new(
                        player_pk.clone(),
                        current_public.clone(),
                        dealer_registry.clone(),
                        player_set.clone(),
                        self.concurrency,
                    );
                    players.insert(player_pk.clone(), player);
                }

                // Setup arbiter
                let mut arbiter = Arbiter::<_, V>::new(
                    current_public.clone(),
                    dealer_registry.clone(),
                    player_set.clone(),
                    self.concurrency,
                );

                // Distribute dealings
                for dealer_pk in active_dealers.iter() {
                    let (commitment, shares) = dealer_outputs
                        .get(dealer_pk)
                        .expect("missing dealer output");
                    let commitment = commitment.clone();
                    let shares = shares.clone();
                    let mut dealer_reveals = Vec::new();
                    {
                        let dealer = dealers.get_mut(dealer_pk).expect("missing dealer instance");
                        for (idx, player_pk) in player_set.iter().enumerate() {
                            let share = shares[idx].clone();
                            if absent_players.position(player_pk).is_some() {
                                dealer_reveals.push(share);
                                continue;
                            }
                            let player_obj = players
                                .get_mut(player_pk)
                                .expect("missing player for share delivery");
                            if let Err(err) =
                                player_obj.share(dealer_pk.clone(), commitment.clone(), share)
                            {
                                panic!(
                                    "failed to deliver share from dealer {dealer_pk:?} to player {player_pk:?}: {err:?}",
                                );
                            }
                            dealer.ack(player_pk.clone()).unwrap();
                        }
                    }

                    let dealer = dealers
                        .remove(dealer_pk)
                        .expect("missing dealer instance after distribution");
                    let dealer_output = dealer.finalize().expect("insufficient acknowledgements");
                    assert_eq!(
                        dealer_output.inactive, expected_inactive,
                        "inactive set mismatch for dealer in round {round_idx}",
                    );
                    let dealer_pos = dealer_registry.position(dealer_pk).unwrap() as u32;
                    if !dealer_reveals.is_empty() {
                        expected_reveals.insert(dealer_pos, dealer_reveals.clone());
                    }
                    arbiter
                        .commitment(
                            dealer_pk.clone(),
                            commitment,
                            dealer_output.active.into(),
                            dealer_reveals,
                        )
                        .unwrap();
                }

                // Finalize arbiter
                assert!(arbiter.ready(), "arbiter not ready in round {round_idx}");
                let (result, disqualified) = arbiter.finalize();
                let expected_disqualified =
                    dealer_registry.len().saturating_sub(active_dealers.len());
                assert_eq!(
                    disqualified.len(),
                    expected_disqualified,
                    "unexpected disqualified dealers in round {round_idx}",
                );
                let output = result.unwrap();
                for (&dealer_idx, _) in output.commitments.iter() {
                    let expected = expected_reveals.remove(&dealer_idx).unwrap_or_default();
                    match output.reveals.get(&dealer_idx) {
                        Some(reveals) => assert_eq!(
                            reveals, &expected,
                            "unexpected reveal content for dealer {dealer_idx} in round {round_idx}",
                        ),
                        None => assert!(
                            expected.is_empty(),
                            "missing reveals for dealer {dealer_idx} in round {round_idx}",
                        ),
                    }
                }
                for dealer_idx in output.reveals.keys() {
                    assert!(
                        output.commitments.contains_key(dealer_idx),
                        "reveals present for unselected dealer {dealer_idx} in round {round_idx}",
                    );
                }
                let expected_commitments = quorum(dealer_registry.len() as u32) as usize;
                assert_eq!(
                    output.commitments.len(),
                    expected_commitments,
                    "unexpected number of commitments in round {round_idx}",
                );

                // Finalize players (that were not revealed)
                let mut round_results = Vec::new();
                let mut next_states = HashMap::new();
                for player_pk in player_set.iter() {
                    if absent_players.position(player_pk).is_some() {
                        continue;
                    }
                    let player_obj = players.remove(player_pk).unwrap();
                    let result = player_obj
                        .finalize(output.commitments.clone(), BTreeMap::new())
                        .unwrap();
                    assert_eq!(result.public, output.public);
                    next_states.insert(player_pk.clone(), result.clone());
                    round_results.push(result);
                }
                assert!(
                    !round_results.is_empty(),
                    "round {round_idx} produced no outputs",
                );

                // Ensure public constant is maintained between rounds
                let public_key = public::<V>(&round_results[0].public);
                if let Some(previous) = current_public.as_ref() {
                    assert_eq!(public_key, public::<V>(previous));
                }

                // Check recovered shares by constructing a proof-of-possession
                let threshold = quorum(player_set.len() as u32);
                let partials = round_results
                    .iter()
                    .map(|res| partial_sign_proof_of_possession::<V>(&res.public, &res.share))
                    .collect::<Vec<_>>();
                let signature = threshold_signature_recover::<V, _>(threshold, &partials)
                    .expect("unable to recover threshold signature");
                verify_proof_of_possession::<V>(public_key, &signature)
                    .expect("invalid proof of possession");

                // Update state for next round
                current_public = Some(round_results[0].public.clone());
                share_holders = Some(player_set);
                participant_states = next_states;
            }

            // Return public constant
            *public::<V>(&current_public.expect("plan must produce a public constant"))
        }
    }

    // Compute the participant set from a list of IDs
    fn participants(ids: &[u64]) -> Set<PublicKey> {
        ids.iter()
            .map(|id| PrivateKey::from_seed(*id).public_key())
            .collect::<Set<_>>()
    }

    #[test]
    fn test_dkg() {
        let plan = Plan::from(vec![Round::from((0..5).collect::<Vec<_>>())]);
        plan.run::<MinPk>();
        plan.run::<MinSig>();
    }

    #[test]
    fn test_dkg_with_absent_dealer() {
        let plan = Plan::from(vec![
            Round::from(vec![0, 1, 2, 3]).with_absent_dealers(vec![3])
        ]);
        plan.run::<MinPk>();
        plan.run::<MinSig>();
    }

    #[test]
    fn test_dkg_with_absent_player() {
        let plan = Plan::from(vec![
            Round::from(vec![0, 1, 2, 3]).with_absent_players(vec![3])
        ]);
        plan.run::<MinPk>();
        plan.run::<MinSig>();
    }

    #[test]
    fn test_dkg_determinism() {
        let plan_template = || Plan::from(vec![Round::from((0..5).collect::<Vec<_>>())]);

        let public_a_pk = plan_template().with_seed(1).run::<MinPk>();
        assert_eq!(public_a_pk, plan_template().with_seed(1).run::<MinPk>());
        let public_b_pk = plan_template().with_seed(2).run::<MinPk>();
        assert_eq!(public_b_pk, plan_template().with_seed(2).run::<MinPk>());
        assert_ne!(public_a_pk, public_b_pk);

        let public_a_sig = plan_template().with_seed(1).run::<MinSig>();
        assert_eq!(public_a_sig, plan_template().with_seed(1).run::<MinSig>());
        let public_b_sig = plan_template().with_seed(2).run::<MinSig>();
        assert_eq!(public_b_sig, plan_template().with_seed(2).run::<MinSig>());
        assert_ne!(public_a_sig, public_b_sig);
    }

    #[test]
    fn test_reshare_distinct() {
        let plan = Plan::from(vec![
            Round::from((0..5).collect::<Vec<_>>()),
            Round::from((5..15).collect::<Vec<_>>()),
            Round::from((15..30).collect::<Vec<_>>()),
        ]);
        plan.run::<MinPk>();
        plan.run::<MinSig>();
    }

    #[test]
    fn test_reshare_increasing_committee() {
        let plan = Plan::from(vec![
            Round::from(vec![0, 1, 2]),
            Round::from(vec![0, 1, 2, 3]),
            Round::from(vec![0, 1, 2, 3, 4]),
            Round::from(vec![0, 1, 2, 3, 4, 5]),
        ]);
        plan.run::<MinPk>();
        plan.run::<MinSig>();
    }

    #[test]
    fn test_reshare_decreasing_committee() {
        let plan = Plan::from(vec![
            Round::from(vec![0, 1, 2, 3, 4, 5]),
            Round::from(vec![0, 1, 2, 3, 4]),
            Round::from(vec![0, 1, 2, 3]),
            Round::from(vec![0, 1, 2]),
        ]);
        plan.run::<MinPk>();
        plan.run::<MinSig>();
    }

    #[test]
    fn test_reshare_with_absent_dealer() {
        let plan = Plan::from(vec![
            Round::from(vec![0, 1, 2, 3]),
            Round::from(vec![4, 5, 6, 7]).with_absent_dealers(vec![3]),
        ]);
        plan.run::<MinPk>();
        plan.run::<MinSig>();
    }

    #[test]
    fn test_reshare_with_absent_player() {
        let plan = Plan::from(vec![
            Round::from(vec![0, 1, 2, 3]),
            Round::from(vec![4, 5, 6, 7]).with_absent_players(vec![4]),
            Round::from(vec![8, 9, 10, 11]).with_absent_dealers(vec![4]),
        ]);
        plan.run::<MinPk>();
        plan.run::<MinSig>();
    }

    #[test]
    fn test_reshare_min_active() {
        let plan = Plan::from(vec![
            Round::from(vec![0, 1, 2, 3]).with_absent_players(vec![3]),
            Round::from(vec![4, 5, 6, 7]).with_absent_dealers(vec![3]),
        ]);
        plan.run::<MinPk>();
        plan.run::<MinSig>();
    }

    #[test]
    fn test_reshare_min_active_different_sizes() {
        let plan = Plan::from(vec![
            Round::from(vec![0, 1, 2, 3]).with_absent_players(vec![3]),
            Round::from(vec![4, 5, 6, 7, 8, 9]).with_absent_dealers(vec![3]),
        ]);
        plan.run::<MinPk>();
        plan.run::<MinSig>();
    }

    #[test]
    fn test_reshare_min_active_large() {
        let plan = Plan::from(vec![
            Round::from((0..20).collect::<Vec<_>>())
                .with_absent_dealers((14..20).collect::<Vec<_>>())
                .with_absent_players((14..20).collect::<Vec<_>>()),
            Round::from((100..200).collect::<Vec<_>>())
                .with_absent_dealers((14..20).collect::<Vec<_>>()),
        ])
        .with_concurrency(4);
        plan.run::<MinPk>();
        plan.run::<MinSig>();
    }

    #[test]
    fn test_reshare_determinism() {
        let plan_template = || {
            Plan::from(vec![
                Round::from((0..5).collect::<Vec<_>>()),
                Round::from((5..10).collect::<Vec<_>>()),
            ])
        };

        let public_a_pk = plan_template().with_seed(1).run::<MinPk>();
        assert_eq!(public_a_pk, plan_template().with_seed(1).run::<MinPk>());
        let public_b_pk = plan_template().with_seed(2).run::<MinPk>();
        assert_eq!(public_b_pk, plan_template().with_seed(2).run::<MinPk>());
        assert_ne!(public_a_pk, public_b_pk);

        let public_a_sig = plan_template().with_seed(1).run::<MinSig>();
        assert_eq!(public_a_sig, plan_template().with_seed(1).run::<MinSig>());
        let public_b_sig = plan_template().with_seed(2).run::<MinSig>();
        assert_eq!(public_b_sig, plan_template().with_seed(2).run::<MinSig>());
        assert_ne!(public_a_sig, public_b_sig);
    }
}
