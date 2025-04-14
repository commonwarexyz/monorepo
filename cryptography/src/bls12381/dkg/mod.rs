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
//! # Synchrony Assumption
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
//! ## Future Work: Dropping the Synchrony Assumption?
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
//! # Tracking Complaints
//!
//! This crate does not provide an integrated mechanism for tracking complaints from players (of malicious dealers). However, it is
//! possible to implement your own mechanism and to manually disqualify dealers from a given round in the arbiter. This decision was made
//! because the mechanism for communicating commitments/shares/acknowledgements is highly dependent on the context in which this
//! construction is used.
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

use thiserror::Error;

#[derive(Error, Debug)]
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
    use crate::bls12381::primitives::ops::{
        partial_sign_proof_of_possession, threshold_signature_recover, verify_proof_of_possession,
    };
    use crate::bls12381::primitives::poly::public;
    use crate::{Ed25519, Signer};
    use commonware_utils::quorum;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::HashMap;

    fn run_dkg_and_reshare(n_0: u32, dealers_0: u32, n_1: u32, dealers_1: u32, concurrency: usize) {
        // Create shared RNG (for reproducibility)
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n_0 {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealers
        let mut dealer_shares = HashMap::new();
        let mut dealers = HashMap::new();
        for con in contributors.iter().take(dealers_0 as usize) {
            let (dealer, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
            dealer_shares.insert(con.clone(), (commitment, shares));
            dealers.insert(con.clone(), dealer);
        }

        // Create players
        let mut players = HashMap::new();
        for con in &contributors {
            let player = Player::new(
                con.clone(),
                None,
                contributors.clone(),
                contributors.clone(),
                concurrency,
            );
            players.insert(con.clone(), player);
        }

        // Create arbiter
        let mut arb = Arbiter::new(
            None,
            contributors.clone(),
            contributors.clone(),
            concurrency,
        );

        // Check ready
        assert!(!arb.ready());

        // Send commitments and shares to players
        for (dealer, mut dealer_obj) in dealers {
            // Distribute shares to players
            let (commitment, shares) = dealer_shares.get(&dealer).unwrap().clone();
            for (player_idx, player) in contributors.iter().enumerate() {
                // Process share
                let player_obj = players.get_mut(player).unwrap();
                player_obj
                    .share(dealer.clone(), commitment.clone(), shares[player_idx])
                    .unwrap();

                // Collect ack
                dealer_obj.ack(player.clone()).unwrap();
            }

            // Finalize dealer
            let output = dealer_obj.finalize().unwrap();

            // Ensure no reveals required
            assert!(output.inactive.is_empty());

            // Send commitment and acks to arbiter
            arb.commitment(dealer, commitment, output.active, Vec::new())
                .unwrap();
        }

        // Check ready
        assert!(arb.ready());

        // Finalize arbiter
        let (result, disqualified) = arb.finalize();

        // Verify disqualifications are empty (only occurs if invalid commitment or missing)
        assert_eq!(disqualified.len(), (n_0 - dealers_0) as usize);

        // Verify result
        let output = result.unwrap();

        // Ensure right number of commitments picked
        let expected_commitments = quorum(n_0).unwrap() as usize;
        assert_eq!(output.commitments.len(), expected_commitments);

        // Ensure no reveals required
        assert!(output.reveals.is_empty());

        // Distribute commitments to players and recover public key
        let mut outputs = HashMap::new();
        for player in contributors.iter() {
            let result = players
                .remove(player)
                .unwrap()
                .finalize(output.commitments.clone(), HashMap::new())
                .unwrap();
            outputs.insert(player.clone(), result);
        }

        // Test that can generate proof-of-possession
        let t = quorum(n_0).unwrap();
        let partials = outputs
            .values()
            .map(|s| partial_sign_proof_of_possession(&s.public, &s.share))
            .collect::<Vec<_>>();
        let signature =
            threshold_signature_recover(t, &partials).expect("unable to recover signature");
        let public_key = public(&outputs.iter().next().unwrap().1.public);
        verify_proof_of_possession(public_key, &signature).expect("invalid proof of possession");

        // Create reshare players (assume no overlap)
        let mut reshare_players = Vec::new();
        for i in 0..n_1 {
            let player = Ed25519::from_seed((i + n_0) as u64).public_key();
            reshare_players.push(player);
        }
        reshare_players.sort();

        // Create reshare dealers
        let mut reshare_shares = HashMap::new();
        let mut reshare_dealers = HashMap::new();
        for con in contributors.iter().take(dealers_1 as usize) {
            let output = outputs.get(con).unwrap();
            let (dealer, commitment, shares) =
                Dealer::new(&mut rng, Some(output.share), reshare_players.clone());
            reshare_shares.insert(con.clone(), (commitment, shares));
            reshare_dealers.insert(con.clone(), dealer);
        }

        // Create reshare player objects
        let mut reshare_player_objs = HashMap::new();
        for con in &reshare_players {
            let player = Player::new(
                con.clone(),
                Some(output.public.clone()),
                contributors.clone(),
                reshare_players.clone(),
                concurrency,
            );
            reshare_player_objs.insert(con.clone(), player);
        }

        // Create arbiter
        let mut arb = Arbiter::new(
            Some(output.public),
            contributors.clone(),
            reshare_players.clone(),
            concurrency,
        );

        // Check ready
        assert!(!arb.ready());

        // Send commitments and shares to players
        for (dealer, mut dealer_obj) in reshare_dealers {
            // Distribute shares to players
            let (commitment, shares) = reshare_shares.get(&dealer).unwrap().clone();
            for (player_idx, player) in reshare_players.iter().enumerate() {
                // Process share
                let player_obj = reshare_player_objs.get_mut(player).unwrap();
                player_obj
                    .share(dealer.clone(), commitment.clone(), shares[player_idx])
                    .unwrap();

                // Collect ack
                dealer_obj.ack(player.clone()).unwrap();
            }

            // Finalize dealer
            let output = dealer_obj.finalize().unwrap();

            // Ensure no reveals required
            assert!(output.inactive.is_empty());

            // Send commitment and acks to arbiter
            arb.commitment(dealer, commitment, output.active, Vec::new())
                .unwrap();
        }

        // Check ready
        assert!(arb.ready());

        // Finalize arbiter
        let (result, disqualified) = arb.finalize();

        // Verify disqualifications are empty (only occurs if invalid commitment)
        assert_eq!(disqualified.len(), (n_0 - dealers_1) as usize);

        // Verify result
        let output = result.unwrap();

        // Ensure right number of commitments picked
        let expected_commitments = quorum(n_0).unwrap() as usize;
        assert_eq!(output.commitments.len(), expected_commitments);

        // Ensure no reveals required
        assert!(output.reveals.is_empty());

        // Distribute commitments to players and recover public key
        let mut outputs = Vec::new();
        for player in reshare_players.iter() {
            let result = reshare_player_objs
                .remove(player)
                .unwrap()
                .finalize(output.commitments.clone(), HashMap::new())
                .unwrap();
            assert_eq!(result.public, output.public);
            outputs.push(result);
        }

        // Test that can generate proof-of-possession
        let t = quorum(n_1).unwrap();
        let partials = outputs
            .iter()
            .map(|s| partial_sign_proof_of_possession(&s.public, &s.share))
            .collect::<Vec<_>>();
        let signature =
            threshold_signature_recover(t, &partials).expect("unable to recover signature");
        let public_key = public(&outputs[0].public);
        verify_proof_of_possession(public_key, &signature).expect("invalid proof of possession");
    }

    #[test]
    fn test_dkg_and_reshare_all_active() {
        run_dkg_and_reshare(5, 5, 10, 5, 4);
    }

    #[test]
    fn test_dkg_and_reshare_min_active() {
        run_dkg_and_reshare(4, 3, 4, 3, 4);
    }

    #[test]
    fn test_dkg_and_reshare_min_active_different_sizes() {
        run_dkg_and_reshare(5, 3, 10, 3, 4);
    }

    #[test]
    fn test_dkg_and_reshare_min_active_large() {
        run_dkg_and_reshare(20, 13, 100, 13, 4);
    }

    #[test]
    #[should_panic]
    fn test_dkg_and_reshare_insufficient_active() {
        run_dkg_and_reshare(5, 3, 10, 2, 4);
    }

    #[test]
    fn test_invalid_commitment() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, _, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create unrelated commitment of correct degree
        let t = quorum(n).unwrap();
        let (public, _) = ops::generate_shares(&mut rng, None, n, t);

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send invalid commitment to player
        let result = player.share(contributors[0].clone(), public, shares[0]);
        assert!(matches!(result, Err(Error::ShareWrongCommitment)));
    }

    #[test]
    fn test_mismatched_commitment() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create unrelated commitment of correct degree
        let t = quorum(n).unwrap();
        let (other_commitment, _) = ops::generate_shares(&mut rng, None, n, t);

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send valid commitment to player
        player
            .share(contributors[0].clone(), commitment, shares[0])
            .unwrap();

        // Send alternative commitment to player
        let result = player.share(contributors[0].clone(), other_commitment, shares[0]);
        assert!(matches!(result, Err(Error::MismatchedCommitment)));
    }

    #[test]
    fn test_mismatched_share() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create unrelated commitment of correct degree
        let t = quorum(n).unwrap();
        let (_, other_shares) = ops::generate_shares(&mut rng, None, n, t);

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send valid share to player
        player
            .share(contributors[0].clone(), commitment.clone(), shares[0])
            .unwrap();

        // Send alternative share to player
        let result = player.share(contributors[0].clone(), commitment, other_shares[0]);
        assert!(matches!(result, Err(Error::MismatchedShare)));
    }

    #[test]
    fn test_duplicate_share() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send valid share to player
        player
            .share(contributors[0].clone(), commitment.clone(), shares[0])
            .unwrap();

        // Send alternative share to player
        let result = player.share(contributors[0].clone(), commitment, shares[0]);
        assert!(matches!(result, Err(Error::DuplicateShare)));
    }

    #[test]
    fn test_misdirected_share() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send misdirected share to player
        let result = player.share(contributors[0].clone(), commitment.clone(), shares[1]);
        assert!(matches!(result, Err(Error::MisdirectedShare)));
    }

    #[test]
    fn test_invalid_dealer() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send share from invalid dealer
        let dealer = Ed25519::from_seed(n as u64).public_key();
        let result = player.share(dealer.clone(), commitment.clone(), shares[0]);
        assert!(matches!(result, Err(Error::DealerInvalid)));

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

        // Send commitment from invalid dealer
        let result = arb.commitment(dealer, commitment, vec![0, 1, 2, 3], Vec::new());
        assert!(matches!(result, Err(Error::DealerInvalid)));
    }

    #[test]
    fn test_invalid_commitment_degree() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, _, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create invalid commitment
        let (public, _) = ops::generate_shares(&mut rng, None, n * 2, 1);

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send invalid commitment to player
        let result = player.share(contributors[0].clone(), public.clone(), shares[0]);
        assert!(matches!(result, Err(Error::CommitmentWrongDegree)));

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

        // Send invalid commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            public,
            vec![0, 1, 2, 3, 4],
            Vec::new(),
        );
        assert!(matches!(result, Err(Error::CommitmentWrongDegree)));
    }

    #[test]
    fn test_reveal() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3],
            vec![shares[4]],
        )
        .unwrap();
    }

    #[test]
    fn test_arbiter_reveals() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

        // Create dealers
        let mut commitments = Vec::with_capacity(n);
        let mut reveals = Vec::with_capacity(n);
        for con in &contributors {
            // Create dealer
            let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
            commitments.push(commitment.clone());
            reveals.push(shares[4]);

            // Add commitment to arbiter
            arb.commitment(con.clone(), commitment, vec![0, 1, 2, 3], vec![shares[4]])
                .unwrap();
        }

        // Finalize arbiter
        let (result, _) = arb.finalize();
        let output = result.unwrap();

        // Ensure commitments and reveals are correct
        assert_eq!(output.commitments.len(), 3);
        for (dealer_idx, commitment) in commitments.iter().enumerate().take(3) {
            let dealer_idx = dealer_idx as u32;
            assert_eq!(output.commitments.get(&dealer_idx).unwrap(), commitment);
            assert_eq!(
                output.reveals.get(&dealer_idx).unwrap()[0],
                reveals[dealer_idx as usize]
            );
        }
    }

    #[test]
    fn test_arbiter_best() {}

    #[test]
    fn test_duplicate_commitment() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        arb.commitment(
            contributors[0].clone(),
            commitment.clone(),
            vec![0, 1, 2, 3],
            vec![shares[4]],
        )
        .unwrap();

        // Add commitment to arbiter (again)
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3],
            vec![shares[4]],
        );
        assert!(matches!(result, Err(Error::DuplicateCommitment)));
    }

    #[test]
    fn test_reveal_duplicate_player() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3],
            vec![shares[3]],
        );
        assert!(matches!(result, Err(Error::AlreadyActive)));
    }

    #[test]
    fn test_insufficient_active() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, _) = Dealer::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

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
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, _) = Dealer::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

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
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2],
            vec![shares[3], shares[4]],
        );
        assert!(matches!(result, Err(Error::TooManyReveals)));
    }

    #[test]
    fn test_incorrect_reveal() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, _) = Dealer::new(&mut rng, None, contributors.clone());

        // Create invalid shares
        let t = quorum(n).unwrap();
        let (_, shares) = ops::generate_shares(&mut rng, None, n, t);

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

        // Add commitment to arbiter
        let result = arb.commitment(
            contributors[0].clone(),
            commitment,
            vec![0, 1, 2, 3],
            vec![shares[4]],
        );
        assert!(matches!(result, Err(Error::ShareWrongCommitment)));
    }

    #[test]
    fn test_reveal_corrupt_share() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

        // Swap share value
        let mut share = shares[3];
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
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, _) = Dealer::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

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
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, _) = Dealer::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

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
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());

        // Create arbiter
        let mut arb = Arbiter::new(None, contributors.clone(), contributors.clone(), 1);

        // Swap share value
        let mut share = shares[3];
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
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (mut dealer, _, _) = Dealer::new(&mut rng, None, contributors.clone());

        // Ack all players
        for player in &contributors {
            dealer.ack(player.clone()).unwrap();
        }

        // Finalize dealer
        let output = dealer.finalize().unwrap();
        assert_eq!(output.active, vec![0, 1, 2, 3, 4]);
        assert!(output.inactive.is_empty());
    }

    #[test]
    fn test_dealer_inactive() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (mut dealer, _, _) = Dealer::new(&mut rng, None, contributors.clone());

        // Ack all players
        for player in contributors.iter().take(4) {
            dealer.ack(player.clone()).unwrap();
        }

        // Finalize dealer
        let output = dealer.finalize().unwrap();
        assert_eq!(output.active, vec![0, 1, 2, 3]);
        assert_eq!(output.inactive, vec![4]);
    }

    #[test]
    fn test_dealer_insufficient() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (mut dealer, _, _) = Dealer::new(&mut rng, None, contributors.clone());

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
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (mut dealer, _, _) = Dealer::new(&mut rng, None, contributors.clone());

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
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (mut dealer, _, _) = Dealer::new(&mut rng, None, contributors.clone());

        // Ack invalid player
        let player = Ed25519::from_seed(n as u64).public_key();
        let result = dealer.ack(player);
        assert!(matches!(result, Err(Error::PlayerInvalid)));
    }

    #[test]
    fn test_player_reveals() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = HashMap::new();
        for (i, con) in contributors.iter().enumerate().take(2) {
            let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0])
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
        commitments.insert(2, commitment);
        let mut reveals = HashMap::new();
        reveals.insert(2, shares[0]);
        player.finalize(commitments, reveals).unwrap();
    }

    #[test]
    fn test_player_missing_reveal() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = HashMap::new();
        for (i, con) in contributors.iter().enumerate().take(2) {
            let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0])
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let (_, commitment, _) = Dealer::new(&mut rng, None, contributors.clone());
        commitments.insert(2, commitment);
        let result = player.finalize(commitments, HashMap::new());
        assert!(matches!(result, Err(Error::MissingShare)));
    }

    #[test]
    fn test_player_insufficient_commitments() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = HashMap::new();
        for (i, con) in contributors.iter().enumerate().take(2) {
            let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0])
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let result = player.finalize(commitments, HashMap::new());
        assert!(matches!(result, Err(Error::InvalidCommitments)));
    }

    #[test]
    fn test_player_misdirected_reveal() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = HashMap::new();
        for (i, con) in contributors.iter().enumerate().take(2) {
            let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0])
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
        commitments.insert(2, commitment);
        let mut reveals = HashMap::new();
        reveals.insert(2, shares[1]);
        let result = player.finalize(commitments, reveals);
        assert!(matches!(result, Err(Error::MisdirectedShare)));
    }

    #[test]
    fn test_player_invalid_commitment() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = HashMap::new();
        for (i, con) in contributors.iter().enumerate().take(2) {
            let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0])
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let (commitment, shares) = ops::generate_shares(&mut rng, None, n, 1);
        commitments.insert(2, commitment);
        let mut reveals = HashMap::new();
        reveals.insert(2, shares[0]);
        let result = player.finalize(commitments, reveals);
        assert!(matches!(result, Err(Error::CommitmentWrongDegree)));
    }

    #[test]
    fn test_player_invalid_reveal() {
        // Initialize test
        let n = 5;
        let mut rng = StdRng::seed_from_u64(0);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create player
        let mut player = Player::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send shares to player
        let mut commitments = HashMap::new();
        for (i, con) in contributors.iter().enumerate().take(2) {
            let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
            player
                .share(con.clone(), commitment.clone(), shares[0])
                .unwrap();
            commitments.insert(i as u32, commitment);
        }

        // Finalize player with reveal
        let (_, commitment, shares) = Dealer::new(&mut rng, None, contributors.clone());
        commitments.insert(2, commitment);
        let mut reveals = HashMap::new();
        let mut share = shares[1];
        share.index = 0;
        reveals.insert(2, share);
        let result = player.finalize(commitments, reveals);
        assert!(matches!(result, Err(Error::ShareWrongCommitment)));
    }
}
