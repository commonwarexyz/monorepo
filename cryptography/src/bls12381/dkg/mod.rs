//! Distributed Key Generation (DKG) and Resharing protocol for the BLS12-381 curve.
//!
//! This crate implements an interactive Distributed Key Generation (DKG) and Resharing protocol
//! for the BLS12-381 curve.
//!
//!
//! TODO: fix (shares only posted during reveal), no ZK
//!
//! TODO: No complaints (more work to track the complaints than they are worth)
//!
//! Unlike many other constructions, this scheme only requires
//! contributors to publicly post shares during a "forced reveal" (when a given dealer
//! does not distribute a share required for a party to recover their secret). Outside of this
//! reveal, all shares are communicated directly between a dealer and recipient over an
//! encrypted channel (which can be instantiated with <https://docs.rs/commonware-p2p>).
//!
//! The DKG is based on the "Joint-Feldman" construction from "Secure Distributed Key
//! Generation for Discrete-Log Based Cryptosystems" (GJKR99) and resharing is based
//! on the construction provided in "Redistributing secret shares to new access structures
//! and its applications" (Desmedt97).
//!
//! # Protocol
//!
//! The protocol has three types of contributors: arbiter, dealer, and player. The arbiter
//! serves as an orchestrator that collects commitments, acks, complaints, and reveals from
//! all contributors and replicates them to other contributors. The arbiter can be implemented as
//! a standalone process or by some consensus protocol. Dealers are the contributors
//! that deal shares and commitments to players in the protocol. It is possible to be both a dealer and a
//! player in the protocol.
//!
//! The protocol can maintain a `2f + 1` threshold (over `3f + 1` contributors) under a
//! synchronous network model (where messages may be delayed up to time `t` between any 2 contributors)
//! across any reshare where `2f + 1` contributors are honest.
//!
//! Whether or not the protocol succeeds (may need to retry during periods of network instability), all contributors
//! that violate the protocol will be identified and returned. If the protocol succeeds, the contributions of any
//! contributors that violated the protocol are excluded (and still returned). It is expected that the set of
//! contributors would punish/exclude "bad" contributors prior to a future round (to eventually make progress).
//!
//! ## Arbiter
//!
//! ### [Phase 0] Step 0: Collect Commitments, Acks, and Reveals
//!
//! An "ack" is a message indicating that a given contributor has received a valid
//! share from a contributor (does not include encrypted or plaintext share material). A "complaint" is a
//! signed share from a given contributor that is invalid (signing is external to this implementation).
//! If the complaint is valid, the dealer that sent it is disqualified. If the complaint is invalid
//! (it is a valid share), the recipient is disqualified. Because all shares must be signed by the dealer
//! that generates them and this signature is over the plaintext share, there is no need to have a
//! "justification" phase where said dealer must "defend" itself.
//!
//! Listen for commitments, acks, and reveals from dealers. If any such is received, verify all signatures on acks,
//! that reveals are valid, and that there exist no more than `f` reveals.
//!
//! If the arbiter is instantiated with a polynomial (from a previous DKG/Reshare), it will enforce all
//! generated commitments are consistent with said polynomial. The arbiter, lastly, enforces that the
//! degree of each commitment is `2f`.
//!
//! _If a complaint is received, disqualify the dealer._
//!
//! ### [Phase 1] Step 1: Finalize Commitments and Forward Reveals
//!
//! After `3t` time has elapsed, select the `2f + 1` commitments with the least number of reveals (most acks).
//!
//! If there do not exist `2f + 1` commitments, the arbiter will abort the protocol.
//!
//! The arbiter sends all selected commitments to all players (regardless of whether or not their commitment
//! was selected) and any reveals required for a player to reconstruct their share.
//!
//! The arbiter will then recover the new group polynomial using said commitments.
//!
//! ## Dealer
//!
//! ### [Phase 0] Step 0: Generate Shares and Commitment
//!
//! Generate shares and a commitment. If it is a DKG, the commitment is a random polynomial
//! with degree of `2f`. If it is a reshare, the commitment must be consistent with the previous
//! group polynomial.
//!
//! ### [Phase 1] Step 1: Distribute Shares and Collect Acks
//!
//! Distribute share to each player and the corresponding commitment. If the player is honest and connected, it will respond
//! with a signed "ack".
//!
//! Periodically redistribute shares to all contributors that have not yet broadcast an "ack".
//!
//! ### [Phase 2] Step 2: Register Commitment, Acks, and Reveals
//!
//! After `2t` time has elapsed, the dealer sends its commitment, any acks it collected, and up to `f` reveals
//! to the arbiter. This gives `t` time to reach arbiter.
//!
//! ## Player
//!
//! ### [Phase 0] Step 0: Listen for Commitments and Shares
//!
//! ### [Phase 0] Step 1: Submit Acks/Complaints
//!
//! After receiving a share from a dealer, the contributor will send an "ack" to the
//! dealer if the share is valid (confirmed against commitment) or a "complaint" if the dealer broadcasts multiple commitments
//! or the share is invalid.
//!
//! ### [Phase 1] Step 2: Recover Group Polynomial and Derive Share
//!
//! If the round is successful, the arbiter will forward the valid commitments to construct shares for the
//! new group polynomial (which shares the same constant term if it is a reshare) and any reveals. Like the arbiter,
//! the player will recover the group polynomial. Unlike above, the player will also recover its new share of the secret (incorporating
//! any reveals if necessary).
//!
//! # Example
//!
//! For a complete example of how to instantiate this crate, checkout [commonware-vrf](https://docs.rs/commonware-vrf).

pub mod arbiter;
pub mod dealer;
pub mod ops;
pub mod player;

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
    #[error("commitment disqualified")]
    CommitmentDisqualified,
    #[error("contributor disqualified")]
    ContributorDisqualified,
    #[error("contributor is invalid")]
    ContributorInvalid,
    #[error("complaint is invalid")]
    ComplaintInvalid,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::dkg::{arbiter, dealer};
    use crate::bls12381::primitives::ops::{
        partial_sign_proof_of_possession, threshold_signature_recover, verify_proof_of_possession,
    };
    use crate::bls12381::primitives::poly::public;
    use crate::{Ed25519, Scheme};
    use commonware_utils::quorum;
    use std::collections::HashMap;

    fn run_dkg_and_reshare(n_0: u32, dealers_0: u32, n_1: u32, dealers_1: u32, concurrency: usize) {
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
            let (p0, commitment, shares) = dealer::P0::new(None, contributors.clone());
            dealer_shares.insert(con.clone(), (commitment, shares));
            dealers.insert(con.clone(), p0);
        }

        // Create players
        let mut players = HashMap::new();
        for con in &contributors {
            let p0 = player::P0::new(
                con.clone(),
                None,
                contributors.clone(),
                contributors.clone(),
                concurrency,
            );
            players.insert(con.clone(), p0);
        }

        // Create arbiter
        let mut arb = arbiter::P0::new(
            None,
            contributors.clone(),
            contributors.clone(),
            concurrency,
        );

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
            threshold_signature_recover(t, partials).expect("unable to recover signature");
        let public_key = public(&outputs.iter().next().unwrap().1.public);
        verify_proof_of_possession(&public_key, &signature).expect("invalid proof of possession");

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
            let (p0, commitment, shares) =
                dealer::P0::new(Some(output.share), reshare_players.clone());
            reshare_shares.insert(con.clone(), (commitment, shares));
            reshare_dealers.insert(con.clone(), p0);
        }

        // Create reshare player objects
        let mut reshare_player_objs = HashMap::new();
        for con in &reshare_players {
            let p0 = player::P0::new(
                con.clone(),
                Some(output.public.clone()),
                contributors.clone(),
                reshare_players.clone(),
                concurrency,
            );
            reshare_player_objs.insert(con.clone(), p0);
        }

        // Create arbiter
        let mut arb = arbiter::P0::new(
            Some(output.public),
            contributors.clone(),
            reshare_players.clone(),
            concurrency,
        );

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
            threshold_signature_recover(t, partials).expect("unable to recover signature");
        let public_key = public(&outputs[0].public);
        verify_proof_of_possession(&public_key, &signature).expect("invalid proof of possession");
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
    fn test_dkg_invalid_commitment() {
        // Initialize test
        let n = 5;

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create dealer
        let (_, _, shares) = dealer::P0::new(None, contributors.clone());

        // Create invalid commitment
        let (public, _) = ops::generate_shares(None, n * 2, 1);

        // Create player
        let mut player = player::P0::new(
            contributors[0].clone(),
            None,
            contributors.clone(),
            contributors.clone(),
            1,
        );

        // Send invalid commitment to player
        let result = player.share(contributors[0].clone(), public, shares[0]);
        assert!(matches!(result, Err(Error::CommitmentWrongDegree)));
    }
}
