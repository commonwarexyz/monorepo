//! Interactive Distributed Key Generation (DKG) and Resharing protocol for the BLS12-381 curve.
//!
//! This crate implements an Interactive Distributed Key Generation (DKG) and Resharing protocol
//! for the BLS12-381 curve. Unlike many other constructions, this scheme only requires
//! participants to publicly post shares during a "forced reveal" (when a given dealer
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
//! The protocol has two types of participants: the arbiter and contributors. The arbiter
//! serves as an orchestrator that collects commitments, acks, complaints, and reveals from
//! contributors and replicates them to other contributors. The arbiter can be implemented as
//! a standalone process or by some consensus protocol. Contributors are the participants
//! that deal shares and commitments to other contributors in the protocol.
//!
//! The protocol safely maintains a `f + 1` threshold (over `3f + 1` participants) in the partially
//! synchronous network model (where messages may be arbitrarily delayed between any 2 participants)
//! across any reshare (including ones with a changing contributor set) where `2f + 1` contributors
//! are online and honest.
//!
//! Whether or not the protocol succeeds in a given round, all contributors that do not adhere to the
//! protocol will be identified and returned. If the protocol succeeds, the contributions of any
//! contributors that did not adhere to the protocol are excluded (and still returned). It is expected
//! that the set of contributors would punish/exclude "bad" contributors prior to a future round (to eventually
//! make progress).
//!
//! ## Extension to `2f + 1` Threshold
//!
//! It is possible to extend this construction to a `2f + 1` threshold (over `3f + 1` participants)
//! in the synchronous network model. To achieve this, timeouts in each phase can be introduced
//! (greater than the synchrony bound for any honest participant to broadcast a message to all other
//! participants). The insight here is that `2f + 1` honest participants "have the time" to interact
//! by the timeout at each phase and will make progress regardless of the actions of up to `f` byzantine
//! participants. This does not apply to the partially synchronous network model because a partition
//! might form that groups `f + 1` honest participants with `f` byzantine participants that could complete
//! the protocol (after which the byzantine nodes could drop offline).
//!
//! ## Arbiter
//!
//! ### [Phase 0] Step 0: Collect Commitments
//!
//! In the first phase, the arbiter collects randomly generated commitments from all contributors.
//! If the arbiter is instantiated with a polynomial (from a previous DKG/Reshare), it will enforce all
//! generated commitments are consistent with said polynomial. The arbiter, lastly, enforces that the
//! degree of each commitment is `f`.
//!
//! If there do not exist `2f + 1` valid commitments (computed from the previous set in the case of resharing)
//! by some timeout, the arbiter will abort the protocol.
//!
//! ### [Phase 0] Step 1: Distribute Valid Commitments
//!
//! The arbiter sends all qualified commitments to all contributors (regardless of whether or not their commitment
//! was selected).
//!
//! ### [Phase 1] Step 2: Collect Acks and Complaints
//!
//! After distributing valid commitments, the arbiter will listen for acks and complaints from all
//! contributors. An "ack" is a message indicating that a given contributor has received a valid
//! share from a contributor (does not include encrypted or plaintext share material). A "complaint" is a
//! signed share from a given contributor that is invalid (signing is external to this implementation).
//! If the complaint is valid, the dealer that sent it is disqualified. If the complaint is invalid
//! (it is a valid share), the recipient is disqualified. Because all shares must be signed by the dealer
//! that generates them and this signature is over the plaintext share, there is no need to have a
//! "justification" phase where said dealer must "defend" itself.
//!
//! If `f + 1` commitments (or `previous.degree + 1` commitments in resharing) are not acked by the same
//! subset of `2f + 1` contributors (each contributor in the subset must have acked the same `f + 1` commitments)
//! by some timeout, the arbiter will abort the protocol.
//!
//! ### [Phase 1] Step 3: Finalize Commitments
//!
//! The arbiter forwards these `f + 1` commitments to all contributors. The arbiter will then recover the
//! new group polynomial using said commitments.
//!
//! ## Contributor
//!
//! ### [Phase 0] Step 0 (Optional): Generate Shares and Commitment
//!
//! If a contributor is joining a pre-existing group (and is not a dealer), it proceeds to Step 2.
//!
//! Otherwise, it generates shares and a commitment. If it is a DKG, the commitment is a random polynomial
//! with degree of `f`. If it is a reshare, the commitment must be consistent with the previous
//! group polynomial. The contributor generates the shares and commitment for Step 1 and sends the commitment
//! to the arbiter.
//!
//! ### [Phase 0] Step 1 (Optional): Distribute Shares
//!
//! After receiving qualified commitments from the arbiter, the contributor (if qualified) will distribute
//! shares to all participants (ordered by participant identity).
//!
//! ### [Phase 1] Step 2: Submit Acks/Complaints
//!
//! After receiving a share from a qualified contributor, the contributor will send an "ack" to the
//! arbiter if the share is valid (confirmed against commitment) or a "complaint" if the share is invalid.
//!
//! The contributor will not send an "ack" for its own share (if it is a qualified contributor).
//!
//! ### [Phase 1] Step 3 (Optional): Recover Group Polynomial and Derive Share
//!
//! If the round is successful, the arbiter will forward the valid commitments to construct shares for the
//! new group polynomial (which shares the same constant term if it is a reshare). Like the aribiter, the contributor
//! will recover the group polynomial. Unlike above, the contributor will also recover its new share of the secret
//! (rather than just adding all shares together).
//!
//! # Example
//!
//! For a complete example of how to instantiate this crate, checkout [commonware-vrf](https://docs.rs/commonware-vrf).

pub mod arbiter;
pub mod contributor;
pub mod ops;
pub mod utils;

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
    #[error("missing share")]
    MissingShare,
    #[error("commitment disqualified")]
    CommitmentDisqualified,
    #[error("contributor disqualified")]
    ContributorDisqualified,
    #[error("contributor is invalid")]
    ContirbutorInvalid,
    #[error("complaint is invalid")]
    ComplaintInvalid,
    #[error("unexpected reveal")]
    UnexpectedReveal,
    #[error("missing commitment")]
    MissingCommitment,
    #[error("self-ack")]
    SelfAck,
    #[error("self-complaint")]
    SelfComplaint,
    #[error("duplicate commitment")]
    DuplicateCommitment,
    #[error("duplicate ack")]
    DuplicateAck,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::idkg::{arbiter, contributor};
    use crate::bls12381::primitives::group::Private;
    use crate::{Ed25519, Scheme};
    use std::collections::HashMap;

    fn run_dkg_and_reshare(
        n_0: u32,
        t_0: u32,
        dealers_0: u32,
        n_1: u32,
        t_1: u32,
        dealers_1: u32,
        concurrency: usize,
    ) {
        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n_0 {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create shares
        let mut contributor_shares = HashMap::new();
        let mut contributor_cons = HashMap::new();
        for con in &contributors {
            let me = con.clone();
            let p0 = contributor::P0::new(
                me,
                t_0,
                None,
                contributors.clone(),
                contributors.clone(),
                concurrency,
            );
            let (p1, public, shares) = p0.finalize();
            contributor_shares.insert(con.clone(), (public, shares));
            contributor_cons.insert(con.clone(), p1.unwrap());
        }

        // Inform arbiter of commitments
        let mut arb = arbiter::P0::new(
            t_0,
            None,
            contributors.clone(),
            contributors.clone(),
            concurrency,
        );
        for contributor in contributors.iter().take(dealers_0 as usize) {
            let (public, _) = contributor_shares.get(contributor).unwrap();
            arb.commitment(contributor.clone(), public.clone()).unwrap();
        }
        let (result, disqualified) = arb.finalize();

        // Verify disqualifications
        assert_eq!(disqualified.len(), (n_0 - dealers_0) as usize);
        for contributor in contributors.iter().skip(dealers_0 as usize) {
            assert!(disqualified.contains(contributor));
        }
        let mut arb = result.unwrap();

        // Send select commitments to contributors
        for (_, dealer, commitment) in arb.commitments().iter() {
            for contributor in contributors.iter() {
                contributor_cons
                    .get_mut(contributor)
                    .unwrap()
                    .commitment(dealer.clone(), commitment.clone())
                    .unwrap();
            }
        }

        // Finalze contributor P1
        let mut p2 = HashMap::new();
        for contributor in contributors.iter() {
            let output = contributor_cons
                .remove(contributor)
                .unwrap()
                .finalize()
                .unwrap();
            p2.insert(contributor.clone(), output);
        }
        let mut contributor_cons = p2;

        // Distribute shares to contributors and send acks to arbiter
        for (dealer, dealer_key, _) in arb.commitments().iter() {
            for (idx, recipient) in contributors.iter().enumerate() {
                let (_, shares) = contributor_shares.get(dealer_key).unwrap().clone();
                let share = shares[idx];
                contributor_cons
                    .get_mut(recipient)
                    .unwrap()
                    .share(dealer_key.clone(), share)
                    .unwrap();

                // Skip ack for self
                if dealer_key == recipient {
                    continue;
                }

                // Ensure ack fails if not commitment
                let result = arb.ack(recipient.clone(), *dealer);
                if idx < dealers_0 as usize {
                    result.unwrap();
                } else {
                    // Should fail if never sent a commitment
                    result.unwrap_err();
                }
            }
        }

        // Finalize arb P1
        let (result, disqualified) = arb.finalize();

        // Verify disqualifications (unchanged)
        assert_eq!(disqualified.len(), (n_0 - dealers_0) as usize);
        for contributor in contributors.iter().skip(dealers_0 as usize) {
            assert!(disqualified.contains(contributor));
        }
        let (arb, requests) = result.unwrap();

        // Verify no missing shares
        //
        // If shares were missing, we'd need to ask for them!
        assert!(requests.is_empty());

        // Recover public key on arbiter
        let (result, disqualified) = arb.finalize();
        assert!(disqualified.len() == (n_0 - dealers_0) as usize);
        for contributor in contributors.iter().skip(dealers_0 as usize) {
            assert!(disqualified.contains(contributor));
        }
        let output = result.unwrap();

        // Distribute final commitments to contributors and recover public key
        let mut results = HashMap::new();
        for contributor in contributors.iter() {
            let result = contributor_cons
                .remove(contributor)
                .unwrap()
                .finalize(output.commitments.clone())
                .unwrap();
            assert_eq!(result.public, output.public);
            results.insert(contributor.clone(), result);
        }

        // Create reshare dealers
        let reshare_dealers = contributors.clone();

        // Create reshare recipients (assume no overlap)
        let mut reshare_recipients = Vec::new();
        for i in 0..n_1 {
            let recipient = Ed25519::from_seed((i + n_0) as u64).public_key();
            reshare_recipients.push(recipient);
        }
        reshare_recipients.sort();

        let mut reshare_contributor_shares = HashMap::new();
        for contributor in contributors.iter() {
            let output = results.get(contributor).unwrap();
            let p0 = contributor::P0::new(
                contributor.clone(),
                t_1,
                Some((output.public.clone(), output.share)),
                reshare_dealers.clone(),
                reshare_recipients.clone(),
                concurrency,
            );
            let (p1, public, shares) = p0.finalize();
            assert!(p1.is_none());
            reshare_contributor_shares.insert(contributor.clone(), (public, shares));
        }

        let mut reshare_contributor_cons = HashMap::new();
        for con in &reshare_recipients {
            let p1 = contributor::P1::new(
                con.clone(),
                t_1,
                Some(output.public.clone()),
                reshare_dealers.clone(),
                reshare_recipients.clone(),
                concurrency,
            );
            reshare_contributor_cons.insert(con.clone(), p1);
        }

        // Inform arbiter of commitments
        let mut arb = arbiter::P0::new(
            t_1,
            Some(output.public.clone()),
            reshare_dealers.clone(),
            reshare_recipients.clone(),
            concurrency,
        );
        for con in reshare_dealers.iter().take(dealers_1 as usize) {
            let (public, _) = reshare_contributor_shares.get(con).unwrap();
            arb.commitment(con.clone(), public.clone()).unwrap();
        }
        let (result, disqualified) = arb.finalize();

        // Verify disqualifications
        assert_eq!(disqualified.len(), (n_0 - dealers_1) as usize);
        for contributor in reshare_dealers.iter().skip(dealers_1 as usize) {
            assert!(disqualified.contains(contributor));
        }
        let mut arb = result.unwrap();

        // Send select commitments to recipients
        for (_, dealer, commitment) in arb.commitments().iter() {
            for contributor in reshare_recipients.iter() {
                reshare_contributor_cons
                    .get_mut(contributor)
                    .unwrap()
                    .commitment(dealer.clone(), commitment.clone())
                    .unwrap();
            }
        }

        // Finalize contributor P0
        let mut p2 = HashMap::new();
        for contributor in reshare_recipients.iter() {
            let output = reshare_contributor_cons
                .remove(contributor)
                .unwrap()
                .finalize()
                .unwrap();
            p2.insert(contributor.clone(), output);
        }
        let mut reshare_contributor_cons = p2;

        // Distribute shares to contributors and send acks to arbiter
        for (dealer, dealer_key, _) in arb.commitments().iter() {
            for (idx, recipient) in reshare_recipients.iter().enumerate() {
                let (_, shares) = reshare_contributor_shares.get(dealer_key).unwrap().clone();
                reshare_contributor_cons
                    .get_mut(recipient)
                    .unwrap()
                    .share(dealer_key.clone(), shares[idx])
                    .unwrap();

                // Skip ack for self
                if dealer_key == recipient {
                    continue;
                }

                arb.ack(recipient.clone(), *dealer).unwrap();
            }
        }

        // Finalize arb p1
        let (result, disqualified) = arb.finalize();

        // Verify disqualifications (unchanged)
        assert_eq!(disqualified.len(), (n_0 - dealers_1) as usize);
        for contributor in reshare_dealers.iter().skip(dealers_1 as usize) {
            assert!(disqualified.contains(contributor));
        }
        let (arb, requests) = result.unwrap();

        // Verify no missing shares
        //
        // If shares were missing, we'd need to ask for them!
        assert!(requests.is_empty());

        // Recover public key on arbiter
        let (result, disqualified) = arb.finalize();
        assert!(disqualified.len() == (n_0 - dealers_1) as usize);
        for contributor in reshare_dealers.iter().skip(dealers_1 as usize) {
            assert!(disqualified.contains(contributor));
        }
        let output = result.unwrap();

        // Distribute final commitments to contributors and recover public key
        for contributor in reshare_recipients.iter() {
            let result = reshare_contributor_cons
                .remove(contributor)
                .unwrap()
                .finalize(output.commitments.clone())
                .unwrap();
            assert_eq!(result.public, output.public);
        }
    }

    #[test]
    fn test_dkg_and_reshare_all_active() {
        run_dkg_and_reshare(5, 3, 5, 10, 7, 5, 4);
    }

    #[test]
    fn test_dkg_and_reshare_min_active() {
        run_dkg_and_reshare(5, 3, 3, 10, 7, 3, 4);
    }

    #[test]
    fn test_dkg_and_reshare_min_active_large() {
        run_dkg_and_reshare(20, 13, 13, 100, 67, 13, 4);
    }

    #[test]
    #[should_panic]
    fn test_dkg_and_reshare_insufficient_active() {
        run_dkg_and_reshare(5, 3, 3, 10, 7, 2, 4);
    }

    fn run_dkg_reveal(defiant: bool) {
        let (n, t) = (5, 4);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create shares
        let mut contributor_shares = HashMap::new();
        let mut contributor_cons = HashMap::new();
        for con in &contributors {
            let p0 = contributor::P0::new(
                con.clone(),
                t,
                None,
                contributors.clone(),
                contributors.clone(),
                1,
            );
            let (p1, public, shares) = p0.finalize();
            contributor_shares.insert(con.clone(), (public, shares));
            contributor_cons.insert(con.clone(), p1.unwrap());
        }

        // Inform arbiter of commitments
        let mut arb = arbiter::P0::new(t, None, contributors.clone(), contributors.clone(), 1);
        for contributor in contributors.iter() {
            let (public, _) = contributor_shares.get(contributor).unwrap();
            arb.commitment(contributor.clone(), public.clone()).unwrap();
        }
        let (result, disqualified) = arb.finalize();

        // Verify disqualifications
        assert!(disqualified.is_empty());
        let mut arb = result.unwrap();

        // Send select commitments to contributors
        for (_, dealer, commitment) in arb.commitments().iter() {
            for contributor in contributors.iter() {
                contributor_cons
                    .get_mut(contributor)
                    .unwrap()
                    .commitment(dealer.clone(), commitment.clone())
                    .unwrap();
            }
        }

        // Finalze contributor P1
        let mut p2 = HashMap::new();
        for contributor in contributors.iter() {
            let output = contributor_cons
                .remove(contributor)
                .unwrap()
                .finalize()
                .unwrap();
            p2.insert(contributor.clone(), output);
        }
        let mut contributor_cons = p2;

        // Distribute shares to contributors and send acks to arbiter
        for (dealer, dealer_key, _) in arb.commitments().iter() {
            for (idx, recipient) in contributors.iter().enumerate() {
                let (_, shares) = contributor_shares.get(dealer_key).unwrap().clone();
                contributor_cons
                    .get_mut(recipient)
                    .unwrap()
                    .share(dealer_key.clone(), shares[idx])
                    .unwrap();

                // Purposely skip ack
                if *dealer == 0 && idx == 1 {
                    continue;
                }

                // Skip ack for self
                if dealer_key == recipient {
                    continue;
                }
                arb.ack(recipient.clone(), *dealer).unwrap();
            }
        }

        // Finalize arb P1
        let (result, disqualified) = arb.finalize();

        // Verify disqualifications (unchanged)
        assert!(disqualified.is_empty());
        let (mut arb, requests) = result.unwrap();

        // Verify 1 missing share
        //
        // If shares were missing, we'd need to ask for them!
        assert_eq!(requests, vec![(0, 1)]);

        // Reval missing share
        if !defiant {
            let dealer = contributors[0].clone();
            let share = contributor_shares.get(&dealer).unwrap().1[1];
            arb.reveal(dealer.clone(), share).unwrap();

            // Recover public key on arbiter
            let (result, disqualified) = arb.finalize();
            assert!(disqualified.is_empty());
            let output = result.unwrap();

            // Distribute final commitments to contributors and recover public key
            for (idx, contributor) in contributors.iter().enumerate() {
                let mut contributor = contributor_cons.remove(contributor).unwrap();
                if idx == 1 {
                    contributor.share(dealer.clone(), share).unwrap();
                }
                let result = contributor.finalize(output.commitments.clone()).unwrap();
                assert_eq!(result.public, output.public);
            }
            return;
        }

        // Recover public key on arbiter
        let (result, disqualified) = arb.finalize();

        // Ensure dealer that did not reveal is disqualified
        assert!(disqualified.len() == 1);
        disqualified.get(&contributors[0]).unwrap();

        // Distribute final commitments to contributors and recover public key
        let output = result.unwrap();
        for contributor in contributors.iter() {
            let result = contributor_cons
                .remove(contributor)
                .unwrap()
                .finalize(output.commitments.clone())
                .unwrap();
            assert_eq!(result.public, output.public);
        }
    }

    #[test]
    fn test_dkg_reveal() {
        run_dkg_reveal(false);
    }

    #[test]
    fn test_dkg_reveal_defiant() {
        run_dkg_reveal(true);
    }

    #[test]
    fn test_dkg_complaint() {
        let (n, t) = (5, 4);

        // Create contributors (must be in sorted order)
        let mut contributors = Vec::new();
        for i in 0..n {
            let signer = Ed25519::from_seed(i as u64).public_key();
            contributors.push(signer);
        }
        contributors.sort();

        // Create shares
        let mut contributor_shares = HashMap::new();
        let mut contributor_cons = HashMap::new();
        for con in &contributors {
            // Generate private key
            let p0 = contributor::P0::new(
                con.clone(),
                t,
                None,
                contributors.clone(),
                contributors.clone(),
                1,
            );
            let (p1, public, mut shares) = p0.finalize();

            // Corrupt shares
            for share in shares.iter_mut() {
                share.private = Private::rand(&mut rand::thread_rng());
            }

            // Record shares
            contributor_shares.insert(con.clone(), (public, shares));
            contributor_cons.insert(con.clone(), p1.unwrap());
        }

        // Inform arbiter of commitments
        let mut arb = arbiter::P0::new(t, None, contributors.clone(), contributors.clone(), 1);
        for contributor in contributors.iter() {
            let (public, _) = contributor_shares.get(contributor).unwrap();
            arb.commitment(contributor.clone(), public.clone()).unwrap();
        }
        let (result, disqualified) = arb.finalize();

        // Verify disqualifications
        assert!(disqualified.is_empty());
        let mut arb = result.unwrap();

        // Send select commitments to contributors
        for (_, dealer, commitment) in arb.commitments().iter() {
            for contributor in contributors.iter() {
                contributor_cons
                    .get_mut(contributor)
                    .unwrap()
                    .commitment(dealer.clone(), commitment.clone())
                    .unwrap();
            }
        }

        // Finalze contributor P0
        let mut p1 = HashMap::new();
        for contributor in contributors.iter() {
            let output = contributor_cons
                .remove(contributor)
                .unwrap()
                .finalize()
                .unwrap();
            p1.insert(contributor.clone(), output);
        }
        let mut contributor_cons = p1;

        // Distribute shares to contributors and send complaints to arbiter
        for (dealer, dealer_key, _) in arb.commitments().iter() {
            for (idx, recipient) in contributors.iter().enumerate() {
                let (_, shares) = contributor_shares.get(dealer_key).unwrap().clone();
                let share = shares[idx];
                match contributor_cons
                    .get_mut(recipient)
                    .unwrap()
                    .share(dealer_key.clone(), share)
                {
                    Err(Error::ShareWrongCommitment) => {}
                    _ => {
                        panic!("expected share to be invalid");
                    }
                }
                let _ = arb.complaint(recipient.clone(), *dealer, &share);
            }
        }

        // Verify failure
        let (result, disqualified) = arb.finalize();
        assert!(result.is_none());
        assert!(disqualified.len() == n as usize);
    }
}
