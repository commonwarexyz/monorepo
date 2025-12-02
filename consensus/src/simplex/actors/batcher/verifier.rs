use crate::simplex::{
    signing_scheme::Scheme,
    types::{
        Attributable, Finalize, Notarize, Nullify, Proposal, SignatureVerification, Vote,
        VoteContext,
    },
};
use commonware_cryptography::Digest;
use rand::{CryptoRng, Rng};

/// `Verifier` is a utility for tracking and batch verifying consensus messages.
///
/// In consensus, verifying multiple signatures at the same time can be much more efficient
/// than verifying them one by one. This struct collects messages from participants in consensus
/// and signals they are ready to be verified when certain conditions are met (e.g., enough messages
/// to potentially reach a quorum, or when a leader's message is received).
///
/// To avoid unnecessary verification, it also tracks the number of already verified messages (ensuring
/// we no longer attempt to verify messages after a quorum of valid messages have already been verified).
pub struct Verifier<S: Scheme, D: Digest> {
    /// Signing scheme used to verify votes and assemble certificates.
    scheme: S,

    /// Required quorum size. `None` disables quorum-based readiness.
    quorum: Option<usize>,

    /// Current leader index.
    leader: Option<u32>,
    /// Proposal associated with the current leader.
    leader_proposal: Option<Proposal<D>>,

    /// Pending notarize votes waiting to be verified.
    notarizes: Vec<Notarize<S, D>>,
    /// Forces notarize verification as soon as possible (set when the leader proposal is known).
    notarizes_force: bool,
    /// Count of already-verified notarize votes.
    notarizes_verified: usize,

    /// Pending nullify votes waiting to be verified.
    nullifies: Vec<Nullify<S>>,
    /// Count of already-verified nullify votes.
    nullifies_verified: usize,

    /// Pending finalize votes waiting to be verified.
    finalizes: Vec<Finalize<S, D>>,
    /// Count of already-verified finalize votes.
    finalizes_verified: usize,
}

impl<S: Scheme, D: Digest> Verifier<S, D> {
    /// Creates a new `Verifier`.
    ///
    /// # Arguments
    ///
    /// * `signing` - Scheme handle used to verify and aggregate votes.
    /// * `quorum` - An optional `u32` specifying the number of votes (2f+1)
    ///   required to reach a quorum. If `None`, batch verification readiness
    ///   checks based on quorum size are skipped.
    pub fn new(scheme: S, quorum: Option<u32>) -> Self {
        Self {
            scheme,

            // Store quorum as usize to simplify comparisons against queue lengths.
            quorum: quorum.map(|q| q as usize),

            leader: None,
            leader_proposal: None,

            notarizes: Vec::new(),
            notarizes_force: false,
            notarizes_verified: 0,

            nullifies: Vec::new(),
            nullifies_verified: 0,

            finalizes: Vec::new(),
            finalizes_verified: 0,
        }
    }

    /// Clears any pending messages that are not for the leader's proposal and forces
    /// the notarizes to be verified.
    ///
    /// We force verification because we need to know the leader's proposal
    /// to begin verifying it.
    fn set_leader_proposal(&mut self, proposal: Proposal<D>) {
        // Drop all notarizes/finalizes that aren't for the leader proposal
        self.notarizes.retain(|n| n.proposal == proposal);
        self.finalizes.retain(|f| f.proposal == proposal);

        // Set the leader proposal
        self.leader_proposal = Some(proposal);

        // Force the notarizes to be verified
        self.notarizes_force = true;
    }

    /// Adds a [Vote] message to the batch for later verification.
    ///
    /// If the message has already been verified (e.g., we built it), it increments
    /// the count of verified messages directly. Otherwise, it adds the message to
    /// the appropriate pending queue.
    ///
    /// If a leader is known and the message is a [Vote::Notarize] from that leader,
    /// this method may trigger `set_leader_proposal`.
    ///
    /// # Arguments
    ///
    /// * `msg` - The [Vote] message to add.
    /// * `verified` - A boolean indicating if the message has already been verified.
    pub fn add(&mut self, msg: Vote<S, D>, verified: bool) {
        match msg {
            Vote::Notarize(notarize) => {
                if let Some(ref leader_proposal) = self.leader_proposal {
                    // If leader proposal is set and the message is not for it, drop it
                    if leader_proposal != &notarize.proposal {
                        return;
                    }
                } else if let Some(leader) = self.leader {
                    // If leader is set but leader proposal is not, set it
                    if leader == notarize.signer() {
                        // Set the leader proposal
                        self.set_leader_proposal(notarize.proposal.clone());
                    }
                }

                // If we've made it this far, add the notarize
                if verified {
                    self.notarizes_verified += 1;
                } else {
                    self.notarizes.push(notarize);
                }
            }
            Vote::Nullify(nullify) => {
                if verified {
                    self.nullifies_verified += 1;
                } else {
                    self.nullifies.push(nullify);
                }
            }
            Vote::Finalize(finalize) => {
                // If leader proposal is set and the message is not for it, drop it
                if let Some(ref leader_proposal) = self.leader_proposal {
                    if leader_proposal != &finalize.proposal {
                        return;
                    }
                }

                // If we've made it this far, add the finalize
                if verified {
                    self.finalizes_verified += 1;
                } else {
                    self.finalizes.push(finalize);
                }
            }
        }
    }

    /// Sets the leader for the current consensus view.
    ///
    /// If the leader is found, we may call `set_leader_proposal` to clear any pending
    /// messages that are not for the leader's proposal and to force verification of said
    /// proposal.
    ///
    /// # Arguments
    ///
    /// * `leader` - The `u32` identifier of the leader.
    pub fn set_leader(&mut self, leader: u32) {
        // Set the leader
        assert!(self.leader.is_none());
        self.leader = Some(leader);

        // Look for a notarize from the leader
        let Some(notarize) = self.notarizes.iter().find(|n| n.signer() == leader) else {
            return;
        };

        // Set the leader proposal
        self.set_leader_proposal(notarize.proposal.clone());
    }

    /// Verifies a batch of pending [Vote::Notarize] messages.
    ///
    /// It uses `S::verify_votes` for efficient batch verification.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    /// * `namespace` - The namespace for signature domain separation.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A `Vec<Vote<S, D>>` of successfully verified [Vote::Notarize] messages.
    /// * A `Vec<u32>` of signer indices for whom verification failed.
    pub fn verify_notarizes<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        namespace: &[u8],
    ) -> (Vec<Vote<S, D>>, Vec<u32>) {
        self.notarizes_force = false;

        let notarizes = std::mem::take(&mut self.notarizes);

        // Early return if there are no notarizes to verify
        if notarizes.is_empty() {
            return (vec![], vec![]);
        }

        let (proposals, signatures): (Vec<_>, Vec<_>) = notarizes
            .into_iter()
            .map(|n| (n.proposal, n.signature))
            .unzip();

        let proposal = &proposals[0];

        let SignatureVerification {
            verified,
            invalid_signers,
        } = self.scheme.verify_votes(
            rng,
            namespace,
            VoteContext::Notarize { proposal },
            signatures,
        );

        self.notarizes_verified += verified.len();

        (
            verified
                .into_iter()
                .zip(proposals)
                .map(|(signature, proposal)| {
                    Vote::Notarize(Notarize {
                        proposal,
                        signature,
                    })
                })
                .collect(),
            invalid_signers,
        )
    }

    /// Checks if there are [Vote::Notarize] messages ready for batch verification.
    ///
    /// Verification is considered "ready" if:
    /// 1. `notarizes_force` is true (e.g., after a leader's proposal is set).
    /// 2. A leader and their proposal are known, and:
    ///    a. The quorum (if set) has not yet been met by verified messages.
    ///    b. The sum of verified and pending messages is enough to potentially reach the quorum.
    /// 3. There are pending [Vote::Notarize] messages to verify.
    ///
    /// # Returns
    ///
    /// `true` if [Vote::Notarize] messages should be verified, `false` otherwise.
    pub fn ready_notarizes(&self) -> bool {
        // If there are no pending notarizes, there is nothing to do.
        if self.notarizes.is_empty() {
            return false;
        }

        // If we have the leader's notarize, we should verify immediately to start
        // block verification.
        if self.notarizes_force {
            return true;
        }

        // If we don't yet know the leader, notarizes may contain messages for
        // a number of different proposals.
        if self.leader.is_none() || self.leader_proposal.is_none() {
            return false;
        }

        // If we have a quorum, we need to check if we have enough verified and pending
        if let Some(quorum) = self.quorum {
            // If we have already performed sufficient verifications, there is nothing more
            // to do.
            if self.notarizes_verified >= quorum {
                return false;
            }

            // If we don't have enough to reach the quorum, there is nothing to do yet.
            if self.notarizes_verified + self.notarizes.len() < quorum {
                return false;
            }
        }

        // If there is no required quorum and we have pending notarizes, we should verify.
        true
    }

    /// Verifies a batch of pending [Vote::Nullify] messages.
    ///
    /// It uses `S::verify_votes` for efficient batch verification.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    /// * `namespace` - The namespace for signature domain separation.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A `Vec<Vote<S, D>>` of successfully verified [Vote::Nullify] messages.
    /// * A `Vec<u32>` of signer indices for whom verification failed.
    pub fn verify_nullifies<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        namespace: &[u8],
    ) -> (Vec<Vote<S, D>>, Vec<u32>) {
        let nullifies = std::mem::take(&mut self.nullifies);

        // Early return if there are no nullifies to verify
        if nullifies.is_empty() {
            return (vec![], vec![]);
        }

        let round = nullifies[0].round;

        let SignatureVerification {
            verified,
            invalid_signers,
        } = self.scheme.verify_votes::<_, D, _>(
            rng,
            namespace,
            VoteContext::Nullify { round },
            nullifies.into_iter().map(|nullify| nullify.signature),
        );

        self.nullifies_verified += verified.len();

        (
            verified
                .into_iter()
                .map(|signature| Vote::Nullify(Nullify { round, signature }))
                .collect(),
            invalid_signers,
        )
    }

    /// Checks if there are [Vote::Nullify] messages ready for batch verification.
    ///
    /// Verification is considered "ready" if:
    /// 1. The quorum (if set) has not yet been met by verified messages.
    /// 2. The sum of verified and pending messages is enough to potentially reach the quorum.
    /// 3. There are pending [Vote::Nullify] messages to verify.
    ///
    /// # Returns
    ///
    /// `true` if [Vote::Nullify] messages should be verified, `false` otherwise.
    pub fn ready_nullifies(&self) -> bool {
        // If there are no pending nullifies, there is nothing to do.
        if self.nullifies.is_empty() {
            return false;
        }

        if let Some(quorum) = self.quorum {
            // If we have already performed sufficient verifications, there is nothing more
            // to do.
            if self.nullifies_verified >= quorum {
                return false;
            }

            // If we don't have enough to reach the quorum, there is nothing to do yet.
            if self.nullifies_verified + self.nullifies.len() < quorum {
                return false;
            }
        }

        // If there is no required quorum and we have pending nullifies, we should verify.
        true
    }

    /// Verifies a batch of pending [Vote::Finalize] messages.
    ///
    /// It uses `S::verify_votes` for efficient batch verification.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    /// * `namespace` - The namespace for signature domain separation.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * A `Vec<Vote<S, D>>` of successfully verified [Vote::Finalize] messages.
    /// * A `Vec<u32>` of signer indices for whom verification failed.
    pub fn verify_finalizes<R: Rng + CryptoRng>(
        &mut self,
        rng: &mut R,
        namespace: &[u8],
    ) -> (Vec<Vote<S, D>>, Vec<u32>) {
        let finalizes = std::mem::take(&mut self.finalizes);

        // Early return if there are no finalizes to verify
        if finalizes.is_empty() {
            return (vec![], vec![]);
        }

        let (proposals, signatures): (Vec<_>, Vec<_>) = finalizes
            .into_iter()
            .map(|n| (n.proposal, n.signature))
            .unzip();

        let proposal = &proposals[0];

        let SignatureVerification {
            verified,
            invalid_signers,
        } = self.scheme.verify_votes(
            rng,
            namespace,
            VoteContext::Finalize { proposal },
            signatures,
        );

        self.finalizes_verified += verified.len();

        (
            verified
                .into_iter()
                .zip(proposals)
                .map(|(signature, proposal)| {
                    Vote::Finalize(Finalize {
                        proposal,
                        signature,
                    })
                })
                .collect(),
            invalid_signers,
        )
    }

    /// Checks if there are [Vote::Finalize] messages ready for batch verification.
    ///
    /// Verification is considered "ready" if:
    /// 1. A leader and their proposal are known (finalizes are proposal-specific).
    /// 2. The quorum (if set) has not yet been met by verified messages.
    /// 3. The sum of verified and pending messages is enough to potentially reach the quorum.
    /// 4. There are pending [Vote::Finalize] messages to verify.
    ///
    /// # Returns
    ///
    /// `true` if [Vote::Finalize] messages should be verified, `false` otherwise.
    pub fn ready_finalizes(&self) -> bool {
        // If there are no pending finalizes, there is nothing to do.
        if self.finalizes.is_empty() {
            return false;
        }

        // If we don't yet know the leader, finalizers may contain messages for
        // a number of different proposals.
        if self.leader.is_none() || self.leader_proposal.is_none() {
            return false;
        }
        if let Some(quorum) = self.quorum {
            // If we have already performed sufficient verifications, there is nothing more
            // to do.
            if self.finalizes_verified >= quorum {
                return false;
            }

            // If we don't have enough to reach the quorum, there is nothing to do yet.
            if self.finalizes_verified + self.finalizes.len() < quorum {
                return false;
            }
        }

        // If there is no required quorum and we have pending finalizes, we should verify.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::signing_scheme::{bls12381_threshold, ed25519},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::{
            dkg::ops::{self},
            primitives::variant::MinSig,
        },
        ed25519::{PrivateKey as EdPrivateKey, PublicKey as EdPublicKey},
        sha256::Digest as Sha256,
        PrivateKeyExt, Signer,
    };
    use commonware_utils::{quorum, set::Ordered};
    use rand::{
        rngs::{OsRng, StdRng},
        SeedableRng,
    };

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256 {
        Sha256::from([v; 32]) // Simple fixed digest for testing
    }

    fn generate_bls12381_threshold_schemes(
        n: u32,
        seed: u64,
    ) -> Vec<bls12381_threshold::Scheme<EdPublicKey, MinSig>> {
        let mut rng = StdRng::seed_from_u64(seed);
        let t = quorum(n);

        // Generate ed25519 keys for participant identities
        let participants: Vec<_> = (0..n)
            .map(|_| EdPrivateKey::from_rng(&mut rng).public_key())
            .collect();
        let (polynomial, shares) = ops::generate_shares::<_, MinSig>(&mut rng, None, n, t);

        shares
            .into_iter()
            .map(|share| {
                bls12381_threshold::Scheme::new(participants.clone().into(), &polynomial, share)
            })
            .collect()
    }

    fn generate_ed25519_schemes(n: usize, seed: u64) -> Vec<ed25519::Scheme> {
        let mut rng = StdRng::seed_from_u64(seed);
        let private_keys: Vec<_> = (0..n).map(|_| EdPrivateKey::from_rng(&mut rng)).collect();

        let participants: Ordered<_> = private_keys.iter().map(|p| p.public_key()).collect();

        private_keys
            .into_iter()
            .map(|sk| ed25519::Scheme::new(participants.clone(), sk))
            .collect()
    }

    // Helper to create a Notarize message for any signing scheme
    fn create_notarize<S: Scheme>(
        scheme: &S,
        round: Round,
        parent_view: View,
        payload_val: u8,
    ) -> Notarize<S, Sha256> {
        let proposal = Proposal::new(round, parent_view, sample_digest(payload_val));
        Notarize::sign(scheme, NAMESPACE, proposal).unwrap()
    }

    // Helper to create a Nullify message for any signing scheme
    fn create_nullify<S: Scheme>(scheme: &S, round: Round) -> Nullify<S> {
        Nullify::sign::<Sha256>(scheme, NAMESPACE, round).unwrap()
    }

    // Helper to create a Finalize message for any signing scheme
    fn create_finalize<S: Scheme>(
        scheme: &S,
        round: Round,
        parent_view: View,
        payload_val: u8,
    ) -> Finalize<S, Sha256> {
        let proposal = Proposal::new(round, parent_view, sample_digest(payload_val));
        Finalize::sign(scheme, NAMESPACE, proposal).unwrap()
    }

    fn add_notarize<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));

        let round = Round::new(Epoch::new(0), View::new(1));
        let notarize1 = create_notarize(&schemes[0], round, View::new(0), 1);
        let notarize2 = create_notarize(&schemes[1], round, View::new(0), 1);
        let notarize_diff = create_notarize(&schemes[2], round, View::new(0), 2);

        verifier.add(Vote::Notarize(notarize1.clone()), false);
        assert_eq!(verifier.notarizes.len(), 1);
        assert_eq!(verifier.notarizes_verified, 0);

        verifier.add(Vote::Notarize(notarize1.clone()), true);
        assert_eq!(verifier.notarizes.len(), 1);
        assert_eq!(verifier.notarizes_verified, 1);

        verifier.set_leader(notarize1.signer());
        assert!(verifier.leader_proposal.is_some());
        assert_eq!(
            verifier.leader_proposal.as_ref().unwrap(),
            &notarize1.proposal
        );
        assert!(verifier.notarizes_force);
        assert_eq!(verifier.notarizes.len(), 1);

        verifier.add(Vote::Notarize(notarize2.clone()), false);
        assert_eq!(verifier.notarizes.len(), 2);

        verifier.add(Vote::Notarize(notarize_diff.clone()), false);
        assert_eq!(verifier.notarizes.len(), 2);

        let mut verifier2 = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round2 = Round::new(Epoch::new(0), View::new(2));
        let notarize_non_leader = create_notarize(&schemes[1], round2, View::new(1), 3);
        let notarize_leader = create_notarize(&schemes[0], round2, View::new(1), 3);

        verifier2.set_leader(notarize_leader.signer());
        verifier2.add(Vote::Notarize(notarize_non_leader.clone()), false);
        assert!(verifier2.leader_proposal.is_none());
        assert_eq!(verifier2.notarizes.len(), 1);

        verifier2.add(Vote::Notarize(notarize_leader.clone()), false);
        assert!(verifier2.leader_proposal.is_some());
        assert_eq!(
            verifier2.leader_proposal.as_ref().unwrap(),
            &notarize_leader.proposal
        );
        assert_eq!(verifier2.notarizes.len(), 2);
    }

    #[test]
    fn test_add_notarize() {
        add_notarize(generate_bls12381_threshold_schemes(5, 123));
        add_notarize(generate_ed25519_schemes(5, 123));
    }

    fn set_leader<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));

        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        let other_notarize = create_notarize(&schemes[1], round, View::new(0), 1);

        verifier.add(Vote::Notarize(other_notarize.clone()), false);
        assert_eq!(verifier.notarizes.len(), 1);

        let leader = leader_notarize.signer();
        verifier.set_leader(leader);
        assert_eq!(verifier.leader, Some(leader));
        assert!(verifier.leader_proposal.is_none());
        assert!(!verifier.notarizes_force);
        assert_eq!(verifier.notarizes.len(), 1);

        verifier.add(Vote::Notarize(leader_notarize.clone()), false);
        assert!(verifier.leader_proposal.is_some());
        assert_eq!(
            verifier.leader_proposal.as_ref().unwrap(),
            &leader_notarize.proposal
        );
        assert!(verifier.notarizes_force);
        assert_eq!(verifier.notarizes.len(), 2);
    }

    #[test]
    fn test_set_leader() {
        set_leader(generate_bls12381_threshold_schemes(5, 124));
        set_leader(generate_ed25519_schemes(5, 124));
    }

    fn ready_and_verify_notarizes<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        let round = Round::new(Epoch::new(0), View::new(1));
        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| create_notarize(scheme, round, View::new(0), 1))
            .collect();

        assert!(!verifier.ready_notarizes());

        verifier.set_leader(notarizes[0].signer());
        verifier.add(Vote::Notarize(notarizes[0].clone()), false);
        assert!(verifier.ready_notarizes());
        assert_eq!(verifier.notarizes.len(), 1);

        let (verified_once, failed_once) = verifier.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified_once.len(), 1);
        assert!(failed_once.is_empty());
        assert_eq!(verifier.notarizes_verified, 1);
        assert!(verifier.notarizes.is_empty());
        assert!(!verifier.notarizes_force);

        verifier.add(Vote::Notarize(notarizes[1].clone()), false);
        assert!(!verifier.ready_notarizes());
        verifier.add(Vote::Notarize(notarizes[2].clone()), false);
        assert!(!verifier.ready_notarizes());
        verifier.add(Vote::Notarize(notarizes[3].clone()), false);
        assert!(verifier.ready_notarizes());
        assert_eq!(verifier.notarizes.len(), 3);

        let (verified_bulk, failed_bulk) = verifier.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified_bulk.len(), 3);
        assert!(failed_bulk.is_empty());
        assert_eq!(verifier.notarizes_verified, 4);
        assert!(verifier.notarizes.is_empty());
        assert!(!verifier.ready_notarizes());

        let mut verifier2 = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round2 = Round::new(Epoch::new(0), View::new(2));
        let leader_vote = create_notarize(&schemes[0], round2, View::new(1), 10);
        let mut faulty_vote = create_notarize(&schemes[1], round2, View::new(1), 10);
        verifier2.set_leader(leader_vote.signer());
        verifier2.add(Vote::Notarize(leader_vote.clone()), false);
        faulty_vote.signature.signer = (schemes.len() as u32) + 10;
        verifier2.add(Vote::Notarize(faulty_vote.clone()), false);
        assert!(verifier2.ready_notarizes());

        let (verified_second, failed_second) = verifier2.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified_second.len(), 1);
        assert!(verified_second
            .into_iter()
            .any(|v| matches!(v, Vote::Notarize(ref n) if n == &leader_vote)));
        assert_eq!(failed_second, vec![faulty_vote.signer()]);
    }

    #[test]
    fn test_ready_and_verify_notarizes() {
        ready_and_verify_notarizes(generate_bls12381_threshold_schemes(5, 125));
        ready_and_verify_notarizes(generate_ed25519_schemes(5, 125));
    }

    fn add_nullify<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(Epoch::new(0), View::new(1));
        let nullify = create_nullify(&schemes[0], round);

        verifier.add(Vote::Nullify(nullify.clone()), false);
        assert_eq!(verifier.nullifies.len(), 1);
        assert_eq!(verifier.nullifies_verified, 0);

        verifier.add(Vote::Nullify(nullify.clone()), true);
        assert_eq!(verifier.nullifies.len(), 1);
        assert_eq!(verifier.nullifies_verified, 1);
    }

    #[test]
    fn test_add_nullify() {
        add_nullify(generate_bls12381_threshold_schemes(5, 127));
        add_nullify(generate_ed25519_schemes(5, 127));
    }

    fn ready_and_verify_nullifies<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        let round = Round::new(Epoch::new(0), View::new(1));
        let nullifies: Vec<_> = schemes
            .iter()
            .map(|scheme| create_nullify(scheme, round))
            .collect();

        verifier.add(Vote::Nullify(nullifies[0].clone()), true);
        assert_eq!(verifier.nullifies_verified, 1);

        verifier.add(Vote::Nullify(nullifies[1].clone()), false);
        assert!(!verifier.ready_nullifies());
        verifier.add(Vote::Nullify(nullifies[2].clone()), false);
        assert!(!verifier.ready_nullifies());
        verifier.add(Vote::Nullify(nullifies[3].clone()), false);
        assert!(verifier.ready_nullifies());
        assert_eq!(verifier.nullifies.len(), 3);

        let (verified, failed) = verifier.verify_nullifies(&mut rng, NAMESPACE);
        assert_eq!(verified.len(), 3);
        assert!(failed.is_empty());
        assert_eq!(verifier.nullifies_verified, 4);
        assert!(verifier.nullifies.is_empty());
        assert!(!verifier.ready_nullifies());
    }

    #[test]
    fn test_ready_and_verify_nullifies() {
        ready_and_verify_nullifies(generate_bls12381_threshold_schemes(5, 128));
        ready_and_verify_nullifies(generate_ed25519_schemes(5, 128));
    }

    fn add_finalize<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(Epoch::new(0), View::new(1));
        let finalize_a = create_finalize(&schemes[0], round, View::new(0), 1);
        let finalize_b = create_finalize(&schemes[1], round, View::new(0), 2);

        verifier.add(Vote::Finalize(finalize_b.clone()), false);
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes_verified, 0);

        verifier.add(Vote::Finalize(finalize_a.clone()), false);
        assert_eq!(verifier.finalizes.len(), 2);

        verifier.set_leader(finalize_a.signer());
        assert!(verifier.leader_proposal.is_none());
        verifier.set_leader_proposal(finalize_a.proposal.clone());
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes[0], finalize_a);
        assert_eq!(verifier.finalizes_verified, 0);

        verifier.add(Vote::Finalize(finalize_a.clone()), true);
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes_verified, 1);

        verifier.add(Vote::Finalize(finalize_b.clone()), false);
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes_verified, 1);
    }

    #[test]
    fn test_add_finalize() {
        add_finalize(generate_bls12381_threshold_schemes(5, 129));
        add_finalize(generate_ed25519_schemes(5, 129));
    }

    fn ready_and_verify_finalizes<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        let round = Round::new(Epoch::new(0), View::new(1));
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| create_finalize(scheme, round, View::new(0), 1))
            .collect();

        assert!(!verifier.ready_finalizes());

        verifier.set_leader(finalizes[0].signer());
        verifier.set_leader_proposal(finalizes[0].proposal.clone());

        verifier.add(Vote::Finalize(finalizes[0].clone()), true);
        assert_eq!(verifier.finalizes_verified, 1);
        assert!(verifier.finalizes.is_empty());

        verifier.add(Vote::Finalize(finalizes[1].clone()), false);
        assert!(!verifier.ready_finalizes());
        verifier.add(Vote::Finalize(finalizes[2].clone()), false);
        assert!(!verifier.ready_finalizes());
        verifier.add(Vote::Finalize(finalizes[3].clone()), false);
        assert!(verifier.ready_finalizes());

        let (verified, failed) = verifier.verify_finalizes(&mut rng, NAMESPACE);
        assert_eq!(verified.len(), 3);
        assert!(failed.is_empty());
        assert_eq!(verifier.finalizes_verified, 4);
        assert!(verifier.finalizes.is_empty());
        assert!(!verifier.ready_finalizes());
    }

    #[test]
    fn test_ready_and_verify_finalizes() {
        ready_and_verify_finalizes(generate_bls12381_threshold_schemes(5, 130));
        ready_and_verify_finalizes(generate_ed25519_schemes(5, 130));
    }

    fn quorum_none<S: Scheme + Clone>(schemes: Vec<S>) {
        let mut rng = OsRng;
        let round = Round::new(Epoch::new(0), View::new(1));

        let mut verifier_notarize = Verifier::<S, Sha256>::new(schemes[0].clone(), None);
        let notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        assert!(!verifier_notarize.ready_notarizes());
        verifier_notarize.set_leader(notarize.signer());
        verifier_notarize.add(Vote::Notarize(notarize.clone()), false);
        assert!(verifier_notarize.ready_notarizes());
        let (verified_notarize, failed_notarize) =
            verifier_notarize.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified_notarize.len(), 1);
        assert!(failed_notarize.is_empty());
        assert_eq!(verifier_notarize.notarizes_verified, 1);
        assert!(!verifier_notarize.ready_notarizes());

        let mut verifier_null = Verifier::<S, Sha256>::new(schemes[0].clone(), None);
        let nullify = create_nullify(&schemes[0], round);
        assert!(!verifier_null.ready_nullifies());
        verifier_null.add(Vote::Nullify(nullify.clone()), false);
        assert!(verifier_null.ready_nullifies());
        let (verified_null, failed_null) = verifier_null.verify_nullifies(&mut rng, NAMESPACE);
        assert_eq!(verified_null.len(), 1);
        assert!(failed_null.is_empty());
        assert_eq!(verifier_null.nullifies_verified, 1);
        assert!(!verifier_null.ready_nullifies());

        let mut verifier_final = Verifier::<S, Sha256>::new(schemes[0].clone(), None);
        let finalize = create_finalize(&schemes[0], round, View::new(0), 1);
        assert!(!verifier_final.ready_finalizes());
        verifier_final.set_leader(finalize.signer());
        verifier_final.set_leader_proposal(finalize.proposal.clone());
        verifier_final.add(Vote::Finalize(finalize.clone()), false);
        assert!(verifier_final.ready_finalizes());
        let (verified_fin, failed_fin) = verifier_final.verify_finalizes(&mut rng, NAMESPACE);
        assert_eq!(verified_fin.len(), 1);
        assert!(failed_fin.is_empty());
        assert_eq!(verifier_final.finalizes_verified, 1);
        assert!(!verifier_final.ready_finalizes());
    }

    #[test]
    fn test_quorum_none() {
        quorum_none(generate_bls12381_threshold_schemes(3, 200));
        quorum_none(generate_ed25519_schemes(3, 200));
    }

    fn leader_proposal_filters_messages<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(Epoch::new(0), View::new(1));
        let proposal_a = Proposal::new(round, View::new(0), sample_digest(10));
        let proposal_b = Proposal::new(round, View::new(0), sample_digest(20));

        let notarize_a = Notarize::sign(&schemes[0], NAMESPACE, proposal_a.clone()).unwrap();
        let notarize_b = Notarize::sign(&schemes[1], NAMESPACE, proposal_b.clone()).unwrap();
        let finalize_a = Finalize::sign(&schemes[0], NAMESPACE, proposal_a.clone()).unwrap();
        let finalize_b = Finalize::sign(&schemes[1], NAMESPACE, proposal_b.clone()).unwrap();

        verifier.add(Vote::Notarize(notarize_a.clone()), false);
        verifier.add(Vote::Notarize(notarize_b.clone()), false);
        verifier.add(Vote::Finalize(finalize_a.clone()), false);
        verifier.add(Vote::Finalize(finalize_b.clone()), false);

        assert_eq!(verifier.notarizes.len(), 2);
        assert_eq!(verifier.finalizes.len(), 2);

        verifier.set_leader(notarize_a.signer());

        assert!(verifier.notarizes_force);
        assert_eq!(verifier.notarizes.len(), 1);
        assert_eq!(verifier.notarizes[0].proposal, proposal_a);
        assert_eq!(verifier.finalizes.len(), 1);
        assert_eq!(verifier.finalizes[0].proposal, proposal_a);
    }

    #[test]
    fn test_leader_proposal_filters_messages() {
        leader_proposal_filters_messages(generate_bls12381_threshold_schemes(3, 201));
        leader_proposal_filters_messages(generate_ed25519_schemes(3, 201));
    }

    fn set_leader_twice_panics<S: Scheme + Clone>(schemes: Vec<S>) {
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(3));
        verifier.set_leader(0);
        verifier.set_leader(1);
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_bls() {
        set_leader_twice_panics(generate_bls12381_threshold_schemes(3, 212));
    }

    #[test]
    #[should_panic(expected = "self.leader.is_none()")]
    fn test_set_leader_twice_panics_ed() {
        set_leader_twice_panics(generate_ed25519_schemes(3, 213));
    }
    fn notarizes_force_flag<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);

        verifier.set_leader(leader_vote.signer());
        verifier.add(Vote::Notarize(leader_vote.clone()), false);

        assert!(
            verifier.notarizes_force,
            "notarizes_force should be true after leader's proposal is set"
        );
        assert!(verifier.ready_notarizes());

        let (verified, _) = verifier.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified.len(), 1);
        assert!(
            !verifier.notarizes_force,
            "notarizes_force should be false after verification"
        );
        assert!(!verifier.ready_notarizes());
    }

    #[test]
    fn test_ready_notarizes_behavior_with_force_flag() {
        notarizes_force_flag(generate_bls12381_threshold_schemes(3, 203));
        notarizes_force_flag(generate_ed25519_schemes(3, 203));
    }

    fn ready_notarizes_without_leader<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(Epoch::new(0), View::new(1));

        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| create_notarize(scheme, round, View::new(0), 1))
            .collect();

        for vote in notarizes.iter() {
            verifier.add(Vote::Notarize(vote.clone()), false);
        }

        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready without leader/proposal set"
        );

        verifier.set_leader(notarizes[0].signer());
        assert!(
            verifier.ready_notarizes(),
            "Should be ready once leader is set"
        );
    }

    #[test]
    fn test_ready_notarizes_without_leader_or_proposal() {
        ready_notarizes_without_leader(generate_bls12381_threshold_schemes(3, 204));
        ready_notarizes_without_leader(generate_ed25519_schemes(3, 204));
    }

    fn ready_finalizes_without_leader<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(Epoch::new(0), View::new(1));
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| create_finalize(scheme, round, View::new(0), 1))
            .collect();

        for finalize in finalizes.iter() {
            verifier.add(Vote::Finalize(finalize.clone()), false);
        }

        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready without leader/proposal set"
        );

        verifier.set_leader(finalizes[0].signer());
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready without leader_proposal set"
        );
    }

    #[test]
    fn test_ready_finalizes_without_leader_or_proposal() {
        ready_finalizes_without_leader(generate_bls12381_threshold_schemes(3, 205));
        ready_finalizes_without_leader(generate_ed25519_schemes(3, 205));
    }

    fn verify_notarizes_empty<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_proposal = Proposal::new(round, View::new(0), sample_digest(1));
        verifier.set_leader_proposal(leader_proposal);
        assert!(verifier.notarizes_force);
        assert!(verifier.notarizes.is_empty());
        assert!(!verifier.ready_notarizes());
    }

    #[test]
    fn test_verify_notarizes_empty_pending_when_forced() {
        verify_notarizes_empty(generate_bls12381_threshold_schemes(3, 206));
        verify_notarizes_empty(generate_ed25519_schemes(3, 206));
    }

    fn verify_nullifies_empty<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        assert!(verifier.nullifies.is_empty());
        assert!(!verifier.ready_nullifies());
        let (verified, failed) = verifier.verify_nullifies(&mut rng, NAMESPACE);
        assert!(verified.is_empty());
        assert!(failed.is_empty());
        assert_eq!(verifier.nullifies_verified, 0);
    }

    #[test]
    fn test_verify_nullifies_empty_pending() {
        verify_nullifies_empty(generate_bls12381_threshold_schemes(3, 207));
        verify_nullifies_empty(generate_ed25519_schemes(3, 207));
    }

    fn verify_finalizes_empty<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        verifier.set_leader(0);
        assert!(verifier.finalizes.is_empty());
        assert!(!verifier.ready_finalizes());
        let (verified, failed) = verifier.verify_finalizes(&mut rng, NAMESPACE);
        assert!(verified.is_empty());
        assert!(failed.is_empty());
        assert_eq!(verifier.finalizes_verified, 0);
    }

    #[test]
    fn test_verify_finalizes_empty_pending() {
        verify_finalizes_empty(generate_bls12381_threshold_schemes(3, 208));
        verify_finalizes_empty(generate_ed25519_schemes(3, 208));
    }

    fn ready_notarizes_exact_quorum<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let mut rng = OsRng;
        let round = Round::new(Epoch::new(0), View::new(1));

        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_vote.signer());
        verifier.add(Vote::Notarize(leader_vote.clone()), true);
        assert_eq!(verifier.notarizes_verified, 1);

        let second_vote = create_notarize(&schemes[1], round, View::new(0), 1);
        verifier.add(Vote::Notarize(second_vote.clone()), false);
        assert!(verifier.ready_notarizes());
        let (verified_once, failed_once) = verifier.verify_notarizes(&mut rng, NAMESPACE);
        assert_eq!(verified_once.len(), 1);
        assert!(failed_once.is_empty());
        assert_eq!(verifier.notarizes_verified, 2);

        for scheme in schemes.iter().take(quorum as usize).skip(2) {
            assert!(!verifier.ready_notarizes());
            verifier.add(
                Vote::Notarize(create_notarize(scheme, round, View::new(0), 1)),
                false,
            );
        }

        assert!(verifier.ready_notarizes());
    }

    #[test]
    fn test_ready_notarizes_exact_quorum() {
        ready_notarizes_exact_quorum(generate_bls12381_threshold_schemes(5, 209));
        ready_notarizes_exact_quorum(generate_ed25519_schemes(5, 209));
    }

    fn ready_nullifies_exact_quorum<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(Epoch::new(0), View::new(1));

        verifier.add(Vote::Nullify(create_nullify(&schemes[0], round)), true);
        assert_eq!(verifier.nullifies_verified, 1);

        for scheme in schemes.iter().take(quorum as usize).skip(1) {
            assert!(!verifier.ready_nullifies());
            verifier.add(Vote::Nullify(create_nullify(scheme, round)), false);
        }

        assert!(verifier.ready_nullifies());
    }

    #[test]
    fn test_ready_nullifies_exact_quorum() {
        ready_nullifies_exact_quorum(generate_bls12381_threshold_schemes(5, 210));
        ready_nullifies_exact_quorum(generate_ed25519_schemes(5, 210));
    }

    fn ready_finalizes_exact_quorum<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_finalize = create_finalize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_finalize.signer());
        verifier.set_leader_proposal(leader_finalize.proposal.clone());
        verifier.add(Vote::Finalize(leader_finalize), true);
        assert_eq!(verifier.finalizes_verified, 1);

        for scheme in schemes.iter().take(quorum as usize).skip(1) {
            assert!(!verifier.ready_finalizes());
            verifier.add(
                Vote::Finalize(create_finalize(scheme, round, View::new(0), 1)),
                false,
            );
        }

        assert!(verifier.ready_finalizes());
    }

    #[test]
    fn test_ready_finalizes_exact_quorum() {
        ready_finalizes_exact_quorum(generate_bls12381_threshold_schemes(5, 211));
        ready_finalizes_exact_quorum(generate_ed25519_schemes(5, 211));
    }

    fn ready_notarizes_quorum_already_met_by_verified<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(Epoch::new(0), View::new(1));

        // Pre-load the leader vote as if it had already been processed.
        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_vote.signer());
        verifier.add(Vote::Notarize(leader_vote.clone()), false);
        verifier.notarizes_force = false;

        // Mark enough verified notarizes to satisfy the quorum outright.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(
                Vote::Notarize(create_notarize(scheme, round, View::new(0), 1)),
                true,
            );
        }
        assert_eq!(verifier.notarizes_verified, quorum as usize);
        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Additional pending votes must not flip readiness in this situation.
        let extra_vote = create_notarize(&schemes[quorum as usize], round, View::new(0), 1);
        verifier.add(Vote::Notarize(extra_vote), false);
        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_notarizes_quorum_already_met_by_verified() {
        ready_notarizes_quorum_already_met_by_verified(generate_bls12381_threshold_schemes(5, 212));
        ready_notarizes_quorum_already_met_by_verified(generate_ed25519_schemes(5, 212));
    }

    fn ready_nullifies_quorum_already_met_by_verified<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(Epoch::new(0), View::new(1));

        // First mark a quorum's worth of verified nullifies.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(Vote::Nullify(create_nullify(scheme, round)), true);
        }
        assert_eq!(verifier.nullifies_verified, quorum as usize);
        assert!(
            !verifier.ready_nullifies(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Pending messages alone cannot transition the batch to ready.
        let extra_nullify = create_nullify(&schemes[quorum as usize], round);
        verifier.add(Vote::Nullify(extra_nullify), false);
        assert!(
            !verifier.ready_nullifies(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_nullifies_quorum_already_met_by_verified() {
        ready_nullifies_quorum_already_met_by_verified(generate_bls12381_threshold_schemes(5, 213));
        ready_nullifies_quorum_already_met_by_verified(generate_ed25519_schemes(5, 213));
    }

    fn ready_finalizes_quorum_already_met_by_verified<S: Scheme + Clone>(schemes: Vec<S>) {
        let quorum = quorum(schemes.len() as u32);
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), Some(quorum));
        let round = Round::new(Epoch::new(0), View::new(1));

        // Prime the leader state so the quorum is already satisfied by verified finalizes.
        let leader_finalize = create_finalize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_finalize.signer());
        verifier.set_leader_proposal(leader_finalize.proposal.clone());

        // Feed exactly the number of verified finalizes required to hit the quorum.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(
                Vote::Finalize(create_finalize(scheme, round, View::new(0), 1)),
                true,
            );
        }
        assert_eq!(verifier.finalizes_verified, quorum as usize);
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Ensure additional pending finalizes do not incorrectly trigger readiness.
        let extra_finalize = create_finalize(&schemes[quorum as usize], round, View::new(0), 1);
        verifier.add(Vote::Finalize(extra_finalize), false);
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_finalizes_quorum_already_met_by_verified() {
        ready_finalizes_quorum_already_met_by_verified(generate_bls12381_threshold_schemes(5, 214));
        ready_finalizes_quorum_already_met_by_verified(generate_ed25519_schemes(5, 214));
    }
}
