use crate::{
    simplex::{
        scheme::Scheme,
        types::{phase, Attributable, Phase, Proposal, Signed, Vote},
    },
    types::Participant,
};
use commonware_cryptography::{certificate::Verification, Digest};
use commonware_parallel::Strategy;
use rand_core::CryptoRng;

/// `Verifier` is a utility for tracking and verifying consensus messages.
///
/// For schemes where [`Verifier::is_batchable()`](commonware_cryptography::certificate::Verifier::is_batchable)
/// returns `true` (such as [ed25519], [bls12381_multisig] and [bls12381_threshold]), this struct collects
/// messages and defers verification until enough messages exist to potentially reach a quorum, enabling
/// efficient batch verification. For schemes where `is_batchable()` returns `false` (such as [secp256r1]),
/// signatures are verified eagerly as they arrive since there is no batching benefit.
///
/// To avoid unnecessary verification, it also tracks the number of already verified messages (ensuring
/// we no longer attempt to verify messages after a quorum of valid messages have already been verified).
///
/// [ed25519]: crate::simplex::scheme::ed25519
/// [bls12381_multisig]: crate::simplex::scheme::bls12381_multisig
/// [bls12381_threshold]: crate::simplex::scheme::bls12381_threshold
/// [secp256r1]: crate::simplex::scheme::secp256r1
pub struct Verifier<S: Scheme<D>, D: Digest> {
    /// Signing scheme used to verify votes and assemble certificates.
    scheme: S,

    /// Required quorum size.
    quorum: usize,

    /// What is known about the round's leader.
    leader: Leader<D>,

    /// Pending notarize votes.
    notarizes: Pending<phase::Notarize, S, D>,
    /// Pending nullify votes.
    nullifies: Pending<phase::Nullify, S, D>,
    /// Pending finalize votes.
    finalizes: Pending<phase::Finalize, S, D>,
}

/// What is known about the round's leader, in increasing order of knowledge.
///
/// Notarize and finalize votes can only be batch-verified against the leader's
/// proposal, so readiness for those phases requires reaching [Leader::Proposed].
#[derive(Debug, PartialEq, Eq)]
enum Leader<D: Digest> {
    /// No leader elected yet.
    Unknown,
    /// The leader is elected; their proposal is not yet known.
    Elected(Participant),
    /// The leader is elected and their proposal is known.
    Proposed(Participant, Proposal<D>),
}

/// Pending votes of one kind, alongside the count of votes already verified.
struct Pending<P: Phase, S: Scheme<D>, D: Digest> {
    /// Votes waiting to be verified.
    votes: Vec<Signed<P, S, D>>,
    /// Count of already-verified votes.
    verified: usize,
}

impl<P: Phase, S: Scheme<D>, D: Digest> Pending<P, S, D> {
    const fn new() -> Self {
        Self {
            votes: Vec::new(),
            verified: 0,
        }
    }

    /// Records a vote, either as already verified or as pending verification.
    fn add(&mut self, vote: Signed<P, S, D>, verified: bool) {
        if verified {
            self.verified += 1;
        } else {
            self.votes.push(vote);
        }
    }

    /// Verifies all pending votes as a batch.
    ///
    /// Returns the successfully verified votes and the signer indices for whom
    /// verification failed.
    fn verify<R: CryptoRng>(
        &mut self,
        scheme: &S,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> (Vec<Signed<P, S, D>>, Vec<Participant>) {
        let votes = std::mem::take(&mut self.votes);
        if votes.is_empty() {
            return (vec![], vec![]);
        }

        let (claims, attestations): (Vec<_>, Vec<_>) = votes
            .into_iter()
            .map(|vote| (vote.claim, vote.attestation))
            .unzip();

        let Verification { verified, invalid } = scheme.verify_attestations::<_, D, _>(
            rng,
            P::subject(&claims[0]),
            attestations,
            strategy,
        );

        self.verified += verified.len();

        (
            verified
                .into_iter()
                .zip(claims)
                .map(|(attestation, claim)| Signed { claim, attestation })
                .collect(),
            invalid,
        )
    }

    /// Returns whether the pending votes are worth verifying now.
    ///
    /// Verification is "ready" when there are pending votes, quorum has not already
    /// been met by verified votes, and either the pending votes could complete a
    /// quorum or the scheme does not benefit from batching (eager verification).
    fn ready(&self, quorum: usize) -> bool {
        if self.votes.is_empty() {
            return false;
        }
        if self.verified >= quorum {
            return false;
        }
        if !S::is_batchable() {
            return true;
        }
        self.verified + self.votes.len() >= quorum
    }
}

impl<S: Scheme<D>, D: Digest> Verifier<S, D> {
    /// Creates a new `Verifier`.
    ///
    /// # Arguments
    ///
    /// * `signing` - Scheme handle used to verify and aggregate votes.
    /// * `quorum` - An optional `u32` specifying the number of votes (2f+1)
    ///   required to reach a quorum. If `None`, batch verification readiness
    ///   checks based on quorum size are skipped.
    pub const fn new(scheme: S, quorum: u32) -> Self {
        Self {
            scheme,

            // Store quorum as usize to simplify comparisons against queue lengths.
            quorum: quorum as usize,

            leader: Leader::Unknown,

            notarizes: Pending::new(),
            nullifies: Pending::new(),
            finalizes: Pending::new(),
        }
    }

    /// Sets the leader's proposal and filters out any pending votes for other proposals.
    ///
    /// Once the leader's proposal is known, we only care about votes for that specific
    /// proposal. Any votes for other proposals are dropped since they cannot contribute
    /// to a valid certificate.
    fn set_leader_proposal(&mut self, proposal: Proposal<D>) {
        let Leader::Elected(leader) = self.leader else {
            panic!("leader must be elected before their proposal is known");
        };
        self.notarizes.votes.retain(|n| n.claim == proposal);
        self.finalizes.votes.retain(|f| f.claim == proposal);
        self.leader = Leader::Proposed(leader, proposal);
    }

    /// Returns the leader and their proposal, if known.
    pub fn get_leader_proposal(&self) -> Option<(Participant, Proposal<D>)> {
        match &self.leader {
            Leader::Proposed(leader, proposal) => Some((*leader, proposal.clone())),
            Leader::Unknown | Leader::Elected(_) => None,
        }
    }

    /// Adds an unverified [Vote] to the pending queue for batch verification.
    ///
    /// If a leader is known and the message is a [Vote::Notarize] from that leader,
    /// this method may trigger `set_leader_proposal`.
    ///
    /// Returns `true` if the vote was accepted, `false` if it was dropped (e.g.,
    /// because it references a different proposal than the leader's).
    pub fn add(&mut self, msg: Vote<S, D>) -> bool {
        self.ingest(msg, false)
    }

    /// Records a [Vote] that is already verified (e.g., one we constructed
    /// ourselves), counting it toward quorum without re-verification.
    ///
    /// Otherwise behaves like [Self::add].
    pub fn add_verified(&mut self, msg: Vote<S, D>) -> bool {
        self.ingest(msg, true)
    }

    fn ingest(&mut self, msg: Vote<S, D>, verified: bool) -> bool {
        match msg {
            Vote::Notarize(notarize) => {
                if let Leader::Proposed(_, proposal) = &self.leader {
                    // If the leader's proposal is known and the message is not for it, drop it
                    if proposal != &notarize.claim {
                        return false;
                    }
                } else if let Leader::Elected(leader) = self.leader {
                    // If the leader is elected but their proposal is not yet known,
                    // adopt it from the leader's own vote
                    if leader == notarize.signer() {
                        self.set_leader_proposal(notarize.claim.clone());
                    }
                }

                // If we've made it this far, add the notarize
                self.notarizes.add(notarize, verified);
                true
            }
            Vote::Nullify(nullify) => {
                self.nullifies.add(nullify, verified);
                true
            }
            Vote::Finalize(finalize) => {
                // If the leader's proposal is known and the message is not for it, drop it
                if let Leader::Proposed(_, proposal) = &self.leader {
                    if proposal != &finalize.claim {
                        return false;
                    }
                }

                // If we've made it this far, add the finalize
                self.finalizes.add(finalize, verified);
                true
            }
        }
    }

    /// Sets the leader for the current consensus view.
    ///
    /// If a notarize vote from the leader has already been received, this will
    /// also set the leader's proposal, filtering out any pending votes for other
    /// proposals.
    pub fn set_leader(&mut self, leader: Participant) {
        assert!(
            matches!(self.leader, Leader::Unknown),
            "leader already elected"
        );
        self.leader = Leader::Elected(leader);

        // If we already have the leader's vote, set the leader proposal
        let Some(notarize) = self.notarizes.votes.iter().find(|n| n.signer() == leader) else {
            return;
        };
        self.set_leader_proposal(notarize.claim.clone());
    }

    /// Verifies a batch of pending [Vote::Notarize] messages.
    ///
    /// Returns the successfully verified messages and the signer indices for whom
    /// verification failed.
    pub fn verify_notarizes<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> (Vec<Vote<S, D>>, Vec<Participant>) {
        let (verified, invalid) = self.notarizes.verify(&self.scheme, rng, strategy);
        (verified.into_iter().map(Vote::Notarize).collect(), invalid)
    }

    /// Checks if there are [Vote::Notarize] messages ready for batch verification.
    ///
    /// In addition to [Pending::ready], the leader and their proposal must be known
    /// (so we know which proposal to verify for).
    pub fn ready_notarizes(&self) -> bool {
        // If we don't yet know the leader's proposal, notarizes may contain
        // messages for a number of different proposals.
        if !matches!(self.leader, Leader::Proposed(..)) {
            return false;
        }
        self.notarizes.ready(self.quorum)
    }

    /// Verifies a batch of pending [Vote::Nullify] messages.
    ///
    /// Returns the successfully verified messages and the signer indices for whom
    /// verification failed.
    pub fn verify_nullifies<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> (Vec<Vote<S, D>>, Vec<Participant>) {
        let (verified, invalid) = self.nullifies.verify(&self.scheme, rng, strategy);
        (verified.into_iter().map(Vote::Nullify).collect(), invalid)
    }

    /// Checks if there are [Vote::Nullify] messages ready for batch verification.
    pub fn ready_nullifies(&self) -> bool {
        self.nullifies.ready(self.quorum)
    }

    /// Verifies a batch of pending [Vote::Finalize] messages.
    ///
    /// Returns the successfully verified messages and the signer indices for whom
    /// verification failed.
    pub fn verify_finalizes<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> (Vec<Vote<S, D>>, Vec<Participant>) {
        let (verified, invalid) = self.finalizes.verify(&self.scheme, rng, strategy);
        (verified.into_iter().map(Vote::Finalize).collect(), invalid)
    }

    /// Checks if there are [Vote::Finalize] messages ready for batch verification.
    ///
    /// In addition to [Pending::ready], the leader and their proposal must be known
    /// (so we know which proposal to verify for).
    pub fn ready_finalizes(&self) -> bool {
        // If we don't yet know the leader's proposal, finalizes may contain
        // messages for a number of different proposals.
        if !matches!(self.leader, Leader::Proposed(..)) {
            return false;
        }
        self.finalizes.ready(self.quorum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::{
                bls12381_multisig,
                bls12381_threshold::{
                    standard as bls12381_threshold_std, vrf as bls12381_threshold_vrf,
                },
                ed25519, secp256r1,
            },
            types::{Finalize, Notarize, Nullify},
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::PublicKey,
        sha256::Digest as Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, Faults, N3f1};
    use rand::rngs::StdRng;

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256 {
        Sha256::from([v; 32]) // Simple fixed digest for testing
    }

    // Helper to create a Notarize message for any signing scheme
    fn create_notarize<S: Scheme<Sha256>>(
        scheme: &S,
        round: Round,
        parent_view: View,
        payload_val: u8,
    ) -> Notarize<S, Sha256> {
        let proposal = Proposal::new(round, parent_view, sample_digest(payload_val));
        Notarize::sign(scheme, proposal).unwrap()
    }

    // Helper to create a Nullify message for any signing scheme
    fn create_nullify<S: Scheme<Sha256>>(scheme: &S, round: Round) -> Nullify<S, Sha256> {
        Nullify::<_, Sha256>::sign(scheme, round).unwrap()
    }

    // Helper to create a Finalize message for any signing scheme
    fn create_finalize<S: Scheme<Sha256>>(
        scheme: &S,
        round: Round,
        parent_view: View,
        payload_val: u8,
    ) -> Finalize<S, Sha256> {
        let proposal = Proposal::new(round, parent_view, sample_digest(payload_val));
        Finalize::sign(scheme, proposal).unwrap()
    }

    fn add_notarize<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);

        let round = Round::new(Epoch::new(0), View::new(1));
        let notarize1 = create_notarize(&schemes[0], round, View::new(0), 1);
        let notarize2 = create_notarize(&schemes[1], round, View::new(0), 1);
        let notarize_diff = create_notarize(&schemes[2], round, View::new(0), 2);

        verifier.add(Vote::Notarize(notarize1.clone()));
        assert_eq!(verifier.notarizes.votes.len(), 1);
        assert_eq!(verifier.notarizes.verified, 0);

        verifier.add_verified(Vote::Notarize(notarize1.clone()));
        assert_eq!(verifier.notarizes.votes.len(), 1);
        assert_eq!(verifier.notarizes.verified, 1);

        verifier.set_leader(notarize1.signer());
        assert_eq!(
            verifier.leader,
            Leader::Proposed(notarize1.signer(), notarize1.claim)
        );
        assert_eq!(verifier.notarizes.votes.len(), 1);

        verifier.add(Vote::Notarize(notarize2));
        assert_eq!(verifier.notarizes.votes.len(), 2);

        verifier.add(Vote::Notarize(notarize_diff));
        assert_eq!(verifier.notarizes.votes.len(), 2);

        let mut verifier2 = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round2 = Round::new(Epoch::new(0), View::new(2));
        let notarize_non_leader = create_notarize(&schemes[1], round2, View::new(1), 3);
        let notarize_leader = create_notarize(&schemes[0], round2, View::new(1), 3);

        verifier2.set_leader(notarize_leader.signer());
        verifier2.add(Vote::Notarize(notarize_non_leader));
        assert_eq!(verifier2.leader, Leader::Elected(notarize_leader.signer()));
        assert_eq!(verifier2.notarizes.votes.len(), 1);

        verifier2.add(Vote::Notarize(notarize_leader.clone()));
        assert_eq!(
            verifier2.leader,
            Leader::Proposed(notarize_leader.signer(), notarize_leader.claim)
        );
        assert_eq!(verifier2.notarizes.votes.len(), 2);
    }

    #[test]
    fn test_add_notarize() {
        add_notarize(bls12381_threshold_vrf::fixture::<MinSig, _>);
        add_notarize(bls12381_threshold_vrf::fixture::<MinPk, _>);
        add_notarize(bls12381_threshold_std::fixture::<MinSig, _>);
        add_notarize(bls12381_threshold_std::fixture::<MinPk, _>);
        add_notarize(bls12381_multisig::fixture::<MinSig, _>);
        add_notarize(bls12381_multisig::fixture::<MinPk, _>);
        add_notarize(ed25519::fixture);
        add_notarize(secp256r1::fixture);
    }

    fn set_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);

        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        let other_notarize = create_notarize(&schemes[1], round, View::new(0), 1);

        verifier.add(Vote::Notarize(other_notarize));
        assert_eq!(verifier.notarizes.votes.len(), 1);

        let leader = leader_notarize.signer();
        verifier.set_leader(leader);
        assert_eq!(verifier.leader, Leader::Elected(leader));
        assert_eq!(verifier.notarizes.votes.len(), 1);

        verifier.add(Vote::Notarize(leader_notarize.clone()));
        assert_eq!(
            verifier.leader,
            Leader::Proposed(leader, leader_notarize.claim)
        );
        assert_eq!(verifier.notarizes.votes.len(), 2);
    }

    #[test]
    fn test_set_leader() {
        set_leader(bls12381_threshold_vrf::fixture::<MinSig, _>);
        set_leader(bls12381_threshold_vrf::fixture::<MinPk, _>);
        set_leader(bls12381_threshold_std::fixture::<MinSig, _>);
        set_leader(bls12381_threshold_std::fixture::<MinPk, _>);
        set_leader(bls12381_multisig::fixture::<MinSig, _>);
        set_leader(bls12381_multisig::fixture::<MinPk, _>);
        set_leader(ed25519::fixture);
        set_leader(secp256r1::fixture);
    }

    fn ready_and_verify_notarizes<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| create_notarize(scheme, round, View::new(0), 1))
            .collect();

        assert!(!verifier.ready_notarizes());

        verifier.set_leader(notarizes[0].signer());
        verifier.add(Vote::Notarize(notarizes[0].clone()));
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.ready_notarizes(), S::is_batchable());
        assert_eq!(verifier.notarizes.votes.len(), 1);

        verifier.add(Vote::Notarize(notarizes[1].clone()));
        assert_eq!(!verifier.ready_notarizes(), S::is_batchable());
        verifier.add(Vote::Notarize(notarizes[2].clone()));
        assert_eq!(!verifier.ready_notarizes(), S::is_batchable());
        verifier.add(Vote::Notarize(notarizes[3].clone()));
        assert!(verifier.ready_notarizes());
        assert_eq!(verifier.notarizes.votes.len(), 4);

        let (verified_bulk, failed_bulk) = verifier.verify_notarizes(&mut rng, &Sequential);
        assert_eq!(verified_bulk.len(), 4);
        assert!(failed_bulk.is_empty());
        assert_eq!(verifier.notarizes.verified, 4);
        assert!(verifier.notarizes.votes.is_empty());
        assert!(!verifier.ready_notarizes());

        let mut verifier2 = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round2 = Round::new(Epoch::new(0), View::new(2));
        let leader_vote = create_notarize(&schemes[0], round2, View::new(1), 10);
        let mut faulty_vote = create_notarize(&schemes[1], round2, View::new(1), 10);
        verifier2.set_leader(leader_vote.signer());
        verifier2.add(Vote::Notarize(leader_vote.clone()));
        faulty_vote.attestation.signer = Participant::from_usize(schemes.len() + 10);
        verifier2.add(Vote::Notarize(faulty_vote.clone()));

        for scheme in schemes.iter().skip(2).take(quorum as usize - 2) {
            verifier2.add(Vote::Notarize(create_notarize(
                scheme,
                round2,
                View::new(1),
                10,
            )));
        }
        assert!(verifier2.ready_notarizes());

        let (verified_second, failed_second) = verifier2.verify_notarizes(&mut rng, &Sequential);
        assert!(verified_second
            .iter()
            .any(|v| matches!(v, Vote::Notarize(ref n) if n == &leader_vote)));
        assert_eq!(failed_second, vec![faulty_vote.signer()]);
    }

    #[test]
    fn test_ready_and_verify_notarizes() {
        ready_and_verify_notarizes(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_and_verify_notarizes(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_and_verify_notarizes(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_and_verify_notarizes(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_and_verify_notarizes(bls12381_multisig::fixture::<MinSig, _>);
        ready_and_verify_notarizes(bls12381_multisig::fixture::<MinPk, _>);
        ready_and_verify_notarizes(ed25519::fixture);
        ready_and_verify_notarizes(secp256r1::fixture);
    }

    fn add_nullify<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let nullify = create_nullify(&schemes[0], round);

        verifier.add(Vote::Nullify(nullify.clone()));
        assert_eq!(verifier.nullifies.votes.len(), 1);
        assert_eq!(verifier.nullifies.verified, 0);

        verifier.add_verified(Vote::Nullify(nullify));
        assert_eq!(verifier.nullifies.votes.len(), 1);
        assert_eq!(verifier.nullifies.verified, 1);
    }

    #[test]
    fn test_add_nullify() {
        add_nullify(bls12381_threshold_vrf::fixture::<MinSig, _>);
        add_nullify(bls12381_threshold_vrf::fixture::<MinPk, _>);
        add_nullify(bls12381_threshold_std::fixture::<MinSig, _>);
        add_nullify(bls12381_threshold_std::fixture::<MinPk, _>);
        add_nullify(bls12381_multisig::fixture::<MinSig, _>);
        add_nullify(bls12381_multisig::fixture::<MinPk, _>);
        add_nullify(ed25519::fixture);
        add_nullify(secp256r1::fixture);
    }

    fn ready_and_verify_nullifies<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let nullifies: Vec<_> = schemes
            .iter()
            .map(|scheme| create_nullify(scheme, round))
            .collect();

        verifier.add_verified(Vote::Nullify(nullifies[0].clone()));
        assert_eq!(verifier.nullifies.verified, 1);

        verifier.add(Vote::Nullify(nullifies[1].clone()));
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.ready_nullifies(), S::is_batchable());
        verifier.add(Vote::Nullify(nullifies[2].clone()));
        assert_eq!(!verifier.ready_nullifies(), S::is_batchable());
        verifier.add(Vote::Nullify(nullifies[3].clone()));
        assert!(verifier.ready_nullifies());
        assert_eq!(verifier.nullifies.votes.len(), 3);

        let (verified, failed) = verifier.verify_nullifies(&mut rng, &Sequential);
        assert_eq!(verified.len(), 3);
        assert!(failed.is_empty());
        assert_eq!(verifier.nullifies.verified, 4);
        assert!(verifier.nullifies.votes.is_empty());
        assert!(!verifier.ready_nullifies());
    }

    #[test]
    fn test_ready_and_verify_nullifies() {
        ready_and_verify_nullifies(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_and_verify_nullifies(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_and_verify_nullifies(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_and_verify_nullifies(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_and_verify_nullifies(bls12381_multisig::fixture::<MinSig, _>);
        ready_and_verify_nullifies(bls12381_multisig::fixture::<MinPk, _>);
        ready_and_verify_nullifies(ed25519::fixture);
        ready_and_verify_nullifies(secp256r1::fixture);
    }

    fn add_finalize<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let finalize_a = create_finalize(&schemes[0], round, View::new(0), 1);
        let finalize_b = create_finalize(&schemes[1], round, View::new(0), 2);

        verifier.add(Vote::Finalize(finalize_b.clone()));
        assert_eq!(verifier.finalizes.votes.len(), 1);
        assert_eq!(verifier.finalizes.verified, 0);

        verifier.add(Vote::Finalize(finalize_a.clone()));
        assert_eq!(verifier.finalizes.votes.len(), 2);

        verifier.set_leader(finalize_a.signer());
        assert_eq!(verifier.leader, Leader::Elected(finalize_a.signer()));
        verifier.set_leader_proposal(finalize_a.claim.clone());
        assert_eq!(verifier.finalizes.votes.len(), 1);
        assert_eq!(verifier.finalizes.votes[0], finalize_a);
        assert_eq!(verifier.finalizes.verified, 0);

        verifier.add_verified(Vote::Finalize(finalize_a));
        assert_eq!(verifier.finalizes.votes.len(), 1);
        assert_eq!(verifier.finalizes.verified, 1);

        verifier.add(Vote::Finalize(finalize_b));
        assert_eq!(verifier.finalizes.votes.len(), 1);
        assert_eq!(verifier.finalizes.verified, 1);
    }

    #[test]
    fn test_add_finalize() {
        add_finalize(bls12381_threshold_vrf::fixture::<MinSig, _>);
        add_finalize(bls12381_threshold_vrf::fixture::<MinPk, _>);
        add_finalize(bls12381_threshold_std::fixture::<MinSig, _>);
        add_finalize(bls12381_threshold_std::fixture::<MinPk, _>);
        add_finalize(bls12381_multisig::fixture::<MinSig, _>);
        add_finalize(bls12381_multisig::fixture::<MinPk, _>);
        add_finalize(ed25519::fixture);
        add_finalize(secp256r1::fixture);
    }

    fn ready_and_verify_finalizes<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| create_finalize(scheme, round, View::new(0), 1))
            .collect();

        assert!(!verifier.ready_finalizes());

        verifier.set_leader(finalizes[0].signer());
        verifier.set_leader_proposal(finalizes[0].claim.clone());

        verifier.add_verified(Vote::Finalize(finalizes[0].clone()));
        assert_eq!(verifier.finalizes.verified, 1);
        assert!(verifier.finalizes.votes.is_empty());

        verifier.add(Vote::Finalize(finalizes[1].clone()));
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.ready_finalizes(), S::is_batchable());
        verifier.add(Vote::Finalize(finalizes[2].clone()));
        assert_eq!(!verifier.ready_finalizes(), S::is_batchable());
        verifier.add(Vote::Finalize(finalizes[3].clone()));
        assert!(verifier.ready_finalizes());

        let (verified, failed) = verifier.verify_finalizes(&mut rng, &Sequential);
        assert_eq!(verified.len(), 3);
        assert!(failed.is_empty());
        assert_eq!(verifier.finalizes.verified, 4);
        assert!(verifier.finalizes.votes.is_empty());
        assert!(!verifier.ready_finalizes());
    }

    #[test]
    fn test_ready_and_verify_finalizes() {
        ready_and_verify_finalizes(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_and_verify_finalizes(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_and_verify_finalizes(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_and_verify_finalizes(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_and_verify_finalizes(bls12381_multisig::fixture::<MinSig, _>);
        ready_and_verify_finalizes(bls12381_multisig::fixture::<MinPk, _>);
        ready_and_verify_finalizes(ed25519::fixture);
        ready_and_verify_finalizes(secp256r1::fixture);
    }

    fn leader_proposal_filters_messages<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let proposal_a = Proposal::new(round, View::new(0), sample_digest(10));
        let proposal_b = Proposal::new(round, View::new(0), sample_digest(20));

        let notarize_a = Notarize::sign(&schemes[0], proposal_a.clone()).unwrap();
        let notarize_b = Notarize::sign(&schemes[1], proposal_b.clone()).unwrap();
        let finalize_a = Finalize::sign(&schemes[0], proposal_a.clone()).unwrap();
        let finalize_b = Finalize::sign(&schemes[1], proposal_b).unwrap();

        verifier.add(Vote::Notarize(notarize_a.clone()));
        verifier.add(Vote::Notarize(notarize_b));
        verifier.add(Vote::Finalize(finalize_a));
        verifier.add(Vote::Finalize(finalize_b));

        assert_eq!(verifier.notarizes.votes.len(), 2);
        assert_eq!(verifier.finalizes.votes.len(), 2);

        verifier.set_leader(notarize_a.signer());

        assert_eq!(verifier.notarizes.votes.len(), 1);
        assert_eq!(verifier.notarizes.votes[0].claim, proposal_a);
        assert_eq!(verifier.finalizes.votes.len(), 1);
        assert_eq!(verifier.finalizes.votes[0].claim, proposal_a);
    }

    #[test]
    fn test_leader_proposal_filters_messages() {
        leader_proposal_filters_messages(bls12381_threshold_vrf::fixture::<MinSig, _>);
        leader_proposal_filters_messages(bls12381_threshold_vrf::fixture::<MinPk, _>);
        leader_proposal_filters_messages(bls12381_threshold_std::fixture::<MinSig, _>);
        leader_proposal_filters_messages(bls12381_threshold_std::fixture::<MinPk, _>);
        leader_proposal_filters_messages(bls12381_multisig::fixture::<MinSig, _>);
        leader_proposal_filters_messages(bls12381_multisig::fixture::<MinPk, _>);
        leader_proposal_filters_messages(ed25519::fixture);
        leader_proposal_filters_messages(secp256r1::fixture);
    }

    fn set_leader_twice_panics<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), 3);
        verifier.set_leader(Participant::new(0));
        verifier.set_leader(Participant::new(1));
    }

    #[test]
    #[should_panic(expected = "leader already elected")]
    fn test_set_leader_twice_panics_bls_threshold_minsig() {
        set_leader_twice_panics(bls12381_threshold_vrf::fixture::<MinSig, _>);
    }

    #[test]
    #[should_panic(expected = "leader already elected")]
    fn test_set_leader_twice_panics_bls_threshold_minpk() {
        set_leader_twice_panics(bls12381_threshold_vrf::fixture::<MinPk, _>);
    }

    #[test]
    #[should_panic(expected = "leader already elected")]
    fn test_set_leader_twice_panics_bls_threshold_std_minsig() {
        set_leader_twice_panics(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    #[test]
    #[should_panic(expected = "leader already elected")]
    fn test_set_leader_twice_panics_bls_threshold_std_minpk() {
        set_leader_twice_panics(bls12381_threshold_std::fixture::<MinPk, _>);
    }

    #[test]
    #[should_panic(expected = "leader already elected")]
    fn test_set_leader_twice_panics_bls_multisig_minsig() {
        set_leader_twice_panics(bls12381_multisig::fixture::<MinSig, _>);
    }

    #[test]
    #[should_panic(expected = "leader already elected")]
    fn test_set_leader_twice_panics_bls_multisig_minpk() {
        set_leader_twice_panics(bls12381_multisig::fixture::<MinPk, _>);
    }

    #[test]
    #[should_panic(expected = "leader already elected")]
    fn test_set_leader_twice_panics_ed() {
        set_leader_twice_panics(ed25519::fixture);
    }

    #[test]
    #[should_panic(expected = "leader already elected")]
    fn test_set_leader_twice_panics_secp() {
        set_leader_twice_panics(secp256r1::fixture);
    }

    fn notarizes_wait_for_quorum<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);

        verifier.set_leader(leader_vote.signer());
        verifier.add(Vote::Notarize(leader_vote));
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(
            !verifier.ready_notarizes(),
            S::is_batchable(),
            "Batchable schemes wait for quorum, non-batchable verify immediately"
        );

        for scheme in schemes.iter().skip(1).take(quorum as usize - 1) {
            verifier.add(Vote::Notarize(create_notarize(
                scheme,
                round,
                View::new(0),
                1,
            )));
        }
        assert!(verifier.ready_notarizes(), "Should be ready at quorum");

        let (verified, _) = verifier.verify_notarizes(&mut rng, &Sequential);
        assert_eq!(verified.len(), quorum as usize);
        assert!(!verifier.ready_notarizes());
    }

    #[test]
    fn test_notarizes_wait_for_quorum() {
        notarizes_wait_for_quorum(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarizes_wait_for_quorum(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarizes_wait_for_quorum(bls12381_threshold_std::fixture::<MinSig, _>);
        notarizes_wait_for_quorum(bls12381_threshold_std::fixture::<MinPk, _>);
        notarizes_wait_for_quorum(bls12381_multisig::fixture::<MinSig, _>);
        notarizes_wait_for_quorum(bls12381_multisig::fixture::<MinPk, _>);
        notarizes_wait_for_quorum(ed25519::fixture);
        notarizes_wait_for_quorum(secp256r1::fixture);
    }

    fn ready_notarizes_without_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| create_notarize(scheme, round, View::new(0), 1))
            .collect();

        for vote in notarizes.iter() {
            verifier.add(Vote::Notarize(vote.clone()));
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
        ready_notarizes_without_leader(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_notarizes_without_leader(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_notarizes_without_leader(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_notarizes_without_leader(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_notarizes_without_leader(bls12381_multisig::fixture::<MinSig, _>);
        ready_notarizes_without_leader(bls12381_multisig::fixture::<MinPk, _>);
        ready_notarizes_without_leader(ed25519::fixture);
        ready_notarizes_without_leader(secp256r1::fixture);
    }

    fn ready_finalizes_without_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let finalizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| create_finalize(scheme, round, View::new(0), 1))
            .collect();

        for finalize in finalizes.iter() {
            verifier.add(Vote::Finalize(finalize.clone()));
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
        ready_finalizes_without_leader(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_finalizes_without_leader(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_finalizes_without_leader(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_finalizes_without_leader(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_finalizes_without_leader(bls12381_multisig::fixture::<MinSig, _>);
        ready_finalizes_without_leader(bls12381_multisig::fixture::<MinPk, _>);
        ready_finalizes_without_leader(ed25519::fixture);
        ready_finalizes_without_leader(secp256r1::fixture);
    }

    fn verify_notarizes_empty<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_proposal = Proposal::new(round, View::new(0), sample_digest(1));
        verifier.set_leader(Participant::new(0));
        verifier.set_leader_proposal(leader_proposal);
        assert!(verifier.notarizes.votes.is_empty());
        assert!(!verifier.ready_notarizes());
    }

    #[test]
    fn test_verify_notarizes_empty_pending_when_forced() {
        verify_notarizes_empty(bls12381_threshold_vrf::fixture::<MinSig, _>);
        verify_notarizes_empty(bls12381_threshold_vrf::fixture::<MinPk, _>);
        verify_notarizes_empty(bls12381_threshold_std::fixture::<MinSig, _>);
        verify_notarizes_empty(bls12381_threshold_std::fixture::<MinPk, _>);
        verify_notarizes_empty(bls12381_multisig::fixture::<MinSig, _>);
        verify_notarizes_empty(bls12381_multisig::fixture::<MinPk, _>);
        verify_notarizes_empty(ed25519::fixture);
        verify_notarizes_empty(secp256r1::fixture);
    }

    fn verify_nullifies_empty<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        assert!(verifier.nullifies.votes.is_empty());
        assert!(!verifier.ready_nullifies());
        let (verified, failed) = verifier.verify_nullifies(&mut rng, &Sequential);
        assert!(verified.is_empty());
        assert!(failed.is_empty());
        assert_eq!(verifier.nullifies.verified, 0);
    }

    #[test]
    fn test_verify_nullifies_empty_pending() {
        verify_nullifies_empty(bls12381_threshold_vrf::fixture::<MinSig, _>);
        verify_nullifies_empty(bls12381_threshold_vrf::fixture::<MinPk, _>);
        verify_nullifies_empty(bls12381_threshold_std::fixture::<MinSig, _>);
        verify_nullifies_empty(bls12381_threshold_std::fixture::<MinPk, _>);
        verify_nullifies_empty(bls12381_multisig::fixture::<MinSig, _>);
        verify_nullifies_empty(bls12381_multisig::fixture::<MinPk, _>);
        verify_nullifies_empty(ed25519::fixture);
        verify_nullifies_empty(secp256r1::fixture);
    }

    fn verify_finalizes_empty<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        verifier.set_leader(Participant::new(0));
        assert!(verifier.finalizes.votes.is_empty());
        assert!(!verifier.ready_finalizes());
        let (verified, failed) = verifier.verify_finalizes(&mut rng, &Sequential);
        assert!(verified.is_empty());
        assert!(failed.is_empty());
        assert_eq!(verifier.finalizes.verified, 0);
    }

    #[test]
    fn test_verify_finalizes_empty_pending() {
        verify_finalizes_empty(bls12381_threshold_vrf::fixture::<MinSig, _>);
        verify_finalizes_empty(bls12381_threshold_vrf::fixture::<MinPk, _>);
        verify_finalizes_empty(bls12381_threshold_std::fixture::<MinSig, _>);
        verify_finalizes_empty(bls12381_threshold_std::fixture::<MinPk, _>);
        verify_finalizes_empty(bls12381_multisig::fixture::<MinSig, _>);
        verify_finalizes_empty(bls12381_multisig::fixture::<MinPk, _>);
        verify_finalizes_empty(ed25519::fixture);
        verify_finalizes_empty(secp256r1::fixture);
    }

    fn ready_notarizes_exact_quorum<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_vote.signer());
        verifier.add_verified(Vote::Notarize(leader_vote));
        assert_eq!(verifier.notarizes.verified, 1);

        for (i, scheme) in schemes.iter().enumerate().skip(1).take(quorum as usize - 1) {
            let is_last = i == quorum as usize - 1;
            verifier.add(Vote::Notarize(create_notarize(
                scheme,
                round,
                View::new(0),
                1,
            )));
            if is_last {
                assert!(
                    verifier.ready_notarizes(),
                    "Should be ready at exact quorum"
                );
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.ready_notarizes());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.ready_notarizes());
            }
        }

        let (verified, failed) = verifier.verify_notarizes(&mut rng, &Sequential);
        assert_eq!(verified.len(), quorum as usize - 1);
        assert!(failed.is_empty());
        assert_eq!(verifier.notarizes.verified, quorum as usize);
        assert!(!verifier.ready_notarizes());
    }

    #[test]
    fn test_ready_notarizes_exact_quorum() {
        ready_notarizes_exact_quorum(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_notarizes_exact_quorum(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_notarizes_exact_quorum(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_notarizes_exact_quorum(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_notarizes_exact_quorum(bls12381_multisig::fixture::<MinSig, _>);
        ready_notarizes_exact_quorum(bls12381_multisig::fixture::<MinPk, _>);
        ready_notarizes_exact_quorum(ed25519::fixture);
        ready_notarizes_exact_quorum(secp256r1::fixture);
    }

    fn ready_nullifies_exact_quorum<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        verifier.add_verified(Vote::Nullify(create_nullify(&schemes[0], round)));
        assert_eq!(verifier.nullifies.verified, 1);

        let pending_schemes: Vec<_> = schemes.iter().take(quorum as usize).skip(1).collect();
        for (i, scheme) in pending_schemes.iter().enumerate() {
            let is_last = i == pending_schemes.len() - 1;
            verifier.add(Vote::Nullify(create_nullify(scheme, round)));
            if is_last {
                assert!(verifier.ready_nullifies());
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.ready_nullifies());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.ready_nullifies());
            }
        }
    }

    #[test]
    fn test_ready_nullifies_exact_quorum() {
        ready_nullifies_exact_quorum(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_nullifies_exact_quorum(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_nullifies_exact_quorum(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_nullifies_exact_quorum(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_nullifies_exact_quorum(bls12381_multisig::fixture::<MinSig, _>);
        ready_nullifies_exact_quorum(bls12381_multisig::fixture::<MinPk, _>);
        ready_nullifies_exact_quorum(ed25519::fixture);
        ready_nullifies_exact_quorum(secp256r1::fixture);
    }

    fn ready_finalizes_exact_quorum<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_finalize = create_finalize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_finalize.signer());
        verifier.set_leader_proposal(leader_finalize.claim.clone());
        verifier.add_verified(Vote::Finalize(leader_finalize));
        assert_eq!(verifier.finalizes.verified, 1);

        let pending_schemes: Vec<_> = schemes.iter().take(quorum as usize).skip(1).collect();
        for (i, scheme) in pending_schemes.iter().enumerate() {
            let is_last = i == pending_schemes.len() - 1;
            verifier.add(Vote::Finalize(create_finalize(
                scheme,
                round,
                View::new(0),
                1,
            )));
            if is_last {
                assert!(verifier.ready_finalizes());
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.ready_finalizes());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.ready_finalizes());
            }
        }
    }

    #[test]
    fn test_ready_finalizes_exact_quorum() {
        ready_finalizes_exact_quorum(bls12381_threshold_vrf::fixture::<MinSig, _>);
        ready_finalizes_exact_quorum(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_finalizes_exact_quorum(bls12381_threshold_std::fixture::<MinSig, _>);
        ready_finalizes_exact_quorum(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_finalizes_exact_quorum(bls12381_multisig::fixture::<MinSig, _>);
        ready_finalizes_exact_quorum(bls12381_multisig::fixture::<MinPk, _>);
        ready_finalizes_exact_quorum(ed25519::fixture);
        ready_finalizes_exact_quorum(secp256r1::fixture);
    }

    fn ready_notarizes_quorum_already_met_by_verified<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        // Pre-load the leader vote as if it had already been processed.
        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_vote.signer());
        verifier.add(Vote::Notarize(leader_vote));

        // Mark enough verified notarizes to satisfy the quorum outright.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add_verified(Vote::Notarize(create_notarize(
                scheme,
                round,
                View::new(0),
                1,
            )));
        }
        assert_eq!(verifier.notarizes.verified, quorum as usize);
        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Additional pending votes must not flip readiness in this situation.
        let extra_vote = create_notarize(&schemes[quorum as usize], round, View::new(0), 1);
        verifier.add(Vote::Notarize(extra_vote));
        assert!(
            !verifier.ready_notarizes(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_notarizes_quorum_already_met_by_verified() {
        ready_notarizes_quorum_already_met_by_verified(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        ready_notarizes_quorum_already_met_by_verified(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_notarizes_quorum_already_met_by_verified(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        ready_notarizes_quorum_already_met_by_verified(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_notarizes_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinSig, _>);
        ready_notarizes_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinPk, _>);
        ready_notarizes_quorum_already_met_by_verified(ed25519::fixture);
        ready_notarizes_quorum_already_met_by_verified(secp256r1::fixture);
    }

    fn ready_nullifies_quorum_already_met_by_verified<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        // First mark a quorum's worth of verified nullifies.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add_verified(Vote::Nullify(create_nullify(scheme, round)));
        }
        assert_eq!(verifier.nullifies.verified, quorum as usize);
        assert!(
            !verifier.ready_nullifies(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Pending messages alone cannot transition the batch to ready.
        let extra_nullify = create_nullify(&schemes[quorum as usize], round);
        verifier.add(Vote::Nullify(extra_nullify));
        assert!(
            !verifier.ready_nullifies(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_nullifies_quorum_already_met_by_verified() {
        ready_nullifies_quorum_already_met_by_verified(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        ready_nullifies_quorum_already_met_by_verified(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_nullifies_quorum_already_met_by_verified(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        ready_nullifies_quorum_already_met_by_verified(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_nullifies_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinSig, _>);
        ready_nullifies_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinPk, _>);
        ready_nullifies_quorum_already_met_by_verified(ed25519::fixture);
        ready_nullifies_quorum_already_met_by_verified(secp256r1::fixture);
    }

    fn ready_finalizes_quorum_already_met_by_verified<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut StdRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(schemes[0].clone(), quorum);
        let round = Round::new(Epoch::new(0), View::new(1));

        // Prime the leader state so the quorum is already satisfied by verified finalizes.
        let leader_finalize = create_finalize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_finalize.signer());
        verifier.set_leader_proposal(leader_finalize.claim);

        // Feed exactly the number of verified finalizes required to hit the quorum.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add_verified(Vote::Finalize(create_finalize(
                scheme,
                round,
                View::new(0),
                1,
            )));
        }
        assert_eq!(verifier.finalizes.verified, quorum as usize);
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Ensure additional pending finalizes do not incorrectly trigger readiness.
        let extra_finalize = create_finalize(&schemes[quorum as usize], round, View::new(0), 1);
        verifier.add(Vote::Finalize(extra_finalize));
        assert!(
            !verifier.ready_finalizes(),
            "Should not be ready if quorum already met by verified messages"
        );
    }

    #[test]
    fn test_ready_finalizes_quorum_already_met_by_verified() {
        ready_finalizes_quorum_already_met_by_verified(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        );
        ready_finalizes_quorum_already_met_by_verified(bls12381_threshold_vrf::fixture::<MinPk, _>);
        ready_finalizes_quorum_already_met_by_verified(
            bls12381_threshold_std::fixture::<MinSig, _>,
        );
        ready_finalizes_quorum_already_met_by_verified(bls12381_threshold_std::fixture::<MinPk, _>);
        ready_finalizes_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinSig, _>);
        ready_finalizes_quorum_already_met_by_verified(bls12381_multisig::fixture::<MinPk, _>);
        ready_finalizes_quorum_already_met_by_verified(ed25519::fixture);
        ready_finalizes_quorum_already_met_by_verified(secp256r1::fixture);
    }
}
