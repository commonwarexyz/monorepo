use crate::{
    simplex::{
        scheme::Scheme,
        types::{
            Attributable, Certificate, Finalization, Finalize, Kind, Notarization, Notarize,
            Nullification, Nullify, Proposal, Subject, Vote,
        },
    },
    types::{Participant, Round as Rnd},
};
use commonware_cryptography::{Digest, certificate::Verification};
use commonware_parallel::Strategy;
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::ordered::Set;
use rand::rngs::StdRng;
use rand_core::{CryptoRng, SeedableRng};
use std::{future::Future, mem, sync::Arc};
use tracing::{Instrument as _, Span, info_span};

/// Runs a CPU-bound job through [Strategy::spawn], entering `span` on the worker thread and
/// instrumenting the awaited future so the offloaded work stays attributed to the caller's trace.
async fn offload<P, F, T>(span: Span, strategy: &P, job: F) -> T
where
    P: Strategy,
    F: FnOnce(P) -> T + Send + 'static,
    T: Send + 'static,
{
    let worker_span = span.clone();
    strategy
        .spawn(move |strategy| worker_span.in_scope(|| job(strategy)))
        .instrument(span)
        .await
}

/// Certification progress for one kind of vote.
///
/// Each kind certifies independently: a view can legitimately certify both
/// a notarization and a nullification.
struct Certification<V> {
    /// Verified votes required to recover a certificate.
    quorum: usize,
    /// Whether the scheme benefits from batching signature verification.
    batchable: bool,
    /// Progress toward a certificate.
    state: State<V>,
}

/// The state of a [Certification].
enum State<V> {
    /// No certificate yet. Votes accumulate toward a quorum.
    Incomplete {
        /// Votes awaiting signature verification.
        pending: Vec<V>,
        /// Votes with verified signatures, held for certificate recovery.
        verified: Vec<V>,
    },
    /// A certificate exists. Further votes are dropped.
    Complete,
}

impl<V> Certification<V> {
    /// Creates an empty [State::Incomplete] with buffers sized for `quorum` votes.
    fn new(quorum: usize, batchable: bool) -> Self {
        Self {
            quorum,
            batchable,
            state: State::Incomplete {
                pending: Vec::with_capacity(quorum),
                verified: Vec::with_capacity(quorum),
            },
        }
    }

    /// Buffers a vote for verification (or, if already verified, for
    /// certificate recovery). Dropped once complete.
    fn add(&mut self, vote: V, is_verified: bool) {
        if let State::Incomplete { pending, verified } = &mut self.state {
            if is_verified { verified } else { pending }.push(vote);
        }
    }

    /// Returns true if a batch verification should run: pending votes exist,
    /// the quorum is unmet, and (for batchable schemes) the buffers together
    /// could reach it.
    const fn should_verify(&self) -> bool {
        match &self.state {
            State::Incomplete { pending, verified } => {
                !pending.is_empty()
                    && verified.len() < self.quorum
                    && (!self.batchable || verified.len() + pending.len() >= self.quorum)
            }
            State::Complete => false,
        }
    }

    /// Runs `f` over the buffered votes and stores the verified set it
    /// returns, or `None` if a batch is not worth verifying (see
    /// [Self::should_verify]).
    ///
    /// `f` receives the pending and previously verified votes and returns the
    /// new verified set plus the signers that failed verification. Returns
    /// the number of votes processed alongside those signers.
    async fn try_verify<F, Fut>(&mut self, f: F) -> Option<(usize, Vec<Participant>)>
    where
        F: FnOnce(Vec<V>, Vec<V>) -> Fut,
        Fut: Future<Output = (Vec<V>, Vec<Participant>)>,
    {
        if !self.should_verify() {
            return None;
        }
        let State::Incomplete { pending, verified } = &mut self.state else {
            unreachable!("certification complete despite should_verify");
        };
        let batch = pending.len();
        let (pending, prior) = (mem::take(pending), mem::take(verified));
        let (votes, invalid) = f(pending, prior).await;
        let State::Incomplete { verified, .. } = &mut self.state else {
            unreachable!("certification completed mid-verification");
        };
        *verified = votes;
        Some((batch, invalid))
    }

    /// Completes with a verified quorum, surrendering it for certificate
    /// recovery, or `None` if the quorum is unmet.
    fn try_complete(&mut self) -> Option<Vec<V>> {
        let State::Incomplete { verified, .. } = &mut self.state else {
            return None;
        };
        if verified.len() < self.quorum {
            return None;
        }
        let votes = mem::take(verified);
        self.complete();
        Some(votes)
    }

    /// Completes, dropping all buffered votes.
    fn complete(&mut self) {
        self.state = State::Complete;
    }

    /// Returns true if a certificate exists.
    const fn is_complete(&self) -> bool {
        matches!(self.state, State::Complete)
    }

    /// Retains only the votes matching `f`.
    fn retain(&mut self, f: impl Fn(&V) -> bool) {
        if let State::Incomplete { pending, verified } = &mut self.state {
            pending.retain(|v| f(v));
            verified.retain(|v| f(v));
        }
    }
}

/// The leader lifecycle for one view.
enum Leader<D: Digest> {
    /// Not yet announced by the voter.
    Unknown,
    /// Announced, but their proposal is not yet known.
    Known(Participant),
    /// Their proposal is known. Notarize and finalize votes filter to it.
    Proposed {
        leader: Participant,
        proposal: Proposal<D>,
    },
}

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
/// Once polled, async verification moves the pending batch and accumulated verified votes into
/// the worker. Do not cancel an in-flight verification unless the verifier will also be discarded.
///
/// [ed25519]: crate::simplex::scheme::ed25519
/// [bls12381_multisig]: crate::simplex::scheme::bls12381_multisig
/// [bls12381_threshold]: crate::simplex::scheme::bls12381_threshold
/// [secp256r1]: crate::simplex::scheme::secp256r1
pub struct Verifier<S: Scheme<D>, D: Digest> {
    /// Signing scheme used to verify votes and assemble certificates.
    scheme: Arc<S>,

    /// The round being certified.
    round: Rnd,

    /// The leader lifecycle.
    leader: Leader<D>,

    /// Notarize certification progress.
    notarize: Certification<Notarize<S, D>>,
    /// Nullify certification progress.
    nullify: Certification<Nullify<S>>,
    /// Finalize certification progress.
    finalize: Certification<Finalize<S, D>>,
}

impl<S: Scheme<D>, D: Digest> Verifier<S, D> {
    /// Creates a new `Verifier`.
    ///
    /// # Arguments
    ///
    /// * `round` - The round being certified.
    /// * `scheme` - Scheme handle used to verify and aggregate votes.
    /// * `quorum` - Number of votes (2f+1) required to reach a quorum.
    pub fn new(round: Rnd, scheme: impl Into<Arc<S>>, quorum: u32) -> Self {
        // Hold quorum as usize to simplify comparisons against queue lengths.
        let quorum = quorum as usize;
        let batchable = S::is_batchable();
        Self {
            scheme: scheme.into(),

            round,

            leader: Leader::Unknown,

            notarize: Certification::new(quorum, batchable),
            nullify: Certification::new(quorum, batchable),
            finalize: Certification::new(quorum, batchable),
        }
    }

    /// Returns the ordered participant set.
    pub(super) fn participants(&self) -> &Set<S::PublicKey> {
        self.scheme.participants()
    }

    /// Attempts to construct a certificate from verified votes: the first kind
    /// (notarization, then nullification, then finalization) with an unconsumed
    /// verified quorum. Call repeatedly to drain every constructible kind.
    ///
    /// Once recovery starts, it consumes the verified votes. Do not cancel unless
    /// the verifier will also be discarded.
    pub async fn try_construct_certificate(
        &mut self,
        strategy: &impl Strategy,
    ) -> Option<Certificate<S, D>> {
        if let Some(notarizes) = self.notarize.try_complete() {
            let span = info_span!(
                "simplex.batcher.try_construct_notarization",
                epoch = self.round.epoch().traced(),
                view = self.round.view().traced()
            );
            let scheme = Arc::clone(&self.scheme);
            let notarization = offload(span, strategy, move |strategy| {
                Notarization::from_owned_notarizes(scheme.as_ref(), notarizes, &strategy)
                    .expect("verified notarize quorum must assemble")
            })
            .await;
            return Some(Certificate::Notarization(notarization));
        }

        if let Some(nullifies) = self.nullify.try_complete() {
            let span = info_span!(
                "simplex.batcher.try_construct_nullification",
                epoch = self.round.epoch().traced(),
                view = self.round.view().traced()
            );
            let scheme = Arc::clone(&self.scheme);
            let nullification = offload(span, strategy, move |strategy| {
                Nullification::from_owned_nullifies(scheme.as_ref(), nullifies, &strategy)
                    .expect("verified nullify quorum must assemble")
            })
            .await;
            return Some(Certificate::Nullification(nullification));
        }

        if let Some(finalizes) = self.finalize.try_complete() {
            let span = info_span!(
                "simplex.batcher.try_construct_finalization",
                epoch = self.round.epoch().traced(),
                view = self.round.view().traced()
            );
            let scheme = Arc::clone(&self.scheme);
            let finalization = offload(span, strategy, move |strategy| {
                Finalization::from_owned_finalizes(scheme.as_ref(), finalizes, &strategy)
                    .expect("verified finalize quorum must assemble")
            })
            .await;
            return Some(Certificate::Finalization(finalization));
        }

        None
    }

    /// Returns true if a certificate of `kind` exists.
    pub(super) const fn has_certificate(&self, kind: Kind) -> bool {
        match kind {
            Kind::Notarization => self.notarize.is_complete(),
            Kind::Nullification => self.nullify.is_complete(),
            Kind::Finalization => self.finalize.is_complete(),
        }
    }

    /// Records that a certificate of `kind` exists, dropping its buffered votes.
    pub(super) fn record_certificate(&mut self, kind: Kind) {
        match kind {
            Kind::Notarization => self.notarize.complete(),
            Kind::Nullification => self.nullify.complete(),
            Kind::Finalization => self.finalize.complete(),
        }
    }

    /// Learns the leader's proposal from `notarize`, dropping buffered votes
    /// for any other proposal (they cannot contribute to a certificate).
    /// Does nothing unless the leader is [Leader::Known] and the vote is theirs.
    fn try_learn_proposal(&mut self, notarize: &Notarize<S, D>) {
        let Leader::Known(leader) = &self.leader else {
            return;
        };
        let leader = *leader;
        if leader != notarize.signer() {
            return;
        }
        let proposal = notarize.proposal.clone();
        self.notarize.retain(|n| n.proposal == proposal);
        self.finalize.retain(|f| f.proposal == proposal);
        self.leader = Leader::Proposed { leader, proposal };
    }

    /// Returns the leader and their proposal, once known.
    pub const fn get_leader_proposal(&self) -> Option<(Participant, &Proposal<D>)> {
        match &self.leader {
            Leader::Proposed { leader, proposal } => Some((*leader, proposal)),
            _ => None,
        }
    }

    /// Adds a [Vote] message to the batch for later verification.
    ///
    /// If the message has already been verified (e.g., we built it), it is stored
    /// directly for certificate recovery. Otherwise, it is added to the appropriate
    /// pending queue. Notarize and finalize votes for a proposal other than the
    /// known leader's are dropped since they cannot contribute to a certificate.
    ///
    /// If a leader is known and the message is a [Vote::Notarize] from that leader,
    /// this method may reveal the leader proposal.
    ///
    /// # Arguments
    ///
    /// * `msg` - The [Vote] message to add.
    /// * `verified` - A boolean indicating if the message has already been verified.
    pub fn add(&mut self, msg: Vote<S, D>, verified: bool) {
        match msg {
            Vote::Notarize(notarize) => {
                self.try_learn_proposal(&notarize);

                // If the leader's proposal is known and the message is not for it, drop it
                if let Leader::Proposed { proposal, .. } = &self.leader
                    && proposal != &notarize.proposal
                {
                    return;
                }
                self.notarize.add(notarize, verified);
            }
            Vote::Nullify(nullify) => {
                self.nullify.add(nullify, verified);
            }
            Vote::Finalize(finalize) => {
                // If the leader's proposal is known and the message is not for it, drop it
                if let Leader::Proposed { proposal, .. } = &self.leader
                    && proposal != &finalize.proposal
                {
                    return;
                }
                self.finalize.add(finalize, verified);
            }
        }
    }

    /// Sets the leader for the current consensus view.
    ///
    /// `notarize` carries the leader's already-received vote, if any. Their
    /// proposal is learned from it and votes for other proposals are dropped.
    ///
    /// # Panics
    ///
    /// Panics if a leader was already set or if `notarize` is not from
    /// `leader`.
    pub fn set_leader(&mut self, leader: Participant, notarize: Option<&Notarize<S, D>>) {
        assert!(matches!(self.leader, Leader::Unknown));
        self.leader = Leader::Known(leader);
        if let Some(notarize) = notarize {
            assert_eq!(notarize.signer(), leader, "notarize must be from leader");
            self.try_learn_proposal(notarize);
        }
    }

    /// Batch verifies pending [Vote::Notarize] messages, if worthwhile: the
    /// leader's proposal is known (notarizes reference one proposal) and the
    /// buffers warrant a batch (see [Certification::should_verify]).
    ///
    /// It uses `S::verify_attestations` for efficient batch verification, run as one CPU-bound job
    /// submitted through [Strategy::spawn] so a parallel strategy hosts it on its own pool
    /// instead of occupying the calling task.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    ///
    /// # Returns
    ///
    /// The number of votes processed and the signer indices for whom verification
    /// failed, or `None` if verification was not worthwhile.
    pub async fn try_verify_notarizes<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> Option<(usize, Vec<Participant>)> {
        // Until the leader's proposal is known, notarizes may reference many
        // different proposals.
        if !matches!(self.leader, Leader::Proposed { .. }) {
            return None;
        }
        self.notarize
            .try_verify(|notarizes, mut verified_notarizes| {
                let span = info_span!(
                    "simplex.batcher.verify_notarizes",
                    epoch = self.round.epoch().traced(),
                    view = self.round.view().traced()
                );
                let scheme = Arc::clone(&self.scheme);
                let mut rng = StdRng::from_rng(rng);
                offload(span, strategy, move |strategy| {
                    let (proposals, attestations): (Vec<_>, Vec<_>) = notarizes
                        .into_iter()
                        .map(|n| (n.proposal, n.attestation))
                        .unzip();
                    // All proposals here are equal: pending votes are filtered to the
                    // leader's proposal before verification becomes ready.
                    let proposal = &proposals[0];

                    let Verification { verified, invalid } = scheme.verify_attestations::<_, D, _>(
                        &mut rng,
                        Subject::Notarize { proposal },
                        attestations,
                        &strategy,
                    );

                    verified_notarizes.extend(verified.into_iter().zip(proposals).map(
                        |(attestation, proposal)| Notarize {
                            proposal,
                            attestation,
                        },
                    ));
                    (verified_notarizes, invalid)
                })
            })
            .await
    }

    /// Batch verifies pending [Vote::Nullify] messages, if worthwhile (see
    /// [Certification::should_verify]).
    ///
    /// It uses `S::verify_attestations` for efficient batch verification, run as one CPU-bound job
    /// submitted through [Strategy::spawn] so a parallel strategy hosts it on its own pool
    /// instead of occupying the calling task.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    ///
    /// # Returns
    ///
    /// The number of votes processed and the signer indices for whom verification
    /// failed, or `None` if verification was not worthwhile.
    pub async fn try_verify_nullifies<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> Option<(usize, Vec<Participant>)> {
        self.nullify
            .try_verify(|nullifies, mut verified_nullifies| {
                let span = info_span!(
                    "simplex.batcher.verify_nullifies",
                    epoch = self.round.epoch().traced(),
                    view = self.round.view().traced()
                );
                let round = nullifies[0].round;
                let scheme = Arc::clone(&self.scheme);
                let mut rng = StdRng::from_rng(rng);
                offload(span, strategy, move |strategy| {
                    let Verification { verified, invalid } = scheme.verify_attestations::<_, D, _>(
                        &mut rng,
                        Subject::Nullify { round },
                        nullifies.into_iter().map(|nullify| nullify.attestation),
                        &strategy,
                    );

                    verified_nullifies.extend(
                        verified
                            .into_iter()
                            .map(|attestation| Nullify { round, attestation }),
                    );
                    (verified_nullifies, invalid)
                })
            })
            .await
    }

    /// Batch verifies pending [Vote::Finalize] messages, if worthwhile: the
    /// leader's proposal is known (finalizes reference one proposal) and the
    /// buffers warrant a batch (see [Certification::should_verify]).
    ///
    /// It uses `S::verify_attestations` for efficient batch verification, run as one CPU-bound job
    /// submitted through [Strategy::spawn] so a parallel strategy hosts it on its own pool
    /// instead of occupying the calling task.
    ///
    /// # Arguments
    ///
    /// * `rng` - Randomness source used by schemes that require batching randomness.
    ///
    /// # Returns
    ///
    /// The number of votes processed and the signer indices for whom verification
    /// failed, or `None` if verification was not worthwhile.
    pub async fn try_verify_finalizes<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> Option<(usize, Vec<Participant>)> {
        // Until the leader's proposal is known, finalizes may reference many
        // different proposals.
        if !matches!(self.leader, Leader::Proposed { .. }) {
            return None;
        }
        self.finalize
            .try_verify(|finalizes, mut verified_finalizes| {
                let span = info_span!(
                    "simplex.batcher.verify_finalizes",
                    epoch = self.round.epoch().traced(),
                    view = self.round.view().traced()
                );
                let scheme = Arc::clone(&self.scheme);
                let mut rng = StdRng::from_rng(rng);
                offload(span, strategy, move |strategy| {
                    let (proposals, attestations): (Vec<_>, Vec<_>) = finalizes
                        .into_iter()
                        .map(|n| (n.proposal, n.attestation))
                        .unzip();
                    let proposal = &proposals[0];

                    let Verification { verified, invalid } = scheme.verify_attestations::<_, D, _>(
                        &mut rng,
                        Subject::Finalize { proposal },
                        attestations,
                        &strategy,
                    );

                    verified_finalizes.extend(verified.into_iter().zip(proposals).map(
                        |(attestation, proposal)| Finalize {
                            proposal,
                            attestation,
                        },
                    ));
                    (verified_finalizes, invalid)
                })
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::scheme::{
            bls12381_multisig,
            bls12381_threshold::{
                standard as bls12381_threshold_std, vrf as bls12381_threshold_vrf,
            },
            ed25519, secp256r1,
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        ed25519::PublicKey,
        sha256::Digest as Sha256,
    };
    use commonware_macros::test_async;
    use commonware_parallel::Sequential;
    use commonware_utils::{Faults, N3f1, TestRng, test_rng};

    const NAMESPACE: &[u8] = b"test";

    impl<V> Certification<V> {
        /// Returns the pending buffer (empty once complete).
        fn pending(&self) -> &[V] {
            match &self.state {
                State::Incomplete { pending, .. } => pending,
                State::Complete => &[],
            }
        }

        /// Returns the verified buffer (empty once complete).
        fn verified(&self) -> &[V] {
            match &self.state {
                State::Incomplete { verified, .. } => verified,
                State::Complete => &[],
            }
        }
    }

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
    fn create_nullify<S: Scheme<Sha256>>(scheme: &S, round: Round) -> Nullify<S> {
        Nullify::sign::<Sha256>(scheme, round).unwrap()
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
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );

        let round = Round::new(Epoch::new(0), View::new(1));
        let notarize1 = create_notarize(&schemes[0], round, View::new(0), 1);
        let notarize2 = create_notarize(&schemes[1], round, View::new(0), 1);
        let notarize_diff = create_notarize(&schemes[2], round, View::new(0), 2);

        verifier.add(Vote::Notarize(notarize1.clone()), false);
        assert_eq!(verifier.notarize.pending().len(), 1);
        assert_eq!(verifier.notarize.verified().len(), 0);

        verifier.add(Vote::Notarize(notarize1.clone()), true);
        assert_eq!(verifier.notarize.pending().len(), 1);
        assert_eq!(verifier.notarize.verified().len(), 1);

        verifier.set_leader(notarize1.signer(), Some(&notarize1));
        assert_eq!(
            verifier.get_leader_proposal(),
            Some((notarize1.signer(), &notarize1.proposal))
        );
        assert_eq!(verifier.notarize.pending().len(), 1);

        verifier.add(Vote::Notarize(notarize2), false);
        assert_eq!(verifier.notarize.pending().len(), 2);

        verifier.add(Vote::Notarize(notarize_diff), false);
        assert_eq!(verifier.notarize.pending().len(), 2);

        let mut verifier2 = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round2 = Round::new(Epoch::new(0), View::new(2));
        let notarize_non_leader = create_notarize(&schemes[1], round2, View::new(1), 3);
        let notarize_leader = create_notarize(&schemes[0], round2, View::new(1), 3);

        verifier2.set_leader(notarize_leader.signer(), None);
        verifier2.add(Vote::Notarize(notarize_non_leader), false);
        assert!(verifier2.get_leader_proposal().is_none());
        assert_eq!(verifier2.notarize.pending().len(), 1);

        verifier2.add(Vote::Notarize(notarize_leader.clone()), false);
        assert_eq!(
            verifier2.get_leader_proposal(),
            Some((notarize_leader.signer(), &notarize_leader.proposal))
        );
        assert_eq!(verifier2.notarize.pending().len(), 2);
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
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );

        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        let other_notarize = create_notarize(&schemes[1], round, View::new(0), 1);

        verifier.add(Vote::Notarize(other_notarize), false);
        assert_eq!(verifier.notarize.pending().len(), 1);

        let leader = leader_notarize.signer();
        verifier.set_leader(leader, None);
        assert!(matches!(verifier.leader, Leader::Known(l) if l == leader));
        assert!(verifier.get_leader_proposal().is_none());
        assert_eq!(verifier.notarize.pending().len(), 1);

        verifier.add(Vote::Notarize(leader_notarize.clone()), false);
        assert_eq!(
            verifier.get_leader_proposal(),
            Some((leader, &leader_notarize.proposal))
        );
        assert_eq!(verifier.notarize.pending().len(), 2);

        let mut verifier2 = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        verifier2.add(Vote::Notarize(leader_notarize.clone()), true);
        verifier2.set_leader(leader, Some(&leader_notarize));
        assert_eq!(
            verifier2.get_leader_proposal(),
            Some((leader, &leader_notarize.proposal))
        );
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

    async fn ready_and_verify_notarizes<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));
        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| create_notarize(scheme, round, View::new(0), 1))
            .collect();

        assert!(!verifier.notarize.should_verify());

        verifier.set_leader(notarizes[0].signer(), None);
        verifier.add(Vote::Notarize(notarizes[0].clone()), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.notarize.should_verify(), S::is_batchable());
        assert_eq!(verifier.notarize.pending().len(), 1);

        verifier.add(Vote::Notarize(notarizes[1].clone()), false);
        assert_eq!(!verifier.notarize.should_verify(), S::is_batchable());
        verifier.add(Vote::Notarize(notarizes[2].clone()), false);
        assert_eq!(!verifier.notarize.should_verify(), S::is_batchable());
        verifier.add(Vote::Notarize(notarizes[3].clone()), false);
        assert!(verifier.notarize.should_verify());
        assert_eq!(verifier.notarize.pending().len(), 4);

        let (batch, failed_bulk) = verifier
            .try_verify_notarizes(&mut rng, &Sequential)
            .await
            .unwrap();
        assert_eq!(batch, 4);
        assert!(failed_bulk.is_empty());
        assert_eq!(verifier.notarize.verified().len(), 4);
        assert!(verifier.notarize.pending().is_empty());
        assert!(!verifier.notarize.should_verify());

        let mut verifier2 = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round2 = Round::new(Epoch::new(0), View::new(2));
        let leader_vote = create_notarize(&schemes[0], round2, View::new(1), 10);
        let mut faulty_vote = create_notarize(&schemes[1], round2, View::new(1), 10);
        verifier2.set_leader(leader_vote.signer(), None);
        verifier2.add(Vote::Notarize(leader_vote.clone()), false);
        faulty_vote.attestation.signer = Participant::from_usize(schemes.len() + 10);
        verifier2.add(Vote::Notarize(faulty_vote.clone()), false);

        for scheme in schemes.iter().skip(2).take(quorum as usize - 2) {
            verifier2.add(
                Vote::Notarize(create_notarize(scheme, round2, View::new(1), 10)),
                false,
            );
        }
        assert!(verifier2.notarize.should_verify());

        let (batch, failed_second) = verifier2
            .try_verify_notarizes(&mut rng, &Sequential)
            .await
            .unwrap();
        assert_eq!(batch, quorum as usize);
        assert!(
            verifier2
                .notarize
                .verified()
                .iter()
                .any(|notarize| notarize == &leader_vote)
        );
        assert_eq!(failed_second, vec![faulty_vote.signer()]);
    }

    #[test_async]
    async fn test_ready_and_verify_notarizes() {
        ready_and_verify_notarizes(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_and_verify_notarizes(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_and_verify_notarizes(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_and_verify_notarizes(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_and_verify_notarizes(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_and_verify_notarizes(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_and_verify_notarizes(ed25519::fixture).await;
        ready_and_verify_notarizes(secp256r1::fixture).await;
    }

    fn add_nullify<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));
        let nullify = create_nullify(&schemes[0], round);

        verifier.add(Vote::Nullify(nullify.clone()), false);
        assert_eq!(verifier.nullify.pending().len(), 1);
        assert_eq!(verifier.nullify.verified().len(), 0);

        verifier.add(Vote::Nullify(nullify), true);
        assert_eq!(verifier.nullify.pending().len(), 1);
        assert_eq!(verifier.nullify.verified().len(), 1);
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

    async fn ready_and_verify_nullifies<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));
        let nullifies: Vec<_> = schemes
            .iter()
            .map(|scheme| create_nullify(scheme, round))
            .collect();

        verifier.add(Vote::Nullify(nullifies[0].clone()), true);
        assert_eq!(verifier.nullify.verified().len(), 1);

        verifier.add(Vote::Nullify(nullifies[1].clone()), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.nullify.should_verify(), S::is_batchable());
        verifier.add(Vote::Nullify(nullifies[2].clone()), false);
        assert_eq!(!verifier.nullify.should_verify(), S::is_batchable());
        verifier.add(Vote::Nullify(nullifies[3].clone()), false);
        assert!(verifier.nullify.should_verify());
        assert_eq!(verifier.nullify.pending().len(), 3);

        let (batch, failed) = verifier
            .try_verify_nullifies(&mut rng, &Sequential)
            .await
            .unwrap();
        assert_eq!(batch, 3);
        assert!(failed.is_empty());
        assert_eq!(verifier.nullify.verified().len(), 4);
        assert!(verifier.nullify.pending().is_empty());
        assert!(!verifier.nullify.should_verify());
    }

    #[test_async]
    async fn test_ready_and_verify_nullifies() {
        ready_and_verify_nullifies(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_and_verify_nullifies(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_and_verify_nullifies(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_and_verify_nullifies(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_and_verify_nullifies(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_and_verify_nullifies(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_and_verify_nullifies(ed25519::fixture).await;
        ready_and_verify_nullifies(secp256r1::fixture).await;
    }

    fn add_finalize<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));
        let finalize_a = create_finalize(&schemes[0], round, View::new(0), 1);
        let finalize_b = create_finalize(&schemes[1], round, View::new(0), 2);

        verifier.add(Vote::Finalize(finalize_b.clone()), false);
        assert_eq!(verifier.finalize.pending().len(), 1);
        assert_eq!(verifier.finalize.verified().len(), 0);

        verifier.add(Vote::Finalize(finalize_a.clone()), false);
        assert_eq!(verifier.finalize.pending().len(), 2);

        verifier.set_leader(finalize_a.signer(), None);
        assert!(verifier.get_leader_proposal().is_none());
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.try_learn_proposal(&leader_notarize);
        assert_eq!(verifier.finalize.pending().len(), 1);
        assert_eq!(verifier.finalize.pending()[0], finalize_a);
        assert_eq!(verifier.finalize.verified().len(), 0);

        verifier.add(Vote::Finalize(finalize_a), true);
        assert_eq!(verifier.finalize.pending().len(), 1);
        assert_eq!(verifier.finalize.verified().len(), 1);

        verifier.add(Vote::Finalize(finalize_b), false);
        assert_eq!(verifier.finalize.pending().len(), 1);
        assert_eq!(verifier.finalize.verified().len(), 1);
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

    async fn ready_and_verify_finalizes<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| create_finalize(scheme, round, View::new(0), 1))
            .collect();

        assert!(!verifier.finalize.should_verify());

        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(finalizes[0].signer(), Some(&leader_notarize));

        verifier.add(Vote::Finalize(finalizes[0].clone()), true);
        assert_eq!(verifier.finalize.verified().len(), 1);
        assert!(verifier.finalize.pending().is_empty());

        verifier.add(Vote::Finalize(finalizes[1].clone()), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.finalize.should_verify(), S::is_batchable());
        verifier.add(Vote::Finalize(finalizes[2].clone()), false);
        assert_eq!(!verifier.finalize.should_verify(), S::is_batchable());
        verifier.add(Vote::Finalize(finalizes[3].clone()), false);
        assert!(verifier.finalize.should_verify());

        let (batch, failed) = verifier
            .try_verify_finalizes(&mut rng, &Sequential)
            .await
            .unwrap();
        assert_eq!(batch, 3);
        assert!(failed.is_empty());
        assert_eq!(verifier.finalize.verified().len(), 4);
        assert!(verifier.finalize.pending().is_empty());
        assert!(!verifier.finalize.should_verify());
    }

    #[test_async]
    async fn test_ready_and_verify_finalizes() {
        ready_and_verify_finalizes(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_and_verify_finalizes(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_and_verify_finalizes(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_and_verify_finalizes(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_and_verify_finalizes(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_and_verify_finalizes(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_and_verify_finalizes(ed25519::fixture).await;
        ready_and_verify_finalizes(secp256r1::fixture).await;
    }

    fn leader_proposal_filters_messages<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));
        let proposal_a = Proposal::new(round, View::new(0), sample_digest(10));
        let proposal_b = Proposal::new(round, View::new(0), sample_digest(20));

        let notarize_a = Notarize::sign(&schemes[0], proposal_a.clone()).unwrap();
        let notarize_b = Notarize::sign(&schemes[1], proposal_b.clone()).unwrap();
        let finalize_a = Finalize::sign(&schemes[0], proposal_a.clone()).unwrap();
        let finalize_b = Finalize::sign(&schemes[1], proposal_b).unwrap();

        verifier.add(Vote::Notarize(notarize_a.clone()), false);
        verifier.add(Vote::Notarize(notarize_b.clone()), false);
        verifier.add(Vote::Notarize(notarize_a.clone()), true);
        verifier.add(Vote::Notarize(notarize_b), true);
        verifier.add(Vote::Finalize(finalize_a.clone()), false);
        verifier.add(Vote::Finalize(finalize_b.clone()), false);
        verifier.add(Vote::Finalize(finalize_a), true);
        verifier.add(Vote::Finalize(finalize_b), true);

        assert_eq!(verifier.notarize.pending().len(), 2);
        assert_eq!(verifier.notarize.verified().len(), 2);
        assert_eq!(verifier.finalize.pending().len(), 2);
        assert_eq!(verifier.finalize.verified().len(), 2);

        verifier.set_leader(notarize_a.signer(), Some(&notarize_a));

        assert_eq!(verifier.notarize.pending().len(), 1);
        assert_eq!(verifier.notarize.pending()[0].proposal, proposal_a);
        assert_eq!(verifier.notarize.verified().len(), 1);
        assert_eq!(verifier.notarize.verified()[0].proposal, proposal_a);
        assert_eq!(verifier.finalize.pending().len(), 1);
        assert_eq!(verifier.finalize.pending()[0].proposal, proposal_a);
        assert_eq!(verifier.finalize.verified().len(), 1);
        assert_eq!(verifier.finalize.verified()[0].proposal, proposal_a);
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
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            3,
        );
        verifier.set_leader(Participant::new(0), None);
        verifier.set_leader(Participant::new(1), None);
    }

    #[test]
    #[should_panic(expected = "Leader::Unknown")]
    fn test_set_leader_twice_panics_bls_threshold_minsig() {
        set_leader_twice_panics(bls12381_threshold_vrf::fixture::<MinSig, _>);
    }

    #[test]
    #[should_panic(expected = "Leader::Unknown")]
    fn test_set_leader_twice_panics_bls_threshold_minpk() {
        set_leader_twice_panics(bls12381_threshold_vrf::fixture::<MinPk, _>);
    }

    #[test]
    #[should_panic(expected = "Leader::Unknown")]
    fn test_set_leader_twice_panics_bls_threshold_std_minsig() {
        set_leader_twice_panics(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    #[test]
    #[should_panic(expected = "Leader::Unknown")]
    fn test_set_leader_twice_panics_bls_threshold_std_minpk() {
        set_leader_twice_panics(bls12381_threshold_std::fixture::<MinPk, _>);
    }

    #[test]
    #[should_panic(expected = "Leader::Unknown")]
    fn test_set_leader_twice_panics_bls_multisig_minsig() {
        set_leader_twice_panics(bls12381_multisig::fixture::<MinSig, _>);
    }

    #[test]
    #[should_panic(expected = "Leader::Unknown")]
    fn test_set_leader_twice_panics_bls_multisig_minpk() {
        set_leader_twice_panics(bls12381_multisig::fixture::<MinPk, _>);
    }

    #[test]
    #[should_panic(expected = "Leader::Unknown")]
    fn test_set_leader_twice_panics_ed() {
        set_leader_twice_panics(ed25519::fixture);
    }

    #[test]
    #[should_panic(expected = "Leader::Unknown")]
    fn test_set_leader_twice_panics_secp() {
        set_leader_twice_panics(secp256r1::fixture);
    }

    async fn notarizes_wait_for_quorum<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);

        verifier.set_leader(leader_vote.signer(), None);
        verifier.add(Vote::Notarize(leader_vote), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(
            !verifier.notarize.should_verify(),
            S::is_batchable(),
            "Batchable schemes wait for quorum, non-batchable verify immediately"
        );

        for scheme in schemes.iter().skip(1).take(quorum as usize - 1) {
            verifier.add(
                Vote::Notarize(create_notarize(scheme, round, View::new(0), 1)),
                false,
            );
        }
        assert!(
            verifier.notarize.should_verify(),
            "Should be ready at quorum"
        );

        let (batch, _) = verifier
            .try_verify_notarizes(&mut rng, &Sequential)
            .await
            .unwrap();
        assert_eq!(batch, quorum as usize);
        assert!(!verifier.notarize.should_verify());
    }

    #[test_async]
    async fn test_notarizes_wait_for_quorum() {
        notarizes_wait_for_quorum(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        notarizes_wait_for_quorum(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        notarizes_wait_for_quorum(bls12381_threshold_std::fixture::<MinSig, _>).await;
        notarizes_wait_for_quorum(bls12381_threshold_std::fixture::<MinPk, _>).await;
        notarizes_wait_for_quorum(bls12381_multisig::fixture::<MinSig, _>).await;
        notarizes_wait_for_quorum(bls12381_multisig::fixture::<MinPk, _>).await;
        notarizes_wait_for_quorum(ed25519::fixture).await;
        notarizes_wait_for_quorum(secp256r1::fixture).await;
    }

    async fn ready_notarizes_without_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));

        let notarizes: Vec<_> = schemes
            .iter()
            .take(quorum as usize)
            .map(|scheme| create_notarize(scheme, round, View::new(0), 1))
            .collect();

        for vote in notarizes.iter() {
            verifier.add(Vote::Notarize(vote.clone()), false);
        }

        // Without the leader's proposal, verification is refused and the
        // buffered votes are untouched
        assert!(
            verifier
                .try_verify_notarizes(&mut rng, &Sequential)
                .await
                .is_none(),
            "Should not verify without leader/proposal set"
        );
        assert_eq!(verifier.notarize.pending().len(), quorum as usize);

        verifier.set_leader(notarizes[0].signer(), Some(&notarizes[0]));
        assert!(
            verifier
                .try_verify_notarizes(&mut rng, &Sequential)
                .await
                .is_some(),
            "Should verify once leader is set"
        );
    }

    #[test_async]
    async fn test_ready_notarizes_without_leader_or_proposal() {
        ready_notarizes_without_leader(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_notarizes_without_leader(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_notarizes_without_leader(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_notarizes_without_leader(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_notarizes_without_leader(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_notarizes_without_leader(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_notarizes_without_leader(ed25519::fixture).await;
        ready_notarizes_without_leader(secp256r1::fixture).await;
    }

    async fn ready_finalizes_without_leader<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
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
            verifier
                .try_verify_finalizes(&mut rng, &Sequential)
                .await
                .is_none(),
            "Should not verify without leader/proposal set"
        );

        verifier.set_leader(finalizes[0].signer(), None);
        assert!(
            verifier
                .try_verify_finalizes(&mut rng, &Sequential)
                .await
                .is_none(),
            "Should not verify without leader_proposal set"
        );
        assert_eq!(verifier.finalize.pending().len(), quorum as usize);
    }

    #[test_async]
    async fn test_ready_finalizes_without_leader_or_proposal() {
        ready_finalizes_without_leader(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_finalizes_without_leader(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_finalizes_without_leader(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_finalizes_without_leader(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_finalizes_without_leader(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_finalizes_without_leader(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_finalizes_without_leader(ed25519::fixture).await;
        ready_finalizes_without_leader(secp256r1::fixture).await;
    }

    fn verify_notarizes_empty<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_notarize.signer(), Some(&leader_notarize));
        assert!(verifier.notarize.pending().is_empty());
        assert!(!verifier.notarize.should_verify());
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

    async fn verify_nullifies_empty<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        assert!(verifier.nullify.pending().is_empty());
        assert!(!verifier.nullify.should_verify());
        assert!(
            verifier
                .try_verify_nullifies(&mut rng, &Sequential)
                .await
                .is_none()
        );
        assert_eq!(verifier.nullify.verified().len(), 0);
    }

    #[test_async]
    async fn test_verify_nullifies_empty_pending() {
        verify_nullifies_empty(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        verify_nullifies_empty(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        verify_nullifies_empty(bls12381_threshold_std::fixture::<MinSig, _>).await;
        verify_nullifies_empty(bls12381_threshold_std::fixture::<MinPk, _>).await;
        verify_nullifies_empty(bls12381_multisig::fixture::<MinSig, _>).await;
        verify_nullifies_empty(bls12381_multisig::fixture::<MinPk, _>).await;
        verify_nullifies_empty(ed25519::fixture).await;
        verify_nullifies_empty(secp256r1::fixture).await;
    }

    async fn verify_finalizes_empty<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 3);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        verifier.set_leader(Participant::new(0), None);
        assert!(verifier.finalize.pending().is_empty());
        assert!(!verifier.finalize.should_verify());
        assert!(
            verifier
                .try_verify_finalizes(&mut rng, &Sequential)
                .await
                .is_none()
        );
        assert_eq!(verifier.finalize.verified().len(), 0);
    }

    #[test_async]
    async fn test_verify_finalizes_empty_pending() {
        verify_finalizes_empty(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        verify_finalizes_empty(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        verify_finalizes_empty(bls12381_threshold_std::fixture::<MinSig, _>).await;
        verify_finalizes_empty(bls12381_threshold_std::fixture::<MinPk, _>).await;
        verify_finalizes_empty(bls12381_multisig::fixture::<MinSig, _>).await;
        verify_finalizes_empty(bls12381_multisig::fixture::<MinPk, _>).await;
        verify_finalizes_empty(ed25519::fixture).await;
        verify_finalizes_empty(secp256r1::fixture).await;
    }

    async fn ready_notarizes_exact_quorum<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));

        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_vote.signer(), None);
        verifier.add(Vote::Notarize(leader_vote), true);
        assert_eq!(verifier.notarize.verified().len(), 1);

        for (i, scheme) in schemes.iter().enumerate().skip(1).take(quorum as usize - 1) {
            let is_last = i == quorum as usize - 1;
            verifier.add(
                Vote::Notarize(create_notarize(scheme, round, View::new(0), 1)),
                false,
            );
            if is_last {
                assert!(
                    verifier.notarize.should_verify(),
                    "Should be ready at exact quorum"
                );
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.notarize.should_verify());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.notarize.should_verify());
            }
        }

        let (batch, failed) = verifier
            .try_verify_notarizes(&mut rng, &Sequential)
            .await
            .unwrap();
        assert_eq!(batch, quorum as usize - 1);
        assert!(failed.is_empty());
        assert_eq!(verifier.notarize.verified().len(), quorum as usize);
        assert!(!verifier.notarize.should_verify());
    }

    #[test_async]
    async fn test_ready_notarizes_exact_quorum() {
        ready_notarizes_exact_quorum(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_notarizes_exact_quorum(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_notarizes_exact_quorum(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_notarizes_exact_quorum(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_notarizes_exact_quorum(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_notarizes_exact_quorum(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_notarizes_exact_quorum(ed25519::fixture).await;
        ready_notarizes_exact_quorum(secp256r1::fixture).await;
    }

    fn ready_nullifies_exact_quorum<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));

        verifier.add(Vote::Nullify(create_nullify(&schemes[0], round)), true);
        assert_eq!(verifier.nullify.verified().len(), 1);

        let pending_schemes: Vec<_> = schemes.iter().take(quorum as usize).skip(1).collect();
        for (i, scheme) in pending_schemes.iter().enumerate() {
            let is_last = i == pending_schemes.len() - 1;
            verifier.add(Vote::Nullify(create_nullify(scheme, round)), false);
            if is_last {
                assert!(verifier.nullify.should_verify());
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.nullify.should_verify());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.nullify.should_verify());
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
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader_finalize = create_finalize(&schemes[0], round, View::new(0), 1);
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_finalize.signer(), Some(&leader_notarize));
        verifier.add(Vote::Finalize(leader_finalize), true);
        assert_eq!(verifier.finalize.verified().len(), 1);

        let pending_schemes: Vec<_> = schemes.iter().take(quorum as usize).skip(1).collect();
        for (i, scheme) in pending_schemes.iter().enumerate() {
            let is_last = i == pending_schemes.len() - 1;
            verifier.add(
                Vote::Finalize(create_finalize(scheme, round, View::new(0), 1)),
                false,
            );
            if is_last {
                assert!(verifier.finalize.should_verify());
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.finalize.should_verify());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.finalize.should_verify());
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
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));

        // Pre-load the leader vote as if it had already been processed.
        let leader_vote = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_vote.signer(), None);
        verifier.add(Vote::Notarize(leader_vote), false);

        // Mark enough verified notarizes to satisfy the quorum outright.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(
                Vote::Notarize(create_notarize(scheme, round, View::new(0), 1)),
                true,
            );
        }
        assert_eq!(verifier.notarize.verified().len(), quorum as usize);
        assert!(
            !verifier.notarize.should_verify(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Additional pending votes must not flip readiness in this situation.
        let extra_vote = create_notarize(&schemes[quorum as usize], round, View::new(0), 1);
        verifier.add(Vote::Notarize(extra_vote), false);
        assert!(
            !verifier.notarize.should_verify(),
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
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));

        // First mark a quorum's worth of verified nullifies.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(Vote::Nullify(create_nullify(scheme, round)), true);
        }
        assert_eq!(verifier.nullify.verified().len(), quorum as usize);
        assert!(
            !verifier.nullify.should_verify(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Pending messages alone cannot transition the batch to ready.
        let extra_nullify = create_nullify(&schemes[quorum as usize], round);
        verifier.add(Vote::Nullify(extra_nullify), false);
        assert!(
            !verifier.nullify.should_verify(),
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
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        assert!(
            schemes.len() > quorum as usize,
            "test requires more validators than the quorum"
        );
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));

        // Prime the leader state so the quorum is already satisfied by verified finalizes.
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_notarize.signer(), Some(&leader_notarize));

        // Feed exactly the number of verified finalizes required to hit the quorum.
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(
                Vote::Finalize(create_finalize(scheme, round, View::new(0), 1)),
                true,
            );
        }
        assert_eq!(verifier.finalize.verified().len(), quorum as usize);
        assert!(
            !verifier.finalize.should_verify(),
            "Should not be ready if quorum already met by verified messages"
        );

        // Ensure additional pending finalizes do not incorrectly trigger readiness.
        let extra_finalize = create_finalize(&schemes[quorum as usize], round, View::new(0), 1);
        verifier.add(Vote::Finalize(extra_finalize), false);
        assert!(
            !verifier.finalize.should_verify(),
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

    #[test_async]
    async fn test_certification_lifecycle() {
        // Non-batchable schemes verify eagerly whenever votes are pending
        let mut eager = Certification::<u64>::new(3, false);
        eager.add(1, false);
        assert!(eager.should_verify());

        let mut votes = Certification::<u64>::new(3, true);
        votes.add(1, false);
        votes.add(2, true);
        assert_eq!(votes.pending(), &[1]);
        assert_eq!(votes.verified(), &[2]);

        // Batchable schemes wait until the buffers could reach quorum
        assert!(!votes.should_verify());
        votes.add(3, false);
        assert!(votes.should_verify());

        // Verification consumes both buffers and stores the new verified set.
        // Below quorum, recovery is refused.
        let (batch, invalid) = votes
            .try_verify(|pending, verified| async move {
                assert_eq!(pending, vec![1, 3]);
                assert_eq!(verified, vec![2]);
                (vec![1, 2], vec![])
            })
            .await
            .unwrap();
        assert_eq!(batch, 2);
        assert!(invalid.is_empty());
        assert!(votes.pending().is_empty());
        assert!(votes.try_complete().is_none());

        // At quorum, recovery surrenders the votes and completes. All later
        // votes are dropped.
        votes.add(3, true);
        assert_eq!(votes.try_complete(), Some(vec![1, 2, 3]));
        assert!(votes.is_complete());
        votes.add(5, false);
        assert!(votes.pending().is_empty());
        assert!(votes.verified().is_empty());
        assert!(
            votes
                .try_verify(|_, _| async { unreachable!() })
                .await
                .is_none()
        );
        assert!(votes.try_complete().is_none());

        // Network certificates complete without any votes
        let mut votes = Certification::<u64>::new(3, true);
        votes.add(1, false);
        votes.complete();
        assert!(votes.is_complete());
        assert!(votes.pending().is_empty());
    }

    /// The leader's late notarize must still set the proposal after the
    /// notarize kind is certified, even though the vote itself is dropped.
    fn late_leader_vote_after_certification<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));

        verifier.record_certificate(Kind::Notarization);
        verifier.set_leader(Participant::new(0), None);
        assert!(verifier.get_leader_proposal().is_none());

        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        let proposal = leader_notarize.proposal.clone();
        verifier.add(Vote::Notarize(leader_notarize), false);
        assert_eq!(
            verifier.get_leader_proposal(),
            Some((Participant::new(0), &proposal))
        );
        assert!(verifier.notarize.pending().is_empty());

        // Certifying one kind leaves the others accumulating
        verifier.add(Vote::Nullify(create_nullify(&schemes[0], round)), false);
        assert_eq!(verifier.nullify.pending().len(), 1);
    }

    #[test]
    fn test_late_leader_vote_after_certification() {
        late_leader_vote_after_certification(ed25519::fixture);
    }

    /// Constructible kinds drain in certificate order, exercising local
    /// assembly for every kind.
    #[test_async]
    async fn test_construct_drains_kinds_in_order() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<_, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(1));

        // Give every kind a pre-verified quorum
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_notarize.signer(), Some(&leader_notarize));
        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(
                Vote::Notarize(create_notarize(scheme, round, View::new(0), 1)),
                true,
            );
            verifier.add(Vote::Nullify(create_nullify(scheme, round)), true);
            verifier.add(
                Vote::Finalize(create_finalize(scheme, round, View::new(0), 1)),
                true,
            );
        }

        assert!(matches!(
            verifier.try_construct_certificate(&Sequential).await,
            Some(Certificate::Notarization(_))
        ));
        assert!(matches!(
            verifier.try_construct_certificate(&Sequential).await,
            Some(Certificate::Nullification(_))
        ));
        assert!(matches!(
            verifier.try_construct_certificate(&Sequential).await,
            Some(Certificate::Finalization(_))
        ));
        assert!(
            verifier
                .try_construct_certificate(&Sequential)
                .await
                .is_none()
        );
    }
}
