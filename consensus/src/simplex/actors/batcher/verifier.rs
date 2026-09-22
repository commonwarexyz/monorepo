use crate::{
    simplex::{
        scheme::Scheme,
        types::{
            Attributable, Certificate, Finalization, Kind, Notarization, Notarize, Nullification,
            Proposal, Subject, Vote,
        },
    },
    types::{Participant, Round as Rnd},
};
use commonware_cryptography::{
    Digest,
    certificate::{Attestation, Scheme as CertificateScheme},
};
use commonware_parallel::Strategy;
use commonware_runtime::telemetry::traces::TracedExt as _;
use commonware_utils::{non_empty, ordered::Set};
use rand::rngs::StdRng;
use rand_core::{CryptoRng, SeedableRng};
use std::{future::Future, mem, sync::Arc};
use tracing::{Instrument as _, Span, info_span};

/// Runs a CPU-bound job through [Strategy::spawn], entering `span` on the worker thread and
/// instrumenting the returned future so the offloaded work stays attributed to the caller's trace.
fn offload<P, F, T>(len: usize, span: Span, strategy: &P, job: F) -> impl Future<Output = T> + Send
where
    P: Strategy,
    F: FnOnce(P) -> T + Send + 'static,
    T: Send + 'static,
{
    let worker_span = span.clone();
    strategy
        .spawn(len, move |strategy| worker_span.in_scope(|| job(strategy)))
        .instrument(span)
}

/// The outcome of processing one vote kind.
pub struct Batch<C> {
    /// Pending votes processed, whether individually or through a certificate.
    pub batch: usize,
    /// Signers identified as invalid by attestation verification.
    ///
    /// An empty result does not mean every input vote was individually verified:
    /// successful optimistic assembly returns no per-vote results.
    pub invalid: Vec<Participant>,
    /// A certificate authenticated from the buffered votes.
    pub certificate: Option<C>,
    /// Whether `optimistic_assemble` returned pending attestation verification results.
    pub fallback: bool,
}

/// Certification progress for one kind of vote.
///
/// Each kind certifies independently: a view can legitimately certify both
/// a notarization and a nullification.
struct Certification<C, S: CertificateScheme> {
    /// Votes required to construct a certificate.
    quorum: usize,
    /// Progress toward a certificate.
    state: State<C, S>,
}

/// The state of a [Certification].
enum State<C, S: CertificateScheme> {
    /// No certificate yet. Votes accumulate toward a quorum.
    Incomplete {
        /// Votes awaiting signature verification.
        pending: Vec<(C, Attestation<S>)>,
        /// Votes with verified signatures, held for certificate construction.
        verified: Vec<(C, Attestation<S>)>,
    },
    /// A certificate exists. Further votes are dropped.
    Complete,
}

impl<C, S: CertificateScheme> Certification<C, S> {
    /// Creates an empty [State::Incomplete] whose vote buffers allocate lazily.
    const fn new(quorum: usize) -> Self {
        Self {
            quorum,
            state: State::Incomplete {
                pending: Vec::new(),
                verified: Vec::new(),
            },
        }
    }

    /// Buffers a vote for verification (or, if already verified, for
    /// certificate construction). The caller owns signer uniqueness. Votes that
    /// arrive after completion are dropped.
    fn add(&mut self, context: C, attestation: Attestation<S>, is_verified: bool) {
        let State::Incomplete { pending, verified } = &mut self.state else {
            return;
        };

        // Verified votes may accumulate to quorum. A batchable pending buffer
        // only needs the remaining unverified slots, while a non-batchable
        // pending buffer is consumed after each vote.
        let initial_capacity = if is_verified || S::is_batchable() {
            self.quorum.saturating_sub(verified.len()).max(1)
        } else {
            1
        };
        let votes = if is_verified { verified } else { pending };
        if votes.capacity() == 0 {
            votes.reserve_exact(initial_capacity);
        }
        votes.push((context, attestation));
    }

    /// Whether an unfinished kind has a verified quorum, allowing construction
    /// before proposal selection.
    const fn has_constructable_quorum(&self) -> bool {
        matches!(&self.state, State::Incomplete { verified, .. } if verified.len() >= self.quorum)
    }

    /// Whether to attempt construction or verify pending votes toward a quorum.
    fn should_construct(&self) -> bool {
        match &self.state {
            State::Incomplete { pending, verified } => {
                verified.len() >= self.quorum
                    || (!pending.is_empty()
                        && (!S::is_batchable() || verified.len() + pending.len() >= self.quorum))
            }
            State::Complete => false,
        }
    }

    /// Processes pending votes and assembles any resulting quorum in one worker.
    /// Pending verification requires one context, retained with every attestation so
    /// proposal changes can filter both buffers. An existing verified quorum skips
    /// pending votes and can complete before proposal selection.
    async fn try_construct<R, D, F, G>(
        &mut self,
        scheme: &Arc<S>,
        rng: &mut R,
        strategy: &impl Strategy,
        span: impl FnOnce() -> Span,
        subject: F,
        wrap: G,
    ) -> Option<Batch<Certificate<S, D>>>
    where
        R: CryptoRng,
        D: Digest,
        S: Scheme<D>,
        C: Clone + Send + Sync + 'static,
        F: for<'a> Fn(&'a C) -> Subject<'a, D> + Send + 'static,
        G: FnOnce(C, S::Certificate) -> Certificate<S, D> + Send + 'static,
    {
        if !self.should_construct() {
            return None;
        }
        let State::Incomplete { pending, verified } = &mut self.state else {
            unreachable!("complete certification cannot require construction");
        };

        // A verified quorum can construct the certificate without processing pending votes.
        if verified.len() >= self.quorum {
            pending.clear();
        }

        // Move the inputs into one worker for assembly and any fallback verification.
        let batch = pending.len();
        let len = batch + verified.len();
        let quorum = self.quorum;
        let (pending, mut verified) = (mem::take(pending), mem::take(verified));
        let scheme = Arc::clone(scheme);
        let mut rng = StdRng::from_rng(rng);
        let (votes, result) = offload(len, span(), strategy, move |strategy| {
            let context = verified
                .first()
                .or_else(|| pending.first())
                .expect("construction attempt requires votes")
                .0
                .clone();

            // A candidate quorum can authenticate the certificate without establishing
            // individual vote validity. Failure returns verification results for pending votes.
            // Below quorum, non-batchable schemes verify pending votes directly.
            let (mut result, fallback) = if len >= quorum {
                match scheme.optimistic_assemble::<_, D, _, _>(
                    &mut rng,
                    subject(&context),
                    pending.into_iter().map(|(_, attestation)| attestation),
                    verified.iter().map(|(_, attestation)| attestation),
                    &strategy,
                ) {
                    Ok(certificate) => {
                        return (
                            Vec::new(),
                            Batch {
                                batch,
                                invalid: Vec::new(),
                                certificate: Some(wrap(context, certificate)),
                                fallback: false,
                            },
                        );
                    }
                    Err(result) => (result, true),
                }
            } else {
                (
                    scheme.verify_attestations::<_, D, _>(
                        &mut rng,
                        subject(&context),
                        pending.into_iter().map(|(_, attestation)| attestation),
                        &strategy,
                    ),
                    false,
                )
            };

            // A quorum of prior and newly verified votes must assemble. Otherwise retain
            // them with their context so proposal changes can filter them.
            let certificate = if verified.len() + result.verified.len() >= quorum {
                let prior = verified.drain(..).map(|(_, attestation)| attestation);
                let certificate = scheme
                    .assemble(
                        non_empty![@prior.chain(result.verified.drain(..))],
                        &strategy,
                    )
                    .expect("verified quorum must assemble");
                Some(wrap(context, certificate))
            } else {
                verified.extend(
                    result
                        .verified
                        .into_iter()
                        .map(|attestation| (context.clone(), attestation)),
                );
                None
            };
            (
                verified,
                Batch {
                    batch,
                    invalid: result.invalid,
                    certificate,
                    fallback,
                },
            )
        })
        .await;

        // Only verified votes survive an incomplete attempt. A certificate completes
        // this kind and releases its buffers.
        if result.certificate.is_some() {
            self.complete();
        } else {
            let State::Incomplete { verified, .. } = &mut self.state else {
                unreachable!("certification completed mid-construction");
            };
            *verified = votes;
        }
        Some(result)
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
    fn retain(&mut self, f: impl Fn(&C) -> bool) {
        if let State::Incomplete { pending, verified } = &mut self.state {
            pending.retain(|(context, _)| f(context));
            verified.retain(|(context, _)| f(context));
        }
    }
}

/// How the selected proposal changed after an update.
pub(super) struct ProposalUpdate {
    /// Whether the selected proposal changed.
    pub(super) changed: bool,
    /// Whether an existing proposal was replaced with a different one.
    pub(super) replaced: bool,
}

/// What the round knows about its proposal, and how it was learned.
pub(super) enum ProposalState<D: Digest> {
    /// No proposal is known.
    Unknown,
    /// Learned from the leader's notarize vote. An authoritative proposal may
    /// replace it.
    Leader(Proposal<D>),
    /// Learned from a verified certificate or locally constructed finalize.
    /// Never replaced.
    Certificate(Proposal<D>),
}

impl<D: Digest> ProposalState<D> {
    /// Returns the proposal, if known.
    const fn proposal(&self) -> Option<&Proposal<D>> {
        match self {
            Self::Unknown => None,
            Self::Leader(proposal) | Self::Certificate(proposal) => Some(proposal),
        }
    }

    /// Updates the proposal from a leader vote or authoritative evidence.
    ///
    /// An unknown proposal accepts either source. An authoritative proposal
    /// may supersede a leader vote. All other transitions are ignored.
    ///
    /// Returns the selected proposal if its value changed. Certifying the
    /// leader-selected proposal returns `None`.
    fn update(&mut self, next: Self) -> Option<&Proposal<D>> {
        match (&*self, &next) {
            (Self::Unknown, Self::Leader(_) | Self::Certificate(_)) => {}
            (Self::Leader(_), Self::Certificate(_)) => {}
            _ => return None,
        }

        let changed = self.proposal() != next.proposal();
        *self = next;
        changed.then(|| self.proposal().expect("updated proposal must be known"))
    }
}

/// `Verifier` is a utility for tracking and verifying consensus messages.
///
/// For schemes where [`Verifier::is_batchable()`](commonware_cryptography::certificate::Verifier::is_batchable)
/// returns `true` (such as [ed25519], [bls12381_multisig] and [bls12381_threshold]), this struct collects
/// messages and defers verification until enough messages exist to potentially reach a quorum, enabling
/// efficient batch verification. For schemes where `is_batchable()` returns `false` (such as [secp256r1]),
/// signatures are verified eagerly as they arrive since there is no batching benefit.
///
/// Candidate quorums use [optimistic assembly](CertificateScheme::optimistic_assemble). Verified
/// votes are retained between attempts, and a verified quorum skips pending vote verification.
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

    /// The round's leader, once identified.
    leader: Option<Participant>,

    /// The round's proposal, once known.
    ///
    /// A known leader's notarize vote may supply the initial proposal. An
    /// independently authenticated proposal is authoritative and may replace
    /// it, or be established before the leader is identified.
    proposal: ProposalState<D>,

    /// Notarize certification progress.
    notarize: Certification<Proposal<D>, S>,
    /// Nullify certification progress.
    nullify: Certification<Rnd, S>,
    /// Finalize certification progress.
    finalize: Certification<Proposal<D>, S>,
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
        Self {
            scheme: scheme.into(),

            round,

            leader: None,
            proposal: ProposalState::Unknown,

            notarize: Certification::new(quorum),
            nullify: Certification::new(quorum),
            finalize: Certification::new(quorum),
        }
    }

    /// Returns the ordered participant set.
    pub(super) fn participants(&self) -> &Set<S::PublicKey> {
        self.scheme.participants()
    }

    /// Returns the round's leader, once known.
    pub const fn leader(&self) -> Option<Participant> {
        self.leader
    }

    /// Returns the round's proposal, once known.
    pub const fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.proposal()
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

    /// Tries to set the proposal from the known leader's notarize, dropping
    /// buffered votes for any other proposal (they cannot contribute to a
    /// certificate).
    ///
    /// Does nothing if the leader is unknown, `notarize` is not from the
    /// leader, or the proposal state rejects the transition.
    fn try_set_proposal_from_leader(&mut self, notarize: &Notarize<S, D>) {
        if self.leader != Some(notarize.signer()) {
            return;
        }
        self.set_proposal(ProposalState::Leader(notarize.proposal.clone()));
    }

    /// Updates the proposal state and, if the selected proposal changes, drops
    /// buffered notarize and finalize votes for any other proposal.
    ///
    /// Returns whether the selected proposal changed and whether the accepted
    /// change replaced an existing proposal. Rejected transitions and a
    /// provenance-only change return `false` for both.
    pub(super) fn set_proposal(&mut self, proposal: ProposalState<D>) -> ProposalUpdate {
        let replaced = self.proposal.proposal().is_some();
        let Some(proposal) = self.proposal.update(proposal) else {
            return ProposalUpdate {
                changed: false,
                replaced: false,
            };
        };
        self.notarize.retain(|context| context == proposal);
        self.finalize.retain(|context| context == proposal);
        ProposalUpdate {
            changed: true,
            replaced,
        }
    }

    /// Adds a [Vote] message to the batch for later verification.
    ///
    /// If the message has already been verified (e.g., we built it), it is stored
    /// directly for certificate recovery. Otherwise, it is added to the appropriate
    /// pending queue. Notarize and finalize votes for a proposal other than the
    /// known proposal are dropped since they cannot contribute to a certificate.
    ///
    /// If a leader is known and the message is a [Vote::Notarize] from that leader,
    /// this method may reveal the leader proposal.
    ///
    /// Callers must add at most one vote of each kind per signer. The batcher's
    /// [`Round`](super::Round) enforces this while recording votes.
    ///
    /// # Arguments
    ///
    /// * `msg` - The [Vote] message to add.
    /// * `verified` - A boolean indicating if the message has already been verified.
    pub fn add(&mut self, msg: Vote<S, D>, verified: bool) {
        match msg {
            Vote::Notarize(notarize) => {
                self.try_set_proposal_from_leader(&notarize);

                // If the proposal is known and the message is not for it, drop it
                if let Some(proposal) = self.proposal()
                    && proposal != &notarize.proposal
                {
                    return;
                }
                self.notarize
                    .add(notarize.proposal, notarize.attestation, verified);
            }
            Vote::Nullify(nullify) => {
                self.nullify
                    .add(nullify.round, nullify.attestation, verified);
            }
            Vote::Finalize(finalize) => {
                // If the proposal is known and the message is not for it, drop it
                if let Some(proposal) = self.proposal()
                    && proposal != &finalize.proposal
                {
                    return;
                }
                self.finalize
                    .add(finalize.proposal, finalize.attestation, verified);
            }
        }
    }

    /// Sets the leader for the current consensus view. Setting the same
    /// leader again is a no-op (stable leaders are re-stamped as the voter's
    /// current view advances through a term).
    ///
    /// `notarize` carries the leader's already-received vote, if any. Its
    /// proposal is learned when none is known. An authoritative proposal is
    /// never replaced.
    ///
    /// # Panics
    ///
    /// Panics if a different leader was already set or if `notarize` is not
    /// from `leader`. Both values are locally derived, so neither assertion
    /// can fire on adversarial input.
    pub fn set_leader(&mut self, leader: Participant, notarize: Option<&Notarize<S, D>>) {
        if let Some(existing) = self.leader {
            // Enforces the stable-leader contract (see `Elector::elect`).
            assert_eq!(existing, leader, "leader changed within round");
        }
        self.leader = Some(leader);
        if let Some(notarize) = notarize {
            assert_eq!(notarize.signer(), leader, "notarize must be from leader");
            self.try_set_proposal_from_leader(notarize);
        }
    }

    /// Attempts to construct a notarization from buffered votes.
    pub async fn try_construct_notarization<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> Option<Batch<Certificate<S, D>>> {
        if matches!(self.proposal, ProposalState::Unknown)
            && !self.notarize.has_constructable_quorum()
        {
            return None;
        }
        self.notarize
            .try_construct(
                &self.scheme,
                rng,
                strategy,
                || {
                    info_span!(
                        "simplex.batcher.construct.notarization",
                        epoch = self.round.epoch().traced(),
                        view = self.round.view().traced(),
                    )
                },
                |proposal| Subject::Notarize { proposal },
                |proposal, certificate| {
                    Certificate::Notarization(Notarization {
                        proposal,
                        certificate,
                    })
                },
            )
            .await
    }

    /// Attempts to construct a nullification from buffered votes.
    pub async fn try_construct_nullification<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> Option<Batch<Certificate<S, D>>> {
        self.nullify
            .try_construct(
                &self.scheme,
                rng,
                strategy,
                || {
                    info_span!(
                        "simplex.batcher.construct.nullification",
                        epoch = self.round.epoch().traced(),
                        view = self.round.view().traced(),
                    )
                },
                |round| Subject::Nullify { round: *round },
                |round, certificate| {
                    Certificate::Nullification(Nullification { round, certificate })
                },
            )
            .await
    }

    /// Attempts to construct a finalization from buffered votes.
    pub async fn try_construct_finalization<R: CryptoRng>(
        &mut self,
        rng: &mut R,
        strategy: &impl Strategy,
    ) -> Option<Batch<Certificate<S, D>>> {
        if matches!(self.proposal, ProposalState::Unknown)
            && !self.finalize.has_constructable_quorum()
        {
            return None;
        }
        self.finalize
            .try_construct(
                &self.scheme,
                rng,
                strategy,
                || {
                    info_span!(
                        "simplex.batcher.construct.finalization",
                        epoch = self.round.epoch().traced(),
                        view = self.round.view().traced(),
                    )
                },
                |proposal| Subject::Finalize { proposal },
                |proposal, certificate| {
                    Certificate::Finalization(Finalization {
                        proposal,
                        certificate,
                    })
                },
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            mocks::wrapped,
            scheme::{
                bls12381_multisig,
                bls12381_threshold::{
                    standard as bls12381_threshold_std, vrf as bls12381_threshold_vrf,
                },
                ed25519, secp256r1,
            },
            types::{Finalize, Nullify},
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

    fn assert_valid<S: Scheme<D>, D: Digest>(
        result: Batch<Certificate<S, D>>,
        expected_batch: usize,
    ) {
        assert_eq!(result.batch, expected_batch);
        assert!(result.invalid.is_empty());
        assert!(!result.fallback);
    }

    impl<C, S: CertificateScheme> Certification<C, S> {
        /// Returns the pending buffer (empty once complete).
        fn pending(&self) -> &[(C, Attestation<S>)] {
            match &self.state {
                State::Incomplete { pending, .. } => pending,
                State::Complete => &[],
            }
        }

        /// Returns the verified buffer (empty once complete).
        fn verified(&self) -> &[(C, Attestation<S>)] {
            match &self.state {
                State::Incomplete { verified, .. } => verified,
                State::Complete => &[],
            }
        }

        /// Returns the capacities of the pending and verified vote buffers.
        fn capacities(&self) -> (usize, usize) {
            match &self.state {
                State::Incomplete { pending, verified } => {
                    (pending.capacity(), verified.capacity())
                }
                State::Complete => (0, 0),
            }
        }
    }

    /// A round reserves vote storage only for phases that receive votes.
    #[test]
    fn test_verifier_allocates_vote_buffers_lazily() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let round = Round::new(Epoch::new(0), View::new(1));
        let mut verifier =
            Verifier::<ed25519::Scheme, Sha256>::new(round, schemes[0].clone(), quorum);

        assert_eq!(verifier.notarize.capacities(), (0, 0));
        assert_eq!(verifier.nullify.capacities(), (0, 0));
        assert_eq!(verifier.finalize.capacities(), (0, 0));

        let notarize = create_notarize(&schemes[0], round, View::zero(), 1);
        verifier.add(Vote::Notarize(notarize), false);
        let (pending, verified) = verifier.notarize.capacities();
        assert!(pending >= quorum as usize);
        assert_eq!(verified, 0);
        assert_eq!(verifier.nullify.capacities(), (0, 0));
        assert_eq!(verifier.finalize.capacities(), (0, 0));

        verifier.record_certificate(Kind::Notarization);
        assert_eq!(verifier.notarize.capacities(), (0, 0));
    }

    #[test_async]
    async fn test_non_batchable_certification_avoids_repeated_quorum_reservations() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = secp256r1::fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let round = Round::new(Epoch::zero(), View::new(1));
        let mut verifier = Verifier::<_, Sha256>::new(round, schemes[0].clone(), quorum);
        verifier.add(Vote::Nullify(create_nullify(&schemes[0], round)), false);
        let result = verifier
            .try_construct_nullification(&mut rng, &Sequential)
            .await
            .unwrap();
        assert_eq!(result.batch, 1);
        assert!(result.certificate.is_none());
        assert!(result.invalid.is_empty());

        verifier.add(Vote::Nullify(create_nullify(&schemes[1], round)), false);
        let (pending, _) = verifier.nullify.capacities();
        assert!(pending < quorum as usize);
    }

    #[test_async]
    async fn test_batchable_certification_reserves_only_remaining_quorum() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let round = Round::new(Epoch::zero(), View::new(1));
        let mut verifier = Verifier::<_, Sha256>::new(round, schemes[0].clone(), quorum);
        for scheme in schemes.iter().take(quorum as usize - 1) {
            verifier.add(Vote::Nullify(create_nullify(scheme, round)), false);
        }
        let mut invalid = create_nullify(
            &schemes[quorum as usize - 1],
            Round::new(Epoch::zero(), View::new(2)),
        );
        invalid.round = round;
        verifier.add(Vote::Nullify(invalid), false);
        let result = verifier
            .try_construct_nullification(&mut rng, &Sequential)
            .await
            .unwrap();
        assert_eq!(result.batch, quorum as usize);
        assert_eq!(result.invalid, vec![Participant::new(quorum - 1)]);
        assert!(result.certificate.is_none());

        verifier.add(
            Vote::Nullify(create_nullify(&schemes[quorum as usize], round)),
            false,
        );
        let (pending, _) = verifier.nullify.capacities();
        assert!(pending < quorum as usize);
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
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        let verified_notarize = create_notarize(&schemes[1], round, View::new(0), 1);
        let pending_notarize = create_notarize(&schemes[2], round, View::new(0), 1);
        let notarize_diff = create_notarize(&schemes[3], round, View::new(0), 2);

        verifier.add(Vote::Notarize(leader_notarize.clone()), false);
        assert_eq!(verifier.notarize.pending().len(), 1);
        assert_eq!(verifier.notarize.verified().len(), 0);

        verifier.add(Vote::Notarize(verified_notarize), true);
        assert_eq!(verifier.notarize.pending().len(), 1);
        assert_eq!(verifier.notarize.verified().len(), 1);

        verifier.set_leader(leader_notarize.signer(), Some(&leader_notarize));
        assert_eq!(verifier.leader(), Some(leader_notarize.signer()));
        assert_eq!(verifier.proposal(), Some(&leader_notarize.proposal));
        assert_eq!(verifier.notarize.pending().len(), 1);

        verifier.add(Vote::Notarize(pending_notarize), false);
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
        assert_eq!(verifier2.leader(), Some(notarize_leader.signer()));
        assert!(verifier2.proposal().is_none());
        assert_eq!(verifier2.notarize.pending().len(), 1);

        verifier2.add(Vote::Notarize(notarize_leader.clone()), false);
        assert_eq!(verifier2.proposal(), Some(&notarize_leader.proposal));
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
        assert_eq!(verifier.leader(), Some(leader));
        assert!(verifier.proposal().is_none());
        assert_eq!(verifier.notarize.pending().len(), 1);

        verifier.add(Vote::Notarize(leader_notarize.clone()), false);
        assert_eq!(verifier.proposal(), Some(&leader_notarize.proposal));
        assert_eq!(verifier.notarize.pending().len(), 2);

        let mut verifier2 = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        verifier2.add(Vote::Notarize(leader_notarize.clone()), true);
        verifier2.set_leader(leader, Some(&leader_notarize));
        assert_eq!(verifier2.leader(), Some(leader));
        assert_eq!(verifier2.proposal(), Some(&leader_notarize.proposal));

        // A verified notarization supersedes a conflicting proposal learned
        // from the leader's vote.
        let notarized_proposal = Proposal::new(round, View::new(0), sample_digest(2));
        assert_ne!(notarized_proposal, leader_notarize.proposal);
        assert!(
            verifier2
                .set_proposal(ProposalState::Certificate(notarized_proposal.clone()))
                .changed
        );
        assert_eq!(verifier2.proposal(), Some(&notarized_proposal));

        // Re-adopting the same proposal reports no change.
        assert!(
            !verifier2
                .set_proposal(ProposalState::Certificate(notarized_proposal.clone()))
                .changed
        );

        // The first notarization remains authoritative.
        let conflicting_notarized_proposal = Proposal::new(round, View::new(0), sample_digest(3));
        assert!(
            !verifier2
                .set_proposal(ProposalState::Certificate(conflicting_notarized_proposal))
                .changed
        );
        assert_eq!(verifier2.proposal(), Some(&notarized_proposal));

        // If the notarization arrives first, setting the leader cannot replace
        // its proposal with a conflicting buffered leader vote.
        let mut verifier3 = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            quorum,
        );
        assert!(
            verifier3
                .set_proposal(ProposalState::Certificate(notarized_proposal.clone()))
                .changed
        );
        assert!(verifier3.leader().is_none());
        assert_eq!(verifier3.proposal(), Some(&notarized_proposal));
        verifier3.set_leader(leader, Some(&leader_notarize));
        assert_eq!(verifier3.leader(), Some(leader));
        assert_eq!(verifier3.proposal(), Some(&notarized_proposal));
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

    async fn ready_and_construct_notarization<S, F>(mut fixture: F)
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

        assert!(!verifier.notarize.should_construct());

        verifier.set_leader(notarizes[0].signer(), None);
        verifier.add(Vote::Notarize(notarizes[0].clone()), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.notarize.should_construct(), S::is_batchable());
        assert_eq!(verifier.notarize.pending().len(), 1);

        verifier.add(Vote::Notarize(notarizes[1].clone()), false);
        assert_eq!(!verifier.notarize.should_construct(), S::is_batchable());
        verifier.add(Vote::Notarize(notarizes[2].clone()), false);
        assert_eq!(!verifier.notarize.should_construct(), S::is_batchable());
        verifier.add(Vote::Notarize(notarizes[3].clone()), false);
        assert!(verifier.notarize.should_construct());
        assert_eq!(verifier.notarize.pending().len(), 4);

        assert_valid(
            verifier
                .try_construct_notarization(&mut rng, &Sequential)
                .await
                .unwrap(),
            4,
        );
        assert!(verifier.notarize.is_complete());
        assert!(verifier.notarize.verified().is_empty());
        assert!(verifier.notarize.pending().is_empty());
        assert!(!verifier.notarize.should_construct());

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
        assert!(verifier2.notarize.should_construct());

        let Batch {
            batch,
            invalid: failed_second,
            ..
        } = verifier2
            .try_construct_notarization(&mut rng, &Sequential)
            .await
            .unwrap();
        assert_eq!(batch, quorum as usize);
        assert!(
            verifier2
                .notarize
                .verified()
                .iter()
                .any(|(proposal, attestation)| proposal == &leader_vote.proposal
                    && attestation == &leader_vote.attestation)
        );
        assert_eq!(failed_second, vec![faulty_vote.signer()]);
    }

    #[test_async]
    async fn test_ready_and_construct_notarization() {
        ready_and_construct_notarization(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_and_construct_notarization(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_and_construct_notarization(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_and_construct_notarization(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_and_construct_notarization(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_and_construct_notarization(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_and_construct_notarization(ed25519::fixture).await;
        ready_and_construct_notarization(secp256r1::fixture).await;
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
        let pending_nullify = create_nullify(&schemes[0], round);
        let verified_nullify = create_nullify(&schemes[1], round);

        verifier.add(Vote::Nullify(pending_nullify), false);
        assert_eq!(verifier.nullify.pending().len(), 1);
        assert_eq!(verifier.nullify.verified().len(), 0);

        verifier.add(Vote::Nullify(verified_nullify), true);
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

    async fn ready_and_construct_nullification<S, F>(mut fixture: F)
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
        assert_eq!(!verifier.nullify.should_construct(), S::is_batchable());
        verifier.add(Vote::Nullify(nullifies[2].clone()), false);
        assert_eq!(!verifier.nullify.should_construct(), S::is_batchable());
        verifier.add(Vote::Nullify(nullifies[3].clone()), false);
        assert!(verifier.nullify.should_construct());
        assert_eq!(verifier.nullify.pending().len(), 3);

        assert_valid(
            verifier
                .try_construct_nullification(&mut rng, &Sequential)
                .await
                .unwrap(),
            3,
        );
        assert!(verifier.nullify.is_complete());
        assert!(verifier.nullify.verified().is_empty());
        assert!(verifier.nullify.pending().is_empty());
        assert!(!verifier.nullify.should_construct());
    }

    #[test_async]
    async fn test_ready_and_construct_nullification() {
        ready_and_construct_nullification(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_and_construct_nullification(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_and_construct_nullification(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_and_construct_nullification(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_and_construct_nullification(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_and_construct_nullification(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_and_construct_nullification(ed25519::fixture).await;
        ready_and_construct_nullification(secp256r1::fixture).await;
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
        let verified_a = create_finalize(&schemes[2], round, View::new(0), 1);
        let rejected_b = create_finalize(&schemes[3], round, View::new(0), 2);

        verifier.add(Vote::Finalize(finalize_b), false);
        assert_eq!(verifier.finalize.pending().len(), 1);
        assert_eq!(verifier.finalize.verified().len(), 0);

        verifier.add(Vote::Finalize(finalize_a.clone()), false);
        assert_eq!(verifier.finalize.pending().len(), 2);

        verifier.set_leader(finalize_a.signer(), None);
        assert!(verifier.proposal().is_none());
        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.try_set_proposal_from_leader(&leader_notarize);
        assert_eq!(verifier.finalize.pending().len(), 1);
        assert_eq!(
            verifier.finalize.pending()[0],
            (finalize_a.proposal, finalize_a.attestation)
        );
        assert_eq!(verifier.finalize.verified().len(), 0);

        verifier.add(Vote::Finalize(verified_a), true);
        assert_eq!(verifier.finalize.pending().len(), 1);
        assert_eq!(verifier.finalize.verified().len(), 1);

        verifier.add(Vote::Finalize(rejected_b), false);
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

    async fn ready_and_construct_finalization<S, F>(mut fixture: F)
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

        assert!(!verifier.finalize.should_construct());

        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(finalizes[0].signer(), Some(&leader_notarize));

        verifier.add(Vote::Finalize(finalizes[0].clone()), true);
        assert_eq!(verifier.finalize.verified().len(), 1);
        assert!(verifier.finalize.pending().is_empty());

        verifier.add(Vote::Finalize(finalizes[1].clone()), false);
        // Non-batchable schemes verify immediately when pending votes exist
        assert_eq!(!verifier.finalize.should_construct(), S::is_batchable());
        verifier.add(Vote::Finalize(finalizes[2].clone()), false);
        assert_eq!(!verifier.finalize.should_construct(), S::is_batchable());
        verifier.add(Vote::Finalize(finalizes[3].clone()), false);
        assert!(verifier.finalize.should_construct());

        assert_valid(
            verifier
                .try_construct_finalization(&mut rng, &Sequential)
                .await
                .unwrap(),
            3,
        );
        assert!(verifier.finalize.is_complete());
        assert!(verifier.finalize.verified().is_empty());
        assert!(verifier.finalize.pending().is_empty());
        assert!(!verifier.finalize.should_construct());
    }

    #[test_async]
    async fn test_ready_and_construct_finalization() {
        ready_and_construct_finalization(bls12381_threshold_vrf::fixture::<MinSig, _>).await;
        ready_and_construct_finalization(bls12381_threshold_vrf::fixture::<MinPk, _>).await;
        ready_and_construct_finalization(bls12381_threshold_std::fixture::<MinSig, _>).await;
        ready_and_construct_finalization(bls12381_threshold_std::fixture::<MinPk, _>).await;
        ready_and_construct_finalization(bls12381_multisig::fixture::<MinSig, _>).await;
        ready_and_construct_finalization(bls12381_multisig::fixture::<MinPk, _>).await;
        ready_and_construct_finalization(ed25519::fixture).await;
        ready_and_construct_finalization(secp256r1::fixture).await;
    }

    fn leader_proposal_filters_messages<S, F>(mut fixture: F)
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
        let proposal_a = Proposal::new(round, View::new(0), sample_digest(10));
        let proposal_b = Proposal::new(round, View::new(0), sample_digest(20));

        let leader_notarize = Notarize::sign(&schemes[0], proposal_a.clone()).unwrap();
        let pending_notarize_b = Notarize::sign(&schemes[1], proposal_b.clone()).unwrap();
        let verified_notarize_a = Notarize::sign(&schemes[2], proposal_a.clone()).unwrap();
        let verified_notarize_b = Notarize::sign(&schemes[3], proposal_b.clone()).unwrap();
        let pending_finalize_a = Finalize::sign(&schemes[0], proposal_a.clone()).unwrap();
        let pending_finalize_b = Finalize::sign(&schemes[1], proposal_b.clone()).unwrap();
        let verified_finalize_a = Finalize::sign(&schemes[2], proposal_a.clone()).unwrap();
        let verified_finalize_b = Finalize::sign(&schemes[3], proposal_b).unwrap();

        verifier.add(Vote::Notarize(leader_notarize.clone()), false);
        verifier.add(Vote::Notarize(pending_notarize_b), false);
        verifier.add(Vote::Notarize(verified_notarize_a), true);
        verifier.add(Vote::Notarize(verified_notarize_b), true);
        verifier.add(Vote::Finalize(pending_finalize_a), false);
        verifier.add(Vote::Finalize(pending_finalize_b), false);
        verifier.add(Vote::Finalize(verified_finalize_a), true);
        verifier.add(Vote::Finalize(verified_finalize_b), true);

        assert_eq!(verifier.notarize.pending().len(), 2);
        assert_eq!(verifier.notarize.verified().len(), 2);
        assert_eq!(verifier.finalize.pending().len(), 2);
        assert_eq!(verifier.finalize.verified().len(), 2);

        verifier.set_leader(leader_notarize.signer(), Some(&leader_notarize));

        assert_eq!(verifier.notarize.pending().len(), 1);
        assert_eq!(verifier.notarize.pending()[0].0, proposal_a);
        assert_eq!(verifier.notarize.verified().len(), 1);
        assert_eq!(verifier.notarize.verified()[0].0, proposal_a);
        assert_eq!(verifier.finalize.pending().len(), 1);
        assert_eq!(verifier.finalize.pending()[0].0, proposal_a);
        assert_eq!(verifier.finalize.verified().len(), 1);
        assert_eq!(verifier.finalize.verified()[0].0, proposal_a);
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

    /// Re-stamping the same leader is scheme-independent bookkeeping, so one
    /// scheme is enough.
    #[test]
    fn test_set_leader_twice_same_value_is_noop() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, NAMESPACE, 3);
        let mut verifier = Verifier::<ed25519::Scheme, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            3,
        );
        let leader = Participant::new(0);
        verifier.set_leader(leader, None);
        verifier.set_leader(leader, None);
    }

    /// Changing an already-set leader is scheme-independent bookkeeping, so
    /// one scheme is enough.
    #[test]
    #[should_panic(expected = "leader changed within round")]
    fn test_set_leader_change_panics() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, NAMESPACE, 3);
        let mut verifier = Verifier::<ed25519::Scheme, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            3,
        );
        verifier.set_leader(Participant::new(0), None);
        verifier.set_leader(Participant::new(1), None);
    }

    /// The notarize handed to set_leader must come from the elected leader.
    /// This is a caller contract, not adversarial-input filtering.
    #[test]
    #[should_panic(expected = "notarize must be from leader")]
    fn test_set_leader_rejects_foreign_notarize() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, NAMESPACE, 3);
        let mut verifier = Verifier::<ed25519::Scheme, Sha256>::new(
            Round::new(Epoch::new(0), View::new(1)),
            schemes[0].clone(),
            3,
        );
        let notarize = create_notarize(
            &schemes[1],
            Round::new(Epoch::new(0), View::new(1)),
            View::new(0),
            10,
        );
        verifier.set_leader(Participant::new(0), Some(&notarize));
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
            !verifier.notarize.should_construct(),
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
            verifier.notarize.should_construct(),
            "Should attempt construction at quorum"
        );

        assert_valid(
            verifier
                .try_construct_notarization(&mut rng, &Sequential)
                .await
                .unwrap(),
            quorum as usize,
        );
        assert!(!verifier.notarize.should_construct());
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
                .try_construct_notarization(&mut rng, &Sequential)
                .await
                .is_none(),
            "Should not verify without leader/proposal set"
        );
        assert_eq!(verifier.notarize.pending().len(), quorum as usize);

        verifier.set_leader(notarizes[0].signer(), Some(&notarizes[0]));
        assert!(
            verifier
                .try_construct_notarization(&mut rng, &Sequential)
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
        let test_verifier_finalize = || {
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

            (verifier, finalizes[0].clone())
        };

        let (mut verifier, finalize) = test_verifier_finalize();

        assert!(
            verifier
                .try_construct_finalization(&mut rng, &Sequential)
                .await
                .is_none(),
            "Should not verify without leader/proposal set"
        );

        verifier.set_leader(finalize.signer(), None);
        assert!(
            verifier
                .try_construct_finalization(&mut rng, &Sequential)
                .await
                .is_none(),
            "Should not verify with a leader but no proposal"
        );
        assert_eq!(verifier.finalize.pending().len(), quorum as usize);

        let (mut verifier, finalize) = test_verifier_finalize();

        verifier.set_proposal(ProposalState::Certificate(finalize.proposal.clone()));
        assert!(verifier.leader.is_none());
        assert!(
            verifier
                .try_construct_finalization(&mut rng, &Sequential)
                .await
                .is_some(),
            "Should verify with a proposal and no leader"
        );
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

    async fn certificate_proposal_allows_finalize_verification<S, F>(mut fixture: F)
    where
        S: Scheme<Sha256, PublicKey = PublicKey>,
        F: FnMut(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let mut verifier = Verifier::<S, Sha256>::new(
            Round::new(Epoch::new(0), View::new(3)),
            schemes[0].clone(),
            quorum,
        );
        let round = Round::new(Epoch::new(0), View::new(3));
        let conflicting = Proposal::new(round, View::new(2), sample_digest(8));
        let proposal = Proposal::new(round, View::new(2), sample_digest(9));

        verifier.set_leader(Participant::new(0), None);
        verifier.add(
            Vote::Notarize(Notarize::sign(&schemes[0], conflicting.clone()).unwrap()),
            false,
        );
        assert_eq!(verifier.proposal(), Some(&conflicting));

        // A certificate-set proposal overrides the vote-learned one.
        let update = verifier.set_proposal(ProposalState::Certificate(proposal.clone()));
        assert!(update.changed && update.replaced);
        assert_eq!(verifier.proposal(), Some(&proposal));

        for scheme in schemes.iter().take(quorum as usize) {
            verifier.add(
                Vote::Finalize(Finalize::sign(scheme, proposal.clone()).unwrap()),
                false,
            );
        }
        assert_valid(
            verifier
                .try_construct_finalization(&mut rng, &Sequential)
                .await
                .expect("finalizes should verify against the certificate proposal"),
            quorum as usize,
        );
    }

    #[test_async]
    async fn test_certificate_proposal_allows_finalize_verification() {
        certificate_proposal_allows_finalize_verification(
            bls12381_threshold_vrf::fixture::<MinSig, _>,
        )
        .await;
        certificate_proposal_allows_finalize_verification(
            bls12381_threshold_vrf::fixture::<MinPk, _>,
        )
        .await;
        certificate_proposal_allows_finalize_verification(
            bls12381_threshold_std::fixture::<MinSig, _>,
        )
        .await;
        certificate_proposal_allows_finalize_verification(
            bls12381_threshold_std::fixture::<MinPk, _>,
        )
        .await;
        certificate_proposal_allows_finalize_verification(bls12381_multisig::fixture::<MinSig, _>)
            .await;
        certificate_proposal_allows_finalize_verification(bls12381_multisig::fixture::<MinPk, _>)
            .await;
        certificate_proposal_allows_finalize_verification(ed25519::fixture).await;
        certificate_proposal_allows_finalize_verification(secp256r1::fixture).await;
    }

    #[test_async]
    async fn test_nonbatchable_finalize_accounting_tracks_proposal_override() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = secp256r1::fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len()) as usize;
        let mut verifier = Verifier::<_, Sha256>::new(
            Round::new(Epoch::new(333), View::new(7)),
            schemes[0].clone(),
            quorum.try_into().unwrap(),
        );
        let round = Round::new(Epoch::new(333), View::new(7));
        let proposal_a = Proposal::new(round, View::new(6), sample_digest(1));
        let proposal_b = Proposal::new(round, View::new(6), sample_digest(2));

        verifier.set_leader(Participant::new(0), None);
        verifier.add(
            Vote::Notarize(Notarize::sign(&schemes[0], proposal_a.clone()).unwrap()),
            false,
        );
        verifier.add(
            Vote::Finalize(Finalize::sign(&schemes[0], proposal_a).unwrap()),
            false,
        );
        assert_valid(
            verifier
                .try_construct_finalization(&mut rng, &Sequential)
                .await
                .expect("nonbatchable schemes verify eagerly"),
            1,
        );
        assert_eq!(verifier.finalize.verified().len(), 1);

        // The override drops the verified finalize for the old proposal.
        verifier.set_proposal(ProposalState::Certificate(proposal_b.clone()));
        assert!(verifier.finalize.verified().is_empty());

        for scheme in schemes.iter().take(quorum).skip(1) {
            verifier.add(
                Vote::Finalize(Finalize::sign(scheme, proposal_b.clone()).unwrap()),
                false,
            );
            assert_valid(
                verifier
                    .try_construct_finalization(&mut rng, &Sequential)
                    .await
                    .expect("nonbatchable schemes verify eagerly"),
                1,
            );
        }
        assert_eq!(verifier.finalize.verified().len(), quorum - 1);

        verifier.add(
            Vote::Finalize(Finalize::sign(&schemes[quorum], proposal_b).unwrap()),
            false,
        );
        assert_valid(
            verifier
                .try_construct_finalization(&mut rng, &Sequential)
                .await
                .expect("nonbatchable schemes verify eagerly"),
            1,
        );
        assert!(verifier.finalize.is_complete());
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
        assert!(!verifier.notarize.should_construct());
    }

    #[test]
    fn test_notarizes_empty_pending() {
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
        assert!(!verifier.nullify.should_construct());
        assert!(
            verifier
                .try_construct_nullification(&mut rng, &Sequential)
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
        assert!(!verifier.finalize.should_construct());
        assert!(
            verifier
                .try_construct_finalization(&mut rng, &Sequential)
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
                    verifier.notarize.should_construct(),
                    "Should attempt construction at exact quorum"
                );
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.notarize.should_construct());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.notarize.should_construct());
            }
        }

        assert_valid(
            verifier
                .try_construct_notarization(&mut rng, &Sequential)
                .await
                .unwrap(),
            quorum as usize - 1,
        );
        assert!(verifier.notarize.is_complete());
        assert!(verifier.notarize.verified().is_empty());
        assert!(!verifier.notarize.should_construct());
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
                assert!(verifier.nullify.should_construct());
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.nullify.should_construct());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.nullify.should_construct());
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
                assert!(verifier.finalize.should_construct());
            } else if S::is_batchable() {
                // Batchable schemes wait for quorum
                assert!(!verifier.finalize.should_construct());
            } else {
                // Non-batchable schemes verify immediately when pending votes exist
                assert!(verifier.finalize.should_construct());
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
        assert!(verifier.notarize.should_construct());

        // Additional pending votes are unnecessary for completion.
        let extra_vote = create_notarize(&schemes[quorum as usize], round, View::new(0), 1);
        verifier.add(Vote::Notarize(extra_vote), false);
        assert!(verifier.notarize.should_construct());
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
        assert!(verifier.nullify.should_construct());

        // Additional pending votes are unnecessary for completion.
        let extra_nullify = create_nullify(&schemes[quorum as usize], round);
        verifier.add(Vote::Nullify(extra_nullify), false);
        assert!(verifier.nullify.should_construct());
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
        assert!(verifier.finalize.should_construct());

        // Additional pending votes are unnecessary for completion.
        let extra_finalize = create_finalize(&schemes[quorum as usize], round, View::new(0), 1);
        verifier.add(Vote::Finalize(extra_finalize), false);
        assert!(verifier.finalize.should_construct());
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
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let quorum = N3f1::quorum(schemes.len());
        let round = Round::new(Epoch::zero(), View::new(1));
        let mut verifier = Verifier::<_, Sha256>::new(round, schemes[0].clone(), quorum);
        verifier.add(Vote::Nullify(create_nullify(&schemes[0], round)), true);
        verifier.add(Vote::Nullify(create_nullify(&schemes[1], round)), false);
        assert!(!verifier.nullify.should_construct());
        verifier.add(Vote::Nullify(create_nullify(&schemes[2], round)), false);
        let mut invalid = create_nullify(&schemes[3], Round::new(Epoch::zero(), View::new(2)));
        invalid.round = round;
        verifier.add(Vote::Nullify(invalid), false);
        assert!(verifier.nullify.should_construct());

        let result = verifier
            .try_construct_nullification(&mut rng, &Sequential)
            .await
            .unwrap();
        assert_eq!(result.batch, 3);
        assert_eq!(result.invalid, vec![Participant::new(3)]);
        assert!(result.certificate.is_none());
        assert!(verifier.nullify.pending().is_empty());
        assert_eq!(verifier.nullify.verified().len(), 3);
        assert!(!verifier.nullify.should_construct());

        verifier.add(Vote::Nullify(create_nullify(&schemes[4], round)), true);
        let result = verifier
            .try_construct_nullification(&mut rng, &Sequential)
            .await
            .unwrap();
        assert_eq!(result.batch, 0);
        assert!(result.invalid.is_empty());
        assert!(!result.fallback);
        assert!(
            result
                .certificate
                .unwrap()
                .verify(&mut rng, &schemes[0], &Sequential)
        );
        assert!(verifier.nullify.is_complete());
        assert!(verifier.nullify.verified().is_empty());

        verifier.add(Vote::Nullify(create_nullify(&schemes[3], round)), false);
        assert!(verifier.nullify.pending().is_empty());
        assert!(
            verifier
                .try_construct_nullification(&mut rng, &Sequential)
                .await
                .is_none()
        );

        let mut verifier = Verifier::<_, Sha256>::new(round, schemes[0].clone(), quorum);
        verifier.add(Vote::Nullify(create_nullify(&schemes[0], round)), false);
        verifier.record_certificate(Kind::Nullification);
        assert!(verifier.nullify.is_complete());
        assert!(verifier.nullify.pending().is_empty());
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
        assert_eq!(verifier.leader(), Some(Participant::new(0)));
        assert!(verifier.proposal().is_none());

        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        let proposal = leader_notarize.proposal.clone();
        verifier.add(Vote::Notarize(leader_notarize), false);
        assert_eq!(verifier.proposal(), Some(&proposal));
        assert!(verifier.notarize.pending().is_empty());

        // Certifying one kind leaves the others accumulating
        verifier.add(Vote::Nullify(create_nullify(&schemes[0], round)), false);
        assert_eq!(verifier.nullify.pending().len(), 1);
    }

    #[test]
    fn test_late_leader_vote_after_certification() {
        late_leader_vote_after_certification(ed25519::fixture);
    }

    #[test_async]
    #[should_panic(expected = "verified quorum must assemble")]
    async fn test_construct_panics_on_recovery_failure() {
        let mut rng = test_rng();
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        let schemes: Vec<_> = schemes
            .into_iter()
            .map(|scheme| wrapped::Scheme::new(scheme, wrapped::Behavior::RecoveryFailure))
            .collect();
        let quorum = N3f1::quorum(schemes.len());
        let quorum_size = usize::try_from(quorum).expect("quorum exceeds usize::MAX");
        let round = Round::new(Epoch::new(0), View::new(1));
        let mut verifier = Verifier::<_, Sha256>::new(round, schemes[0].clone(), quorum);

        let leader_notarize = create_notarize(&schemes[0], round, View::new(0), 1);
        verifier.set_leader(leader_notarize.signer(), Some(&leader_notarize));
        for scheme in schemes.iter().take(quorum_size) {
            verifier.add(
                Vote::Notarize(create_notarize(scheme, round, View::new(0), 1)),
                true,
            );
        }

        let _ = verifier
            .try_construct_notarization(&mut rng, &Sequential)
            .await;
    }

    #[test_async]
    async fn test_verified_quorums_complete_without_pending_verification() {
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

        // A verified quorum makes additional pending input unnecessary.
        let unused = create_notarize(&schemes[quorum as usize], round, View::new(0), 2);
        verifier.add(Vote::Notarize(unused), false);
        for (kind, result) in [
            (
                Kind::Notarization,
                verifier
                    .try_construct_notarization(&mut rng, &Sequential)
                    .await,
            ),
            (
                Kind::Nullification,
                verifier
                    .try_construct_nullification(&mut rng, &Sequential)
                    .await,
            ),
            (
                Kind::Finalization,
                verifier
                    .try_construct_finalization(&mut rng, &Sequential)
                    .await,
            ),
        ] {
            let result = result.unwrap();
            assert_eq!(result.batch, 0);
            assert!(result.invalid.is_empty());
            assert!(!result.fallback);
            let certificate = result.certificate.unwrap();
            assert_eq!(certificate.kind(), kind);
            assert!(certificate.verify(&mut rng, &schemes[0], &Sequential));
        }
        assert!(
            verifier
                .try_construct_notarization(&mut rng, &Sequential)
                .await
                .is_none()
        );
        assert!(
            verifier
                .try_construct_nullification(&mut rng, &Sequential)
                .await
                .is_none()
        );
        assert!(
            verifier
                .try_construct_finalization(&mut rng, &Sequential)
                .await
                .is_none()
        );
    }
}
