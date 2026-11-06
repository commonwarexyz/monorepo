//! Structural checks run before any signature check.
//!
//! [`Counting`] is the Ed25519 suite with every role wrapped to count the signatures,
//! aggregates, and certificates it is asked to verify, so these tests observe exactly which
//! artifacts reach the role schemes.

use super::*;
use crate::multimmit::scheme::{DaSubject, NullifySubject, RoleDigest};
use commonware_cryptography::{
    Digest as DigestTrait,
    certificate::{AssemblyError, Item, Membership, Term, Verification},
};
use commonware_parallel::Strategy;
use commonware_utils::{iter::NonEmpty, ordered::Set};
use core::marker::PhantomData;
use rand_core::CryptoRng;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// A role scheme over subjects `T` that counts every verification it performs.
#[derive(Clone, Debug)]
pub(super) struct Counted<R, T> {
    inner: R,
    checks: Arc<AtomicUsize>,
    _subject: PhantomData<fn() -> T>,
}

impl<R, T> Counted<R, T> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            checks: Arc::new(AtomicUsize::new(0)),
            _subject: PhantomData,
        }
    }

    fn record(&self, checks: usize) {
        self.checks.fetch_add(checks, Ordering::SeqCst);
    }

    /// Returns how many signatures, aggregates, and certificates this role has verified.
    pub(super) fn checks(&self) -> usize {
        self.checks.load(Ordering::SeqCst)
    }
}

fn unwrap<R, T>(
    attestation: &certificate::Attestation<Counted<R, T>>,
) -> certificate::Attestation<R>
where
    R: for<'a> certificate::Scheme<Subject<'a, RoleDigest> = T>,
    T: certificate::Subject + 'static,
{
    certificate::Attestation {
        signer: attestation.signer,
        signature: attestation.signature.clone(),
    }
}

fn wrap<R, T>(attestation: certificate::Attestation<R>) -> certificate::Attestation<Counted<R, T>>
where
    R: for<'a> certificate::Scheme<Subject<'a, RoleDigest> = T>,
    T: certificate::Subject + 'static,
{
    certificate::Attestation {
        signer: attestation.signer,
        signature: attestation.signature,
    }
}

fn wrap_verification<R, T>(verification: Verification<R>) -> Verification<Counted<R, T>>
where
    R: for<'a> certificate::Scheme<Subject<'a, RoleDigest> = T>,
    T: certificate::Subject + 'static,
{
    Verification::new(
        verification.verified.into_iter().map(wrap).collect(),
        verification.invalid,
    )
}

// Every subject type here ignores the digest parameter, so the inner scheme is always called at
// the role digest.
impl<R, T> Verifier for Counted<R, T>
where
    R: for<'a> certificate::Scheme<Subject<'a, RoleDigest> = T>,
    T: certificate::Subject + 'static,
{
    type Subject<'a, D: DigestTrait> = T;
    type Faults = R::Faults;
    type PublicKey = R::PublicKey;
    type Certificate = R::Certificate;

    fn verify_certificate<G, D>(
        &self,
        rng: &mut G,
        subject: T,
        certificate: &Self::Certificate,
        strategy: &impl Strategy,
    ) -> bool
    where
        G: CryptoRng,
        D: DigestTrait,
    {
        self.record(1);
        self.inner
            .verify_certificate::<_, RoleDigest>(rng, subject, certificate, strategy)
    }

    fn verify_certificates<'a, G, D, I>(
        &self,
        rng: &mut G,
        certificates: NonEmpty<I>,
        strategy: &impl Strategy,
    ) -> bool
    where
        G: CryptoRng,
        D: DigestTrait,
        I: Iterator<Item = (T, &'a Self::Certificate)>,
    {
        let certificates = certificates.into_iter().collect::<Vec<_>>();
        self.record(certificates.len());
        self.inner.verify_certificates::<_, RoleDigest, _>(
            rng,
            NonEmpty::try_new(certificates.into_iter()).expect("non-empty input"),
            strategy,
        )
    }

    fn is_batchable() -> bool {
        R::is_batchable()
    }

    fn max_certificate_size(participants: u32) -> usize {
        R::max_certificate_size(participants)
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {
        self.inner.certificate_codec_config()
    }

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {
        R::certificate_codec_config_unbounded()
    }
}

impl<R, T> certificate::Scheme for Counted<R, T>
where
    R: for<'a> certificate::Scheme<Subject<'a, RoleDigest> = T>,
    T: certificate::Subject + 'static,
{
    type Signature = R::Signature;

    fn me(&self) -> Option<Membership> {
        self.inner.me()
    }

    fn participants(&self) -> &Set<Self::PublicKey> {
        self.inner.participants()
    }

    fn sign<D: DigestTrait>(&self, subject: T) -> Option<certificate::Attestation<Self>> {
        self.inner.sign::<RoleDigest>(subject).map(wrap)
    }

    fn verify_attestation<G, D>(
        &self,
        rng: &mut G,
        subject: T,
        attestation: &certificate::Attestation<Self>,
        strategy: &impl Strategy,
    ) -> bool
    where
        G: CryptoRng,
        D: DigestTrait,
    {
        self.record(1);
        self.inner
            .verify_attestation::<_, RoleDigest>(rng, subject, &unwrap(attestation), strategy)
    }

    fn verify_attestations<G, D, I>(
        &self,
        rng: &mut G,
        subject: T,
        attestations: I,
        strategy: &impl Strategy,
    ) -> Verification<Self>
    where
        G: CryptoRng,
        D: DigestTrait,
        I: IntoIterator<Item = certificate::Attestation<Self>>,
        I::IntoIter: Send,
    {
        let attestations = attestations
            .into_iter()
            .map(|attestation| unwrap(&attestation))
            .collect::<Vec<_>>();
        self.record(attestations.len());
        wrap_verification(self.inner.verify_attestations::<_, RoleDigest, _>(
            rng,
            subject,
            attestations,
            strategy,
        ))
    }

    fn optimistic_assemble<'a, G, D, I, J>(
        &self,
        rng: &mut G,
        subject: T,
        pending: I,
        verified: J,
        strategy: &impl Strategy,
    ) -> Result<Self::Certificate, Verification<Self>>
    where
        G: CryptoRng,
        D: DigestTrait,
        I: IntoIterator<Item = certificate::Attestation<Self>>,
        I::IntoIter: ExactSizeIterator + Send,
        J: IntoIterator<Item = &'a certificate::Attestation<Self>>,
        J::IntoIter: Send,
    {
        let pending = pending
            .into_iter()
            .map(|attestation| unwrap(&attestation))
            .collect::<Vec<_>>();
        let verified = verified.into_iter().map(unwrap).collect::<Vec<_>>();
        self.record(pending.len() + 1);
        self.inner
            .optimistic_assemble::<_, RoleDigest, _, _>(
                rng,
                subject,
                pending,
                verified.iter(),
                strategy,
            )
            .map_err(wrap_verification)
    }

    fn assemble<I>(
        &self,
        attestations: NonEmpty<I>,
        strategy: &impl Strategy,
    ) -> Result<Self::Certificate, AssemblyError>
    where
        I: Iterator<Item = certificate::Attestation<Self>> + Send,
    {
        let attestations = attestations
            .into_iter()
            .map(|attestation| unwrap(&attestation))
            .collect::<Vec<_>>();
        self.inner.assemble(
            NonEmpty::try_new(attestations.into_iter()).expect("non-empty input"),
            strategy,
        )
    }

    fn is_attributable() -> bool {
        R::is_attributable()
    }
}

impl<R, T> Aggregator for Counted<R, T>
where
    R: for<'a> Aggregator<Subject<'a, RoleDigest> = T>,
    T: certificate::Subject + 'static,
{
    type Aggregate = R::Aggregate;

    fn aggregate<'a, I>(&self, attestations: NonEmpty<I>) -> Result<Self::Aggregate, AssemblyError>
    where
        I: Iterator<Item = &'a certificate::Attestation<Self>>,
    {
        let attestations = attestations.into_iter().map(unwrap).collect::<Vec<_>>();
        self.inner
            .aggregate(NonEmpty::try_new(attestations.iter()).expect("non-empty input"))
    }

    fn verify_aggregates<G, D>(
        &self,
        rng: &mut G,
        items: &[Item<'_, '_, Self, D>],
        strategy: &impl Strategy,
    ) -> Vec<bool>
    where
        G: CryptoRng,
        D: DigestTrait,
    {
        self.record(items.len());
        // Own every attestation first, so the inner items can borrow them.
        let mut owned = Vec::new();
        for item in items {
            match item {
                Item::Attestation { attestation, .. } => owned.push(unwrap(attestation)),
                Item::Aggregate { terms, .. } => {
                    owned.extend(terms.iter().filter_map(|term| term.known.map(unwrap)));
                }
            }
        }
        let mut next = 0;
        let mut terms = Vec::with_capacity(items.len());
        let mut attestations = Vec::with_capacity(items.len());
        for item in items {
            match item {
                Item::Attestation { .. } => {
                    attestations.push(Some(next));
                    terms.push(Vec::new());
                    next += 1;
                }
                Item::Aggregate { terms: outer, .. } => {
                    attestations.push(None);
                    terms.push(
                        outer
                            .iter()
                            .map(|term| Term::<'_, R, RoleDigest> {
                                signer: term.signer,
                                subject: term.subject.clone(),
                                known: term.known.map(|_| {
                                    next += 1;
                                    &owned[next - 1]
                                }),
                            })
                            .collect::<Vec<_>>(),
                    );
                }
            }
        }
        let inner = items
            .iter()
            .zip(&terms)
            .zip(&attestations)
            .map(|((item, terms), attestation)| match item {
                Item::Attestation { subject, .. } => Item::Attestation {
                    subject: subject.clone(),
                    attestation: &owned[attestation.expect("attestation item")],
                },
                Item::Aggregate { aggregate, .. } => Item::Aggregate {
                    terms: terms.as_slice(),
                    aggregate,
                },
            })
            .collect::<Vec<_>>();
        self.inner
            .verify_aggregates::<_, RoleDigest>(rng, &inner, strategy)
    }

    fn max_aggregate_size(terms: u32) -> usize {
        R::max_aggregate_size(terms)
    }

    fn aggregate_codec_config(terms: u32) -> <Self::Aggregate as Read>::Cfg {
        R::aggregate_codec_config(terms)
    }
}

/// The Ed25519 suite with counting roles.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) struct Counting;

impl Scheme for Counting {
    type PublicKey = Ed25519PublicKey;
    type Ordinary = Counted<ed25519_suite::ordinary::Scheme, OrdinarySubject>;
    type Da = Counted<ed25519_suite::da::Scheme, DaSubject>;
    type Nullify = Counted<ed25519_suite::nullify::Scheme, NullifySubject>;

    fn da_certificate_config(participants: usize) -> usize {
        participants
    }

    fn nullification_config(participants: usize) -> usize {
        participants
    }

    fn da_signers(_: &Self::Da, certificate: &DaCertificateOf<Self>) -> Option<usize> {
        Some(certificate.signers.count())
    }
}

impl Suite for Counting {
    fn committee(
        _: &mut TestRng,
        parameters: &Arc<Parameters>,
        network_keys: &[Ed25519PrivateKey],
    ) -> (Vec<Generic<Self>>, Generic<Self>) {
        let namespace = parameters.namespace();
        let participants = Set::try_from(
            network_keys
                .iter()
                .map(|key| key.public_key())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let signers = network_keys
            .iter()
            .map(|key| {
                Generic::new(
                    parameters,
                    Counted::new(
                        ed25519_suite::ordinary::Scheme::signer(
                            namespace,
                            participants.clone(),
                            key.clone(),
                        )
                        .unwrap(),
                    ),
                    Counted::new(
                        ed25519_suite::da::Scheme::signer(
                            namespace,
                            participants.clone(),
                            key.clone(),
                        )
                        .unwrap(),
                    ),
                    Counted::new(
                        ed25519_suite::nullify::Scheme::signer(
                            namespace,
                            participants.clone(),
                            key.clone(),
                        )
                        .unwrap(),
                    ),
                )
                .unwrap()
            })
            .collect();
        let verifier = Generic::new(
            parameters,
            Counted::new(ed25519_suite::ordinary::Scheme::verifier(
                namespace,
                participants.clone(),
            )),
            Counted::new(ed25519_suite::da::Scheme::verifier(
                namespace,
                participants.clone(),
            )),
            Counted::new(ed25519_suite::nullify::Scheme::verifier(
                namespace,
                participants,
            )),
        )
        .unwrap();
        (signers, verifier)
    }
}

/// Returns how many checks `scheme`'s roles have performed.
fn checks(scheme: &Generic<Counting>) -> usize {
    scheme.ordinary().checks() + scheme.da().checks() + scheme.nullify().checks()
}

/// Every artifact kind, built for an epoch other than the fixture's with the same keys.
fn other_epoch_artifacts() -> Vec<Artifact<Counting, Digest>> {
    let committee = Committee::<Counting>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .limits(PathLimits::new(2, 2))
        .build();
    let config = keys::test_config(
        SEED + 1,
        NAMESPACE,
        PARTICIPANTS,
        committee.config.producers().to_vec(),
        PathLimits::new(2, 2),
    );
    let (signers, verifier) = Counting::committee(
        &mut TestRng::new(SEED),
        config.parameters(),
        &committee.network_keys,
    );
    let other = Fixture {
        codec: config.codec_config(),
        round: Round::new(config.epoch(), View::new(7)),
        tips: config.genesis().tips().to_vec(),
        config,
        signers,
        verifier,
    };
    super::batch::signed_message_cohort(&other)
        .artifacts
        .into_iter()
        .chain(super::batch::certificate_cohort(&other).artifacts)
        .collect()
}

/// Structurally invalid artifacts of every kind within the fixture's epoch, each carrying
/// signatures that would verify for some message.
fn malformed_artifacts(fixture: &Fixture<Counting>) -> Vec<Artifact<Counting, Digest>> {
    let outsider = Participant::new(PARTICIPANTS);
    let unconfigured = fixture.header(PARTICIPANTS, 1);
    let mut artifacts = Vec::new();

    // A transaction block on chain 0 signed by chain 1's producer.
    let foreign = fixture.signers[1]
        .sign_transaction_block(fixture.header(1, 2))
        .unwrap();
    artifacts.push(Artifact::TransactionBlock(SignedTransactionBlock::new(
        fixture.header(0, 2),
        foreign.attestation().clone(),
    )));
    artifacts.push(Artifact::TransactionBlock(SignedTransactionBlock::new(
        unconfigured.clone(),
        foreign.attestation().clone(),
    )));

    // DA votes by a non-member and for an unconfigured chain.
    let vote = fixture.signers[0]
        .sign_da_vote(fixture.header(0, 3))
        .unwrap();
    artifacts.push(Artifact::DaVote(DaVote::new(
        fixture.header(0, 3),
        certificate::Attestation {
            signer: outsider,
            signature: vote.attestation().signature.clone(),
        },
    )));
    artifacts.push(Artifact::DaVote(DaVote::new(
        unconfigured.clone(),
        vote.attestation().clone(),
    )));

    // A DA certificate for an unconfigured chain, and a leader block anchored on it.
    let certificate = fixture.da_certificate(&fixture.header(0, 4));
    let unconfigured_certificate =
        DaCertificate::new(unconfigured, certificate.certificate().clone());
    artifacts.push(Artifact::DaCertificate(unconfigured_certificate));

    // A leader block signed by a participant other than the scheduled leader.
    let leader = fixture.leader(5);
    let scheduled = fixture.scheduled(leader.view());
    let impostor = (scheduled + 1) % PARTICIPANTS as usize;
    let impostor_signature = fixture.signers[impostor]
        .sign_vote(fixture.standard_body(&leader))
        .unwrap()
        .attestation()
        .clone();
    artifacts.push(Artifact::LeaderBlock(SignedLeaderBlock::new(
        leader.clone(),
        impostor_signature,
    )));

    // A leader block and a vote exceeding the epoch's path limits, signed under wider limits.
    let wide = Committee::<Counting>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .limits(PathLimits::new(3, 3))
        .build();
    let deep_proposals = fixture
        .tips
        .iter()
        .enumerate()
        .map(|(index, tip)| {
            ChainProposal::new(
                ChainId::new(index as u32),
                Anchor::Tip(*tip),
                (0..3).map(|offset| digest(b"deep", offset)).collect(),
                3,
            )
            .unwrap()
        })
        .collect();
    let deep = LeaderBlock::new(
        fixture.round,
        CertificateId::new(digest(b"parent vqc", 6)),
        digest(b"history", 6),
        deep_proposals,
        wide.codec(),
    )
    .unwrap();
    artifacts.push(Artifact::LeaderBlock(
        wide.signers[scheduled].sign_leader_block(deep).unwrap(),
    ));
    let mut extensions = vec![Extension::empty(); PARTICIPANTS as usize];
    extensions[0] =
        Extension::new((0..3).map(|offset| digest(b"wide", offset)).collect(), 3).unwrap();
    let wide_body = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&leader),
        vec![Position::new(0); PARTICIPANTS as usize],
        extensions,
        wide.codec(),
    )
    .unwrap();
    artifacts.push(Artifact::Vote(
        wide.signers[0].sign_vote(wide_body).unwrap(),
    ));

    // A nullify share by a non-member.
    let share = fixture.signers[0].sign_nullify(fixture.round).unwrap();
    artifacts.push(Artifact::Nullify(
        Nullify::new(
            fixture.round,
            certificate::Attestation {
                signer: outsider,
                signature: share.attestation().signature.clone(),
            },
        )
        .unwrap(),
    ));
    artifacts
}

#[test]
fn structurally_invalid_artifacts_never_reach_the_schemes() {
    let fixture = Fixture::<Counting>::new();
    let verifier = &fixture.verifier;
    let mut invalid = other_epoch_artifacts();
    invalid.extend(malformed_artifacts(&fixture));
    assert!(invalid.len() > 30);

    let before = checks(verifier);
    for artifact in &invalid {
        assert_eq!(
            verifier.verify_artifacts::<_, Sha256, Digest>(
                &mut test_rng(),
                &[artifact],
                &[],
                &Sequential
            ),
            [false],
            "{:?} passed",
            artifact.kind()
        );
    }
    let invalid_refs = invalid.iter().collect::<Vec<_>>();
    assert_eq!(
        verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &invalid_refs,
            &[],
            &Sequential
        ),
        vec![false; invalid.len()]
    );
    assert_eq!(
        checks(verifier),
        before,
        "a structurally invalid artifact reached a role scheme"
    );

    // Mixed with valid artifacts, the invalid ones add no checks to the batch.
    let mut cohort = super::batch::signed_message_cohort(&fixture);
    let certificates = super::batch::certificate_cohort(&fixture);
    cohort.artifacts.extend(certificates.artifacts);
    let valid = cohort.artifacts.iter().collect::<Vec<_>>();
    let before = checks(verifier);
    let verdicts =
        verifier.verify_artifacts::<_, Sha256, Digest>(&mut test_rng(), &valid, &[], &Sequential);
    let alone = checks(verifier) - before;
    assert!(alone > 0);
    let mut mixed = valid.clone();
    let mut expected = verdicts;
    for (index, artifact) in invalid.iter().enumerate() {
        let position = (index * 7) % (mixed.len() + 1);
        mixed.insert(position, artifact);
        expected.insert(position, false);
    }
    let before = checks(verifier);
    assert_eq!(
        verifier.verify_artifacts::<_, Sha256, Digest>(&mut test_rng(), &mixed, &[], &Sequential),
        expected
    );
    assert_eq!(checks(verifier) - before, alone);
}

#[test]
fn counting_suite_matches_ed25519_verdicts() {
    let fixture = Fixture::<Counting>::new();
    let mut cohort = super::batch::signed_message_cohort(&fixture);
    let certificates = super::batch::certificate_cohort(&fixture);
    assert_eq!(cohort.individual, cohort.expected);
    assert_eq!(certificates.individual, certificates.expected);
    cohort.artifacts.extend(certificates.artifacts);
    cohort.expected.extend(certificates.expected);
    let artifacts = cohort.artifacts.iter().collect::<Vec<_>>();
    assert_eq!(
        fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &artifacts,
            &[],
            &Sequential
        ),
        cohort.expected
    );
}
