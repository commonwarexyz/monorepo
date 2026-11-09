#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Decode, Encode, EncodeSize, FixedSize};
use commonware_consensus::{
    Epochable, Viewable,
    simplex::{
        scheme::bls12381_threshold::vrf::{self, Certificate, Seed, Seedable, Signature},
        types::{Finalization, Notarization, Proposal, Subject},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::{
        primitives::variant::{MinPk, MinSig, Variant},
        tle,
    },
    certificate::{
        AssemblyError, Attestation, Membership, Scheme as _, Verifier as _, mocks::Fixture,
    },
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
};
use commonware_math::algebra::Random as _;
use commonware_parallel::Sequential;
use commonware_runtime::{Runner, deterministic};
use commonware_utils::{
    Entropy, Faults, FuzzRng, N3f1, Participant,
    iter::{NonEmpty, zip_eq},
    non_empty,
    ordered::Quorum,
};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;

type Scheme<V> = vrf::Scheme<PublicKey, V>;
type Vote<V> = Attestation<Scheme<V>>;

const NAMESPACE: &[u8] = b"simplex_threshold_vrf";
const MIN_PARTICIPANTS: u32 = 4;
const MAX_PARTICIPANTS: u32 = 7;
const MAX_CASES: usize = 4;
const MAX_CERTIFICATES: usize = 4;
const EPOCHS: u64 = 2;
const VIEWS: u64 = 2;

/// Bytes of the stream a session is sampled from, enough for the longest session, of the
/// input's head that seeds the stream, and of the stream's tail that seeds the runtime.
const STREAM_BYTES: usize = 1 << 9;
const SEED_BYTES: usize = 8;
const ENTROPY_BYTES: usize = 32;

/// Bytes a forged seed is sampled from: its round and the scalar behind its signature.
const FORGED_BYTES: usize = 48;

#[derive(Arbitrary, Clone, Copy, Debug)]
enum VariantKind {
    MinPk,
    MinSig,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Kind {
    Notarize,
    Nullify,
    Finalize,
}

/// The role of the instance that verifies.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Role {
    Signer,
    Verifier,
    Member,
}

/// Rounds are few, so the subjects of a session often share one.
fn round(u: &mut Unstructured<'_>) -> arbitrary::Result<Round> {
    Ok(Round::new(
        Epoch::new(u.int_in_range(0..=EPOCHS - 1)?),
        View::new(u.int_in_range(1..=VIEWS)?),
    ))
}

#[derive(Arbitrary, Clone, Copy, Debug)]
struct SubjectInput {
    kind: Kind,
    #[arbitrary(with = round)]
    round: Round,
    payload: bool,
}

/// How a signature fails to verify.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum Fault {
    /// The vote signature is over another subject of the same round.
    Vote,
    /// The seed signature is over another round.
    Seed,
    /// The signature does not decode.
    Malformed,
}

/// How a vote fails to verify.
#[derive(Arbitrary, Clone, Copy, Debug)]
enum VoteFault {
    Signature(Fault),
    /// The signature is the next participant's.
    Share,
    /// The signer is outside the committee.
    Unknown,
}

/// One fault rejects a whole batch, so most signatures hold.
fn fault<'a, T: Arbitrary<'a>>(u: &mut Unstructured<'a>) -> arbitrary::Result<Option<T>> {
    Ok(if u.ratio(1, 8)? {
        Some(u.arbitrary()?)
    } else {
        None
    })
}

#[derive(Debug)]
struct VoteInput {
    signer: usize,
    fault: Option<VoteFault>,
}

/// Samples the votes of distinct signers among `n`, in any order. Most batches hold a quorum.
fn votes(u: &mut Unstructured<'_>, n: usize) -> arbitrary::Result<Vec<VoteInput>> {
    let min = if u.ratio(1, 4)? {
        0
    } else {
        N3f1::quorum(n) as usize
    };
    let mut signers: Vec<_> = (0..n).collect();
    (0..u.int_in_range(min..=n)?)
        .map(|i| {
            signers.swap(i, u.int_in_range(i..=n - 1)?);
            Ok(VoteInput {
                signer: signers[i],
                fault: fault(u)?,
            })
        })
        .collect()
}

#[derive(Arbitrary, Debug)]
struct CertificateInput {
    subject: SubjectInput,
    /// The first of the consecutive participants whose votes are assembled.
    first: u8,
    #[arbitrary(with = fault)]
    fault: Option<Fault>,
}

#[derive(Debug)]
enum Case {
    /// Verifies votes one by one and as a batch, then assembles them.
    Votes {
        subject: SubjectInput,
        votes: Vec<VoteInput>,
        role: Role,
    },
    /// Assembles the first `pending` votes with the rest, which are already verified.
    Optimistic {
        subject: SubjectInput,
        votes: Vec<VoteInput>,
        pending: usize,
        role: Role,
    },
    /// Verifies certificates one by one and as a batch.
    Certificates {
        certificates: Vec<CertificateInput>,
        role: Role,
    },
    /// Derives the seed of the subject's round and decrypts a message encrypted for `target`.
    Seed {
        subject: SubjectInput,
        target: Round,
        message: [u8; 32],
        forged: [u8; FORGED_BYTES],
        role: Role,
    },
}

fn case(u: &mut Unstructured<'_>, n: usize) -> arbitrary::Result<Case> {
    Ok(match u.int_in_range(0..=3)? {
        0 => Case::Votes {
            subject: u.arbitrary()?,
            votes: votes(u, n)?,
            role: u.arbitrary()?,
        },
        1 => {
            let votes = votes(u, n)?;
            Case::Optimistic {
                subject: u.arbitrary()?,
                pending: u.int_in_range(0..=votes.len())?,
                votes,
                role: u.arbitrary()?,
            }
        }
        2 => Case::Certificates {
            certificates: (0..u.int_in_range(1..=MAX_CERTIFICATES)?)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
            role: u.arbitrary()?,
        },
        _ => Case::Seed {
            subject: u.arbitrary()?,
            target: round(u)?,
            message: u.arbitrary()?,
            forged: u.arbitrary()?,
            role: u.arbitrary()?,
        },
    })
}

#[derive(Debug)]
struct FuzzInput {
    variant: VariantKind,
    participants: u32,
    /// The participant that also joins the committee without its share.
    member: usize,
    cases: Vec<Case>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // libFuzzer starts from inputs of a few bytes and lengthens them slowly, and a session
        // sampled from so few bytes would hold no signature. The input's head therefore seeds a
        // fixed-size stream of [`FuzzRng`] output that the rest of the input overwrites from its
        // start, so every input, even an empty one, samples whole cases, and a byte mutated
        // past the head changes only what is sampled from it.
        let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let (session, entropy) = stream.split_at(stream.len() - ENTROPY_BYTES);
        let u = &mut Unstructured::new(session);

        let variant = u.arbitrary()?;
        let participants = u.int_in_range(MIN_PARTICIPANTS..=MAX_PARTICIPANTS)?;
        let n = participants as usize;
        let member = u.int_in_range(0..=n - 1)?;
        let cases = (0..u.int_in_range(1..=MAX_CASES)?)
            .map(|_| case(u, n))
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self {
            variant,
            participants,
            member,
            cases,
            entropy: Unstructured::new(entropy).arbitrary()?,
        })
    }
}

fn subject(kind: Kind, proposal: &Proposal<Digest>) -> Subject<'_, Digest> {
    match kind {
        Kind::Notarize => Subject::Notarize { proposal },
        Kind::Nullify => Subject::Nullify {
            round: proposal.round,
        },
        Kind::Finalize => Subject::Finalize { proposal },
    }
}

/// The subject signatures are checked against, and the subjects a faulty signature is over.
struct Subjects {
    kind: Kind,
    proposal: Proposal<Digest>,
    /// The proposal in a round no session samples.
    stray: Proposal<Digest>,
}

impl Subjects {
    fn new(input: &SubjectInput) -> Self {
        let proposal = |round: Round| {
            let parent = round.view().previous().expect("views start at one");
            Proposal::new(round, parent, Sha256::hash(&[&[u8::from(input.payload)]]))
        };
        let stray = Epoch::new(input.round.epoch().get() + EPOCHS);
        Self {
            kind: input.kind,
            proposal: proposal(input.round),
            stray: proposal(Round::new(stray, input.round.view())),
        }
    }

    fn subject(&self) -> Subject<'_, Digest> {
        subject(self.kind, &self.proposal)
    }

    /// Returns another subject of the same round. Of the signatures over it, only the seed
    /// signature holds for [`Self::subject`].
    fn same_round(&self) -> Subject<'_, Digest> {
        let kind = match self.kind {
            Kind::Notarize => Kind::Nullify,
            Kind::Nullify => Kind::Finalize,
            Kind::Finalize => Kind::Notarize,
        };
        subject(kind, &self.proposal)
    }

    /// Returns the subject in another round. Neither signature over it holds for
    /// [`Self::subject`].
    fn other_round(&self) -> Subject<'_, Digest> {
        subject(self.kind, &self.stray)
    }
}

/// Returns what `sign` yields over the subject of `subjects`, with the signature `fault` names
/// taken from what it yields over another subject.
fn sign_with<V: Variant>(
    subjects: &Subjects,
    fault: Option<Fault>,
    sign: impl Fn(Subject<'_, Digest>) -> Signature<V>,
) -> Signature<V> {
    let mut signature = sign(subjects.subject());
    match fault {
        Some(Fault::Vote) => signature.vote_signature = sign(subjects.same_round()).vote_signature,
        Some(Fault::Seed) => signature.seed_signature = sign(subjects.other_round()).seed_signature,
        Some(Fault::Malformed) | None => {}
    }
    signature
}

/// Returns `value` as decoded from the network, its trailing signatures still encoded. A
/// malformed value arrives with them zeroed, which encodes no signature.
fn received<V: Variant, T: Encode + Decode>(value: &T, cfg: &T::Cfg, malformed: bool) -> T {
    let mut encoded = value.encode().to_vec();
    if malformed {
        let signatures = encoded.len() - Signature::<V>::SIZE;
        encoded[signatures..].fill(0);
    }
    T::decode_cfg(encoded, cfg).expect("signatures must decode lazily")
}

/// Splits `votes` as verifying them must: those without a fault, in order, and the sorted
/// signers of the rest.
fn partition<V: Variant>(
    votes: &[Vote<V>],
    inputs: &[VoteInput],
) -> (Vec<Vote<V>>, Vec<Participant>) {
    let mut verified = Vec::new();
    let mut invalid = Vec::new();
    for (vote, input) in zip_eq(votes, inputs) {
        if input.fault.is_none() {
            verified.push(vote.clone());
        } else {
            invalid.push(vote.signer);
        }
    }
    invalid.sort_unstable();
    (verified, invalid)
}

/// One committee in every role an instance plays.
struct Committee<V: Variant> {
    signers: Vec<Scheme<V>>,
    verifier: Scheme<V>,
    member: Scheme<V>,
    certificate_verifier: Scheme<V>,
}

impl<V: Variant> Committee<V> {
    /// Deals shares to `n` participants and builds every role from them, checking what each
    /// role reports about itself. The participant at `member` also joins without its share.
    fn new(context: &mut deterministic::Context, n: u32, member: usize) -> Self {
        let Fixture {
            participants,
            schemes: signers,
            verifier,
            ..
        } = vrf::fixture::<V, _>(context, NAMESPACE, n);
        let committee = verifier.participants().clone();
        let polynomial = verifier.polynomial().clone();
        let identity = *verifier.identity();

        for (index, signer) in signers.iter().enumerate() {
            let index = Participant::from_usize(index);
            assert_eq!(signer.me(), Some(Membership::Signer(index)));
            assert_eq!(signer.identity(), &identity);
        }
        assert_eq!(verifier.me(), None);
        assert!(verifier.share().is_none());

        // Only a participant is a member, and a member reports its index but holds no share.
        let index = Participant::from_usize(member);
        let outsider = PrivateKey::random(&mut *context).public_key();
        let joins =
            |key| Scheme::<V>::member(NAMESPACE, committee.clone(), polynomial.clone(), key);
        assert_eq!(
            joins(&outsider).is_some(),
            committee.index(&outsider).is_some()
        );
        let joined = joins(&participants[member]).expect("a participant must be a member");
        assert_eq!(joined.me(), Some(Membership::Member(index)));
        assert!(joined.share().is_none());

        // A share signs only at the index it was dealt to.
        let mut share = signers[member]
            .share()
            .expect("a signer must hold a share")
            .clone();
        share.index = Participant::from_usize((member + 1) % signers.len());
        let moved = Scheme::<V>::signer(NAMESPACE, committee.clone(), polynomial.clone(), share);
        assert!(moved.is_none());

        let certificate_verifier = Scheme::<V>::certificate_verifier(NAMESPACE, identity);
        assert_eq!(certificate_verifier.me(), None);
        assert!(certificate_verifier.share().is_none());
        assert_eq!(certificate_verifier.identity(), &identity);

        assert!(Scheme::<V>::is_batchable());
        assert!(!Scheme::<V>::is_attributable());
        assert_eq!(Scheme::<V>::max_certificate_size(n), Certificate::<V>::SIZE);

        Self {
            signers,
            verifier,
            member: joined,
            certificate_verifier,
        }
    }

    fn role(&self, role: Role) -> &Scheme<V> {
        match role {
            Role::Signer => &self.signers[0],
            Role::Verifier => &self.verifier,
            Role::Member => &self.member,
        }
    }

    fn quorum(&self) -> usize {
        N3f1::quorum(self.signers.len()) as usize
    }

    /// Returns the signatures of the participant at `signer` over `subject`.
    fn sign(&self, signer: usize, subject: Subject<'_, Digest>) -> Signature<V> {
        let vote = self.signers[signer]
            .sign::<Digest>(subject)
            .expect("a signer must sign");
        let signature = vote.signature.get().expect("a signer's vote must decode");
        signature.clone()
    }

    /// Returns the signatures over `subject` that a quorum of consecutive participants
    /// starting at `first` recovers.
    fn certify(&self, first: usize, subject: Subject<'_, Digest>) -> Signature<V> {
        let votes: Vec<_> = (first..first + self.quorum())
            .map(|signer| {
                self.signers[signer % self.signers.len()]
                    .sign::<Digest>(subject)
                    .expect("a signer must sign")
            })
            .collect();
        let certificate = self
            .verifier
            .assemble(non_empty![@votes], &Sequential)
            .expect("a quorum of votes must assemble");
        let signature = certificate
            .get()
            .expect("an assembled certificate must decode");
        signature.clone()
    }

    /// Returns the vote `input` describes over the subject of `subjects`, as received from the
    /// network.
    fn vote(&self, subjects: &Subjects, input: &VoteInput) -> Vote<V> {
        let (mut signer, mut share, mut fault) = (input.signer, input.signer, None);
        match input.fault {
            Some(VoteFault::Signature(signature)) => fault = Some(signature),
            Some(VoteFault::Share) => share = (share + 1) % self.signers.len(),
            Some(VoteFault::Unknown) => signer += self.signers.len(),
            None => {}
        }
        let signature = sign_with(subjects, fault, |subject| self.sign(share, subject));
        let vote = Vote::<V> {
            signer: Participant::from_usize(signer),
            signature: signature.into(),
        };
        received::<V, _>(&vote, &(), matches!(fault, Some(Fault::Malformed)))
    }

    /// Returns the certificate `input` describes over the subject of `subjects`, as received
    /// from the network.
    fn certificate(&self, subjects: &Subjects, input: &CertificateInput) -> Certificate<V> {
        let first = usize::from(input.first) % self.signers.len();
        let signature = sign_with(subjects, input.fault, |subject| {
            self.certify(first, subject)
        });
        received::<V, _>(
            &Certificate::from(signature),
            &self.verifier.certificate_codec_config(),
            matches!(input.fault, Some(Fault::Malformed)),
        )
    }
}

fn check_votes<V: Variant>(
    context: &mut deterministic::Context,
    committee: &Committee<V>,
    subject: &SubjectInput,
    inputs: &[VoteInput],
    role: Role,
) {
    let subjects = Subjects::new(subject);
    let subject = subjects.subject();
    let scheme = committee.role(role);
    let votes: Vec<_> = inputs
        .iter()
        .map(|input| committee.vote(&subjects, input))
        .collect();
    let (verified, invalid) = partition(&votes, inputs);

    // A batch accepts exactly the votes that verify alone.
    for (vote, input) in zip_eq(&votes, inputs) {
        let valid = scheme.verify_attestation::<_, Digest>(context, subject, vote, &Sequential);
        assert_eq!(valid, input.fault.is_none(), "{input:?}");
    }
    let verification = scheme.verify_attestations::<_, Digest, _>(
        context,
        subject,
        votes.iter().cloned(),
        &Sequential,
    );
    assert_eq!(verification.verified, verified);
    assert_eq!(verification.invalid, invalid);

    // Assembly reports the first signature that does not decode, then the first signer outside
    // the committee, then a missing quorum. It verifies nothing else.
    let Some(attestations) = NonEmpty::try_new(votes.iter().cloned()) else {
        return;
    };
    let n = committee.signers.len();
    let quorum = committee.quorum();
    let malformed =
        |input: &&VoteInput| matches!(input.fault, Some(VoteFault::Signature(Fault::Malformed)));
    let unknown = |input: &&VoteInput| matches!(input.fault, Some(VoteFault::Unknown));
    let error = if let Some(input) = inputs.iter().find(malformed) {
        let signer = Participant::from_usize(input.signer);
        Some(AssemblyError::MalformedSignature(signer))
    } else if let Some(input) = inputs.iter().find(unknown) {
        let signer = Participant::from_usize(input.signer + n);
        Some(AssemblyError::UnknownSigner(signer))
    } else if inputs.len() < quorum {
        let (quorum, found) = (quorum as u32, inputs.len() as u32);
        Some(AssemblyError::InsufficientAttestations(quorum, found))
    } else {
        None
    };
    let assembled = scheme.assemble(attestations, &Sequential);
    let Some(error) = error else {
        let certificate = assembled.expect("a well-formed quorum must assemble");
        if invalid.is_empty() {
            assert!(scheme.verify_certificate::<_, Digest>(
                context,
                subject,
                &certificate,
                &Sequential
            ));
        }
        return;
    };
    assert_eq!(assembled, Err(error));
}

fn check_optimistic<V: Variant>(
    context: &mut deterministic::Context,
    committee: &Committee<V>,
    subject: &SubjectInput,
    inputs: &[VoteInput],
    pending: usize,
    role: Role,
) {
    let subjects = Subjects::new(subject);
    let subject = subjects.subject();
    let scheme = committee.role(role);
    let (pending_inputs, verified_inputs) = inputs.split_at(pending);
    let pending: Vec<_> = pending_inputs
        .iter()
        .map(|input| committee.vote(&subjects, input))
        .collect();
    let verified: Vec<_> = verified_inputs
        .iter()
        .map(|input| {
            let input = VoteInput {
                signer: input.signer,
                fault: None,
            };
            committee.vote(&subjects, &input)
        })
        .collect();
    let (accepted, rejected) = partition(&pending, pending_inputs);

    match scheme.optimistic_assemble::<_, Digest, _, _>(
        context,
        subject,
        pending.iter().cloned(),
        &verified,
        &Sequential,
    ) {
        // Assembly recovers from the lowest signers only, so a certificate may form despite a
        // faulty pending vote, but never without a quorum and never an invalid one.
        Ok(certificate) => {
            assert!(inputs.len() >= committee.quorum());
            assert!(scheme.verify_certificate::<_, Digest>(
                context,
                subject,
                &certificate,
                &Sequential
            ));
        }
        // Without a faulty pending vote, only a missing quorum prevents the certificate.
        Err(verification) => {
            assert!(!rejected.is_empty() || inputs.len() < committee.quorum());
            assert_eq!(verification.verified, accepted);
            let mut invalid = verification.invalid;
            invalid.sort_unstable();
            assert_eq!(invalid, rejected);
        }
    }
}

fn check_certificates<V: Variant>(
    context: &mut deterministic::Context,
    committee: &Committee<V>,
    inputs: &[CertificateInput],
    role: Role,
) {
    let subjects: Vec<_> = inputs
        .iter()
        .map(|input| Subjects::new(&input.subject))
        .collect();
    let certificates: Vec<_> = zip_eq(&subjects, inputs)
        .map(|(subjects, input)| committee.certificate(subjects, input))
        .collect();
    let pairs: Vec<_> = zip_eq(&subjects, &certificates)
        .map(|(subjects, certificate)| (subjects.subject(), certificate))
        .collect();
    let expected: Vec<_> = inputs.iter().map(|input| input.fault.is_none()).collect();

    // A certificate read back from storage is the one that was received.
    for certificate in &certificates {
        let cfg = &Scheme::<V>::certificate_codec_config_unbounded();
        assert_eq!(&received::<V, _>(certificate, cfg, false), certificate);
    }

    // A batch holds exactly when each of its certificates verifies alone, whether or not the
    // instance knows the committee.
    for scheme in [committee.role(role), &committee.certificate_verifier] {
        for ((subject, certificate), valid) in zip_eq(&pairs, &expected) {
            let verified =
                scheme.verify_certificate::<_, Digest>(context, *subject, certificate, &Sequential);
            assert_eq!(verified, *valid);
        }
        let bisected = scheme.verify_certificates_bisect::<_, Digest>(context, &pairs, &Sequential);
        assert_eq!(bisected, expected);
        let batch = non_empty![@pairs.iter().copied()];
        let verified = scheme.verify_certificates::<_, Digest, _>(context, batch, &Sequential);
        assert_eq!(verified, expected.iter().all(|valid| *valid));
    }
}

fn check_seed<V: Variant>(
    context: &mut deterministic::Context,
    committee: &Committee<V>,
    subject: &SubjectInput,
    target: Round,
    message: [u8; 32],
    forged: &[u8],
    role: Role,
) where
    V::Signature: for<'a> Arbitrary<'a>,
{
    let subjects = Subjects::new(subject);
    let proposal = &subjects.proposal;
    let round = proposal.round;
    let scheme = committee.role(role);

    // The seed of a round is the same whichever certificate carries it and whichever quorum
    // signed that certificate.
    let notarization = Notarization::<Scheme<V>, _> {
        proposal: proposal.clone(),
        certificate: committee.certify(0, Subject::Notarize { proposal }).into(),
    };
    let finalization = Finalization::<Scheme<V>, _> {
        proposal: proposal.clone(),
        certificate: committee.certify(1, Subject::Finalize { proposal }).into(),
    };
    let seed = notarization.seed();
    assert_eq!(seed, finalization.seed());
    assert_eq!(seed, Seed::new(round, seed.signature));
    assert_eq!(seed.round(), round);
    assert_eq!(seed.epoch(), round.epoch());
    assert_eq!(seed.view(), round.view());
    let encoded = seed.encode();
    assert_eq!(encoded.len(), seed.encode_size());
    assert_eq!(received::<V, _>(&seed, &(), false), seed);

    // A seed verifies for its own round only, and a forged one only if it is its round's seed.
    let stray = Seed::<V>::new(subjects.stray.round, seed.signature);
    let forged = Seed::<V>::arbitrary(&mut Unstructured::new(forged)).expect("bytes are padded");
    let forged_round = forged.round;
    let recovered = committee.certify(
        0,
        Subject::Nullify {
            round: forged_round,
        },
    );
    for scheme in [scheme, &committee.certificate_verifier] {
        assert!(seed.verify(scheme));
        assert!(!stray.verify(scheme));
        assert_eq!(
            forged.verify(scheme),
            forged.signature == recovered.seed_signature
        );
    }

    // The seed decrypts exactly the messages encrypted for its round.
    let expected = (target == round).then(|| tle::Block::new(message));
    let ciphertext = scheme
        .encrypt(context, target, message)
        .expect("the identity of a dealt committee must encrypt");
    assert_eq!(seed.decrypt(&ciphertext), expected);
    let ciphertext = vrf::encrypt::<_, V>(context, *scheme.identity(), NAMESPACE, target, message)
        .expect("the identity of a dealt committee must encrypt");
    assert_eq!(vrf::decrypt(&seed, &ciphertext), expected);
}

fn session<V: Variant>(
    context: &mut deterministic::Context,
    participants: u32,
    member: usize,
    cases: &[Case],
) where
    V::Signature: for<'a> Arbitrary<'a>,
{
    let committee = Committee::<V>::new(context, participants, member);
    for case in cases {
        match case {
            Case::Votes {
                subject,
                votes,
                role,
            } => check_votes(context, &committee, subject, votes, *role),
            Case::Optimistic {
                subject,
                votes,
                pending,
                role,
            } => check_optimistic(context, &committee, subject, votes, *pending, *role),
            Case::Certificates { certificates, role } => {
                check_certificates(context, &committee, certificates, *role)
            }
            Case::Seed {
                subject,
                target,
                message,
                forged,
                role,
            } => check_seed(
                context, &committee, subject, *target, *message, forged, *role,
            ),
        }
    }
}

fn fuzz(input: FuzzInput) {
    let FuzzInput {
        variant,
        participants,
        member,
        cases,
        entropy,
    } = input;
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(entropy));
    let runner = deterministic::Runner::new(cfg);
    runner.start(|mut context| async move {
        match variant {
            VariantKind::MinPk => session::<MinPk>(&mut context, participants, member, &cases),
            VariantKind::MinSig => session::<MinSig>(&mut context, participants, member, &cases),
        }
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
