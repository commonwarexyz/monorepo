use super::fixtures::{
    ActiveProfile, CloseFixture, active_close_fixture_with_assignment, selected_active_profiles,
    strategy,
};
use commonware_clearing::bajillion::{
    admission::{Committee, Vote, bls12381},
    transition::{Assignment, Header, ProofSlice, validate_close},
};
use commonware_codec::{Encode as _, EncodeSize};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops::compute_public,
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_cryptography_curve25519::signing::{
    BatchVerifier as PaymentBatchVerifier, StrictVerifyingKey as VerifyingKey,
};
use commonware_utils::{Participant, TestRng};

pub(crate) const VALIDATORS: usize = 100;
pub(crate) const FAULTS: usize = 33;
pub(crate) const QUORUM: usize = 67;
pub(crate) const SLICE_BITS: u8 = 8;
pub(crate) const SLICES: usize = 1 << SLICE_BITS;

const VALIDATOR_SEED_START: u64 = 1_000_000;

pub(crate) struct Validators {
    committee: Committee,
    keys: Vec<Private>,
}

impl Validators {
    pub(crate) fn new() -> Self {
        let mut validators = (0..VALIDATORS)
            .map(|index| {
                let index = u64::try_from(index).expect("validator index fits in u64");
                let signing = Private::new(Scalar::from(VALIDATOR_SEED_START + index + 1));
                (compute_public::<MinSig>(&signing), signing)
            })
            .collect::<Vec<_>>();
        validators.sort_unstable_by_key(|validator| validator.0);
        let committee = Committee::new(validators.iter().map(|(public, _)| *public).collect())
            .expect("benchmark committee is canonical");
        assert_eq!(committee.faults(), FAULTS);
        assert_eq!(committee.quorum(), QUORUM);
        Self {
            committee,
            keys: validators.into_iter().map(|(_, private)| private).collect(),
        }
    }

    pub(crate) const fn committee(&self) -> &Committee {
        &self.committee
    }

    pub(crate) fn assignment(&self) -> Assignment<Digest> {
        Assignment::new(self.committee.commitment::<Sha256>(), SLICE_BITS)
            .expect("benchmark assignment is valid")
    }

    pub(crate) fn signer(&self, validator: Participant) -> bls12381::Scheme {
        bls12381::Scheme::signer(
            self.committee.clone(),
            self.keys[usize::from(validator)].clone(),
        )
        .expect("benchmark validator belongs to the committee")
    }

    pub(crate) fn attestations(&self, header: &Header<Digest>) -> Vec<Vote> {
        (0..QUORUM)
            .map(|index| {
                self.signer(Participant::from_usize(index))
                    .sign(header)
                    .expect("benchmark validator can sign")
            })
            .collect()
    }

    pub(crate) fn largest_assignment(
        &self,
        assignment: &Assignment<Digest>,
        all_slices: &[ProofSlice<VerifyingKey, Digest>],
    ) -> (Participant, Vec<u16>, usize) {
        let encoded_size = |indices: &[u16]| {
            indices.len().encode_size()
                + indices
                    .iter()
                    .map(|index| all_slices[usize::from(*index)].encode_size())
                    .sum::<usize>()
        };
        let mut validator = Participant::new(0);
        let mut slices = commonware_clearing::bajillion::admission::assigned_slice_indices::<
            Sha256,
            _,
        >(&self.committee, assignment, validator)
        .expect("benchmark assignment matches the committee");
        let mut bytes = encoded_size(&slices);
        for index in 1..VALIDATORS {
            let candidate = Participant::from_usize(index);
            let candidate_slices =
                commonware_clearing::bajillion::admission::assigned_slice_indices::<Sha256, _>(
                    &self.committee,
                    assignment,
                    candidate,
                )
                .expect("benchmark assignment matches the committee");
            let candidate_bytes = encoded_size(&candidate_slices);
            if candidate_bytes > bytes {
                validator = candidate;
                slices = candidate_slices;
                bytes = candidate_bytes;
            }
        }
        let assigned = slices
            .iter()
            .map(|index| all_slices[usize::from(*index)].clone())
            .collect::<Vec<_>>();
        let encoded = assigned.encode();
        assert_eq!(assigned.encode_size(), encoded.len());
        assert_eq!(bytes, encoded.len());
        (validator, slices, encoded.len())
    }
}

pub(crate) struct CertificateFixture {
    pub(crate) header: Header<Digest>,
    pub(crate) assembler: bls12381::Scheme,
    pub(crate) verifier: bls12381::Scheme,
    pub(crate) attestations: Vec<Vote>,
    pub(crate) certificate: bls12381::Certificate,
}

pub(crate) struct ValidatorFixture {
    pub(crate) validators: Validators,
    pub(crate) close: CloseFixture,
    pub(crate) validator: Participant,
    pub(crate) slices: Vec<ProofSlice<VerifyingKey, Digest>>,
    pub(crate) public_corpus_bytes: usize,
    pub(crate) slice_corpus_bytes: usize,
    pub(crate) assignment_bytes: usize,
}

pub(crate) fn validator_fixture(profile: ActiveProfile) -> ValidatorFixture {
    let validators = Validators::new();
    let assignment = validators.assignment();
    let close = active_close_fixture_with_assignment(profile, assignment);
    validate_close::<Sha256, _, _, PaymentBatchVerifier, _>(
        &close.context,
        &close.deposits,
        &close.withdrawals,
        close.prepared.close(),
        &mut TestRng::new(0),
    )
    .expect("benchmark close is publicly valid");
    let all_slices = close
        .prepared
        .assemble_slices(&close.cache, strategy())
        .expect("benchmark slices are valid");
    assert_eq!(all_slices.len(), SLICES);
    let public_corpus_bytes = close.prepared.close().encode_size();
    let slice_corpus_bytes = all_slices.iter().map(EncodeSize::encode_size).sum();
    let (validator, indices, assignment_bytes) =
        validators.largest_assignment(close.context.assignment(), &all_slices);
    let slices = indices
        .iter()
        .map(|index| all_slices[usize::from(*index)].clone())
        .collect::<Vec<_>>();
    ValidatorFixture {
        validators,
        close,
        validator,
        slices,
        public_corpus_bytes,
        slice_corpus_bytes,
        assignment_bytes,
    }
}

pub(crate) fn certificate_fixture() -> CertificateFixture {
    let validators = Validators::new();
    let assignment = validators.assignment();
    let profile = selected_active_profiles()
        .first()
        .map(|(_, profile)| *profile)
        .expect("at least one active benchmark profile exists");
    let fixture = active_close_fixture_with_assignment(profile, assignment);
    let header = fixture.prepared.close().header;
    let attestations = validators.attestations(&header);
    assert_eq!(attestations.len(), QUORUM);
    let assembler = validators.signer(Participant::new(0));
    let certificate = assembler
        .assemble_exact(attestations.clone())
        .expect("benchmark attestations form an exact certificate");
    let verifier = bls12381::Scheme::verifier(validators.committee().clone());
    CertificateFixture {
        header,
        assembler,
        verifier,
        attestations,
        certificate,
    }
}
