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
use std::ops::Range;

pub(crate) const VALIDATORS: usize = 100;
pub(crate) const FAULTS: usize = 33;
pub(crate) const QUORUM: usize = 67;
pub(crate) const SLICE_BITS: u8 = 8;
pub(crate) const SLICES: usize = 1 << SLICE_BITS;

const VALIDATOR_SEED_START: u64 = 1_000_000;

/// One validator, its dealing, and the dealing's encoded size.
pub(crate) type Largest = (Participant, Vec<ProofSlice<VerifyingKey, Digest>>, usize);

/// Every slice as its own span: the per-interval corpus the size accounting reports.
pub(crate) fn single_spans() -> Vec<Range<u16>> {
    (0..SLICES as u16).map(|slice| slice..slice + 1).collect()
}

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

    /// Each validator's assigned spans, in committee order.
    pub(crate) fn spans(&self, assignment: &Assignment<Digest>) -> Vec<Vec<Range<u16>>> {
        (0..VALIDATORS)
            .map(|index| {
                commonware_clearing::bajillion::admission::assigned_slice_spans::<Sha256, _>(
                    &self.committee,
                    assignment,
                    Participant::from_usize(index),
                )
                .expect("benchmark assignment matches the committee")
            })
            .collect()
    }

    /// The distinct spans dealt across the committee: what the operator assembles once.
    pub(crate) fn distinct_spans(&self, assignment: &Assignment<Digest>) -> Vec<Range<u16>> {
        commonware_clearing::bajillion::admission::committee_spans::<Sha256, _>(
            &self.committee,
            assignment,
        )
        .expect("benchmark assignment matches the committee")
    }

    /// Deals every validator and returns the one whose full dealing encodes largest.
    pub(crate) fn largest_assignment(&self, close: &CloseFixture) -> Largest {
        let mut largest: Option<Largest> = None;
        for (index, spans) in self
            .spans(close.context.assignment())
            .into_iter()
            .enumerate()
        {
            let dealing = close
                .prepared
                .assemble_slices(&close.cache, &spans, strategy())
                .expect("benchmark dealing is valid");
            let bytes = dealing.encode_size();
            if largest.as_ref().is_none_or(|(_, _, best)| bytes > *best) {
                largest = Some((Participant::from_usize(index), dealing, bytes));
            }
        }
        let (validator, dealing, bytes) = largest.expect("committee is nonempty");
        assert_eq!(dealing.encode().len(), bytes);
        (validator, dealing, bytes)
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
        &close.operator_bls,
        &close.deposits,
        &close.withdrawals,
        close.prepared.close(),
        &mut TestRng::new(0),
    )
    .expect("benchmark close is publicly valid");
    let all_slices = close
        .prepared
        .assemble_slices(&close.cache, &single_spans(), strategy())
        .expect("benchmark slices are valid");
    assert_eq!(all_slices.len(), SLICES);
    let public_corpus_bytes = close.prepared.close().encoded_size();
    let slice_corpus_bytes = all_slices.iter().map(EncodeSize::encode_size).sum();
    drop(all_slices);
    let (validator, slices, assignment_bytes) = validators.largest_assignment(&close);
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
