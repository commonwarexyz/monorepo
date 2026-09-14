use commonware_clearing::bajillion::{
    admission::{Committee, Vote, bls12381},
    transition::Header,
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::{
        group::{Private, Scalar},
        ops::compute_public,
        variant::MinSig,
    },
    sha256::Digest,
};
use commonware_runtime::Runner as _;
use commonware_utils::Participant;

pub(crate) const VALIDATORS: usize = 100;
pub(crate) const FAULTS: usize = 33;
pub(crate) const QUORUM: usize = 67;
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
}
pub(crate) struct CertificateFixture {
    pub(crate) header: Header<Digest>,
    pub(crate) assembler: bls12381::Scheme,
    pub(crate) verifier: bls12381::Scheme,
    pub(crate) attestations: Vec<Vote>,
    pub(crate) certificate: bls12381::Certificate,
}

pub(crate) fn certificate_fixture() -> CertificateFixture {
    super::fixtures::runner().start(|runtime| async move {
        let validators = Validators::new();
        let profile = super::fixtures::selected_active_profiles()[0].1;
        let fixture = super::fixtures::active_close_fixture_with_committee(
            runtime,
            profile,
            validators.committee().commitment::<Sha256>(),
        )
        .await;
        let header = fixture.prepared.close().header;
        let attestations = validators.attestations(&header);
        let assembler = validators.signer(Participant::new(0));
        let certificate = assembler
            .assemble_exact(attestations.clone())
            .expect("exact certificate");
        let verifier = bls12381::Scheme::verifier(validators.committee().clone());
        CertificateFixture {
            header,
            assembler,
            verifier,
            attestations,
            certificate,
        }
    })
}
