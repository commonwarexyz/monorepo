use bytes::Bytes;
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::{
        group::Private,
        ops::{compute_public, sign_proof_of_possession, verify_proof_of_possession},
        variant::{MinPk, MinSig, Variant},
    },
    certificate::{Attestation, Scheme as _, Subject, Verifier as _},
    ed25519, impl_certificate_bls12381_multisig,
    sha256::Digest as Sha256Digest,
};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use commonware_utils::{Faults, N3f1, TestRng, TryCollect, non_empty, ordered::BiMap};
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_MULTISIG_OPTIMISTIC_ASSEMBLE";
const POP_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_MULTISIG_OPTIMISTIC_ASSEMBLE_POP";
const MESSAGE: &[u8] = b"hello";

#[derive(Clone, Debug)]
pub struct BenchSubject;

impl Subject for BenchSubject {
    type Namespace = Vec<u8>;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        derived
    }

    fn message(&self) -> Bytes {
        Bytes::from_static(MESSAGE)
    }
}

impl_certificate_bls12381_multisig!(BenchSubject, Vec<u8>, N3f1);

type Multisig<V> = Scheme<ed25519::PublicKey, V>;

fn setup<V: Variant>(n: u32) -> (Multisig<V>, Vec<Attestation<Multisig<V>>>) {
    let identity_keys: Vec<_> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(u64::from(i)))
        .collect();
    let mut rng = TestRng::new(u64::from(n));
    let signing_keys: Vec<_> = (0..n).map(|_| Private::random(&mut rng)).collect();
    let signing_publics: Vec<_> = signing_keys.iter().map(compute_public::<V>).collect();

    for (private, public) in signing_keys.iter().zip(&signing_publics) {
        let proof = sign_proof_of_possession::<V>(private, POP_NAMESPACE);
        verify_proof_of_possession::<V>(public, POP_NAMESPACE, &proof)
            .expect("proof of possession must verify");
    }

    let participants: BiMap<_, _> = identity_keys
        .iter()
        .map(|key| key.public_key())
        .zip(signing_publics)
        .try_collect()
        .unwrap();
    let quorum = N3f1::quorum(n) as usize;
    let attestations = signing_keys
        .into_iter()
        .take(quorum)
        .map(|private| {
            Scheme::signer(NAMESPACE, participants.clone(), private)
                .expect("signer must be a participant")
                .sign::<Sha256Digest>(BenchSubject)
                .unwrap()
        })
        .collect();

    (Scheme::verifier(NAMESPACE, participants), attestations)
}

fn bench_variant<V: Variant>(c: &mut Criterion, variant: &str) {
    for (n, quorum) in [(100, 67), (298, 199)] {
        assert_eq!(N3f1::quorum(n), quorum);
        let (scheme, attestations) = setup::<V>(n);
        let mut check_rng = TestRng::new(0);
        let certificate = scheme
            .optimistic_assemble::<_, Sha256Digest, _, _>(
                &mut check_rng,
                BenchSubject,
                attestations.clone(),
                std::iter::empty(),
                &Sequential,
            )
            .ok()
            .expect("valid quorum must certify");
        assert!(scheme.verify_certificate::<_, Sha256Digest>(
            &mut check_rng,
            BenchSubject,
            &certificate,
            &Sequential,
        ));

        let mut optimistic_rng = TestRng::new(1);
        c.bench_function(
            &format!(
                "{}/path=optimistic variant={} n={} quorum={}",
                module_path!(),
                variant,
                n,
                quorum,
            ),
            |b| {
                b.iter_batched(
                    || attestations.clone(),
                    |pending| {
                        let certificate = scheme
                            .optimistic_assemble::<_, Sha256Digest, _, _>(
                                &mut optimistic_rng,
                                BenchSubject,
                                pending,
                                std::iter::empty(),
                                &Sequential,
                            )
                            .ok()
                            .expect("valid quorum must certify");
                        black_box(certificate);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        let mut baseline_rng = TestRng::new(1);
        c.bench_function(
            &format!(
                "{}/path=baseline variant={} n={} quorum={}",
                module_path!(),
                variant,
                n,
                quorum,
            ),
            |b| {
                b.iter_batched(
                    || attestations.clone(),
                    |pending| {
                        let verification = scheme.verify_attestations::<_, Sha256Digest, _>(
                            &mut baseline_rng,
                            BenchSubject,
                            pending,
                            &Sequential,
                        );
                        let certificate = scheme
                            .assemble(non_empty![@verification.verified], &Sequential)
                            .expect("verified quorum must assemble");
                        black_box(certificate);
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

fn bench_multisig_optimistic_assemble(c: &mut Criterion) {
    bench_variant::<MinPk>(c, "MinPk");
    bench_variant::<MinSig>(c, "MinSig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_multisig_optimistic_assemble,
}
