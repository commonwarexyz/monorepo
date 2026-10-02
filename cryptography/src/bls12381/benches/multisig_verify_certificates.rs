use bytes::Bytes;
use commonware_cryptography::{
    Signer as _,
    bls12381::primitives::{
        group::Private,
        ops::{compute_public, sign_proof_of_possession, verify_proof_of_possession},
        variant::{MinPk, MinSig, Variant},
    },
    certificate::{Scheme as _, Subject, Verifier as _},
    ed25519, impl_certificate_bls12381_multisig,
    sha256::Digest,
};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use commonware_utils::{Faults, N3f1, TestRng, TryCollect, non_empty, ordered::BiMap};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_MULTISIG_VERIFY_CERTIFICATES";
const POP_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_MULTISIG_VERIFY_CERTIFICATES_POP";

#[derive(Clone, Debug)]
pub struct BenchSubject(Bytes);

impl Subject for BenchSubject {
    type Namespace = Vec<u8>;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        derived
    }

    fn message(&self) -> Bytes {
        self.0.clone()
    }
}

impl_certificate_bls12381_multisig!(BenchSubject, Vec<u8>, N3f1);

fn bench_variant<V: Variant>(c: &mut Criterion, variant: &str) {
    for n in [4, 100] {
        let mut rng = TestRng::new(n);
        let keys: Vec<_> = (0..n).map(|_| Private::random(&mut rng)).collect();
        let participants: BiMap<_, _> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                let public = compute_public::<V>(key);
                let proof = sign_proof_of_possession::<V>(key, POP_NAMESPACE);
                verify_proof_of_possession::<V>(&public, POP_NAMESPACE, &proof).unwrap();
                (
                    ed25519::PrivateKey::from_seed(i as u64).public_key(),
                    public,
                )
            })
            .try_collect()
            .unwrap();
        let schemes: Vec<Scheme<ed25519::PublicKey, V>> = keys
            .into_iter()
            .map(|key| Scheme::signer(NAMESPACE, participants.clone(), key).unwrap())
            .collect();
        let verifier = Scheme::<_, V>::verifier(NAMESPACE, participants);
        let subjects: Vec<_> = (0u64..32)
            .map(|i| BenchSubject(Bytes::copy_from_slice(&i.to_le_bytes())))
            .collect();
        let certificates: Vec<_> = subjects
            .iter()
            .enumerate()
            .map(|(i, subject)| {
                let attestations = schemes
                    .iter()
                    .cycle()
                    .skip(i)
                    .take(N3f1::quorum(n as u32) as usize)
                    .map(|scheme| scheme.sign::<Digest>(subject.clone()).unwrap());
                schemes[0]
                    .assemble(non_empty![@attestations], &Sequential)
                    .unwrap()
            })
            .collect();

        for count in [1, 2, 4, 8, 32] {
            for mode in ["individual", "batch"] {
                c.bench_function(
                    &format!(
                        "{}/variant={variant} n={n} certs={count} mode={mode}",
                        module_path!()
                    ),
                    |b| {
                        b.iter(|| {
                            let mut entries =
                                subjects.iter().cloned().zip(&certificates).take(count);
                            black_box(if mode == "batch" {
                                verifier.verify_certificates::<_, Digest, _>(
                                    &mut rng,
                                    non_empty![@entries],
                                    &Sequential,
                                )
                            } else {
                                entries.all(|(subject, certificate)| {
                                    verifier.verify_certificate::<_, Digest>(
                                        &mut rng,
                                        subject,
                                        certificate,
                                        &Sequential,
                                    )
                                })
                            })
                        })
                    },
                );
            }
        }
    }
}

fn bench_multisig_verify_certificates(c: &mut Criterion) {
    bench_variant::<MinPk>(c, "MinPk");
    bench_variant::<MinSig>(c, "MinSig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_multisig_verify_certificates,
}
