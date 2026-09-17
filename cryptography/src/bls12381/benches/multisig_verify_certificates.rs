use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        certificate::multisig::Certificate,
        primitives::{
            group::Private,
            ops,
            variant::{MinPk, MinSig, Variant},
        },
    },
    certificate::{Scheme as _, Verifier as _},
    ed25519, impl_certificate_bls12381_multisig,
    sha256::Digest,
};
use commonware_math::algebra::Random;
use commonware_parallel::Sequential;
use commonware_utils::{Faults, N3f1, TestRng, TryCollect, non_empty, ordered::BiMap, test_rng};
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

#[derive(Clone, Debug)]
pub struct Subject(Bytes);

impl commonware_cryptography::certificate::Subject for Subject {
    type Namespace = Vec<u8>;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        derived
    }

    fn message(&self) -> Bytes {
        self.0.clone()
    }
}

impl_certificate_bls12381_multisig!(Subject, Vec<u8>, N3f1);

fn bench_variant<V: Variant>(c: &mut Criterion, variant: &str) {
    let namespace = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_MULTISIG_CERTIFICATES_BENCH";
    let mut rng = test_rng();
    let mut verify_rng = TestRng::new(1);
    for participants in [4, 32, 128] {
        let private_keys: Vec<_> = (0..participants)
            .map(|_| Private::random(&mut rng))
            .collect();
        let keys: BiMap<_, _> = private_keys
            .iter()
            .map(|private| {
                let public = ops::compute_public::<V>(private);
                let pop = ops::sign_proof_of_possession::<V>(private, namespace);
                ops::verify_proof_of_possession::<V>(&public, namespace, &pop).unwrap();
                (ed25519::PrivateKey::random(&mut rng).public_key(), public)
            })
            .try_collect()
            .unwrap();
        let schemes: Vec<_> = private_keys
            .into_iter()
            .map(|private| Scheme::signer(namespace, keys.clone(), private).unwrap())
            .collect();
        let verifier = Scheme::verifier(namespace, keys);
        let quorum = N3f1::quorum(participants) as usize;

        for count in [1, 2, 8, 32] {
            let subjects: Vec<_> = (0..count)
                .map(|i| Subject(Bytes::from(vec![i as u8; 32])))
                .collect();
            let encoded: Vec<_> = subjects
                .iter()
                .enumerate()
                .map(|(i, subject)| {
                    let attestations = schemes
                        .iter()
                        .cycle()
                        .skip(i % schemes.len())
                        .take(quorum)
                        .map(|s| s.sign::<Digest>(subject.clone()).unwrap());
                    verifier
                        .assemble(non_empty![@attestations], &Sequential)
                        .unwrap()
                        .encode()
                })
                .collect();

            for invalid in ["none", "first", "last"] {
                let mut subjects = subjects.clone();
                if invalid != "none" {
                    let index = if invalid == "first" { 0 } else { count - 1 };
                    // Keep the signature well-formed so rejection requires cryptographic work.
                    subjects[index] = Subject(Bytes::from(vec![255; 32]));
                }
                for mode in ["loop", "batch"] {
                    let name = format!(
                        "{}/v={variant} pks={participants} certs={count} bad={invalid} mode={mode}",
                        module_path!(),
                    );
                    c.bench_function(&name, |b| {
                        // Recreate lazy signatures so verification includes group validation.
                        b.iter_batched(
                            || {
                                encoded
                                    .iter()
                                    .map(|bytes| {
                                        Certificate::<V>::decode_cfg(
                                            bytes.clone(),
                                            &(participants as usize),
                                        )
                                        .unwrap()
                                    })
                                    .collect::<Vec<_>>()
                            },
                            |certificates| {
                                let mut entries = subjects.iter().cloned().zip(&certificates);
                                let valid = if mode == "batch" {
                                    verifier.verify_certificates::<_, Digest, _>(
                                        &mut verify_rng,
                                        non_empty![@entries],
                                        &Sequential,
                                    )
                                } else {
                                    entries.all(|(subject, cert)| {
                                        verifier.verify_certificate::<_, Digest>(
                                            &mut verify_rng,
                                            subject,
                                            cert,
                                            &Sequential,
                                        )
                                    })
                                };
                                assert_eq!(black_box(valid), invalid == "none");
                            },
                            BatchSize::SmallInput,
                        );
                    });
                }
            }
        }
    }
}

fn bench_multisig_verify_certificates(c: &mut Criterion) {
    bench_variant::<MinPk>(c, "min_pk");
    bench_variant::<MinSig>(c, "min_sig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_multisig_verify_certificates
}
