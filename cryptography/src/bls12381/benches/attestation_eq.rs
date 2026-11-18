use super::utils::optimistic_assemble::BenchSubject;
use bytes::Bytes;
use commonware_codec::{Encode as _, types::lazy::Lazy};
use commonware_cryptography::{
    bls12381::primitives::{group::Private, ops::sign_message, variant::MinPk},
    certificate::Attestation,
    ed25519, impl_certificate_bls12381_multisig,
};
use commonware_math::algebra::Random;
use commonware_utils::{N3f1, Participant, test_rng};
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

impl_certificate_bls12381_multisig!(BenchSubject, Vec<u8>, N3f1);

type Multisig = Scheme<ed25519::PublicKey, MinPk>;

fn attestation(encoded: &Bytes) -> Attestation<Multisig> {
    Attestation {
        signer: Participant::new(0),
        signature: Lazy::deferred(&mut encoded.clone(), ()),
    }
}

fn bench_attestation_eq(c: &mut Criterion) {
    let private = Private::random(test_rng());
    let stored = sign_message::<MinPk>(&private, b"namespace", b"stored").encode();
    let other = sign_message::<MinPk>(&private, b"namespace", b"other").encode();
    for (bytes, received) in [("equal", &stored), ("different", &other)] {
        c.bench_function(&format!("{}/bytes={bytes}", module_path!()), |b| {
            // The stored signature was decoded when it was verified.
            let previous = attestation(&stored);
            previous.signature.get().unwrap();
            b.iter_batched(
                || attestation(received),
                |incoming| {
                    black_box(previous == incoming);
                    incoming
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, bench_attestation_eq);
