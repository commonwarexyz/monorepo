use commonware_codec::{Encode as _, types::lazy::Lazy};
use commonware_cryptography::{Signer as _, bls12381};
use commonware_math::algebra::Random;
use commonware_utils::test_rng;
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

fn bench_lazy_signature_eq(c: &mut Criterion) {
    let mut rng = test_rng();
    let private_key = bls12381::PrivateKey::random(&mut rng);
    let stored = private_key.sign(b"namespace", b"stored").encode();
    let other = private_key.sign(b"namespace", b"other").encode();
    for (bytes, received) in [("equal", &stored), ("different", &other)] {
        c.bench_function(&format!("{}/bytes={bytes}", module_path!()), |b| {
            // The stored signature was decoded when it was verified.
            let previous = Lazy::<bls12381::Signature>::deferred(&mut stored.clone(), ());
            previous.get().unwrap();
            b.iter_batched(
                || Lazy::<bls12381::Signature>::deferred(&mut received.clone(), ()),
                |incoming| {
                    black_box(previous == incoming);
                    incoming
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(benches, bench_lazy_signature_eq);
