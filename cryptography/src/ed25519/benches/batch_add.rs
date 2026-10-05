use commonware_cryptography::{BatchVerifier, Signer as _, ed25519};
use commonware_math::algebra::Random;
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, TestRng, test_rng};
use criterion::{BatchSize, Criterion, criterion_group};
use rand::RngExt as _;
use std::hint::black_box;

const NAMESPACE: &[u8] = b"constantinople-tx";

/// Signs `n` random `msg_len`-byte messages, each with a distinct signer.
fn signed(
    rng: &mut TestRng,
    n: usize,
    msg_len: usize,
) -> Vec<(ed25519::PublicKey, Vec<u8>, ed25519::Signature)> {
    (0..n)
        .map(|_| {
            let signer = ed25519::PrivateKey::random(&mut *rng);
            let mut msg = vec![0u8; msg_len];
            rng.fill(&mut msg[..]);
            let sig = signer.sign(NAMESPACE, &msg);
            (signer.public_key(), msg, sig)
        })
        .collect()
}

fn queue(items: &[(ed25519::PublicKey, Vec<u8>, ed25519::Signature)]) -> ed25519::Batch {
    let mut batch = ed25519::Batch::new(items.len());
    for (public_key, msg, sig) in items {
        assert!(batch.add(NAMESPACE, msg, public_key, sig));
    }
    batch
}

fn bench_batch_add(c: &mut Criterion) {
    let mut rng = test_rng();
    let mut verify_rng = TestRng::new(1);
    let rayon = Rayon::new(NZUsize!(8)).unwrap();
    for n in [10_000, 100_000] {
        let items = signed(&mut rng, n, 32);
        c.bench_function(&format!("{}/op=add sigs={n}", module_path!()), |b| {
            b.iter_batched(
                || (),
                |()| drop(black_box(queue(&items))),
                BatchSize::SmallInput,
            );
        });
        c.bench_function(
            &format!("{}/op=add_verify sigs={n} conc=8", module_path!()),
            |b| {
                b.iter_batched(
                    || (),
                    |()| black_box(queue(&items).verify(&mut verify_rng, &rayon)),
                    BatchSize::SmallInput,
                );
            },
        );
    }

    // Messages too long to frame inline.
    let items = signed(&mut rng, 10_000, 96);
    c.bench_function(
        &format!("{}/op=add sigs=10000 msg=96", module_path!()),
        |b| {
            b.iter_batched(
                || (),
                |()| drop(black_box(queue(&items))),
                BatchSize::SmallInput,
            );
        },
    );

    // Small batches, as when verifying a certificate.
    for n in [10, 100] {
        let items = signed(&mut rng, n, 32);
        c.bench_function(
            &format!("{}/op=add_verify sigs={n} conc=1", module_path!()),
            |b| {
                b.iter_batched(
                    || (),
                    |()| black_box(queue(&items).verify(&mut verify_rng, &Sequential)),
                    BatchSize::SmallInput,
                );
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_batch_add
}
