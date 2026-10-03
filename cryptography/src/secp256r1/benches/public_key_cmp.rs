use commonware_cryptography::{PrivateKey, secp256r1};
use criterion::{BatchSize, Criterion, criterion_group};
use std::hint::black_box;

fn bench_public_key_cmp<S: PrivateKey>(variant: &str, c: &mut Criterion) {
    for n in [10, 100, 1_000, 10_000] {
        let keys: Vec<_> = (0..n).map(|i| S::from_seed(i).public_key()).collect();
        c.bench_function(
            &format!("{}/variant={variant} op=sort n={n}", module_path!()),
            |b| {
                b.iter_batched(
                    || keys.clone(),
                    |mut keys| {
                        keys.sort_unstable();
                        keys
                    },
                    BatchSize::LargeInput,
                );
            },
        );
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        c.bench_function(
            &format!("{}/variant={variant} op=search n={n}", module_path!()),
            |b| {
                b.iter(|| {
                    for key in &keys {
                        black_box(sorted.binary_search(black_box(key)).is_ok());
                    }
                });
            },
        );
    }
}

fn bench_standard_public_key_cmp(c: &mut Criterion) {
    bench_public_key_cmp::<secp256r1::standard::PrivateKey>("standard", c);
}

fn bench_recoverable_public_key_cmp(c: &mut Criterion) {
    bench_public_key_cmp::<secp256r1::recoverable::PrivateKey>("recoverable", c);
}

criterion_group!(
    benches,
    bench_standard_public_key_cmp,
    bench_recoverable_public_key_cmp
);
