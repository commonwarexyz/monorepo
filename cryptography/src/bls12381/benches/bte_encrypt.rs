use commonware_cryptography::bls12381::primitives::group::{Scalar, G1};
use commonware_cryptography::bte::{dealer::Dealer, encryption::encrypt, utils::Domain};
use commonware_math::algebra::{CryptoGroup, Random};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

fn bench_bte_encrypt(c: &mut Criterion) {
    let n = 1 << 4;
    let t = n / 2 - 1;

    for size in 2..=5 {
        let batch_size = 1 << size;
        let mut rng = StdRng::seed_from_u64(0);
        let tx_domain = Domain::new(batch_size);

        let mut dealer = Dealer::new(batch_size, n, t, &mut rng);
        let (_, pk, _) = dealer.setup(&mut rng);

        let msg = [1u8; 32];
        let x = tx_domain.group_gen();
        let hid = G1::generator() * &Scalar::random(&mut rng);

        c.bench_function(
            &format!("{}/batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(encrypt(msg, x.clone(), hid, &pk, &mut rng));
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_bte_encrypt
}
