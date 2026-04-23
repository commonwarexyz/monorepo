use commonware_cryptography::bls12381::primitives::group::{Scalar, G1};
use commonware_cryptography::bte::{
    dealer::Dealer,
    decryption::SecretKey,
    encryption::encrypt,
    utils::Domain,
};
use commonware_math::algebra::{CryptoGroup, Random};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::hint::black_box;

fn bench_bte_partial_decrypt(c: &mut Criterion) {
    let n = 1 << 4;
    let t = n / 2 - 1;

    for size in 2..=10 {
        let batch_size = 1 << size;
        let mut rng = StdRng::seed_from_u64(0);
        let tx_domain = Domain::new(batch_size);

        let mut dealer = Dealer::new(batch_size, n, t, &mut rng);
        let (crs, pk, sk_shares) = dealer.setup(&mut rng);

        let hid = G1::generator() * &Scalar::random(&mut rng);

        let ct: Vec<_> = (0..batch_size)
            .map(|i| {
                let msg = [i as u8; 32];
                let x = tx_domain.element(i);
                encrypt(msg, x, hid, &pk, &mut rng)
            })
            .collect();

        let secret_key = SecretKey::new(sk_shares[0].clone());

        c.bench_function(
            &format!("{}/batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(secret_key.partial_decrypt(&ct, hid, &crs));
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_bte_partial_decrypt
}
