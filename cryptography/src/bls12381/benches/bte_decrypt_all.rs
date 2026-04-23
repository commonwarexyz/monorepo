use commonware_cryptography::bls12381::primitives::group::{Scalar, G1};
use commonware_cryptography::bte::{
    dealer::Dealer,
    decryption::{aggregate_partial_decryptions, decrypt_all, SecretKey},
    encryption::encrypt,
    utils::Domain,
};
use commonware_math::algebra::{CryptoGroup, Random};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::{collections::BTreeMap, hint::black_box};

fn bench_bte_decrypt_all(c: &mut Criterion) {
    let n = 1 << 4;
    let t = n / 2 - 1;

    for size in 2..=10 {
        let batch_size = 1 << size;
        let mut rng = StdRng::seed_from_u64(0);
        let tx_domain = Domain::new(batch_size);

        let mut dealer = Dealer::new(batch_size, n, t, &mut rng);
        let (crs, pk, sk_shares) = dealer.setup(&mut rng);

        let hid = G1::generator() * &Scalar::random(&mut rng);

        let msgs: Vec<[u8; 32]> = (0..batch_size)
            .map(|i| {
                let mut m = [0u8; 32];
                m[0] = i as u8;
                m
            })
            .collect();

        let ct: Vec<_> = (0..batch_size)
            .map(|i| {
                let x = tx_domain.element(i);
                encrypt(msgs[i], x, hid, &pk, &mut rng)
            })
            .collect();

        let num_parties = n / 2;
        let mut partial_decryptions = BTreeMap::new();
        for i in 0..num_parties {
            let sk = SecretKey::new(sk_shares[i].clone());
            let pd = sk.partial_decrypt(&ct, hid, &crs);
            partial_decryptions.insert(i + 1, pd);
        }

        // Verify correctness once outside the benchmark
        let sigma = aggregate_partial_decryptions(&partial_decryptions);
        let decrypted = decrypt_all(sigma, &ct, &crs);
        for i in 0..batch_size {
            assert_eq!(decrypted[i].msg, msgs[i], "decryption mismatch at index {i}");
        }

        c.bench_function(
            &format!("{}/batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    let sigma = aggregate_partial_decryptions(&partial_decryptions);
                    black_box(decrypt_all(sigma, &ct, &crs));
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_bte_decrypt_all
}
