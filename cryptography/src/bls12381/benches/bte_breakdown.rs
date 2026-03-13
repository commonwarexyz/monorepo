use commonware_cryptography::bls12381::primitives::group::{Scalar, G1, G2, GT};
use commonware_cryptography::bte::{
    dealer::Dealer,
    decryption::{aggregate_partial_decryptions, batch_verify, decrypt_all, SecretKey},
    encryption::encrypt,
    utils::{open_all_values, Domain},
};
use commonware_math::algebra::{CryptoGroup, Random, Space};
use commonware_parallel::Sequential;
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, SeedableRng};
use std::{collections::BTreeMap, hint::black_box};

fn bench_bte_breakdown(c: &mut Criterion) {
    let n = 1 << 4;
    let t = n / 2 - 1;

    for size in [6, 8, 10] {
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
            .map(|i| encrypt(msgs[i], tx_domain.element(i), hid, &pk, &mut rng))
            .collect();

        let fevals: Vec<Scalar> = (0..batch_size)
            .map(|_| Scalar::random(&mut rng))
            .collect();

        let fcoeffs = tx_domain.ifft(&fevals);

        let g1_points: Vec<G1> = (0..batch_size)
            .map(|_| G1::generator() * &Scalar::random(&mut rng))
            .collect();

        let scalars: Vec<Scalar> = (0..batch_size)
            .map(|_| Scalar::random(&mut rng))
            .collect();

        // --- 1. Scalar IFFT ---
        c.bench_function(
            &format!("{}/op=scalar_ifft batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(tx_domain.ifft(&fevals));
                });
            },
        );

        // --- 2. Scalar FFT ---
        c.bench_function(
            &format!("{}/op=scalar_fft batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(tx_domain.fft(&fcoeffs));
                });
            },
        );

        // --- 3. G1 FFT ---
        c.bench_function(
            &format!("{}/op=g1_fft batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(tx_domain.fft(&g1_points));
                });
            },
        );

        // --- 4. G1 IFFT ---
        let g1_evals = tx_domain.fft(&g1_points);
        c.bench_function(
            &format!("{}/op=g1_ifft batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(tx_domain.ifft(&g1_evals));
                });
            },
        );

        // --- 5. G1 MSM ---
        c.bench_function(
            &format!("{}/op=g1_msm batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(G1::msm(&crs.powers_of_g, &fcoeffs, &Sequential));
                });
            },
        );

        // --- 6. Pointwise G1 * Scalar ---
        c.bench_function(
            &format!(
                "{}/op=pointwise_g1_scalar batch_size={batch_size}",
                module_path!()
            ),
            |b| {
                b.iter(|| {
                    let h: Vec<G1> = g1_points
                        .iter()
                        .zip(scalars.iter())
                        .map(|(&gi, si)| gi * si)
                        .collect();
                    black_box(h);
                });
            },
        );

        // --- 7. open_all_values (FK22) ---
        c.bench_function(
            &format!("{}/op=open_all_values batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(open_all_values(&crs.y, &fcoeffs, &tx_domain));
                });
            },
        );

        // --- 8. Multi-pairing (2-way, single) ---
        let g1a = G1::generator() * &Scalar::random(&mut rng);
        let g1b = G1::generator() * &Scalar::random(&mut rng);
        let g2a = G2::generator() * &Scalar::random(&mut rng);
        let g2b = G2::generator() * &Scalar::random(&mut rng);
        c.bench_function(
            &format!("{}/op=multi_pairing_2way batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(GT::multi_pairing(&[(g1a, g2a), (g1b, g2b)]));
                });
            },
        );

        // --- 9. Multi-pairing loop (batch_size pairings, as in decrypt_all) ---
        c.bench_function(
            &format!(
                "{}/op=pairing_loop batch_size={batch_size}",
                module_path!()
            ),
            |b| {
                let pairs: Vec<_> = (0..batch_size)
                    .map(|_| {
                        (
                            G1::generator() * &Scalar::random(&mut rng),
                            G2::generator() * &Scalar::random(&mut rng),
                            G1::generator() * &Scalar::random(&mut rng),
                            G2::generator() * &Scalar::random(&mut rng),
                        )
                    })
                    .collect();
                b.iter(|| {
                    for (g1a, g2a, g1b, g2b) in &pairs {
                        black_box(GT::multi_pairing(&[(*g1a, *g2a), (*g1b, *g2b)]));
                    }
                });
            },
        );

        // --- 10. Single G1 scalar mul ---
        let g1_point = G1::generator() * &Scalar::random(&mut rng);
        let scalar = Scalar::random(&mut rng);
        c.bench_function(
            &format!("{}/op=g1_scalar_mul batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(g1_point * &scalar);
                });
            },
        );

        // --- 11. Single G2 scalar mul ---
        let g2_point = G2::generator() * &Scalar::random(&mut rng);
        c.bench_function(
            &format!("{}/op=g2_scalar_mul batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(g2_point * &scalar);
                });
            },
        );

        // --- 12. Full decrypt_all ---
        let num_parties = n / 2;
        let mut partial_decryptions = BTreeMap::new();
        for i in 0..num_parties {
            let sk = SecretKey::new(sk_shares[i].clone());
            let pd = sk.partial_decrypt(&ct, hid, &crs);
            partial_decryptions.insert(i + 1, pd);
        }
        let sigma = aggregate_partial_decryptions(&partial_decryptions);

        c.bench_function(
            &format!("{}/op=full_decrypt_all batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(decrypt_all(sigma, &ct, &crs));
                });
            },
        );

        // --- 13. Batch verify ---
        let decrypted = decrypt_all(sigma, &ct, &crs);
        c.bench_function(
            &format!("{}/op=batch_verify batch_size={batch_size}", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(batch_verify(&ct, &decrypted, hid, &pk, &mut rng));
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_bte_breakdown
}
