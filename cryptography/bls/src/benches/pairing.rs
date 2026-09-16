use blst::{blst_fp12, blst_p1_affine, blst_p2_affine};
use commonware_cryptography_bls::bls12381::{
    group::{G1, G2},
    pairing::multi_pairing,
    scalar::Scalar,
};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    for count in [1, 2, 8, 16, 32] {
        let pairs: Vec<_> = (1..=count)
            .map(|i| {
                let p = G1::generator().mul(&Scalar::from_u64(i as u64));
                let q = G2::generator().mul(&Scalar::from_u64((i + 1) as u64));
                (
                    G1::from_bytes(&p.to_bytes()).unwrap(),
                    G2::from_bytes(&q.to_bytes()).unwrap(),
                )
            })
            .collect();
        let p: Vec<blst_p1_affine> = pairs
            .iter()
            .map(|(p, _)| {
                blst::min_pk::PublicKey::from_bytes(&p.to_bytes())
                    .unwrap()
                    .into()
            })
            .collect();
        let q: Vec<blst_p2_affine> = pairs
            .iter()
            .map(|(_, q)| {
                blst::min_sig::PublicKey::from_bytes(&q.to_bytes())
                    .unwrap()
                    .into()
            })
            .collect();
        assert_eq!(
            multi_pairing(&pairs).to_bytes(),
            blst_fp12::miller_loop_n(&q, &p).final_exp().to_bendian(),
        );

        c.bench_function(
            &format!("{}/pairs={count} impl=native", module_path!()),
            |b| {
                b.iter(|| black_box(multi_pairing(black_box(&pairs))));
            },
        );
        c.bench_function(
            &format!("{}/pairs={count} impl=blst", module_path!()),
            |b| {
                b.iter(|| {
                    black_box(blst_fp12::miller_loop_n(black_box(&q), black_box(&p)).final_exp())
                });
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
