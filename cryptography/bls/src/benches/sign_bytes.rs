use super::utils::{MESSAGE, MIN_PK_DST, MIN_SIG_DST};
use commonware_cryptography_bls::bls12381::signing::{SigningKey, min_pk, min_sig};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    let key = SigningKey::key_gen(&[42; 32], b"").expect("valid deterministic key material");
    let blst_min_pk = blst::min_pk::SecretKey::from_bytes(&key.to_bytes()).unwrap();
    let blst_min_sig = blst::min_sig::SecretKey::from_bytes(&key.to_bytes()).unwrap();
    assert_eq!(
        min_pk::sign(&key, MESSAGE, MIN_PK_DST).to_bytes(),
        blst_min_pk.sign(MESSAGE, MIN_PK_DST, b"").to_bytes()
    );
    assert_eq!(
        min_sig::sign(&key, MESSAGE, MIN_SIG_DST).to_bytes(),
        blst_min_sig.sign(MESSAGE, MIN_SIG_DST, b"").to_bytes()
    );

    c.bench_function(
        &format!("{}/scheme=min_pk impl=native", module_path!()),
        |b| {
            b.iter(|| {
                black_box(min_pk::sign(black_box(&key), black_box(MESSAGE), MIN_PK_DST).to_bytes())
            });
        },
    );
    c.bench_function(
        &format!("{}/scheme=min_pk impl=blst", module_path!()),
        |b| {
            b.iter(|| {
                black_box(
                    blst_min_pk
                        .sign(black_box(MESSAGE), MIN_PK_DST, b"")
                        .to_bytes(),
                )
            });
        },
    );
    c.bench_function(
        &format!("{}/scheme=min_sig impl=native", module_path!()),
        |b| {
            b.iter(|| {
                black_box(
                    min_sig::sign(black_box(&key), black_box(MESSAGE), MIN_SIG_DST).to_bytes(),
                )
            });
        },
    );
    c.bench_function(
        &format!("{}/scheme=min_sig impl=blst", module_path!()),
        |b| {
            b.iter(|| {
                black_box(
                    blst_min_sig
                        .sign(black_box(MESSAGE), MIN_SIG_DST, b"")
                        .to_bytes(),
                )
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
