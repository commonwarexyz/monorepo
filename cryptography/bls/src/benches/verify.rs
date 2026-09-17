use super::utils::{MESSAGE, MIN_PK_DST, MIN_SIG_DST};
use commonware_cryptography_bls::bls12381::{
    group::{G1, G2},
    signing::{SigningKey, min_pk, min_sig},
};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    let key = SigningKey::key_gen(&[42; 32], b"").unwrap();
    let pk = G1::from_bytes(&min_pk::public_key(&key).to_bytes()).unwrap();
    let signature = G2::from_bytes(&min_pk::sign(&key, MESSAGE, MIN_PK_DST).to_bytes()).unwrap();
    let sig_pk = G2::from_bytes(&min_sig::public_key(&key).to_bytes()).unwrap();
    let sig_signature =
        G1::from_bytes(&min_sig::sign(&key, MESSAGE, MIN_SIG_DST).to_bytes()).unwrap();
    let reference_pk = blst::min_pk::PublicKey::from_bytes(&pk.to_bytes()).unwrap();
    let reference_signature = blst::min_pk::Signature::from_bytes(&signature.to_bytes()).unwrap();
    let reference_sig_pk = blst::min_sig::PublicKey::from_bytes(&sig_pk.to_bytes()).unwrap();
    let reference_sig_signature =
        blst::min_sig::Signature::from_bytes(&sig_signature.to_bytes()).unwrap();

    // Both implementations receive decoded, subgroup-checked public keys and signatures.
    c.bench_function(
        &format!("{}/scheme=min_pk impl=native", module_path!()),
        |b| {
            b.iter(|| {
                black_box(min_pk::verify(
                    black_box(&pk),
                    black_box(MESSAGE),
                    MIN_PK_DST,
                    black_box(&signature),
                ))
            });
        },
    );
    c.bench_function(
        &format!("{}/scheme=min_pk impl=blst", module_path!()),
        |b| {
            b.iter(|| {
                black_box(reference_signature.verify(
                    false,
                    black_box(MESSAGE),
                    MIN_PK_DST,
                    b"",
                    black_box(&reference_pk),
                    false,
                ))
            });
        },
    );
    c.bench_function(
        &format!("{}/scheme=min_sig impl=native", module_path!()),
        |b| {
            b.iter(|| {
                black_box(min_sig::verify(
                    black_box(&sig_pk),
                    black_box(MESSAGE),
                    MIN_SIG_DST,
                    black_box(&sig_signature),
                ))
            });
        },
    );
    c.bench_function(
        &format!("{}/scheme=min_sig impl=blst", module_path!()),
        |b| {
            b.iter(|| {
                black_box(reference_sig_signature.verify(
                    false,
                    black_box(MESSAGE),
                    MIN_SIG_DST,
                    b"",
                    black_box(&reference_sig_pk),
                    false,
                ))
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench,
}
