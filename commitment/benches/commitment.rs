use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use commonware_commitment::{
    field::{BinaryElem128, BinaryElem32},
    prover_config_20, verifier_config_20,
    transcript::Sha256Transcript,
};
use rand::Rng;
use std::hint::black_box;

fn random_poly(size: usize) -> Vec<BinaryElem32> {
    let mut rng = rand::thread_rng();
    (0..size)
        .map(|_| BinaryElem32::from(rng.gen::<u32>()))
        .collect()
}

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment::prove");
    group.sample_size(10);

    let config = prover_config_20::<BinaryElem32, BinaryElem128>();
    let poly = random_poly(1 << 20);

    group.bench_function(BenchmarkId::new("sha256", "2^20"), |b| {
        b.iter(|| {
            let mut transcript = Sha256Transcript::new(0);
            let proof = commonware_commitment::prove(
                &config,
                black_box(&poly),
                &mut transcript,
            )
            .unwrap();
            black_box(proof)
        });
    });

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitment::verify");
    group.sample_size(10);

    let prover_config = prover_config_20::<BinaryElem32, BinaryElem128>();
    let verifier_config = verifier_config_20();
    let poly = random_poly(1 << 20);

    let mut pt = Sha256Transcript::new(0);
    let proof = commonware_commitment::prove(&prover_config, &poly, &mut pt).unwrap();

    group.bench_function(BenchmarkId::new("sha256", "2^20"), |b| {
        b.iter(|| {
            let mut vt = Sha256Transcript::new(0);
            let valid = commonware_commitment::verify(
                &verifier_config,
                black_box(&proof),
                &mut vt,
            )
            .unwrap();
            black_box(valid)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_prove, bench_verify);
criterion_main!(benches);
