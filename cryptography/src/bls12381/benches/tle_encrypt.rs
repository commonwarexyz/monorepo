use commonware_cryptography::bls12381::{
    primitives::{ops::keypair, variant::MinSig},
    tle::{encrypt, Block},
};
use criterion::{criterion_group, Criterion};
use rand::thread_rng;
use std::hint::black_box;

fn benchmark_tle_encrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (_, master_public) = keypair::<_, MinSig>(&mut rng);
    let target = 10u64.to_be_bytes();
    let message = Block::new([0x42u8; 32]);

    c.bench_function(module_path!(), |b| {
        b.iter(|| {
            black_box(encrypt::<_, MinSig>(
                &mut rng,
                master_public,
                (None, &target),
                &message,
            ));
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_tle_encrypt
}
