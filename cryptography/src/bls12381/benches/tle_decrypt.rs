use commonware_cryptography::bls12381::{
    primitives::{ops, variant::MinSig},
    tle::{decrypt, encrypt, Block},
};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::thread_rng;
use std::hint::black_box;

fn bench_tle_decrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (master_secret, master_public) = ops::keypair::<_, MinSig>(&mut rng);
    let target = 10u64.to_be_bytes();
    let message = Block::new([0x42u8; 32]);
    let signature = ops::sign_message::<MinSig>(&master_secret, b"_BENCH_TLE_", &target);

    c.bench_function(module_path!(), |b| {
        b.iter_batched(
            || encrypt::<_, MinSig>(&mut rng, master_public, (b"_BENCH_TLE_", &target), &message),
            |ciphertext| {
                black_box(decrypt::<MinSig>(&signature, &ciphertext).unwrap());
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_tle_decrypt
}
