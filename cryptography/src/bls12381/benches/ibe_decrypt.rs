use commonware_cryptography::bls12381::{
    ibe::{decrypt, encrypt, Block},
    primitives::{
        group::Element,
        ops::{hash_message, keypair},
        variant::{MinSig, Variant},
    },
};
use criterion::{criterion_group, BatchSize, Criterion};
use rand::thread_rng;
use std::hint::black_box;

fn benchmark_ibe_decrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let (master_secret, master_public) = keypair::<_, MinSig>(&mut rng);
    let identity = b"user@example.com";
    let message = Block::new([0x42u8; 32]);

    // Generate private key for identity
    let id_point = hash_message::<MinSig>(MinSig::MESSAGE, identity);
    let mut private_key = id_point;
    private_key.mul(&master_secret);

    c.bench_function(module_path!(), |b| {
        b.iter_batched(
            || {
                encrypt::<_, MinSig>(&mut rng, master_public, &message, (None, identity))
                    .expect("Encryption should succeed")
            },
            |ciphertext| {
                black_box(decrypt::<MinSig>(private_key, &ciphertext).unwrap());
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_ibe_decrypt
}
