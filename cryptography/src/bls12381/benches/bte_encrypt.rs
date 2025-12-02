use commonware_cryptography::bls12381::{
    bte::{encrypt, PublicKey},
    dkg::ops::generate_shares,
    primitives::variant::MinSig,
};
use criterion::{criterion_group, Criterion};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::hint::black_box;

fn benchmark_bte_encrypt(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let (commitment, _) = generate_shares::<_, MinSig>(&mut rng, None, 1, 1);
    let public = PublicKey::<MinSig>::new(*commitment.constant());
    let message = vec![0x42u8; 64];

    c.bench_function(module_path!(), |b| {
        b.iter(|| {
            black_box(encrypt(&mut rng, &public, b"bench-label", &message));
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_bte_encrypt
}
