use commonware_cryptography::bls12381::{
    bte::{encrypt, respond_to_batch, BatchRequest, PublicKey},
    dkg::ops::generate_shares,
};
use commonware_utils::quorum;
use criterion::{black_box, criterion_group, Criterion};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const SIZES: [usize; 3] = [10, 100, 1000];
const PARTICIPANTS: [u32; 2] = [10, 100];
const THREADS: [usize; 2] = [1, 8];

struct PrepareData {
    public: PublicKey<commonware_cryptography::bls12381::primitives::variant::MinSig>,
    ciphertexts: Vec<
        commonware_cryptography::bls12381::bte::Ciphertext<
            commonware_cryptography::bls12381::primitives::variant::MinSig,
        >,
    >,
    shares: Vec<commonware_cryptography::bls12381::primitives::group::Share>,
    threshold: u32,
    threads: usize,
    label: Vec<u8>,
}

fn benchmark_bte_decrypt_prepare(c: &mut Criterion) {
    use commonware_cryptography::bls12381::primitives::variant::MinSig;

    for &threads in THREADS.iter() {
        for &participants in PARTICIPANTS.iter() {
            let threshold = quorum(participants);
            for &size in SIZES.iter() {
                let mut rng = ChaCha20Rng::from_seed([size as u8; 32]);
                let (commitment, shares) =
                    generate_shares::<_, MinSig>(&mut rng, None, participants, threshold);
                let public = PublicKey::<MinSig>::new(*commitment.constant());
                let ciphertexts: Vec<_> = (0..size)
                    .map(|i| {
                        let msg = format!("bench-msg-{i}").into_bytes();
                        encrypt(&mut rng, &public, b"bench-label", &msg)
                    })
                    .collect();

                let data = PrepareData {
                    public,
                    ciphertexts,
                    shares,
                    threshold,
                    threads,
                    label: format!("bench-{size}").into_bytes(),
                };

                let id = format!("bte_decrypt_prepare/n={participants}/threads={threads}");
                let mut bench_rng = ChaCha20Rng::from_seed([size as u8; 32]);
                c.bench_function(&format!("{id}/size={size}"), |b| {
                    b.iter(|| {
                        let request = BatchRequest::new(
                            &data.public,
                            data.ciphertexts.clone(),
                            data.label.clone(),
                            data.threshold,
                            data.threads,
                        );
                        black_box(respond_to_batch(&mut bench_rng, &data.shares[0], &request));
                    });
                });
            }
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_bte_decrypt_prepare
);
