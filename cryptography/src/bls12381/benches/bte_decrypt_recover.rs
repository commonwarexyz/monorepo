use commonware_cryptography::bls12381::{
    bte::{
        combine_partials, encrypt, respond_to_batch, verify_batch_response_with_scratch,
        BatchRequest, BatchVerifyScratch,
    },
    dkg::ops::generate_shares,
    primitives::{poly::Eval, variant::MinSig},
};
use commonware_utils::quorum;
use criterion::{black_box, criterion_group, Criterion};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::{prelude::*, ThreadPoolBuilder};
use std::sync::Arc;

const SIZES: [usize; 3] = [10, 100, 1000];
const PARTICIPANTS: [u32; 2] = [10, 100];
const THREADS: [usize; 2] = [1, 8];

fn benchmark_bte_decrypt_recover(c: &mut Criterion) {
    for &threads in THREADS.iter() {
        let pool = Arc::new(
            ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("pool"),
        );
        for &participants in PARTICIPANTS.iter() {
            let threshold = quorum(participants);
            for &size in SIZES.iter() {
                let mut rng = ChaCha20Rng::from_seed([size as u8; 32]);
                let (commitment, shares) =
                    generate_shares::<_, MinSig>(&mut rng, None, participants, threshold);
                let public = commonware_cryptography::bls12381::bte::PublicKey::<MinSig>::new(
                    *commitment.constant(),
                );
                let ciphertexts: Vec<_> = (0..size)
                    .map(|i| {
                        let msg = format!("bench-msg-{i}").into_bytes();
                        encrypt(&mut rng, &public, b"bench-label", &msg)
                    })
                    .collect();
                let request = BatchRequest::new(
                    &public,
                    ciphertexts.clone(),
                    format!("bench-{size}").into_bytes(),
                    threshold,
                    threads,
                );
                let responses: Vec<_> = shares
                    .iter()
                    .take(threshold as usize)
                    .map(|share| respond_to_batch(&mut rng, share, &request))
                    .collect();
                let evals: Vec<Eval<<MinSig as commonware_cryptography::bls12381::primitives::variant::Variant>::Public>> =
                    shares
                        .iter()
                        .take(threshold as usize)
                        .map(|share| Eval {
                            index: share.index,
                            value: share.public::<MinSig>(),
                        })
                        .collect();

                let results = pool.install(|| {
                    responses
                        .par_iter()
                        .zip(evals.par_iter())
                        .map_init(
                            || BatchVerifyScratch::new(),
                            |scratch, (response, eval)| {
                                verify_batch_response_with_scratch(
                                    &request, eval, response, scratch,
                                )
                                .map(|partials| (response.index, partials))
                            },
                        )
                        .collect::<Vec<_>>()
                });
                let mut share_indices = Vec::with_capacity(results.len());
                let mut partials = Vec::with_capacity(results.len());
                for entry in results {
                    let (idx, verified) = entry.unwrap();
                    share_indices.push(idx);
                    partials.push(verified);
                }

                let id = format!("bte_decrypt_recover/n={participants}/threads={threads}");
                c.bench_function(&format!("{id}/size={size}"), |b| {
                    b.iter(|| {
                        black_box(
                            combine_partials(&request, &share_indices, &partials, threads).unwrap(),
                        );
                    });
                });
            }
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_bte_decrypt_recover
);
