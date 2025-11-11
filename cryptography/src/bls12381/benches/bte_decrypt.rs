use commonware_cryptography::bls12381::{
    bte::{
        batch_verify_responses, combine_partials, encrypt, respond_to_batch, BatchRequest,
        BatchResponse, BatchVerification, Ciphertext, ContextPublicShare, PublicKey,
    },
    dkg::ops::generate_shares,
    primitives::{
        group::{Scalar, Share},
        poly::Eval,
        variant::{MinSig, Variant},
    },
};
use commonware_utils::quorum;
use criterion::{criterion_group, BenchmarkId, Criterion};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator},
    ThreadPoolBuilder,
};
use std::{hint::black_box, sync::Arc};

const SIZES: [usize; 3] = [10, 100, 1000];
const PARTICIPANTS: [u32; 2] = [10, 100];
const THREADS: [usize; 2] = [1, 8];

struct BenchmarkData {
    public: PublicKey<MinSig>,
    ciphertexts: Vec<Ciphertext<MinSig>>,
    shares: Vec<Share>,
    mask_shares: Vec<Share>,
    responses: Vec<BatchResponse<MinSig>>,
    evals: Vec<ContextPublicShare<MinSig>>,
}

fn benchmark_bte_decrypt(c: &mut Criterion) {
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
                let id = format!("bte_decrypt/n={participants}/threads={threads}");

                let mut rng = ChaCha20Rng::from_seed([size as u8; 32]);
                let (commitment, shares) =
                    generate_shares::<_, MinSig>(&mut rng, None, participants, threshold);
                let zero_seed = Share {
                    index: 0,
                    private: Scalar::zero(),
                };
                let (_, mask_shares) =
                    generate_shares::<_, MinSig>(&mut rng, Some(zero_seed), participants, threshold);
                let public = PublicKey::<MinSig>::new(*commitment.constant());

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
                    .zip(mask_shares.iter())
                    .map(|(share, mask)| respond_to_batch(&mut rng, share, mask, &request))
                    .collect();
                let evals: Vec<ContextPublicShare<MinSig>> = shares
                    .iter()
                    .take(threshold as usize)
                    .zip(mask_shares.iter())
                    .map(|(share, mask)| ContextPublicShare {
                        secret: Eval {
                            index: share.index,
                            value: share.public::<MinSig>(),
                        },
                        mask: Eval {
                            index: mask.index,
                            value: mask.public::<MinSig>(),
                        },
                    })
                    .collect();

                let data = BenchmarkData {
                    public,
                    ciphertexts,
                    shares,
                    mask_shares,
                    responses,
                    evals,
                };

                c.bench_with_input(BenchmarkId::new(id, size), &data, |b, data| {
                    b.iter(|| {
                        // Compute batch request and handle one batch response to simulate a single player's contribution (although we already have the data)
                        let request = BatchRequest::new(
                            &data.public,
                            data.ciphertexts.clone(),
                            format!("bench-{size}").into_bytes(),
                            threshold,
                            threads,
                        );
                        black_box(respond_to_batch(
                            &mut rng,
                            &data.shares[0],
                            &data.mask_shares[0],
                            &request,
                        ));

                        // Verify all responses with MSM batching
                        let BatchVerification { valid, invalid } =
                            pool.install(|| batch_verify_responses(&request, &data.evals, &data.responses))
                                .unwrap();
                        assert!(
                            invalid.is_empty(),
                            "unexpected invalid responders: {invalid:?}"
                        );
                        let mut share_indices = Vec::with_capacity(valid.len());
                        let mut partials = Vec::with_capacity(valid.len());
                        for (idx, verified) in valid {
                            share_indices.push(idx);
                            partials.push(verified);
                        }
                        black_box(
                            combine_partials(&request, &share_indices, &partials, threads).unwrap(),
                        );
                    });
                });
            }
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_bte_decrypt
}
