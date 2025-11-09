use commonware_cryptography::bls12381::{
    bte::{
        batch_verify_responses, combine_partials, encrypt, respond_to_batch, verify_batch_response,
        BatchRequest, BatchResponse, BatchVerifierState, Ciphertext, PreparedResponse, PublicKey,
    },
    dkg::ops::generate_shares,
    primitives::{
        group::{Element, G1, Share},
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
    responses: Vec<BatchResponse<MinSig>>,
    evals: Vec<Eval<<MinSig as Variant>::Public>>,
    other_shares: Vec<G1>,
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
                    .map(|share| respond_to_batch(share, &request))
                    .collect();
                let evals: Vec<Eval<<MinSig as Variant>::Public>> = shares
                    .iter()
                    .take(threshold as usize)
                    .map(|share| Eval {
                        index: share.index,
                        value: share.public::<MinSig>(),
                    })
                    .collect();
                let other_shares: Vec<G1> = shares
                    .iter()
                    .take(threshold as usize)
                    .map(|share| {
                        let mut other = G1::one();
                        other.mul(&share.private);
                        other
                    })
                    .collect();

                let data = BenchmarkData {
                    public,
                    ciphertexts,
                    shares,
                    responses,
                    evals,
                    other_shares,
                };

                c.bench_with_input(BenchmarkId::new(id, size), &data, |b, data| {
                    b.iter(|| {
                        let mut iter_rng = ChaCha20Rng::from_seed([size as u8; 32]);
                        let request = BatchRequest::new(
                            &data.public,
                            data.ciphertexts.clone(),
                            format!("bench-{size}").into_bytes(),
                            threshold,
                            threads,
                        );
                        let verifier = BatchVerifierState::new(&mut iter_rng, &request).unwrap();

                        // Verify all responses and prepare them for batch pairing
                        let prepared_results = pool.install(|| {
                            data.responses
                                .par_iter()
                                .zip(data.evals.par_iter().zip(data.other_shares.par_iter()))
                                .map(|(response, (eval, other))| {
                                    verify_batch_response(&verifier, eval, other, response)
                                })
                                .collect::<Vec<_>>()
                        });
                        let prepared: Vec<PreparedResponse<MinSig>> = prepared_results
                            .into_iter()
                            .map(|res| res.unwrap())
                            .collect();

                        let verified = batch_verify_responses(
                            &verifier,
                            &mut iter_rng,
                            &prepared,
                            threshold as usize,
                        )
                        .unwrap();

                        black_box(
                            combine_partials(
                                &request,
                                &verified.share_indices,
                                &verified.partials,
                                threads,
                            )
                            .unwrap(),
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
