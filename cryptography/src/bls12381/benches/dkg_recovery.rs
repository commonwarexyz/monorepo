use commonware_cryptography::{bls12381::dkg, ed25519::insecure_signer, Scheme};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::collections::HashMap;
use std::hint::black_box;

fn benchmark_dkg_recovery(c: &mut Criterion) {
    let concurrency = 1; // only used in recovery during reshare
    for &n in &[5, 10, 20, 50, 100, 250, 500] {
        let t = dkg::utils::threshold(n).unwrap();
        c.bench_function(&format!("conc={} n={} t={}", concurrency, n, t), |b| {
            b.iter_batched(
                || {
                    // Create contributors
                    let mut contributors = (0..n)
                        .map(|i| insecure_signer(i as u16).me())
                        .collect::<Vec<_>>();
                    contributors.sort();

                    // Create shares
                    let mut contributor = None;
                    let mut commitments = HashMap::new();
                    for i in 0..n {
                        let me = contributors[i as usize].clone();
                        let p0 = dkg::contributor::P0::new(
                            me,
                            t,
                            None,
                            contributors.clone(),
                            contributors.clone(),
                            concurrency,
                        );
                        let (p1, commitment, shares) = p0.finalize();
                        if i == 0 {
                            contributor = p1;
                        }
                        commitments.insert(i, (commitment, shares));
                    }
                    let mut contributor = contributor.unwrap();

                    // Distribute commitments
                    for i in 0..n {
                        // Get recipient share
                        let (commitment, _) = commitments.get(&i).unwrap();
                        let commitment = commitment.clone();

                        // Send share to contributor
                        let dealer = contributors[i as usize].clone();
                        contributor.commitment(dealer, commitment).unwrap();
                    }

                    // Convert to p1
                    let mut contributor = contributor.finalize().unwrap();

                    // Distribute shares
                    for i in 0..n {
                        // Get recipient share
                        let (_, shares) = commitments.get(&i).unwrap();
                        let share = shares[0];

                        // Send share to contributor
                        let dealer = contributors[i as usize].clone();
                        contributor.share(dealer, share).unwrap();
                    }

                    // Finalize
                    let commitments = (0..n).collect::<Vec<_>>();
                    (contributor, commitments)
                },
                |(contributor, commitments)| {
                    black_box(contributor.finalize(commitments).unwrap());
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_dkg_recovery
}
criterion_main!(benches);
