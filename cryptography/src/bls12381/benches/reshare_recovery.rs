use commonware_cryptography::{
    bls12381::{dkg, primitives::poly},
    Ed25519, Scheme,
};
use commonware_utils::quorum;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::collections::HashMap;
use std::hint::black_box;

fn benchmark_reshare_recovery(c: &mut Criterion) {
    for &n in &[5, 10, 20, 50, 100, 250, 500] {
        // Perform DKG
        //
        // We do this once outside of the benchmark to reduce the overhead
        // of each sample (which can be large as `n` grows).

        // Create contributors
        let mut contributors = (0..n)
            .map(|i| Ed25519::from_seed(i as u64).public_key())
            .collect::<Vec<_>>();
        contributors.sort();

        // Create shares
        let t = quorum(n).unwrap();
        let mut contributor_shares = HashMap::new();
        let mut commitments = Vec::new();
        for i in 0..n {
            let me = contributors[i as usize].clone();
            let p0 = dkg::contributor::P0::new(
                me,
                t,
                None,
                contributors.clone(),
                contributors.clone(),
                1,
            );
            let (p1, commitment, shares) = p0.finalize();
            contributor_shares.insert(i, (commitment.clone(), shares, p1.unwrap()));
            commitments.push(commitment);
        }

        // Distribute commitments
        for i in 0..n {
            let dealer = contributors[i as usize].clone();
            for j in 0..n {
                // Get recipient share
                let (commitment, _, _) = contributor_shares.get(&i).unwrap();
                let commitment = commitment.clone();

                // Send share to recipient
                let (_, _, ref mut recipient) = contributor_shares.get_mut(&j).unwrap();
                recipient.commitment(dealer.clone(), commitment).unwrap();
            }
        }

        // Convert to p2
        let mut p2 = HashMap::new();
        for i in 0..n {
            let (_, shares, contributor) = contributor_shares.remove(&i).unwrap();
            let contributor = contributor.finalize().unwrap();
            p2.insert(i, (shares, contributor));
        }
        let mut contributor_shares = p2;

        // Distribute shares
        for i in 0..n {
            let dealer = contributors[i as usize].clone();
            for j in 0..n {
                // Get recipient share
                let (shares, _) = contributor_shares.get(&i).unwrap();
                let share = shares[j as usize];

                // Send share to recipient
                let (_, recipient) = contributor_shares.get_mut(&j).unwrap();
                recipient.share(dealer.clone(), share).unwrap();
            }
        }

        // Finalize
        let included_commitments = (0..n).collect::<Vec<_>>();
        let commitments = commitments[0..n as usize].to_vec();
        let mut group: Option<poly::Public> = None;
        let mut outputs = Vec::new();
        for i in 0..n {
            let (_, contributor) = contributor_shares.remove(&i).unwrap();
            let output = contributor
                .finalize(included_commitments.clone())
                .expect("unable to finalize");
            assert_eq!(output.commitments, commitments);
            match &group {
                Some(group) => {
                    assert_eq!(output.public, *group);
                }
                None => {
                    group = Some(output.public.clone());
                }
            }
            outputs.push(output);
        }

        for &concurrency in &[1, 2, 4, 8] {
            c.bench_function(&format!("conc={} n={} t={}", concurrency, n, t), |b| {
                b.iter_batched(
                    || {
                        // Create reshare
                        let group = group.clone().unwrap();
                        let mut contributor = None;
                        let mut commitments = HashMap::new();
                        for i in 0..n {
                            let me = contributors[i as usize].clone();
                            let share = outputs[i as usize].share;
                            let p0 = dkg::contributor::P0::new(
                                me,
                                t,
                                Some((group.clone(), share)),
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

                        // Convert to p2
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
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = benchmark_reshare_recovery
}
criterion_main!(benches);
