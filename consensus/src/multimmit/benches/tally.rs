//! Verification of one view's `n - f` votes: one by one, as one batch, and as one aggregate.
//!
//! Individual and batch verification check votes as they arrive in updates; aggregate verification
//! is what a certificate's tally costs once its votes are combined. Agreeing votes share one
//! content and so one pairing in the batch and aggregate checks; staggered votes are all distinct.

use super::common::{Workload, bench_strategies, scenarios};
use commonware_consensus::multimmit::{
    scheme::bls12381::Signed, test_utils::benchmarks::ViewScenario,
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
};
use commonware_parallel::Strategy;
use commonware_utils::{TestRng, test_rng};
use core::fmt;
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// How the votes are verified.
#[derive(Clone, Copy)]
enum Method {
    /// One pairing check per vote.
    Individual,
    /// One randomly scaled pairing product over every vote.
    Batch,
    /// One check of the combined signature over every signer's content.
    Aggregate,
}

impl Method {
    const ALL: [Self; 3] = [Self::Individual, Self::Batch, Self::Aggregate];
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Individual => "individual",
            Self::Batch => "batch",
            Self::Aggregate => "aggregate",
        })
    }
}

/// Verifies the view's final votes by one method.
struct VerifyVotes<'a, V: Variant> {
    view: &'a ViewScenario<V>,
    method: Method,
    rng: TestRng,
}

impl<V: Variant> Workload for VerifyVotes<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        let verifier = self.view.verifier();
        let finals = self.view.finals();
        let valid = match self.method {
            Method::Individual => strategy
                .map_collect_vec(finals, |(content, attestation)| {
                    verifier.verify_vote(content, attestation)
                })
                .into_iter()
                .all(|valid| valid),
            Method::Batch => {
                let items: Vec<_> = finals
                    .iter()
                    .map(|(content, attestation)| Signed::Vote {
                        content,
                        attestation,
                    })
                    .collect();
                verifier
                    .verify_batch::<_, Sha256, _>(&mut self.rng, &items, strategy)
                    .iter()
                    .all(|verdict| verdict.is_valid())
            }
            Method::Aggregate => {
                let signature = self.view.vqc().signature().expect("aggregate decodes");
                verifier.verify_tally(&mut self.rng, self.view.contents(), signature, strategy)
            }
        };
        assert!(black_box(valid));
    }
}

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    for (participants, shape, view) in scenarios::<V>() {
        for method in Method::ALL {
            bench_strategies(
                c,
                &format!(
                    "{}::verify_votes/variant={variant} n={participants} votes={shape} method={method}",
                    module_path!()
                ),
                || VerifyVotes {
                    view: &view,
                    method,
                    rng: test_rng(),
                },
            );
        }
    }
}

fn bench_tally(c: &mut Criterion) {
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_tally
}
