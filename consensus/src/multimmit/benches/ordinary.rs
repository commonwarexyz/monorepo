//! Batch verification of signed transaction blocks.

use super::common::{SIZES, Workload, bench_strategies};
use commonware_consensus::multimmit::{
    mocks::{Committee, Scenario},
    scheme::bls12381::{Scheme, Signed},
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    ed25519,
    sha256::Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::{TestRng, test_rng};
use criterion::{Criterion, criterion_group};
use std::hint::black_box;

/// The committee seed.
const SEED: u64 = 9;

/// Batch-verifies one header per chain.
struct VerifyHeaders<'a, V: Variant> {
    verifier: &'a Scheme<ed25519::PublicKey, V>,
    items: &'a [Signed<'a, V, Digest>],
    rng: TestRng,
}

impl<V: Variant> Workload for VerifyHeaders<'_, V> {
    fn run<S: Strategy>(&mut self, strategy: &S) {
        let verdicts =
            self.verifier
                .verify_batch::<_, Sha256, _>(&mut self.rng, self.items, strategy);
        assert!(black_box(verdicts).iter().all(|verdict| verdict.is_valid()));
    }
}

fn register<V: Variant>(c: &mut Criterion, variant: &str) {
    for participants in SIZES {
        let mut scenario = Scenario::new(Committee::<V>::builder(SEED, participants).build());
        let genesis = scenario.genesis();
        let tips = scenario.extend_all(genesis.tips(), 1);
        let items: Vec<_> = tips
            .iter()
            .map(|tip| Signed::TransactionBlock(scenario.block(tip).expect("header is held")))
            .collect();
        bench_strategies(
            c,
            &format!(
                "{}::verify_headers/variant={variant} n={participants}",
                module_path!()
            ),
            || VerifyHeaders {
                verifier: &scenario.committee().verifier,
                items: &items,
                rng: test_rng(),
            },
        );
    }
}

fn bench_ordinary(c: &mut Criterion) {
    register::<MinPk>(c, "minpk");
    register::<MinSig>(c, "minsig");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_ordinary
}
