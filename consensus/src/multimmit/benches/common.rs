//! Shared scenarios and strategy registration for the Multimmit benchmarks.

use commonware_consensus::multimmit::test_utils::benchmarks::{ViewScenario, VoteShape};
use commonware_cryptography::bls12381::primitives::variant::Variant;
use commonware_parallel::{Rayon, Sequential, Strategy};
use commonware_utils::NZUsize;
use criterion::Criterion;

/// Committee sizes measured: a mid-sized committee and one at deployment scale.
pub const SIZES: [u32; 2] = [31, 50];

/// Builds the view scenario of every measured committee size and vote shape.
pub fn scenarios<V: Variant>() -> impl Iterator<Item = (u32, VoteShape, ViewScenario<V>)> {
    SIZES.into_iter().flat_map(|participants| {
        VoteShape::ALL
            .into_iter()
            .map(move |shape| (participants, shape, ViewScenario::new(participants, shape)))
    })
}

fn rayon() -> Rayon {
    Rayon::new(NZUsize!(8)).unwrap()
}

/// A measured operation that runs under any execution strategy.
pub trait Workload {
    /// Runs the operation once under `strategy`, passing its result through [`std::hint::black_box`].
    fn run<S: Strategy>(&mut self, strategy: &S);
}

/// Registers the workload `new` builds once per execution strategy, sequential then rayon.
///
/// Each benchmark gets a fresh workload and is labeled `label` followed by `strategy=<name>`.
pub fn bench_strategies<W: Workload>(c: &mut Criterion, label: &str, mut new: impl FnMut() -> W) {
    measure(
        c,
        &format!("{label} strategy=sequential"),
        new(),
        &Sequential,
    );
    measure(c, &format!("{label} strategy=rayon"), new(), &rayon());
}

fn measure<W: Workload, S: Strategy>(
    c: &mut Criterion,
    label: &str,
    mut workload: W,
    strategy: &S,
) {
    c.bench_function(label, |b| b.iter(|| workload.run(strategy)));
}
