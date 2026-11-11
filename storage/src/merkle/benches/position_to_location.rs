use commonware_storage::merkle::{Family, Location, Position};
use commonware_utils::test_rng;
use criterion::{Criterion, criterion_group};
use rand::RngExt as _;
use std::hint::black_box;

fn n_leaves() -> &'static [u64] {
    if commonware_bench::full() {
        &[1_000_000, 1_000_000_000_000, 1 << 62]
    } else {
        &[1_000_000, 1_000_000_000_000]
    }
}

/// Positions evaluated per measured iteration. Amortizes timer overhead and exercises a spread of
/// bit patterns (the cost varies with the popcount structure near the target).
const SAMPLES: usize = 4096;

/// Generate `SAMPLES` valid leaf positions drawn from leaf counts in `[0, max_leaves)`. The
/// benchmark focuses on the common leaf/size (`Some`) path exercised by callers like `leaves()` and
/// `Location::try_from`; it does not measure the non-leaf (`None`) path used for leaf detection.
fn sample_positions<F: Family>(max_leaves: u64) -> Vec<Position<F>> {
    let mut rng = test_rng();
    (0..SAMPLES)
        .map(|_| F::location_to_position(Location::new(rng.random_range(0..max_leaves))))
        .collect()
}

fn bench_position_to_location_family<F: Family>(c: &mut Criterion, family: &str) {
    for &n in n_leaves() {
        let positions = sample_positions::<F>(n);
        c.bench_function(&format!("{}/n={n} family={family}", module_path!()), |b| {
            b.iter(|| {
                for &pos in &positions {
                    black_box(F::position_to_location(black_box(pos)));
                }
            });
        });
    }
}

fn bench_position_to_location(c: &mut Criterion) {
    bench_position_to_location_family::<commonware_storage::mmr::Family>(c, "mmr");
    bench_position_to_location_family::<commonware_storage::mmb::Family>(c, "mmb");
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_position_to_location
}
