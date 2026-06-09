use commonware_storage::merkle::{Family, Location, Position};
use criterion::{criterion_group, Criterion};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::hint::black_box;

#[cfg(not(full_bench))]
const N_LEAVES: [u64; 2] = [1_000_000, 1_000_000_000_000];
#[cfg(full_bench)]
const N_LEAVES: [u64; 3] = [1_000_000, 1_000_000_000_000, 1 << 62];

/// Positions evaluated per measured iteration. Amortizes timer overhead and exercises a spread of
/// bit patterns (the cost varies with the popcount structure near the target).
const SAMPLES: usize = 4096;

/// Generate `SAMPLES` valid leaf positions drawn from leaf counts in `[0, max_leaves)`. Callers of
/// `position_to_location` (e.g. `leaves()`, `Location::try_from`) always pass leaf-aligned sizes,
/// so the benchmark mirrors that and does not exercise the non-leaf (`None`) path.
fn sample_positions<F: Family>(max_leaves: u64) -> Vec<Position<F>> {
    let mut rng = StdRng::seed_from_u64(0);
    (0..SAMPLES)
        .map(|_| F::location_to_position(Location::new(rng.gen_range(0..max_leaves))))
        .collect()
}

fn bench_position_to_location_family<F: Family>(c: &mut Criterion, family: &str) {
    for n in N_LEAVES {
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
