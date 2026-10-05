use commonware_parallel::{Rayon, Sequential, Strategy};
use criterion::{Criterion, criterion_group, criterion_main};
use std::{hint::black_box, num::NonZeroUsize};

const ITEMS: usize = 100_000;
const THREADS: usize = 8;

/// A 128-byte output, roughly the size of a prepared transaction.
type Output = [u64; 16];

/// Fills the output with the input (overhead dominates).
const fn cheap(seed: &u64) -> Output {
    [*seed; 16]
}

/// Fills the output with `rounds` rounds of mixing (16 rounds take a few hundred nanoseconds).
fn mix(seed: u64, rounds: usize) -> Output {
    let mut out = [0u64; 16];
    let mut x = seed;
    for _ in 0..rounds {
        for word in &mut out {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            *word ^= z ^ (z >> 31);
        }
    }
    out
}

/// Uniform per-item work.
fn work(seed: &u64) -> Output {
    mix(*seed, 16)
}

/// The first tenth of the items cost ten times as much as the rest.
fn skewed(seed: &u64) -> Output {
    if *seed < (ITEMS / 10) as u64 {
        mix(*seed, 160)
    } else {
        mix(*seed, 16)
    }
}

/// 100 adjacent items in the middle cost 200 times as much as the rest, so most of the work
/// lands in one small region.
fn clustered(seed: &u64) -> Output {
    let middle = (ITEMS / 2) as u64;
    if (middle..middle + 100).contains(seed) {
        mix(*seed, 3200)
    } else {
        mix(*seed, 16)
    }
}

fn bench_strategy<S: Strategy>(c: &mut Criterion, label: &str, strategy: &S, inputs: &[u64]) {
    let n = inputs.len();
    for (map, op) in [
        ("cheap", cheap as fn(&u64) -> Output),
        ("work", work),
        ("skewed", skewed),
        ("clustered", clustered),
    ] {
        c.bench_function(
            &format!(
                "{}::try_map_collect_vec/items={n} map={map} strategy={label}",
                module_path!()
            ),
            |b| {
                b.iter(|| {
                    let out: Result<Vec<Output>, ()> =
                        strategy.try_map_collect_vec(inputs, |x| Ok(op(x)));
                    black_box(out)
                })
            },
        );
        c.bench_function(
            &format!(
                "{}::map_collect_vec/items={n} map={map} strategy={label}",
                module_path!()
            ),
            |b| b.iter(|| black_box(strategy.map_collect_vec(inputs, op))),
        );
    }
}

/// `map_init_collect_vec` whose `init` allocates a 64 KiB scratch buffer, so each extra
/// initialization costs a few microseconds.
fn bench_init<S: Strategy>(c: &mut Criterion, label: &str, strategy: &S, inputs: &[u64]) {
    c.bench_function(
        &format!(
            "{}::map_init_collect_vec/items={} init=alloc_64k strategy={label}",
            module_path!(),
            inputs.len()
        ),
        |b| {
            b.iter(|| {
                black_box(strategy.map_init_collect_vec(
                    inputs,
                    || vec![0u8; 64 * 1024],
                    |scratch, x| {
                        let i = *x as usize % scratch.len();
                        scratch[i] ^= 1;
                        work(x)
                    },
                ))
            })
        },
    );
}

/// `map_collect_vec` over few items, where per-chunk overhead matters most.
fn bench_small<S: Strategy>(c: &mut Criterion, label: &str, strategy: &S, inputs: &[u64]) {
    for (map, op) in [("cheap", cheap as fn(&u64) -> Output), ("work", work)] {
        c.bench_function(
            &format!(
                "{}::map_collect_vec/items={} map={map} strategy={label}",
                module_path!(),
                inputs.len()
            ),
            |b| b.iter(|| black_box(strategy.map_collect_vec(inputs, op))),
        );
    }
}

fn bench_collect(c: &mut Criterion) {
    let inputs: Vec<u64> = (0..ITEMS as u64).collect();
    let rayon = Rayon::new(NonZeroUsize::new(THREADS).unwrap()).unwrap();
    bench_strategy(c, "sequential", &Sequential, &inputs);
    bench_strategy(c, "adaptive", &rayon, &inputs);
    bench_strategy(c, "parallel", &rayon.manual(), &inputs);
    bench_init(c, "adaptive", &rayon, &inputs);
    bench_init(c, "parallel", &rayon.manual(), &inputs);
    // Below and just above the chunking threshold (1,024 items per thread).
    for n in [1_000, 10_000] {
        let small: Vec<u64> = (0..n).collect();
        bench_small(c, "adaptive", &rayon, &small);
        bench_small(c, "parallel", &rayon.manual(), &small);
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(30);
    targets = bench_collect
}
criterion_main!(benches);
