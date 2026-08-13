//! Production-integrated freelist summary benchmarks.
//!
//! These workloads use the benchmark facade's production operations. Boundary
//! cases compare automatic policy with forced direct and summary traversal on
//! the same geometry. They do not model synthetic summary words or unavailable
//! oversized or multiword modes.
//!
//! Concentrated and scattered layouts around 16 and 32 physical leaf blocks
//! exercise the x86-64 direct-scan boundary. The adjacent 33-block shape
//! exercises automatic summary navigation. Other targets retain their
//! production policy selection.

use commonware_runtime::iobuf::bench::{Freelist, PooledBuffer};
use criterion::Criterion;
use crossbeam_utils::CachePadded;
use std::{
    alloc::Layout,
    hint::black_box,
    mem::size_of,
    num::{NonZeroU32, NonZeroUsize},
    sync::atomic::AtomicU64,
    time::{Duration, Instant},
};

const BENCH_BUFFER_SIZE: usize = 64;
const BENCH_BUFFER_ALIGNMENT: usize = 64;
const BENCH_LAYOUT: Layout =
    match Layout::from_size_align(BENCH_BUFFER_SIZE, BENCH_BUFFER_ALIGNMENT) {
        Ok(layout) => layout,
        Err(_) => panic!("valid benchmark layout"),
    };

const LEAF_WORDS_PER_BLOCK: usize = size_of::<CachePadded<AtomicU64>>() / size_of::<AtomicU64>();
const SLOTS_PER_LEAF_BLOCK: usize = LEAF_WORDS_PER_BLOCK * u64::BITS as usize;
const BOUNDARY_BLOCKS: [usize; 6] = [15, 16, 17, 31, 32, 33];
const BATCH_SIZES: [usize; 7] = [8, 32, 128, 256, 512, 1024, 2048];
const M8_SUCCESS_CYCLES: usize = 8;

const _: () = assert!(size_of::<CachePadded<AtomicU64>>().is_multiple_of(size_of::<AtomicU64>()));
const _: () = assert!(LEAF_WORDS_PER_BLOCK.is_power_of_two());

#[derive(Clone, Copy)]
enum Policy {
    Automatic,
    Direct,
    Summary,
}

impl Policy {
    const ALL: [Self; 3] = [Self::Automatic, Self::Direct, Self::Summary];

    const fn name(self) -> &'static str {
        match self {
            Self::Automatic => "auto",
            Self::Direct => "direct",
            Self::Summary => "summary",
        }
    }
}

pub fn bench(c: &mut Criterion) {
    bench_settled_empty_boundary(c);
    bench_successful_cycles(c);
    bench_m8_boundary(c);
    bench_stale_cleanup(c);
    bench_batch_publication(c);
    bench_high_stripe_empty(c);
    bench_high_stripe_construction(c);
}

fn bench_settled_empty_boundary(c: &mut Criterion) {
    for blocks in BOUNDARY_BLOCKS {
        for (shape, capacity, parallelism) in boundary_shapes(blocks) {
            let name = format!(
                "{}/op=settled shape={shape} blocks={blocks} cap={capacity} p={parallelism}",
                module_path!(),
            );

            c.bench_function(&name, |b| {
                let freelist = new_freelist(capacity, parallelism, false);
                // SAFETY: no buffer has been created for this freelist.
                assert!(unsafe { freelist.take() }.is_none());

                b.iter(|| {
                    // SAFETY: no buffer has been created for this freelist,
                    // and it remains alive for the duration of the call.
                    let result = unsafe { freelist.take() };
                    black_box(result)
                });
            });
        }
    }
}

fn bench_successful_cycles(c: &mut Criterion) {
    for blocks in BOUNDARY_BLOCKS {
        for (shape, capacity, parallelism) in boundary_shapes(blocks) {
            let name = format!(
                "{}/op=cycle shape={shape} blocks={blocks} cap={capacity} p={parallelism}",
                module_path!(),
            );

            c.bench_function(&name, |b| {
                let mut state = SparseState::new(capacity, parallelism, 1);
                b.iter(|| {
                    state.single_cycle();
                    black_box(state.cycling.len())
                });
            });
        }
    }
}

fn bench_m8_boundary(c: &mut Criterion) {
    for blocks in BOUNDARY_BLOCKS {
        for (shape, capacity, parallelism) in boundary_shapes(blocks) {
            for policy in Policy::ALL {
                let policy_name = policy.name();
                let name = format!(
                    "{}/op=m8 mode={policy_name} shape={shape} blocks={blocks} cap={capacity} p={parallelism}",
                    module_path!(),
                );

                c.bench_function(&name, |b| {
                    let mut state = SparseState::new_with_policy(capacity, parallelism, 1, policy);
                    b.iter(|| {
                        for _ in 0..M8_SUCCESS_CYCLES {
                            state.single_cycle();
                        }
                        state.empty_miss();
                    });
                });
            }
        }
    }
}

fn bench_stale_cleanup(c: &mut Criterion) {
    let blocks = 33;
    for (shape, capacity, parallelism) in boundary_shapes(blocks) {
        for clean_misses in [0, 1, 4, 8] {
            let name = format!(
                "{}/op=cleanup misses={clean_misses} shape={shape} blocks={blocks} cap={capacity} p={parallelism}",
                module_path!(),
            );

            c.bench_function(&name, |b| {
                let mut state = SparseState::new(capacity, parallelism, 1);
                b.iter(|| {
                    // A completed return and take leaves one advisory group
                    // stale. The first miss cleans it, then the requested
                    // settled-empty misses follow in the same sample.
                    state.single_cycle();
                    state.empty_miss();
                    for _ in 0..clean_misses {
                        state.empty_miss();
                    }
                });
            });
        }
    }
}

fn bench_batch_publication(c: &mut Criterion) {
    for blocks in [32, 33] {
        for (shape, capacity, parallelism) in boundary_shapes(blocks) {
            for batch in BATCH_SIZES {
                let name = format!(
                    "{}/op=batch n={batch} shape={shape} blocks={blocks} cap={capacity} p={parallelism}",
                    module_path!(),
                );

                c.bench_function(&name, |b| {
                    let mut state = SparseState::new(capacity, parallelism, batch);
                    b.iter(|| {
                        state.batch_cycle();
                        black_box(state.cycling.len())
                    });
                });
            }
        }
    }
}

fn bench_high_stripe_empty(c: &mut Criterion) {
    for (capacity, parallelism) in [(64, 64), (4096, 1024), (4096, 4096)] {
        let name = format!(
            "{}/op=settled_high cap={capacity} p={parallelism}",
            module_path!(),
        );

        c.bench_function(&name, |b| {
            let freelist = new_freelist(capacity, parallelism, false);
            // SAFETY: no buffer has been created for this freelist.
            assert!(unsafe { freelist.take() }.is_none());

            b.iter(|| {
                // SAFETY: no buffer has been created for this freelist, and
                // the freelist remains alive for the duration of the call.
                let result = unsafe { freelist.take() };
                black_box(result)
            });
        });
    }
}

fn bench_high_stripe_construction(c: &mut Criterion) {
    for (capacity, parallelism) in [(64, 64), (4096, 1024), (4096, 4096)] {
        let name = format!(
            "{}/op=construct cap={capacity} p={parallelism}",
            module_path!(),
        );

        c.bench_function(&name, |b| {
            b.iter_custom(|iterations| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    let start = Instant::now();
                    let freelist = black_box(new_freelist(capacity, parallelism, false));
                    elapsed += start.elapsed();
                    drop(freelist);
                }
                elapsed
            });
        });
    }
}

const fn capacity_for_blocks(blocks: usize) -> usize {
    blocks
        .checked_mul(SLOTS_PER_LEAF_BLOCK)
        .expect("benchmark capacity must be representable")
}

fn boundary_shapes(blocks: usize) -> [(&'static str, usize, usize); 2] {
    let stripes = 1usize << blocks.ilog2();
    let extra_blocks = blocks - stripes;
    let scattered_capacity = stripes
        .checked_mul(SLOTS_PER_LEAF_BLOCK)
        .and_then(|capacity| capacity.checked_add(extra_blocks))
        .expect("scattered benchmark capacity must be representable");
    [
        ("concentrated", capacity_for_blocks(blocks), 1),
        ("scattered", scattered_capacity, stripes),
    ]
}

fn new_freelist(capacity: usize, parallelism: usize, prefill: bool) -> Freelist {
    new_freelist_with_policy(capacity, parallelism, prefill, Policy::Automatic)
}

fn new_freelist_with_policy(
    capacity: usize,
    parallelism: usize,
    prefill: bool,
    policy: Policy,
) -> Freelist {
    let capacity = u32::try_from(capacity).expect("benchmark capacity must fit in u32");
    let capacity = NonZeroU32::new(capacity).expect("benchmark capacity must be non-zero");
    let parallelism =
        NonZeroUsize::new(parallelism).expect("benchmark parallelism must be non-zero");
    match policy {
        Policy::Automatic => Freelist::new(capacity, parallelism, BENCH_LAYOUT, prefill),
        Policy::Direct => Freelist::new_forced_bypass(capacity, parallelism, BENCH_LAYOUT, prefill),
        Policy::Summary => {
            Freelist::new_forced_summary(capacity, parallelism, BENCH_LAYOUT, prefill)
        }
    }
}

struct SparseState {
    freelist: Freelist,
    held: Vec<PooledBuffer>,
    cycling: Vec<PooledBuffer>,
}

impl SparseState {
    fn new(capacity: usize, parallelism: usize, cycling: usize) -> Self {
        Self::new_with_policy(capacity, parallelism, cycling, Policy::Automatic)
    }

    fn new_with_policy(
        capacity: usize,
        parallelism: usize,
        cycling: usize,
        policy: Policy,
    ) -> Self {
        assert!(cycling > 0 && cycling <= capacity);

        let freelist = new_freelist_with_policy(capacity, parallelism, true, policy);
        let mut buffers = Vec::with_capacity(capacity);
        // SAFETY: the prefilled buffers remain owned by this state and the
        // freelist outlives every handle returned to the callback.
        let taken = unsafe {
            freelist.take_batch(capacity, |buffer| {
                buffers.push(buffer);
            })
        };
        assert_eq!(taken, capacity);

        // Prefill starts with every valid availability group set. Once all
        // buffers are checked out, settle those stale groups so each measured
        // cycle starts from only the availability it publishes itself.
        // SAFETY: every initialized buffer is held in `buffers`, and the
        // freelist remains alive for this call.
        assert!(unsafe { freelist.take() }.is_none());

        let mut held = Vec::with_capacity(capacity);
        let mut cycling_buffers = Vec::with_capacity(cycling);
        for (index, buffer) in buffers.into_iter().enumerate() {
            let next = cycling_buffers.len() * capacity / cycling;
            if cycling_buffers.len() < cycling && index == next {
                cycling_buffers.push(buffer);
            } else {
                held.push(buffer);
            }
        }
        assert_eq!(cycling_buffers.len(), cycling);

        Self {
            freelist,
            held,
            cycling: cycling_buffers,
        }
    }

    #[inline]
    fn single_cycle(&mut self) {
        assert_eq!(self.cycling.len(), 1);
        let buffer = self.cycling.pop().expect("one cycling buffer");
        // SAFETY: the buffer was taken from this freelist and is unavailable.
        unsafe { self.freelist.put(buffer) };
        // SAFETY: the freelist stays alive in this state until the returned
        // buffer is put back during a later cycle or during Drop.
        let buffer = unsafe { self.freelist.take() }.expect("returned buffer must be found");
        self.cycling.push(buffer);
    }

    #[inline]
    fn batch_cycle(&mut self) {
        let batch = self.cycling.len();
        // SAFETY: every cycling buffer was taken from this freelist, all slots
        // are distinct, and the drain iterator cannot panic.
        unsafe { self.freelist.put_batch(self.cycling.drain(..)) };

        let freelist = &self.freelist;
        let cycling = &mut self.cycling;
        // SAFETY: the freelist stays alive in this state and the preallocated
        // vector callback cannot allocate or panic while collecting `batch`.
        let taken = unsafe {
            freelist.take_batch(batch, |buffer| {
                cycling.push(buffer);
            })
        };
        assert_eq!(taken, batch);
    }

    #[inline]
    fn empty_miss(&self) {
        // SAFETY: all initialized buffers are checked out in `held` or
        // `cycling`, and this state keeps the freelist alive.
        let result = unsafe { self.freelist.take() };
        assert!(result.is_none());
        black_box(result);
    }
}

impl Drop for SparseState {
    fn drop(&mut self) {
        self.held.append(&mut self.cycling);
        // SAFETY: every buffer was taken from this freelist exactly once. The
        // combined vector contains unique unavailable slots and its drain
        // iterator cannot panic.
        unsafe { self.freelist.put_batch(self.held.drain(..)) };
    }
}
