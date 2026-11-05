use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod count_ones;
mod roaring_contains;
mod roaring_difference;
mod roaring_insert;
mod roaring_insert_range;
mod roaring_intersection;
mod roaring_iteration;
mod roaring_union;
mod roaring_write;
mod write;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

/// Whether to run benchmarks with their smallest inputs.
fn smoke() -> bool {
    std::env::var_os("COMMONWARE_BENCH_SMOKE").is_some()
}

criterion_main!(
    count_ones::benches,
    write::benches,
    roaring_insert::benches,
    roaring_insert_range::benches,
    roaring_contains::benches,
    roaring_union::benches,
    roaring_intersection::benches,
    roaring_difference::benches,
    roaring_iteration::benches,
    roaring_write::benches,
);
