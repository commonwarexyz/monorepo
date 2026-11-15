use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod get;
mod insert;
mod mixed;
mod refill;
mod remove;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(
    get::benches,
    insert::benches,
    mixed::benches,
    refill::benches,
    remove::benches
);
