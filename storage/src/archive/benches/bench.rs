use criterion::criterion_main;

mod prunable_get;
mod prunable_put;
mod prunable_restart;
mod utils;

criterion_main!(
    prunable_put::benches,
    prunable_get::benches,
    prunable_restart::benches
);
