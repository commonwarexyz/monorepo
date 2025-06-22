use criterion::criterion_main;

mod immutable_get;
mod immutable_put;
mod immutable_restart;
mod prunable_get;
mod prunable_put;
mod prunable_restart;
mod utils;

criterion_main!(
    prunable_put::benches,
    prunable_get::benches,
    prunable_restart::benches,
    immutable_put::benches,
    immutable_get::benches,
    immutable_restart::benches
);
