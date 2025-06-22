use criterion::criterion_main;

mod immutable_get;
mod immutable_put;
mod immutable_restart;
mod ordinal_get;
mod ordinal_put;
mod ordinal_restart;
mod utils;

criterion_main!(
    immutable_put::benches,
    immutable_get::benches,
    immutable_restart::benches,
    ordinal_put::benches,
    ordinal_get::benches,
    ordinal_restart::benches
);
