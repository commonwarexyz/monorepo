use criterion::criterion_main;

mod get_random_index;
mod get_random_key;
mod get_sequential_index;
mod put;
mod restart;
mod utils;

criterion_main!(
    put::benches,
    get_sequential_index::benches,
    get_random_index::benches,
    get_random_key::benches,
    restart::benches,
);
