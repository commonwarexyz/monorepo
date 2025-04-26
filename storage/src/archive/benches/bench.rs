use criterion::criterion_main;

mod get_random_index;
mod get_random_key;
mod get_sequential_index;
mod hashmap_insert;
mod hashmap_insert_fixed;
mod hashmap_iteration;
mod put;
mod replay;
mod utils;

criterion_main!(
    hashmap_iteration::benches,
    hashmap_insert_fixed::benches,
    hashmap_insert::benches,
    put::benches,
    get_sequential_index::benches,
    get_random_index::benches,
    get_random_key::benches,
    replay::benches,
);
