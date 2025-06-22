use criterion::criterion_main;

mod hashmap_insert;
mod hashmap_insert_fixed;
mod hashmap_iteration;
mod mutable_insert;

criterion_main!(
    hashmap_iteration::benches,
    hashmap_insert_fixed::benches,
    hashmap_insert::benches,
    mutable_insert::benches,
);
