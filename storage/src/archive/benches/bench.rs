mod hashmap_insert;
mod hashmap_insert_fixed;
mod hashmap_iteration;

use criterion::criterion_main;

criterion_main!(
    hashmap_iteration::benches,
    hashmap_insert_fixed::benches,
    hashmap_insert::benches,
);
