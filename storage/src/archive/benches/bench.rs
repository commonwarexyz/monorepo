mod hashmap_iteration;
mod hashmap_load;
mod hashmap_load_fixed;

use criterion::criterion_main;

criterion_main!(
    hashmap_iteration::benches,
    hashmap_load_fixed::benches,
    hashmap_load::benches,
);
