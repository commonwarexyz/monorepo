use criterion::criterion_main;

#[path = "../../benches/hash_many.rs"]
mod workload;

mod hash_many;

criterion_main!(hash_many::benches);
