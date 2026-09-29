use criterion::criterion_main;

#[path = "../../benches/hash_workloads.rs"]
mod hash_workloads;

mod concurrent;
mod hash_many;
mod hash_many_parts;
mod hash_message;
mod hash_pair;
mod hash_with;

criterion_main!(
    hash_message::benches,
    hash_many::benches,
    hash_many_parts::benches,
    hash_pair::benches,
    concurrent::benches,
    hash_with::benches
);
