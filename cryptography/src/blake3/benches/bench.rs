use criterion::criterion_main;

mod concurrent;
mod hash_many;
mod hash_message;
mod hash_pair;
mod hash_with;

criterion_main!(
    hash_message::benches,
    hash_many::benches,
    hash_pair::benches,
    concurrent::benches,
    hash_with::benches
);
