use criterion::criterion_main;

mod hash_message;
mod hash_pair;

criterion_main!(hash_message::benches, hash_pair::benches);
