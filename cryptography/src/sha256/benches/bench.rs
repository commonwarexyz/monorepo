use criterion::criterion_main;

mod hash_many;
mod hash_message;

criterion_main!(hash_message::benches, hash_many::benches);
