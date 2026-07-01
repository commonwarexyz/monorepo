use criterion::criterion_main;

mod hash_message;
mod hash_message_pair;

criterion_main!(hash_message::benches, hash_message_pair::benches);
