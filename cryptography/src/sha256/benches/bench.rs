use criterion::criterion_main;

mod digest_pair;
mod hash_message;

criterion_main!(digest_pair::benches, hash_message::benches);
