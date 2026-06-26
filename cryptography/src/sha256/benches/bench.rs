use criterion::criterion_main;

mod fixed;
mod hash_message;

criterion_main!(hash_message::benches, fixed::benches);
