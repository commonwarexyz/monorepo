use criterion::criterion_main;

mod hash_message;

criterion_main!(hash_message::benches);
