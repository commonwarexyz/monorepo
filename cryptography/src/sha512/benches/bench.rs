use criterion::criterion_main;

mod hash_many;

criterion_main!(hash_many::benches);
