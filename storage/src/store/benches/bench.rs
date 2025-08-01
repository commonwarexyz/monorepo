use criterion::criterion_main;

mod store_init;

criterion_main!(store_init::benches);
