use criterion::criterion_main;

mod seal_open;

criterion_main!(seal_open::benches);
