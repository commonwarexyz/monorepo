use criterion::criterion_main;

mod e2e;

criterion_main!(e2e::benches);
