use criterion::criterion_main;

mod restart;

criterion_main!(restart::benches);
