use criterion::criterion_main;

mod put;

criterion_main!(put::benches);
