use criterion::criterion_main;

mod lazy_get;
mod tx;

criterion_main!(lazy_get::benches);
