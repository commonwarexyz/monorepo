use criterion::criterion_main;

mod contains;

criterion_main!(contains::benches);
