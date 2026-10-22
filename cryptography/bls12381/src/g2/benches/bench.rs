use criterion::criterion_main;

mod hash;

criterion_main!(hash::benches);
