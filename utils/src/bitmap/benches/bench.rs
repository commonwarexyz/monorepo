use criterion::criterion_main;

mod count_ones;

criterion_main!(count_ones::benches);
