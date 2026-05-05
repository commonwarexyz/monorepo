use criterion::criterion_main;

mod count_ones;
mod write;

criterion_main!(count_ones::benches, write::benches);
