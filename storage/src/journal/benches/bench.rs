use criterion::criterion_main;

mod fixed_read;
mod fixed_write;

criterion_main!(fixed_write::benches, fixed_read::benches);
