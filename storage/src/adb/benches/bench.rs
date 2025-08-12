use criterion::criterion_main;

mod fixed_init;
mod variable_init;

criterion_main!(fixed_init::benches, variable_init::benches);
