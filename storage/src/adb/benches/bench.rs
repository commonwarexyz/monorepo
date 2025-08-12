use criterion::criterion_main;

mod current_init;
mod fixed_init;
mod variable_init;

criterion_main!(
    fixed_init::benches,
    variable_init::benches,
    current_init::benches
);
