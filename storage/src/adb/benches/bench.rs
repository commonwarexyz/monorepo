use criterion::criterion_main;

mod current_init;
mod fixed_generate;
mod fixed_init;
mod keyless_generate;
mod variable_generate;
mod variable_init;

criterion_main!(
    fixed_generate::benches,
    keyless_generate::benches,
    variable_generate::benches,
    fixed_init::benches,
    variable_init::benches,
    current_init::benches,
);
