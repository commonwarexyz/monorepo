use criterion::criterion_main;

mod fixed;
mod keyless_generate;
mod variable_generate;
mod variable_init;

criterion_main!(
    fixed::generate::benches,
    keyless_generate::benches,
    variable_generate::benches,
    fixed::init::benches,
    variable_init::benches,
);
