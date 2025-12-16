use criterion::criterion_main;

mod fixed;
mod keyless_generate;
mod variable;

criterion_main!(
    fixed::generate::benches,
    fixed::init::benches,
    keyless_generate::benches,
    variable::generate::benches,
    variable::init::benches,
);
