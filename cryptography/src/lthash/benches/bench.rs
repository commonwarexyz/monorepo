use criterion::criterion_main;

mod add;
mod combine;
mod finalize;
mod incremental_vs_full;
mod subtract;

criterion_main!(
    add::benches,
    subtract::benches,
    combine::benches,
    finalize::benches,
    incremental_vs_full::benches
);