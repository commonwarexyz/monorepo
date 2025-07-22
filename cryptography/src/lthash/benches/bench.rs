use criterion::criterion_main;

mod add;
mod combine;
mod finalize;
mod subtract;
mod update;

criterion_main!(
    add::benches,
    subtract::benches,
    combine::benches,
    finalize::benches,
    update::benches
);
