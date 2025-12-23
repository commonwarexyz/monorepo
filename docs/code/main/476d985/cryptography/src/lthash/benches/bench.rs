use criterion::criterion_main;

mod add;
mod checksum;
mod combine;
mod subtract;
mod update;

criterion_main!(
    add::benches,
    subtract::benches,
    combine::benches,
    checksum::benches,
    update::benches
);
