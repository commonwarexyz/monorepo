use criterion::criterion_main;

mod append;
mod append_additional;
mod update;

criterion_main!(append::benches, append_additional::benches, update::benches,);
