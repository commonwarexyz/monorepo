use criterion::criterion_main;

mod commit;
mod open;
mod verify;

criterion_main!(commit::benches, open::benches, verify::benches,);
