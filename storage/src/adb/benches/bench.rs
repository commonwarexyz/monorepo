use criterion::criterion_main;

mod any_init;
mod current_init;

criterion_main!(any_init::benches, current_init::benches);
