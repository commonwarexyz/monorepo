use criterion::criterion_main;

mod any_init;

criterion_main!(any_init::benches);
