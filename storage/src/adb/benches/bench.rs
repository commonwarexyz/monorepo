use criterion::criterion_main;

mod anydb_init;

criterion_main!(anydb_init::benches);
