use criterion::criterion_main;

mod commit;

criterion_main!(commit::benches);
