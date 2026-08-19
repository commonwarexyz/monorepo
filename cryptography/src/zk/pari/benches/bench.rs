use criterion::criterion_main;

mod pari;

criterion_main!(pari::benches);
