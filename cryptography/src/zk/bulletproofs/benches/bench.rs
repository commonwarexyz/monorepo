use criterion::criterion_main;

mod ipa;

criterion_main!(ipa::benches);
