use criterion::criterion_main;

mod init;

criterion_main!(init::benches);
