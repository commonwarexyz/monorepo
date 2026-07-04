use criterion::criterion_main;

mod mailbox;
mod throughput;

criterion_main!(mailbox::benches, throughput::benches);
