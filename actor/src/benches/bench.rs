use criterion::criterion_main;

mod mailbox;

criterion_main!(mailbox::benches);
