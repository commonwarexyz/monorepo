use criterion::criterion_main;

mod actor_mailbox;

criterion_main!(actor_mailbox::benches);
