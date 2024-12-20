use criterion::criterion_main;

mod receiver_receive;
mod sender_send;

criterion_main!(sender_send::benches, receiver_receive::benches);
