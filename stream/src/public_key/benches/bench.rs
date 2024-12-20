mod receiver_receive;
mod sender_send;

use criterion::criterion_main;

criterion_main!(sender_send::benches, receiver_receive::benches,);
