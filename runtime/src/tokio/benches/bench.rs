use criterion::{criterion_group, criterion_main};

mod oneshot_round_trip;
mod ping_pong;
mod ping_pong_unbounded;

criterion_group!(
    benches,
    oneshot_round_trip::bench,
    ping_pong::bench,
    ping_pong_unbounded::bench
);

criterion_main!(benches);
