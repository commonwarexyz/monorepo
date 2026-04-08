use criterion::{criterion_group, criterion_main};

mod ping_pong;

criterion_group!(benches, ping_pong::bench);

criterion_main!(benches);
