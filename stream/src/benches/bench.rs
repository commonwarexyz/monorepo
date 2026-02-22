use criterion::criterion_main;

mod steady_state;

criterion_main!(steady_state::benches);
