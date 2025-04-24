use criterion::criterion_main;
mod union;

criterion_main!(
  union::benches,
);
