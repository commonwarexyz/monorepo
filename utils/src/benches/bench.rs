use criterion::criterion_main;
mod union;
mod u64;



criterion_main!(
  union::benches,
  u64::benches,
);
