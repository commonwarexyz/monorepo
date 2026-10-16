//! Multimmit benchmarks: signature verification and certificate assembly, the extraction and
//! ordering algebra, the journal, the machine, marshal custody intake, and whole engines.

use criterion::criterion_main;

mod aggregate;
mod algebra;
mod assemble;
mod common;
mod engine;
mod journal;
mod machine;
mod marshal;
mod ordinary;
mod tally;

criterion_main!(
    ordinary::benches,
    tally::benches,
    aggregate::benches,
    assemble::benches,
    algebra::benches,
    journal::benches,
    machine::benches,
    marshal::benches,
    engine::benches,
);
