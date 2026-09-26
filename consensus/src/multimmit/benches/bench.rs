//! Multimmit benchmarks: signature verification and assembly, the private core, the journal,
//! marshal intake, and the whole-engine profile.

use criterion::criterion_main;

mod aggregate;
mod assemble;
mod common;
mod engine;
mod journal;
mod machine;
mod marshal;
mod ordinary;
mod recover;
mod shares;

criterion_main!(
    ordinary::benches,
    shares::benches,
    recover::benches,
    aggregate::benches,
    assemble::benches,
    machine::benches,
    journal::benches,
    marshal::benches,
    engine::benches,
);
