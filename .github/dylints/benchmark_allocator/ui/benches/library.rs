// compile-flags: --edition=2021 --crate-type=lib

// A library in a `benches` directory is not a benchmark.
pub fn helper() {}
