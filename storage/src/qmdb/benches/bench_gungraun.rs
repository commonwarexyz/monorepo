//! Gungraun benchmark entry point for all tracked QMDB benchmarks.

cfg_if::cfg_if! {
    if #[cfg(not(benchmark_tracking))] {
        fn main() {}
    } else {
        #[allow(dead_code, unused_imports, unused_macros)]
        mod common;

        #[allow(dead_code, unused_imports, unused_macros)]
        mod merkleize;

        #[allow(dead_code, unused_imports, unused_macros)]
        mod merkleize_gungraun;
        use merkleize_gungraun::qmdb_merkleize;

        gungraun::main!(
            config = gungraun::LibraryBenchmarkConfig::default().tool(
                gungraun::Callgrind::with_args(["--collect-atstart=no", "--cache-sim=yes"])
                    .entry_point(gungraun::EntryPoint::None),
            ).pass_through_env(commonware_bench::METRICS_PATH_ENV);
            library_benchmark_groups = qmdb_merkleize
        );
    }
}
