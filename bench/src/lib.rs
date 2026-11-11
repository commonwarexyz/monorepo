#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(ALPHA {
    use std::{
        collections::BTreeMap,
        ffi::OsString,
        future::Future,
        hint::black_box,
        sync::LazyLock,
        time::{Duration, Instant},
    };
    #[cfg(feature = "gungraun")]
    use std::{env, fs, io::Write};

    /// Environment variable containing a JSONL file for custom benchmark metrics.
    pub const METRICS_PATH_ENV: &str = "COMMONWARE_BENCH_METRICS_PATH";

    /// Environment variable that adds the large benchmark inputs when set to `1`.
    pub const FULL_ENV: &str = "COMMONWARE_BENCH_FULL";

    /// Returns whether [`FULL_ENV`] is set to `1`, so benchmarks add their large inputs.
    pub fn full() -> bool {
        static FULL: LazyLock<bool> =
            LazyLock::new(|| std::env::var_os(FULL_ENV).is_some_and(|value| value == "1"));
        *FULL
    }

    /// Returns whether Criterion runs each benchmark once instead of measuring it, as under
    /// `cargo test --benches`.
    ///
    /// Benchmarks check this to use their smallest inputs when nothing is measured. Measuring
    /// and listing (`--list`) return `false`, so both see the regular inputs. It also returns
    /// `false` when [`full`] is set, so `cargo test --benches` then runs the large inputs once.
    pub fn smoke() -> bool {
        static SMOKE: LazyLock<bool> =
            LazyLock::new(|| !full() && criterion_test_mode(std::env::args_os().skip(1)));
        *SMOKE
    }

    /// Mirrors the mode selection in Criterion's `configure_from_args`, where arguments after
    /// `--` are filters.
    fn criterion_test_mode(args: impl IntoIterator<Item = OsString>) -> bool {
        let (mut bench, mut test, mut list) = (false, false, false);
        for arg in args {
            match arg.to_str() {
                Some("--") => break,
                Some("--bench") => bench = true,
                Some("--test") => test = true,
                Some("--list") => list = true,
                _ => {}
            }
        }
        !list && (!bench || test)
    }

    /// A named benchmark configuration shared by Criterion and Gungraun.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Benchmark {
        name: String,
    }

    impl Benchmark {
        /// Create a benchmark from a Commonware benchmark prefix.
        pub fn new(prefix: impl Into<String>) -> Self {
            Self {
                name: prefix.into(),
            }
        }

        /// Append one `key=value` parameter to the benchmark name.
        pub fn with_param(mut self, key: &str, value: impl ToString) -> Self {
            if !self.name.contains('/') {
                self.name.push('/');
            } else {
                self.name.push(' ');
            }
            self.name.push_str(key);
            self.name.push('=');
            self.name.push_str(&value.to_string());
            self
        }

        /// Return the full benchmark name.
        pub fn name(&self) -> &str {
            &self.name
        }

        /// Run a workload with Criterion's `iter_custom` timing model.
        pub async fn criterion<W>(&self, mut workload: W, iters: u64) -> Duration
        where
            W: Workload,
        {
            workload.setup().await;

            let mut total = Duration::ZERO;
            for _ in 0..iters {
                workload.before_iter().await;

                let start = Instant::now();
                let output = workload.iter().await;
                black_box(output);
                total += start.elapsed();
            }

            workload.teardown().await;
            total
        }

        /// Run one workload iteration with Callgrind collection enabled only
        /// around the timed work.
        #[cfg(feature = "gungraun")]
        pub async fn gungraun<W>(&self, mut workload: W) -> W::Output
        where
            W: Workload,
        {
            workload.setup().await;
            workload.before_iter().await;

            gungraun::client_requests::callgrind::toggle_collect();
            let output = workload.iter().await;
            gungraun::client_requests::callgrind::toggle_collect();

            self.emit_metrics(&workload.metrics());

            workload.teardown().await;
            black_box(output)
        }

        /// Format custom benchmark metrics as one benchmark-tracking JSON object.
        pub fn metrics_json(&self, metrics: &[Metric]) -> serde_json::Value {
            let mut values = BTreeMap::new();
            for metric in metrics {
                values.insert(metric.name.as_str(), metric.value);
            }

            serde_json::json!({
                "commonware_bench_metrics": true,
                "benchmark": self.name(),
                "metrics": values,
            })
        }

        #[cfg(feature = "gungraun")]
        fn emit_metrics(&self, metrics: &[Metric]) {
            let line = self.metrics_json(metrics).to_string();
            let Ok(path) = env::var(METRICS_PATH_ENV) else {
                return;
            };
            if let Some(parent) = std::path::Path::new(&path).parent() {
                fs::create_dir_all(parent)
                    .unwrap_or_else(|err| panic!("failed to create benchmark metrics directory `{}`: {err}", parent.display()));
            }
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap_or_else(|err| panic!("failed to open benchmark metrics file `{path}`: {err}"));
            writeln!(file, "{line}")
                .unwrap_or_else(|err| panic!("failed to write benchmark metrics file `{path}`: {err}"));
        }
    }

    /// A custom metric emitted by a benchmark workload.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Metric {
        /// Metric name.
        pub name: String,
        /// Metric value.
        pub value: u64,
    }

    impl Metric {
        /// Create a metric.
        pub fn new(name: impl Into<String>, value: u64) -> Self {
            Self {
                name: name.into(),
                value,
            }
        }
    }

    /// A benchmark workload shared by Criterion and Gungraun harnesses.
    pub trait Workload {
        /// Output from a timed iteration.
        type Output;

        /// Prepare the benchmark state.
        fn setup(&mut self) -> impl Future<Output = ()> {
            async {}
        }

        /// Prepare one iteration without timing it.
        fn before_iter(&mut self) -> impl Future<Output = ()> {
            async {}
        }

        /// Run one timed benchmark iteration.
        fn iter(&mut self) -> impl Future<Output = Self::Output>;

        /// Tear down the benchmark state.
        fn teardown(&mut self) -> impl Future<Output = ()> {
            async {}
        }

        /// Return custom metrics sampled after a timed iteration.
        fn metrics(&self) -> Vec<Metric> {
            Vec::new()
        }
    }
});

#[cfg(test)]
mod tests {
    use crate::{Benchmark, Metric, criterion_test_mode};
    use std::ffi::OsString;

    #[test]
    fn detects_criterion_test_mode() {
        let cases: &[(&[&str], bool)] = &[
            (&[], true),
            (&["--verbose"], true),
            (&["--bench"], false),
            (&["--bench", "--test"], true),
            (&["--list"], false),
            (&["--bench", "--list"], false),
            (&["--bench", "--profile-time", "5"], false),
            (&["--profile-time", "5"], true),
            (&["--", "--bench"], true),
            (&["--bench", "--", "--test"], false),
            (&["--bench", "--", "--list"], false),
        ];
        for &(args, expected) in cases {
            let mode = criterion_test_mode(args.iter().map(OsString::from));
            assert_eq!(mode, expected, "{args:?}");
        }
    }

    #[test]
    fn formats_dynamic_name() {
        let benchmark = Benchmark::new("qmdb::merkleize")
            .with_param("variant", "any::unordered::fixed::mmr")
            .with_param("keys", 10_000)
            .with_param("ch", false);

        assert_eq!(
            benchmark.name(),
            "qmdb::merkleize/variant=any::unordered::fixed::mmr keys=10000 ch=false"
        );
    }

    #[test]
    fn formats_metric_json_line() {
        let metrics = Benchmark::new("qmdb::merkleize")
            .with_param("variant", "a")
            .metrics_json(&[Metric::new("updates", 100), Metric::new("keys", 1_000)]);

        assert_eq!(
            metrics.to_string(),
            "{\"benchmark\":\"qmdb::merkleize/variant=a\",\"commonware_bench_metrics\":true,\"metrics\":{\"keys\":1000,\"updates\":100}}"
        );
    }
}
