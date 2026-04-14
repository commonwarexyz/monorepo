//! Standalone harness for benchmarking the runtime-selected storage backend.
//!
//! This binary exercises the storage implementation selected by normal runtime
//! feature compilation under a small set of workload shapes that are useful for
//! profiling:
//! - steady-state sequential reads and writes on fixed-size files
//! - steady-state random reads and writes on fixed-size files
//! - append-only writes on a growing file
//! - mixed append-plus-read pressure with one writer and many readers
//!
//! One backend is compiled into each binary. This keeps every run aligned with
//! the runtime's real storage setup and easy to profile with tools like
//! `perf stat` or `perf record`.

mod config;
mod environment;
mod helpers;
mod report;
mod scenarios;

use crate::{
    config::{Config, OutputFormat},
    environment::Environment,
    report::{print_human_report, print_json_report},
    scenarios::run_benchmark,
};
use commonware_runtime::Runner as _;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cfg = match Config::parse_from(std::env::args_os()) {
        Ok(cfg) => cfg,
        Err(err) => {
            let _ = err.print();
            return if err.should_exit_success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
    };

    let environment = match Environment::new(cfg.scenario.name(), &cfg.root) {
        Ok(environment) => environment,
        Err(err) => {
            eprintln!("failed to create benchmark root: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut runtime_cfg = commonware_runtime::tokio::Config::default()
        .with_worker_threads(cfg.worker_threads)
        .with_storage_directory(environment.root().to_path_buf());
    if let Some(global_queue_interval) = cfg.global_queue_interval {
        runtime_cfg = runtime_cfg.with_global_queue_interval(global_queue_interval);
    }
    let report = match commonware_runtime::tokio::Runner::new(runtime_cfg)
        .start(|context| async { run_benchmark(&cfg, &environment, context).await })
    {
        Ok(report) => report,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };

    match cfg.output {
        OutputFormat::Human => print_human_report(&cfg, &environment, &report),
        OutputFormat::Json => print_json_report(&cfg, &environment, &report),
    }
    ExitCode::SUCCESS
}
