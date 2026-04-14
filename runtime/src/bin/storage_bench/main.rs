//! Standalone harness for benchmarking the runtime storage backend.
//!
//! This binary exercises the storage implementation selected by normal runtime
//! feature compilation under a small set of workload shapes that are useful for
//! profiling:
//! - steady-state sequential reads and writes on fixed-size files
//! - steady-state random reads and writes on fixed-size files
//! - append-only writes on a growing file
//! - mixed append-plus-read pressure with one writer and many readers

mod config;
mod filesystem;
mod report;
mod workers;
mod workloads;

use crate::{
    config::{Config, OutputFormat},
    filesystem::{cleanup_root, prepare_root},
    report::{print_human_report, print_json_report},
    workloads::run_benchmark,
};
use commonware_runtime::{tokio, Runner as _};
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

    let root = match prepare_root(&cfg.root, cfg.scenario.name()) {
        Ok(root) => root,
        Err(err) => {
            eprintln!("failed to create benchmark root: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut runtime_cfg = tokio::Config::default()
        .with_worker_threads(cfg.worker_threads)
        .with_storage_directory(root.clone());

    if let Some(global_queue_interval) = cfg.global_queue_interval {
        runtime_cfg = runtime_cfg.with_global_queue_interval(global_queue_interval);
    }

    let result = tokio::Runner::new(runtime_cfg)
        .start(|context| async { run_benchmark(&cfg, &root, context).await });

    cleanup_root(&root);

    let report = match result {
        Ok(report) => report,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };

    match cfg.output {
        OutputFormat::Human => print_human_report(&cfg, &report),
        OutputFormat::Json => print_json_report(&cfg, &report),
    }
    ExitCode::SUCCESS
}
