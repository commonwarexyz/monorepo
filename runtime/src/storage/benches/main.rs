//! Standalone harness for benchmarking the runtime storage backend.
//!
//! This binary exercises the storage implementation selected by normal runtime
//! feature compilation under a small set of workload shapes that are useful for
//! profiling:
//! - steady-state sequential reads and writes on fixed-size files
//! - steady-state random reads and writes on fixed-size files
//! - append-only writes on a growing file
//! - durable positioned writes comparing sync strategies
//! - mixed append-plus-read pressure with one writer and many readers

mod config;
mod error;
mod filesystem;
mod report;
mod runner;
mod workload;

use crate::{
    config::{Config, OutputFormat},
    error::Result,
    filesystem::{cleanup_root, prepare_root},
    workload::run_benchmark,
};
use commonware_runtime::{tokio, Runner as _};

fn main() -> Result<()> {
    let mut cfg = Config::parse();
    cfg.root = prepare_root(&cfg.root)?;

    let mut runtime_cfg = tokio::Config::default()
        .with_worker_threads(cfg.worker_threads)
        .with_storage_directory(cfg.root.clone());

    if let Some(global_queue_interval) = cfg.global_queue_interval {
        runtime_cfg = runtime_cfg.with_global_queue_interval(global_queue_interval);
    }

    let report = tokio::Runner::new(runtime_cfg)
        .start(|context| async { run_benchmark(&cfg, context).await });

    cleanup_root(&cfg.root)?;

    match cfg.output {
        OutputFormat::Human => report?.print_human(&cfg),
        OutputFormat::Json => report?.print_json(&cfg),
    }

    Ok(())
}
