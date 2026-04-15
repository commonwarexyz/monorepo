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
mod runner;
mod workload;

use crate::{
    config::{Config, OutputFormat},
    filesystem::{cleanup_root, prepare_root},
    runner::ResultExt,
    workload::run_benchmark,
};
use commonware_runtime::{tokio, Runner as _};

fn main() -> Result<(), String> {
    let cfg = Config::parse();
    let workload = cfg.workload.to_string();

    let root = prepare_root(&cfg.root, &workload).str_err()?;

    let mut runtime_cfg = tokio::Config::default()
        .with_worker_threads(cfg.worker_threads)
        .with_storage_directory(root.clone());

    if let Some(global_queue_interval) = cfg.global_queue_interval {
        runtime_cfg = runtime_cfg.with_global_queue_interval(global_queue_interval);
    }

    let report = tokio::Runner::new(runtime_cfg)
        .start(|context| async { run_benchmark(&cfg, &root, context).await });

    cleanup_root(&root);

    match cfg.output {
        OutputFormat::Human => report?.print_human(&cfg),
        OutputFormat::Json => report?.print_json(&cfg),
    }
    Ok(())
}
