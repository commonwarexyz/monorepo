//! Standalone harness for benchmarking the runtime storage backend.
//!
//! This binary exercises the storage implementation of the runtime selected
//! with `--backend` under a small set of workload shapes that are useful for
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
    config::{Backend, Config, OutputFormat},
    error::Result,
    filesystem::{cleanup_root, prepare_root},
    report::Report,
    workload::run_benchmark,
};
use commonware_allocator::mimalloc;
#[cfg(target_os = "linux")]
use commonware_runtime::iouring;
use commonware_runtime::{Runner as _, tokio};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

fn main() -> Result<()> {
    let mut cfg = Config::parse();
    cfg.root = prepare_root(&cfg.root)?;

    let report = match cfg.backend {
        Backend::Tokio => run_tokio(&cfg),
        #[cfg(target_os = "linux")]
        Backend::Iouring => run_iouring(&cfg),
        #[cfg(not(target_os = "linux"))]
        Backend::Iouring => unreachable!("validation rejects io_uring off Linux"),
    };

    cleanup_root(&cfg.root)?;

    match cfg.output {
        OutputFormat::Human => report?.print_human(&cfg),
        OutputFormat::Json => report?.print_json(&cfg),
    }

    Ok(())
}

/// Run the benchmark on the Tokio runtime.
fn run_tokio(cfg: &Config) -> Result<Report> {
    let mut runtime_cfg = tokio::Config::default()
        .with_worker_threads(cfg.worker_threads())
        .with_storage_directory(cfg.root.clone());
    if let Some(global_queue_interval) = cfg.global_queue_interval {
        runtime_cfg = runtime_cfg.with_global_queue_interval(global_queue_interval);
    }
    tokio::Runner::new(runtime_cfg).start(|context| run_benchmark(cfg, context))
}

/// Run the benchmark on the io_uring runtime.
#[cfg(target_os = "linux")]
fn run_iouring(cfg: &Config) -> Result<Report> {
    let mut runtime_cfg = iouring::Config::default()
        .with_worker_threads(cfg.worker_threads())
        .with_storage_directory(cfg.root.clone())
        .with_ring_config(iouring::RingConfig {
            size: cfg.effective_ring_size().unwrap(),
            ..Default::default()
        });
    if let Some(global_queue_interval) = cfg.global_queue_interval {
        runtime_cfg = runtime_cfg.with_global_queue_interval(global_queue_interval);
    }
    iouring::Runner::new(runtime_cfg).start(|context| run_benchmark(cfg, context))
}
