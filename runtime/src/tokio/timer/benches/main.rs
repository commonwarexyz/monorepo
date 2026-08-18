//! Standalone harness for measuring production Tokio timer behavior.
//!
//! The harness compares sleeps through the real Commonware
//! [`commonware_runtime::Clock`] with direct `tokio::time` sleeps. It reports
//! explicit latency distributions because synchronized timer workloads are not
//! well represented by a Criterion iteration loop.

mod accuracy;
mod config;
mod report;
mod utils;
mod worst_case;

use commonware_runtime::{Runner as _, tokio as commonware_tokio};
pub(crate) use config::{Backend, Config};
use std::{error::Error, io};

/// Parses configuration and runs the selected production timer workloads.
fn main() -> Result<(), Box<dyn Error>> {
    let Some(config) = Config::parse() else {
        return Ok(());
    };
    if config.scenario.runs_accuracy() || config.scenario.runs_contention() {
        let runtime = commonware_tokio::Runner::new(
            commonware_tokio::Config::default().with_worker_threads(config.worker_threads),
        );
        runtime.start(|context| async {
            report::print_effective_config(
                &config,
                "configured",
                config.worker_threads,
                config.shards(),
            );
            let clock = std::sync::Arc::new(context);

            if config.scenario.runs_accuracy() {
                accuracy::run(&config, std::sync::Arc::clone(&clock)).await?;
            }
            if config.scenario.runs_contention() {
                worst_case::run_contention(&config, clock).await?;
            }
            Ok::<_, io::Error>(())
        })?;
    }

    // Fairness uses one worker so the timer driver and runnable peer must
    // cooperate on the same executor regardless of the main configuration.
    if config.scenario.runs_expiry() {
        let shards = cfg!(any(target_os = "linux", target_os = "macos")).then_some(1);
        report::print_effective_config(&config, "expiry", 1, shards);
        worst_case::run_fairness(&config)?;
    }
    Ok(())
}
