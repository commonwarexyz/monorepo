//! Track Gungraun benchmark results in CI.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod config;
mod render;
mod results;
mod runner;

use config::load_config;
use results::{compare, load_baseline, write_outputs};
use runner::run_benchmarks;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
enum Mode {
    Generate,
    Check,
}

#[derive(Parser)]
#[command(name = "benchmark-tracker")]
struct Args {
    #[command(subcommand)]
    mode: Mode,
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long)]
    baseline: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let config = std::fs::read_to_string(&args.config)
        .with_context(|| format!("read `{}`", args.config.display()))?;
    let benchmarks =
        load_config(&config).with_context(|| format!("parse `{}`", args.config.display()))?;
    let current = run_benchmarks(&benchmarks, &args.output_dir)?;

    let comparisons = if args.mode == Mode::Check {
        Some(compare(
            &current,
            &load_baseline(args.baseline.as_deref())?,
        )?)
    } else {
        None
    };
    write_outputs(&args.output_dir, &current, comparisons.as_deref())?;

    println!("benchmark_count: {}", current.len());
    if let Some(comparisons) = comparisons {
        let regressions = comparisons.iter().filter(|item| item.regressed()).count();
        println!("regression_count: {regressions}");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
