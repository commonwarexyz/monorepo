//! Readiness score linter for the Commonware Library.
//!
//! This tool validates that modules don't depend on less-ready modules
//! and generates readiness.json for the documentation page.
//!
//! # What This Tool Tracks
//!
//! This tool tracks Rust **modules** (`mod` declarations), not individual types,
//! traits, or functions. All items within a module share the same readiness level.
//! For example, `simplex::elector` appears as a single module even though it
//! contains multiple types like `RoundRobin` and `Random`.
//!
//! To track items at finer granularity, split them into separate submodules
//! (e.g., `elector/round_robin.rs` and `elector/random.rs`).
//!
//! # Readiness Levels
//!
//! - **0**: Experimental/little testing (default)
//! - **1**: Decent test coverage, breaking format changes possible
//! - **2**: Decent test coverage, wire/storage format stable
//! - **3**: Levels 1+2, API stable
//! - **4**: Production-deployed, audited multiple times
//!
//! # Usage
//!
//! Annotate modules with `commonware_macros::readiness!(N)` where N is 0-4.
//! Submodules inherit their parent's readiness level unless explicitly annotated.

mod output;
mod parser;
mod validator;

use clap::Parser;
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser, Debug)]
#[command(name = "readiness-lint")]
#[command(about = "Validate readiness score constraints and generate documentation")]
struct Args {
    /// Path to the repository root
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,

    /// Validate readiness constraints (exit with error if violations found)
    #[arg(long)]
    validate: bool,

    /// Output path for readiness.json
    #[arg(long)]
    output: Option<PathBuf>,

    /// Check that existing readiness.json is up-to-date
    #[arg(long)]
    check: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    // Load config from .readiness.toml
    let config = match parser::Config::load(&args.repo_root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error loading config: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Parse the workspace to find all modules and their readiness levels
    let workspace = match parser::parse_workspace(&args.repo_root, &config) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Error parsing workspace: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Check for crate-level readiness (prohibited)
    let crate_level_violations = validator::check_crate_level_readiness(&workspace);
    if !crate_level_violations.is_empty() {
        eprintln!("Crate-level readiness!() is prohibited. Move items to modules:");
        for (crate_name, path) in &crate_level_violations {
            eprintln!("  {crate_name}: {}", path.display());
        }
        return ExitCode::FAILURE;
    }

    // Validate constraints if requested
    if args.validate {
        let violations = validator::validate(&workspace);
        if !violations.is_empty() {
            eprintln!("Readiness constraint violations found:");
            for violation in &violations {
                eprintln!("  {violation}");
            }
            return ExitCode::FAILURE;
        }
        println!("All readiness constraints satisfied.");
    }

    // Generate output if requested
    if let Some(output_path) = args.output {
        if let Err(e) = output::generate(&workspace, &output_path) {
            eprintln!("Error generating output: {e}");
            return ExitCode::FAILURE;
        }
        println!("Generated {}", output_path.display());
    }

    // Check if existing output is up-to-date
    if let Some(check_path) = args.check {
        match output::check(&workspace, &check_path) {
            Ok(true) => {
                println!("{} is up-to-date.", check_path.display());
            }
            Ok(false) => {
                eprintln!(
                    "{} is out-of-date. Run with --output {} to regenerate.",
                    check_path.display(),
                    check_path.display()
                );
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("Error checking {}: {e}", check_path.display());
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}
