//! Readiness score linter for the Commonware Library.
//!
//! This tool validates that public items have `#[ready(N)]` annotations
//! and that higher-readiness code only depends on equal or higher readiness items.
//!
//! # Readiness Levels
//!
//! | Level | Description |
//! |-------|-------------|
//! | 0 | Experimental/little testing |
//! | 1 | Decent test coverage, breaking format changes possible with no migration path |
//! | 2 | Wire/storage format stable, decent test coverage |
//! | 3 | API stable, wire/storage format stable, decent test coverage |
//! | 4 | Deployed in production without issue, audited multiple times |
//!
//! # Usage
//!
//! Annotate public structs, enums, functions, and type aliases with `#[ready(N)]`.
//! Traits and constants are excluded from this requirement.

mod parser;
mod validator;

use clap::Parser;
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser, Debug)]
#[command(name = "readiness-lint")]
#[command(about = "Validate readiness score constraints")]
struct Args {
    /// Path to the repository root
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,

    /// Validate readiness constraints (exit with error if violations found)
    #[arg(long)]
    validate: bool,
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

    // Check for missing #[ready(N)] annotations on public items
    let missing = validator::check_missing_annotations(&workspace);
    if !missing.is_empty() {
        eprintln!("Missing #[ready(N)] annotations on public items:");
        for item in &missing {
            eprintln!("  {item}");
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

    ExitCode::SUCCESS
}
