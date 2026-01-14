//! Readiness score linter for the Commonware Library.
//!
//! This tool validates that modules don't depend on less-ready modules
//! and generates readiness.json for the documentation page.

mod analyzer;
mod output;
mod parser;
mod validator;

use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

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
}

fn main() -> ExitCode {
    let args = Args::parse();

    // Parse the workspace to find all modules and their readiness levels
    let workspace = match parser::parse_workspace(&args.repo_root) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Error parsing workspace: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Analyze dependencies
    let dependencies = match analyzer::analyze(&workspace) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error analyzing dependencies: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Validate constraints if requested
    if args.validate {
        let violations = validator::validate(&workspace, &dependencies);
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

    ExitCode::SUCCESS
}
