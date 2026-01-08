use clap::Parser;
use commonware_status::validator::Severity;
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(name = "status")]
#[command(about = "Generate module status reports for the Commonware workspace")]
#[command(version)]
struct Cli {
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,

    #[arg(long, short, default_value = "docs/status.json")]
    output: PathBuf,

    #[arg(long, short)]
    verbose: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let repo_root = if cli.repo_root.is_absolute() {
        cli.repo_root
    } else {
        std::env::current_dir()
            .expect("Failed to get current directory")
            .join(&cli.repo_root)
    };

    let output_path = if cli.output.is_absolute() {
        cli.output
    } else {
        repo_root.join(&cli.output)
    };

    let (report, conflicts) = match commonware_status::run(&repo_root) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let json = serde_json::to_string_pretty(&report).expect("Failed to serialize");
    std::fs::write(&output_path, format!("{}\n", json)).expect("Failed to write output");
    println!("Generated {}", output_path.display());

    println!("\nSummary:");
    println!("  Total modules: {}", report.summary.total_modules);
    println!("  By stage: {:?}", report.summary.by_stage);
    println!("  LTS modules: {}", report.summary.lts_count);

    let errors: Vec<_> = conflicts
        .iter()
        .filter(|c| matches!(c.severity, Severity::Error))
        .collect();
    let warnings: Vec<_> = conflicts
        .iter()
        .filter(|c| matches!(c.severity, Severity::Warning))
        .collect();

    if !warnings.is_empty() {
        println!("\nWarnings ({}):", warnings.len());
        for c in &warnings {
            println!("  - {}: {}", c.path, c.message);
        }
    }

    if !errors.is_empty() {
        println!("\nErrors ({}):", errors.len());
        for c in &errors {
            println!("  - {}: {}", c.path, c.message);
        }
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
