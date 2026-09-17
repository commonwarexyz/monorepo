//! ABI reference inputs for Solidity differential tests.

use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod merkle;
mod simplex;

#[derive(Parser)]
#[command(about = "Generate and verify Commonware test inputs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// MMR and MMB proofs.
    #[command(subcommand)]
    Merkle(merkle::Command),
    /// Simplex threshold signatures and hash-to-curve points.
    #[command(subcommand)]
    Simplex(simplex::Command),
}

impl Command {
    fn execute(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Merkle(command) => command.execute(),
            Self::Simplex(command) => command.execute(),
        }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command.execute() {
        Ok(encoded) => {
            println!("0x{}", const_hex::encode(encoded));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}
