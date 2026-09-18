//! ABI reference inputs for Solidity differential tests.

use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod bmt;
mod certificate;
mod merkle;
mod simplex;

/// Hash function used by the tree proof oracle.
#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum Hash {
    Sha256,
    Keccak,
}

#[derive(Parser)]
#[command(about = "Generate and verify Commonware test inputs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Binary Merkle Tree proofs.
    Bmt {
        #[arg(long, value_enum)]
        hash: Hash,
        #[command(subcommand)]
        command: bmt::Command,
    },
    /// BLS12-381 certificates and hash-to-curve points.
    #[command(subcommand)]
    Certificate(certificate::Command),
    /// MMR and MMB proofs.
    Merkle {
        #[arg(long, value_enum)]
        hash: Hash,
        #[command(subcommand)]
        command: merkle::Command,
    },
    /// Simplex signatures.
    #[command(subcommand)]
    Simplex(simplex::Command),
}

impl Command {
    fn execute(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Bmt { hash, command } => command.execute(hash),
            Self::Certificate(command) => command.execute(),
            Self::Merkle { hash, command } => command.execute(hash),
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
