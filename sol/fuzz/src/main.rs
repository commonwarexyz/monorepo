//! ABI reference inputs for Solidity differential tests.

use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod bmt;
mod certificate;
mod merkle;
mod multisig;
mod simplex;

/// Hash function used by the tree proof oracle.
#[derive(Clone, Copy, Default, clap::ValueEnum)]
pub(crate) enum Hash {
    Sha256,
    #[default]
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
    #[command(subcommand)]
    Bmt(bmt::Command),
    /// BLS12-381 threshold certificates and hash-to-curve points.
    #[command(subcommand)]
    Certificate(certificate::Command),
    /// MMR and MMB proofs.
    #[command(subcommand)]
    Merkle(merkle::Command),
    /// BLS12-381 multi-signatures.
    #[command(subcommand)]
    Multisig(multisig::Command),
    /// Simplex threshold and multi-signatures.
    #[command(subcommand)]
    Simplex(simplex::Command),
}

impl Command {
    fn execute(self) -> Result<Vec<u8>, String> {
        match self {
            Self::Bmt(command) => command.execute(),
            Self::Certificate(command) => command.execute(),
            Self::Merkle(command) => command.execute(),
            Self::Multisig(command) => command.execute(),
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
