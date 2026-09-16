#[allow(dead_code)]
mod withdrawal;

use stateright::Model;
use std::{env, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args();
    let program = arguments
        .next()
        .unwrap_or_else(|| "terminal_withdrawal_model".to_string());
    let address = arguments
        .next()
        .unwrap_or_else(|| "127.0.0.1:8089".to_string());
    if arguments.next().is_some() {
        eprintln!("Usage: {program} [address]");
        return ExitCode::FAILURE;
    }
    eprintln!("Exploring native withdrawal lifecycle at http://{address}");
    withdrawal::WithdrawalModel::default()
        .checker()
        .serve(&address);
    ExitCode::SUCCESS
}
