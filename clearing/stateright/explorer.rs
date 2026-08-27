#[allow(dead_code, unused_imports)]
mod certification;
#[allow(dead_code, unused_imports)]
mod challenge;
#[allow(dead_code, unused_imports)]
mod claims;
#[allow(dead_code, unused_imports)]
mod settlement;

use std::{env, process::ExitCode};

const DEFAULT_ADDRESS: &str = "127.0.0.1:3000";

fn usage(program: &str) {
    eprintln!("Usage: {program} <certification|challenge|claims|settlement> [address]");
}

fn main() -> ExitCode {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "bajillion_model".to_string());
    let Some(component) = args.next() else {
        usage(&program);
        return ExitCode::FAILURE;
    };
    let address = args.next().unwrap_or_else(|| DEFAULT_ADDRESS.to_string());
    if args.next().is_some() {
        usage(&program);
        return ExitCode::FAILURE;
    }

    eprintln!("Exploring Bajillion {component} at http://{address}");
    match component.as_str() {
        "certification" => certification::explore(&address),
        "challenge" => challenge::explore(&address),
        "claims" => claims::explore(&address),
        "settlement" => settlement::explore(&address),
        _ => {
            usage(&program);
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
