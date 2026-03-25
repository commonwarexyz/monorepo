//! Interactive Symbolic Testing (IST) CLI for Simplex consensus.
//!
//! Usage:
//!   cargo run -p commonware-consensus-fuzz --bin ist -- [OPTIONS]
//!
//! Options:
//!   --spec <path>       Path to the Quint spec (default: consensus/quint/itf_n4f1b1.qnt)
//!   --main <module>     Quint main module name (default: itf_main)
//!   --steps <N>         Maximum number of steps (default: 100)
//!   --url <URL>         Apalache server URL (default: http://localhost:8822/rpc)
//!   --compact <N>       Compact solver every N steps (default: 20, 0 = off)
//!   --tla <path>        Path to pre-compiled TLA+ file (skips quint compile)
//!
//! Prerequisites:
//!   - Apalache server running:
//!     `docker run --rm -p 8822:8822 ghcr.io/apalache-mc/apalache:latest server --server-type=explorer`
//!   - `quint` CLI installed

use commonware_consensus_fuzz::ist::{self, IstConfig};
use std::{env, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut cfg = IstConfig::default();

    // Default spec path relative to the fuzz crate
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    cfg.spec_path = format!("{manifest_dir}/../quint/itf_n4f1b1.qnt");

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--spec" => {
                i += 1;
                cfg.spec_path = args.get(i).expect("--spec requires a path").clone();
            }
            "--main" => {
                i += 1;
                cfg.main_module = args.get(i).expect("--main requires a module name").clone();
            }
            "--steps" => {
                i += 1;
                cfg.max_steps = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .expect("--steps requires a number");
            }
            "--url" => {
                i += 1;
                cfg.apalache_url = args.get(i).expect("--url requires a URL").clone();
            }
            "--compact" => {
                i += 1;
                cfg.compact_every = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .expect("--compact requires a number");
            }
            "--tla" => {
                i += 1;
                cfg.tla_path = Some(args.get(i).expect("--tla requires a path").clone());
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    println!("IST Configuration:");
    if let Some(tla) = &cfg.tla_path {
        println!("  tla:     {tla}");
    } else {
        println!("  spec:    {}", cfg.spec_path);
        println!("  main:    {}", cfg.main_module);
    }
    println!("  steps:   {}", cfg.max_steps);
    println!("  url:     {}", cfg.apalache_url);
    println!(
        "  compact: {}",
        if cfg.compact_every > 0 {
            format!("every {} steps", cfg.compact_every)
        } else {
            "off".into()
        }
    );
    println!();

    match ist::run_ist(&cfg) {
        Ok(report) => {
            println!("\n{report}");
            if report.is_ok() {
                println!("PASS: no divergences found");
            } else {
                println!("FAIL: divergences detected");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("IST failed: {e}");
            process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!(
        "Usage: ist [OPTIONS]\n\n\
         Options:\n\
         \x20 --spec <path>     Quint spec path (default: consensus/quint/itf_n4f1b1.qnt)\n\
         \x20 --main <module>   Quint main module (default: itf_main)\n\
         \x20 --steps <N>       Max steps (default: 100)\n\
         \x20 --url <URL>       Apalache URL (default: http://localhost:8822/rpc)\n\
         \x20 --compact <N>     Compact every N steps (default: 20, 0=off)\n\
         \x20 --tla <path>      Pre-compiled TLA+ file (skips quint compile)\n\
         \x20 --help            Show this help"
    );
}
