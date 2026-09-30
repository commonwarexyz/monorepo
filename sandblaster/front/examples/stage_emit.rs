//! `stage_emit <root.rs> [--target aarch64|x86_64]`: the optimized stage
//! output of a DSL root (`driver::stage::verify_and_optimize`): proofs, the
//! optimizer, the printer and the round trip, **without** the §15 gates.
//! The file carries the header `STATUS: STAGE OUTPUT (not a crate verdict:
//! the §15 gates did not run)`, which no consumer of crate output accepts;
//! only the optimizer corpus's own harness (`bench/opt-corpus/cgen`)
//! accepts it, and only for the corpus root.
//!
//! Exit status 1 when the proofs, the optimizer (in strict mode, from
//! `SANDBLASTER_STRICT_OPT`) or the round trip fail. It is a toolchain tool
//! for the optimizer corpus (`bench/opt-corpus/run.sh`), not a build path:
//! `sandblaster::build::compile` and the CLI's verdict commands go through
//! `driver::build_crate`.
//!
//! ```text
//! cargo run -p sandblaster-front --example stage_emit -- \
//!     sandblaster/front/tests/opt_corpus/dsl/mod.rs --target aarch64 > gen.rs
//! ```

use std::path::Path;
use std::process::ExitCode;

use sandblaster_front::driver::{self, VerifyOptions};
use sandblaster_front::loader::RealFs;
use sandblaster_front::target::TargetInfo;

fn main() -> ExitCode {
    sandblaster_front::memguard::init_from_env();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root = None;
    let mut target = TargetInfo::host();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--target" => match it.next().and_then(|t| TargetInfo::from_name(t)) {
                Some(t) => target = t,
                None => {
                    eprintln!("usage: stage_emit <root.rs> [--target aarch64|x86_64]");
                    return ExitCode::from(2);
                }
            },
            _ if root.is_none() => root = Some(a.clone()),
            _ => {
                eprintln!("usage: stage_emit <root.rs> [--target aarch64|x86_64]");
                return ExitCode::from(2);
            }
        }
    }
    let Some(root) = root else {
        eprintln!("usage: stage_emit <root.rs> [--target aarch64|x86_64]");
        return ExitCode::from(2);
    };
    let c = driver::check(Path::new(&root), &RealFs, &target);
    if !c.ok() {
        eprintln!("{}", c.render());
        return ExitCode::from(1);
    }
    let oopts = sandblaster_front::opt::OptOptions::from_env();
    let built = driver::stage::verify_and_optimize(&c, &VerifyOptions::default(), &oopts, &root);
    let diags = built.v.diags.render(&c.sm);
    if !diags.is_empty() {
        eprintln!("{diags}");
    }
    let em = match built.emit {
        Some(Ok(em)) if built.v.proofs_ok => em,
        Some(Err(e)) => {
            eprintln!("error: optimization failed: {e}");
            return ExitCode::from(1);
        }
        _ => {
            eprintln!("error: the proofs of `{root}` did not check");
            return ExitCode::from(1);
        }
    };
    for w in &em.opt.warnings {
        eprintln!("warning[optimizer]: {w}");
    }
    let bad: Vec<String> = em.opt.errors.iter().map(|e| format!("error[optimizer]: {e}")).chain(em.roundtrip.iter().map(|e| format!("error[round-trip]: {e}"))).collect();
    if !bad.is_empty() {
        for b in &bad {
            eprintln!("{b}");
        }
        return ExitCode::from(1);
    }
    print!("{}", em.code);
    ExitCode::SUCCESS
}
