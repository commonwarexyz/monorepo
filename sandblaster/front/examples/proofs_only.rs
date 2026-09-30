//! `proofs_only <root.rs> [--dump-lift DIR]`: the front end and the proofs
//! of a DSL root (`driver::check` + `driver::stage::verify_audited`), no
//! optimizer and no §15 gate: a development tool for iterating on proofs
//! (the build and the CLI always run everything). Prints the counts and
//! every diagnostic; exit status 1 when a proof fails.

use std::path::Path;
use std::process::ExitCode;

use sandblaster_front::driver::{self, VerifyOptions};
use sandblaster_front::loader::RealFs;
use sandblaster_front::target::TargetInfo;

fn main() -> ExitCode {
    sandblaster_front::memguard::init_from_env();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(root) = args.first() else {
        eprintln!("usage: proofs_only <root.rs>");
        return ExitCode::from(2);
    };
    let t = std::time::Instant::now();
    let c = driver::check(Path::new(root), &RealFs, &TargetInfo::host());
    eprintln!("front end: {:.1}s", t.elapsed().as_secs_f64());
    if !c.ok() {
        eprintln!("{}", c.render());
        return ExitCode::from(1);
    }
    let k = c.krate.as_ref().expect("crate");
    let (v, _audit) = driver::stage::verify_audited(k, &VerifyOptions::default(), &c.sm);
    let s = v.stats();
    eprintln!("{}", v.diags.render(&c.sm));
    println!("definitions {} obligations {} (failed {}) laws {} proofs_ok {} time {:.1}s", v.defs.len(), v.obligations.len(), s.failed, v.laws.len(), v.proofs_ok, t.elapsed().as_secs_f64());
    if v.proofs_ok { ExitCode::SUCCESS } else { ExitCode::from(1) }
}
