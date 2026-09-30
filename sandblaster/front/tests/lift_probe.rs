//! Scratch probe for lifted crates (`#[ignore]`d): runs the front end on
//! the DSL root `LIFT_PROBE_ROOT` (real files) and prints its diagnostics;
//! with `LIFT_PROBE_VERIFY=1` it also verifies (ghost code included unless
//! `LIFT_PROBE_EXEC_ONLY=1`) and prints every definition that did not check
//! and every unproven obligation, with the elapsed times.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use std::path::Path;

use sandblaster_front::driver::{self, ProverSet, VerifyOptions};
use sandblaster_front::loader::RealFs;
use sandblaster_front::target::TargetInfo;

#[test]
#[ignore]
fn lift_probe() {
    let root = std::env::var("LIFT_PROBE_ROOT").expect("LIFT_PROBE_ROOT");
    let t0 = std::time::Instant::now();
    let c = driver::check(Path::new(&root), &RealFs, &TargetInfo::aarch64_apple_darwin());
    eprintln!("{}", c.render());
    eprintln!("front end: {:?}, ok = {}", t0.elapsed(), c.ok());
    assert!(c.ok());
    if std::env::var("LIFT_PROBE_VERIFY").is_err() {
        return;
    }
    let exec_only = std::env::var("LIFT_PROBE_EXEC_ONLY").is_ok();
    let t1 = std::time::Instant::now();
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Standard, exec_only });
    eprintln!("{}", util::explain(&c, &v));
    let proven = v.obligations.iter().filter(|o| o.proven()).count();
    eprintln!("verify: {:?}; {} obligations, {} proven; {} definitions, {} failed", t1.elapsed(), v.obligations.len(), proven, v.defs.len(), v.failed_defs().len());
}
