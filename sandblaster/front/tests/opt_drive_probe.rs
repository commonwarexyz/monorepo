//! Development probe for the Σ1 driver (ignored): prints the kernel bodies
//! of QMDB functions as core text.
//!
//! `OPT_PROBE=crate::codec::byte,seq::eq cargo test --test opt_drive_probe -- --ignored --nocapture`

use std::path::Path;

use sandblaster_front::driver;
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::RealFs;
use sandblaster_front::target::TargetInfo;

#[test]
#[ignore]
fn probe_bodies() {
    let root = std::env::var("OPT_PROBE_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster/mod.rs"));
    let c = driver::check(&root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let names = std::env::var("OPT_PROBE").unwrap_or_else(|_| "crate::codec::byte".into());
        for n in names.split(',') {
            let Some(g) = out.env.lookup_global(n) else {
                println!("{n}: no global");
                continue;
            };
            let ty = out.env.global_type(g).unwrap();
            let body = out.env.global_body(g).unwrap();
            println!("== {n} (arity {:?}, opaque {:?}, kind {:?})", out.env.global_arity(g), out.env.global_opaque(g), out.env.global_kind(g));
            println!("type: {}", out.env.print_term(&[], &ty));
            println!("body: {}", out.env.print_term(&[], &body));
        }
    });
}

#[test]
#[ignore]
fn probe_hir() {
    let root = std::env::var("OPT_PROBE_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster/mod.rs"));
    let c = driver::check(&root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let names = std::env::var("OPT_PROBE").unwrap_or_else(|_| "crate::codec::byte".into());
    for n in names.split(',') {
        for it in &k.items {
            if it.path.to_string() == n {
                if let sandblaster_front::hir::ItemKind::Fn(f) = &it.kind {
                    println!("== {n}\nparams: {:#?}\nlocals: {:#?}\nbody: {:#?}", f.params, f.locals, f.body);
                }
            }
        }
    }
}

/// The QMDB pipeline (exec code only) with the driver: every function's
/// outcome, and the printed code of `OPT_PROBE` functions.
#[test]
#[ignore]
fn probe_optimize() {
    use sandblaster_front::driver::VerifyOptions;
    use sandblaster_front::opt::{OptOptions, Outcome};
    let root = std::env::var("OPT_PROBE_ROOT").map(std::path::PathBuf::from).unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster/mod.rs"));
    let c = driver::check(&root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let t = std::time::Instant::now();
    let exec_only = std::env::var_os("OPT_PROBE_FULL").is_none();
    // `OPT_PROBE_CACHE=<dir>`: the hints-only proof cache
    let oopts = OptOptions { cache_dir: std::env::var_os("OPT_PROBE_CACHE").map(std::path::PathBuf::from), ..Default::default() };
    let built = driver::stage::verify_and_optimize(&c, &VerifyOptions { exec_only, ..Default::default() }, &oopts, "probe");
    let em = built.emit.expect("optimized").expect("emitted");
    println!("optimized in {:?} (optimizer {} ms)", t.elapsed(), em.opt.millis);
    let mut n = 0;
    for f in &em.opt.fns {
        let o = match &f.outcome {
            Outcome::Specialized { nodes, .. } => {
                n += 1;
                format!("Specialized {nodes} nodes {:?} {:?}", f.link, f.rung)
            }
            Outcome::Unspecialized { reason, .. } => format!("Unspecialized: {}", reason.chars().take(160).collect::<String>()),
        };
        println!("{} [{} ms]: {o}", f.name, f.millis);
        for c in &f.candidates {
            if c.rung == sandblaster_front::opt::Rung::Driven && !c.chosen {
                println!("    driven: {} ({:?})", c.reason.chars().take(900).collect::<String>(), c.rejected_by);
            }
        }
    }
    println!("{n}/{} specialized; warnings {:?}; errors {:?}; round trip {:?}", em.opt.fns.len(), em.opt.warnings.len(), em.opt.errors, em.roundtrip);
    if let Ok(names) = std::env::var("OPT_PROBE") {
        for name in names.split(',') {
            let short = name.rsplit("::").next().unwrap();
            let mut on = false;
            for line in em.code.lines() {
                if line.contains(&format!("fn {short}(")) {
                    on = true;
                }
                if on {
                    println!("{line}");
                    if line.trim_start().starts_with('}') && line.starts_with("        }") {
                        on = false;
                    }
                }
            }
        }
    }
    if let Ok(p) = std::env::var("OPT_PROBE_OUT") {
        std::fs::write(p, &em.code).unwrap();
    }
}
