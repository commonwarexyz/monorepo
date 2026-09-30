//! Performance of the kernel on a symbolic SHA-256 compress written in core
//! text (DESIGN.md §5.9, §9.8; tests/sha256.core), with timings printed
//! (`--nocapture`; run with `--release` for release numbers):
//!
//! * default-mode evaluation of the FIPS compress on a symbolic state and
//!   block (64 unrolled rounds, schedule, 64 byte loads), and a shared quote;
//! * conversion between two formulations with different control structure
//!   (sliding-window rounds vs a materialized schedule folded over (K, W)
//!   pairs) — evaluation of both sides plus memoized conversion;
//! * `BvRefl` between the ARMv8-shaped compress and the FIPS compress
//!   (normalizer + tripwire), for one and two chained blocks.
//!
//! `SANDBLASTER_PERF_REPEAT=n` repeats the measurements and reports the
//! minimum of each (for stable numbers on a loaded machine, and for
//! profilers).

mod common;

use std::time::Instant;

use common::*;
use sandblaster_kernel::api::*;
use sandblaster_kernel::term::{Lvl, Rel};
use sandblaster_kernel::value::Budget;

const SHA: &str = include_str!("sha256.core");

fn ctx(env: &Env, vars: &[(&str, &str)]) -> (Ctx, Vec<&'static str>) {
    let mut c = Ctx::default();
    let mut names: Vec<&'static str> = Vec::new();
    for (n, t) in vars {
        let ty = env.parse_term(&names, t).unwrap();
        let tv = env.eval(&env.ctx_venv(&c), c.depth(), &ty, &mut budget()).unwrap();
        c = c.push(CtxEntry { name: (*n).into(), rel: Rel::Rel, ty: tv, def: None });
        names.push(Box::leak(n.to_string().into_boxed_str()));
    }
    (c, names)
}

#[test]
fn symbolic_sha256_compress() {
    big_stack(|| {
        let repeat: usize = std::env::var("SANDBLASTER_PERF_REPEAT").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
        let mut env = prelude();
        let t0 = Instant::now();
        load(&mut env, SHA).unwrap_or_else(|e| panic!("{e}"));
        let t_load = t0.elapsed();
        let (c1, n1) = ctx(&env, &[("s", "Array U32 8usize"), ("b", "Array U8 64usize")]);
        let (c2, n2) = ctx(&env, &[("s", "Array U32 8usize"), ("b0", "Array U8 64usize"), ("b1", "Array U8 64usize")]);
        let mut best: Vec<std::time::Duration> = vec![std::time::Duration::MAX; 8];
        let mut steps = (0, 0);
        for _ in 0..repeat {
            let venv = env.ctx_venv(&c1);
            // Default-mode evaluation (+ shared read-back).
            let t = env.parse_term(&n1, "sha::compress s b").unwrap();
            let mut b = Budget { steps: 500_000_000 };
            let t0 = Instant::now();
            let v = env.eval(&venv, c1.depth(), &t, &mut b).unwrap();
            let t_eval = t0.elapsed();
            let steps_eval = 500_000_000 - b.steps;
            let t0 = Instant::now();
            let q = env.quote(c1.depth(), &v, true);
            let t_quote = t0.elapsed();
            let _ = q;
            // Conversion between two control structures.
            let t2 = env.parse_term(&n1, "sha2::compress s b").unwrap();
            let mut b = Budget { steps: 500_000_000 };
            let t0 = Instant::now();
            let v1 = env.eval(&venv, c1.depth(), &t, &mut b).unwrap();
            let v2 = env.eval(&venv, c1.depth(), &t2, &mut b).unwrap();
            let t_eval2 = t0.elapsed();
            let t0 = Instant::now();
            assert!(env.conv(c1.depth(), &v1, &v2, &mut b).unwrap());
            let t_conv = t0.elapsed();
            let steps_conv = 500_000_000 - b.steps;
            // The kernel rule on the same equation (check = both evaluations
            // and conversion).
            let goal = env.parse_term(&n1, "Eq(Array U32 8usize, sha::compress s b, sha2::compress s b)").unwrap();
            let gv = env.eval(&venv, c1.depth(), &goal, &mut budget()).unwrap();
            let pf = env.parse_term(&n1, "refl(Array U32 8usize, sha::compress s b)").unwrap();
            let t0 = Instant::now();
            env.check(&c1, &pf, &gv, &mut Budget { steps: 500_000_000 }).unwrap_or_else(|e| panic!("{e}"));
            let t_check = t0.elapsed();
            // BvRefl: hardware-shaped vs FIPS.
            let bv = env.parse_term(&n1, "bvrefl(Array U32 8usize, arm::compress s b, sha::compress s b)").unwrap();
            let t0 = Instant::now();
            env.infer(&c1, &bv, &mut Budget { steps: 500_000_000 }).unwrap_or_else(|e| panic!("{e}"));
            let t_bv = t0.elapsed();
            let bv2 = env.parse_term(&n2, "bvrefl(Array U32 8usize, arm::compress2 s b0 b1, sha2::compress2 s b0 b1)").unwrap();
            let t0 = Instant::now();
            env.infer(&c2, &bv2, &mut Budget { steps: 1_000_000_000 }).unwrap_or_else(|e| panic!("{e}"));
            let t_bv2 = t0.elapsed();
            for (i, t) in [t_eval, t_quote, t_eval2, t_conv, t_check, t_bv, t_bv2].into_iter().enumerate() {
                best[i] = best[i].min(t);
            }
            steps = (steps_eval, steps_conv);
            let _ = Lvl(0);
        }
        eprintln!(
            "perf_sha (min of {repeat}): load {t_load:?}; eval FIPS compress {:?} ({} steps); shared quote {:?}; \
             eval both formulations {:?}; conv {:?} (total {} steps); check refl {:?}; bvrefl arm == FIPS {:?}; two blocks {:?}",
            best[0], steps.0, best[1], best[2], best[3], steps.1, best[4], best[5], best[6]
        );
    })
}
