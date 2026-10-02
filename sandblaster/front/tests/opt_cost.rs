//! Regression checks on three development-set decisions of the cost model
//! (docs/optimizer-plan.md O8; optimizer design §10.2, §14.1, §12.3, §7.6).
//! They were the model's O8 acceptance, but all three are decisions on the
//! programs the model was tuned for (QMDB's SHA-256 and shape walk, the
//! corpus varint), so they show it still decides those as measured, not that
//! it is accurate in general: its accuracy is to be measured on the held-out
//! decision set (fairness audit, 2026-10-02).
//!
//! 1. **NEON SHA lanes are rejected.** QMDB's portable `compress` lifted to
//!    a 4-lane NEON candidate (every scalar operation one vector operation,
//!    rotates two) costs more per message than the SHA2-instruction variant
//!    `compress_sha2` on the M5 tables (measured: `par sha`, 98 vs 30 ns per
//!    message).
//! 2. **SWAR varint is rejected.** A SWAR decoder (an 8-byte load, the stop
//!    bit by `trailing_zeros`, three mask-and-shift compaction steps) costs
//!    more than the unrolled byte-at-a-time decoder (measured on the M5,
//!    design §12.3: 8.2 vs 1.46 ns for `parse`).
//! 3. **On the development profile the closed form beats set-bit iteration
//!    at N = 32**: the loop summarizer prices `shape_go`'s rungs on the
//!    traces of `sandblaster/fixtures/qmdb/PROFILE.json`'s N = 32 samples
//!    and keeps the closed form, ≥ 3% cheaper than the set-bit iteration and
//!    the early exit. A regression check on the development profile (J8):
//!    the profile is QMDB's, recorded on the profile half of its fixtures
//!    (`splits/n32-profile.txt`, never timed), not a held-out distribution.
//!
//! Every decision is also checked against the measured M5 tuning rows
//! (`sandblaster/targets/evidence/tuning-aarch64-m5.json`): the model
//! and the measurement agree.

use std::collections::HashMap;
use std::path::Path;

use sandblaster_front::driver::{self, Checked};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::hir::{Crate, FnBody, ItemId, ItemKind};
use sandblaster_front::loader::{MemFs, RealFs};
use sandblaster_front::opt::cost::model::{SetModel, beats, fmt_mc};
use sandblaster_front::opt::cost::tuning::Tuning;
use sandblaster_front::opt::{OptOptions, Outcome, Rung};
use sandblaster_front::target::TargetInfo;

fn repo() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn item(k: &Crate, path: &str) -> ItemId {
    k.items.iter().find(|it| it.path.to_string() == path && matches!(it.kind, ItemKind::Fn(_))).map(|it| it.id).unwrap_or_else(|| panic!("no function {path}"))
}

/// The cost of a function's source body (callees at their own cost,
/// memoized; `lifted`: every operation in its vector form).
fn cost(m: &SetModel, k: &Crate, id: ItemId, lifted: bool, memo: &mut HashMap<(ItemId, bool), u64>) -> u64 {
    if let Some(c) = memo.get(&(id, lifted)) {
        return *c;
    }
    memo.insert((id, lifted), 0); // a recursive callee costs nothing here
    let f = k.fn_def(id).unwrap().clone();
    let cell = std::cell::RefCell::new(std::mem::take(memo));
    let callee = |c: ItemId| -> Option<u64> {
        let mut m2 = std::mem::take(&mut *cell.borrow_mut());
        let v = matches!(k.fn_def(c).map(|g| &g.body), Some(FnBody::Exec(_))).then(|| cost(m, k, c, lifted, &mut m2));
        *cell.borrow_mut() = m2;
        v
    };
    let v = if lifted { m.lifted_fn_cost(k, &f, &callee) } else { m.fn_cost(k, &f, &callee) };
    *memo = cell.into_inner();
    memo.insert((id, lifted), v);
    v
}

fn tuning_value(t: &Tuning, arch: &str, uarch: &str, key: &str) -> f64 {
    t.file(arch, uarch).and_then(|f| f.values.iter().find(|(k, _)| k == key).map(|(_, v)| *v)).unwrap_or_else(|| panic!("tuning {arch}/{uarch}: no {key}"))
}

#[test]
fn neon_sha_lanes_are_rejected_on_the_m5() {
    let root = repo().join("sandblaster/fixtures/qmdb/sandblaster/mod.rs");
    let c = driver::check(&root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let t = Tuning::committed();
    let sha2 = SetModel::new("sha2", "aarch64", &["neon".into(), "sha2".into()], &t);
    let mut memo = HashMap::new();
    let isa = cost(&sha2, k, item(k, "crate::sha256::compress_sha2"), false, &mut memo);
    let portable = cost(&sha2, k, item(k, "crate::sha256::compress"), false, &mut memo);
    // the lane candidate: the portable compress lifted to 4 lanes, per lane
    let lifted = cost(&sha2, k, item(k, "crate::sha256::compress"), true, &mut memo);
    let lanes = lifted / 4;
    println!("M5 per block: SHA2 instructions {}, NEON 4-lane software {} per lane ({} for 4), portable scalar {}", fmt_mc(isa), fmt_mc(lanes), fmt_mc(lifted), fmt_mc(portable));
    // the lane candidate would have to be 3% cheaper to be selected: it is not
    assert!(!beats(lanes, isa), "the NEON lane candidate must be rejected: {lanes} vs {isa}");
    assert!(beats(isa, lanes), "the SHA2 variant is cheaper by the gate");
    assert!(beats(isa, portable), "and cheaper than the portable code");
    // the measurement agrees (par sha on this M5)
    let hw = tuning_value(&t, "aarch64", "m5", "sha.hw.x1.ns_per_msg");
    let neon = tuning_value(&t, "aarch64", "m5", "sha.neon4.ns_per_msg");
    println!("measured: sha2-x1 {hw} ns/msg, neon4 {neon} ns/msg");
    assert!(neon > hw * 1.03);
}

/// The two varint decoders (candidate shapes, checked only for typing: the
/// cost model reads their HIR).
const VARINT: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

/// The unrolled decoder (the shape of the driven residual of `uint64`,
/// design §12.3): one byte at a time, an early exit per byte.
pub fn varint_unrolled(xs: &[u8; 8]) -> Option<u64> {
    let b0 = xs[0] as u64;
    if b0 < 128 { return Some(b0); }
    let b1 = xs[1] as u64;
    let v1 = (b0 & 127) | ((b1 & 127) << 7u32);
    if b1 < 128 { return Some(v1); }
    let b2 = xs[2] as u64;
    let v2 = v1 | ((b2 & 127) << 14u32);
    if b2 < 128 { return Some(v2); }
    let b3 = xs[3] as u64;
    let v3 = v2 | ((b3 & 127) << 21u32);
    if b3 < 128 { return Some(v3); }
    let b4 = xs[4] as u64;
    let v4 = v3 | ((b4 & 127) << 28u32);
    if b4 < 128 { return Some(v4); }
    None
}

/// The SWAR decoder (design §12.3's rejected candidate): an 8-byte load,
/// the first clear continuation bit by `trailing_zeros`, the kept bytes
/// masked and the 7-bit groups compacted in three steps.
pub fn varint_swar(xs: &[u8; 8]) -> Option<u64> {
    let x = u64::from_le_bytes(*xs);
    let stop = !x & 9259542123273814144u64;
    if stop == 0 { return None; }
    let n = stop.trailing_zeros();
    let keep = x & (u64::MAX >> (63 - n));
    let m = keep & 9187201950435737471u64;
    let a = (m & 35747867511423103u64) | ((m & 9151313343305220864u64) >> 1u32);
    let b = (a & 70364449226751u64) | ((a & 4611474908973580288u64) >> 2u32);
    let c = (b & 268435455u64) | ((b & 1152921500311879680u64) >> 4u32);
    Some(c)
}
"#;

#[test]
fn swar_varint_is_rejected_on_the_m5() {
    let fs = MemFs::from_files([("v/mod.rs", VARINT)]);
    let c = driver::check(Path::new("v/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let t = Tuning::committed();
    let m5 = SetModel::portable("aarch64", &t);
    let mut memo = HashMap::new();
    let unrolled = cost(&m5, k, item(k, "crate::varint_unrolled"), false, &mut memo);
    let swar = cost(&m5, k, item(k, "crate::varint_swar"), false, &mut memo);
    println!("M5: unrolled {}, SWAR {}", fmt_mc(unrolled), fmt_mc(swar));
    assert!(!beats(swar, unrolled), "the SWAR decoder must be rejected: {swar} vs {unrolled}");
    // the measurement agrees (the design's M5 rows in the tuning file):
    // parity within noise at 1 and 2 bytes, SWAR slower at 5 and 9 bytes and
    // over the four lengths (design §12.3: 8.2 vs 1.46 ns for `parse`)
    let (mut su, mut ss) = (0.0, 0.0);
    for b in ["1B", "2B", "5B", "9B"] {
        let u = tuning_value(&t, "aarch64", "m5", &format!("varint.unrolled_ns.{b}"));
        let s = tuning_value(&t, "aarch64", "m5", &format!("varint.swar_ns.{b}"));
        println!("measured {b}: unrolled {u} ns, SWAR {s} ns");
        if b == "5B" || b == "9B" {
            assert!(s > u * 1.03, "{b}");
        }
        su += u;
        ss += s;
    }
    assert!(ss > su * 1.03, "over the four lengths: SWAR {ss} vs unrolled {su}");
}

/// QMDB N = 32 optimized with its `PROFILE.json` samples (as the build
/// script does): `shape_go`'s rung costs, from the report.
fn shape_rung_costs(root: &str) -> Vec<(String, u64)> {
    let rel = format!("sandblaster/fixtures/qmdb/sandblaster/{root}");
    let path = repo().join(&rel);
    let c: Checked = driver::check(&path, &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let mut opts = OptOptions { strict: true, ..Default::default() };
    let (pf, parsed) = sandblaster_front::opt::cost::profile::for_root(&RealFs, &path).expect("sandblaster/fixtures/qmdb/PROFILE.json");
    // the N = 32 corpus's samples only (`PROFILE.json` also holds N = 1's;
    // a build merges both)
    let mut prof = parsed.unwrap_or_else(|e| panic!("{}: {e}", pf.display()));
    prof.entries.retain(|e| e.root.ends_with(root));
    assert_eq!(prof.entries.len(), 1, "one entry for {root}");
    opts.loops.profile = prof.loop_samples();
    assert!(!opts.loops.profile.is_empty(), "the profile has samples");
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let em = driver::stage::optimize_emit_mode(&c, &mut out, &rel, "", &opts, true).unwrap();
        assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
        let shape = em.opt.fns.iter().find(|f| f.name == "crate::merkle::shape").expect("shape");
        assert!(matches!(shape.outcome, Outcome::Specialized { .. }) && shape.rung == Some(Rung::ClosedForm), "{:?}", shape.rung);
        let why = shape.candidates.iter().find(|c| c.chosen).map(|c| c.reason.clone()).unwrap_or_default();
        let line = why.split("rung costs (portable, traces): ").nth(1).unwrap_or_else(|| panic!("no rung costs in: {why}"));
        let line = line.split(';').next().unwrap();
        println!("{root}: {line}");
        line.split(", ")
            .map(|p| {
                let (r, c) = p.split_once(' ').unwrap();
                let c = c.trim_end_matches(" cycles");
                let (i, f) = c.split_once('.').unwrap();
                (r.to_string(), i.parse::<u64>().unwrap() * 1000 + f.parse::<u64>().unwrap())
            })
            .collect()
    })
}

/// A regression check on the development profile (see the module docs).
#[test]
fn closed_form_beats_set_bits_at_n32_on_the_development_profile() {
    let costs = shape_rung_costs("mod.rs");
    let get = |r: &str| costs.iter().find(|(n, _)| n == r).map(|(_, c)| *c).unwrap_or_else(|| panic!("no {r} in {costs:?}"));
    let (closed, set_bits, early) = (get("ClosedForm"), get("SetBits"), get("EarlyExit"));
    assert!(beats(closed, set_bits), "closed form {closed} vs set-bit {set_bits}");
    assert!(beats(closed, early), "closed form {closed} vs early exit {early}");
}
