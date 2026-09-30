//! The SIMD search lowering (plan O10, corpus P12; `opt::par::search`): a
//! byte search with an early exit gets a NEON variant testing 16 bytes per
//! step, linked by an instance of the kernel-checked search library.

use std::path::Path;

use sandblaster_front::driver;
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::OptOptions;
use sandblaster_front::opt::par::search;
use sandblaster_front::target::TargetInfo;

const P12: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;
#[decreases(xs.len())]
fn first_small_go(xs: &[u8], i: u64) -> Option<u64> {
    match xs {
        [] => None,
        [h, t @ ..] => {
            if *h < 0x80 { Some(i) } else { first_small_go(t, i.wrapping_add(1)) }
        }
    }
}
pub fn first_small(xs: &[u8]) -> Option<u64> { first_small_go(xs, 0) }
"#;

/// Other byte tests, orientations and result types.
const KINDS: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;
#[decreases(xs.len())]
fn digit_go(xs: &[u8], i: u64) -> Option<u64> {
    match xs {
        [] => None,
        [h, t @ ..] => {
            if *h >= 0x30 { Some(i) } else { digit_go(t, i.wrapping_add(1)) }
        }
    }
}
pub fn digit(xs: &[u8]) -> Option<u64> { digit_go(xs, 0) }
#[decreases(xs.len())]
fn newline_go(xs: &[u8], i: u64) -> u64 {
    match xs {
        [] => i,
        [h, t @ ..] => {
            if *h == 10 { i } else { newline_go(t, i.wrapping_add(1)) }
        }
    }
}
pub fn newline(xs: &[u8]) -> u64 { newline_go(xs, 0) }
#[decreases(xs.len())]
fn high_go(xs: &[u8], i: u64) -> Option<(u64, bool)> {
    match xs {
        [] => None,
        [h, t @ ..] => {
            if 0x7f < *h { Some((i.wrapping_mul(2), true)) } else { high_go(t, i.wrapping_add(1)) }
        }
    }
}
pub fn high(xs: &[u8]) -> Option<(u64, bool)> { high_go(xs, 0) }
// not a search site: the index steps by 2
#[decreases(xs.len())]
fn skip_go(xs: &[u8], i: u64) -> Option<u64> {
    match xs {
        [] => None,
        [h, t @ ..] => {
            if *h < 0x80 { Some(i) } else { skip_go(t, i.wrapping_add(2)) }
        }
    }
}
pub fn skip(xs: &[u8]) -> Option<u64> { skip_go(xs, 0) }
"#;

fn optimize(src: &str, target: &TargetInfo) -> driver::OptimizedEmit {
    let fs = MemFs::from_files([("p/mod.rs", src)]);
    let c = driver::check(Path::new("p/mod.rs"), &fs, target);
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        driver::stage::optimize_emit_mode(&c, &mut out, "p/mod.rs", "", &OptOptions { strict: true, ..Default::default() }, true).unwrap()
    })
}

#[test]
fn p12_gets_a_neon_search_variant_on_aarch64() {
    let em = optimize(P12, &TargetInfo::aarch64_apple_darwin());
    assert!(em.opt.errors.is_empty() && em.opt.warnings.is_empty() && em.roundtrip.is_empty(), "{:?} {:?} {:?}", em.opt.errors, em.opt.warnings, em.roundtrip);
    let v = em.opt.variants.iter().find(|v| v.variant == "crate::first_small_go__search_neon").expect("the search variant");
    println!("{}", v.note);
    // the per-site cost is the library instance only (the library is
    // checked once per crate): a few thousand steps
    let instance: u64 = v.note.split(" instance steps").next().and_then(|s| s.rsplit('(').next()).and_then(|n| n.trim().parse().ok()).unwrap_or_else(|| panic!("no instance step count: {}", v.note));
    println!("search_equiv instance: {instance} steps");
    assert!(instance > 0 && instance < 100_000, "{instance} steps");
    assert_eq!(v.implements, "crate::first_small_go");
    assert!(v.dispatched, "{}", v.note);
    assert_eq!(v.equivalence.as_ref().map(|e| e.0.clone()).unwrap(), "crate::first_small_go__search_neon::search_equiv");
    assert!(v.evidence.iter().all(|(_, s)| s.starts_with("validated")), "{:?}", v.evidence);
    for needle in ["::core::arch::aarch64::vcltq_u8(", "::core::arch::aarch64::vshrn_n_u16::<4>(", "split_first_chunk::<16>", "first_small_go__search_neon(", "fn first_small__neon("] {
        assert!(em.code.contains(needle), "missing `{needle}`:\n{}", em.code);
    }
}

#[test]
fn every_byte_test_kind_is_lowered_and_proven() {
    let em = optimize(KINDS, &TargetInfo::aarch64_apple_darwin());
    assert!(em.opt.errors.is_empty() && em.opt.warnings.is_empty() && em.roundtrip.is_empty(), "{:?} {:?} {:?}", em.opt.errors, em.opt.warnings, em.roundtrip);
    for (f, test) in [("digit_go", "ge_hc"), ("newline_go", "eq_hc"), ("high_go", "lt_ch")] {
        let v = em.opt.variants.iter().find(|v| v.variant == format!("crate::{f}__search_neon")).unwrap_or_else(|| panic!("no search variant of {f}: {:?}", em.opt.variants.iter().map(|v| &v.variant).collect::<Vec<_>>()));
        println!("{f}: {}", v.note);
        assert!(v.equivalence.is_ok() && v.note.contains(&format!("test `{test}`")), "{f}: {}", v.note);
        assert!(v.dispatched, "{f}: {}", v.note);
    }
    assert!(!em.opt.variants.iter().any(|v| v.variant.contains("skip_go")), "skip_go is not a search site");
    assert!(em.code.contains("::core::arch::aarch64::vcgeq_u8(") && em.code.contains("::core::arch::aarch64::vceqq_u8("), "{}", em.code);
}

#[test]
fn x86_gets_no_search_variant() {
    let em = optimize(P12, &TargetInfo::x86_64_apple_darwin());
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    assert!(!em.opt.variants.iter().any(|v| v.variant.contains("search")), "{:?}", em.opt.variants.iter().map(|v| &v.variant).collect::<Vec<_>>());
}

/// A NEON search written by hand with the wrong nibble shift (`z >> 3`):
/// the library instance must not prove it equal to the source.
const WRONG: &str = r#"#![forbid(unsafe_code)]
use core::arch::aarch64::*;
use sandblaster::arch::aarch64::load_u8x16;
use sandblaster::prelude::*;
#[decreases(xs.len())]
fn first_small_go(xs: &[u8], i: u64) -> Option<u64> {
    match xs {
        [] => None,
        [h, t @ ..] => {
            if *h < 0x80 { Some(i) } else { first_small_go(t, i.wrapping_add(1)) }
        }
    }
}
#[target_feature(enable = "neon")]
#[decreases(xs.len())]
fn go_neon(xs: &[u8], i: u64) -> Option<u64> {
    match xs.split_first_chunk::<16>() {
        None => first_small_go(xs, i),
        Some((c, t)) => {
            let n = vshrn_n_u16::<4>(vreinterpretq_u16_u8(vcltq_u8(load_u8x16(c), vdupq_n_u8(128))));
            let m = vgetq_lane_u64::<0>(vreinterpretq_u64_u8(vcombine_u8(n, n)));
            let z = m.trailing_zeros();
            if z < 64 { Some(i.wrapping_add((z >> SHIFT) as u64)) } else { go_neon(t, i.wrapping_add(16)) }
        }
    }
}
"#;

#[test]
fn the_library_proves_the_right_variant_and_rejects_a_wrong_one() {
    for (shift, ok) in [("2u32", true), ("3u32", false)] {
        let src = WRONG.replace("SHIFT", shift);
        let fs = MemFs::from_files([("p/mod.rs", src.as_str())]);
        let c = driver::check(Path::new("p/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
        assert!(c.ok(), "{}", c.render());
        let k = c.krate.as_ref().unwrap();
        elab::with_big_stack(|| {
            let mut chain = ProverChain::standard();
            let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
            let (f, g) = (out.env.lookup_global("crate::first_small_go").unwrap(), out.env.lookup_global("crate::go_neon").unwrap());
            let r = search::prove_link(&mut out.env, f, g, "crate::go_neon::search_equiv");
            match (ok, &r) {
                (true, Ok(_)) => {}
                (false, Err(e)) => assert!(e.contains("rejected by the kernel"), "{e}"),
                _ => panic!("shift {shift}: {r:?}"),
            }
        });
    }
}

const EQ: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;
pub fn equal(a: &[u8; 32], b: &[u8; 32]) -> bool { a == b }
pub fn equal16(a: [u8; 16], b: [u8; 16]) -> bool { a == b }
"#;

#[test]
fn the_simd_seq_eq_candidate_is_proven_and_priced() {
    let em = optimize(EQ, &TargetInfo::aarch64_apple_darwin());
    assert!(em.opt.errors.is_empty() && em.opt.warnings.is_empty() && em.roundtrip.is_empty(), "{:?} {:?} {:?}", em.opt.errors, em.opt.warnings, em.roundtrip);
    assert_eq!(em.opt.seq_eq.iter().map(|r| r.bytes).collect::<Vec<_>>(), vec![16, 32]);
    for r in &em.opt.seq_eq {
        println!("{:?}: {}", r.functions, r.note);
        assert_eq!(r.lemma.as_deref(), Ok(format!("seqeq::neon_word_{}", r.bytes).as_str()), "{}", r.note);
        assert!(r.neon_cost > 0 && r.word_cost > 0, "{}", r.note);
        assert!(!r.chosen, "the word form is cheaper on the M5 tables: {}", r.note);
    }
    // the word form stays in the emitted code
    assert!(!em.code.contains("veorq_u8"), "{}", em.code);
}
