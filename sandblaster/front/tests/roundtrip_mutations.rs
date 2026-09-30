//! The codegen round trip (DESIGN.md §8.3) must reject printed code whose
//! relevant structure differs from the optimized core: an unchecked read
//! hoisted out of its guard, a dropped operation, swapped operands, an
//! extra statement, a bound check re-inserted as unchecked somewhere else.
//! The unmutated output must pass.

use std::path::Path;

use sandblaster_front::driver::{self, Checked};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::OptOptions;
use sandblaster_front::roundtrip;
use sandblaster_front::target::TargetInfo;

const SRC: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

/// A guarded read (the guard's path condition proves the index).
pub fn pick(xs: &[u32], i: usize) -> u32 {
    if i < xs.len() { xs[i] } else { 0u32 }
}

/// Straight-line arithmetic (specialized).
pub fn mix(a: u32, b: u32) -> u32 {
    a.wrapping_sub(b) ^ (a >> 3u32)
}

/// A loop over a fixed array.
pub fn total(xs: &[u8; 16]) -> u32 {
    let mut s: u32 = 0;
    for i in 0usize..16 {
        s = s.wrapping_add(xs[i] as u32);
    }
    s
}

/// Tail recursion (printed as the canonical loop).
pub fn count(xs: &[u8], acc: u32) -> u32 {
    match xs {
        [] => acc,
        [_, rest @ ..] => count(rest, acc.wrapping_add(1u32)),
    }
}
"#;

fn check() -> Checked {
    let fs = MemFs::from_files([("r/mod.rs", SRC)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    c
}

/// Replaces exactly one occurrence of `from` (after whitespace
/// normalization of the search, the text must contain it once).
fn mutate(code: &str, from: &str, to: &str) -> String {
    assert_eq!(code.matches(from).count(), 1, "mutation site `{from}` must occur exactly once in:\n{code}");
    code.replacen(from, to, 1)
}

#[test]
fn round_trip_accepts_the_output_and_rejects_mutations() {
    let c = check();
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let em = driver::stage::optimize_emit(&c, &mut out, "r/mod.rs", "", &OptOptions { strict: true, ..Default::default() }).unwrap();
        assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
        assert!(em.roundtrip.is_empty(), "the unmutated output must pass the round trip: {:?}\n{}", em.roundtrip, em.code);
        assert!(em.roundtrip_stats.compared >= 4, "{:?}", em.roundtrip_stats);
        let code = em.code.clone();
        println!("{code}");
        let run = |label: &str, mutated: &str, out: &mut elab::Output| {
            let st = roundtrip::check(mutated, &em.opt, out, &c.sm, &c.reexports);
            let failures = match st {
                Ok(s) => s.failures,
                Err(e) => vec![e],
            };
            assert!(!failures.is_empty(), "mutation `{label}` was accepted by the round trip:\n{mutated}");
            println!("{label}: rejected ({})", failures[0].lines().next().unwrap_or(""));
        };
        // 1. an unchecked read hoisted out of its guard (executed even when
        //    the index is out of bounds)
        let hoisted = mutate(&code, "if l1_i < <[u32]>::len(l0_xs) {", "unsafe { *<[u32]>::get_unchecked(&(*l0_xs), l1_i) };\n        if l1_i < <[u32]>::len(l0_xs) {");
        run("hoisted unchecked read", &hoisted, &mut out);
        // 2. a dropped operation
        let dropped = mutate(&code, " ^ crate::__rt::chk::shr_u32(l0_a, 3u32)", "");
        run("dropped operation", &dropped, &mut out);
        // 3. swapped operands
        let swapped = mutate(&code, "<u32>::wrapping_sub(l0_a, l1_b)", "<u32>::wrapping_sub(l1_b, l0_a)");
        run("swapped operands", &swapped, &mut out);
        // 4. a duplicated operation
        let dup = mutate(&code, "<u32>::wrapping_sub(l0_a, l1_b)", "<u32>::wrapping_sub(<u32>::wrapping_sub(l0_a, l1_b), l1_b)");
        run("duplicated operation", &dup, &mut out);
        // 5. a changed literal
        let lit = mutate(&code, "l1_acc, 1u32", "l1_acc, 2u32");
        run("changed literal", &lit, &mut out);
        // 6. an unchecked read moved to another index
        let moved = mutate(&code, "get_unchecked(&(*l0_xs), l1_i)", "get_unchecked(&(*l0_xs), 0usize)");
        run("changed index", &moved, &mut out);
        // 8. a smuggled attribute
        let attr = mutate(&code, "    pub fn pick(", "    #[unsafe(no_mangle)]\n    pub fn pick(");
        run("smuggled attribute", &attr, &mut out);
        // 9. `unsafe` around an ordinary call
        let uns = mutate(&code, "<u32>::wrapping_add(l1_acc, 1u32)", "unsafe { <u32>::wrapping_add(l1_acc, 1u32) }");
        run("unsafe around a safe call", &uns, &mut out);
        // 10. a tail-loop self-call moved out of tail position (rustc's
        //     `continue` would abandon the surrounding computation)
        let cont = mutate(&code, "&[] => l1_acc,", "&[] => <u32>::wrapping_add({ let t9__next = l0_xs; let t10__next = l1_acc; a0__arg = t9__next; a1__arg = t10__next; continue; }, 0u32),");
        run("self-call outside tail position", &cont, &mut out);
        // 11. a checked (safe) index is still the same core: accepted
        // (the unchecked read of `pick`, with its `SAFETY:` comment naming
        // the obligation of whichever definition is printed: the source or
        // its driven residual)
        let read = {
            let a = code.find("unsafe { /* SAFETY: the index is in bounds: index-bounds obligation #").expect("the unchecked read of `pick`");
            let tail = "*<[u32]>::get_unchecked(&(*l0_xs), l1_i) }";
            let b = a + code[a..].find(tail).expect("the unchecked read of `pick`") + tail.len();
            code[a..b].to_string()
        };
        let checked = mutate(&code, &read, "(*l0_xs)[l1_i]");
        let st = roundtrip::check(&checked, &em.opt, &mut out, &c.sm, &c.reexports).unwrap();
        assert!(st.failures.is_empty(), "a checked index denotes the same core: {:?}", st.failures);
        // 12. `#[inline]` is semantics-free and ignored by the round trip (the
        //     residual helpers of plan O4 print it): accepted on a residual
        for attr in ["#[inline]", "#[inline(always)]"] {
            let hinted = mutate(&code, "    pub fn mix(", &format!("    {attr}\n    pub fn mix("));
            let st = roundtrip::check(&hinted, &em.opt, &mut out, &c.sm, &c.reexports).unwrap();
            assert!(st.failures.is_empty(), "`{attr}` on a residual is ignored by the round trip: {:?}", st.failures);
        }
        // 7. an extra function
        let extra = mutate(&code, "mod __sandblaster {", "mod __sandblaster {\n    fn smuggled() -> u32 { 7u32 }");
        run("extra item", &extra, &mut out);
    });
}

// ---------------------------------------------------------------------------
// R19 (design §20, plan O2): checked-arithmetic helpers (E0)
// ---------------------------------------------------------------------------

const SRC_E0: &str = r#"#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[derive(Clone, Copy)]
pub struct Acc {
    pub lo: u32,
    pub hi: u64,
}

/// Checked operations at every width, proven from the guard.
pub fn widths(a: u64, b: u32, c: u16, d: u8, e: usize) -> (u64, u32, u16, u8, usize) {
    if a >= 1000 || b >= 1000 || c >= 1000 || d >= 100 || e >= 1000 {
        return (0, 0, 0, 0, 0);
    }
    (a * 7 - a, b + 3, c * 2 + 1, d + 100, (e << 2u8) >> 1u64)
}

/// Checked compound assignments on an array element, a field and a local.
pub fn compound(xs: [u32; 4], i: usize, v: u8) -> ([u32; 4], Acc) {
    let mut ys = xs;
    let mut acc = Acc { lo: 1, hi: 2 };
    let mut n: u64 = 5;
    if i < 4 && ys[i] < 1000 {
        ys[i] += 7;
        ys[i] <<= 1u8;
    }
    acc.lo *= 3;
    n -= 1;
    n >>= 2u64;
    acc.hi += n;
    if v < 60 {
        acc.hi <<= v;
    }
    (ys, acc)
}

/// A checked compound assignment inside a tail-loop argument.
pub fn sum3(xs: &[u8], acc: u32) -> u32 {
    match xs {
        [] => acc,
        [x, rest @ ..] => {
            if acc < 1000000 {
                sum3(rest, { let mut t = acc; t += *x as u32; t })
            } else {
                acc
            }
        }
    }
}
"#;

/// Compiles the generated file as a library with rustc, with or without
/// debug assertions (the two profiles of the `__rt::chk` templates), under
/// `-D warnings`.
fn compiles(code: &str, tag: &str, debug: bool) -> Result<(), String> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("roundtrip-mutations").join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sandblaster.rs"), code).unwrap();
    std::fs::write(dir.join("lib.rs"), "include!(\"sandblaster.rs\");\n").unwrap();
    let da = if debug { "debug-assertions=on" } else { "debug-assertions=off" };
    let out = std::process::Command::new("rustc")
        .args(["--edition", "2024", "--crate-type", "lib", "-D", "warnings", "-C", da, "-C", "overflow-checks=on", "-o"])
        .arg(dir.join("lib.rlib"))
        .arg(dir.join("lib.rs"))
        .output()
        .unwrap();
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).to_string()) }
}

/// R19 (design §20, plan O2): a checked-arithmetic helper printed with
/// swapped operands, the wrong width or the wrong operator — in an
/// expression or in the E0 form of a compound assignment — fails the round
/// trip, and so does any change to the fixed `__rt` template (the TCB's
/// meaning of the helpers). The plain operator denotes the same checked
/// primitive and is accepted (control).
#[test]
fn r19_checked_arithmetic_helpers() {
    let fs = MemFs::from_files([("r/mod.rs", SRC_E0)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let em = driver::stage::optimize_emit(&c, &mut out, "r/mod.rs", "", &OptOptions { strict: true, ..Default::default() }).unwrap();
        assert!(em.opt.errors.is_empty(), "{:?}", em.opt.errors);
        assert!(em.roundtrip.is_empty(), "the unmutated output must pass the round trip: {:?}\n{}", em.roundtrip, em.code);
        let code = em.code.clone();
        println!("{code}");
        // every checked form is printed through a helper: expressions at
        // every width, shift amounts of other widths converted, compound
        // assignments on an element, a field and a local
        for h in ["sub_u64", "mul_u64", "add_u32", "add_u16", "mul_u16", "add_u8", "shl_usize", "shr_usize", "shl_u32", "mul_u32", "shr_u64", "add_u64", "shl_u64"] {
            assert!(code.contains(&format!("crate::__rt::chk::{h}(")), "`{h}` is not called:\n{code}");
        }
        let body = &code[code.find("mod __sandblaster {").unwrap()..code.find("mod __rt {").unwrap()];
        for op in [" + ", " - ", " * ", " << ", " >> ", "+=", "-=", "*=", "<<=", ">>="] {
            assert!(!body.contains(op), "a checked `{op}` is printed as an operator:\n{code}");
        }
        // the templates compile in both profiles
        for debug in [false, true] {
            if let Err(e) = compiles(&code, if debug { "r19-debug" } else { "r19-release" }, debug) {
                panic!("the E0 output does not compile (debug assertions {debug}):\n{e}");
            }
        }
        // rejected, and for the intended reason (`why` in some failure)
        let rejected = |label: &str, mutated: &str, why: &str, out: &mut elab::Output| {
            let st = roundtrip::check(mutated, &em.opt, out, &c.sm, &c.reexports);
            let failures = match st {
                Ok(s) => s.failures,
                Err(e) => vec![e],
            };
            assert!(!failures.is_empty(), "R19 mutation `{label}` was accepted by the round trip:\n{mutated}");
            assert!(failures.iter().any(|f| f.contains(why)), "R19 mutation `{label}` was rejected, but not because {why:?}: {failures:?}");
            println!("R19 {label}: rejected ({})", failures.iter().find(|f| f.contains(why)).unwrap().chars().take(200).collect::<String>());
        };
        let core = "does not match its optimized core";
        let tmpl = "differs from its template";
        let sub = "crate::__rt::chk::sub_u64(crate::__rt::chk::mul_u64(l0_a, 7u64), l0_a)";
        let add = "crate::__rt::chk::add_u32(l1_b, 3u32)";
        // swapped operands (a non-commutative and a commutative operation)
        rejected("swapped operands (sub)", &mutate(&code, sub, "crate::__rt::chk::sub_u64(l0_a, crate::__rt::chk::mul_u64(l0_a, 7u64))"), core, &mut out);
        rejected("swapped operands (add)", &mutate(&code, add, "crate::__rt::chk::add_u32(3u32, l1_b)"), core, &mut out);
        // wrong width: of the helper, of the operation (type-consistent), of
        // a shift amount
        rejected("wrong width (helper)", &mutate(&code, "crate::__rt::chk::add_u8(l3_d, 100u8)", "crate::__rt::chk::add_u16(l3_d, 100u8)"), "arguments of `add_u16`", &mut out);
        rejected("wrong width (operation)", &mutate(&code, "crate::__rt::chk::add_u8(l3_d, 100u8)", "(crate::__rt::chk::add_u16(l3_d as u16, 100u16) as u8)"), core, &mut out);
        // (`widths` is driven since the S1 merge — its guard's motive
        // abstraction is well typed — and its residual folds `2u8 as u32`
        // to `2u32`: the amount's width is checked the other way round)
        rejected("wrong width (shift amount)", &mutate(&code, "crate::__rt::chk::shl_usize(l4_e, 2u32)", "crate::__rt::chk::shl_usize(l4_e, 2u8 as u32)"), core, &mut out);
        // wrong operator
        rejected("wrong operator (add -> mul)", &mutate(&code, add, "crate::__rt::chk::mul_u32(l1_b, 3u32)"), core, &mut out);
        rejected("wrong operator (shr -> shl, compound)", &mutate(&code, "crate::__rt::chk::shr_u64(l5_n, t5__v as u32)", "crate::__rt::chk::shl_u64(l5_n, t5__v as u32)"), core, &mut out);
        rejected("a wrapping operation for the checked one", &mutate(&code, add, "<u32>::wrapping_add(l1_b, 3u32)"), core, &mut out);
        // the compound form: swapped operands, another place, another temporary
        rejected("compound: swapped operands", &mutate(&code, "crate::__rt::chk::sub_u64(l5_n, t4__v)", "crate::__rt::chk::sub_u64(t4__v, l5_n)"), "must be the assigned place", &mut out);
        rejected("compound: another place", &mutate(&code, "crate::__rt::chk::add_u64(l4_acc.hi, t6__v)", "crate::__rt::chk::add_u64(l5_n, t6__v)"), "must be the assigned place", &mut out);
        rejected("compound: another temporary", &mutate(&code, "let t3__v: u32 = 3u32; crate::__rt::chk::mul_u32(l4_acc.lo, t3__v)", "let t9__v: u32 = 3u32; crate::__rt::chk::mul_u32(l4_acc.lo, t9__v)"), "the printer's is `t3__v`", &mut out);
        // `unsafe` around a helper call
        rejected("`unsafe` around a helper call", &mutate(&code, add, &format!("unsafe {{ {add} }}")), "`unsafe` around a call of a function without `requires`", &mut out);
        // the template: a release body, a debug body, a profile, an unused
        // helper, the module missing or moved
        rejected("template: release body", &mutate(&code, "pub(crate) fn add_u32(a: u32, b: u32) -> u32 { <u32>::wrapping_add(a, b) }", "pub(crate) fn add_u32(a: u32, b: u32) -> u32 { <u32>::wrapping_add(a, b) ^ 1u32 }"), tmpl, &mut out);
        rejected("template: debug body without the check", &mutate(&code, "pub(crate) fn sub_u64(a: u64, b: u64) -> u64 { a - b }", "pub(crate) fn sub_u64(a: u64, b: u64) -> u64 { <u64>::wrapping_sub(a, b) }"), tmpl, &mut out);
        rejected("template: profile", &mutate(&code, "    #[cfg(debug_assertions)]\n    pub(crate) mod chk {", "    #[cfg(all())]\n    pub(crate) mod chk {"), tmpl, &mut out);
        rejected("template: an unused helper", &mutate(&code, "        pub(crate) fn add_u8(a: u8, b: u8) -> u8 { a + b }\n", "        pub(crate) fn add_u8(a: u8, b: u8) -> u8 { a + b }\n        #[inline(always)]\n        pub(crate) fn add_usize(a: usize, b: usize) -> usize { a + b }\n"), tmpl, &mut out);
        let (lo, hi) = (code.find("// Trusted glue (DESIGN.md §8.3").unwrap(), code.find("pub use __sandblaster::Acc as Acc;").unwrap());
        let module = &code[lo..hi];
        rejected("template: the module missing", &code.replacen(module, "", 1), "the glue module `__rt` is not printed", &mut out);
        rejected("template: the module after the exports", &format!("{}{module}", code.replacen(module, "", 1)), "the exports differ", &mut out);
        // control: the plain operator is the same checked primitive
        let plain = mutate(&code, add, "l1_b + 3u32");
        let st = roundtrip::check(&plain, &em.opt, &mut out, &c.sm, &c.reexports).unwrap();
        assert!(st.failures.is_empty(), "the operator denotes the same checked primitive: {:?}", st.failures);
    });
}
