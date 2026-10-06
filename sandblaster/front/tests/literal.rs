//! The literal reading L of rustc's MIR (`crate::mir::literal`,
//! `docs/mir-lift.md` §20.4) and the statement of a function's theorem
//! (`crate::mir::stmt`, §20.5).
//!
//! Each construct on a small hand-written `.sbmir` body: its reading is
//! generated, checked by the kernel (types and termination) and evaluated
//! by the kernel on concrete inputs against the value rustc's semantics
//! gives; each risky construct has a negative twin (the input or the fuel
//! for which the reading must fail, or the value a misreading would give).
//! The acceptance runs at the end read every MIR instance of codec's varint
//! and storage's MMR and verifier, and prove the first theorems.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use sandblaster_front::diag::DiagKind;
use sandblaster_front::lift::test_hook::{self, WrongRule};
use sandblaster_front::loader::MemFs;
use sandblaster_front::mir::checked::{self, Entry, Prover};
use sandblaster_front::mir::literal::{Gen, KNames, LFn};
use sandblaster_front::mir::{self, ModuleNames};
use sandblaster_front::target::TargetInfo;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::Lvl;
use sandblaster_kernel::value::{Budget, VEnv};

const HEADER: &str = r#"(sbmir 1)
(rustc "rustc 1.98.0-nightly (8b6558a02 2026-06-20)")
(crate "k")
(module "k::m")
(overflow-checks on)
(exclude)
"#;

/// The subset's declarations the fixtures' module types are read as.
const STUBS: &str = "inductive crate::m::P { | P(a : U32, b : U32) }\n";

/// The kernel environment of a lifted crate's names (the prelude, the lift
/// prelude and models: `crate::__lift`, `crate::__lift_model`) plus
/// [`STUBS`], on the elaboration thread.
fn with_env(f: impl FnOnce(&mut Env) + Send) {
    let root = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n#[lift(mir = \"w.sbmir\")]\nmod w;\npub use w::{Counter, Wrap};\n";
    let fs = MemFs::from_files([("r/mod.rs", root), ("r/w.rs", include_str!("mir_fixtures/lift_w/w.rs")), ("r/w.sbmir", include_str!("mir_fixtures/lift_w/w.sbmir"))]);
    let c = sandblaster_front::driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    sandblaster_front::elab::with_big_stack(move || {
        let mut out = checked::elaborate_names(k, &[]);
        out.env.load_core(STUBS, &mut Budget { steps: 1_000_000 }).expect("stubs");
        f(&mut out.env)
    });
}

fn names() -> ModuleNames {
    let mut host_enums = BTreeMap::new();
    host_enums.insert("Error".to_string(), vec!["EndOfBuffer".to_string()]);
    ModuleNames { module: String::new(), sealed: BTreeSet::new(), host_enums, requires: BTreeSet::new(), open: BTreeMap::new(), dsl_modules: vec!["crate::m".into()], current: Default::default(), consts: BTreeMap::new(), invariant_types: BTreeSet::new(), host: Default::default() }
}

/// The reading of a fixture, loaded (every instance with a body).
struct Fixture {
    m: mir::ir::Sbmir,
    names: ModuleNames,
    lit: checked::Literal,
}

fn load(env: &mut Env, body: &str) -> Fixture {
    let l = mir::load(&format!("{HEADER}{body}"), &|_| None, names(), "m").expect("load");
    let lit = checked::load_literal(env, &l.m, &l.names, &[], None).unwrap_or_else(|e| panic!("{e}"));
    assert!(lit.refused.is_empty(), "{:?}", lit.refused);
    Fixture { m: l.m, names: l.names, lit }
}

impl Fixture {
    fn lf(&self, f: &str) -> &LFn {
        self.lit.lfn(&format!("k::m::{f}")).unwrap_or_else(|| panic!("no reading of `{f}`"))
    }

    /// `run fuel b0 (Some init)` of `f` at the arguments (core text; a
    /// `&mut` parameter's argument is its referent, held in its cell; an
    /// `Option<&mut T>`'s is the referent, or `-` for `None`).
    fn run(&self, f: &str, fuel: usize, args: &[&str]) -> String {
        let lf = self.lf(f);
        let rc = format!("Tuple2(L::{}::Root, List(mir::Proj))", lf.id);
        let code = |j: usize| format!("tuple2[L::{id}::Root, List(mir::Proj)](L::{id}::Root::rc{j}, Nil[mir::Proj])", id = lf.id);
        let mut slots: Vec<String> = Vec::new();
        for (i, t) in lf.local_tys.iter().enumerate() {
            let t = t.replace("@RC@", &rc);
            slots.push(match lf.cells.iter().position(|c| c.param == i && c.parent.is_none()) {
                Some(_) if i >= 1 && i <= args.len() && args[i - 1] == "-" => format!("Some[{t}](None[{rc}])"),
                Some(j) if i >= 1 && i <= args.len() && lf.cells[j].optional => format!("Some[{t}](Some[{rc}]({}))", code(j)),
                Some(j) if i >= 1 && i <= args.len() => format!("Some[{t}]({})", code(j)),
                _ if i >= 1 && i <= args.len() => format!("Some[{t}]({})", args[i - 1]),
                _ => format!("None[{t}]"),
            });
        }
        for c in &lf.cells {
            let ct = c.ty.replace("@RC@", &rc);
            slots.push(if args[c.param - 1] == "-" { format!("None[{ct}]") } else { format!("Some[{ct}]({})", args[c.param - 1]) });
        }
        let fuel = (0..fuel).fold("Nil[Unit]".to_string(), |l, _| format!("Cons[Unit](tt, {l})"));
        format!("{} ({fuel}) {}::b0 (mir::Res::Ret[{st}]({st}::st({})))", lf.run, lf.blk, slots.join(", "), st = lf.st)
    }
}

/// The kernel's value of `got` is the value of `want` (both closed core text).
#[track_caller]
fn same(env: &Env, got: &str, want: &str) {
    let mut b = Budget { steps: 2_000_000_000 };
    let (g, w) = (env.parse_term(&[], got).unwrap_or_else(|e| panic!("{e}\n{got}")), env.parse_term(&[], want).unwrap_or_else(|e| panic!("{e}\n{want}")));
    let gv = env.eval(&VEnv::default(), Lvl(0), &g, &mut b).expect("eval");
    let wv = env.eval(&VEnv::default(), Lvl(0), &w, &mut b).expect("eval");
    if !env.conv(Lvl(0), &gv, &wv, &mut b).expect("conv") {
        let shown = env.eval_closed(&g, &mut b).map(|t| env.print_term(&[], &t)).unwrap_or_else(|e| format!("{e}"));
        panic!("the reading gives\n  {shown}\nwhere rustc's semantics gives\n  {want}");
    }
}

// ---------------------------------------------------------------------------
// arithmetic: checked operations, undefined behaviour, shifts, signed bits
// ---------------------------------------------------------------------------

const ARITH: &str = r#"(fn "k::m::add" (kind root) (def "k::m::add") (args ()) (item fn "add") (argc 2)
  (locals (0 u16 mut) (1 u16 imm) (2 u16 imm) (3 (tuple u16 bool) mut))
  (bb 0 (assign (p 3) (checked add (copy (p 1)) (copy (p 2)))) (assert (move (p 3 (field 1 bool))) false overflow 1))
  (bb 1 (assign (p 0) (use (move (p 3 (field 0 u16))))) (return)))
(fn "k::m::div" (kind root) (def "k::m::div") (args ()) (item fn "div") (argc 2)
  (locals (0 u32 mut) (1 u32 imm) (2 u32 imm))
  (bb 0 (assign (p 0) (bin div (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::shl" (kind root) (def "k::m::shl") (args ()) (item fn "shl") (argc 2)
  (locals (0 u8 mut) (1 u8 imm) (2 u32 imm))
  (bb 0 (assign (p 0) (bin shl (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::shlu" (kind root) (def "k::m::shlu") (args ()) (item fn "shlu") (argc 2)
  (locals (0 u8 mut) (1 u8 imm) (2 u32 imm))
  (bb 0 (assign (p 0) (bin shl-unchecked (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::slt" (kind root) (def "k::m::slt") (args ()) (item fn "slt") (argc 2)
  (locals (0 bool mut) (1 i8 imm) (2 i8 imm))
  (bb 0 (assign (p 0) (bin lt (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::ult" (kind root) (def "k::m::ult") (args ()) (item fn "ult") (argc 2)
  (locals (0 bool mut) (1 u8 imm) (2 u8 imm))
  (bb 0 (assign (p 0) (bin lt (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::sext" (kind root) (def "k::m::sext") (args ()) (item fn "sext") (argc 1)
  (locals (0 i64 mut) (1 i16 imm))
  (bb 0 (assign (p 0) (cast int-to-int (copy (p 1)) i64)) (return)))
(fn "k::m::zext" (kind root) (def "k::m::zext") (args ()) (item fn "zext") (argc 1)
  (locals (0 u64 mut) (1 u16 imm))
  (bb 0 (assign (p 0) (cast int-to-int (copy (p 1)) u64)) (return)))
(fn "k::m::sar" (kind root) (def "k::m::sar") (args ()) (item fn "sar") (argc 2)
  (locals (0 i32 mut) (1 i32 imm) (2 u32 imm))
  (bb 0 (assign (p 0) (bin shr (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::cnt" (kind root) (def "k::m::cnt") (args ()) (item fn "cnt") (argc 1)
  (locals (0 u32 mut) (1 u64 imm))
  (bb 0 (call (intrinsic "ctlz" (u64)) (args (copy (p 1))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::swap" (kind root) (def "k::m::swap") (args ()) (item fn "swap") (argc 1)
  (locals (0 u32 mut) (1 u32 imm))
  (bb 0 (call (intrinsic "bswap" (u32)) (args (copy (p 1))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::le" (kind root) (def "k::m::le") (args ()) (item fn "le") (argc 1)
  (locals (0 (array u8 4) mut) (1 u32 imm))
  (bb 0 (assign (p 0) (cast transmute (copy (p 1)) (array u8 4))) (return)))
"#;

#[test]
fn checked_and_partial_arithmetic_fail_exactly_where_rust_panics_or_is_undefined() {
    with_env(|env| {
        let fx = load(env, ARITH);
        same(env, &fx.run("add", 0, &["3u16", "4u16"]), "mir::Res::Ret[U16](7u16)");
        // negative twin: the overflow assert fails
        same(env, &fx.run("add", 0, &["65535u16", "1u16"]), "mir::Res::Panic[U16]");
        same(env, &fx.run("div", 0, &["7u32", "2u32"]), "mir::Res::Ret[U32](3u32)");
        same(env, &fx.run("div", 0, &["7u32", "0u32"]), "mir::Res::Stuck[U32]");
        // `Shl` masks its amount (9 is 1 for a byte); `ShlUnchecked` is undefined there
        same(env, &fx.run("shl", 0, &["1u8", "9u32"]), "mir::Res::Ret[U8](2u8)");
        same(env, &fx.run("shlu", 0, &["1u8", "9u32"]), "mir::Res::Stuck[U8]");
        same(env, &fx.run("shlu", 0, &["1u8", "7u32"]), "mir::Res::Ret[U8](128u8)");
    });
}

#[test]
fn signed_values_are_their_bits_with_signed_comparisons_and_sign_extension() {
    with_env(|env| {
        let fx = load(env, ARITH);
        // -1 < 1 for `i8` (bits 255), while 255 < 1 is false for `u8`
        same(env, &fx.run("slt", 0, &["255u8", "1u8"]), "mir::Res::Ret[Bool](true)");
        same(env, &fx.run("ult", 0, &["255u8", "1u8"]), "mir::Res::Ret[Bool](false)");
        // `-2i16 as i64` extends the sign; `65534u16 as u64` does not
        same(env, &fx.run("sext", 0, &["crate::__lift::I16::I16(65534u16)"]), "mir::Res::Ret[crate::__lift::I64](crate::__lift::I64::I64(18446744073709551614u64))");
        same(env, &fx.run("zext", 0, &["65534u16"]), "mir::Res::Ret[U64](65534u64)");
        // `-8i32 >> 1` is arithmetic
        same(env, &fx.run("sar", 0, &["crate::__lift::I32::I32(4294967288u32)", "1u32"]), "mir::Res::Ret[crate::__lift::I32](crate::__lift::I32::I32(4294967292u32))");
    });
}

#[test]
fn intrinsics_and_transmute_are_their_primitives() {
    with_env(|env| {
        let fx = load(env, ARITH);
        same(env, &fx.run("cnt", 0, &["1u64"]), "mir::Res::Ret[U32](63u32)");
        same(env, &fx.run("swap", 0, &["16909060u32"]), "mir::Res::Ret[U32](67305985u32)");
        // the targets are little-endian
        same(env, &fx.run("le", 0, &["16909060u32"]), "mir::Res::Ret[Array U8 4usize](u32::to_le_bytes 16909060u32)");
        same(env, &fx.run("le", 0, &["16909060u32"]), "mir::Res::Ret[Array U8 4usize](pair(Array U8 4usize, Cons[U8](4u8, Cons[U8](3u8, Cons[U8](2u8, Cons[U8](1u8, Nil[U8])))), refl(Int, 4int)))");
    });
}

/// Findings of the review of the generator against the MIR reference
/// (stage cs-assurance): readings that gave a value where rustc's
/// semantics differ, each now `None` (or refused by the parse) with its twin.
const REVIEW: &str = r#"(adt-def "std::option::Option<u16>" (path "std::option::Option") (kind enum) (args (u16))
  (variant 0 "None" 0)
  (variant 1 "Some" 1 (field "0" u16)))
(fn "k::m::wide" (kind root) (def "k::m::wide") (args ()) (item fn "wide") (argc 2)
  (locals (0 u128 mut) (1 u128 imm) (2 u128 imm))
  (bb 0 (assign (p 0) (bin add (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::narrow" (kind root) (def "k::m::narrow") (args ()) (item fn "narrow") (argc 2)
  (locals (0 u64 mut) (1 u64 imm) (2 u64 imm))
  (bb 0 (assign (p 0) (bin add (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::shlw" (kind root) (def "k::m::shlw") (args ()) (item fn "shlw") (argc 2)
  (locals (0 u8 mut) (1 u8 imm) (2 u64 imm))
  (bb 0 (assign (p 0) (bin shl-unchecked (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::zst" (kind root) (def "k::m::zst") (args ()) (item fn "zst") (argc 0)
  (locals (0 (adt "std::option::Option<u16>") mut))
  (bb 0 (assign (p 0) (use (zst (adt "std::option::Option<u16>")))) (return)))
(adt-def "std::ops::RangeTo<usize>" (path "std::ops::RangeTo") (kind struct) (args (usize))
  (variant 0 "RangeTo" 0 (field "end" usize) (no-glue)))
(adt-def "k::myops::RangeTo<usize>" (path "k::myops::RangeTo") (kind struct) (args (usize))
  (variant 0 "RangeTo" 0 (field "end" usize) (no-glue)))
(adt-def "option::Option<u16>" (path "option::Option") (kind enum) (args (u16))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" u16) (no-glue)))
(fn "k::m::pre" (kind root) (def "k::m::pre") (args ()) (item fn "pre") (argc 2)
  (locals (0 usize mut) (1 (array u8 4) imm) (2 usize imm) (3 (ref shared (slice u8)) mut) (4 (adt "std::ops::RangeTo<usize>") mut))
  (bb 0 (assign (p 4) (agg (adt (adt "std::ops::RangeTo<usize>") 0) (copy (p 2)))) (call (leaf "std::ops::Index::index" ((array u8 4) (adt "std::ops::RangeTo<usize>"))) (args (copy (p 1)) (move (p 4))) (p 3) 1))
  (bb 1 (assign (p 0) (un ptr-metadata (copy (p 3)))) (return)))
(fn "k::m::mypre" (kind root) (def "k::m::mypre") (args ()) (item fn "mypre") (argc 2)
  (locals (0 usize mut) (1 (array u8 4) imm) (2 usize imm) (3 (ref shared (slice u8)) mut) (4 (adt "k::myops::RangeTo<usize>") mut))
  (bb 0 (assign (p 4) (agg (adt (adt "k::myops::RangeTo<usize>") 0) (copy (p 2)))) (call (leaf "std::ops::Index::index" ((array u8 4) (adt "k::myops::RangeTo<usize>"))) (args (copy (p 1)) (move (p 4))) (p 3) 1))
  (bb 1 (assign (p 0) (un ptr-metadata (copy (p 3)))) (return)))
(fn "k::m::other" (kind root) (def "k::m::other") (args ()) (item fn "other") (argc 1)
  (locals (0 (adt "option::Option<u16>") mut) (1 u16 imm))
  (bb 0 (assign (p 0) (agg (adt (adt "option::Option<u16>") 1) (copy (p 1)))) (return)))
(fn "k::m::myidx" (kind root) (def "k::m::myidx") (args ()) (item fn "myidx") (argc 2)
  (locals (0 usize mut) (1 (array u8 4) imm) (2 usize imm) (3 (ref shared (slice u8)) mut) (4 (adt "std::ops::RangeTo<usize>") mut))
  (bb 0 (assign (p 4) (agg (adt (adt "std::ops::RangeTo<usize>") 0) (copy (p 2)))) (call (leaf "k::myops::Index::index" ((array u8 4) (adt "std::ops::RangeTo<usize>"))) (args (copy (p 1)) (move (p 4))) (p 3) 1))
  (bb 1 (assign (p 0) (un ptr-metadata (copy (p 3)))) (return)))
"#;

#[test]
fn readings_the_review_found_wrong_are_none_where_rust_differs() {
    with_env(|env| {
        let fx = load(env, REVIEW);
        // `u128` was read as a 64-bit word (its values truncated): it is not modeled
        assert!(fx.lf("wide").local_tys.iter().all(|t| t == "mir::Unmodeled"), "{:?}", fx.lf("wide").local_tys);
        assert!(fx.lf("wide").faults.iter().any(|f| f.starts_with("bb0")), "{:?}", fx.lf("wide").faults);
        // negative twin: a `u64` sum is read
        assert!(fx.lf("narrow").faults.is_empty(), "{:?}", fx.lf("narrow").faults);
        same(env, &fx.run("narrow", 0, &["2u64", "3u64"]), "mir::Res::Ret[U64](5u64)");
        // `ShlUnchecked` by a `u64` amount of 2^32 is undefined behaviour: its low
        // 32 bits (0) were tested instead
        same(env, &fx.run("shlw", 0, &["1u8", "4294967296u64"]), "mir::Res::Stuck[U8]");
        same(env, &fx.run("shlw", 0, &["1u8", "3u64"]), "mir::Res::Ret[U8](8u8)");
        // a zero-sized constant of a type with several variants is not read as
        // its first variant
        assert!(fx.lf("zst").faults.iter().any(|f| f.contains("zst") || f.contains("Zst")), "{:?}", fx.lf("zst").faults);
        // a library type or range is core's by its exact path: an index by a
        // type whose path merely ends in `ops::RangeTo` was read as `&a[..j]`
        let a = "pair(Array U8 4usize, Cons[U8](1u8, Cons[U8](2u8, Cons[U8](3u8, Cons[U8](4u8, Nil[U8])))), refl(Int, 4int))";
        assert!(fx.lf("mypre").faults.iter().any(|f| f.contains("k::myops::RangeTo")), "{:?}", fx.lf("mypre").faults);
        same(env, &fx.run("mypre", 0, &[a, "2usize"]), "mir::Res::Stuck[Usize]");
        // negative twin: core's `RangeTo`
        same(env, &fx.run("pre", 0, &[a, "2usize"]), "mir::Res::Ret[Usize](2usize)");
        // the same for the index leaf itself (stage tcb-review): a crate's own
        // `myops::Index::index` on an array (the printer makes any such call a
        // leaf) was read as core's indexing; its meaning is the crate's impl
        assert!(fx.lf("myidx").faults.iter().any(|f| f.contains("k::myops::Index::index")), "{:?}", fx.lf("myidx").faults);
        same(env, &fx.run("myidx", 0, &[a, "2usize"]), "mir::Res::Stuck[Usize]");
        // a crate's own `option::Option` is not the prelude's `Option` (it is
        // read as L's own inductive), while core's is
        assert!(fx.lit.state.adt_ty("option::Option<u16>").is_some_and(|t| t.starts_with("L::")), "{:?}", fx.lit.state.adt_ty("option::Option<u16>"));
        assert_eq!(fx.lit.state.adt_ty("std::option::Option<u16>").as_deref(), Some("Option(U16)"));
    });
}

/// The parse L reads (trusted since stage cs-assurance) guesses nothing.
#[test]
fn the_parse_refuses_what_it_would_have_guessed() {
    let ok = r#"(adt-def "k::m::E" (path "k::m::E") (kind enum) (args ())
  (variant 0 "A" 0 (no-glue))
  (variant 1 "B" 5 (no-glue)))
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 bool mut) (1 bool imm))
  (bb 0 (assert (copy (p 1)) true overflow 1))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return)))
"#;
    let parse = |t: &str| mir::ir::parse(&format!("{HEADER}{t}"));
    let m = parse(ok).expect("well-formed");
    assert_eq!(m.adts["k::m::E"].variants[1].discr, 5);
    for (bad, what) in [
        (ok.replace("(variant 1 \"B\" 5", "(variant 2 \"B\" 5"), "variants out of order"),
        (ok.replace("\"B\" 5", "\"B\" five"), "variant discriminant"),
        (ok.replace("(1 bool imm)", "(2 bool imm)"), "locals out of order"),
        (ok.replace("true overflow", "yes overflow"), "assert's expected value"),
    ] {
        let e = parse(&bad).expect_err(what);
        assert!(e.contains(what), "{what}: {e}");
    }
}

// ---------------------------------------------------------------------------
// control flow: switches, loops and fuel, panics, self-calls
// ---------------------------------------------------------------------------

const FLOW: &str = r#"(adt-def "std::option::Option<u16>" (path "std::option::Option") (kind enum) (args (u16))
  (variant 0 "None" 0)
  (variant 1 "Some" 1 (field "0" u16)))
(fn "k::m::get" (kind root) (def "k::m::get") (args ()) (item fn "get") (argc 1)
  (locals (0 u16 mut) (1 (adt "std::option::Option<u16>") imm) (2 isize mut))
  (bb 0 (assign (p 2) (discr (p 1))) (switch (move (p 2)) (0 1) (1 2) (otherwise 3)))
  (bb 1 (assign (p 0) (use (int u16 0))) (return))
  (bb 2 (assign (p 0) (use (copy (p 1 (downcast 1) (field 0 u16))))) (return))
  (bb 3 (unreachable)))
(fn "k::m::sum" (kind root) (def "k::m::sum") (args ()) (item fn "sum") (argc 1)
  (locals (0 u32 mut) (1 u32 imm) (2 u32 mut) (3 bool mut) (4 (tuple u32 bool) mut) (5 (tuple u32 bool) mut))
  (bb 0 (assign (p 0) (use (int u32 0))) (assign (p 2) (use (int u32 0))) (goto 1))
  (bb 1 (assign (p 3) (bin lt (copy (p 2)) (copy (p 1)))) (switch (move (p 3)) (0 3) (otherwise 2)))
  (bb 2 (assign (p 4) (checked add (copy (p 0)) (copy (p 2)))) (assert (move (p 4 (field 1 bool))) false overflow 4))
  (bb 3 (return))
  (bb 4 (assign (p 0) (use (move (p 4 (field 0 u32))))) (assign (p 5) (checked add (copy (p 2)) (int u32 1))) (assert (move (p 5 (field 1 bool))) false overflow 5))
  (bb 5 (assign (p 2) (use (move (p 5 (field 0 u32))))) (goto 1)))
(fn "k::m::nz" (kind root) (def "k::m::nz") (args ()) (item fn "nz") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 never imm))
  (bb 0 (assign (p 2) (bin eq (copy (p 1)) (int u16 0))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (call (diverge "core::panicking::panic") (args) (p 3) none))
  (bb 2 (assign (p 0) (use (copy (p 1)))) (return)))
(fn "k::m::fact" (kind root) (def "k::m::fact") (args ()) (item fn "fact") (argc 1)
  (locals (0 u32 mut) (1 u32 imm) (2 bool mut) (3 u32 mut) (4 u32 mut))
  (bb 0 (assign (p 2) (bin eq (copy (p 1)) (int u32 0))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (int u32 1))) (return))
  (bb 2 (assign (p 3) (bin sub (copy (p 1)) (int u32 1))) (call (fn "k::m::fact") (args (move (p 3))) (p 4) 3))
  (bb 3 (assign (p 0) (bin mul (copy (p 1)) (move (p 4)))) (return)))
(fn "k::m::exp" (kind callee) (def "k::m::exp") (args ()) (item fn "exp") (argc 2)
  (locals (0 u16 mut) (1 (adt "std::option::Option<u16>") imm) (2 (ref shared str) imm) (3 isize mut) (4 never imm))
  (bb 0 (assign (p 3) (discr (p 1))) (switch (move (p 3)) (1 2) (otherwise 1)))
  (bb 1 (call (diverge "core::option::expect_failed") (args (copy (p 2))) (p 4) none))
  (bb 2 (assign (p 0) (use (copy (p 1 (downcast 1) (field 0 u16))))) (return)))
(fn "k::m::expect" (kind root) (def "k::m::expect") (args ()) (item fn "expect") (argc 1)
  (locals (0 u16 mut) (1 (adt "std::option::Option<u16>") imm) (2 (ref shared str) mut))
  (bb 0 (assign (p 2) (use (unsupported "constant of type (ref shared str)"))) (call (fn "k::m::exp") (args (copy (p 1)) (move (p 2))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::clo::{closure#0}" (kind callee) (def "k::m::clo::{closure#0}") (args ()) (item closure) (argc 2)
  (locals (0 u16 mut) (1 (closure "k::m::clo::{closure#0}" unit) imm) (2 u16 imm))
  (bb 0 (assign (p 0) (bin add (copy (p 2)) (int u16 1))) (return)))
(fn "k::m::clo" (kind root) (def "k::m::clo") (args ()) (item fn "clo") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 (closure "k::m::clo::{closure#0}" unit) mut) (3 (tuple u16) mut))
  (bb 0 (assign (p 2) (agg (closure (closure "k::m::clo::{closure#0}" unit)))) (assign (p 3) (agg (tuple) (copy (p 1)))) (call (fn "k::m::clo::{closure#0}") (args (move (p 2)) (move (p 3))) (p 0) 1))
  (bb 1 (return)))
"#;

#[test]
fn a_switch_tests_the_value_and_a_discriminant_its_variant() {
    with_env(|env| {
        let fx = load(env, FLOW);
        same(env, &fx.run("get", 0, &["Some[U16](5u16)"]), "mir::Res::Ret[U16](5u16)");
        same(env, &fx.run("get", 0, &["None[U16]"]), "mir::Res::Ret[U16](0u16)");
    });
}

#[test]
fn a_loop_needs_one_unit_of_fuel_per_entry_of_its_header() {
    with_env(|env| {
        let fx = load(env, FLOW);
        assert_eq!(fx.lf("sum").headers, vec![1]);
        // 0 + 1 + 2 + 3: the header is entered 5 times
        same(env, &fx.run("sum", 5, &["4u32"]), "mir::Res::Ret[U32](6u32)");
        same(env, &fx.run("sum", 50, &["4u32"]), "mir::Res::Ret[U32](6u32)");
        // negative twin: one unit less is out of fuel
        same(env, &fx.run("sum", 4, &["4u32"]), "mir::Res::Stuck[U32]");
    });
}

#[test]
fn a_path_that_panics_fails_and_a_self_call_consumes_fuel() {
    with_env(|env| {
        let fx = load(env, FLOW);
        same(env, &fx.run("nz", 0, &["3u16"]), "mir::Res::Ret[U16](3u16)");
        same(env, &fx.run("nz", 0, &["0u16"]), "mir::Res::Panic[U16]");
        assert_eq!(fx.lf("nz").panics, vec![1]);
        assert!(fx.lf("nz").faults.is_empty(), "{:?}", fx.lf("nz").faults);
        // 4! with the four nested calls each consuming one unit
        same(env, &fx.run("fact", 4, &["4u32"]), "mir::Res::Ret[U32](24u32)");
        same(env, &fx.run("fact", 3, &["4u32"]), "mir::Res::Stuck[U32]");
    });
}

#[test]
fn a_string_constant_is_a_token_and_a_closure_takes_its_arguments_spread() {
    with_env(|env| {
        let fx = load(env, FLOW);
        same(env, &fx.run("expect", 0, &["Some[U16](3u16)"]), "mir::Res::Ret[U16](3u16)");
        same(env, &fx.run("expect", 0, &["None[U16]"]), "mir::Res::Panic[U16]");
        same(env, &fx.run("clo", 0, &["4u16"]), "mir::Res::Ret[U16](5u16)");
    });
}

/// The outcomes of a run (`mir::Res`, docs/mir-lift.md §20.4): a panic is
/// read only where the MIR certainly panics; everything else that gives no
/// value is stuck. Each body is `if x <= 10 { x } else { <panic path> }`,
/// the panic path built as rustc builds `assert!(c, "msg")` (the message's
/// `fmt::Arguments`, then `std::rt::panic_fmt`), or with one construct
/// changed: a function returning `!` that is no panic (`process::abort`, the
/// aborting `panic_nounwind_fmt`), an `assume` on the way (undefined
/// behaviour unless it holds), a switch one of whose targets is
/// `unreachable` (undefined behaviour), a jump to itself (no termination).
const PANICS: &str = r#"(adt-def "std::fmt::Arguments<'_>" (path "std::fmt::Arguments") (kind struct) (args ())
  (variant 0 "Arguments" 0 (field "template" usize) (no-glue)))
(fn "std::fmt::Arguments::<'_>::from_str" (kind callee) (def "std::fmt::Arguments::<'a>::from_str") (args ()) (item inherent (adt "std::fmt::Arguments<'_>") "from_str") (argc 1)
  (locals (0 (adt "std::fmt::Arguments<'_>") mut) (1 (ref shared str) imm))
  (bb 0 (unreachable)))
(fn "k::m::msg" (kind root) (def "k::m::msg") (args ()) (item fn "msg") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 never imm) (4 (adt "std::fmt::Arguments<'_>") mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return))
  (bb 2 (call (fn "std::fmt::Arguments::<'_>::from_str") (args (unsupported "constant of type (ref shared str)")) (p 4) 3))
  (bb 3 (call (diverge "std::rt::panic_fmt") (args (move (p 4))) (p 3) none)))
(fn "k::m::abort" (kind root) (def "k::m::abort") (args ()) (item fn "abort") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 never imm) (4 (adt "std::fmt::Arguments<'_>") mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return))
  (bb 2 (call (fn "std::fmt::Arguments::<'_>::from_str") (args (unsupported "constant of type (ref shared str)")) (p 4) 3))
  (bb 3 (call (diverge "std::process::abort") (args) (p 3) none)))
(fn "k::m::nounwind" (kind root) (def "k::m::nounwind") (args ()) (item fn "nounwind") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 never imm) (4 (adt "std::fmt::Arguments<'_>") mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return))
  (bb 2 (call (fn "std::fmt::Arguments::<'_>::from_str") (args (unsupported "constant of type (ref shared str)")) (p 4) 3))
  (bb 3 (call (diverge "core::panicking::panic_nounwind_fmt") (args (move (p 4))) (p 3) none)))
(fn "k::m::assumed" (kind root) (def "k::m::assumed") (args ()) (item fn "assumed") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 never imm))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return))
  (bb 2 (assume (copy (p 2))) (call (diverge "core::panicking::panic") (args) (p 3) none)))
(fn "k::m::half" (kind root) (def "k::m::half") (args ()) (item fn "half") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 never imm) (4 u16 mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return))
  (bb 2 (assign (p 4) (bin rem (copy (p 1)) (int u16 2))) (switch (move (p 4)) (0 3) (otherwise 4)))
  (bb 3 (call (diverge "core::panicking::panic") (args) (p 3) none))
  (bb 4 (unreachable)))
(fn "k::m::wrapped" (kind root) (def "k::m::wrapped") (args ()) (item fn "wrapped") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 never imm) (4 u16 mut) (5 u32 mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return))
  (bb 2 (assign (p 4) (bin add (copy (p 1)) (int u16 1))) (assign (p 5) (cast int-to-int (copy (p 4)) u32)) (call (diverge "core::panicking::panic") (args) (p 3) none)))
(fn "k::m::divided" (kind root) (def "k::m::divided") (args ()) (item fn "divided") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 never imm) (4 u16 mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return))
  (bb 2 (assign (p 4) (bin div (int u16 100) (copy (p 1)))) (call (diverge "core::panicking::panic") (args) (p 3) none)))
(fn "k::m::transmuted" (kind root) (def "k::m::transmuted") (args ()) (item fn "transmuted") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 never imm) (4 i16 mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return))
  (bb 2 (assign (p 4) (cast transmute (copy (p 1)) i16)) (call (diverge "core::panicking::panic") (args) (p 3) none)))
(fn "k::m::spin" (kind root) (def "k::m::spin") (args ()) (item fn "spin") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return))
  (bb 2 (goto 2)))
"#;

/// A block every path of which ends in a call of a panic function (the
/// message built on the way) is a panic; its twins are stuck.
#[test]
fn a_panic_is_read_only_where_every_path_ends_in_a_panic_function() {
    with_env(|env| {
        let fx = load(env, PANICS);
        same(env, &fx.run("msg", 0, &["4u16"]), "mir::Res::Ret[U16](4u16)");
        same(env, &fx.run("msg", 0, &["11u16"]), "mir::Res::Panic[U16]");
        assert_eq!(fx.lf("msg").panics, vec![2, 3]);
        assert!(fx.lf("msg").faults.is_empty(), "{:?}", fx.lf("msg").faults);
        // negative twins: a function returning `!` that is no panic function
        // (an abort; the aborting `panic_nounwind_fmt`), an `assume` on the
        // way, a switch one of whose targets is `unreachable`: stuck
        for f in ["abort", "nounwind", "assumed", "half"] {
            same(env, &fx.run(f, 0, &["4u16"]), "mir::Res::Ret[U16](4u16)");
            same(env, &fx.run(f, 0, &["11u16"]), "mir::Res::Stuck[U16]");
        }
        for f in ["abort", "nounwind", "assumed"] {
            assert!(fx.lf(f).panics.is_empty(), "{f}: {:?}", fx.lf(f).panics);
        }
        // (`half`'s block of the panic call alone is a panic; the switch
        // that may reach `unreachable` is stuck, even where it would panic)
        assert_eq!(fx.lf("half").panics, vec![3]);
        same(env, &fx.run("half", 0, &["12u16"]), "mir::Res::Stuck[U16]");
        // the allow-lists of a panic's path: a wrapping operator and an
        // integer cast on the way are a panic; a division (undefined on a
        // zero divisor) or a transmute on the way is stuck
        for f in ["wrapped", "divided", "transmuted"] {
            same(env, &fx.run(f, 0, &["4u16"]), "mir::Res::Ret[U16](4u16)");
        }
        same(env, &fx.run("wrapped", 0, &["11u16"]), "mir::Res::Panic[U16]");
        assert_eq!(fx.lf("wrapped").panics, vec![2]);
        for f in ["divided", "transmuted"] {
            same(env, &fx.run(f, 0, &["11u16"]), "mir::Res::Stuck[U16]");
            assert!(fx.lf(f).panics.is_empty(), "{f}: {:?}", fx.lf(f).panics);
        }
    });
}

const ASSERT_KINDS: &str = r#"(fn "k::m::a_overflow" (kind root) (def "k::m::a_overflow") (args ()) (item fn "a_overflow") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (assert (copy (p 2)) true overflow 1))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return)))
(fn "k::m::a_overflow_neg" (kind root) (def "k::m::a_overflow_neg") (args ()) (item fn "a_overflow_neg") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (assert (copy (p 2)) true overflow-neg 1))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return)))
(fn "k::m::a_bounds" (kind root) (def "k::m::a_bounds") (args ()) (item fn "a_bounds") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (assert (copy (p 2)) true bounds 1))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return)))
(fn "k::m::a_div_zero" (kind root) (def "k::m::a_div_zero") (args ()) (item fn "a_div_zero") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (assert (copy (p 2)) true div-zero 1))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return)))
(fn "k::m::a_rem_zero" (kind root) (def "k::m::a_rem_zero") (args ()) (item fn "a_rem_zero") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (assert (copy (p 2)) true rem-zero 1))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return)))
(fn "k::m::a_other" (kind root) (def "k::m::a_other") (args ()) (item fn "a_other") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (assert (copy (p 2)) true other 1))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return)))
(fn "k::m::g_overflow" (kind root) (def "k::m::g_overflow") (args ()) (item fn "g_overflow") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 never imm) (4 bool mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return))
  (bb 2 (assign (p 4) (bin lt (copy (p 1)) (int u16 1000))) (assert (copy (p 4)) true overflow 3))
  (bb 3 (call (diverge "core::panicking::panic") (args) (p 3) none)))
(fn "k::m::g_other" (kind root) (def "k::m::g_other") (args ()) (item fn "g_other") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 never imm) (4 bool mut))
  (bb 0 (assign (p 2) (bin le (copy (p 1)) (int u16 10))) (switch (move (p 2)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return))
  (bb 2 (assign (p 4) (bin lt (copy (p 1)) (int u16 1000))) (assert (copy (p 4)) true other 3))
  (bb 3 (call (diverge "core::panicking::panic") (args) (p 3) none)))
"#;

/// A failed `Assert` is a panic only for the kinds whose failure panics
/// (overflow, bounds, division or remainder by zero); a kind whose failure
/// aborts (`other`: a misaligned or null pointer dereference, an invalid
/// enum construction) is stuck where it fails, and a panic's path may not
/// run it.
#[test]
fn a_failed_assert_is_a_panic_only_for_the_kinds_that_panic() {
    with_env(|env| {
        let fx = load(env, ASSERT_KINDS);
        for f in ["a_overflow", "a_overflow_neg", "a_bounds", "a_div_zero", "a_rem_zero", "a_other"] {
            same(env, &fx.run(f, 0, &["4u16"]), "mir::Res::Ret[U16](4u16)");
        }
        for f in ["a_overflow", "a_overflow_neg", "a_bounds", "a_div_zero", "a_rem_zero"] {
            same(env, &fx.run(f, 0, &["11u16"]), "mir::Res::Panic[U16]");
        }
        // negative twin: the same failed assertion of kind `other` aborts
        same(env, &fx.run("a_other", 0, &["11u16"]), "mir::Res::Stuck[U16]");
        // on a panic's path: an overflow check that may fail is a panic
        // either way, so its block panics; an `other` check is not (where
        // it fails the process aborts), so only the call's block is a
        // panic, and the block of the check, from which every path
        // diverges without every path panicking, is stuck as a whole
        assert_eq!(fx.lf("g_overflow").panics, vec![2, 3]);
        assert_eq!(fx.lf("g_other").panics, vec![3]);
        assert!(fx.lf("g_other").diverging.contains(&2), "{:?}", fx.lf("g_other").diverging);
        for f in ["g_overflow", "g_other"] {
            same(env, &fx.run(f, 0, &["4u16"]), "mir::Res::Ret[U16](4u16)");
        }
        for x in ["11u16", "2000u16"] {
            same(env, &fx.run("g_overflow", 0, &[x]), "mir::Res::Panic[U16]");
            same(env, &fx.run("g_other", 0, &[x]), "mir::Res::Stuck[U16]");
        }
    });
}

/// A path that does not terminate is stuck at every fuel, never a panic.
#[test]
fn a_path_that_does_not_terminate_is_stuck_at_every_fuel() {
    with_env(|env| {
        let fx = load(env, PANICS);
        same(env, &fx.run("spin", 0, &["4u16"]), "mir::Res::Ret[U16](4u16)");
        for fuel in [0, 1, 7, 64] {
            same(env, &fx.run("spin", fuel, &["11u16"]), "mir::Res::Stuck[U16]");
        }
    });
}

/// The library paths of the panic functions: core's and std's, generic
/// arguments dropped; a crate's own is none.
#[test]
fn panic_functions_are_core_and_std_paths() {
    use sandblaster_front::mir::literal::{lib_fn, PANIC_FNS};
    assert_eq!(lib_fn("core::panicking::assert_failed::<u64, u64>"), Some("panicking::assert_failed"));
    assert_eq!(lib_fn("std::rt::panic_fmt"), Some("rt::panic_fmt"));
    assert_eq!(lib_fn("std::fmt::Arguments::<'_>::from_str"), Some("fmt::Arguments::<'_>::from_str"));
    assert_eq!(lib_fn("std::fmt::rt::Argument::<'_>::new_display::<u64>"), Some("fmt::rt::Argument::<'_>::new_display"));
    assert!(PANIC_FNS.contains(&"panicking::panic") && PANIC_FNS.contains(&"option::expect_failed"));
    // negative twins: a crate's own function of the same path; an abort
    assert_eq!(lib_fn("k::panicking::panic"), None);
    assert!(!PANIC_FNS.iter().any(|p| p.contains("abort") || p.contains("nounwind") || p.contains("exit")));
}

/// A closure without captures that the MIR never assigns (rustc's
/// `RemoveZsts` drops the assignment of a data-free value: the local `_2` of
/// `let f = |n| ..; f(x)` is only borrowed), and its negative twin, a local
/// with data read before any assignment.
const ZST: &str = r#"(fn "k::m::cloz::{closure#0}" (kind callee) (def "k::m::cloz::{closure#0}") (args ()) (item closure) (argc 2)
  (locals (0 u16 mut) (1 (ref shared (closure "k::m::cloz::{closure#0}" unit)) imm) (2 u16 imm))
  (bb 0 (assign (p 0) (bin add (copy (p 2)) (int u16 1))) (return)))
(fn "k::m::cloz" (kind root) (def "k::m::cloz") (args ()) (item fn "cloz") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 (closure "k::m::cloz::{closure#0}" unit) imm) (3 (ref shared (closure "k::m::cloz::{closure#0}" unit)) mut) (4 (tuple u16) mut))
  (bb 0 (assign (p 3) (ref shared (p 2))) (assign (p 4) (agg (tuple) (copy (p 1)))) (call (fn "k::m::cloz::{closure#0}") (args (move (p 3)) (move (p 4))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::unset" (kind root) (def "k::m::unset") (args ()) (item fn "unset") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 u16 mut))
  (bb 0 (assign (p 0) (use (copy (p 2)))) (return)))
"#;

#[test]
fn a_data_free_local_holds_its_value_unassigned_and_a_local_with_data_does_not() {
    with_env(|env| {
        let fx = load(env, ZST);
        same(env, &fx.run("cloz", 0, &["4u16"]), "mir::Res::Ret[U16](5u16)");
        // negative twin: a local with data, never assigned, is read as a failure
        same(env, &fx.run("unset", 0, &["4u16"]), "mir::Res::Stuck[U16]");
    });
}

// ---------------------------------------------------------------------------
// references: borrows of locals, `&mut` parameters, calls and write-backs,
// nested cells and returned references
// ---------------------------------------------------------------------------

const REFS: &str = r#"(adt-def "k::m::P" (path "k::m::P") (kind struct) (args ())
  (variant 0 "P" 0 (field "a" u32) (field "b" u32) (no-glue)))
(adt-def "std::option::Option<&mut u32>" (path "std::option::Option") (kind enum) (args ((ref mut u32)))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" (ref mut u32)) (no-glue)))
(fn "k::m::bump" (kind root) (def "k::m::bump") (args ()) (item fn "bump") (argc 1)
  (locals (0 u32 mut) (1 u32 imm) (2 u32 mut) (3 (ref mut u32) mut) (4 u32 mut))
  (bb 0 (assign (p 2) (use (copy (p 1)))) (assign (p 3) (ref mut (p 2))) (assign (p 4) (bin add (copy (p 3 deref)) (int u32 1))) (assign (p 3 deref) (use (move (p 4)))) (assign (p 0) (use (copy (p 2)))) (return)))
(fn "k::m::snap" (kind root) (def "k::m::snap") (args ()) (item fn "snap") (argc 1)
  (locals (0 u32 mut) (1 u32 imm) (2 u32 mut) (3 (ref mut u32) mut) (4 u32 mut) (5 u32 mut))
  (bb 0 (assign (p 2) (use (copy (p 1)))) (assign (p 5) (use (copy (p 2)))) (assign (p 3) (ref mut (p 2))) (assign (p 4) (bin add (copy (p 3 deref)) (int u32 1))) (assign (p 3 deref) (use (move (p 4)))) (assign (p 0) (bin add (copy (p 5)) (copy (p 2)))) (return)))
(fn "k::m::inc" (kind root) (def "k::m::inc") (args ()) (item fn "inc") (argc 1)
  (locals (0 unit mut) (1 (ref mut u32) imm) (2 u32 mut))
  (bb 0 (assign (p 2) (bin add (copy (p 1 deref)) (int u32 1))) (assign (p 1 deref) (use (move (p 2)))) (return)))
(fn "k::m::twice" (kind root) (def "k::m::twice") (args ()) (item fn "twice") (argc 1)
  (locals (0 u32 mut) (1 u32 imm) (2 u32 mut) (3 (ref mut u32) mut) (4 unit mut) (5 (ref mut u32) mut) (6 unit mut))
  (bb 0 (assign (p 2) (use (copy (p 1)))) (assign (p 3) (ref mut (p 2))) (call (fn "k::m::inc") (args (move (p 3))) (p 4) 1))
  (bb 1 (assign (p 5) (ref mut (p 2))) (call (fn "k::m::inc") (args (move (p 5))) (p 6) 2))
  (bb 2 (assign (p 0) (use (copy (p 2)))) (return)))
(fn "k::m::setb" (kind root) (def "k::m::setb") (args ()) (item fn "setb") (argc 2)
  (locals (0 unit mut) (1 (ref mut (adt "k::m::P")) imm) (2 u32 imm))
  (bb 0 (assign (p 1 deref (field 1 u32)) (use (copy (p 2)))) (return)))
(fn "k::m::fieldref" (kind root) (def "k::m::fieldref") (args ()) (item fn "fieldref") (argc 1)
  (locals (0 (adt "k::m::P") mut) (1 (adt "k::m::P") imm) (2 (adt "k::m::P") mut) (3 (ref mut u32) mut) (4 unit mut))
  (bb 0 (assign (p 2) (use (copy (p 1)))) (assign (p 3) (ref mut (p 2 (field 0 u32)))) (call (fn "k::m::inc") (args (move (p 3))) (p 4) 1))
  (bb 1 (assign (p 0) (use (copy (p 2)))) (return)))
(fn "k::m::dm" (kind callee) (def "k::m::dm") (args ()) (item fn "dm") (argc 1)
  (locals (0 (ref mut u32) mut) (1 (ref mut (ref mut u32)) imm))
  (bb 0 (assign (p 0) (use (copy (p 1 deref)))) (return)))
(fn "k::m::ad" (kind callee) (def "k::m::ad") (args ()) (item fn "ad") (argc 1)
  (locals (0 (adt "std::option::Option<&mut u32>") mut) (1 (ref mut (adt "std::option::Option<&mut u32>")) imm) (2 isize mut) (3 (ref mut (ref mut u32)) mut) (4 (ref mut u32) mut))
  (bb 0 (assign (p 2) (discr (p 1 deref))) (switch (move (p 2)) (0 1) (1 2) (otherwise 3)))
  (bb 1 (assign (p 0) (agg (adt (adt "std::option::Option<&mut u32>") 0))) (return))
  (bb 2 (assign (p 3) (ref mut (p 1 deref (downcast 1) (field 0 (ref mut u32))))) (call (fn "k::m::dm") (args (move (p 3))) (p 4) 4))
  (bb 3 (unreachable))
  (bb 4 (assign (p 0) (agg (adt (adt "std::option::Option<&mut u32>") 1) (copy (p 4)))) (return)))
(fn "k::m::through" (kind root) (def "k::m::through") (args ()) (item fn "through") (argc 1)
  (locals (0 u32 mut) (1 u32 imm) (2 u32 mut) (3 (ref mut u32) mut) (4 (adt "std::option::Option<&mut u32>") mut) (5 (ref mut (adt "std::option::Option<&mut u32>")) mut) (6 (adt "std::option::Option<&mut u32>") mut) (7 isize mut) (8 (ref mut u32) mut) (9 u32 mut))
  (bb 0 (assign (p 2) (use (copy (p 1)))) (assign (p 3) (ref mut (p 2))) (assign (p 4) (agg (adt (adt "std::option::Option<&mut u32>") 1) (move (p 3)))) (assign (p 5) (ref mut (p 4))) (call (fn "k::m::ad") (args (move (p 5))) (p 6) 1))
  (bb 1 (assign (p 7) (discr (p 6))) (switch (move (p 7)) (1 2) (otherwise 3)))
  (bb 2 (assign (p 8) (use (copy (p 6 (downcast 1) (field 0 (ref mut u32)))))) (assign (p 9) (bin add (copy (p 8 deref)) (int u32 1))) (assign (p 8 deref) (use (move (p 9)))) (goto 3))
  (bb 3 (assign (p 5) (ref mut (p 4))) (call (fn "k::m::ad") (args (move (p 5))) (p 6) 4))
  (bb 4 (assign (p 7) (discr (p 6))) (switch (move (p 7)) (1 5) (otherwise 6)))
  (bb 5 (assign (p 8) (use (copy (p 6 (downcast 1) (field 0 (ref mut u32)))))) (assign (p 9) (bin mul (copy (p 8 deref)) (int u32 10))) (assign (p 8 deref) (use (move (p 9)))) (goto 6))
  (bb 6 (assign (p 0) (use (copy (p 2)))) (return)))
(fn "k::m::opt" (kind root) (def "k::m::opt") (args ()) (item fn "opt") (argc 1)
  (locals (0 unit mut) (1 (adt "std::option::Option<&mut u32>") imm) (2 isize mut) (3 (ref mut u32) mut) (4 u32 mut))
  (bb 0 (assign (p 2) (discr (p 1))) (switch (move (p 2)) (1 1) (otherwise 2)))
  (bb 1 (assign (p 3) (use (copy (p 1 (downcast 1) (field 0 (ref mut u32)))))) (assign (p 4) (bin add (copy (p 3 deref)) (int u32 1))) (assign (p 3 deref) (use (move (p 4)))) (goto 2))
  (bb 2 (return)))
"#;

#[test]
fn a_write_through_a_borrow_changes_the_place_and_a_value_read_before_keeps_its_value() {
    with_env(|env| {
        let fx = load(env, REFS);
        same(env, &fx.run("bump", 0, &["5u32"]), "mir::Res::Ret[U32](6u32)");
        // negative twin of a historical structuring bug (a value snapshot
        // restored a variable after an in-place write): the copy taken
        // before is 5, the variable after is 6
        same(env, &fx.run("snap", 0, &["5u32"]), "mir::Res::Ret[U32](11u32)");
    });
}

#[test]
fn a_mut_parameter_is_a_cell_written_back_at_each_call() {
    with_env(|env| {
        let fx = load(env, REFS);
        // the cell's final value is the output
        same(env, &fx.run("inc", 0, &["5u32"]), "mir::Res::Ret[U32](6u32)");
        same(env, &fx.run("twice", 0, &["5u32"]), "mir::Res::Ret[U32](7u32)");
        same(env, &fx.run("setb", 0, &["crate::m::P::P(1u32, 2u32)", "9u32"]), "mir::Res::Ret[crate::m::P](crate::m::P::P(1u32, 9u32))");
        // a borrow of a field is a code with a path; the callee's write lands there
        same(env, &fx.run("fieldref", 0, &["crate::m::P::P(1u32, 2u32)"]), "mir::Res::Ret[crate::m::P](crate::m::P::P(2u32, 2u32))");
        // an `Option<&mut T>` parameter: a cell when present
        same(env, &fx.run("opt", 0, &["5u32"]), "mir::Res::Ret[Option(U32)](Some[U32](6u32))");
        same(env, &fx.run("opt", 0, &["-"]), "mir::Res::Ret[Option(U32)](None[U32])");
    });
}

#[test]
fn a_returned_reference_is_translated_back_and_nested_cells_are_written_back() {
    with_env(|env| {
        let fx = load(env, REFS);
        // `ad` (`Option::as_deref_mut`'s shape) holds an optional `&mut` in
        // its cell: a nested cell; `dm` (`DerefMut` of `&mut &mut T`) returns
        // its nested cell's code, which the callers translate back to theirs
        assert_eq!(fx.lf("ad").cells.len(), 2);
        assert_eq!(fx.lf("ad").cells[1].parent, Some(0));
        assert_eq!(fx.lf("dm").cells.len(), 2);
        // both writes through the returned references land in `x`: (5 + 1) * 10
        same(env, &fx.run("through", 0, &["5u32"]), "mir::Res::Ret[U32](60u32)");
    });
}

// ---------------------------------------------------------------------------
// values: aggregates, discriminants, drops, leaves, slices
// ---------------------------------------------------------------------------

const VALUES: &str = r#"(adt-def "k::lib::E" (path "k::lib::E") (kind enum) (args ())
  (variant 0 "A" -1 (no-glue))
  (variant 1 "B" 1 (field "0" u16)))
(adt-def "std::ops::RangeToInclusive<usize>" (path "std::ops::RangeToInclusive") (kind struct) (args (usize))
  (variant 0 "RangeToInclusive" 0 (field "end" usize) (no-glue)))
(adt-def "std::result::Result<u8, bytes::TryGetError>" (path "std::result::Result") (kind enum) (args (u8 (adt "bytes::TryGetError")))
  (variant 0 "Ok" 0 (field "0" u8))
  (variant 1 "Err" 1 (field "0" (adt "bytes::TryGetError"))))
(adt-def "bytes::TryGetError" (path "bytes::TryGetError") (kind struct) (args ())
  (variant 0 "TryGetError" 0 (field "requested" usize) (field "available" usize)))
(adt-def "std::vec::Vec<u32>" (path "std::vec::Vec") (kind struct) (args (u32 (adt "std::alloc::Global")))
  (variant 0 "Vec" 0))
(adt-def "std::alloc::Global" (path "std::alloc::Global") (kind struct) (args ())
  (variant 0 "Global" 0 (no-glue)))
(fn "k::m::mk" (kind root) (def "k::m::mk") (args ()) (item fn "mk") (argc 2)
  (locals (0 (tuple (array u8 2) (array u8 3)) mut) (1 u8 imm) (2 u8 imm) (3 (array u8 2) mut) (4 (array u8 3) mut))
  (bb 0 (assign (p 3) (agg (array u8) (copy (p 1)) (copy (p 2)))) (assign (p 4) (repeat (copy (p 2)) 3)) (assign (p 0) (agg (tuple) (move (p 3)) (move (p 4)))) (return)))
(fn "k::m::dis" (kind root) (def "k::m::dis") (args ()) (item fn "dis") (argc 1)
  (locals (0 i8 mut) (1 bool imm) (2 (adt "k::lib::E") mut))
  (bb 0 (switch (copy (p 1)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 2) (agg (adt (adt "k::lib::E") 0))) (goto 3))
  (bb 2 (assign (p 2) (agg (adt (adt "k::lib::E") 1) (int u16 7))) (goto 3))
  (bb 3 (assign (p 0) (discr (p 2))) (return)))
(fn "k::m::drp" (kind root) (def "k::m::drp") (args ()) (item fn "drp") (argc 1)
  (locals (0 u16 mut) (1 (adt "k::lib::E") imm))
  (bb 0 (drop (p 1) glue 1))
  (bb 1 (assign (p 0) (use (int u16 1))) (return)))
(fn "k::m::get" (kind root) (def "k::m::get") (args ()) (item fn "get") (argc 1)
  (locals (0 (adt "std::result::Result<u8, bytes::TryGetError>") mut) (1 (ref mut (ref shared (slice u8))) imm))
  (bb 0 (call (leaf "bytes::Buf::try_get_u8" ((ref shared (slice u8)))) (args (copy (p 1))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::push2" (kind root) (def "k::m::push2") (args ()) (item fn "push2") (argc 1)
  (locals (0 unit mut) (1 (ref mut (adt "std::vec::Vec<u32>")) imm) (2 unit mut) (3 unit mut))
  (bb 0 (call (leaf "std::vec::Vec::<T, A>::push" (u32 (adt "std::alloc::Global"))) (args (copy (p 1)) (int u32 1)) (p 2) 1))
  (bb 1 (call (leaf "std::vec::Vec::<T, A>::push" (u32 (adt "std::alloc::Global"))) (args (copy (p 1)) (int u32 2)) (p 3) 2))
  (bb 2 (return)))
(fn "k::m::upto" (kind root) (def "k::m::upto") (args ()) (item fn "upto") (argc 2)
  (locals (0 usize mut) (1 (array u8 4) imm) (2 usize imm) (3 (ref shared (slice u8)) mut) (4 (adt "std::ops::RangeToInclusive<usize>") mut))
  (bb 0 (assign (p 4) (agg (adt (adt "std::ops::RangeToInclusive<usize>") 0) (copy (p 2)))) (call (leaf "std::ops::Index::index" ((array u8 4) (adt "std::ops::RangeToInclusive<usize>"))) (args (copy (p 1)) (move (p 4))) (p 3) 1))
  (bb 1 (assign (p 0) (un ptr-metadata (copy (p 3)))) (return)))
(fn "k::m::len" (kind root) (def "k::m::len") (args ()) (item fn "len") (argc 1)
  (locals (0 usize mut) (1 (array u8 4) imm) (2 (ref shared (array u8 4)) mut) (3 (ref shared (slice u8)) mut))
  (bb 0 (assign (p 2) (ref shared (p 1))) (assign (p 3) (cast unsize (copy (p 2)) (ref shared (slice u8)))) (assign (p 0) (un ptr-metadata (copy (p 3)))) (return)))
(fn "k::m::un" (kind root) (def "k::m::un") (args ()) (item fn "un") (argc 1)
  (locals (0 u16 mut) (1 bool imm) (2 (unsupported "type FnPtr(..)") mut))
  (bb 0 (switch (copy (p 1)) (0 2) (otherwise 1)))
  (bb 1 (assign (p 2) (use (copy (p 2)))) (assign (p 0) (use (int u16 1))) (return))
  (bb 2 (assign (p 0) (use (int u16 2))) (return)))
"#;

#[test]
fn aggregates_are_their_constructors_and_a_discriminant_is_its_value_at_its_type() {
    with_env(|env| {
        let fx = load(env, VALUES);
        same(env, &fx.run("mk", 0, &["1u8", "2u8"]), "mir::Res::Ret[Tuple2(Array U8 2usize, Array U8 3usize)](tuple2[Array U8 2usize, Array U8 3usize](pair(Array U8 2usize, Cons[U8](1u8, Cons[U8](2u8, Nil[U8])), refl(Int, 2int)), pair(Array U8 3usize, Cons[U8](2u8, Cons[U8](2u8, Cons[U8](2u8, Nil[U8]))), refl(Int, 3int))))");
        // `A = -1` is the bits 255 of an `i8`; `B = 1`
        same(env, &fx.run("dis", 0, &["true"]), "mir::Res::Ret[U8](255u8)");
        same(env, &fx.run("dis", 0, &["false"]), "mir::Res::Ret[U8](1u8)");
    });
}

#[test]
fn a_drop_with_glue_is_nothing_only_for_a_variant_without_glue() {
    with_env(|env| {
        let fx = load(env, VALUES);
        let e = fx.lit.state.adt_ty("k::lib::E").expect("E");
        same(env, &fx.run("drp", 0, &[&format!("{e}::v0_A")]), "mir::Res::Ret[U16](1u16)");
        // negative twin: the variant with glue (its drop code is not read)
        same(env, &fx.run("drp", 0, &[&format!("{e}::v1_B(3u16)")]), "mir::Res::Stuck[U16]");
    });
}

#[test]
fn leaves_are_their_models_through_the_referent() {
    with_env(|env| {
        let fx = load(env, VALUES);
        same(env, &fx.run("get", 0, &["Cons[U8](5u8, Cons[U8](6u8, Nil[U8]))"]), "mir::Res::Ret[Tuple2(List(U8), crate::__lift::Result(U8, crate::__lift::TryGetError))](tuple2[List(U8), crate::__lift::Result(U8, crate::__lift::TryGetError)](Cons[U8](6u8, Nil[U8]), crate::__lift::Result::Ok[U8, crate::__lift::TryGetError](5u8)))");
        same(env, &fx.run("get", 0, &["Nil[U8]"]), "mir::Res::Ret[Tuple2(List(U8), crate::__lift::Result(U8, crate::__lift::TryGetError))](tuple2[List(U8), crate::__lift::Result(U8, crate::__lift::TryGetError)](Nil[U8], crate::__lift::Result::Err[U8, crate::__lift::TryGetError](crate::__lift::TryGetError::TryGetError)))");
        // two pushes through the same `&mut Vec`: both land, in order
        same(env, &fx.run("push2", 0, &["Nil[U32]"]), "mir::Res::Ret[List(U32)](Cons[U32](1u32, Cons[U32](2u32, Nil[U32])))");
        // `&a[..=j]`: a panic past the end
        let a = "pair(Array U8 4usize, Cons[U8](1u8, Cons[U8](2u8, Cons[U8](3u8, Cons[U8](4u8, Nil[U8])))), refl(Int, 4int))";
        same(env, &fx.run("upto", 0, &[a, "1usize"]), "mir::Res::Ret[Usize](2usize)");
        same(env, &fx.run("upto", 0, &[a, "4usize"]), "mir::Res::Panic[Usize]");
        same(env, &fx.run("len", 0, &[a]), "mir::Res::Ret[Usize](4usize)");
    });
}

#[test]
fn an_unmodeled_construct_is_none_on_its_path_only_and_named() {
    with_env(|env| {
        let fx = load(env, VALUES);
        same(env, &fx.run("un", 0, &["false"]), "mir::Res::Ret[U16](2u16)");
        same(env, &fx.run("un", 0, &["true"]), "mir::Res::Stuck[U16]");
        let faults = &fx.lf("un").faults;
        assert!(faults.iter().any(|f| f.starts_with("bb1: statement 0") && f.contains("Unsupported(\"type FnPtr(..)\")")), "{faults:?}");
    });
}

// ---------------------------------------------------------------------------
// the statement's preconditions: the declared contract's, checked by the
// elaborator (`hir::FnDef::declared`)
// ---------------------------------------------------------------------------

/// The lift fixture with a declared precondition of `Counter::chunks` (an
/// attachment), lifted with `hook`: whether `Counter::chunks` is defined,
/// and the elaboration's errors.
fn chunks_elaborated(hook: Option<WrongRule>) -> (bool, Vec<String>) {
    // (`Counter` is not exported: a boundary function has no precondition)
    let root = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n#[lift(mir = \"w.sbmir\")]\nmod w;\npub use w::Wrap;\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"pre.rs\"]\nmod pre;\n";
    let pre = "use sandblaster::prelude::*;\n#[lift_attach(crate::w::Counter::chunks)]\nfn chunks_pre() {\n    requires(bits < 1000usize);\n}\n";
    let fs = MemFs::from_files([("r/mod.rs", root), ("r/pre.rs", pre), ("r/w.rs", include_str!("mir_fixtures/lift_w/w.rs")), ("r/w.sbmir", include_str!("mir_fixtures/lift_w/w.sbmir"))]);
    test_hook::set(hook);
    let c = sandblaster_front::driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    test_hook::set(None);
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    sandblaster_front::elab::with_big_stack(move || {
        let out = checked::elaborate_names(k, &["w::Counter::chunks".to_string()]);
        let errs = out.diags.list.iter().filter(|d| d.kind == DiagKind::Elab).map(|d| d.msg.clone()).collect();
        (out.env.lookup_global("crate::w::Counter::chunks").is_some(), errs)
    })
}

/// `S_f`'s preconditions are the declared contract's: with the declared
/// `requires(bits < 1000usize)`, `Counter::chunks` is elaborated with that
/// precondition; the negative twin (`WrongRule::ChangedRequires`): the
/// function's own clause replaced by `requires(true)` after the declared
/// contract was carried — one clause as declared, so the binder is still
/// `h_req0` — and the elaborator refuses it, naming both clauses. (A clause
/// the contract lacks: `tests/fault_injection.rs`.)
#[test]
fn a_precondition_other_than_the_declared_clause_is_refused() {
    let (defined, errs) = chunks_elaborated(None);
    assert!(defined && errs.is_empty(), "{errs:?}");
    let (defined, errs) = chunks_elaborated(Some(WrongRule::ChangedRequires));
    assert!(!defined, "a precondition other than the declared clause: not elaborated");
    let e = errs.iter().find(|e| e.starts_with("`crate::w::Counter::chunks` could not be elaborated")).unwrap_or_else(|| panic!("{errs:?}"));
    assert!(e.contains("its precondition 0 `") && e.contains("is not its declared contract's `") && e.contains("1000"), "{e}");
}

/// core's `RangeInclusive<u32>` and `Once<(u32, u32)>`, which the
/// structured reading models by the lift prelude's structs.
const MODELS: &str = r#"(adt-def "std::ops::RangeInclusive<u32>" (path "std::ops::RangeInclusive") (kind struct) (args (u32))
  (variant 0 "RangeInclusive" 0 (field "start" u32) (field "end" u32) (field "exhausted" bool) (no-glue)))
(adt-def "std::iter::Once<(u32, u32)>" (path "std::iter::Once") (kind struct) (args ((tuple u32 u32)))
  (variant 0 "Once" 0 (field "inner" (adt "std::option::IntoIter<(u32, u32)>")) (no-glue)))
(adt-def "std::option::IntoIter<(u32, u32)>" (path "std::option::IntoIter") (kind struct) (args ((tuple u32 u32)))
  (variant 0 "IntoIter" 0 (field "inner" (adt "std::option::Item<(u32, u32)>")) (no-glue)))
(adt-def "std::option::Item<(u32, u32)>" (path "std::option::Item") (kind struct) (args ((tuple u32 u32)))
  (variant 0 "Item" 0 (field "opt" (adt "std::option::Option<(u32, u32)>")) (no-glue)))
(adt-def "std::option::Option<(u32, u32)>" (path "std::option::Option") (kind enum) (args ((tuple u32 u32)))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" (tuple u32 u32)) (no-glue)))
(fn "k::m::range" (kind root) (def "k::m::range") (args ()) (item fn "range") (argc 1)
  (locals (0 (adt "std::ops::RangeInclusive<u32>") mut) (1 u32 imm))
  (bb 0 (assign (p 0) (agg (adt (adt "std::ops::RangeInclusive<u32>") 0) (int u32 1) (copy (p 1)) (int bool 0))) (return)))
(fn "k::m::once" (kind root) (def "k::m::once") (args ()) (item fn "once") (argc 1)
  (locals (0 (adt "std::iter::Once<(u32, u32)>") mut) (1 (adt "std::iter::Once<(u32, u32)>") imm))
  (bb 0 (assign (p 0) (use (copy (p 1)))) (return)))
"#;

#[test]
fn a_core_type_the_structured_reading_models_is_erased_field_by_field() {
    with_env(|env| {
        let fx = load(env, MODELS);
        let k = KNames { names: &fx.names, env };
        let mut g = Gen::resume(&fx.m, &k, fx.lit.state.clone());
        // RangeInclusive<u32>: the prelude's `RangeInclusiveU32 { start, end, exhausted }`
        let r = mir::ir::Ty::Adt("std::ops::RangeInclusive<u32>".into());
        let er = sandblaster_front::mir::stmt::erase(&mut g, env, &r, "x").unwrap();
        let want = g.ctor("std::ops::RangeInclusive<u32>", 0, &["1u32".into(), "5u32".into(), "false".into()]).unwrap();
        same(env, &format!("(fun (x : crate::__lift::RangeInclusiveU32) => {er}) (crate::__lift::RangeInclusiveU32::RangeInclusiveU32(1u32, 5u32, false))"), &want);
        // negative twin: another field order is another value
        let swapped = g.ctor("std::ops::RangeInclusive<u32>", 0, &["5u32".into(), "1u32".into(), "false".into()]).unwrap();
        let mut b = Budget { steps: 1_000_000 };
        let (a, w) = (env.parse_term(&[], &format!("(fun (x : crate::__lift::RangeInclusiveU32) => {er}) (crate::__lift::RangeInclusiveU32::RangeInclusiveU32(1u32, 5u32, false))")).unwrap(), env.parse_term(&[], &swapped).unwrap());
        let (av, wv) = (env.eval(&VEnv::default(), Lvl(0), &a, &mut b).unwrap(), env.eval(&VEnv::default(), Lvl(0), &w, &mut b).unwrap());
        assert!(!env.conv(Lvl(0), &av, &wv, &mut b).unwrap());
        // Once<T>: the prelude's `Once { v }` is `Once { inner: IntoIter { inner: Item { opt: v } } }`
        let o = mir::ir::Ty::Adt("std::iter::Once<(u32, u32)>".into());
        let eo = sandblaster_front::mir::stmt::erase(&mut g, env, &o, "x").unwrap();
        let some = "Some[Tuple2(U32, U32)](tuple2[U32, U32](3u32, 4u32))";
        let item = g.ctor("std::option::Item<(u32, u32)>", 0, &[some.into()]).unwrap();
        let iter = g.ctor("std::option::IntoIter<(u32, u32)>", 0, &[item]).unwrap();
        let want = g.ctor("std::iter::Once<(u32, u32)>", 0, &[iter]).unwrap();
        same(env, &format!("(fun (x : crate::__lift::Once(Tuple2(U32, U32))) => {eo}) (crate::__lift::Once::Once[Tuple2(U32, U32)]({some}))"), &want);
    });
}

// ---------------------------------------------------------------------------
// reader widening: rotations, signed checked arithmetic, `?`'s residual,
// bytes to words, core's slice iterator and a slice's `get` by a range
// ---------------------------------------------------------------------------

const WIDEN: &str = r#"(adt-def "std::convert::Infallible" (path "std::convert::Infallible") (kind enum) (args ()))
(adt-def "std::option::Option<std::convert::Infallible>" (path "std::option::Option") (kind enum) (args ((adt "std::convert::Infallible")))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" (adt "std::convert::Infallible")) (no-glue)))
(adt-def "std::option::Option<u8>" (path "std::option::Option") (kind enum) (args (u8))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" u8) (no-glue)))
(adt-def "std::option::Option<&u8>" (path "std::option::Option") (kind enum) (args ((ref shared u8)))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" (ref shared u8)) (no-glue)))
(adt-def "std::option::Option<&[u8]>" (path "std::option::Option") (kind enum) (args ((ref shared (slice u8))))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" (ref shared (slice u8))) (no-glue)))
(adt-def "std::slice::Iter<'_, u8>" (path "std::slice::Iter") (kind struct) (args (u8))
  (variant 0 "Iter" 0 (field "ptr" (unsupported "type RawPtr")) (field "end_or_len" (unsupported "type RawPtr")) (no-glue)))
(adt-def "std::ops::Range<usize>" (path "std::ops::Range") (kind struct) (args (usize))
  (variant 0 "Range" 0 (field "start" usize) (field "end" usize) (no-glue)))
(adt-def "std::ops::RangeTo<usize>" (path "std::ops::RangeTo") (kind struct) (args (usize))
  (variant 0 "RangeTo" 0 (field "end" usize) (no-glue)))
(adt-def "std::ops::RangeFrom<usize>" (path "std::ops::RangeFrom") (kind struct) (args (usize))
  (variant 0 "RangeFrom" 0 (field "start" usize) (no-glue)))
(adt-def "std::ops::RangeToInclusive<usize>" (path "std::ops::RangeToInclusive") (kind struct) (args (usize))
  (variant 0 "RangeToInclusive" 0 (field "end" usize) (no-glue)))
(adt-def "k::myops::Range<usize>" (path "k::myops::Range") (kind struct) (args (usize))
  (variant 0 "Range" 0 (field "start" usize) (field "end" usize) (no-glue)))
(fn "k::m::rotl" (kind root) (def "k::m::rotl") (args ()) (item fn "rotl") (argc 2)
  (locals (0 u32 mut) (1 u32 imm) (2 u32 imm))
  (bb 0 (call (intrinsic "rotate_left" (u32)) (args (copy (p 1)) (copy (p 2))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::rotr" (kind root) (def "k::m::rotr") (args ()) (item fn "rotr") (argc 2)
  (locals (0 u8 mut) (1 u8 imm) (2 u32 imm))
  (bb 0 (call (intrinsic "rotate_right" (u8)) (args (copy (p 1)) (copy (p 2))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::sadd" (kind root) (def "k::m::sadd") (args ()) (item fn "sadd") (argc 2)
  (locals (0 (tuple i32 bool) mut) (1 i32 imm) (2 i32 imm))
  (bb 0 (assign (p 0) (checked add (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::ssub" (kind root) (def "k::m::ssub") (args ()) (item fn "ssub") (argc 2)
  (locals (0 (tuple i8 bool) mut) (1 i8 imm) (2 i8 imm))
  (bb 0 (assign (p 0) (checked sub (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::smul" (kind root) (def "k::m::smul") (args ()) (item fn "smul") (argc 2)
  (locals (0 (tuple i32 bool) mut) (1 i32 imm) (2 i32 imm))
  (bb 0 (assign (p 0) (checked mul (copy (p 1)) (copy (p 2)))) (return)))
(fn "k::m::resid" (kind root) (def "k::m::resid") (args ()) (item fn "resid") (argc 0)
  (locals (0 bool mut) (1 (adt "std::option::Option<std::convert::Infallible>") imm) (2 isize mut))
  (bb 0 (assign (p 2) (discr (p 1))) (assign (p 0) (bin eq (copy (p 2)) (int isize 0))) (return)))
(fn "k::m::residc" (kind root) (def "k::m::residc") (args ()) (item fn "residc") (argc 0)
  (locals (0 (adt "std::option::Option<std::convert::Infallible>") mut))
  (bb 0 (assign (p 0) (use (zst (adt "std::option::Option<std::convert::Infallible>")))) (return)))
(fn "k::m::unset8" (kind root) (def "k::m::unset8") (args ()) (item fn "unset8") (argc 0)
  (locals (0 bool mut) (1 (adt "std::option::Option<u8>") imm) (2 isize mut))
  (bb 0 (assign (p 2) (discr (p 1))) (assign (p 0) (bin eq (copy (p 2)) (int isize 0))) (return)))
(fn "k::m::le4" (kind root) (def "k::m::le4") (args ()) (item fn "le4") (argc 1)
  (locals (0 u32 mut) (1 (array u8 4) imm))
  (bb 0 (assign (p 0) (cast transmute (copy (p 1)) u32)) (return)))
(fn "k::m::le3" (kind root) (def "k::m::le3") (args ()) (item fn "le3") (argc 1)
  (locals (0 u32 mut) (1 (array u8 3) imm))
  (bb 0 (assign (p 0) (cast transmute (copy (p 1)) u32)) (return)))
(fn "core::slice::iter::<impl std::iter::IntoIterator for &[u8]>::into_iter" (kind callee) (def "core::slice::iter::<impl std::iter::IntoIterator for &'a [T]>::into_iter") (args (u8)) (item impl (ref shared (slice u8)) "IntoIterator" () "into_iter") (argc 1)
  (locals (0 (adt "std::slice::Iter<'_, u8>") mut) (1 (ref shared (slice u8)) imm))
  (bb 0 (unreachable)))
(fn "<std::slice::Iter<'_, u8> as std::iter::Iterator>::next" (kind callee) (def "<std::slice::Iter<'a, T> as std::iter::Iterator>::next") (args (u8)) (item impl (adt "std::slice::Iter<'_, u8>") "Iterator" () "next") (argc 1)
  (locals (0 (adt "std::option::Option<&u8>") mut) (1 (ref mut (adt "std::slice::Iter<'_, u8>")) imm))
  (bb 0 (unreachable)))
(fn "<k::m::Iter<'_, u8> as std::iter::Iterator>::next" (kind callee) (def "<k::m::Iter<'a, T> as std::iter::Iterator>::next") (args (u8)) (item impl (adt "std::slice::Iter<'_, u8>") "Iterator" () "next") (argc 1)
  (locals (0 (adt "std::option::Option<&u8>") mut) (1 (ref mut (adt "std::slice::Iter<'_, u8>")) imm))
  (bb 0 (unreachable)))
(fn "k::m::sum" (kind root) (def "k::m::sum") (args ()) (item fn "sum") (argc 1)
  (locals (0 u64 mut) (1 (ref shared (slice u8)) imm) (2 (adt "std::slice::Iter<'_, u8>") mut) (3 (adt "std::option::Option<&u8>") mut) (4 (ref mut (adt "std::slice::Iter<'_, u8>")) mut) (5 isize mut) (6 u8 mut) (7 u64 mut))
  (bb 0 (assign (p 0) (use (int u64 0))) (call (fn "core::slice::iter::<impl std::iter::IntoIterator for &[u8]>::into_iter") (args (copy (p 1))) (p 2) 1))
  (bb 1 (assign (p 4) (ref mut (p 2))) (call (fn "<std::slice::Iter<'_, u8> as std::iter::Iterator>::next") (args (copy (p 4))) (p 3) 2))
  (bb 2 (assign (p 5) (discr (p 3))) (switch (move (p 5)) (0 4) (1 3) (otherwise 5)))
  (bb 3 (assign (p 6) (use (copy (p 3 (downcast 1) (field 0 (ref shared u8)) deref)))) (assign (p 7) (cast int-to-int (copy (p 6)) u64)) (assign (p 0) (bin add (copy (p 0)) (copy (p 7)))) (goto 1))
  (bb 4 (return))
  (bb 5 (unreachable)))
(fn "k::m::mysum" (kind root) (def "k::m::mysum") (args ()) (item fn "mysum") (argc 1)
  (locals (0 u64 mut) (1 (ref shared (slice u8)) imm) (2 (adt "std::slice::Iter<'_, u8>") mut) (3 (adt "std::option::Option<&u8>") mut) (4 (ref mut (adt "std::slice::Iter<'_, u8>")) mut) (5 isize mut) (6 u8 mut) (7 u64 mut))
  (bb 0 (assign (p 0) (use (int u64 0))) (call (fn "core::slice::iter::<impl std::iter::IntoIterator for &[u8]>::into_iter") (args (copy (p 1))) (p 2) 1))
  (bb 1 (assign (p 4) (ref mut (p 2))) (call (fn "<k::m::Iter<'_, u8> as std::iter::Iterator>::next") (args (copy (p 4))) (p 3) 2))
  (bb 2 (assign (p 5) (discr (p 3))) (switch (move (p 5)) (0 4) (1 3) (otherwise 5)))
  (bb 3 (assign (p 6) (use (copy (p 3 (downcast 1) (field 0 (ref shared u8)) deref)))) (assign (p 7) (cast int-to-int (copy (p 6)) u64)) (assign (p 0) (bin add (copy (p 0)) (copy (p 7)))) (goto 1))
  (bb 4 (return))
  (bb 5 (unreachable)))
(fn "<std::ops::Range<usize> as std::slice::SliceIndex<[u8]>>::get" (kind callee) (def "<std::ops::Range<usize> as std::slice::SliceIndex<[T]>>::get") (args (u8)) (item impl (adt "std::ops::Range<usize>") "SliceIndex" ((slice u8)) "get") (argc 2)
  (locals (0 (adt "std::option::Option<&[u8]>") mut) (1 (adt "std::ops::Range<usize>") imm) (2 (ref shared (slice u8)) imm))
  (bb 0 (unreachable)))
(fn "k::m::win" (kind root) (def "k::m::win") (args ()) (item fn "win") (argc 3)
  (locals (0 (adt "std::option::Option<&[u8]>") mut) (1 (ref shared (slice u8)) imm) (2 usize imm) (3 usize imm) (4 (adt "std::ops::Range<usize>") mut))
  (bb 0 (assign (p 4) (agg (adt (adt "std::ops::Range<usize>") 0) (copy (p 2)) (copy (p 3)))) (call (fn "<std::ops::Range<usize> as std::slice::SliceIndex<[u8]>>::get") (args (move (p 4)) (copy (p 1))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::sto" (kind root) (def "k::m::sto") (args ()) (item fn "sto") (argc 2)
  (locals (0 (ref shared (slice u8)) mut) (1 (ref shared (slice u8)) imm) (2 usize imm) (3 (adt "std::ops::RangeTo<usize>") mut))
  (bb 0 (assign (p 3) (agg (adt (adt "std::ops::RangeTo<usize>") 0) (copy (p 2)))) (call (leaf "std::ops::Index::index" ((slice u8) (adt "std::ops::RangeTo<usize>"))) (args (copy (p 1)) (move (p 3))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::sfrom" (kind root) (def "k::m::sfrom") (args ()) (item fn "sfrom") (argc 2)
  (locals (0 (ref shared (slice u8)) mut) (1 (ref shared (slice u8)) imm) (2 usize imm) (3 (adt "std::ops::RangeFrom<usize>") mut))
  (bb 0 (assign (p 3) (agg (adt (adt "std::ops::RangeFrom<usize>") 0) (copy (p 2)))) (call (leaf "std::ops::Index::index" ((slice u8) (adt "std::ops::RangeFrom<usize>"))) (args (copy (p 1)) (move (p 3))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::srange" (kind root) (def "k::m::srange") (args ()) (item fn "srange") (argc 3)
  (locals (0 (ref shared (slice u8)) mut) (1 (ref shared (slice u8)) imm) (2 usize imm) (3 usize imm) (4 (adt "std::ops::Range<usize>") mut))
  (bb 0 (assign (p 4) (agg (adt (adt "std::ops::Range<usize>") 0) (copy (p 2)) (copy (p 3)))) (call (leaf "std::ops::Index::index" ((slice u8) (adt "std::ops::Range<usize>"))) (args (copy (p 1)) (move (p 4))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::sincl" (kind root) (def "k::m::sincl") (args ()) (item fn "sincl") (argc 2)
  (locals (0 (ref shared (slice u8)) mut) (1 (ref shared (slice u8)) imm) (2 usize imm) (3 (adt "std::ops::RangeToInclusive<usize>") mut))
  (bb 0 (assign (p 3) (agg (adt (adt "std::ops::RangeToInclusive<usize>") 0) (copy (p 2)))) (call (leaf "std::ops::Index::index" ((slice u8) (adt "std::ops::RangeToInclusive<usize>"))) (args (copy (p 1)) (move (p 3))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::smyrange" (kind root) (def "k::m::smyrange") (args ()) (item fn "smyrange") (argc 3)
  (locals (0 (ref shared (slice u8)) mut) (1 (ref shared (slice u8)) imm) (2 usize imm) (3 usize imm) (4 (adt "k::myops::Range<usize>") mut))
  (bb 0 (assign (p 4) (agg (adt (adt "k::myops::Range<usize>") 0) (copy (p 2)) (copy (p 3)))) (call (leaf "std::ops::Index::index" ((slice u8) (adt "k::myops::Range<usize>"))) (args (copy (p 1)) (move (p 4))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::smyidx" (kind root) (def "k::m::smyidx") (args ()) (item fn "smyidx") (argc 3)
  (locals (0 (ref shared (slice u8)) mut) (1 (ref shared (slice u8)) imm) (2 usize imm) (3 usize imm) (4 (adt "std::ops::Range<usize>") mut))
  (bb 0 (assign (p 4) (agg (adt (adt "std::ops::Range<usize>") 0) (copy (p 2)) (copy (p 3)))) (call (leaf "k::myops::Index::index" ((slice u8) (adt "std::ops::Range<usize>"))) (args (copy (p 1)) (move (p 4))) (p 0) 1))
  (bb 1 (return)))
"#;

/// A slice of bytes (core text).
fn sl(bytes: &[u8]) -> String {
    let n = bytes.len();
    let l = bytes.iter().rev().fold("Nil[U8]".to_string(), |l, b| format!("Cons[U8]({b}u8, {l})"));
    format!("slice::mk U8 {n}usize ({l}) .pair(SliceOk U8 {n}usize ({l}), refl(Int, {n}int), refl(Bool, true))")
}

#[test]
fn rotations_take_their_amount_modulo_the_width() {
    with_env(|env| {
        let fx = load(env, WIDEN);
        // 0x8000_0001 rotated left by 1 is 3; by 33 the same (Rust: the amount modulo 32)
        same(env, &fx.run("rotl", 0, &["2147483649u32", "1u32"]), "mir::Res::Ret[U32](3u32)");
        same(env, &fx.run("rotl", 0, &["2147483649u32", "33u32"]), "mir::Res::Ret[U32](3u32)");
        // negative twin: a rotation is not a shift (the high bit comes back)
        same(env, &fx.run("rotl", 0, &["2147483648u32", "1u32"]), "mir::Res::Ret[U32](1u32)");
        same(env, &fx.run("rotr", 0, &["1u8", "1u32"]), "mir::Res::Ret[U8](128u8)");
        assert!(fx.lf("rotl").faults.is_empty() && fx.lf("rotr").faults.is_empty());
    });
}

#[test]
fn signed_checked_arithmetic_flags_exactly_the_overflows_of_the_signed_range() {
    with_env(|env| {
        let fx = load(env, WIDEN);
        let i32v = |v: i32| format!("crate::__lift::I32::I32({}u32)", v as u32);
        let pair = |v: i32, o: bool| format!("mir::Res::Ret[Tuple2(crate::__lift::I32, Bool)](tuple2[crate::__lift::I32, Bool]({}, {o}))", i32v(v));
        same(env, &fx.run("sadd", 0, &[&i32v(i32::MAX), &i32v(1)]), &pair(i32::MIN, true));
        same(env, &fx.run("sadd", 0, &[&i32v(-1), &i32v(i32::MIN)]), &pair(i32::MAX, true));
        same(env, &fx.run("sadd", 0, &[&i32v(-5), &i32v(3)]), &pair(-2, false));
        // negative twin: what is an overflow of the unsigned bits (-1 + 1) is none here
        same(env, &fx.run("sadd", 0, &[&i32v(-1), &i32v(1)]), &pair(0, false));
        let p8 = |v: i8, o: bool| format!("mir::Res::Ret[Tuple2(U8, Bool)](tuple2[U8, Bool]({}u8, {o}))", v as u8);
        same(env, &fx.run("ssub", 0, &[&format!("{}u8", i8::MIN as u8), "1u8"]), &p8(i8::MAX, true));
        same(env, &fx.run("ssub", 0, &["0u8", &format!("{}u8", i8::MIN as u8)]), &p8(i8::MIN, true));
        same(env, &fx.run("ssub", 0, &[&format!("{}u8", (-100i8) as u8), &format!("{}u8", 27u8)]), &p8(-127, false));
        // a signed checked multiplication is not modeled
        assert!(fx.lf("smul").faults.iter().any(|f| f.contains("checked mul")), "{:?}", fx.lf("smul").faults);
    });
}

#[test]
fn the_residual_of_question_mark_on_option_is_its_one_value_even_unassigned() {
    with_env(|env| {
        let fx = load(env, WIDEN);
        // `Option<Infallible>` has one value, `None`: read unassigned (rustc drops
        // the assignment of a zero-sized value) and as a zero-sized constant
        same(env, &fx.run("resid", 0, &[]), "mir::Res::Ret[Bool](true)");
        same(env, &fx.run("residc", 0, &[]), "mir::Res::Ret[Option(mir::Infallible)](None[mir::Infallible])");
        // negative twin: an `Option<u8>` read unassigned is a failure
        same(env, &fx.run("unset8", 0, &[]), "mir::Res::Stuck[Bool]");
    });
}

#[test]
fn bytes_transmuted_to_a_word_are_its_little_endian_bytes() {
    with_env(|env| {
        let fx = load(env, WIDEN);
        let a = "pair(Array U8 4usize, Cons[U8](1u8, Cons[U8](2u8, Cons[U8](3u8, Cons[U8](4u8, Nil[U8])))), refl(Int, 4int))";
        same(env, &fx.run("le4", 0, &[a]), "mir::Res::Ret[U32](67305985u32)");
        // negative twin: three bytes are no `u32` (not modeled)
        assert!(fx.lf("le3").faults.iter().any(|f| f.contains("transmute")), "{:?}", fx.lf("le3").faults);
    });
}

#[test]
fn core_slice_iterator_is_its_slice_and_index_and_yields_each_element_once() {
    with_env(|env| {
        let fx = load(env, WIDEN);
        assert_eq!(fx.lit.state.adt_ty("std::slice::Iter<'_, u8>").as_deref(), Some("Tuple2((Slice U8), Usize)"));
        // 1 + 2 + 250: the header is entered once per element and once more
        same(env, &fx.run("sum", 4, &[&sl(&[1, 2, 250])]), "mir::Res::Ret[U64](253u64)");
        same(env, &fx.run("sum", 1, &[&sl(&[])]), "mir::Res::Ret[U64](0u64)");
        // negative twin: one unit of fuel less is out of fuel
        same(env, &fx.run("sum", 3, &[&sl(&[1, 2, 250])]), "mir::Res::Stuck[U64]");
        // a function only named like core's `next` is read from its MIR (here
        // `unreachable`): the model is core's, by its exact path
        same(env, &fx.run("mysum", 4, &[&sl(&[1, 2, 250])]), "mir::Res::Stuck[U64]");
        assert!(fx.lf("sum").faults.is_empty(), "{:?}", fx.lf("sum").faults);
    });
}

#[test]
fn a_slices_get_by_a_range_is_the_subslice_or_none() {
    with_env(|env| {
        let fx = load(env, WIDEN);
        let some = |b: &[u8]| format!("mir::Res::Ret[Option(Slice U8)](Some[Slice U8]({}))", sl(b));
        let none = "mir::Res::Ret[Option(Slice U8)](None[Slice U8])";
        same(env, &fx.run("win", 0, &[&sl(&[10, 20, 30]), "1usize", "3usize"]), &some(&[20, 30]));
        same(env, &fx.run("win", 0, &[&sl(&[10, 20, 30]), "3usize", "3usize"]), &some(&[]));
        // `None` is a value here, not a panic: start past end, end past the length
        same(env, &fx.run("win", 0, &[&sl(&[10, 20, 30]), "2usize", "1usize"]), none);
        same(env, &fx.run("win", 0, &[&sl(&[10, 20, 30]), "1usize", "4usize"]), none);
    });
}

/// A slice's sub-slices by core's `Index` (stage finish-A: `&data[i..i + 4]`
/// in the copy rustc compiles of a printed residual) are the array's leaves
/// over the slice, `leaf::slice_*`: the sub-slice, or a panic (`None`) where
/// Rust panics. Core's `Index` and range types by their exact paths only.
#[test]
fn a_slices_index_by_a_range_is_the_subslice_or_a_panic() {
    with_env(|env| {
        let fx = load(env, WIDEN);
        let s = sl(&[10, 20, 30]);
        let some = |b: &[u8]| format!("mir::Res::Ret[Slice U8]({})", sl(b));
        let panic = "mir::Res::Panic[Slice U8]";
        let stuck = "mir::Res::Stuck[Slice U8]";
        for f in ["sto", "sfrom", "srange", "sincl"] {
            assert!(fx.lf(f).faults.is_empty(), "{f}: {:?}", fx.lf(f).faults);
        }
        same(env, &fx.run("sto", 0, &[&s, "2usize"]), &some(&[10, 20]));
        same(env, &fx.run("sto", 0, &[&s, "3usize"]), &some(&[10, 20, 30]));
        same(env, &fx.run("sto", 0, &[&s, "4usize"]), panic);
        same(env, &fx.run("sfrom", 0, &[&s, "1usize"]), &some(&[20, 30]));
        same(env, &fx.run("sfrom", 0, &[&s, "3usize"]), &some(&[]));
        same(env, &fx.run("sfrom", 0, &[&s, "4usize"]), panic);
        same(env, &fx.run("srange", 0, &[&s, "1usize", "3usize"]), &some(&[20, 30]));
        same(env, &fx.run("srange", 0, &[&s, "2usize", "2usize"]), &some(&[]));
        // start past end, end past the length: Rust panics (unlike `get`'s `None` value)
        same(env, &fx.run("srange", 0, &[&s, "2usize", "1usize"]), panic);
        same(env, &fx.run("srange", 0, &[&s, "1usize", "4usize"]), panic);
        same(env, &fx.run("sincl", 0, &[&s, "1usize"]), &some(&[10, 20]));
        same(env, &fx.run("sincl", 0, &[&s, "2usize"]), &some(&[10, 20, 30]));
        same(env, &fx.run("sincl", 0, &[&s, "3usize"]), panic);
        // negative twins: a crate's own range type, a crate's own `Index`
        assert!(fx.lf("smyrange").faults.iter().any(|f| f.contains("k::myops::Range")), "{:?}", fx.lf("smyrange").faults);
        same(env, &fx.run("smyrange", 0, &[&s, "1usize", "3usize"]), stuck);
        assert!(fx.lf("smyidx").faults.iter().any(|f| f.contains("k::myops::Index::index")), "{:?}", fx.lf("smyidx").faults);
        same(env, &fx.run("smyidx", 0, &[&s, "1usize", "3usize"]), stuck);
    });
}

// ---------------------------------------------------------------------------
// acceptance: every MIR instance of the three crates, and the first theorems
// ---------------------------------------------------------------------------

/// The reading of every MIR instance with a body of `root`'s extractions:
/// generated and checked; returns (instances, constructs read as `None`).
fn read_all(root: &str) -> (usize, Vec<String>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(root);
    let c = sandblaster_front::driver::check(&root, &sandblaster_front::loader::RealFs, &TargetInfo::host());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let mms = c.lift_facts.mir_loaded.clone();
    sandblaster_front::elab::with_big_stack(move || {
        let mut out = checked::elaborate_names(k, &[]);
        let (mut n, mut faults, mut seen) = (0, Vec::new(), BTreeSet::new());
        for mm in &mms {
            if !seen.insert(mm.loaded.m.module.clone()) {
                continue;
            }
            let lit = checked::load_literal(&mut out.env, &mm.loaded.m, &mm.loaded.names, &[], None).unwrap_or_else(|e| panic!("{e}"));
            assert!(lit.refused.is_empty(), "{:?}", lit.refused);
            assert_eq!(lit.state.fns.len(), mm.loaded.m.fns.values().filter(|f| f.has_body).count());
            n += lit.state.fns.len();
            for (key, fs) in checked::faults(&lit) {
                faults.extend(fs.iter().map(|f| format!("{key}: {f}")));
            }
        }
        (n, faults)
    })
}

#[test]
fn every_varint_instance_is_read_without_an_unmodeled_construct() {
    let (n, faults) = read_all("../../codec/sandblaster/varint/mod.rs");
    assert_eq!(n, 168);
    assert!(faults.is_empty(), "{faults:#?}");
}

#[test]
fn every_mmr_and_verifier_instance_is_read() {
    // the constructs read as `None` are all in the host's codec impls and
    // panic messages, which no lifted function of these modules calls
    for root in ["../../storage/sandblaster/mmr/mod.rs", "../../storage/sandblaster/verifier/mod.rs"] {
        let (n, faults) = read_all(root);
        assert!(n >= 116, "{n}");
        for f in &faults {
            assert!(f.contains("commonware_codec") || f.starts_with("std::fmt::Arguments"), "{f}");
        }
    }
}

/// Proves `entries` against the reading of `keys` in `root`'s first
/// extraction, after elaborating the items named by `items`.
fn prove(root: &str, items: &[&str], keys: &[&str], entries: Vec<Entry>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(root);
    let c = sandblaster_front::driver::check(&root, &sandblaster_front::loader::RealFs, &TargetInfo::host());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let (mm, contracts) = (c.lift_facts.mir_loaded[0].clone(), c.lift_facts.mir_contracts.clone());
    let items: Vec<String> = items.iter().map(|s| s.to_string()).collect();
    let keys: Vec<String> = keys.iter().map(|s| s.to_string()).collect();
    sandblaster_front::elab::with_big_stack(move || {
        let mut out = checked::elaborate_names(k, &items);
        let lit = checked::load_literal(&mut out.env, &mm.loaded.m, &mm.loaded.names, &keys, None).unwrap_or_else(|e| panic!("{e}"));
        let mut pv = Prover::new(&mut out.env, &mm.loaded.m, &mm.loaded.names, &lit, &out.pre_commit, &contracts);
        for e in &entries {
            pv.prove(e).unwrap_or_else(|err| panic!("{}", &err[..err.len().min(3000)]));
        }
    });
}

fn thm(key: &str, s: &str) -> Entry {
    Entry::Fn { key: key.into(), s_global: s.into() }
}

#[test]
fn the_varint_decoder_theorems_prove() {
    let read = "commonware_codec::varint::read::<u32, &[u8]>";
    let slots = vec![("l14".into(), "p0".into()), ("l2".into(), "p1".into()), ("c0".into(), "p2".into()), ("l1".into(), "code".into())];
    prove(
        "../../codec/sandblaster/varint/mod.rs",
        &["read__u32", "read__u32__loop0"],
        &["commonware_codec::varint::Decoder::<u32>::new", "commonware_codec::varint::Decoder::<u32>::feed", read],
        vec![
            thm("commonware_codec::varint::Decoder::<u32>::new", "crate::varint::Decoder__u32::new"),
            thm("commonware_codec::varint::Decoder::<u32>::feed", "crate::varint::Decoder__u32::feed"),
            Entry::Helper { key: read.into(), s_global: "crate::varint::read__u32__loop0".into(), header: 10, slots },
            thm(read, "crate::varint::read__u32"),
        ],
    );
}

#[test]
fn the_mmr_peak_iterator_theorems_prove() {
    let p = "commonware_storage::merkle::position::Position<commonware_storage::merkle::mmr::Family>";
    let n = "<commonware_storage::merkle::mmr::iterator::PeakIterator as std::iter::Iterator>::next";
    prove(
        "../../storage/sandblaster/mmr/mod.rs",
        &["PeakIterator::next", "^words::", "^stdlib::"],
        &[n],
        vec![
            thm(&format!("<{p} as std::cmp::Ord>::cmp"), "crate::merkle::position::Position::cmp"),
            thm(&format!("<{p} as std::cmp::PartialOrd>::partial_cmp"), "crate::merkle::position::Position::partial_cmp"),
            Entry::Helper { key: n.into(), s_global: "crate::merkle::mmr::iterator::PeakIterator::next__loop0".into(), header: 1, slots: vec![("c0".into(), "p0".into()), ("l1".into(), "code".into())] },
            thm(n, "crate::merkle::mmr::iterator::PeakIterator::next"),
        ],
    );
}

#[test]
fn the_verifier_hasher_theorems_prove() {
    let h = "<commonware_storage::merkle::hasher::Standard<commonware_cryptography::Sha256> as commonware_storage::merkle::hasher::Hasher<commonware_storage::merkle::mmr::Family>>";
    prove(
        "../../storage/sandblaster/verifier/mod.rs",
        &["reconstruct_digest", "^words::", "^stdlib::", "^sha256::"],
        &[&format!("{h}::leaf_digest"), &format!("{h}::node_digest")],
        vec![thm(&format!("{h}::leaf_digest"), "crate::merkle::hasher::Standard::leaf_digest"), thm(&format!("{h}::node_digest"), "crate::merkle::hasher::Standard::node_digest")],
    );
}
