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
        format!("{} ({fuel}) {}::b0 (Some[{st}]({st}::st({})))", lf.run, lf.blk, slots.join(", "), st = lf.st)
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
        same(env, &fx.run("add", 0, &["3u16", "4u16"]), "Some[U16](7u16)");
        // negative twin: the overflow assert fails
        same(env, &fx.run("add", 0, &["65535u16", "1u16"]), "None[U16]");
        same(env, &fx.run("div", 0, &["7u32", "2u32"]), "Some[U32](3u32)");
        same(env, &fx.run("div", 0, &["7u32", "0u32"]), "None[U32]");
        // `Shl` masks its amount (9 is 1 for a byte); `ShlUnchecked` is undefined there
        same(env, &fx.run("shl", 0, &["1u8", "9u32"]), "Some[U8](2u8)");
        same(env, &fx.run("shlu", 0, &["1u8", "9u32"]), "None[U8]");
        same(env, &fx.run("shlu", 0, &["1u8", "7u32"]), "Some[U8](128u8)");
    });
}

#[test]
fn signed_values_are_their_bits_with_signed_comparisons_and_sign_extension() {
    with_env(|env| {
        let fx = load(env, ARITH);
        // -1 < 1 for `i8` (bits 255), while 255 < 1 is false for `u8`
        same(env, &fx.run("slt", 0, &["255u8", "1u8"]), "Some[Bool](true)");
        same(env, &fx.run("ult", 0, &["255u8", "1u8"]), "Some[Bool](false)");
        // `-2i16 as i64` extends the sign; `65534u16 as u64` does not
        same(env, &fx.run("sext", 0, &["crate::__lift::I16::I16(65534u16)"]), "Some[crate::__lift::I64](crate::__lift::I64::I64(18446744073709551614u64))");
        same(env, &fx.run("zext", 0, &["65534u16"]), "Some[U64](65534u64)");
        // `-8i32 >> 1` is arithmetic
        same(env, &fx.run("sar", 0, &["crate::__lift::I32::I32(4294967288u32)", "1u32"]), "Some[crate::__lift::I32](crate::__lift::I32::I32(4294967292u32))");
    });
}

#[test]
fn intrinsics_and_transmute_are_their_primitives() {
    with_env(|env| {
        let fx = load(env, ARITH);
        same(env, &fx.run("cnt", 0, &["1u64"]), "Some[U32](63u32)");
        same(env, &fx.run("swap", 0, &["16909060u32"]), "Some[U32](67305985u32)");
        // the targets are little-endian
        same(env, &fx.run("le", 0, &["16909060u32"]), "Some[Array U8 4usize](u32::to_le_bytes 16909060u32)");
        same(env, &fx.run("le", 0, &["16909060u32"]), "Some[Array U8 4usize](pair(Array U8 4usize, Cons[U8](4u8, Cons[U8](3u8, Cons[U8](2u8, Cons[U8](1u8, Nil[U8])))), refl(Int, 4int)))");
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
        same(env, &fx.run("narrow", 0, &["2u64", "3u64"]), "Some[U64](5u64)");
        // `ShlUnchecked` by a `u64` amount of 2^32 is undefined behaviour: its low
        // 32 bits (0) were tested instead
        same(env, &fx.run("shlw", 0, &["1u8", "4294967296u64"]), "None[U8]");
        same(env, &fx.run("shlw", 0, &["1u8", "3u64"]), "Some[U8](8u8)");
        // a zero-sized constant of a type with several variants is not read as
        // its first variant
        assert!(fx.lf("zst").faults.iter().any(|f| f.contains("zst") || f.contains("Zst")), "{:?}", fx.lf("zst").faults);
        // a library type or range is core's by its exact path: an index by a
        // type whose path merely ends in `ops::RangeTo` was read as `&a[..j]`
        let a = "pair(Array U8 4usize, Cons[U8](1u8, Cons[U8](2u8, Cons[U8](3u8, Cons[U8](4u8, Nil[U8])))), refl(Int, 4int))";
        assert!(fx.lf("mypre").faults.iter().any(|f| f.contains("k::myops::RangeTo")), "{:?}", fx.lf("mypre").faults);
        same(env, &fx.run("mypre", 0, &[a, "2usize"]), "None[Usize]");
        // negative twin: core's `RangeTo`
        same(env, &fx.run("pre", 0, &[a, "2usize"]), "Some[Usize](2usize)");
        // the same for the index leaf itself (stage tcb-review): a crate's own
        // `myops::Index::index` on an array (the printer makes any such call a
        // leaf) was read as core's indexing; its meaning is the crate's impl
        assert!(fx.lf("myidx").faults.iter().any(|f| f.contains("k::myops::Index::index")), "{:?}", fx.lf("myidx").faults);
        same(env, &fx.run("myidx", 0, &[a, "2usize"]), "None[Usize]");
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
        same(env, &fx.run("get", 0, &["Some[U16](5u16)"]), "Some[U16](5u16)");
        same(env, &fx.run("get", 0, &["None[U16]"]), "Some[U16](0u16)");
    });
}

#[test]
fn a_loop_needs_one_unit_of_fuel_per_entry_of_its_header() {
    with_env(|env| {
        let fx = load(env, FLOW);
        assert_eq!(fx.lf("sum").headers, vec![1]);
        // 0 + 1 + 2 + 3: the header is entered 5 times
        same(env, &fx.run("sum", 5, &["4u32"]), "Some[U32](6u32)");
        same(env, &fx.run("sum", 50, &["4u32"]), "Some[U32](6u32)");
        // negative twin: one unit less is out of fuel
        same(env, &fx.run("sum", 4, &["4u32"]), "None[U32]");
    });
}

#[test]
fn a_path_that_panics_fails_and_a_self_call_consumes_fuel() {
    with_env(|env| {
        let fx = load(env, FLOW);
        same(env, &fx.run("nz", 0, &["3u16"]), "Some[U16](3u16)");
        same(env, &fx.run("nz", 0, &["0u16"]), "None[U16]");
        assert_eq!(fx.lf("nz").panics, vec![1]);
        assert!(fx.lf("nz").faults.is_empty(), "{:?}", fx.lf("nz").faults);
        // 4! with the four nested calls each consuming one unit
        same(env, &fx.run("fact", 4, &["4u32"]), "Some[U32](24u32)");
        same(env, &fx.run("fact", 3, &["4u32"]), "None[U32]");
    });
}

#[test]
fn a_string_constant_is_a_token_and_a_closure_takes_its_arguments_spread() {
    with_env(|env| {
        let fx = load(env, FLOW);
        same(env, &fx.run("expect", 0, &["Some[U16](3u16)"]), "Some[U16](3u16)");
        same(env, &fx.run("expect", 0, &["None[U16]"]), "None[U16]");
        same(env, &fx.run("clo", 0, &["4u16"]), "Some[U16](5u16)");
    });
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
        same(env, &fx.run("cloz", 0, &["4u16"]), "Some[U16](5u16)");
        // negative twin: a local with data, never assigned, is read as a failure
        same(env, &fx.run("unset", 0, &["4u16"]), "None[U16]");
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
        same(env, &fx.run("bump", 0, &["5u32"]), "Some[U32](6u32)");
        // negative twin of a historical structuring bug (a value snapshot
        // restored a variable after an in-place write): the copy taken
        // before is 5, the variable after is 6
        same(env, &fx.run("snap", 0, &["5u32"]), "Some[U32](11u32)");
    });
}

#[test]
fn a_mut_parameter_is_a_cell_written_back_at_each_call() {
    with_env(|env| {
        let fx = load(env, REFS);
        // the cell's final value is the output
        same(env, &fx.run("inc", 0, &["5u32"]), "Some[U32](6u32)");
        same(env, &fx.run("twice", 0, &["5u32"]), "Some[U32](7u32)");
        same(env, &fx.run("setb", 0, &["crate::m::P::P(1u32, 2u32)", "9u32"]), "Some[crate::m::P](crate::m::P::P(1u32, 9u32))");
        // a borrow of a field is a code with a path; the callee's write lands there
        same(env, &fx.run("fieldref", 0, &["crate::m::P::P(1u32, 2u32)"]), "Some[crate::m::P](crate::m::P::P(2u32, 2u32))");
        // an `Option<&mut T>` parameter: a cell when present
        same(env, &fx.run("opt", 0, &["5u32"]), "Some[Option(U32)](Some[U32](6u32))");
        same(env, &fx.run("opt", 0, &["-"]), "Some[Option(U32)](None[U32])");
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
        same(env, &fx.run("through", 0, &["5u32"]), "Some[U32](60u32)");
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
        same(env, &fx.run("mk", 0, &["1u8", "2u8"]), "Some[Tuple2(Array U8 2usize, Array U8 3usize)](tuple2[Array U8 2usize, Array U8 3usize](pair(Array U8 2usize, Cons[U8](1u8, Cons[U8](2u8, Nil[U8])), refl(Int, 2int)), pair(Array U8 3usize, Cons[U8](2u8, Cons[U8](2u8, Cons[U8](2u8, Nil[U8]))), refl(Int, 3int))))");
        // `A = -1` is the bits 255 of an `i8`; `B = 1`
        same(env, &fx.run("dis", 0, &["true"]), "Some[U8](255u8)");
        same(env, &fx.run("dis", 0, &["false"]), "Some[U8](1u8)");
    });
}

#[test]
fn a_drop_with_glue_is_nothing_only_for_a_variant_without_glue() {
    with_env(|env| {
        let fx = load(env, VALUES);
        let e = fx.lit.state.adt_ty("k::lib::E").expect("E");
        same(env, &fx.run("drp", 0, &[&format!("{e}::v0_A")]), "Some[U16](1u16)");
        // negative twin: the variant with glue (its drop code is not read)
        same(env, &fx.run("drp", 0, &[&format!("{e}::v1_B(3u16)")]), "None[U16]");
    });
}

#[test]
fn leaves_are_their_models_through_the_referent() {
    with_env(|env| {
        let fx = load(env, VALUES);
        same(env, &fx.run("get", 0, &["Cons[U8](5u8, Cons[U8](6u8, Nil[U8]))"]), "Some[Tuple2(List(U8), crate::__lift::Result(U8, crate::__lift::TryGetError))](tuple2[List(U8), crate::__lift::Result(U8, crate::__lift::TryGetError)](Cons[U8](6u8, Nil[U8]), crate::__lift::Result::Ok[U8, crate::__lift::TryGetError](5u8)))");
        same(env, &fx.run("get", 0, &["Nil[U8]"]), "Some[Tuple2(List(U8), crate::__lift::Result(U8, crate::__lift::TryGetError))](tuple2[List(U8), crate::__lift::Result(U8, crate::__lift::TryGetError)](Nil[U8], crate::__lift::Result::Err[U8, crate::__lift::TryGetError](crate::__lift::TryGetError::TryGetError)))");
        // two pushes through the same `&mut Vec`: both land, in order
        same(env, &fx.run("push2", 0, &["Nil[U32]"]), "Some[List(U32)](Cons[U32](1u32, Cons[U32](2u32, Nil[U32])))");
        // `&a[..=j]`: a panic past the end
        let a = "pair(Array U8 4usize, Cons[U8](1u8, Cons[U8](2u8, Cons[U8](3u8, Cons[U8](4u8, Nil[U8])))), refl(Int, 4int))";
        same(env, &fx.run("upto", 0, &[a, "1usize"]), "Some[Usize](2usize)");
        same(env, &fx.run("upto", 0, &[a, "4usize"]), "None[Usize]");
        same(env, &fx.run("len", 0, &[a]), "Some[Usize](4usize)");
    });
}

#[test]
fn an_unmodeled_construct_is_none_on_its_path_only_and_named() {
    with_env(|env| {
        let fx = load(env, VALUES);
        same(env, &fx.run("un", 0, &["false"]), "Some[U16](2u16)");
        same(env, &fx.run("un", 0, &["true"]), "None[U16]");
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
