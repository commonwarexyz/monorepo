//! The MIR reading (`crate::mir`, `docs/mir-lift.md` §20): each construct on a
//! small hand-written `.sbmir` body, with a negative twin for each refusal,
//! and the codec varint extraction read end to end by the front end.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use quote::ToTokens;
use sandblaster_front::mir::read::{self, Spec};
use sandblaster_front::mir::{self, ModuleNames};

const HEADER: &str = r#"(sbmir 1)
(rustc "rustc 1.98.0-nightly (8b6558a02 2026-06-20)")
(crate "k")
(module "k::m")
(overflow-checks on)
(exclude)
"#;

fn names() -> ModuleNames {
    let mut host = BTreeMap::new();
    host.insert("Error".to_string(), vec!["EndOfBuffer".to_string()]);
    ModuleNames { module: String::new(), sealed: BTreeSet::new(), host_enums: host, requires: BTreeSet::new(), open: BTreeMap::new(), dsl_modules: vec![], current: Default::default(), consts: BTreeMap::new(), invariant_types: BTreeSet::new(), host: Default::default() }
}

fn load(body: &str) -> Result<mir::Loaded, String> {
    let text = format!("{HEADER}{body}");
    mir::load(&text, &|_| None, names(), "m")
}

/// Reads `k::m::f` with the given parameters (states by position).
fn read_f(body: &str, params: &[&str], states: &[usize], has_ret: bool, out_ty: &str) -> Result<String, String> {
    let l = load(body)?;
    let spec = Spec { key: "k::m::f", lifted_name: "f", params: params.iter().map(|s| s.to_string()).collect(), states: states.to_vec(), has_ret, out_ty: syn::parse_str(out_ty).unwrap(), loops: HashMap::new(), ref_params: vec![] };
    let o = read::read(&l.m, &l.names, &spec)?;
    let mut s = o.body.to_token_stream().to_string();
    for h in &o.helpers {
        s.push_str(" ;; ");
        s.push_str(&h.to_token_stream().to_string());
    }
    Ok(s)
}

const CHECKED_ADD: &str = r#"(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 2)
  (locals (0 u16 mut) (1 u16 imm) (2 u16 imm) (3 (tuple u16 bool) mut))
  (debug "a" (p 1) (arg 1)) (debug "b" (p 2) (arg 2))
  (bb 0 (assign (p 3) (checked add (copy (p 1)) (copy (p 2)))) (assert (move (p 3 (field 1 bool))) false overflow 1))
  (bb 1 (assign (p 0) (use (move (p 3 (field 0 u16))))) (return)))
"#;

#[test]
fn a_checked_add_is_the_subset_operator_and_its_assert_is_its_obligation() {
    let s = read_f(CHECKED_ADD, &["a", "b"], &[], true, "u16").unwrap();
    assert!(s.contains("a + b"), "{s}");
    assert!(!s.contains("unreachable"), "the overflow assert is the operator's own obligation: {s}");
}

#[test]
fn a_signed_checked_add_is_refused() {
    let body = CHECKED_ADD.replace("(0 u16 mut) (1 u16 imm) (2 u16 imm) (3 (tuple u16 bool) mut)", "(0 i16 mut) (1 i16 imm) (2 i16 imm) (3 (tuple i16 bool) mut)").replace("(field 0 u16)", "(field 0 i16)");
    let e = read_f(&body, &["a", "b"], &[], true, "crate::__lift::I16").unwrap_err();
    assert!(e.contains("signed checked"), "{e}");
}

const ASSERT_ONLY: &str = r#"(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut))
  (debug "a" (p 1) (arg 1))
  (bb 0 (assign (p 2) (bin lt (copy (p 1)) (int u16 5))) (assert (move (p 2)) true bounds 1))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return)))
"#;

#[test]
fn an_assert_no_following_operation_states_is_an_obligation() {
    let s = read_f(ASSERT_ONLY, &["a"], &[], true, "u16").unwrap();
    assert!(s.contains("if ! (a < 5u16) { unreachable ! () }"), "{s}");
}

const INDEX: &str = r#"(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 2)
  (locals (0 (array u8 4) mut) (1 (array u8 4) imm) (2 usize imm) (3 bool mut) (4 (array u8 4) mut))
  (debug "a" (p 1) (arg 1)) (debug "i" (p 2) (arg 2)) (debug "b" (p 4))
  (bb 0 (assign (p 4) (use (copy (p 1)))) (assign (p 3) (bin lt (copy (p 2)) (int usize 4))) (assert (move (p 3)) true bounds 1))
  (bb 1 (assign (p 4 (index 2)) (use (int u8 7))) (assign (p 0) (use (copy (p 4)))) (return)))
"#;

#[test]
fn a_bounds_check_before_an_index_is_the_index_obligation() {
    let s = read_f(INDEX, &["a", "i"], &[], true, "[u8; 4usize]").unwrap();
    assert!(s.contains("b [i] = 7u8"), "{s}");
    assert!(!s.contains("unreachable"), "{s}");
    // negative twin: an index of another length is not what the check states
    let other = INDEX.replace("(int usize 4)", "(int usize 3)");
    let s2 = read_f(&other, &["a", "i"], &[], true, "[u8; 4usize]").unwrap();
    assert!(s2.contains("unreachable"), "{s2}");
}

const KNOWN_CTOR: &str = r#"(adt-def "std::option::Option<u16>" (path "std::option::Option") (kind enum) (args (u16))
  (variant 0 "None" 0)
  (variant 1 "Some" 1 (field "0" u16)))
(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 (adt "std::option::Option<u16>") mut) (3 isize mut))
  (debug "a" (p 1) (arg 1))
  (bb 0 (assign (p 2) (agg (adt (adt "std::option::Option<u16>") 1) (copy (p 1)))) (assign (p 3) (discr (p 2))) (switch (move (p 3)) (0 1) (1 2) (otherwise 3)))
  (bb 1 (assign (p 0) (use (int u16 0))) (return))
  (bb 2 (assign (p 0) (use (copy (p 2 (downcast 1) (field 0 u16))))) (return))
  (bb 3 (unreachable)))
"#;

#[test]
fn a_switch_on_a_known_constructor_takes_its_arm() {
    let s = read_f(KNOWN_CTOR, &["a"], &[], true, "u16").unwrap();
    assert_eq!(s, "{ return a ; }");
}

const WHILE: &str = r#"(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 u16 mut) (3 bool mut) (4 bool mut))
  (debug "a" (p 1) (arg 1)) (debug "x" (p 2))
  (bb 0 (assign (p 2) (use (copy (p 1)))) (goto 1))
  (bb 1 (assign (p 3) (bin gt (copy (p 2)) (int u16 0))) (switch (move (p 3)) (0 3) (otherwise 2)))
  (bb 2 (assign (p 4) (bin lt (int u32 1) (int u32 16))) (assert (move (p 4)) true overflow 4))
  (bb 3 (assign (p 0) (use (copy (p 2)))) (return))
  (bb 4 (assign (p 2) (bin shr (copy (p 2)) (int u32 1))) (goto 1)))
"#;

#[test]
fn a_loop_whose_only_exit_is_its_test_is_a_while() {
    let s = read_f(WHILE, &["a"], &[], true, "u16").unwrap();
    assert!(s.contains("while x > 0u16 {"), "{s}");
    // the shift has an obligation: it is bound where it occurs, then assigned
    assert!(s.contains("let __t1 : u16 = x >> 1u32 ; x = __t1 ;"), "{s}");
    assert!(!s.contains("unreachable"), "the shift check is the shift's own obligation: {s}");
}

const LOOP_RETURN: &str = r#"(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 u16 mut) (3 bool mut) (4 bool mut))
  (debug "a" (p 1) (arg 1)) (debug "x" (p 2))
  (bb 0 (assign (p 2) (use (copy (p 1)))) (goto 1))
  (bb 1 (assign (p 3) (bin eq (copy (p 2)) (int u16 7))) (switch (move (p 3)) (0 2) (otherwise 3)))
  (bb 2 (assign (p 4) (bin lt (int u32 1) (int u32 16))) (assert (move (p 4)) true overflow 4))
  (bb 3 (assign (p 0) (use (copy (p 2)))) (return))
  (bb 4 (assign (p 2) (bin shr (copy (p 2)) (int u32 1))) (goto 1)))
"#;

#[test]
fn a_loop_with_an_exit_inside_is_a_tail_recursive_helper() {
    // the only exit is still the test here, but the test is `==` with the
    // loop continuing on `false`: a `while !(..)`; with a second exit it
    // becomes a helper
    let s = read_f(LOOP_RETURN, &["a"], &[], true, "u16").unwrap();
    assert!(s.contains("while ! (x == 7u16)"), "{s}");
    let two_exits = LOOP_RETURN.replace("(bb 4 (assign (p 2) (bin shr (copy (p 2)) (int u32 1))) (goto 1))", "(bb 4 (assign (p 2) (bin shr (copy (p 2)) (int u32 1))) (assign (p 3) (bin eq (copy (p 2)) (int u16 0))) (switch (move (p 3)) (0 1) (otherwise 3)))");
    let s2 = read_f(&two_exits, &["a"], &[], true, "u16").unwrap();
    assert!(s2.contains("return f__loop0 (x)"), "{s2}");
    assert!(s2.contains("fn f__loop0 (mut x : u16) -> u16"), "{s2}");
}

const MUT_REF: &str = r#"(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 u16 mut) (3 (ref mut u16) mut))
  (debug "a" (p 1) (arg 1)) (debug "x" (p 2))
  (bb 0 (assign (p 2) (use (copy (p 1)))) (assign (p 3) (ref mut (p 2))) (assign (p 3 deref) (bin or (copy (p 3 deref)) (int u16 1))) (assign (p 0) (use (copy (p 2)))) (return)))
"#;

#[test]
fn a_write_through_a_mutable_borrow_assigns_the_place() {
    let s = read_f(MUT_REF, &["a"], &[], true, "u16").unwrap();
    assert!(s.contains("x = x | 1u16"), "{s}");
    assert!(s.ends_with("return x ; }"), "{s}");
}

#[test]
fn a_drop_with_drop_glue_is_refused() {
    let body = MUT_REF.replace("(return)))", "(drop (p 2) glue 1))\n  (bb 1 (return)))");
    let e = read_f(&body, &["a"], &[], true, "u16").unwrap_err();
    assert!(e.contains("drop glue"), "{e}");
    // a drop without glue is nothing
    let ok = MUT_REF.replace("(return)))", "(drop (p 2) no-glue 1))\n  (bb 1 (return)))");
    read_f(&ok, &["a"], &[], true, "u16").unwrap();
}

#[test]
fn a_call_that_was_not_extracted_is_refused() {
    let body = MUT_REF.replace("(assign (p 0) (use (copy (p 2)))) (return)))", "(call (unextracted \"core::x\") (args) (p 0) 1))\n  (bb 1 (return)))");
    let e = read_f(&body, &["a"], &[], true, "u16").unwrap_err();
    assert!(e.contains("not extracted"), "{e}");
}

#[test]
fn blocks_out_of_order_are_refused() {
    let body = WHILE.replace("(bb 3 (assign (p 0) (use (copy (p 2)))) (return))\n  (bb 4 (assign (p 2) (bin shr (copy (p 2)) (int u32 1))) (goto 1)))", "(bb 4 (assign (p 2) (bin shr (copy (p 2)) (int u32 1))) (goto 1))\n  (bb 3 (assign (p 0) (use (copy (p 2)))) (return)))");
    assert_ne!(body, WHILE);
    assert!(read_f(&body, &["a"], &[], true, "u16").unwrap_err().contains("out of order"));
}

#[test]
fn a_length_rvalue_and_unknown_forms_are_refused() {
    let body = ASSERT_ONLY.replace("(bin lt (copy (p 1)) (int u16 5))", "(len (p 1))");
    assert!(read_f(&body, &["a"], &[], true, "u16").is_err());
    let body2 = ASSERT_ONLY.replace("(bin lt (copy (p 1)) (int u16 5))", "(frobnicate (p 1))");
    assert!(read_f(&body2, &["a"], &[], true, "u16").is_err());
}

#[test]
fn a_state_parameter_must_be_a_mutable_borrow() {
    let e = read_f(CHECKED_ADD, &["a", "b"], &[0], true, "(u16, u16)").unwrap_err();
    assert!(e.contains("not `&mut`"), "{e}");
}

#[test]
fn an_extraction_of_another_module_or_version_is_refused() {
    let text = format!("{HEADER}{CHECKED_ADD}");
    assert!(mir::load(&text, &|_| None, names(), "other").unwrap_err().contains("not of the module"));
    let v2 = text.replace("(sbmir 1)", "(sbmir 2)");
    assert!(mir::load(&v2, &|_| None, names(), "m").unwrap_err().contains("version"));
    let unchecked = text.replace("(overflow-checks on)", "(overflow-checks off)");
    assert!(mir::load(&unchecked, &|_| None, names(), "m").unwrap_err().contains("overflow checks"));
}

#[test]
fn a_stale_extraction_is_refused() {
    let src = b"fn f() {}\n".to_vec();
    let h = sandblaster_front::surface::hex(&sandblaster_front::surface::sha256(&src));
    let text = format!("{HEADER}(source \"src/m.rs\" \"{h}\")\n{CHECKED_ADD}");
    let same = src.clone();
    mir::load(&text, &move |p| (p == "src/m.rs").then(|| same.clone()), names(), "m").unwrap();
    let e = mir::load(&text, &|p| (p == "src/m.rs").then(|| b"fn f() { 1; }\n".to_vec()), names(), "m").unwrap_err();
    assert!(e.contains("changed since the MIR was extracted"), "{e}");
    let e2 = mir::load(&text, &|_| None, names(), "m").unwrap_err();
    assert!(e2.contains("does not exist"), "{e2}");
}

/// The checked-in extraction of commonware-codec's varint is current (its
/// source hash matches) and the front end reads every lifted function of
/// the module from it.
#[test]
fn the_codec_varint_bodies_are_read_from_rustc_mir() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../codec/sandblaster/varint/mod.rs");
    let c = sandblaster_front::driver::check(&root, &sandblaster_front::loader::RealFs, &sandblaster_front::target::TargetInfo::host());
    assert!(c.ok(), "{}", c.render());
    let read = &c.lift_facts.mir_read;
    assert!(read.len() >= 50, "{} functions read from MIR", read.len());
    for f in ["write__u16", "read__u64", "Decoder__u32::feed", "UInt__u16::read_cfg", "SPrim__i64__un_zigzag"] {
        assert!(read.iter().any(|(n, _, _)| n == f), "`{f}` is read from MIR");
    }
    let loops: Vec<&(usize, String)> = read.iter().filter(|(n, _, _)| n.starts_with("write__") || n.starts_with("read__")).flat_map(|(_, _, l)| l).collect();
    assert!(loops.iter().any(|(_, f)| f == "while") && loops.iter().any(|(_, f)| f == "helper"), "{loops:?}");
    assert!(c.lift_facts.mir_rustc.as_deref().is_some_and(|r| r.starts_with("rustc 1.98")));
}

// ---------------------------------------------------------------------------
// The MMR's constructs (storage's `merkle::{position, location, mmr}` in place)
// ---------------------------------------------------------------------------

/// Reads `key` with a names layer adjusted by `f` (the module is `k::m`).
fn read_with(body: &str, key: &str, lifted: &str, params: &[&str], states: &[usize], has_ret: bool, out_ty: &str, f: impl FnOnce(&mut ModuleNames)) -> Result<String, String> {
    let text = format!("{HEADER}{body}");
    let mut nm = names();
    f(&mut nm);
    let l = mir::load(&text, &|_| None, nm, "m")?;
    let spec = Spec { key, lifted_name: lifted, params: params.iter().map(|s| s.to_string()).collect(), states: states.to_vec(), has_ret, out_ty: syn::parse_str(out_ty).unwrap(), loops: HashMap::new(), ref_params: vec![] };
    let o = read::read(&l.m, &l.names, &spec)?;
    let mut s = o.body.to_token_stream().to_string();
    for h in &o.helpers {
        s.push_str(" ;; ");
        s.push_str(&h.to_token_stream().to_string());
    }
    Ok(s)
}

/// `assert_ne!(a, 0)`'s failing path: it builds `AssertKind::Ne` and a
/// `fmt::Arguments` (a string constant the printer does not transcribe)
/// before calling the diverging `assert_failed`.
const PANIC_PAYLOAD: &str = r#"(adt-def "core::panicking::AssertKind" (path "core::panicking::AssertKind") (kind enum) (args ())
  (variant 0 "Eq" 0 (no-glue))
  (variant 1 "Ne" 1 (no-glue)))
(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 bool mut) (3 (adt "core::panicking::AssertKind") imm) (4 never imm) (5 (adt "core::fmt::Arguments") mut))
  (debug "a" (p 1) (arg 1)) (debug "kind" (p 3))
  (bb 0 (assign (p 2) (bin eq (copy (p 1)) (int u16 0))) (switch (move (p 2)) (0 3) (otherwise 1)))
  (bb 1 (assign (p 3) (agg (adt (adt "core::panicking::AssertKind") 1))) (call (fn "core::fmt::Arguments::from_str") (args (unsupported "constant of type (ref shared str)")) (p 5) 2))
  (bb 2 (call (diverge "core::panicking::assert_failed") (args (copy (p 3)) (move (p 5))) (p 4) none))
  (bb 3 (assign (p 0) (use (copy (p 1)))) (return)))
"#;

#[test]
fn a_path_that_must_panic_is_one_obligation_whatever_its_payload() {
    let s = read_with(PANIC_PAYLOAD, "k::m::f", "f", &["a"], &[], true, "u16", |_| {}).unwrap();
    assert!(s.contains("if a == 0u16 { unreachable ! () ; } else { return a ; }"), "{s}");
    // negative twin: the same payload on a path that returns is read (and
    // refused: the message's `from_str` has no MIR here)
    let returns = PANIC_PAYLOAD.replace("(bb 2 (call (diverge \"core::panicking::assert_failed\") (args (copy (p 3)) (move (p 5))) (p 4) none))", "(bb 2 (goto 3))");
    let e = read_with(&returns, "k::m::f", "f", &["a"], &[], true, "u16", |_| {}).unwrap_err();
    assert!(e.contains("AssertKind") || e.contains("from_str"), "{e}");
}

/// core's `checked_add`: the overflow flag of `CheckedAdd` is tested, not
/// asserted.
const CHECKED_TESTED: &str = r#"(adt-def "std::option::Option<u16>" (path "std::option::Option") (kind enum) (args (u16))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" u16) (no-glue)))
(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 2)
  (locals (0 (adt "std::option::Option<u16>") mut) (1 u16 imm) (2 u16 imm) (3 (tuple u16 bool) mut) (4 bool mut))
  (debug "a" (p 1) (arg 1)) (debug "b" (p 2) (arg 2))
  (bb 0 (assign (p 3) (checked add (copy (p 1)) (copy (p 2)))) (assign (p 4) (use (copy (p 3 (field 1 bool))))) (switch (copy (p 4)) (0 1) (otherwise 2)))
  (bb 1 (assign (p 0) (agg (adt (adt "std::option::Option<u16>") 1) (copy (p 3 (field 0 u16))))) (return))
  (bb 2 (assign (p 0) (agg (adt (adt "std::option::Option<u16>") 0))) (return)))
"#;

#[test]
fn a_checked_operation_whose_flag_is_tested_is_the_exact_pair() {
    let s = read_with(CHECKED_TESTED, "k::m::f", "f", &["a", "b"], &[], true, "Option<u16>", |_| {}).unwrap();
    assert!(s.contains("a . checked_add (b) . is_none ()") && s.contains("a . wrapping_add (b)"), "{s}");
    // no `a + b`: that would claim a panic where core returns `None`
    assert!(!s.contains("a + b"), "{s}");
    // negative twin: the same operation with its flag asserted is `a + b`
    let s2 = read_f(CHECKED_ADD, &["a", "b"], &[], true, "u16").unwrap();
    assert!(s2.contains("a + b"), "{s2}");
    // and a signed one with a tested flag is refused
    let signed = CHECKED_TESTED.replace("(1 u16 imm) (2 u16 imm) (3 (tuple u16 bool) mut)", "(1 i16 imm) (2 i16 imm) (3 (tuple i16 bool) mut)");
    assert!(read_with(&signed, "k::m::f", "f", &["a", "b"], &[], true, "Option<u16>", |_| {}).unwrap_err().contains("signed"));
}

const DROP_KNOWN: &str = r#"(adt-def "k::m::E" (path "k::m::E") (kind enum) (args ())
  (variant 0 "A" 0 (field "0" u16) (no-glue))
  (variant 1 "B" 1 (field "0" u16)))
(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 u16 mut) (1 u16 imm) (2 (adt "k::m::E") mut))
  (debug "a" (p 1) (arg 1))
  (bb 0 (assign (p 2) (agg (adt (adt "k::m::E") 0) (copy (p 1)))) (drop (p 2) glue 1))
  (bb 1 (assign (p 0) (use (copy (p 1)))) (return)))
"#;

#[test]
fn a_drop_of_a_known_variant_without_glue_is_nothing() {
    let s = read_with(DROP_KNOWN, "k::m::f", "f", &["a"], &[], true, "u16", |_| {}).unwrap();
    assert_eq!(s, "{ return a ; }");
    // negative twins: a variant whose drop runs code, and a value whose
    // variant is not known here
    let b = DROP_KNOWN.replace("(agg (adt (adt \"k::m::E\") 0)", "(agg (adt (adt \"k::m::E\") 1)");
    assert!(read_with(&b, "k::m::f", "f", &["a"], &[], true, "u16", |_| {}).unwrap_err().contains("drop glue"));
    let unknown = DROP_KNOWN.replace("(locals (0 u16 mut) (1 u16 imm) (2 (adt \"k::m::E\") mut))", "(locals (0 u16 mut) (1 u16 imm) (2 (adt \"k::m::E\") mut) (3 (adt \"k::m::E\") imm))").replace("(argc 1)", "(argc 3)").replace("(debug \"a\" (p 1) (arg 1))", "(debug \"a\" (p 1) (arg 1)) (debug \"e\" (p 3) (arg 3))").replace("(drop (p 2) glue 1)", "(drop (p 3) glue 1)");
    assert!(read_with(&unknown, "k::m::f", "f", &["a", "_", "e"], &[], true, "u16", |_| {}).unwrap_err().contains("drop glue"));
}

/// A `&mut self` method with a loop over its field (two exits: a helper).
const METHOD_LOOP: &str = r#"(adt-def "k::m::S" (path "k::m::S") (kind struct) (args ())
  (variant 0 "S" 0 (field "x" u16) (no-glue)))
(root "k::m::S::f")
(fn "k::m::S::f" (kind root) (def "k::m::S::f") (args ()) (item inherent (adt "k::m::S") "f") (argc 1)
  (locals (0 unit mut) (1 (ref mut (adt "k::m::S")) imm) (2 bool mut) (3 bool mut))
  (debug "self" (p 1) (arg 1))
  (bb 0 (goto 1))
  (bb 1 (assign (p 2) (bin gt (copy (p 1 deref (field 0 u16))) (int u16 0))) (switch (move (p 2)) (0 3) (otherwise 2)))
  (bb 2 (assign (p 1 deref (field 0 u16)) (bin shr (copy (p 1 deref (field 0 u16))) (int u32 1))) (assign (p 3) (bin eq (copy (p 1 deref (field 0 u16))) (int u16 5))) (switch (move (p 3)) (0 1) (otherwise 3)))
  (bb 3 (return)))
"#;

#[test]
fn a_methods_loop_over_its_receiver_is_a_method_helper() {
    let s = read_with(METHOD_LOOP, "k::m::S::f", "S::f", &["self"], &[0], false, "S", |_| {}).unwrap();
    assert!(s.contains("return Self :: f__loop0 (self)"), "{s}");
    assert!(s.contains("# [lift_method] fn f__loop0 (mut self) -> S"), "{s}");
    assert!(s.contains("self . x = "), "a struct without an invariant is written in place: {s}");
    // negative twin: the same loop over a parameter that is not the
    // receiver is a free helper
    let free = METHOD_LOOP.replace("(debug \"self\" (p 1) (arg 1))", "(debug \"s\" (p 1) (arg 1))");
    let s2 = read_with(&free, "k::m::S::f", "S::f", &["s"], &[0], false, "S", |_| {}).unwrap();
    assert!(s2.contains("return S__f__loop0 (s)") && s2.contains("fn S__f__loop0 (mut s : S) -> S") && !s2.contains("lift_method"), "{s2}");
}

#[test]
fn a_state_with_an_invariant_is_held_field_by_field_and_built_whole_where_it_leaves() {
    let s = read_with(METHOD_LOOP, "k::m::S::f", "S::f", &["self"], &[0], false, "S", |n| {
        n.invariant_types.insert("S".into());
    })
    .unwrap();
    // each field write is a variable's; the value is built at the helper call and the return
    assert!(s.contains("let mut __self_x = self . x ;"), "{s}");
    assert!(s.contains("let __t1 : u16 = __self_x >> 1u32 ; __self_x = __t1 ;"), "{s}");
    assert!(s.contains("return Self :: f__loop0 (S { x : __self_x })"), "{s}");
    assert!(s.contains("return S { x : __self_x }"), "{s}");
    assert!(!s.contains("self . x = "), "{s}");
    // negative twin: a state of a struct without an invariant is written in place
    let s2 = read_with(METHOD_LOOP, "k::m::S::f", "S::f", &["self"], &[0], false, "S", |_| {}).unwrap();
    assert!(s2.contains("self . x = ") && !s2.contains("__self_x"), "{s2}");
}

/// `a <= b` over a module type whose `PartialOrd` impl defines
/// `partial_cmp` only: core's provided `le` at that type.
const PROVIDED_LE: &str = r#"(adt-def "k::m::P" (path "k::m::P") (kind struct) (args ())
  (variant 0 "P" 0 (field "0" u64) (no-glue)))
(adt-def "std::cmp::Ordering" (path "std::cmp::Ordering") (kind enum) (args ())
  (variant 0 "Less" 255 (no-glue))
  (variant 1 "Equal" 0 (no-glue))
  (variant 2 "Greater" 1 (no-glue)))
(adt-def "std::option::Option<std::cmp::Ordering>" (path "std::option::Option") (kind enum) (args ((adt "std::cmp::Ordering")))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" (adt "std::cmp::Ordering")) (no-glue)))
(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 2)
  (locals (0 bool mut) (1 (adt "k::m::P") imm) (2 (adt "k::m::P") imm) (3 (ref shared (adt "k::m::P")) mut) (4 (ref shared (adt "k::m::P")) mut))
  (debug "a" (p 1) (arg 1)) (debug "b" (p 2) (arg 2))
  (bb 0 (assign (p 3) (ref shared (p 1))) (assign (p 4) (ref shared (p 2))) (call (fn "<k::m::P as std::cmp::PartialOrd>::le") (args (move (p 3)) (move (p 4))) (p 0) 1))
  (bb 1 (return)))
(fn "<k::m::P as std::cmp::PartialOrd>::partial_cmp" (kind root) (def "k::m::<impl std::cmp::PartialOrd for k::m::P>::partial_cmp") (args ()) (item impl (adt "k::m::P") "PartialOrd" () "partial_cmp") (argc 2)
  (locals (0 (adt "std::option::Option<std::cmp::Ordering>") mut) (1 (ref shared (adt "k::m::P")) imm) (2 (ref shared (adt "k::m::P")) imm))
  (debug "self" (p 1) (arg 1)) (debug "other" (p 2) (arg 2))
  (bb 0 (assign (p 0) (agg (adt (adt "std::option::Option<std::cmp::Ordering>") 0))) (return)))
(fn "<k::m::P as std::cmp::PartialOrd>::le" (kind callee) (def "std::cmp::PartialOrd::le") (args ((adt "k::m::P") (adt "k::m::P"))) (item fn "le") (argc 2)
  (locals (0 bool mut) (1 (ref shared (adt "k::m::P")) imm) (2 (ref shared (adt "k::m::P")) imm) (3 (adt "std::option::Option<std::cmp::Ordering>") mut) (4 isize mut) (5 (adt "std::cmp::Ordering") imm) (6 i8 mut))
  (debug "self" (p 1) (arg 1)) (debug "other" (p 2) (arg 2))
  (bb 0 (call (fn "<k::m::P as std::cmp::PartialOrd>::partial_cmp") (args (move (p 1)) (move (p 2))) (p 3) 1))
  (bb 1 (assign (p 4) (discr (p 3))) (switch (move (p 4)) (0 3) (1 2) (otherwise 4)))
  (bb 2 (assign (p 5) (use (move (p 3 (downcast 1) (field 0 (adt "std::cmp::Ordering")))))) (assign (p 6) (discr (p 5))) (assign (p 0) (bin le (move (p 6)) (int i8 0))) (goto 5))
  (bb 3 (assign (p 0) (use (int bool 0))) (goto 5))
  (bb 4 (unreachable))
  (bb 5 (return)))
"#;

#[test]
fn a_provided_comparison_through_a_lifted_partial_cmp_is_the_prelude_predicate() {
    let s = read_with(PROVIDED_LE, "k::m::f", "f", &["a", "b"], &[], true, "bool", |_| {}).unwrap();
    assert!(s.contains("crate :: __lift :: ord_le (P :: partial_cmp (a , & b))"), "{s}");
    // negative twin: a provided `le` that does not start by calling
    // `partial_cmp` on its own parameters is inlined (core's MIR, read as
    // is: the discriminant of the unknown `Ordering` compared per variant,
    // `Less` being -1 though printed as its bits, 255)
    let swapped = PROVIDED_LE.replace("(args (move (p 1)) (move (p 2))) (p 3) 1)", "(args (move (p 2)) (move (p 1))) (p 3) 1)");
    let s2 = read_with(&swapped, "k::m::f", "f", &["a", "b"], &[], true, "bool", |_| {}).unwrap();
    assert!(!s2.contains("ord_le"), "{s2}");
    assert!(s2.contains("crate :: __lift :: Ordering :: Less => true , crate :: __lift :: Ordering :: Equal => true , crate :: __lift :: Ordering :: Greater => false"), "{s2}");
}

const KNOWN_ORDERING: &str = r#"(adt-def "std::cmp::Ordering" (path "std::cmp::Ordering") (kind enum) (args ())
  (variant 0 "Less" 255 (no-glue))
  (variant 1 "Equal" 0 (no-glue))
  (variant 2 "Greater" 1 (no-glue)))
(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 0)
  (locals (0 bool mut) (1 (adt "std::cmp::Ordering") mut) (2 i8 mut))
  (bb 0 (assign (p 1) (agg (adt (adt "std::cmp::Ordering") 0))) (assign (p 2) (discr (p 1))) (assign (p 0) (bin le (move (p 2)) (int i8 0))) (return)))
"#;

#[test]
fn a_known_negative_discriminant_compares_as_its_value() {
    // `Ordering::Less as i8 <= 0`: true (its bits, 255, are not its value)
    let s = read_with(KNOWN_ORDERING, "k::m::f", "f", &[], &[], true, "bool", |_| {}).unwrap();
    assert_eq!(s, "{ return true ; }");
    // negative twin: `Greater` (1) is not `<= 0`
    let g = KNOWN_ORDERING.replace("(agg (adt (adt \"std::cmp::Ordering\") 0))", "(agg (adt (adt \"std::cmp::Ordering\") 2))");
    assert_eq!(read_with(&g, "k::m::f", "f", &[], &[], true, "bool", |_| {}).unwrap(), "{ return false ; }");
}

const CONST_ITEM: &str = r#"(adt-def "k::m::S" (path "k::m::S") (kind struct) (args ())
  (variant 0 "S" 0 (field "x" u16) (no-glue)))
(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 0)
  (locals (0 (adt "k::m::S") mut))
  (bb 0 (assign (p 0) (use (const-item (adt "k::m::S") "MAX" (const-agg (adt "k::m::S") 0 (int u16 3))))) (return)))
"#;

#[test]
fn a_named_constant_is_the_lifted_constant_it_names() {
    let s = read_with(CONST_ITEM, "k::m::f", "f", &[], &[], true, "S", |n| {
        n.consts.insert(("S".into(), "MAX".into()), true);
    })
    .unwrap();
    assert_eq!(s, "{ return S__MAX () ; }");
    // negative twin: a constant the lift does not lift is its value
    let s2 = read_with(CONST_ITEM, "k::m::f", "f", &[], &[], true, "S", |_| {}).unwrap();
    assert_eq!(s2, "{ return S { x : 3u16 } ; }");
}

/// `g(&S::MAX)`: a promoted reference to a named constant, and
/// `h(&u64::MAX)`: one of a primitive type's inherent impl.
const CONST_ITEM_REF: &str = r#"(adt-def "k::m::S" (path "k::m::S") (kind struct) (args ())
  (variant 0 "S" 0 (field "x" u16) (no-glue)))
(root "k::m::f")
(root "k::m::f2")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 0)
  (locals (0 bool mut))
  (bb 0 (call (fn "k::m::g") (args (const-ref (const-item (adt "k::m::S") "MAX" (const-agg (adt "k::m::S") 0 (int u16 3))))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::f2" (kind root) (def "k::m::f2") (args ()) (item fn "f2") (argc 0)
  (locals (0 bool mut))
  (bb 0 (call (fn "k::m::h") (args (const-ref (const-item u64 "MAX" (int u64 18446744073709551615)))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::g" (kind root) (def "k::m::g") (args ()) (item fn "g") (argc 1)
  (locals (0 bool mut) (1 (ref shared (adt "k::m::S")) imm))
  (debug "s" (p 1) (arg 1))
  (bb 0 (assign (p 0) (use (int bool 1))) (return)))
(fn "k::m::h" (kind root) (def "k::m::h") (args ()) (item fn "h") (argc 1)
  (locals (0 bool mut) (1 (ref shared u64) imm))
  (debug "x" (p 1) (arg 1))
  (bb 0 (assign (p 0) (use (int bool 1))) (return)))
"#;

#[test]
fn a_reference_to_a_named_constant_is_a_reference_to_the_lifted_constant() {
    let s = read_with(CONST_ITEM_REF, "k::m::f", "f", &[], &[], true, "bool", |n| {
        n.consts.insert(("S".into(), "MAX".into()), true);
    })
    .unwrap();
    assert!(s.contains("g (& S__MAX ())"), "{s}");
    // `u64::MAX` is no lifted constant: its value
    let s3 = read_with(CONST_ITEM_REF, "k::m::f2", "f2", &[], &[], true, "bool", |_| {}).unwrap();
    assert!(s3.contains("h (& 18446744073709551615u64)"), "{s3}");
    // negative twin: a constant the lift does not lift is a reference to its value
    let s2 = read_with(CONST_ITEM_REF, "k::m::f", "f", &[], &[], true, "bool", |_| {}).unwrap();
    assert!(s2.contains("g (& S { x : 3u16 })") && !s2.contains("S__MAX"), "{s2}");
}

const CONST_REF_ARG: &str = r#"(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 0)
  (locals (0 bool mut))
  (bb 0 (call (fn "k::m::g") (args (const-ref (int u16 0))) (p 0) 1))
  (bb 1 (return)))
(fn "k::m::g" (kind root) (def "k::m::g") (args ()) (item fn "g") (argc 1)
  (locals (0 bool mut) (1 (ref shared u16) imm))
  (debug "x" (p 1) (arg 1))
  (bb 0 (assign (p 0) (use (int bool 1))) (return)))
"#;

#[test]
fn a_reference_to_a_constant_is_a_reference() {
    let s = read_with(CONST_REF_ARG, "k::m::f", "f", &[], &[], true, "bool", |_| {}).unwrap();
    assert!(s.contains("g (& 0u16)"), "{s}");
    // negative twin: a constant passed by value is the value, not a reference
    let by_value = CONST_REF_ARG.replace("(const-ref (int u16 0))", "(int u16 0)").replace("(1 (ref shared u16) imm)", "(1 u16 imm)");
    let s2 = read_with(&by_value, "k::m::f", "f", &[], &[], true, "bool", |_| {}).unwrap();
    assert!(s2.contains("g (0u16)") && !s2.contains('&'), "{s2}");
}

#[test]
fn a_comparison_of_literals_is_its_value() {
    let lits = ASSERT_ONLY.replace("(bin lt (copy (p 1)) (int u16 5))", "(bin lt (int u32 1) (int u32 64))");
    let s = read_f(&lits, &["a"], &[], true, "u16").unwrap();
    assert_eq!(s, "{ return a ; }");
    // negative twin: a false one is the obligation that the path is not taken
    let false_ = ASSERT_ONLY.replace("(bin lt (copy (p 1)) (int u16 5))", "(bin lt (int u32 70) (int u32 64))");
    assert!(read_f(&false_, &["a"], &[], true, "u16").unwrap().contains("unreachable"));
}

/// `let mut pos = pos.as_u64();` then a loop over the shadow.
const SHADOW: &str = r#"(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 u64 mut) (1 u64 imm) (2 u64 mut) (3 bool mut))
  (debug "pos" (p 1) (arg 1)) (debug "pos" (p 2))
  (bb 0 (assign (p 2) (use (copy (p 1)))) (goto 1))
  (bb 1 (assign (p 3) (bin gt (copy (p 2)) (int u64 0))) (switch (move (p 3)) (0 3) (otherwise 2)))
  (bb 2 (assign (p 2) (bin shr (copy (p 2)) (int u32 1))) (goto 1))
  (bb 3 (assign (p 0) (use (copy (p 2)))) (return)))
"#;

#[test]
fn a_loop_attachment_names_the_variable_in_scope_at_the_loop() {
    let l = load(SHADOW).unwrap();
    let scopes = read::loop_scopes(&l.m, "k::m::f", &["pos".to_string()]).unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].get("pos").map(String::as_str), Some("pos_2"), "{scopes:?}");
    // negative twin: without a shadow the name is the parameter's
    let plain = SHADOW.replace("(debug \"pos\" (p 2))", "(debug \"q\" (p 2))");
    let l2 = load(&plain).unwrap();
    assert!(read::loop_scopes(&l2.m, "k::m::f", &["pos".to_string()]).unwrap()[0].is_empty());
}

#[test]
fn variant_markers_parse_and_unknown_ones_are_refused() {
    let l = load(DROP_KNOWN).unwrap();
    let e = &l.m.adts["k::m::E"];
    assert!(e.variants[0].no_glue && !e.variants[1].no_glue);
    let bad = DROP_KNOWN.replace("(field \"0\" u16) (no-glue))\n  (variant 1", "(field \"0\" u16) (bogus))\n  (variant 1");
    assert!(load(&bad).unwrap_err().contains("variant"));
}

#[test]
fn the_round_trip_mir_sits_next_to_the_module_mir() {
    let p = sandblaster_front::lift::roundtrip_mir_path(Path::new("/x/mmr.sbmir"), "crate::merkle::mmr::iterator");
    assert_eq!(p, Path::new("/x/mmr.roundtrip__merkle__mmr__iterator.sbmir"));
}

// ---------------------------------------------------------------------------
// The Merkle proof verifier's constructs (storage's `merkle::{hasher, proof}`
// in place: `Standard<Sha256>`, `Subtree::reconstruct_digest`)
// ---------------------------------------------------------------------------

/// An open trait `Tr` read at `S`: its impl's `hash`, `S`'s inherent `hash`
/// (the lift lifts that one), a provided `fold`, and core's blanket
/// `From<T> for T` at `S`.
const NAMING: &str = r#"(adt-def "k::m::S" (path "k::m::S") (kind struct) (args ())
  (variant 0 "S" 0 (no-glue)))
(root "<k::m::S as k::m::Tr>::hash")
(root "k::m::S::hash")
(root "<k::m::S as k::m::Tr>::fold")
(root "<k::m::S as std::convert::From<k::m::S>>::from")
(fn "<k::m::S as k::m::Tr>::hash" (kind root) (def "<k::m::S as k::m::Tr>::hash") (args ()) (item impl (adt "k::m::S") "Tr" () "hash") (argc 0) (locals (0 unit mut)) (bb 0 (return)))
(fn "k::m::S::hash" (kind root) (def "k::m::S::hash") (args ()) (item inherent (adt "k::m::S") "hash") (argc 0) (locals (0 unit mut)) (bb 0 (return)))
(fn "<k::m::S as k::m::Tr>::fold" (kind root) (def "k::m::Tr::fold") (args ((adt "k::m::S"))) (item provided (adt "k::m::S") "Tr" () "fold") (argc 0) (locals (0 unit mut)) (bb 0 (return)))
(fn "<k::m::S as std::convert::From<k::m::S>>::from" (kind root) (def "<T as std::convert::From<T>>::from") (args ((adt "k::m::S"))) (item impl (adt "k::m::S") "From" ((adt "k::m::S")) "from") (argc 1) (locals (0 (adt "k::m::S") mut) (1 (adt "k::m::S") imm)) (bb 0 (assign (p 0) (use (move (p 1)))) (return)))
"#;

fn load_open(body: &str) -> mir::Loaded {
    let mut nm = names();
    nm.open.insert("Tr".into(), "m::S".into());
    mir::load(&format!("{HEADER}{body}"), &|_| None, nm, "m").unwrap()
}

#[test]
fn an_open_traits_methods_at_its_instance_are_named_by_the_instance_and_the_inherent_one_wins() {
    let l = load_open(NAMING);
    // the inherent `hash` (rustc resolves `S::hash` to it; the lift lifts it)
    assert_eq!(l.by_lifted.get("S::hash").map(String::as_str), Some("k::m::S::hash"), "{:?}", l.by_lifted);
    // a provided method at the instance is the instance's method
    assert_eq!(l.by_lifted.get("S::fold").map(String::as_str), Some("<k::m::S as k::m::Tr>::fold"));
    // core's blanket `From<T> for T` is library code (inlined), not `S::from`
    assert!(!l.by_lifted.contains_key("S::from"), "{:?}", l.by_lifted);
    // negative twins: without the inherent method the impl's is the one; the
    // inherent one wins whatever the order; a module's own `From` impl is lifted
    let no_inherent = NAMING.replace("(root \"k::m::S::hash\")\n", "");
    assert_eq!(load_open(&no_inherent).by_lifted.get("S::hash").map(String::as_str), Some("<k::m::S as k::m::Tr>::hash"));
    let reordered = NAMING.replace("(root \"<k::m::S as k::m::Tr>::hash\")\n(root \"k::m::S::hash\")", "(root \"k::m::S::hash\")\n(root \"<k::m::S as k::m::Tr>::hash\")");
    assert_eq!(load_open(&reordered).by_lifted.get("S::hash").map(String::as_str), Some("k::m::S::hash"));
    let own = NAMING.replace("(def \"<T as std::convert::From<T>>::from\")", "(def \"k::m::<impl std::convert::From<k::m::S> for k::m::S>::from\")");
    assert!(load_open(&own).by_lifted.contains_key("S::from"), "a module's own impl is lifted");
}

/// `fn f(d: &D) -> D`-like bodies over a library newtype `x::D([u8; 4])`
/// read as the host model `h::D = [u8; 4]`, and a host model's method
/// (`x::H` is the instance of the open trait `CH`, model `h::H`).
const HOST: &str = r#"(adt-def "x::D" (path "x::D") (kind struct) (args ())
  (variant 0 "D" 0 (field "0" (array u8 4)) (no-glue)))
(adt-def "x::H" (path "x::H") (kind struct) (args ())
  (variant 0 "H" 0 (no-glue)))
(root "k::m::f")
(root "k::m::g")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 (adt "x::D") mut) (1 (ref shared (adt "x::D")) imm) (2 (ref shared (slice u8)) mut) (3 (array (ref shared (slice u8)) 1) mut) (4 (ref shared (array (ref shared (slice u8)) 1)) mut) (5 (ref shared (slice (ref shared (slice u8)))) mut))
  (debug "d" (p 1) (arg 1))
  (bb 0 (call (fn "<x::D as std::ops::Deref>::deref") (args (copy (p 1))) (p 2) 1))
  (bb 1 (assign (p 3) (agg (array (ref shared (slice u8))) (copy (p 2)))) (assign (p 4) (ref shared (p 3))) (assign (p 5) (cast unsize (copy (p 4)) (ref shared (slice (ref shared (slice u8)))))) (call (leaf "x::Hasher::hash" ((adt "x::H"))) (args (copy (p 5))) (p 0) 2))
  (bb 2 (return)))
(fn "k::m::g" (kind root) (def "k::m::g") (args ()) (item fn "g") (argc 1)
  (locals (0 (adt "x::D") mut) (1 (ref shared (adt "x::D")) imm))
  (debug "d" (p 1) (arg 1))
  (bb 0 (assign (p 0) (agg (adt (adt "x::D") 0) (copy (p 1 deref (field 0 (array u8 4)))))) (return)))
(fn "<x::D as std::ops::Deref>::deref" (kind callee) (def "<x::D as std::ops::Deref>::deref") (args ()) (item impl (adt "x::D") "Deref" () "deref")
  (nobody))
"#;

fn host_names(n: &mut ModuleNames) {
    n.host.types.insert("D".into(), ("crate::h::D".into(), "[u8 ; 4]".into()));
    n.host.structs.insert("H".into(), "crate::h::H".into());
    n.open.insert("CH".into(), "h::H".into());
}

#[test]
fn a_library_newtype_of_a_host_model_type_is_read_as_its_field() {
    let s = read_with(HOST, "k::m::g", "g", &["d"], &[], true, "crate::h::D", host_names).unwrap();
    assert_eq!(s, "{ return d ; }");
    let l = mir::load(&format!("{HEADER}{HOST}"), &|_| None, { let mut n = names(); host_names(&mut n); n }, "m").unwrap();
    let t = read::Names::ty(&l.names, &l.m, &mir::ir::Ty::Adt("x::D".into())).unwrap();
    assert_eq!(t.to_token_stream().to_string(), "crate :: h :: D");
    // negative twins: a field of another type, or a second field, is no newtype of the model
    let other = HOST.replace("(field \"0\" (array u8 4))", "(field \"0\" (array u8 8))");
    assert!(read_with(&other, "k::m::g", "g", &["d"], &[], true, "crate::h::D", host_names).unwrap_err().contains("x::D"));
    let two = HOST.replace("(field \"0\" (array u8 4)) (no-glue)", "(field \"0\" (array u8 4)) (field \"1\" u8) (no-glue)");
    assert!(read_with(&two, "k::m::g", "g", &["d"], &[], true, "crate::h::D", host_names).is_err());
}

#[test]
fn a_host_models_deref_and_method_are_the_models() {
    let s = read_with(HOST, "k::m::f", "f", &["d"], &[], true, "crate::h::D", host_names).unwrap();
    // `Deref` (no MIR exported) is the field as a slice; `<H as Hasher>::hash` the model's
    assert!(s.contains("& (& d) [..]"), "{s}");
    assert!(s.contains("crate :: h :: H :: hash (__t"), "{s}");
    // negative twins: without the model, the leaf is refused and the body-less `deref` too
    let e = read_with(HOST, "k::m::f", "f", &["d"], &[], true, "crate::h::D", |n| {
        n.host.types.insert("D".into(), ("crate::h::D".into(), "[u8 ; 4]".into()));
    })
    .unwrap_err();
    assert!(e.contains("the leaf `x::Hasher::hash`"), "{e}");
    let e2 = read_with(HOST, "k::m::f", "f", &["d"], &[], true, "crate::h::D", |n| {
        n.host.structs.insert("H".into(), "crate::h::H".into());
        n.open.insert("CH".into(), "h::H".into());
    })
    .unwrap_err();
    assert!(e2.contains("has no MIR body"), "{e2}");
}

/// `Option<&mut Vec<u16>>` as a state: passed on by `o.as_deref_mut()`,
/// written through `if let Some(v) = &mut o { v.push(x) }`.
const OPT_STATE: &str = r#"(adt-def "std::alloc::Global" (path "std::alloc::Global") (kind struct) (args ())
  (variant 0 "Global" 0 (no-glue)))
(adt-def "std::vec::Vec<u16>" (path "std::vec::Vec") (kind struct) (args (u16 (adt "std::alloc::Global")))
  (variant 0 "Vec" 0))
(adt-def "std::option::Option<&mut std::vec::Vec<u16>>" (path "std::option::Option") (kind enum) (args ((ref mut (adt "std::vec::Vec<u16>"))))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" (ref mut (adt "std::vec::Vec<u16>"))) (no-glue)))
(root "k::m::f")
(root "k::m::g")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 2)
  (locals (0 unit mut) (1 (adt "std::option::Option<&mut std::vec::Vec<u16>>") mut) (2 u16 imm) (3 isize mut) (4 (ref mut (ref mut (adt "std::vec::Vec<u16>"))) imm) (5 (ref mut (adt "std::vec::Vec<u16>")) mut) (6 unit imm) (7 (ref mut (adt "std::option::Option<&mut std::vec::Vec<u16>>")) mut) (8 (adt "std::option::Option<&mut std::vec::Vec<u16>>") mut) (9 unit mut))
  (debug "o" (p 1) (arg 1)) (debug "x" (p 2) (arg 2)) (debug "v" (p 4))
  (bb 0 (assign (p 7) (ref mut (p 1))) (call (fn "std::option::Option::<&mut std::vec::Vec<u16>>::as_deref_mut") (args (move (p 7))) (p 8) 1))
  (bb 1 (call (fn "k::m::g") (args (move (p 8)) (copy (p 2))) (p 9) 2))
  (bb 2 (assign (p 3) (discr (p 1))) (switch (move (p 3)) (1 3) (0 5) (otherwise 6)))
  (bb 3 (assign (p 4) (ref mut (p 1 (downcast 1) (field 0 (ref mut (adt "std::vec::Vec<u16>")))))) (assign (p 5) (use (copy (p 4 deref)))) (call (leaf "std::vec::Vec::<T, A>::push" (u16 (adt "std::alloc::Global"))) (args (copy (p 5)) (copy (p 2))) (p 6) 4))
  (bb 4 (call (leaf "std::vec::Vec::<T, A>::push" (u16 (adt "std::alloc::Global"))) (args (copy (p 5)) (copy (p 2))) (p 6) 5))
  (bb 5 (return))
  (bb 6 (unreachable)))
(fn "std::option::Option::<&mut std::vec::Vec<u16>>::as_deref_mut" (kind callee) (def "std::option::Option::<T>::as_deref_mut") (args ((ref mut (adt "std::vec::Vec<u16>")))) (item inherent (adt "std::option::Option<&mut std::vec::Vec<u16>>") "as_deref_mut") (argc 1)
  (locals (0 (adt "std::option::Option<&mut std::vec::Vec<u16>>") mut) (1 (ref mut (adt "std::option::Option<&mut std::vec::Vec<u16>>")) imm))
  (bb 0 (unreachable)))
(fn "k::m::g" (kind root) (def "k::m::g") (args ()) (item fn "g") (argc 2)
  (locals (0 unit mut) (1 (adt "std::option::Option<&mut std::vec::Vec<u16>>") mut) (2 u16 imm))
  (debug "o" (p 1) (arg 1)) (debug "x" (p 2) (arg 2))
  (bb 0 (return)))
"#;

#[test]
fn an_optional_mutable_borrow_is_a_state_written_through_its_matched_field() {
    let s = read_f(OPT_STATE, &["o", "x"], &[0], false, "Option<Seq<u16>>").unwrap();
    // `o.as_deref_mut()` passes the state `o` on and takes it back
    assert!(s.contains("= g (o , x) ; o = __s"), "{s}");
    // the pushes go to the matched field's variable, and `o` is rebuilt from
    // it after them (never from a copy taken before them)
    let push = s.find("vec_push").expect("a push");
    let back = s.find("o = Some (__m").expect("the write back");
    assert!(push < back && s.matches("vec_push").count() == 2, "{s}");
    assert!(!s.contains("let __v"), "no snapshot of the state before its field changes: {s}");
    assert!(s.contains("o = Some (__m4) ; return o ;") && s.contains("None => { return o ; }"), "{s}");
    // negative twin: another `Option` method is library code (here its
    // body is unreachable), not the same optional place
    let other = OPT_STATE.replace("(def \"std::option::Option::<T>::as_deref_mut\")", "(def \"std::option::Option::<T>::as_mut\")");
    assert!(read_f(&other, &["o", "x"], &[0], false, "Option<Seq<u16>>").unwrap().contains("unreachable"));
    // negative twin: a shared `Option<&T>` is no state
    let shared = OPT_STATE.replace("(1 (adt \"std::option::Option<&mut std::vec::Vec<u16>>\") mut) (2 u16 imm) (3 isize mut)", "(1 (ref shared u16) imm) (2 u16 imm) (3 isize mut)");
    assert!(read_f(&shared, &["o", "x"], &[0], false, "Option<Seq<u16>>").unwrap_err().contains("not `&mut`"));
}

/// `e.next()` of the byte-string iterator model (a `&mut` state).
const BYTES_ITER: &str = r#"(adt-def "std::slice::Iter<'_, &[u8]>" (path "std::slice::Iter") (kind struct) (args ((ref shared (slice u8)))))
(adt-def "std::iter::Copied<std::slice::Iter<'_, &[u8]>>" (path "std::iter::Copied") (kind struct) (args ((adt "std::slice::Iter<'_, &[u8]>"))))
(adt-def "std::option::Option<&[u8]>" (path "std::option::Option") (kind enum) (args ((ref shared (slice u8))))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" (ref shared (slice u8))) (no-glue)))
(root "k::m::f")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 (adt "std::option::Option<&[u8]>") mut) (1 (ref mut (adt "std::iter::Copied<std::slice::Iter<'_, &[u8]>>")) imm))
  (debug "e" (p 1) (arg 1))
  (bb 0 (call (leaf "std::iter::Iterator::next" ((adt "std::iter::Copied<std::slice::Iter<'_, &[u8]>>"))) (args (copy (p 1))) (p 0) 1))
  (bb 1 (return)))
"#;

#[test]
fn the_byte_string_iterators_next_is_the_prelude_model() {
    let s = read_f(BYTES_ITER, &["e"], &[0], true, "(&[&[u8]], Option<&[u8]>)").unwrap();
    assert!(s.contains("= crate :: __lift :: bytes_iter_next (e) ; e = __it"), "{s}");
    let l = load(BYTES_ITER).unwrap();
    let t = read::Names::ty(&l.names, &l.m, &mir::ir::Ty::Adt("std::iter::Copied<std::slice::Iter<'_, &[u8]>>".into())).unwrap();
    assert_eq!(t.to_token_stream().to_string(), "& [& [u8]]");
    // negative twin: an iterator over another item type is no model
    let bytes = BYTES_ITER.replace("(adt-def \"std::slice::Iter<'_, &[u8]>\" (path \"std::slice::Iter\") (kind struct) (args ((ref shared (slice u8)))))", "(adt-def \"std::slice::Iter<'_, &[u8]>\" (path \"std::slice::Iter\") (kind struct) (args (u8)))");
    assert!(read_f(&bytes, &["e"], &[0], true, "(&[&[u8]], Option<&[u8]>)").unwrap_err().contains("the leaf `std::iter::Iterator::next`"));
}

/// `x.to_be_bytes()` and `s.get(i)`: builtins of the subset.
const BUILTINS: &str = r#"(adt-def "std::option::Option<&u16>" (path "std::option::Option") (kind enum) (args ((ref shared u16)))
  (variant 0 "None" 0 (no-glue))
  (variant 1 "Some" 1 (field "0" (ref shared u16)) (no-glue)))
(root "k::m::f")
(root "k::m::g")
(fn "k::m::f" (kind root) (def "k::m::f") (args ()) (item fn "f") (argc 1)
  (locals (0 (array u8 8) mut) (1 u64 imm))
  (debug "x" (p 1) (arg 1))
  (bb 0 (call (fn "core::num::<impl u64>::to_be_bytes") (args (copy (p 1))) (p 0) 1))
  (bb 1 (return)))
(fn "core::num::<impl u64>::to_be_bytes" (kind callee) (def "core::num::<impl u64>::to_be_bytes") (args ()) (item inherent u64 "to_be_bytes") (argc 1)
  (locals (0 (array u8 8) mut) (1 u64 imm))
  (bb 0 (unreachable)))
(fn "k::m::g" (kind root) (def "k::m::g") (args ()) (item fn "g") (argc 2)
  (locals (0 (adt "std::option::Option<&u16>") mut) (1 (ref shared (slice u16)) imm) (2 usize imm))
  (debug "s" (p 1) (arg 1)) (debug "i" (p 2) (arg 2))
  (bb 0 (call (fn "core::slice::<impl [u16]>::get::<usize>") (args (copy (p 1)) (copy (p 2))) (p 0) 1))
  (bb 1 (return)))
(fn "core::slice::<impl [u16]>::get::<usize>" (kind callee) (def "core::slice::<impl [T]>::get") (args (u16 usize)) (item inherent (slice u16) "get") (argc 2)
  (locals (0 (adt "std::option::Option<&u16>") mut) (1 (ref shared (slice u16)) imm) (2 usize imm))
  (bb 0 (unreachable)))
"#;

#[test]
fn big_endian_bytes_and_slice_get_are_builtins() {
    assert_eq!(read_f(BUILTINS, &["x"], &[], true, "[u8; 8usize]").unwrap(), "{ return x . to_be_bytes () ; }");
    let g = read_with(BUILTINS, "k::m::g", "g", &["s", "i"], &[], true, "Option<&u16>", |_| {}).unwrap();
    // (`s` is a `&[u16]` parameter the lift would keep as a reference; here it is read by value)
    assert_eq!(g, "{ return (& s) . get (i) ; }");
    // negative twins: another method, another index type: their (here
    // unreachable) bodies are read
    let le = BUILTINS.replace("(item inherent u64 \"to_be_bytes\")", "(item inherent u64 \"to_le_bytes\")");
    assert!(read_f(&le, &["x"], &[], true, "[u8; 8usize]").unwrap().contains("unreachable"));
    let range = BUILTINS.replace("(args (u16 usize)) (item inherent (slice u16) \"get\")", "(args (u16 u32)) (item inherent (slice u16) \"get\")");
    assert!(read_with(&range, "k::m::g", "g", &["s", "i"], &[], true, "Option<&u16>", |_| {}).unwrap().contains("unreachable"));
}

/// The checked-in extraction of storage's verifier (set 1) is current and the
/// front end reads every lifted function of it from rustc's MIR.
#[test]
fn the_storage_verifier_bodies_are_read_from_rustc_mir() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../storage/sandblaster/verifier/mod.rs");
    let c = sandblaster_front::driver::check(&root, &sandblaster_front::loader::RealFs, &sandblaster_front::target::TargetInfo::host());
    assert!(c.ok(), "{}", c.render());
    let read = &c.lift_facts.mir_read;
    for f in ["Standard::hash", "Standard::node_digest", "Standard::leaf_digest", "Subtree::children", "Subtree::reconstruct_digest", "Family::children"] {
        assert!(read.iter().any(|(n, _, _)| n == f), "`{f}` is read from MIR: {:?}", read.iter().map(|r| &r.0).collect::<Vec<_>>());
    }
}

/// The checked-in extraction of storage's MMR is current and the front end
/// reads every lifted function of it (and of `opt.rs`) from rustc's MIR.
#[test]
fn the_storage_mmr_bodies_are_read_from_rustc_mir() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../storage/sandblaster/mmr/mod.rs");
    let c = sandblaster_front::driver::check(&root, &sandblaster_front::loader::RealFs, &sandblaster_front::target::TargetInfo::host());
    assert!(c.ok(), "{}", c.render());
    let read = &c.lift_facts.mir_read;
    assert!(read.len() >= 70, "{} functions read from MIR", read.len());
    for f in ["Family::position_to_location", "PeakIterator::next", "Position::add__u64", "to_nearest_size_fast"] {
        assert!(read.iter().any(|(n, _, _)| n == f), "`{f}` is read from MIR: {:?}", read.iter().map(|r| &r.0).collect::<Vec<_>>());
    }
}
