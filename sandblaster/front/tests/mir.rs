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
    ModuleNames { module: String::new(), sealed: BTreeSet::new(), host_enums: host, requires: BTreeSet::new(), open: BTreeMap::new(), dsl_modules: vec![], current: Default::default() }
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
