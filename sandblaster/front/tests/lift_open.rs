//! The lift of a host crate's own files (`#[lift(in_place, ..)]`,
//! SEMANTICS.md §19.5–19.9): open traits at a declared instance, operator
//! impls, core's `Option`/`Result`/integer methods as templates, closures,
//! `impl Trait` returns, `for`/`while` loops (helpers and attachments),
//! assertion macros, dropped host items, attachment merging and bridge
//! rules. Each feature has a positive test and a negative twin.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use std::path::Path;

use sandblaster_front::diag::{DiagKind, Severity};
use sandblaster_front::driver::{self, Checked, ProverSet, Verification, VerifyOptions};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;
use util::opts;

const ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

fn check(files: &[(&str, &str)]) -> Checked {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (*p, *c)));
    driver::check(Path::new(files[0].0), &fs, &TargetInfo::aarch64_apple_darwin())
}

fn errors(c: &Checked) -> Vec<(DiagKind, String)> {
    c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| (d.kind, d.msg.clone())).collect()
}

fn warnings(c: &Checked) -> Vec<String> {
    c.diags.list.iter().filter(|d| d.severity == Severity::Warning).map(|d| d.msg.clone()).collect()
}

#[track_caller]
fn rejects(c: &Checked, needle: &str) {
    assert!(errors(c).iter().any(|(_, m)| m.contains(needle)), "expected an error containing {needle:?}; got:\n{}", c.render());
}

#[track_caller]
fn front_ok(files: &[(&str, &str)]) -> Checked {
    let c = check(files);
    assert!(c.ok(), "front end rejected the lifted crate:\n{}", c.render());
    c
}

/// Every definition, lemmas included (proof steps in lifted code call
/// lemmas, so exec-only verification would leave their callers blocked).
fn verify(c: &Checked) -> Verification {
    let o = VerifyOptions { exec_only: false, ..opts(ProverSet::Standard) };
    driver::stage::verify(c.krate.as_ref().unwrap(), &o)
}

#[track_caller]
fn verified(files: &[(&str, &str)]) {
    let c = front_ok(files);
    let v = verify(&c);
    util::assert_verified(&c, &v);
}

/// The names of the definitions that did not check.
#[track_caller]
fn failed(files: &[(&str, &str)]) -> Vec<String> {
    let c = front_ok(files);
    let v = verify(&c);
    let f: Vec<String> = v.failed_defs().iter().map(|d| d.name.clone()).collect();
    assert!(!f.is_empty(), "expected a definition to fail; everything checked:\n{}", util::explain(&c, &v));
    f
}

/// A DSL root lifting the host file `src/a.rs` in place with `opts`, and
/// the proof file when `proof` is given.
fn root(opts: &str, proof: bool) -> String {
    let mut r = format!("{ROOT}#[lift(in_place{opts})]\n#[path = \"../../src/a.rs\"]\npub mod a;\n");
    if proof {
        r.push_str("#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n");
    }
    r
}

const R: &str = "c/sandblaster/m/mod.rs";
const A: &str = "c/src/a.rs";
const P: &str = "c/sandblaster/m/PROOF.rs";

// ---------------------------------------------------------------------
// open traits at a declared instance
// ---------------------------------------------------------------------

const OPEN: &str = r#"
// the open trait lives in a host module the lift does not read (as
// `crate::merkle::Family` does for the storage crate)
use super::Fam;
use core::marker::PhantomData;

pub struct Small;
pub struct Big;

impl Fam for Small {
    const MAX: u64 = 100;
    fn cap(x: u64) -> u64 {
        if x > Self::MAX { Self::MAX } else { x }
    }
}

impl Fam for Big {
    const MAX: u64 = 7;
    fn cap(x: u64) -> u64 {
        x % 8
    }
}

pub struct P<F: Fam>(u64, PhantomData<F>);

impl<F: Fam> P<F> {
    pub fn new(x: u64) -> Self {
        Self(F::cap(x), PhantomData)
    }
    pub fn get(&self) -> u64 {
        self.0
    }
    pub fn room(x: u64) -> u64 {
        F::MAX - F::cap(x)
    }
}
"#;

#[test]
fn an_open_trait_is_lifted_at_its_declared_instance() {
    let r = root(", instance = \"Fam: crate::a::Small\", unverified_instances = \"Fam: crate::a::Big\"", false);
    let c = front_ok(&[(R, &r), (A, OPEN)]);
    assert!(warnings(&c).iter().any(|m| m.contains("Big")), "the unverified instance must be listed:\n{}", c.render());
    let v = verify(&c);
    util::assert_verified(&c, &v);
    let names: Vec<String> = v.defs.iter().map(|d| d.name.clone()).collect();
    assert!(names.iter().any(|n| n == "crate::a::P::room"), "{names:?}");
}

#[test]
fn an_open_trait_without_a_declared_instance_is_not_lifted() {
    let r = root("", false);
    let c = check(&[(R, &r), (A, OPEN)]);
    assert!(!c.ok(), "a generic over an open trait needs `instance = ..`:\n{}", c.render());
}

#[test]
fn the_declared_instance_is_the_one_checked() {
    // `room` is `MAX - cap(x)`, safe at `Small` (`cap` is at most `MAX`);
    // a `Big` whose `cap` can exceed its `MAX` fails when it is the
    // declared instance
    let bad = OPEN.replace("x % 8", "x % 9");
    let r = root(", instance = \"Fam: crate::a::Big\", unverified_instances = \"Fam: crate::a::Small\"", false);
    let f = failed(&[(R, &r), (A, &bad)]);
    assert!(f.iter().any(|n| n.contains("room")), "{f:?}");
}

// ---------------------------------------------------------------------
// operator impls, `Deref`, derived `Default`
// ---------------------------------------------------------------------

const OPS: &str = r#"
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pos(u64);

impl Pos {
    pub const fn new(x: u64) -> Self {
        Self(x)
    }
}

impl core::ops::Add<u64> for Pos {
    type Output = Self;
    fn add(self, r: u64) -> Self {
        Self(self.0 + r)
    }
}

impl core::ops::Deref for Pos {
    type Target = u64;
    fn deref(&self) -> &u64 {
        &self.0
    }
}

pub fn next(p: Pos) -> u64 {
    let q = p + 1;
    *q
}

pub fn zero() -> u64 {
    let z = Pos::default();
    *z
}
"#;

const OPS_PRE: &str = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::next)]\nfn next_pre() {\n    requires((p.0 as Int) + 1 < pow2(64));\n}\n\n#[lift_attach(crate::a::Pos::add__u64)]\nfn add_pre() {\n    requires((self.0 as Int) + (r as Int) < pow2(64));\n}\n";

#[test]
fn operators_deref_and_default_are_lifted_through_their_impls() {
    verified(&[(R, &root("", true)), (A, OPS), (P, OPS_PRE)]);
}

#[test]
fn an_operator_impl_keeps_its_overflow_obligation() {
    let f = failed(&[(R, &root("", false)), (A, OPS)]);
    assert!(f.iter().any(|n| n.contains("next") || n.contains("add")), "{f:?}");
}

// ---------------------------------------------------------------------
// templates: Option/Result/integer methods, closures
// ---------------------------------------------------------------------

const TPL: &str = r#"
pub fn dbl(x: u64) -> u64 {
    x.checked_mul(2).expect("small")
}

pub fn dec2(x: Option<u64>) -> Option<u64> {
    x.and_then(|v| v.checked_sub(2))
}

pub fn half_or_zero(x: Option<u64>) -> u64 {
    x.map_or(0u64, |v| v / 2)
}

pub fn need(x: Option<u64>) -> Result<u64, u8> {
    x.ok_or(3u8)
}

pub fn shl_or_zero(x: u64, s: u32) -> u64 {
    match x.checked_shl(s) {
        Some(v) => v,
        None => 0,
    }
}

pub fn ones(x: u64) -> u32 {
    x.trailing_ones()
}

pub fn size(n: u64) -> u64 {
    let f = |k: u64| 2 * k - k.count_ones() as u64;
    f(n)
}
"#;

const TPL_PRE: &str = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::dbl)]\nfn dbl_pre() {\n    requires((x as Int) * 2 < pow2(64));\n}\n\n#[lift_attach(crate::a::size)]\nfn size_pre() {\n    requires((n as Int) < pow2(62) && n >= 64u64);\n}\n";

#[test]
fn core_methods_and_closures_are_lifted_as_checked_templates() {
    verified(&[(R, &root("", true)), (A, TPL), (P, TPL_PRE)]);
}

#[test]
fn an_expect_that_can_fail_is_an_unproven_panic() {
    let pre = TPL_PRE.replace("requires((x as Int) * 2 < pow2(64));", "requires(true);");
    let f = failed(&[(R, &root("", true)), (A, TPL), (P, &pre)]);
    assert!(f.iter().any(|n| n.contains("dbl")), "{f:?}");
}

#[test]
fn a_closure_whose_capture_changes_is_refused() {
    let src = "pub fn g(x: u64) -> u64 {\n    let mut a = 1u64;\n    let f = |k: u64| k / 2 + a;\n    a = 2;\n    f(x) + a\n}\n";
    let c = check(&[(R, &root("", false)), (A, src)]);
    rejects(&c, "re-bound or assigned while the closure lives");
}

#[test]
fn a_template_message_must_be_a_literal() {
    let src = "pub fn g(x: Option<u64>, m: &str) -> u64 {\n    x.expect(m)\n}\n";
    let c = check(&[(R, &root("", false)), (A, src)]);
    rejects(&c, "string literal");
}

// ---------------------------------------------------------------------
// `impl Trait` returns, custom iterators, `for` loops
// ---------------------------------------------------------------------

const ITER: &str = r#"
pub struct Down {
    n: u32,
}

impl Iterator for Down {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.n == 0 {
            return None;
        }
        self.n -= 1;
        Some(self.n)
    }
}

impl Down {
    pub fn new(n: u32) -> Self {
        Self { n }
    }
}

pub fn down(n: u32) -> impl Iterator<Item = u32> {
    Down::new(n)
}

pub fn heights(k: u32) -> impl Iterator<Item = u32> {
    1..=k
}

pub fn count(n: u32) -> u64 {
    let mut acc = 0u64;
    for _i in down(n) {
        acc += 1;
    }
    acc
}
"#;

const ITER_PROOF: &str = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::count, loop_nr = 0)]\nfn count_loop() {\n    invariant((acc as Int) + (iter.n as Int) == (n as Int));\n    decreases(iter.n);\n}\n";

#[test]
fn impl_trait_returns_iterators_and_for_loops_are_lifted() {
    verified(&[(R, &root("", true)), (A, ITER), (P, ITER_PROOF)]);
}

#[test]
fn a_for_loop_without_its_invariant_leaves_the_overflow_unproven() {
    let f = failed(&[(R, &root("", false)), (A, ITER)]);
    assert!(f.iter().any(|n| n.contains("count")), "{f:?}");
}

#[test]
fn a_for_loop_over_an_unknown_iterator_is_refused() {
    let src = "pub fn f(v: [u64; 3]) -> u64 {\n    let mut a = 0u64;\n    for x in v.iter() {\n        a = *x;\n    }\n    a\n}\n";
    let c = check(&[(R, &root("", false)), (A, src)]);
    assert!(!c.ok(), "{}", c.render());
}

// ---------------------------------------------------------------------
// `while` helpers of `&mut self` methods, assertion macros, `at_start!`
// ---------------------------------------------------------------------

const WALK: &str = r#"
pub struct Walk {
    pos: u64,
    step: u64,
}

impl Walk {
    pub fn go(&mut self, limit: u64) -> u64 {
        while self.step > 1 {
            if self.pos < limit {
                self.pos += self.step - 1;
                assert!(self.pos >= limit);
                return self.pos;
            }
            self.step >>= 1;
        }
        0
    }
}
"#;

const WALK_PROOF: &str = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::Walk::go, loop_nr = 0)]\nfn go_loop() {\n    invariant((self.pos as Int) + (self.step as Int) < pow2(64) && ((self.pos as Int) >= (limit as Int) || (self.pos as Int) + (self.step as Int) >= (limit as Int) + 1));\n    decreases(self.step);\n}\n\n#[lift_attach(crate::a::Walk::go)]\nfn go_pre() {\n    requires((self.pos as Int) + (self.step as Int) < pow2(64) && ((self.pos as Int) >= (limit as Int) || (self.pos as Int) + (self.step as Int) >= (limit as Int) + 1));\n}\n";

#[test]
fn an_assertion_in_a_while_helper_reads_the_updated_fields() {
    verified(&[(R, &root("", true)), (A, WALK), (P, WALK_PROOF)]);
}

#[test]
fn a_false_assertion_in_a_while_helper_is_unproven() {
    let pre = WALK_PROOF.replace(" || (self.pos as Int) + (self.step as Int) >= (limit as Int) + 1", " || true");
    let f = failed(&[(R, &root("", true)), (A, WALK), (P, &pre)]);
    assert!(f.iter().any(|n| n.contains("go")), "{f:?}");
}

const HALVE: &str = r#"
pub fn halve(mut x: u64, mut k: u64) -> u64 {
    while k != 0 {
        x = x / 2 + 1;
        k -= 1;
    }
    x
}
"#;

#[test]
fn a_plain_loop_runs_its_at_start_steps_each_iteration() {
    let proof = "use sandblaster::prelude::*;\n\n#[lemma]\nfn half_le(x: u64) {\n    requires(x >= 2u64);\n    ensures(x / 2 + 1 <= x);\n    follows();\n}\n\n#[lift_attach(crate::a::halve, loop_nr = 0)]\nfn halve_loop() {\n    invariant(x >= 2u64);\n    decreases(k);\n    at_start! {\n        crate::proof::half_le(x);\n    }\n}\n\n#[lift_attach(crate::a::halve)]\nfn halve_pre() {\n    requires(x >= 2u64);\n}\n";
    verified(&[(R, &root("", true)), (A, HALVE), (P, proof)]);
}

#[test]
fn an_at_start_step_is_checked_where_it_runs() {
    // the lemma's precondition does not hold on entry without `halve_pre`
    let proof = "use sandblaster::prelude::*;\n\n#[lemma]\nfn half_le(x: u64) {\n    requires(x >= 2u64);\n    ensures(x / 2 + 1 <= x);\n    follows();\n}\n\n#[lift_attach(crate::a::halve, loop_nr = 0)]\nfn halve_loop() {\n    decreases(k);\n    at_start! {\n        crate::proof::half_le(x);\n    }\n}\n";
    let f = failed(&[(R, &root("", true)), (A, HALVE), (P, proof)]);
    assert!(f.iter().any(|n| n.contains("halve")), "{f:?}");
}

const ASSERTS: &str = r#"
pub fn check(x: u64) -> u64 {
    assert_eq!(x % 2, 0, "even");
    assert_ne!(x, 1);
    debug_assert!(x != 3);
    x / 2
}
"#;

#[test]
fn assertion_macros_are_obligations() {
    let proof = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::check)]\nfn check_pre() {\n    requires(x % 2u64 == 0u64);\n}\n";
    verified(&[(R, &root("", true)), (A, ASSERTS), (P, proof)]);
}

#[test]
fn an_assertion_that_can_fail_is_unproven() {
    let f = failed(&[(R, &root("", false)), (A, ASSERTS)]);
    assert!(f.iter().any(|n| n.contains("check")), "{f:?}");
}

// ---------------------------------------------------------------------
// host items left out: item macros, declared unverified impls
// ---------------------------------------------------------------------

const HOSTY: &str = r#"
pub struct Q(u64);

impl Q {
    pub fn get(&self) -> u64 {
        self.0
    }
}

impl codec::Write for Q {
    fn write(&self, buf: &mut Vec<u8>) {
        buf.push(self.0 as u8);
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        pub mod full;
    }
}
"#;

#[test]
fn declared_unverified_impls_and_item_macros_are_left_out_and_listed() {
    let c = front_ok(&[(R, &root(", unverified_impls = \"codec::Write\"", false)), (A, HOSTY)]);
    let w = warnings(&c);
    assert!(w.iter().any(|m| m.contains("codec::Write") || m.contains("Write")), "{}", c.render());
    let v = verify(&c);
    util::assert_verified(&c, &v);
}

#[test]
fn an_undeclared_host_impl_is_an_error() {
    let c = check(&[(R, &root("", false)), (A, HOSTY)]);
    assert!(!c.ok(), "an impl of an unknown trait must be declared unverified:\n{}", c.render());
}

// ---------------------------------------------------------------------
// a declared unverified method stays host code
// ---------------------------------------------------------------------

const PARTLY: &str = "pub struct T(u64);

impl T {
    pub fn get(&self) -> u64 {
        self.0
    }
    pub fn bump(&self) -> u64 {
        self.0 + 1
    }
}
";

#[test]
fn a_declared_unverified_method_is_left_out_and_listed() {
    //  can overflow; declared unverified it is not lifted, and the
    // rest checks
    let c = front_ok(&[(R, &root(", unverified_fns = \"T::bump\"", false)), (A, PARTLY)]);
    assert!(warnings(&c).iter().any(|m| m.contains("T::bump") && m.contains("unverified_fns")), "{}", c.render());
    let v = verify(&c);
    util::assert_verified(&c, &v);
    assert!(!v.defs.iter().any(|d| d.name.contains("bump")), "bump must not be lifted");
}

#[test]
fn a_call_to_a_declared_unverified_method_is_refused() {
    // the gap cannot hide inside checked code: a lifted caller of `bump`
    // does not load
    let src = PARTLY.replace("    pub fn get(&self) -> u64 {\n        self.0\n    }", "    pub fn get(&self) -> u64 {\n        self.bump()\n    }");
    assert!(src.contains("self.bump()"));
    let c = check(&[(R, &root(", unverified_fns = \"T::bump\"", false)), (A, &src)]);
    assert!(!c.ok(), "{}", c.render());
}

#[test]
fn an_undeclared_method_is_checked() {
    let f = failed(&[(R, &root("", false)), (A, PARTLY)]);
    assert!(f.iter().any(|n| n.contains("bump")), "{f:?}");
}

// ---------------------------------------------------------------------
// attachments: several on one item are merged
// ---------------------------------------------------------------------

const TWO: &str = "pub fn inc(x: u64) -> u64 {\n    x + 1\n}\n";

#[test]
fn two_attachments_to_one_function_are_merged() {
    let laws = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::inc)]\nfn inc_pre() {\n    requires((x as Int) < 100);\n}\n";
    let proof = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::inc)]\nfn inc_post() {\n    ensures(|ret: u64| (ret as Int) <= 100);\n}\n";
    let r = format!("{}#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n", root("", true));
    verified(&[(R, &r), (A, TWO), (P, proof), ("c/sandblaster/m/LAWS.rs", laws)]);
}

#[test]
fn a_merged_attachment_still_needs_its_partner() {
    let proof = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::inc)]\nfn inc_post() {\n    ensures(|ret: u64| (ret as Int) <= 100);\n}\n";
    let f = failed(&[(R, &root("", true)), (A, TWO), (P, proof)]);
    assert!(f.iter().any(|n| n.contains("inc")), "{f:?}");
}

// ---------------------------------------------------------------------
// bridge rules: inequalities and conditional integer equations join
// linear arithmetic
// ---------------------------------------------------------------------

const BRIDGE_ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n\n#[cfg(sandblaster)]\n#[bridges]\n#[path = \"WORDS.rs\"]\nmod words;\n\n#[cfg(sandblaster)]\n#[path = \"PROOF.rs\"]\nmod proof;\n";

/// A conditional integer equation and a conditional inequality about
/// opaque functions.
const WORDS: &str = "use sandblaster::prelude::*;\n\n#[lemma]\npub fn dbl_rw(x: Int) {\n    requires(x >= 0);\n    ensures(crate::proof::dbl(x) == 2 * x);\n    unfold(crate::proof::dbl);\n    follows();\n}\n\n#[lemma]\npub fn half_le(x: Int) {\n    requires(x >= 0);\n    ensures(crate::proof::half(x) <= x);\n    unfold(crate::proof::half);\n    follows();\n}\n";

const USES: &str = "use sandblaster::prelude::*;\n\n#[spec]\n#[opaque]\npub fn dbl(x: Int) -> Int {\n    2 * x\n}\n\n#[spec]\n#[opaque]\npub fn half(x: Int) -> Int {\n    if x >= 0 { x / 2 } else { 0 }\n}\n\n#[lemma]\nfn use_rules(x: Int) {\n    requires(x >= 1);\n    ensures(dbl(x) > 2 * x - 1 && half(x) < dbl(x));\n    follows();\n}\n";

#[test]
fn bridge_equations_and_inequalities_are_applied_without_a_call() {
    let c = front_ok(&[("b/mod.rs", BRIDGE_ROOT), ("b/WORDS.rs", WORDS), ("b/PROOF.rs", USES)]);
    let v = verify(&c);
    util::assert_verified(&c, &v);
}

#[test]
fn without_the_bridge_module_the_rules_are_not_known() {
    let root = BRIDGE_ROOT.replace("#[bridges]\n", "");
    let c = front_ok(&[("b/mod.rs", &root), ("b/WORDS.rs", WORDS), ("b/PROOF.rs", USES)]);
    let v = verify(&c);
    assert!(v.failed_defs().iter().any(|d| d.name.contains("use_rules")), "the facts need the bridges:\n{}", util::explain(&c, &v));
}

// ---------------------------------------------------------------------
// the templates are core's definitions (native differential test)
// ---------------------------------------------------------------------

#[allow(dead_code, clippy::all)]
#[path = "../lift/combinators.rs"]
mod templates;

const WORDS64: [u64; 12] = [0, 1, 2, 3, 7, 8, 255, 256, 0x8000_0000_0000_0000, 0x7fff_ffff_ffff_ffff, u64::MAX - 1, u64::MAX];

#[test]
fn the_integer_templates_agree_with_core() {
    for &x in &WORDS64 {
        for s in 0..70u32 {
            assert_eq!(templates::u64_checked_shl(x, s), x.checked_shl(s), "checked_shl({x}, {s})");
            assert_eq!(templates::u64_checked_shr(x, s), x.checked_shr(s), "checked_shr({x}, {s})");
            let (y, z) = (x as u32, (x >> 3) as u16);
            assert_eq!(templates::u32_checked_shl(y, s), y.checked_shl(s));
            assert_eq!(templates::u16_checked_shr(z, s), z.checked_shr(s));
        }
        assert_eq!(templates::u64_trailing_ones(x), x.trailing_ones());
        assert_eq!(templates::u64_leading_ones(x), x.leading_ones());
        assert_eq!(templates::u8_trailing_ones(x as u8), (x as u8).trailing_ones());
        for &w in &WORDS64 {
            assert_eq!(templates::u64_cmp(&x, &w), x.cmp(&w));
            assert_eq!(templates::u64_partial_cmp(&x, &w), x.partial_cmp(&w));
            assert_eq!(templates::usize_cmp(&(x as usize), &(w as usize)), (x as usize).cmp(&(w as usize)));
        }
    }
}

#[test]
fn the_option_and_result_templates_agree_with_core() {
    let opts: [Option<u64>; 4] = [None, Some(0), Some(5), Some(u64::MAX)];
    for &o in &opts {
        assert_eq!(templates::option_and_then(o, |v| v.checked_sub(2)), o.and_then(|v| v.checked_sub(2)));
        assert_eq!(templates::option_map(o, |v| v / 3), o.map(|v| v / 3));
        assert_eq!(templates::option_map_or(o, 7, |v| v % 5), o.map_or(7, |v| v % 5));
        assert_eq!(templates::option_ok_or(o, 3u8), o.ok_or(3u8));
        assert_eq!(templates::option_filter(o, |v| *v > 1), o.filter(|v| *v > 1));
        assert_eq!(templates::option_or(o, Some(9)), o.or(Some(9)));
        assert_eq!(templates::option_is_some_and(o, |v| v % 2 == 1), o.is_some_and(|v| v % 2 == 1));
        assert_eq!(templates::option_unwrap_or_else(o, || 4), o.unwrap_or_else(|| 4));
        if let Some(v) = o {
            assert_eq!(templates::option_expect(o, "m"), v);
        } else {
            assert!(std::panic::catch_unwind(|| templates::option_expect(o, "m")).is_err());
        }
        let r: Result<u64, u8> = o.ok_or(1);
        assert_eq!(templates::result_ok(r), r.ok());
        assert_eq!(templates::result_is_ok(r), r.is_ok());
        assert_eq!(templates::result_and_then(r, |v| if v > 3 { Ok(v) } else { Err(2) }), r.and_then(|v| if v > 3 { Ok(v) } else { Err(2) }));
        match r {
            Ok(v) => {
                assert_eq!(templates::result_expect(r, "m"), v);
                assert_eq!(templates::result_unwrap(r), v);
            }
            Err(_) => {
                assert!(std::panic::catch_unwind(|| templates::result_expect(r, "m")).is_err());
                assert!(std::panic::catch_unwind(|| templates::result_unwrap(r)).is_err());
            }
        }
    }
}

// ---------------------------------------------------------------------
// `ensures` of a function with an unreachable tail (`expect`'s `else`)
// ---------------------------------------------------------------------

const EXPECT: &str = "pub fn half_of_double(x: u64) -> u64 {\n    x.checked_mul(2).expect(\"small\") / 2\n}\n";

#[test]
fn an_unreachable_tail_is_closed_by_the_bodys_own_proof() {
    let proof = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::half_of_double)]\nfn hod() {\n    requires((x as Int) <= pow2(62));\n    ensures(|ret: u64| ret == x);\n}\n";
    verified(&[(R, &root("", true)), (A, EXPECT), (P, proof)]);
}

#[test]
fn an_unreachable_tail_does_not_prove_a_false_ensures() {
    let proof = "use sandblaster::prelude::*;\n\n#[lift_attach(crate::a::half_of_double)]\nfn hod() {\n    requires((x as Int) <= pow2(62));\n    ensures(|ret: u64| ret == x / 2u64);\n}\n";
    let f = failed(&[(R, &root("", true)), (A, EXPECT), (P, proof)]);
    assert!(f.iter().any(|n| n.contains("half_of_double")), "{f:?}");
}

// ---------------------------------------------------------------------
// building in place before the specification lock: proofs enforced, §15
// gates reported
// ---------------------------------------------------------------------

fn build_in_place(src: &str, gates: driver::GateUse) -> driver::BuildOutcome {
    let fs = MemFs::from_files([("c/src/lib.rs", "mod a;\n"), ("c/src/a.rs", src), ("c/sandblaster/m/mod.rs", root("", false).as_str())]);
    let env = |k: &str| -> Option<String> {
        match k {
            "CARGO_MANIFEST_DIR" => Some("c".into()),
            "OUT_DIR" => Some("out".into()),
            "CARGO_CFG_TARGET_ARCH" => Some("aarch64".into()),
            "CARGO_CFG_TARGET_FEATURE" => Some("neon".into()),
            "CARGO_CFG_TARGET_ENDIAN" => Some("little".into()),
            "CARGO_CFG_TARGET_POINTER_WIDTH" => Some("64".into()),
            _ => None,
        }
    };
    driver::build_lifted_with("sandblaster/m/mod.rs", "m", None, &env, &fs, gates)
}

const SAFE: &str = "pub fn half(x: u64) -> u64 {\n    x / 2\n}\n";

#[test]
fn a_pending_gates_build_passes_on_checked_proofs_and_says_so() {
    let o = build_in_place(SAFE, driver::GateUse::Pending);
    assert!(o.ok, "{}", o.stderr);
    let record = &o.outputs.iter().find(|(p, _)| p.ends_with("m-pending.txt")).expect("the record").1;
    assert!(record.starts_with("NOT VERIFIED — DEVELOPMENT BUILD: PROOFS CHECKED, §15 GATES PENDING") && record.contains("no verdict"), "{record}");
    assert!(record.contains("lift conformance: not run"), "{record}");
    // it cannot be mistaken for a verified build: no verified record, no
    // verdict key, the report says so, a warning on every build
    let stub = &o.outputs.iter().find(|(p, _)| p.ends_with("m-verified.txt")).expect("the stub").1;
    assert!(stub.starts_with("NOT VERIFIED") && !stub.contains("VERIFIED +"), "{stub}");
    assert!(o.outputs.iter().any(|(p, c)| p.ends_with("m-verdict.key") && c.is_empty()), "the verdict key is cleared");
    let report = &o.outputs.iter().find(|(p, _)| p.ends_with("m-report.json")).expect("the report").1;
    assert!(report.contains("\"status\": \"NOT VERIFIED — DEVELOPMENT BUILD: PROOFS CHECKED, §15 GATES PENDING\"") && report.contains("\"development_build\""), "{report}");
    assert!(o.cargo.iter().any(|l| l.starts_with("cargo::warning=") && l.contains("§15 GATES PENDING")), "{:?}", o.cargo);
    // cargo watches the files read, and no missing path (a missing path
    // would re-run the build script on every build)
    assert!(o.cargo.iter().any(|l| l.starts_with("cargo::rerun-if-changed=") && l.ends_with("a.rs")), "{:?}", o.cargo);
    assert!(!o.cargo.iter().any(|l| l.starts_with("cargo::rerun-if-changed=") && (l.contains('<') || l.ends_with("SPEC.lock"))), "{:?}", o.cargo);
    // the same crate without an accepted lock fails an enforcing build
    let e = build_in_place(SAFE, driver::GateUse::Enforce);
    assert!(!e.ok, "no lock: the enforcing build must fail");
}

#[test]
fn a_pending_gates_build_fails_on_an_unproven_obligation() {
    let o = build_in_place("pub fn inc(x: u64) -> u64 {\n    x + 1\n}\n", driver::GateUse::Pending);
    assert!(!o.ok, "an overflow is unproven: the build must fail");
    assert!(!o.outputs.iter().any(|(p, c)| (p.ends_with("m-verified.txt") || p.ends_with("m-pending.txt")) && c.contains("PROOFS CHECKED")));
}

#[path = "gated_util.rs"]
mod gated;

fn cargo_env(k: &str) -> Option<String> {
    match k {
        "CARGO_MANIFEST_DIR" => Some("c".into()),
        "OUT_DIR" => Some("out".into()),
        "CARGO_CFG_TARGET_ARCH" => Some("aarch64".into()),
        "CARGO_CFG_TARGET_FEATURE" => Some("neon".into()),
        "CARGO_CFG_TARGET_ENDIAN" => Some("little".into()),
        "CARGO_CFG_TARGET_POINTER_WIDTH" => Some("64".into()),
        _ => None,
    }
}

#[test]
fn an_in_place_build_runs_the_conformance_check_after_the_gates() {
    // the lock its own gates accepted: every §15 gate passes, so the
    // enforcing build reaches the lift conformance check, which does not
    // support in-place modules yet — no verdict, and the reason is named
    let target = TargetInfo::from_cargo_env(&cargo_env).expect("target");
    let dsl_root = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n#[lift(in_place)]\n#[path = \"../../src/a.rs\"]\nmod a;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"LAWS.rs\"]\nmod laws;\n\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\n\npub use a::half;\n";
    let laws = "use sandblaster::prelude::*;\nuse crate::a::half;\n\n/// `half` rounds down.\n#[law]\nfn half_rounds_down(x: u64) {\n    ensures(half(x) as Nat == (x as Nat) / 2);\n}\n";
    let proof = "use sandblaster::prelude::*;\n#[allow(unused_imports)]\nuse crate::a::half;\n\n/// By the definition.\n#[proof]\nfn half_rounds_down(x: u64) {\n    follows();\n}\n";
    let files: Vec<(String, String)> = vec![("c/src/lib.rs".into(), "mod a;\n".into()), (A.into(), SAFE.into()), (R.into(), dsl_root.into()), ("c/sandblaster/m/LAWS.rs".into(), laws.into()), ("c/sandblaster/m/PROOF.rs".into(), proof.into())];
    let files = gated::with_accepted_lock(&files, R, &target).expect("every gate but the lock passes");
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let o = driver::build_lifted_with("sandblaster/m/mod.rs", "m", None, &cargo_env, &fs, driver::GateUse::Enforce);
    assert!(!o.ok, "no verdict without the lift conformance check");
    assert!(o.stderr.contains("lift conformance") && o.stderr.contains("lifted in place"), "{}", o.stderr);
    assert!(!o.outputs.iter().any(|(p, c)| p.ends_with("m-verified.txt") && c.contains("VERIFIED +")), "no verified record");
    // the pending build of the same crate: every gate passed, the check
    // ran and failed; still no verdict, and the record says so
    let p = driver::build_lifted_with("sandblaster/m/mod.rs", "m", None, &cargo_env, &fs, driver::GateUse::Pending);
    assert!(p.ok, "{}", p.stderr);
    let record = &p.outputs.iter().find(|(p, _)| p.ends_with("m-pending.txt")).expect("the record").1;
    assert!(record.contains("§15 gate findings (reported, not enforced): 0 (none)") && record.contains("lift conformance: FAILED"), "{record}");
    assert!(!p.outputs.iter().any(|(p, c)| p.ends_with("m-verified.txt") && c.contains("VERIFIED +")), "no verified record");
}
