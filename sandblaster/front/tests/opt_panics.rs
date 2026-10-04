//! Panic-preserving optimization of exec-only code (DESIGN.md §8.2 item 12,
//! `opt::panics`): a function whose arithmetic, division or indexing no
//! precondition makes safe is `Unproven` in the exec-only path, and the
//! optimizer works on its **panic-explicit reading** `f__panics : Option<R>`
//! (`None` the panic outcome). Each test is a small program, checked for the
//! reading the optimizer builds, its kernel-checked residual (an equality
//! over `Option<R>`: it covers the panic outcome) and the reading's values,
//! evaluated by the kernel, against the source's panics; with must-reject
//! twins for what is not read (a panic inside a loop, an assertion).
//!
//! `cargo test -p sandblaster-front --test opt_panics`

use std::path::Path;

use sandblaster_front::driver::{self, Checked};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::{self, Link, OptOptions, Optimized, Outcome};
use sandblaster_front::target::TargetInfo;
use sandblaster_kernel::term::{Rel, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Budget, Value};

const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

fn check_src(src: &str) -> Checked {
    let fs = MemFs::from_files([("r/mod.rs", src)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    c
}

/// Elaborates exec-only (unproven obligations allowed) and optimizes `src`;
/// `f` gets `(output, optimized)` and runs on the big stack.
fn with_optimized<R: Send>(src: &str, f: impl FnOnce(&mut elab::Output, &Optimized) -> R + Send) -> R {
    let c = check_src(src);
    let k = c.krate.as_ref().unwrap().clone();
    elab::with_big_stack(move || {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(&k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let o = opt::optimize(&mut out, &k, &OptOptions::default());
        f(&mut out, &o)
    })
}

fn reading_of<'a>(o: &'a Optimized, source: &str) -> &'a opt::panics::PanicReading {
    o.panics.iter().find(|r| o.print.item(r.source).path.to_string() == source).unwrap_or_else(|| panic!("no reading entry for {source}: {:?}", o.panics))
}

fn report<'a>(o: &'a Optimized, name: &str) -> &'a opt::FnReport {
    o.fns.iter().find(|f| f.name == name && f.set.is_none()).unwrap_or_else(|| panic!("no report for {name}"))
}

/// The kernel's value of `g` applied to the `u32`/`u8` literals `args`:
/// `None` (the panic outcome) or `Some(n)`.
fn eval(out: &elab::Output, g: &str, args: &[(Width, u64)]) -> Option<u64> {
    let gid = out.env.lookup_global(g).unwrap_or_else(|| panic!("no global {g}"));
    let t = mk::apps(mk::global(gid), args.iter().map(|(w, n)| (Rel::Rel, mk::lit(*w, *n))).collect::<Vec<_>>());
    let v = out.env.eval(&Default::default(), sandblaster_kernel::term::Lvl(0), &t, &mut Budget { steps: 10_000_000 }).expect("evaluation");
    match &*v {
        Value::Ctor { ctor: 0, .. } => None,
        Value::Ctor { ctor: 1, args, .. } => match args.first() {
            Some(sandblaster_kernel::value::Arg::Rel(x)) => match &**x {
                Value::Lit { n, .. } => Some(n.to_string().parse::<u64>().unwrap()),
                other => panic!("not a literal: {other:?}"),
            },
            _ => panic!("a `Some` without its value"),
        },
        other => panic!("not an `Option`: {other:?}"),
    }
}

/// `a / b` and `q + 1` can panic and nothing rules them out: the function
/// is optimized through its reading, whose residual is linked to it by a
/// kernel-checked equality lemma over `Option<u32>` (driven: it branches).
#[test]
fn a_function_that_can_panic_gets_a_panic_explicit_reading() {
    let src = format!(
        "{HEADER}
pub fn ceil_div(a: u32, b: u32) -> u32 {{
    let q = a / b;
    if a % b != 0 {{ q + 1 }} else {{ q }}
}}
"
    );
    with_optimized(&src, |out, o| {
        let r = reading_of(o, "crate::ceil_div");
        assert!(r.item.is_some(), "no reading: {}", r.note);
        assert_eq!(o.print.item(r.item.unwrap()).path.to_string(), "crate::ceil_div__panics");
        // the source: not kernel-checked, its reading optimized in its place (not an optimizer failure)
        let f = report(o, "crate::ceil_div");
        assert!(matches!(&f.outcome, Outcome::Unspecialized { reason, failure: false } if reason.contains("panic-explicit reading")), "{:?}", f.outcome);
        // the reading: specialized, its link an equality lemma over `Option<u32>`
        let p = report(o, "crate::ceil_div__panics");
        assert!(matches!(p.outcome, Outcome::Specialized { .. }), "{:?}", p.outcome);
        let Some(Link::Lemma(l)) = &p.link else { panic!("link {:?}", p.link) };
        let ty = out.env.global_type(out.env.lookup_global(l).unwrap()).unwrap();
        let shown = out.env.print_term(&[], &ty);
        assert!(shown.contains("Eq(Option(U32)"), "{shown}");
        assert!(o.warnings.is_empty() && o.errors.is_empty(), "{:?} {:?}", o.warnings, o.errors);
    });
}

/// The reading returns `None` exactly where the source panics: evaluated by
/// the kernel, `b == 0` and an overflowing increment are `None`, every
/// other input the source's value; and so does the residual.
#[test]
fn the_reading_is_none_exactly_where_the_source_panics() {
    let src = format!(
        "{HEADER}
pub fn ceil_div(a: u32, b: u32) -> u32 {{
    let q = a / b;
    if a % b != 0 {{ q + 1 }} else {{ q }}
}}

pub fn inc(x: u8) -> u8 {{
    x + 1
}}
"
    );
    with_optimized(&src, |out, o| {
        let u = Width::U32;
        let res = |name: &str| match &report(o, name).outcome {
            Outcome::Specialized { residual, .. } => out.env.global_name(*residual).unwrap().to_string(),
            other => panic!("{name}: {other:?}"),
        };
        for g in ["crate::ceil_div__panics".to_string(), res("crate::ceil_div__panics")] {
            assert_eq!(eval(out, &g, &[(u, 7), (u, 0)]), None, "{g}: 7 / 0 panics");
            assert_eq!(eval(out, &g, &[(u, 7), (u, 2)]), Some(4), "{g}");
            assert_eq!(eval(out, &g, &[(u, 6), (u, 2)]), Some(3), "{g}");
            assert_eq!(eval(out, &g, &[(u, u32::MAX as u64), (u, 1)]), Some(u32::MAX as u64), "{g}");
        }
        for g in ["crate::inc__panics".to_string(), res("crate::inc__panics")] {
            assert_eq!(eval(out, &g, &[(Width::U8, 255)]), None, "{g}: 255 + 1 overflows");
            assert_eq!(eval(out, &g, &[(Width::U8, 3)]), Some(4), "{g}");
        }
    });
}

/// A callee that can panic has a reading, and so does its caller (blocked
/// by it): the caller's reading calls the callee's under `?`, so the
/// callee's panic is the caller's.
#[test]
fn a_callers_reading_propagates_its_callees_panic() {
    let src = format!(
        "{HEADER}
fn inc(x: u8) -> u8 {{
    x + 1
}}

pub fn inc_twice(x: u8) -> u8 {{
    inc(inc(x))
}}
"
    );
    with_optimized(&src, |out, o| {
        let r = reading_of(o, "crate::inc_twice");
        assert!(r.item.is_some(), "no reading: {}", r.note);
        assert_eq!(eval(out, "crate::inc_twice__panics", &[(Width::U8, 253)]), Some(255));
        assert_eq!(eval(out, "crate::inc_twice__panics", &[(Width::U8, 254)]), None);
        assert_eq!(eval(out, "crate::inc_twice__panics", &[(Width::U8, 255)]), None);
    });
}

/// Must-reject twins: what the reading does not read leaves the function
/// without one, with the reason. A panic inside a loop (the loop is read
/// as written, its overflow still an obligation), an assertion (an
/// `unreachable!()` the prover does not refute: in MIR a `debug_assert!` is
/// an `assert!`, absent from release builds), and a function with nothing
/// it could panic at.
#[test]
fn what_the_reading_does_not_read_is_reported() {
    let src = format!(
        "{HEADER}
pub fn sum_to(n: u32) -> u32 {{
    let mut i = 0u32;
    let mut acc = 0u32;
    while i < n {{
        proof! {{ decreases(n - i); }}
        acc = acc + i;
        i = i + 1;
    }}
    acc
}}

pub fn checked_inv(x: u32) -> u32 {{
    if x == 0 {{ unreachable!() }} else {{ 1000 / x }}
}}
"
    );
    with_optimized(&src, |_out, o| {
        let r = reading_of(o, "crate::sum_to");
        assert!(r.item.is_none(), "a reading of a loop's panic");
        assert!(r.note.contains("unproven"), "{}", r.note);
        let r = reading_of(o, "crate::checked_inv");
        assert!(r.item.is_none(), "a reading of an assertion");
        assert!(r.note.contains("Unreachable"), "{}", r.note);
        // the functions without a reading are the source as written (no
        // optimizer failure: exec-only code that is not verified)
        assert!(o.fns.iter().all(|f| !f.name.contains("__panics") || f.name.starts_with("crate::nothing")));
    });
}
