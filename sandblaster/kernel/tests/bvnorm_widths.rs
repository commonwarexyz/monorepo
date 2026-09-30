//! `bvnorm`: one width per class (DESIGN.md §9.8; `bvnorm/mod.rs` module
//! doc, `Norm::width_clash`).
//!
//! A bound variable's class is its level, whatever its type, so two binders
//! at the same depth (sibling λs, the arms of a match on `Either(U8, U32)`)
//! share one class, and so do the classes built from them (`g 5u32` for two
//! sibling `g`s). `note_width` used to keep the first width it saw: after the
//! `U8` arm, `(y as u16) >> 8` for `y : U32` was normalized as if `y` were a
//! `U8` (support `0xff`), i.e. to `0`, and the tripwire, which masks atom
//! values with the same recorded width, agreed. The kernel accepted closed
//! proofs of `Empty`. Now a class used at two widths rejects the problem.
//!
//! * the closed `Empty` lemmas (sibling λs; match arms, narrowing and
//!   widening; applications of sibling function binders) are rejected by the
//!   kernel with the width message; the control (the `U8` arm not using its
//!   field) is rejected as unequal;
//! * `decide` answers `Different` with the width message (with and without
//!   the tripwire, for both orders of the arms); `classify` and
//!   `tripwire_agrees` fail;
//! * the rejection is narrow: siblings of one width, and siblings of two
//!   widths of which only one is used under a primitive, are still proven by
//!   `decide` and by the kernel; a true equation over fields of two widths is
//!   not decided (the known incompleteness, pinned so it is noticed if it
//!   changes).

mod common;

use std::rc::Rc;

use common::*;
use sandblaster_kernel::api::*;
use sandblaster_kernel::bvnorm::{BvOptions, BvVerdict, classify, decide, tripwire_agrees};
use sandblaster_kernel::term::*;
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::V;

/// A fragment of the width-clash message.
const CLASH: &str = "two machine widths";

/// `def[lemma] name : Empty`: `L : (e : ty) -> Eq(w, lhs, rhs)` by `bvrefl`,
/// instantiated at `arg`, where `lhs` is `1` and `rhs` is `0`.
fn empty_lemma(name: &str, ty: &str, w: &str, lhs: &str, rhs: &str, arg: &str) -> String {
    let lw = w.to_lowercase();
    format!(
        "def[lemma] {name} : Empty :=
  let L : (e : {ty}) -> Eq({w}, {lhs}, {rhs}) =
    fun (e : {ty}) => bvrefl({w}, {lhs}, {rhs});
  bool::false_ne_true
    (transport({w}, 1{lw}, 0{lw}, L ({arg}), y. Eq(Bool, #eq_{lw}(y, 1{lw}), true), refl(Bool, true)))"
    )
}

/// `match e : ty return w` with arms `Left(x) => l` and `Right(y) => r`.
fn either(ty: &str, w: &str, l: &str, r: &str) -> String {
    format!("match e : {ty} as _ return {w} with | Left(x) => {l} | Right(y) => {r} end")
}

const E81: &str = "Either(U8, U32)";
const XOR8: &str = "#cast_u8_u16(#xor_u8(x, 90u8))";
const HI16: &str = "#wshr_u16(#cast_u32_u16(y), 8u32)";
/// Equal to [`HI16`] for every `y : U32`.
const HI16_ALT: &str = "#and_u16(#cast_u32_u16(#wshr_u32(y, 8u32)), 255u16)";

/// `(name, ty, w, lhs, rhs, arg)`: false equations that the pre-fix
/// normalizer and tripwire accepted.
fn booms() -> Vec<(&'static str, String, &'static str, String, String, String)> {
    let lam = |b: &str| format!("e (fun (x : U8) => #xor_u8(x, 90u8)) (fun (y : U32) => {b})");
    let apps = "Either(U32 -> U8, U32 -> U32)";
    vec![
        (
            "boom_lambdas",
            "(U8 -> U8) -> (U32 -> U16) -> U16".into(),
            "U16",
            lam(HI16),
            lam("0u16"),
            "fun (g : U8 -> U8) (h : U32 -> U16) => h 256u32".into(),
        ),
        (
            "boom_either",
            E81.into(),
            "U16",
            either(E81, "U16", XOR8, HI16),
            either(E81, "U16", XOR8, "0u16"),
            "Right[U8, U32](256u32)".into(),
        ),
        (
            "boom_widen",
            E81.into(),
            "U64",
            either(E81, "U64", "#cast_u8_u64(#xor_u8(x, 90u8))", "#wshr_u64(#cast_u32_u64(y), 8u32)"),
            either(E81, "U64", "#cast_u8_u64(#xor_u8(x, 90u8))", "0u64"),
            "Right[U8, U32](256u32)".into(),
        ),
        (
            "boom_apps",
            apps.into(),
            "U16",
            either(apps, "U16", "#cast_u8_u16(x 5u32)", "#wshr_u16(#cast_u32_u16(y 5u32), 8u32)"),
            either(apps, "U16", "#cast_u8_u16(x 5u32)", "0u16"),
            "Right[U32 -> U8, U32 -> U32](fun (z : U32) => 256u32)".into(),
        ),
    ]
}

#[test]
fn closed_proofs_of_empty_are_rejected() {
    for (name, ty, w, lhs, rhs, arg) in booms() {
        let mut env = prelude();
        let r = load(&mut env, &empty_lemma(name, &ty, w, &lhs, &rhs, &arg));
        let e = r.expect_err(&format!("UNSOUND: {name} (a closed proof of Empty) accepted"));
        assert!(e.to_string().contains(CLASH), "{name}: rejected for another reason: {e}");
    }
    // Control: the `U8` arm does not use its field, so `y`'s class is only
    // ever a `U32` and the false equation is rejected as unequal.
    let mut env = prelude();
    let src = empty_lemma(
        "control",
        E81,
        "U16",
        &either(E81, "U16", "7u16", HI16),
        &either(E81, "U16", "7u16", "0u16"),
        "Right[U8, U32](256u32)",
    );
    let e = load(&mut env, &src).expect_err("UNSOUND: control accepted");
    assert!(e.to_string().contains("normal forms differ"), "control: {e}");
}

/// A context with one variable `e : ty`.
fn ctx1(env: &Env, ty: &str) -> Ctx {
    let t = env.parse_term(&[], ty).unwrap();
    let tv = env.eval(&env.ctx_venv(&Ctx::default()), Lvl(0), &t, &mut budget()).unwrap();
    Ctx::default().push(CtxEntry { name: "e".into(), rel: Rel::Rel, ty: tv, def: None })
}

fn terms(env: &Env, lhs: &str, rhs: &str) -> (Tm, Tm) {
    (env.parse_term(&["e"], lhs).unwrap(), env.parse_term(&["e"], rhs).unwrap())
}

fn verdict(env: &Env, ctx: &Ctx, l: &Tm, r: &Tm, tripwire: bool) -> BvVerdict {
    decide(env, ctx, l, r, BvOptions { tripwire }, &mut budget()).unwrap()
}

fn is_clash(v: &BvVerdict) -> bool {
    matches!(v, BvVerdict::Different(m) if m.contains(CLASH))
}

/// The kernel's `bvrefl` on `l == r` at width `w` in `ctx`.
fn kernel(env: &Env, ctx: &Ctx, w: Width, l: &Tm, r: &Tm) -> Result<V, KernelError> {
    let t = Rc::new(Term::BvRefl { ty: mk::int_ty(w), lhs: l.clone(), rhs: r.clone() });
    env.infer(ctx, &t, &mut budget())
}

#[test]
fn every_entry_point_rejects_a_width_clash() {
    let env = prelude();
    let mut cases: Vec<(String, String, String)> =
        booms().into_iter().filter(|b| b.0 != "boom_lambdas").map(|(_, ty, _, l, r, _)| (ty, l, r)).collect();
    // The other order of the arms: the wide field first, the narrow one second.
    let e18 = "Either(U32, U8)";
    let xor8 = "#cast_u8_u16(#xor_u8(y, 90u8))";
    let hi16 = "#wshr_u16(#cast_u32_u16(x), 8u32)";
    cases.push((e18.into(), either(e18, "U16", hi16, xor8), either(e18, "U16", "0u16", xor8)));
    // (a true equation, `(y as u16) >> 8 == 0` for `y : U8`: still not decided)
    cases.push((
        e18.into(),
        either(e18, "U16", "#cast_u32_u16(x)", "#wshr_u16(#cast_u8_u16(y), 8u32)"),
        either(e18, "U16", "#cast_u32_u16(x)", "0u16"),
    ));
    for (ty, lhs, rhs) in &cases {
        let ctx = ctx1(&env, ty);
        let (l, r) = terms(&env, lhs, rhs);
        for tw in [false, true] {
            let v = verdict(&env, &ctx, &l, &r, tw);
            assert!(is_clash(&v), "{lhs} == {rhs} (tripwire {tw}): {v:?}");
        }
        let c = classify(&env, &ctx, &[l.clone(), r.clone()], &mut budget());
        assert!(c.as_ref().is_err_and(|e| e.message.contains(CLASH)), "classify: {c:?}");
        let t = tripwire_agrees(&env, &ctx, &l, &r, &mut budget());
        assert!(t.as_ref().is_err_and(|e| e.message.contains(CLASH)), "tripwire_agrees: {t:?}");
        let w = if lhs.contains("return U64") { Width::U64 } else { Width::U16 };
        let k = kernel(&env, &ctx, w, &l, &r);
        assert!(k.as_ref().is_err_and(|e| e.message.contains(CLASH)), "kernel: {lhs} == {rhs}: {k:?}");
    }
}

#[test]
fn the_rejection_is_narrow() {
    let env = prelude();
    // Siblings of one width; siblings of two widths with only one used under
    // a primitive: true equations, still proven.
    let e32 = "Either(U32, U32)";
    let hi_x = HI16.replace('y', "x");
    let alt_x = HI16_ALT.replace('y', "x");
    let proven = [
        (e32, either(e32, "U16", &hi_x, HI16), either(e32, "U16", &alt_x, HI16_ALT)),
        (E81, either(E81, "U16", "7u16", HI16), either(E81, "U16", "7u16", HI16_ALT)),
    ];
    for (ty, lhs, rhs) in &proven {
        let ctx = ctx1(&env, ty);
        let (l, r) = terms(&env, lhs, rhs);
        assert_eq!(verdict(&env, &ctx, &l, &r, true), BvVerdict::Equal, "{lhs} == {rhs}");
        kernel(&env, &ctx, Width::U16, &l, &r).unwrap_or_else(|e| panic!("kernel rejects {lhs} == {rhs}: {e}"));
    }
    // A true equation over fields of two widths: not decided.
    let ctx = ctx1(&env, E81);
    let (l, r) = terms(&env, &either(E81, "U16", XOR8, HI16), &either(E81, "U16", XOR8, HI16_ALT));
    let v = verdict(&env, &ctx, &l, &r, true);
    assert!(is_clash(&v), "the known incompleteness changed: {v:?}");
}
