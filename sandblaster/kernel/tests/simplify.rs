//! The §5.7 neutral simplifications: each rule fires on neutral operands and
//! is an identity (the simplified term agrees with the original on every
//! value, checked exhaustively over U8 by instantiating the variable).

mod common;

use std::rc::Rc;

use common::*;
use sandblaster_kernel::api::*;
use sandblaster_kernel::term::*;
use sandblaster_kernel::value::*;

fn neutral_var(l: u32) -> V {
    Rc::new(Value::Neu(Neutral { head: Head::Var(Lvl(l)), spine: vec![] }))
}

/// Evaluate `src` (in scope `x`) under a neutral `x : ty`, check the printed
/// normal form, then check original and simplified agree for all `x` in
/// `values`.
fn rule(env: &Env, ty: &str, src: &str, expect: &str, values: impl Iterator<Item = u64>, suffix: &str) {
    let t = env.parse_term(&["x"], src).unwrap();
    let venv = VEnv(Rc::new(vec![EnvEntry::Rel(neutral_var(0))]));
    let v = env.eval(&venv, Lvl(1), &t, &mut budget()).unwrap();
    let q = env.quote(Lvl(1), &v, false);
    let printed = env.print_term(&[Rc::from("x")], &q);
    assert_eq!(printed, expect, "normal form of `{src}`");
    for k in values {
        let lit = format!("{k}{suffix}");
        let a = norm(env, &format!("let x : {ty} = {lit}; {src}"));
        let b = norm(env, &format!("let x : {ty} = {lit}; {}", printed));
        assert_eq!(a, b, "`{src}` vs `{printed}` at x = {lit}");
    }
}

fn u8s() -> impl Iterator<Item = u64> {
    0..256
}

#[test]
fn additive_identities() {
    let env = Env::new();
    rule(&env, "U8", "#wadd_u8(x, 0u8)", "x", u8s(), "u8");
    rule(&env, "U8", "#wadd_u8(0u8, x)", "x", u8s(), "u8");
    rule(&env, "U8", "#add_u8(x, 0u8; _)", "x", u8s(), "u8");
    rule(&env, "U8", "#wsub_u8(x, 0u8)", "x", u8s(), "u8");
    rule(&env, "U8", "#sub_u8(x, 0u8; _)", "x", u8s(), "u8");
    rule(&env, "U8", "#wmul_u8(x, 1u8)", "x", u8s(), "u8");
    rule(&env, "U8", "#wmul_u8(1u8, x)", "x", u8s(), "u8");
    rule(&env, "U8", "#wmul_u8(x, 0u8)", "0u8", u8s(), "u8");
    rule(&env, "U8", "#mul_u8(0u8, x; _)", "0u8", u8s(), "u8");
    rule(&env, "Int", "#iadd(x, 0int)", "x", 0..50, "int");
    rule(&env, "Int", "#imul(1int, x)", "x", 0..50, "int");
    rule(&env, "Int", "#imul(x, 0int)", "0int", 0..50, "int");
}

#[test]
fn literal_moves_right_and_reassociation() {
    let env = Env::new();
    rule(&env, "U8", "#xor_u8(5u8, x)", "#xor_u8(x, 5u8)", u8s(), "u8");
    rule(&env, "U8", "#wadd_u8(#wadd_u8(x, 200u8), 100u8)", "#wadd_u8(x, 44u8)", u8s(), "u8");
    rule(&env, "U8", "#wadd_u8(#wadd_u8(x, 128u8), 128u8)", "x", u8s(), "u8");
    rule(&env, "U8", "#wadd_u8(3u8, #wadd_u8(x, 4u8))", "#wadd_u8(x, 7u8)", u8s(), "u8");
    // Checked: only when the sum is in range (always the case in domain).
    rule(&env, "U8", "#add_u8(#add_u8(x, 3u8; _), 4u8; _)", "#add_u8(x, 7u8; _)", 0..249, "u8");
    rule(&env, "Int", "#iadd(#iadd(x, 3int), -5int)", "#iadd(x, -2int)", 0..30, "int");
}

#[test]
fn add_then_sub_cancels() {
    let env = Env::new();
    for c in [1u64, 7, 200, 255] {
        rule(&env, "U8", &format!("#wsub_u8(#wadd_u8(x, {c}u8), {c}u8)"), "x", u8s(), "u8");
        // The checked sub is in domain (c ≤ wadd(x, c)) iff no wrap occurred.
        rule(&env, "U8", &format!("#sub_u8(#wadd_u8(x, {c}u8), {c}u8; _)"), "x", 0..(256 - c), "u8");
        // Checked add under wrapping sub: in domain (x + c ≤ 255) only.
        rule(&env, "U8", &format!("#wsub_u8(#add_u8(x, {c}u8; _), {c}u8)"), "x", 0..(256 - c), "u8");
        rule(&env, "U8", &format!("#sub_u8(#add_u8({c}u8, x; _), {c}u8; _)"), "x", 0..(256 - c), "u8");
    }
    rule(&env, "Int", "#isub(#iadd(x, 9int), 9int)", "x", 0..30, "int");
}

#[test]
fn positive_checked_add_comparisons() {
    let env = Env::new();
    // Valid for x + c in domain (x + c ≤ MAX).
    rule(&env, "U8", "#eq_u8(#add_u8(x, 3u8; _), 0u8)", "false", 0..253, "u8");
    rule(&env, "U8", "#eq_u8(0u8, #add_u8(x, 3u8; _))", "false", 0..253, "u8");
    rule(&env, "U8", "#ne_u8(#add_u8(x, 1u8; _), 0u8)", "true", 0..255, "u8");
    rule(&env, "U8", "#lt_u8(0u8, #add_u8(x, 1u8; _))", "true", 0..255, "u8");
    rule(&env, "U8", "#le_u8(1u8, #add_u8(x, 1u8; _))", "true", 0..255, "u8");
    rule(&env, "U8", "#gt_u8(#add_u8(x, 1u8; _), 0u8)", "true", 0..255, "u8");
    // Not for wrapping adds (x + 1 wraps to 0 at 255).
    rule(&env, "U8", "#eq_u8(#wadd_u8(x, 1u8), 0u8)", "#eq_u8(#wadd_u8(x, 1u8), 0u8)", u8s(), "u8");
    // Not with c = 0.
    rule(&env, "U8", "#eq_u8(#add_u8(x, 0u8; _), 0u8)", "#eq_u8(x, 0u8)", u8s(), "u8");
}

#[test]
fn casts() {
    let env = Env::new();
    rule(&env, "U8", "#cast_u32_u64(#cast_u8_u32(x))", "#cast_u8_u64(x)", u8s(), "u8");
    rule(&env, "U8", "#cast_u16_int(#cast_u8_u16(x))", "#cast_u8_int(x)", u8s(), "u8");
    rule(&env, "U8", "#cast_u32_u8(#cast_u8_u32(x))", "x", u8s(), "u8");
    rule(&env, "U8", "#cast_u8_u8(x)", "x", u8s(), "u8");
    rule(&env, "U8", "#of_int_u8(#cast_u8_int(x); _, _)", "x", u8s(), "u8");
    rule(&env, "U8", "#of_int_u32(#cast_u8_int(x); _, _)", "#cast_u8_u32(x)", u8s(), "u8");
    rule(&env, "Int", "#cast_u8_int(#of_int_u8(x; _, _))", "x", 0..256, "int");
    // Narrowing then widening does not collapse.
    rule(&env, "U8", "#cast_u8_u64(#cast_u32_u8(#cast_u8_u32(x)))", "#cast_u8_u64(x)", u8s(), "u8");
    rule(
        &env,
        "U8",
        "#cast_u8_u32(#cast_u16_u8(#wmul_u16(#cast_u8_u16(x), 3u16)))",
        "#cast_u8_u32(#cast_u16_u8(#wmul_u16(#cast_u8_u16(x), 3u16)))",
        u8s(),
        "u8",
    );
}

#[test]
fn byte_rules_and_list_rules() {
    let env = prelude();
    // from_le_bytes(to_le_bytes(x)) = x (conversion under a binder).
    for (w, t) in [("u16", "U16"), ("u32", "U32"), ("u64", "U64")] {
        let lhs = tm(&env, &format!("fun (x : {t}) => {w}::from_le_bytes ({w}::to_le_bytes x)"));
        let rhs = tm(&env, &format!("fun (x : {t}) => x"));
        assert!(env.conv(Lvl(0), &ev(&env, &lhs), &ev(&env, &rhs), &mut budget()).unwrap(), "{w}");
        // to_le_bytes(from_le_bytes(b)) = b for an array variable (array eta).
        let n = match w {
            "u16" => 2,
            "u32" => 4,
            _ => 8,
        };
        let lhs = tm(&env, &format!("fun (b : Array U8 {n}usize) => {w}::to_le_bytes ({w}::from_le_bytes b)"));
        let rhs = tm(&env, &format!("fun (b : Array U8 {n}usize) => b"));
        assert!(env.conv(Lvl(0), &ev(&env, &lhs), &ev(&env, &rhs), &mut budget()).unwrap(), "{w} bytes");
        // from_be = from_le ∘ rev, to_be = rev ∘ to_le round trip.
        let lhs = tm(&env, &format!("fun (x : {t}) => {w}::from_be_bytes ({w}::to_be_bytes x)"));
        let rhs = tm(&env, &format!("fun (x : {t}) => x"));
        assert!(env.conv(Lvl(0), &ev(&env, &lhs), &ev(&env, &rhs), &mut budget()).unwrap(), "{w} be");
    }
    // Closed values compute.
    assert_eq!(norm(&env, "u32::from_le_bytes (u32::to_le_bytes 305419896u32)"), "305419896u32");
    assert_eq!(norm(&env, "u32::from_be_bytes (u32::to_le_bytes 305419896u32)"), "2018915346u32");
    assert_eq!(norm(&env, "u16::from_be_bytes (u16::to_be_bytes 4660u16)"), "4660u16");
    // index(take/drop(l, a), i) → index(l, a + i) for literal offsets: an
    // element read through a sub-slice of an array variable is the variable's
    // element.
    let lhs = tm(
        &env,
        "fun (a : Array U8 8usize) => slice::index U8 (slice::range U8 (array::as_slice U8 8usize a .refl(Bool, true)) 2usize 6usize .refl(Bool, true) .refl(Bool, true)) 1usize .refl(Bool, true)",
    );
    let rhs = tm(&env, "fun (a : Array U8 8usize) => array::index U8 8usize a 3usize .refl(Bool, true)");
    assert!(env.conv(Lvl(0), &ev(&env, &lhs), &ev(&env, &rhs), &mut budget()).unwrap());
}
