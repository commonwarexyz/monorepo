//! Primitive semantics (DESIGN.md §5.7) against independent native Rust
//! computations: exhaustive over U8, exhaustive in one argument over U16,
//! boundary values at U64/Usize, and exact Int arithmetic.

mod common;

use num_bigint::BigInt;
use sandblaster_kernel::prim::{LitOut, eval_prim};
use sandblaster_kernel::term::{PrimOp, Width};
use sandblaster_kernel::value::EvalError;

fn int(w: Width, v: u64) -> Option<LitOut> {
    Some(LitOut::Int(w, BigInt::from(v)))
}
fn b(v: bool) -> Option<LitOut> {
    Some(LitOut::Bool(v))
}
fn run(op: PrimOp, args: &[u64]) -> Option<LitOut> {
    let a: Vec<BigInt> = args.iter().map(|x| BigInt::from(*x)).collect();
    eval_prim(op, &a).unwrap()
}

macro_rules! width_tests {
    ($name:ident, $t:ty, $w:expr, $bin_a:expr, $bin_b:expr, $shift_a:expr) => {
        #[test]
        fn $name() {
            use PrimOp::*;
            let w: Width = $w;
            let bits = <$t>::BITS;
            // Unary ops, exhaustive over the sample (full range for U8/U16).
            for a in $shift_a {
                let x = a as $t;
                let a = a as u64;
                assert_eq!(run(WNeg(w), &[a]), int(w, x.wrapping_neg() as u64), "wneg {a}");
                assert_eq!(run(Not(w), &[a]), int(w, (!x) as u64), "not {a}");
                assert_eq!(run(CountOnes(w), &[a]), int(Width::U32, x.count_ones() as u64));
                assert_eq!(run(LeadingZeros(w), &[a]), int(Width::U32, x.leading_zeros() as u64));
                assert_eq!(run(TrailingZeros(w), &[a]), int(Width::U32, x.trailing_zeros() as u64));
                assert_eq!(run(SwapBytes(w), &[a]), int(w, x.swap_bytes() as u64));
                for to in [Width::U8, Width::U16, Width::U32, Width::U64, Width::Usize] {
                    let expect = match to {
                        Width::U8 => x as u8 as u64,
                        Width::U16 => x as u16 as u64,
                        Width::U32 => x as u32 as u64,
                        _ => x as u64,
                    };
                    assert_eq!(run(Cast { from: w, to }, &[a]), int(to, expect), "cast {a}");
                }
                assert_eq!(run(Cast { from: w, to: Width::Int }, &[a]), Some(LitOut::Int(Width::Int, BigInt::from(a))));
                // Shifts and rotations: the amount is taken mod w.
                for s in (0..(2 * bits + 3)).chain([u32::MAX, u32::MAX - 1, 1 << 31]) {
                    let s64 = s as u64;
                    assert_eq!(run(WShl(w), &[a, s64]), int(w, x.wrapping_shl(s) as u64), "wshl {a} {s}");
                    assert_eq!(run(WShr(w), &[a, s64]), int(w, x.wrapping_shr(s) as u64), "wshr {a} {s}");
                    assert_eq!(run(Shl(w), &[a, s64]), int(w, x.wrapping_shl(s) as u64), "shl {a} {s}");
                    assert_eq!(run(Shr(w), &[a, s64]), int(w, x.wrapping_shr(s) as u64), "shr {a} {s}");
                    assert_eq!(run(Rotl(w), &[a, s64]), int(w, x.rotate_left(s) as u64), "rotl {a} {s}");
                    assert_eq!(run(Rotr(w), &[a, s64]), int(w, x.rotate_right(s) as u64), "rotr {a} {s}");
                }
            }
            // Binary ops.
            let check_pair = |a: u64, c: u64| {
                let (x, y) = (a as $t, c as $t);
                assert_eq!(run(WAdd(w), &[a, c]), int(w, x.wrapping_add(y) as u64), "wadd {a} {c}");
                assert_eq!(run(WSub(w), &[a, c]), int(w, x.wrapping_sub(y) as u64), "wsub {a} {c}");
                assert_eq!(run(WMul(w), &[a, c]), int(w, x.wrapping_mul(y) as u64), "wmul {a} {c}");
                assert_eq!(run(And(w), &[a, c]), int(w, (x & y) as u64));
                assert_eq!(run(Or(w), &[a, c]), int(w, (x | y) as u64));
                assert_eq!(run(Xor(w), &[a, c]), int(w, (x ^ y) as u64));
                assert_eq!(run(Min(w), &[a, c]), int(w, x.min(y) as u64));
                assert_eq!(run(Max(w), &[a, c]), int(w, x.max(y) as u64));
                assert_eq!(run(SatAdd(w), &[a, c]), int(w, x.saturating_add(y) as u64), "satadd {a} {c}");
                assert_eq!(run(SatSub(w), &[a, c]), int(w, x.saturating_sub(y) as u64));
                assert_eq!(run(SatMul(w), &[a, c]), int(w, x.saturating_mul(y) as u64), "satmul {a} {c}");
                assert_eq!(run(Eq(w), &[a, c]), b(x == y));
                assert_eq!(run(Ne(w), &[a, c]), b(x != y));
                assert_eq!(run(Lt(w), &[a, c]), b(x < y));
                assert_eq!(run(Le(w), &[a, c]), b(x <= y));
                assert_eq!(run(Gt(w), &[a, c]), b(x > y));
                assert_eq!(run(Ge(w), &[a, c]), b(x >= y));
                // Checked ops compute inside their domain and are stuck outside.
                assert_eq!(run(Add(w), &[a, c]), x.checked_add(y).and_then(|v| int(w, v as u64)), "add {a} {c}");
                assert_eq!(run(Sub(w), &[a, c]), x.checked_sub(y).and_then(|v| int(w, v as u64)), "sub {a} {c}");
                assert_eq!(run(Mul(w), &[a, c]), x.checked_mul(y).and_then(|v| int(w, v as u64)), "mul {a} {c}");
                assert_eq!(run(Div(w), &[a, c]), x.checked_div(y).and_then(|v| int(w, v as u64)), "div {a} {c}");
                assert_eq!(run(Rem(w), &[a, c]), x.checked_rem(y).and_then(|v| int(w, v as u64)), "rem {a} {c}");
            };
            for a in $bin_a {
                for c in $bin_b {
                    check_pair(a as u64, c as u64);
                    check_pair(c as u64, a as u64);
                }
            }
            // Ill-typed literals are stuck, never wrapped.
            let too_big = (<$t>::MAX as u128 + 1) as u64;
            if bits < 64 {
                assert_eq!(run(WAdd(w), &[too_big, 0]), None);
            }
        }
    };
}

fn u16_samples() -> Vec<u16> {
    let mut v = vec![0, 1, 2, 7, 8, 15, 16, 255, 256, 0x7fff, 0x8000, 0xfffe, 0xffff];
    let mut x: u32 = 0x1234_5678;
    for _ in 0..3 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        v.push(x as u16);
    }
    v
}

fn u64_samples() -> Vec<u64> {
    vec![
        0,
        1,
        2,
        3,
        0x7f,
        0x80,
        0xff,
        0x100,
        0xffff,
        0x1_0000,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x1_0000_0000,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        0xffff_ffff_ffff_fffe,
        0xffff_ffff_ffff_ffff,
        0x0123_4567_89ab_cdef,
    ]
}

width_tests!(u8_exhaustive, u8, Width::U8, 0u64..256, 0u64..256, 0u64..256);
width_tests!(u16_one_arg_exhaustive, u16, Width::U16, 0u64..65536, u16_samples(), 0u64..65536);
width_tests!(
    u32_samples,
    u32,
    Width::U32,
    u64_samples().into_iter().map(|x| x as u32),
    u64_samples().into_iter().map(|x| x as u32),
    u64_samples().into_iter().map(|x| x as u32)
);
width_tests!(u64_boundaries, u64, Width::U64, u64_samples(), u64_samples(), u64_samples());
width_tests!(usize_boundaries, u64, Width::Usize, u64_samples(), u64_samples(), u64_samples());

#[test]
fn int_exact_euclidean() {
    use PrimOp::*;
    let vals: Vec<i128> = vec![0, 1, -1, 2, -2, 3, -3, 7, -7, 10, -10, 1 << 70, -(1 << 70), i64::MAX as i128, i64::MIN as i128];
    let bi = |x: i128| BigInt::from(x);
    let r = |op: PrimOp, a: i128, c: i128| eval_prim(op, &[bi(a), bi(c)]).unwrap();
    let i = |x: i128| Some(LitOut::Int(Width::Int, bi(x)));
    for &a in &vals {
        for &c in &vals {
            assert_eq!(r(IAdd, a, c), i(a + c));
            assert_eq!(r(ISub, a, c), i(a - c));
            assert_eq!(r(IMul, a, c), Some(LitOut::Int(Width::Int, bi(a) * bi(c))));
            if c == 0 {
                assert_eq!(r(IDiv, a, c), i(0), "x/0 = 0");
                assert_eq!(r(IMod, a, c), i(a), "x%0 = x");
            } else {
                assert_eq!(r(IDiv, a, c), i(a.div_euclid(c)), "idiv {a} {c}");
                assert_eq!(r(IMod, a, c), i(a.rem_euclid(c)), "imod {a} {c}");
            }
            assert_eq!(r(Lt(Width::Int), a, c), Some(LitOut::Bool(a < c)));
        }
        assert_eq!(eval_prim(INeg, &[bi(a)]).unwrap(), i(-a));
        // of_int / int_to_sat at U8.
        let of = eval_prim(OfInt(Width::U8), &[bi(a)]).unwrap();
        assert_eq!(of, if (0..=255).contains(&a) { Some(LitOut::Int(Width::U8, bi(a))) } else { None });
        let sat = eval_prim(IntToSat(Width::U8), &[bi(a)]).unwrap();
        assert_eq!(sat, Some(LitOut::Int(Width::U8, bi(a.clamp(0, 255)))));
    }
}

#[test]
fn int_implementation_limit_is_an_error() {
    use PrimOp::*;
    let big = BigInt::from(1u8) << 4095u32;
    assert!(eval_prim(IAdd, &[big.clone(), BigInt::from(0)]).unwrap().is_some());
    assert_eq!(eval_prim(IAdd, &[big.clone(), big.clone()]), Err(EvalError::IntOverflow));
    assert_eq!(eval_prim(IMul, &[big.clone(), BigInt::from(2)]), Err(EvalError::IntOverflow));
    let huge = BigInt::from(1u8) << 5000u32;
    assert_eq!(eval_prim(ISub, &[huge, BigInt::from(1)]), Err(EvalError::IntOverflow));
}

#[test]
fn evaluator_agrees_with_prim_table_u8() {
    // Through the full evaluator (terms, values, simplifier) for a few ops.
    let env = sandblaster_kernel::api::Env::new();
    for a in (0u32..256).step_by(7) {
        for c in (0u32..256).step_by(5) {
            let s = format!("#wadd_u8({a}u8, #wmul_u8({c}u8, 3u8))");
            let got = common::norm(&env, &s);
            assert_eq!(got, format!("{}u8", (a as u8).wrapping_add((c as u8).wrapping_mul(3))));
        }
    }
}
