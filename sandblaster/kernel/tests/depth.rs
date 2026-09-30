//! Deep evaluation: tail recursion runs in constant Rust stack; deep
//! non-tail recursion fails with `OutOfFuel` (never a stack overflow) under
//! the default stack allowance, and succeeds with a larger allowance.

mod common;

use common::*;
use sandblaster_kernel::term::*;
use sandblaster_kernel::value::*;

#[test]
fn tail_recursion_is_constant_stack() {
    // seq::rev_onto is tail recursive: reversing a 20k-element list
    // built by replicate (non-tail) would overflow; build it with a tail
    // recursive helper instead.
    let mut env = prelude();
    load(
        &mut env,
        r#"
def[spec] build : (n : Int) -> (acc : List(U8)) -> List(U8) :=
  fun (n : Int) (acc : List(U8)) =>
    if #le_int(n, 0int) as .c return List(U8) then acc else
      rec(#isub(n, 1int), Cons[U8](0u8, acc);
        pair(Sigma (_ : Eq(Bool, #le_int(0int, #isub(n, 1int)), true)), Eq(Bool, #lt_int(#isub(n, 1int), n), true),
             linarith([c : Eq(Bool, #le_int(n, 0int), false)]; Eq(Bool, #le_int(0int, #isub(n, 1int)), true); [1, 1]),
             linarith([]; Eq(Bool, #lt_int(#isub(n, 1int), n), true); [1])))
  measure (n)
def[spec] count : (l : List(U8)) -> (acc : Int) -> Int :=
  fun (l : List(U8)) (acc : Int) => match l : List(U8) as _ return Int with | Nil => acc | Cons(h, t) => rec(t, #iadd(acc, 1int)) end
  structural 0
"#,
    )
    .unwrap();
    let t = tm(&env, "count (build 20000int Nil[U8]) 0int");
    let v = env.eval(&VEnv::default(), Lvl(0), &t, &mut Budget { steps: 1 << 40 }).unwrap();
    assert!(matches!(&*v, Value::Lit { n, .. } if *n == 20000.into()));
}

#[test]
fn deep_non_tail_recursion_is_an_error_not_a_crash() {
    let env = prelude();
    let t = tm(&env, "seq::len U8 (seq::replicate U8 100000int 0u8)");
    let r = env.eval(&VEnv::default(), Lvl(0), &t, &mut Budget { steps: 1 << 40 });
    assert_eq!(r.unwrap_err(), EvalError::OutOfFuel);
    // With a larger allowance (on a thread with a larger stack) it succeeds.
    let ok = big_stack(|| {
        let env = prelude();
        let t = tm(&env, "seq::len U8 (seq::replicate U8 20000int 0u8)");
        let v = env.eval(&VEnv::default(), Lvl(0), &t, &mut Budget { steps: 1 << 40 }).unwrap();
        matches!(&*v, Value::Lit { n, .. } if *n == 20000.into())
    });
    assert!(ok);
}
