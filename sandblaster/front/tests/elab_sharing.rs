//! A recursion that destructures its own result evaluates its recursive
//! call once (`elab::pat`, `compile_ctor`): `let (a, b) = f(n - 1);` binds
//! the call by a `let` and projects its variable, where projecting the call
//! itself would copy it once per field — and evaluation (the kernel's, the
//! reference evaluator of the lift conformance check) would compute it once
//! per copy, exponentially in the depth (the verifier's
//! `Subtree::reconstruct_digest`, whose state tuple has four fields). A
//! call of another function is projected in place, as before (a constant
//! factor, and the shape the provers and the checked-structuring walker
//! read).

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use sandblaster_front::driver::ProverSet;
use sandblaster_kernel::term::{GlobalId, Tm};
use sandblaster_kernel::value::Budget;

const PROGRAM: &str = r#"
#[requires(n <= 64u32)]
#[decreases(n, max = 64)]
fn walk(n: u32) -> (u32, u32, u32, u32) {
    if n == 0u32 {
        (0u32, 0u32, 0u32, 0u32)
    } else {
        let (a, b, c, d) = walk(n - 1u32);
        (a.wrapping_add(1u32), b, c, d)
    }
}

fn four(x: u32) -> (u32, u32, u32, u32) {
    (x, x, x, x)
}

fn sum_four(x: u32) -> u32 {
    let (a, b, c, d) = four(x);
    a.wrapping_add(b).wrapping_add(c).wrapping_add(d)
}

pub fn walk40() -> u32 {
    walk(40u32).0
}
"#;

/// The number of occurrences of the global `g` in `t` (as a tree: a shared
/// subterm counts once per occurrence).
fn occurrences(env: &sandblaster_kernel::api::Env, t: &Tm, g: GlobalId) -> usize {
    let name = env.global_name(g).unwrap().to_string();
    let printed = env.print_term(&[], t);
    printed.matches(&format!("{name} ")).count() + printed.matches(&format!("{name})")).count()
}

#[test]
fn a_recursion_destructuring_its_result_calls_itself_once() {
    util::with_elab(PROGRAM, ProverSet::Standard, |c, out| {
        let k = c.krate.as_ref().unwrap();
        let g = |p: &str| out.fn_globals[&k.find(p).unwrap()];
        // `walk`'s committed body names itself once: the recursive call is
        // bound once, its four fields are projections of the bound variable
        let walk = g("crate::walk");
        assert_eq!(occurrences(&out.env, &out.env.global_body(walk).unwrap(), walk), 1);
        // and evaluates in time linear in the depth: 40 levels within a
        // budget that one copy per field (4^40 calls) would exhaust at once
        let w40 = g("crate::walk40");
        let mut b = Budget { steps: 5_000_000 };
        let v = out.env.eval_closed(&sandblaster_kernel::util::mk::global(w40), &mut b).expect("walk40 evaluates within the budget");
        assert_eq!(out.env.print_term(&[], &v), "40u32");
        // the twin: a call of another function is projected in place, once
        // per field (the body of `sum_four` names `four` four times)
        let four = g("crate::four");
        assert_eq!(occurrences(&out.env, &out.env.global_body(g("crate::sum_four")).unwrap(), four), 4);
    });
}
