//! The evaluator's performance shortcuts compute exactly what plain
//! unfolding computes (DESIGN.md §5.6): reuse of a successful speculation
//! (tail calls, folded calls as direct constructor fields — and not when a
//! folded call is also referenced elsewhere), direct indexing into a
//! constructor spine, in-place environment extension, and type checking that
//! skips arguments of non-dependent codomains.

mod common;

use common::*;

const SRC: &str = r#"
inductive Tree { | leaf | node(l : Tree, r : Tree) }
def[spec] sum : (acc : U32) -> (l : List(U32)) -> U32 :=
  fun (acc : U32) (l : List(U32)) =>
    match l : List(U32) as _ return U32 with | Nil => acc | Cons(x, t) => rec(#wadd_u32(acc, x), t) end
  structural l
def[spec] dbl : (l : List(U32)) -> List(U32) :=
  fun (l : List(U32)) =>
    match l : List(U32) as _ return List(U32) with | Nil => Nil[U32] | Cons(x, t) => Cons[U32](#wadd_u32(x, x), rec(t)) end
  structural l
def[spec] full : (l : List(U32)) -> Tree :=
  fun (l : List(U32)) =>
    match l : List(U32) as _ return Tree with | Nil => leaf | Cons(x, t) => let r : Tree = rec(t); node(r, r) end
  structural l
def[spec] lop : (l : List(U32)) -> Tree :=
  fun (l : List(U32)) =>
    match l : List(U32) as _ return Tree with | Nil => leaf | Cons(x, t) => let r : Tree = rec(t); node(r, node(r, leaf)) end
  structural l
def[spec] wrap : (l : List(U32)) -> Option(List(U32)) :=
  fun (l : List(U32)) =>
    match l : List(U32) as _ return Option(List(U32)) with
    | Nil => Some[List(U32)](Nil[U32])
    | Cons(x, t) => match rec(t) : Option(List(U32)) as _ return Option(List(U32)) with
        | None => None[List(U32)]
        | Some(r) => Some[List(U32)](Cons[U32](x, r))
        end
    end
  structural l
"#;

fn list(xs: &[u32]) -> String {
    xs.iter().rev().fold("Nil[U32]".to_string(), |acc, x| format!("Cons[U32]({x}u32, {acc})"))
}

#[test]
fn shortcuts_agree_with_unfolding() {
    let mut env = prelude();
    load(&mut env, SRC).unwrap_or_else(|e| panic!("{e}"));
    let l = list(&[1, 2, 3, 4, 5]);
    // Tail recursion.
    assert_eq!(norm(&env, &format!("sum 10u32 ({l})")), "25u32");
    // A folded call as a direct constructor field.
    assert_eq!(norm(&env, &format!("dbl ({l})")), list(&[2, 4, 6, 8, 10]));
    // The same folded call as two direct fields.
    assert_eq!(norm(&env, &format!("full ({})", list(&[1, 2]))), "node(node(leaf, leaf), node(leaf, leaf))");
    // A folded call referenced directly and nested (no reuse: re-evaluation).
    assert_eq!(
        norm(&env, &format!("lop ({})", list(&[1, 2]))),
        "node(node(leaf, node(leaf, leaf)), node(node(leaf, node(leaf, leaf)), leaf))"
    );
    // A folded call under a match: the speculation is stuck at its head on
    // the folded call; the arguments are closed, so the body is evaluated
    // with the real policy (phase-3 refinement of §5.6) and computes.
    assert_eq!(norm(&env, &format!("wrap ({l})")), format!("Some[List(U32)]({l})"));
    // A symbolic tail keeps it folded exactly where unfolding gets stuck.
    let s = norm(&env, "fun (t : List(U32)) => wrap Cons[U32](7u32, t)");
    assert_eq!(s, "fun (t : List(U32)) => wrap Cons[U32](7u32, t)");
    // Symbolic tails stay neutral exactly where unfolding gets stuck.
    let s = norm(&env, "fun (t : List(U32)) => dbl Cons[U32](7u32, t)");
    assert_eq!(s, "fun (t : List(U32)) => Cons[U32](14u32, dbl t)");
    let s = norm(&env, "fun (t : List(U32)) => sum 0u32 Cons[U32](7u32, t)");
    assert_eq!(s, "fun (t : List(U32)) => sum 7u32 t");
    // Direct indexing: in range (including a symbolic tail beyond the index),
    // out of the constructor spine (stays neutral), and a negative index
    // (the definition returns the head).
    assert_eq!(norm(&env, &format!("seq::index U32 ({l}) 3int ._ ._")), "4u32");
    assert_eq!(
        norm(&env, "fun (t : List(U32)) => seq::index U32 Cons[U32](1u32, Cons[U32](2u32, t)) 1int ._ ._"),
        "fun (t : List(U32)) => 2u32"
    );
    let s = norm(&env, "fun (t : List(U32)) => seq::index U32 Cons[U32](1u32, t) 2int ._ ._");
    assert!(s.contains("seq::index"), "{s}");
    assert_eq!(norm(&env, &format!("seq::index U32 ({l}) -2int ._ ._")), "1u32");
}

#[test]
fn checking_does_not_evaluate_non_dependent_arguments() {
    // A definition whose body applies a function to a huge computation: the
    // argument is checked but not evaluated (the codomain does not depend on
    // it), so a small budget suffices to check it; the same budget cannot
    // evaluate it.
    let mut env = prelude();
    load(&mut env, SRC).unwrap();
    load(&mut env, "def[spec] big : (n : Int) -> List(U32) := fun (n : Int) => seq::replicate U32 n 1u32").unwrap();
    let t = tm(&env, "fun (x : U32) => sum x (big 100000int)");
    let mut b = sandblaster_kernel::value::Budget { steps: 20_000 };
    env.infer(&sandblaster_kernel::api::Ctx::default(), &t, &mut b).unwrap_or_else(|e| panic!("{e}"));
    let r = env.eval(
        &Default::default(),
        sandblaster_kernel::term::Lvl(0),
        &tm(&env, "sum 0u32 (big 100000int)"),
        &mut sandblaster_kernel::value::Budget { steps: 20_000 },
    );
    assert!(r.is_err());
    // Dependent codomains still see the argument's value.
    assert!(check(&env, "array::index U32 2usize (pair(Array U32 2usize, Cons[U32](1u32, Cons[U32](2u32, Nil[U32])), refl(Int, 2int))) 1usize .refl(Bool, true)", "U32").is_ok());
    assert!(check(&env, "array::index U32 2usize (pair(Array U32 2usize, Cons[U32](1u32, Cons[U32](2u32, Nil[U32])), refl(Int, 2int))) 2usize .refl(Bool, true)", "U32").is_err());
}
