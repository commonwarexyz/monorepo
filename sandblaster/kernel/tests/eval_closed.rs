//! DESIGN.md §15.7: `Env::eval_closed`, the kernel's closed evaluator for
//! `#[example]`s. It agrees with the front end's reference evaluator (the
//! driver's `Unfolder`, reproduced below from public kernel operations) and
//! with native Rust on non-tail recursion that inspects its own result
//! (path-like), computes where checking-mode conversion keeps opaque
//! definitions folded, completes folded applications, and fails closed: an
//! exhausted budget, an ill-typed or open term and a non-data result are
//! errors, never results.

mod common;

use std::rc::Rc;

use common::*;
use sandblaster_kernel::api::*;
use sandblaster_kernel::term::*;
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::*;

const DEC: &str = "pair(Sigma (_ : Eq(Bool, #le_int(0int, #isub(n, 1int)), true)), Eq(Bool, #lt_int(#isub(n, 1int), n), true), \
                   linarith([c : Eq(Bool, #le_int(n, 0int), false)]; Eq(Bool, #le_int(0int, #isub(n, 1int)), true); []), \
                   linarith([]; Eq(Bool, #lt_int(#isub(n, 1int), n), true); []))";

fn env() -> Env {
    let mut env = prelude();
    let src = format!(
        r#"
-- Non-tail recursion inspecting its own result; opaque, like the
-- elaborator's loop functions (checking-mode conversion never unfolds it).
def[exec, opaque] path : (n : Int) -> List(U8) :=
  fun (n : Int) =>
    if #le_int(n, 0int) as .c return List(U8) then Cons[U8](1u8, Nil[U8]) else
      match rec(#isub(n, 1int); {DEC}) : List(U8) as _ return List(U8) with
      | Nil => Nil[U8]
      | Cons(h, t) => Cons[U8](#wadd_u8(h, 3u8), Cons[U8](h, t))
      end
  measure (n)
-- An intrinsic applied to a function value stays folded in every mode
-- (a λ is not a closed value): only completion computes it.
def[intrinsic] twice : (f : U8 -> U8) -> (x : U8) -> U8 := fun (f : U8 -> U8) (x : U8) => f (f x)
"#
    );
    load(&mut env, &src).unwrap_or_else(|e| panic!("{e}"));
    env
}

/// `path(n)` natively.
fn native_path(n: i64) -> Vec<u8> {
    let mut v = vec![1u8];
    for _ in 0..n.max(0) {
        v.insert(0, v[0].wrapping_add(3));
    }
    v
}

fn list_src(xs: &[u8]) -> String {
    xs.iter().rev().fold("Nil[U8]".to_string(), |acc, x| format!("Cons[U8]({x}u8, {acc})"))
}

/// The front end's reference evaluator (`driver::eval_in` + `Unfolder`),
/// from public kernel operations only.
struct Unfolder<'e> {
    env: &'e Env,
    b: Budget,
}

impl Unfolder<'_> {
    fn eval(&mut self, entries: Vec<EnvEntry>, t: &Tm) -> V {
        self.env.eval_opaque(&VEnv(Rc::new(entries)), Lvl(0), t, &|_| false, &mut self.b).expect("eval")
    }

    fn entry(a: &Arg) -> EnvEntry {
        match a {
            Arg::Rel(v) => EnvEntry::Rel(v.clone()),
            Arg::Irr(c) => EnvEntry::Irr(c.clone()),
        }
    }

    fn force(&mut self, mut v: V) -> V {
        loop {
            let Value::Neu(n) = &*v else { return v };
            let Head::Global { def, args } = &n.head else { return v };
            let body = self.env.global_body(*def).unwrap();
            let arity = self.env.global_arity(*def).unwrap() as usize;
            if args.len() != arity {
                return v;
            }
            let mut inner = body;
            for _ in 0..arity {
                let Term::Lam { body, .. } = &*inner.clone() else { return v };
                inner = body.clone();
            }
            let mut hv = self.eval(args.iter().map(Self::entry).collect(), &inner);
            for e in &n.spine {
                hv = self.force(hv);
                hv = match e {
                    Elim::App(a) => {
                        let rel = if matches!(a, Arg::Rel(_)) { Rel::Rel } else { Rel::Irr };
                        self.eval(vec![EnvEntry::Rel(hv), Self::entry(a)], &mk::apps(mk::var(1), [(rel, mk::var(0))]))
                    }
                    Elim::Fst => self.eval(vec![EnvEntry::Rel(hv)], &mk::fst(mk::var(0))),
                    Elim::Snd => self.eval(vec![EnvEntry::Rel(hv)], &mk::snd(mk::var(0))),
                    Elim::Match { arms, .. } => match &*hv {
                        Value::Ctor { ctor, args: fields, .. } => {
                            let arm = &arms[*ctor as usize];
                            let mut es: Vec<EnvEntry> = (*arm.env.0).clone();
                            es.extend(fields.iter().map(Self::entry));
                            self.eval(es, &arm.body)
                        }
                        _ => panic!("reference evaluator stuck on a match"),
                    },
                };
            }
            v = hv;
        }
    }

    fn deep(&mut self, v: V) -> V {
        let v = self.force(v);
        match &*v {
            Value::Ctor { ind, ctor, params, args } => {
                let args = args
                    .iter()
                    .map(|a| match a {
                        Arg::Rel(x) => Arg::Rel(self.deep(x.clone())),
                        Arg::Irr(c) => Arg::Irr(c.clone()),
                    })
                    .collect();
                Rc::new(Value::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args })
            }
            _ => v,
        }
    }
}

fn reference(env: &Env, src: &str) -> String {
    let t = tm(env, src);
    let v = env.eval_opaque(&VEnv::default(), Lvl(0), &t, &|_| false, &mut budget()).unwrap();
    let mut u = Unfolder { env, b: budget() };
    let v = u.deep(v);
    env.print_term(&[], &env.quote(Lvl(0), &v, false))
}

fn closed(env: &Env, src: &str) -> Result<String, KernelError> {
    env.eval_closed(&tm(env, src), &mut budget()).map(|t| env.print_term(&[], &t))
}

fn printed(env: &Env, src: &str) -> String {
    env.print_term(&[], &tm(env, src))
}

#[test]
fn agrees_with_the_reference_evaluator_and_native_on_path_like_recursion() {
    let env = env();
    for n in [0i64, 1, 2, 5, 12, 40] {
        let src = format!("path {n}int");
        let got = closed(&env, &src).unwrap();
        assert_eq!(got, reference(&env, &src), "n = {n}");
        assert_eq!(got, printed(&env, &list_src(&native_path(n))), "n = {n}");
    }
    // A boolean example over it (what `#[example]` checks).
    assert_eq!(closed(&env, "#eq_int(seq::len U8 (path 30int), 31int)").unwrap(), "true");
    assert_eq!(closed(&env, "#eq_int(seq::len U8 (path 30int), 30int)").unwrap(), "false");
}

#[test]
fn computes_where_checking_mode_conversion_keeps_terms_folded() {
    let env = env();
    // `refl` does not check: `path` is opaque in checking mode.
    let expected = list_src(&native_path(3));
    assert!(check(&env, "refl(List(U8), path 3int)", &format!("Eq(List(U8), path 3int, {expected})")).is_err());
    assert_eq!(closed(&env, "path 3int").unwrap(), printed(&env, &expected));
}

#[test]
fn completes_folded_applications() {
    let env = env();
    let src = "twice (fun (y : U8) => #wadd_u8(y, 5u8)) 1u8";
    // Transparent evaluation leaves the intrinsic folded (a λ argument is
    // not a closed value); completion unfolds it, like the reference.
    let v = env.eval_transparent(&VEnv::default(), Lvl(0), &tm(&env, src), &mut budget()).unwrap();
    assert!(matches!(&*v, Value::Neu(_)));
    assert_eq!(closed(&env, src).unwrap(), "11u8");
    assert_eq!(reference(&env, src), "11u8");
    // Inside data, under an arithmetic primitive and a match.
    let src = "Cons[U8](#wadd_u8(twice (fun (y : U8) => #wadd_u8(y, 5u8)) 1u8, 1u8), Nil[U8])";
    assert_eq!(closed(&env, src).unwrap(), printed(&env, "Cons[U8](12u8, Nil[U8])"));
    let src =
        "match #lt_u8(twice (fun (y : U8) => #wadd_u8(y, 5u8)) 1u8, 20u8) : Bool as _ return U8 with | false => 0u8 | true => 1u8 end";
    assert_eq!(closed(&env, src).unwrap(), "1u8");
}

#[test]
fn fails_closed() {
    let env = env();
    // An exhausted budget is an error, never a (partial) result.
    let e = env.eval_closed(&tm(&env, "path 200int"), &mut Budget { steps: 2_000 }).unwrap_err();
    assert_eq!(e.kind, KernelErrorKind::Eval(EvalError::OutOfFuel), "{e}");
    // Ill-typed, open and erased terms are rejected before evaluation.
    assert!(closed(&env, "#wadd_u8(1u8, true)").is_err());
    assert!(env.eval_closed(&mk::var(0), &mut budget()).is_err());
    assert!(env.eval_closed(&Rc::new(Term::Erased), &mut budget()).is_err());
    // Functions and types are not data.
    assert!(closed(&env, "fun (x : U8) => x").unwrap_err().message.contains("not first-order data"));
    assert!(closed(&env, "U8").is_err());
}
