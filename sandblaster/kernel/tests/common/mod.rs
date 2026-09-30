//! Shared helpers for the kernel tests: environments, parsing/evaluation
//! shortcuts, and a small reference linear-arithmetic certificate search
//! (Fourier–Motzkin with exact integer multipliers; tests only — the kernel
//! only *checks* certificates).
#![allow(dead_code)]

use std::rc::Rc;

use num_bigint::BigInt;
use num_traits::{One, Signed, Zero};
use sandblaster_kernel::api::*;
use sandblaster_kernel::linarith::{ConstraintKind, LinSystem};
use sandblaster_kernel::term::*;
use sandblaster_kernel::value::*;

pub fn budget() -> Budget {
    Budget { steps: 50_000_000 }
}

thread_local! {
    static PRELUDE: Rc<()> = Rc::new(());
}

/// A fresh environment with the prelude.
pub fn prelude() -> Env {
    Env::with_prelude()
}

/// Parse a closed term.
pub fn tm(env: &Env, src: &str) -> Tm {
    env.parse_term(&[], src).unwrap_or_else(|e| panic!("parse `{src}`: {e}"))
}

/// Evaluate a closed term.
pub fn ev(env: &Env, t: &Tm) -> V {
    env.eval(&VEnv::default(), Lvl(0), t, &mut budget()).expect("eval")
}

/// Evaluate and print a closed term.
pub fn norm(env: &Env, src: &str) -> String {
    let v = ev(env, &tm(env, src));
    let q = env.quote(Lvl(0), &v, false);
    env.print_term(&[], &q)
}

/// Infer the type of a closed term.
pub fn infer(env: &Env, src: &str) -> Result<V, KernelError> {
    env.infer(&Ctx::default(), &tm(env, src), &mut budget())
}

/// Check a closed term against a closed type.
pub fn check(env: &Env, t: &str, ty: &str) -> Result<(), KernelError> {
    let tyv = ev(env, &tm(env, ty));
    env.check(&Ctx::default(), &tm(env, t), &tyv, &mut budget())
}

/// Load core text into `env`.
pub fn load(env: &mut Env, src: &str) -> Result<Vec<Name>, KernelError> {
    env.load_core(src, &mut budget())
}

/// Run `f` on a thread with a large stack (deep symbolic executions).
pub fn big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(512 << 20)
        .spawn(move || {
            sandblaster_kernel::util::set_stack_limit(448 << 20);
            f()
        })
        .unwrap()
        .join()
        .unwrap()
}

/// Find a certificate for every problem of `sys` (Fourier–Motzkin). Returns
/// `None` if some problem is feasible over the rationals.
pub fn find_cert(sys: &LinSystem) -> Option<Vec<Rat>> {
    let mut out = Vec::new();
    for p in &sys.problems {
        out.extend(fm_problem(p, sys.atoms.len())?);
    }
    Some(out)
}

#[derive(Clone)]
struct Row {
    coeffs: Vec<BigInt>,
    constant: BigInt,
    /// Multipliers over the original constraints (for `=` constraints, the
    /// signed multiplier).
    mult: Vec<BigInt>,
}

fn fm_problem(p: &[sandblaster_kernel::linarith::Constraint], natoms: usize) -> Option<Vec<Rat>> {
    let n = p.len();
    let mut rows = Vec::new();
    for (i, c) in p.iter().enumerate() {
        let mut coeffs = vec![BigInt::zero(); natoms];
        for (a, k) in &c.coeffs {
            coeffs[*a] += k;
        }
        let mut mult = vec![BigInt::zero(); n];
        mult[i] = BigInt::one();
        rows.push(Row { coeffs: coeffs.clone(), constant: c.constant.clone(), mult: mult.clone() });
        if c.kind == ConstraintKind::Eq0 {
            let mut m2 = vec![BigInt::zero(); n];
            m2[i] = -BigInt::one();
            rows.push(Row { coeffs: coeffs.iter().map(|x| -x).collect(), constant: -c.constant.clone(), mult: m2 });
        }
    }
    for a in 0..natoms {
        if let Some(r) = rows.iter().find(|r| r.coeffs.iter().all(|x| x.is_zero()) && r.constant.is_positive()) {
            return Some(to_rats(&r.mult));
        }
        let (pos, rest): (Vec<Row>, Vec<Row>) = rows.into_iter().partition(|r| r.coeffs[a].is_positive());
        let (neg, zero): (Vec<Row>, Vec<Row>) = rest.into_iter().partition(|r| r.coeffs[a].is_negative());
        let mut next = zero;
        for pr in &pos {
            for nr in &neg {
                let (kp, kn) = (pr.coeffs[a].clone(), -nr.coeffs[a].clone());
                let comb = |x: &BigInt, y: &BigInt| x * &kn + y * &kp;
                next.push(Row {
                    coeffs: pr.coeffs.iter().zip(&nr.coeffs).map(|(x, y)| comb(x, y)).collect(),
                    constant: comb(&pr.constant, &nr.constant),
                    mult: pr.mult.iter().zip(&nr.mult).map(|(x, y)| comb(x, y)).collect(),
                });
            }
        }
        if next.len() > 20_000 {
            return None;
        }
        rows = next;
    }
    rows.iter().find(|r| r.constant.is_positive()).map(|r| to_rats(&r.mult))
}

fn to_rats(m: &[BigInt]) -> Vec<Rat> {
    m.iter().map(|x| Rat { num: x.clone(), den: BigInt::one() }).collect()
}

/// Build `linarith(hyps; goal; cert)` in a context, searching the
/// certificate with [`find_cert`].
pub fn auto_linarith(env: &Env, ctx: &Ctx, hyps: Vec<(Tm, Tm)>, goal: Tm) -> Option<Tm> {
    let sys = env.linearize(ctx, &hyps, &goal, &mut budget()).ok()?;
    let cert = find_cert(&sys)?;
    Some(Rc::new(Term::Linarith { hyps, goal, cert }))
}

/// Print a rational certificate as core text.
pub fn cert_text(c: &[Rat]) -> String {
    c.iter().map(|r| if r.den.is_one() { r.num.to_string() } else { format!("{}/{}", r.num, r.den) }).collect::<Vec<_>>().join(", ")
}
