//! The constants of a loop's closed-form search (optimizer design §7.3,
//! §7.4), **harvested from the loop itself**.
//!
//! The leaf constants and divisors of the enumeration ([`super::synth`]),
//! the guard thresholds and template divisors of [`super::guards`] and the
//! literal corner samples of [`super::traces`] come from the loop under
//! summary, never from a fixed list: a fixed list is a list of somebody's
//! constants, and the summarizer must work alike for every loop (the
//! fairness audit of 2026-10-02 found LEB128's `6`, `7`, `/7`, `128` and
//! `2^14` hard-coded here; a base-32 encoder got no such help). What is
//! fixed is what the **width** gives: `{0, 1, 2, W − 1, W}` and, for the
//! corner samples, `2^k − 1`, `2^k`, `2^k + 1` for every `k ≤ W`.
//!
//! Harvested from the loop's continuing and exit paths (their guards, the
//! next state and the exit values, [`super::classify`]):
//!
//! * every literal `c`, with `c − 1` and `c + 1` (a test `x ≤ c` is
//!   `x < c + 1`);
//! * every literal **shift amount** `k` (of `<<`, `>>` and the `Shift(k)`
//!   recurrence class), with `k − 1` and `2^k`; as thresholds, the
//!   per-iteration boundaries `2^(j·k)` below the width (the values a
//!   digit-at-a-time loop crosses);
//! * every literal divisor;
//! * the literals of the loop's own comparisons (the guard thresholds, with
//!   `c + 1`).
//!
//! The pool only steers which candidates are enumerated and tried: every
//! candidate is still checked on every trace and then by the kernel.

use sandblaster_kernel::term::{PrimOp, Width};

use super::classify::{Class, ContPath, ExitPath, Loop, SVal};
use super::expr::{self, CE, E};

/// The harvested constants of one loop (see the module docs). Each list is
/// deduplicated and in first-seen order (deterministic).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pool {
    /// Every literal of the paths.
    pub literals: Vec<u128>,
    /// Literal shift amounts.
    pub shifts: Vec<u32>,
    /// Literal divisors (`> 1`).
    pub divisors: Vec<u128>,
    /// Literals compared with (`<`, `≤`, `>`, `≥`, `==`, `!=`).
    pub comparisons: Vec<u128>,
}

fn push<T: PartialEq>(v: &mut Vec<T>, x: T) {
    if !v.contains(&x) {
        v.push(x);
    }
}

/// `xs` deduplicated, first occurrence kept.
fn dedup(xs: impl IntoIterator<Item = u128>) -> Vec<u128> {
    let mut out = Vec::new();
    for x in xs {
        push(&mut out, x);
    }
    out
}

impl Pool {
    /// The pool of a classified loop: its paths and its `Shift(k)` classes.
    pub fn harvest(lp: &Loop) -> Pool {
        let mut p = Pool::of_paths(&lp.cont, &lp.exits);
        for c in &lp.classes {
            if let Class::Shift(k) = c {
                push(&mut p.shifts, *k);
            }
        }
        p
    }

    /// The pool of a loop's continuing and exit paths.
    pub fn of_paths(cont: &[ContPath], exits: &[ExitPath]) -> Pool {
        let mut p = Pool::default();
        for c in cont {
            for (g, _) in &c.guards {
                p.expr(g);
            }
            for s in &c.next {
                p.sval(s);
            }
        }
        for e in exits {
            for (g, _) in &e.guards {
                p.expr(g);
            }
            p.sval(&e.value);
        }
        p
    }

    /// The pool of a set of expressions (tests, and loops given by parts).
    pub fn of_exprs(es: &[E]) -> Pool {
        let mut p = Pool::default();
        for e in es {
            p.expr(e);
        }
        p
    }

    fn sval(&mut self, s: &SVal) {
        match s {
            SVal::Ce(e) => self.expr(e),
            SVal::Ctor { args, .. } => args.iter().for_each(|a| self.sval(a)),
            SVal::Ite(c, a, b) => {
                self.expr(c);
                self.sval(a);
                self.sval(b);
            }
            SVal::Param(_) => {}
        }
    }

    fn expr(&mut self, e: &E) {
        let lit = |x: &E| match &**x {
            CE::Lit(_, n) => Some(*n),
            _ => None,
        };
        match &**e {
            CE::Lit(_, n) => push(&mut self.literals, *n),
            CE::Var(..) | CE::J | CE::BoolLit(_) => {}
            CE::Op(op, a) => {
                use PrimOp::*;
                match op {
                    WShl(_) | WShr(_) => {
                        if let Some(k) = a.get(1).and_then(lit).and_then(|k| u32::try_from(k).ok()) {
                            push(&mut self.shifts, k);
                        }
                    }
                    Lt(_) | Le(_) | Gt(_) | Ge(_) | Eq(_) | Ne(_) => {
                        for x in a {
                            if let Some(c) = lit(x) {
                                push(&mut self.comparisons, c);
                            }
                        }
                    }
                    _ => {}
                }
                a.iter().for_each(|x| self.expr(x));
            }
            CE::ShrSat(x, k) | CE::ShlSat(x, k) => {
                if let Some(k) = lit(k).and_then(|k| u32::try_from(k).ok()) {
                    push(&mut self.shifts, k);
                }
                self.expr(x);
                self.expr(k);
            }
            CE::DivLit(x, c) => {
                if *c > 1 {
                    push(&mut self.divisors, *c);
                }
                self.expr(x);
            }
            CE::Ite(c, a, b) => {
                self.expr(c);
                self.expr(a);
                self.expr(b);
            }
        }
    }

    /// The enumeration's leaf constants at width `w`: the width's
    /// `{0, 1, 2, W − 1, W}`, then every literal with its neighbours, then
    /// per shift amount `k`: `k`, `k − 1`, `2^k` (each masked to `w`).
    pub fn leaves(&self, w: Width) -> Vec<u128> {
        let b = expr::bits(w) as u128;
        let m = expr::mask(w);
        let mut v = vec![0, 1, 2, b - 1, b];
        for &c in &self.literals {
            v.push(c);
            v.extend(c.checked_sub(1));
            v.extend(c.checked_add(1));
        }
        for &k in &self.shifts {
            let k = k as u128;
            v.push(k);
            v.extend(k.checked_sub(1));
            if k < 128 {
                v.push(1u128 << k);
            }
        }
        dedup(v.into_iter().filter(|x| *x <= m))
    }

    /// The enumeration's literal divisors: `2`, the shift amounts (a digit
    /// count is a bit count over the digit width) and the literal divisors.
    pub fn divisors(&self) -> Vec<u128> {
        let mut v = vec![2u128];
        v.extend(self.shifts.iter().map(|k| *k as u128));
        v.extend(self.divisors.iter().copied());
        dedup(v.into_iter().filter(|d| *d > 1))
    }

    /// The guard thresholds `c` of `xᵢ < c` at width `w`: the loop's own
    /// comparison literals (and `c + 1`), then the per-iteration boundaries
    /// `2^(j·k)` of each shift amount `k` below the width.
    pub fn thresholds(&self, w: Width) -> Vec<u128> {
        let b = expr::bits(w);
        let m = expr::mask(w);
        let mut v = Vec::new();
        for &c in &self.comparisons {
            v.push(c);
            v.extend(c.checked_add(1));
        }
        for &k in &self.shifts {
            if k == 0 {
                continue;
            }
            let mut e = k;
            while e < b && e < 128 {
                v.push(1u128 << e);
                e += k;
            }
        }
        dedup(v.into_iter().filter(|x| *x > 0 && *x <= m))
    }

    /// Literal corner values for the traces: every literal of the paths with
    /// its neighbours (the samples on both sides of each test).
    pub fn corner_literals(&self) -> Vec<u128> {
        let mut v = Vec::new();
        for &c in self.literals.iter().chain(&self.comparisons) {
            v.extend(c.checked_sub(1));
            v.push(c);
            v.extend(c.checked_add(1));
        }
        dedup(v)
    }
}
