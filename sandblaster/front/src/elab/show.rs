//! Size-bounded printing of kernel values for diagnostics.
//!
//! Failure reports (unproven obligations, `auto` failures, `show()`) used to
//! quote every fact and goal back to a term and print it. Quoting a value
//! re-instantiates every irrelevant closure (proofs) by substitution and
//! treats shared value graphs as trees, so reporting a failure on a goal
//! whose facts are large symbolic computations (a whole verifier unfolded
//! into a hypothesis) could take longer than the proof search itself.
//! [`value`] walks the value graph directly, never instantiates closures,
//! and stops after a fixed number of characters. The output is core-text
//! flavoured but not re-parsable: it is for humans only.

use std::fmt::Write;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{Name, PrimOp, Width};
use sandblaster_kernel::value::{Arg, Elim, Head, Neutral, V, Value};

/// Prints `v` (a value at depth `names.len()`) in at most about `max`
/// characters.
pub fn value(env: &Env, names: &[Name], v: &V, max: usize) -> String {
    let mut p = P { env, names, out: String::new(), max };
    p.v(v, 0);
    if p.out.len() > max {
        let mut cut = max;
        while !p.out.is_char_boundary(cut) {
            cut -= 1;
        }
        p.out.truncate(cut);
        p.out.push('…');
    }
    p.out
}

struct P<'a> {
    env: &'a Env,
    names: &'a [Name],
    out: String,
    max: usize,
}

fn prim_name(op: PrimOp) -> String {
    let s = format!("{op:?}");
    // `Add(U32)` → `add_u32`
    match s.split_once('(') {
        Some((a, b)) => format!("{}_{}", a.to_lowercase(), b.trim_end_matches(')').to_lowercase()),
        None => s.to_lowercase(),
    }
}

fn width_suffix(w: Width) -> &'static str {
    match w {
        Width::U8 => "u8",
        Width::U16 => "u16",
        Width::U32 => "u32",
        Width::U64 => "u64",
        Width::Usize => "usize",
        Width::Int => "int",
    }
}

impl P<'_> {
    fn full(&self) -> bool {
        self.out.len() > self.max
    }

    fn s(&mut self, s: &str) {
        self.out.push_str(s);
    }

    fn arg(&mut self, a: &Arg, d: u32) {
        match a {
            Arg::Rel(v) => self.v(v, d),
            Arg::Irr(_) => self.s("_"),
        }
    }

    fn list(&mut self, vs: &[V], d: u32) {
        for (i, x) in vs.iter().enumerate() {
            if i > 0 {
                self.s(", ");
            }
            if self.full() {
                self.s("…");
                return;
            }
            self.v(x, d);
        }
    }

    fn v(&mut self, v: &V, d: u32) {
        if self.full() {
            self.s("…");
            return;
        }
        if d > 40 {
            self.s("…");
            return;
        }
        match &**v {
            Value::Sort(s) => {
                let _ = write!(self.out, "{s:?}");
            }
            Value::IntTy(w) => {
                let _ = write!(self.out, "{w:?}");
            }
            Value::Lit { w, n } => {
                let _ = write!(self.out, "{n}{}", width_suffix(*w));
            }
            Value::Pi { name, dom, .. } => {
                let _ = write!(self.out, "({name} : ");
                self.v(dom, d + 1);
                self.s(") -> …");
            }
            Value::Lam { name, .. } => {
                let _ = write!(self.out, "fun {name} => …");
            }
            Value::Sigma { name, fst, .. } => {
                let _ = write!(self.out, "Sigma ({name} : ");
                self.v(fst, d + 1);
                self.s("), …");
            }
            Value::Pair { fst, snd } => {
                self.s("pair(");
                self.v(fst, d + 1);
                self.s(", ");
                self.arg(snd, d + 1);
                self.s(")");
            }
            Value::Eq { ty, lhs, rhs } => {
                self.s("Eq(");
                self.v(ty, d + 1);
                self.s(", ");
                self.v(lhs, d + 1);
                self.s(", ");
                self.v(rhs, d + 1);
                self.s(")");
            }
            Value::Refl { val, .. } => {
                self.s("refl(");
                self.v(val, d + 1);
                self.s(")");
            }
            Value::Ind { ind, params } => {
                let name = self.env.inductive_decl(*ind).map(|x| x.name.to_string()).unwrap_or_else(|| format!("ind{}", ind.0));
                self.s(&name);
                if !params.is_empty() {
                    self.s("(");
                    self.list(params, d + 1);
                    self.s(")");
                }
            }
            Value::Ctor { ind, ctor, args, .. } => {
                let decl = self.env.inductive_decl(*ind);
                let name = decl.as_ref().and_then(|x| x.ctors.get(*ctor as usize)).map(|c| c.name.to_string()).unwrap_or_else(|| format!("c{ctor}"));
                if *ind == self.env.bool_ind() {
                    self.s(if *ctor == 1 { "true" } else { "false" });
                    return;
                }
                self.s(&name);
                if !args.is_empty() {
                    self.s("(");
                    for (i, a) in args.iter().enumerate() {
                        if i > 0 {
                            self.s(", ");
                        }
                        if self.full() {
                            self.s("…");
                            break;
                        }
                        self.arg(a, d + 1);
                    }
                    self.s(")");
                }
            }
            Value::Neu(n) => self.neu(n, d),
        }
    }

    fn neu(&mut self, n: &Neutral, d: u32) {
        // eliminators wrap the head from the inside out
        let mut prefix = String::new();
        for e in n.spine.iter().rev() {
            match e {
                Elim::Match { .. } => prefix.push_str("match "),
                Elim::Fst => prefix.push_str("fst("),
                Elim::Snd => prefix.push_str("snd("),
                Elim::App(_) => {}
            }
        }
        self.s(&prefix);
        match &n.head {
            Head::Var(l) => {
                let name = self.names.get(l.0 as usize).map(|x| x.to_string()).unwrap_or_else(|| format!("#{}", l.0));
                self.s(&name);
            }
            Head::Global { def, args } => {
                let name = self.env.global_name(*def).map(|x| x.to_string()).unwrap_or_else(|| format!("g{}", def.0));
                self.s(&name);
                for a in args {
                    if self.full() {
                        break;
                    }
                    match a {
                        Arg::Rel(v) => {
                            self.s(" ");
                            let atomic = matches!(&**v, Value::Lit { .. } | Value::Sort(_) | Value::IntTy(_)) || matches!(&**v, Value::Neu(Neutral { head: Head::Var(_), spine }) if spine.is_empty());
                            if !atomic {
                                self.s("(");
                            }
                            self.v(v, d + 1);
                            if !atomic {
                                self.s(")");
                            }
                        }
                        Arg::Irr(_) => self.s(" _"),
                    }
                }
            }
            Head::Prim { op, args, .. } => {
                let _ = write!(self.out, "#{}(", prim_name(*op));
                self.list(args, d + 1);
                self.s(")");
            }
            Head::Absurd { .. } => self.s("absurd(…)"),
            Head::Transport { val, .. } => {
                self.s("transport(…, ");
                self.v(val, d + 1);
                self.s(")");
            }
            Head::Axiom { ax, .. } => {
                let _ = write!(self.out, "axiom{ax:?}(…)");
            }
        }
        for e in &n.spine {
            if self.full() {
                self.s("…");
                return;
            }
            match e {
                Elim::App(a) => {
                    self.s(" ");
                    match a {
                        Arg::Rel(v) => {
                            self.s("(");
                            self.v(v, d + 1);
                            self.s(")");
                        }
                        Arg::Irr(_) => self.s("_"),
                    }
                }
                Elim::Fst | Elim::Snd => self.s(")"),
                Elim::Match { arms, .. } => {
                    let _ = write!(self.out, " with {} arms", arms.len());
                }
            }
        }
    }
}
