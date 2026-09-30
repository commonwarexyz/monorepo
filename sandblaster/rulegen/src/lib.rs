//! Rulegen v0: offline rule discovery for the optimizer's aegraph
//! (optimizer design §10.5; plan O8).
//!
//! **What it does.** For each rule *template* it enumerates candidate
//! identities `Π x̄. Eq(τ, lhs x̄, rhs x̄)` over its parameters (widths,
//! accumulator types), **filters** them by evaluating both sides in the
//! kernel's reference evaluator on corner and pseudo-random inputs (a
//! candidate that disagrees anywhere is dropped: the templates include
//! deliberately wrong controls, which the filter must drop), **proves**
//! the survivors (a generated proof script whose `linarith` certificates are
//! found by `auto`'s simplex), and **checks** each proof by loading it into
//! a fresh kernel environment. The survivors are written as core text:
//!
//! * `sandblaster/front/lemmas/rules/bitsum.core`: the bit-sum idiom
//!   `Σ_{i<w} ((x >> i) & 1) = count_ones(x)` (corpus P3, the design's
//!   `count_ones_sum`) for every source width and accumulator type, stated
//!   in the form a straight-line residual has (a left-nested wrapping sum
//!   starting at bit 0). The aegraph matches these rules modulo `bvnorm`,
//!   so a different summation order or grouping matches too;
//! * `sandblaster/front/lemmas/cong.core`: the `cong_irr` congruence
//!   lemmas the aegraph's explanations use to rewrite an operand of a
//!   checked operation, whose proof slot mentions that operand.
//!
//! **Trust.** None: the build never runs rulegen. It loads the files and the
//! kernel checks every lemma again on every build that uses them
//! (`opt::egraph::rules::ensure`); a wrong rule cannot be loaded.

use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{Lvl, Rel, Tm, Width};
use sandblaster_kernel::value::{Arg, Budget, VEnv, Value};

/// A generated lemma: its name and core text (certificates filled in).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub text: String,
}

/// A width's names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wd {
    pub w: Width,
    /// `u64`
    pub s: &'static str,
    /// `U64`
    pub t: &'static str,
    pub bits: u32,
}

pub fn wd(w: Width) -> Wd {
    let (s, t) = match w {
        Width::U8 => ("u8", "U8"),
        Width::U16 => ("u16", "U16"),
        Width::U32 => ("u32", "U32"),
        Width::U64 => ("u64", "U64"),
        Width::Usize => ("usize", "Usize"),
        Width::Int => panic!("no Int instance"),
    };
    Wd { w, s, t, bits: w.bits().unwrap_or(0) }
}

pub const WIDTHS: [Width; 5] = [Width::U8, Width::U16, Width::U32, Width::U64, Width::Usize];

impl Wd {
    pub fn max(self) -> u128 {
        (1u128 << self.bits) - 1
    }
    pub fn lit(self, v: u128) -> String {
        format!("{v}{}", self.s)
    }
}

/// A `linarith` whose certificate is filled in by [`certify`].
#[derive(Clone, Debug)]
struct Hole {
    /// Binders in scope (a prefix of the proof's binders).
    scope: usize,
    hyps: Vec<(String, String)>,
    goal: String,
}

/// A binder of a generated proof: a parameter, or a `let` (relevant values
/// carry their definition, facts do not need it).
#[derive(Clone, Debug)]
struct Binder {
    name: String,
    irr: bool,
    ty: String,
    /// `Some(value)` for a `let`.
    val: Option<String>,
}

/// A proof under construction: parameters, then a chain of `let`s, then a
/// final term.
#[derive(Clone, Debug, Default)]
struct Proof {
    binders: Vec<Binder>,
    params: usize,
    holes: Vec<Hole>,
}

fn marker(i: usize) -> String {
    format!("@@CERT{i}@@")
}

impl Proof {
    fn param(&mut self, name: &str, ty: &str) {
        let irr = name.starts_with('.');
        self.binders.push(Binder { name: name.trim_start_matches('.').to_string(), irr, ty: ty.to_string(), val: None });
        self.params += 1;
    }
    fn let_val(&mut self, name: &str, ty: &str, val: &str) {
        self.binders.push(Binder { name: name.to_string(), irr: false, ty: ty.to_string(), val: Some(val.to_string()) });
    }
    fn let_fact(&mut self, name: &str, ty: &str, val: &str) {
        self.binders.push(Binder { name: name.to_string(), irr: true, ty: ty.to_string(), val: Some(val.to_string()) });
    }
    /// A proof bound relevantly (usable as a hypothesis of a `linarith` in
    /// a relevant position).
    fn let_proof(&mut self, name: &str, ty: &str, val: &str) {
        self.binders.push(Binder { name: name.to_string(), irr: false, ty: ty.to_string(), val: Some(val.to_string()) });
    }
    /// `linarith(hyps; goal; <certificate>)` in the current scope.
    fn lin(&mut self, hyps: Vec<(String, String)>, goal: &str) -> String {
        let i = self.holes.len();
        let text = hyps.iter().map(|(p, s)| format!("{p} : {s}")).collect::<Vec<_>>().join(", ");
        self.holes.push(Hole { scope: self.binders.len(), hyps, goal: goal.to_string() });
        format!("linarith([{text}]; {goal}; {})", marker(i))
    }
    /// The lemma text (uncertified).
    fn text(&self, name: &str, goal: &str, body: &str, comment: &str) -> String {
        let ps = &self.binders[..self.params];
        let pis: String = ps.iter().map(|b| format!("({}{} : {}) -> ", if b.irr { "." } else { "" }, b.name, b.ty)).collect();
        let lams: String = ps.iter().map(|b| format!("({}{} : {})", if b.irr { "." } else { "" }, b.name, b.ty)).collect::<Vec<_>>().join(" ");
        let mut t = String::new();
        for l in comment.lines() {
            t.push_str(&format!("-- {l}\n"));
        }
        t.push_str(&format!("def[lemma] {name} : {pis}{goal} :=\n  fun {lams} =>\n"));
        for b in &self.binders[self.params..] {
            t.push_str(&format!("    let {}{} : {} = {};\n", if b.irr { "." } else { "" }, b.name, b.ty, b.val.as_deref().unwrap_or("")));
        }
        t.push_str(&format!("    {body}\n"));
        t
    }
}

/// Fills in every hole's certificate (found by `auto`'s simplex over the
/// kernel's own linearization of the hole).
fn certify(env: &Env, p: &Proof, text: &str, b: &mut Budget) -> Result<String, String> {
    let mut certs: Vec<String> = Vec::new();
    let fill = |s: &str, certs: &[String]| {
        let mut s = s.to_string();
        for (i, c) in certs.iter().enumerate() {
            s = s.replace(&marker(i), c);
        }
        s
    };
    // the context of every binder, built once
    let mut ctxs: Vec<Ctx> = vec![Ctx::default()];
    let mut names: Vec<String> = Vec::new();
    for bd in &p.binders {
        let ctx = ctxs.last().unwrap().clone();
        let ns: Vec<&str> = names.iter().map(|n| n.as_str()).collect();
        let tyt = env.parse_term(&ns, &bd.ty).map_err(|e| format!("`{}`: {e}", bd.ty))?;
        let venv = env.ctx_venv(&ctx);
        let tyv = env.eval(&venv, ctx.depth(), &tyt, b).map_err(|e| format!("{e:?}"))?;
        let def = match (&bd.val, bd.irr) {
            (Some(v), false) => {
                let vt = env.parse_term(&ns, v).map_err(|e| format!("`{v}`: {e}"))?;
                Some(Arg::Rel(env.eval(&venv, ctx.depth(), &vt, b).map_err(|e| format!("{e:?}"))?))
            }
            _ => None,
        };
        let rel = if bd.irr { Rel::Irr } else { Rel::Rel };
        ctxs.push(ctx.push(CtxEntry { name: Rc::from(bd.name.as_str()), rel, ty: tyv, def }));
        names.push(bd.name.clone());
    }
    for h in &p.holes {
        let ctx = &ctxs[h.scope];
        let ns: Vec<&str> = names[..h.scope].iter().map(|n| n.as_str()).collect();
        let parse = |src: &str| env.parse_term(&ns, &fill(src, &certs)).map_err(|e| format!("`{src}`: {e}"));
        let mut hyps = Vec::new();
        for (pf, st) in &h.hyps {
            hyps.push((parse(pf)?, parse(st)?));
        }
        let goal = parse(&h.goal)?;
        let sys = env.linearize(ctx, &hyps, &goal, b).map_err(|e| format!("{e}"))?;
        let cert = match sandblaster_front::auto::simplex::certificate(&sys) {
            Some(c) => format!(
                "[{}]",
                c.iter().map(|r| if r.den == num_bigint::BigInt::from(1) { r.num.to_string() } else { format!("{}/{}", r.num, r.den) }).collect::<Vec<_>>().join(", ")
            ),
            None => return Err(format!("no certificate for `{}`", h.goal)),
        };
        certs.push(cert);
    }
    Ok(fill(text, &certs))
}

// ---------------------------------------------------------------- bit sums

/// A bit-sum template instance: source width `w`, accumulator `acc`, and
/// which bits it sums (`0..w` is the idiom; the controls sum `1..w` or add
/// one bit twice).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitSum {
    pub w: Width,
    pub acc: Width,
    pub variant: BitSumVariant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitSumVariant {
    /// `Σ_{i<w} bit_i` (the idiom).
    All,
    /// Control: bit 0 dropped (the P3 must-reject variant).
    DropFirst,
    /// Control: bit `w−1` counted twice.
    LastTwice,
}

impl BitSum {
    pub fn name(&self) -> String {
        let (w, a) = (wd(self.w), wd(self.acc));
        format!("rules::count_ones_sum_{}_{}", w.s, a.s)
    }

    fn bits(&self) -> Vec<u32> {
        let n = wd(self.w).bits;
        match self.variant {
            BitSumVariant::All => (0..n).collect(),
            BitSumVariant::DropFirst => (1..n).collect(),
            BitSumVariant::LastTwice => (0..n).chain([n - 1]).collect(),
        }
    }

    /// Bit `i` of `x` in the source width.
    fn src_bit(&self, x: &str, i: u32) -> String {
        let w = wd(self.w);
        format!("#and_{s}(#wshr_{s}({x}, {i}u32), {one})", s = w.s, one = w.lit(1))
    }

    /// Bit `i` in the accumulator's type (a cast when the widths differ).
    fn acc_bit(&self, x: &str, i: u32) -> String {
        let (w, a) = (wd(self.w), wd(self.acc));
        if self.w == self.acc { self.src_bit(x, i) } else { format!("#cast_{}_{}({})", w.s, a.s, self.src_bit(x, i)) }
    }

    /// The left side: `wadd(… wadd(bit_0, bit_1) …, bit_{w−1})`.
    pub fn lhs(&self, x: &str) -> String {
        let a = wd(self.acc);
        let bits = self.bits();
        let mut s = self.acc_bit(x, bits[0]);
        for &i in &bits[1..] {
            s = format!("#wadd_{}({s}, {})", a.s, self.acc_bit(x, i));
        }
        s
    }

    /// The right side: `count_ones(x)` in the accumulator's type.
    pub fn rhs(&self, x: &str) -> String {
        let w = wd(self.w);
        let c = format!("#count_ones_{}({x})", w.s);
        if self.acc == Width::U32 { c } else { format!("#cast_u32_{}({c})", wd(self.acc).s) }
    }

    /// The statement's type `Eq(Acc, lhs, rhs)`.
    pub fn statement(&self, x: &str) -> String {
        format!("Eq({}, {}, {})", wd(self.acc).t, self.lhs(x), self.rhs(x))
    }

    /// The proof (see [`bitsum_rule`]): the summands `b_k` and partial sums
    /// `s_k` as `let`s; per step the helper lemmas `bs_bit` (`b_k ≤ 1`),
    /// `bs_step` (the wrapping add is exact in `Int`) and `bs_bound`
    /// (`s_{k+1} ≤ k + 1`); then one `linarith` with K1's `count_ones_def`.
    fn proof(&self) -> (Proof, String) {
        let (w, a) = (wd(self.w), wd(self.acc));
        let mut p = Proof::default();
        p.param("x", w.t);
        let bits = self.bits();
        let n = bits.len();
        for (k, &i) in bits.iter().enumerate() {
            p.let_val(&format!("b{k}"), a.t, &self.acc_bit("x", i));
        }
        p.let_val("s1", a.t, "b0");
        for k in 1..n {
            p.let_val(&format!("s{}", k + 1), a.t, &format!("#wadd_{}(s{k}, b{k})", a.s));
        }
        let le = |lhs: &str, k: usize| format!("Eq(Bool, #le_{}({lhs}, {}), true)", a.s, a.lit(k as u128));
        for (k, &i) in bits.iter().enumerate() {
            p.let_fact(&format!("l{k}"), &le(&format!("b{k}"), 1), &format!("{} (#wshr_{}(x, {i}u32))", bs_bit_name(self.w, self.acc), w.s));
        }
        p.let_fact("u1", &le("s1", 1), "l0");
        let mut hy: Vec<(String, String)> = Vec::new();
        for k in 1..n {
            let est = format!("Eq(Int, #cast_{s}_int(s{k1}), #iadd(#cast_{s}_int(s{k}), #cast_{s}_int(b{k})))", s = a.s, k1 = k + 1);
            let args = format!("s{k} b{k} {} .u{k} .l{k} .refl(Bool, true)", a.lit(k as u128));
            p.let_proof(&format!("e{k}"), &est, &format!("rules::bs_step_{} {args}", a.s));
            hy.push((format!("e{k}"), est));
            p.let_fact(&format!("u{}", k + 1), &le(&format!("s{}", k + 1), k + 1), &format!("rules::bs_bound_{} {args}", a.s));
        }
        // a narrowed summand widens back to the bit (BvRefl: the bit is at
        // most 1, so the truncation is exact)
        if a.bits < w.bits {
            for (k, &i) in bits.iter().enumerate() {
                let st = format!("Eq({}, #cast_{}_{}(b{k}), {})", w.t, a.s, w.s, self.src_bit("x", i));
                p.let_proof(&format!("f{k}"), &st, &format!("bvrefl({}, #cast_{}_{}(b{k}), {})", w.t, a.s, w.s, self.src_bit("x", i)));
                hy.push((format!("f{k}"), st));
            }
        }
        hy.push((format!("axiom[count_ones_def_{s}](x)", s = w.s), format!("Eq(Int, #cast_u32_int(#count_ones_{s}(x)), bits::cnt_sum_{s} (x))", s = w.s)));
        if a.bits < 32 {
            let st = format!("Eq(U32, #cast_{}_u32({}), #count_ones_{}(x))", a.s, self.rhs("x"), w.s);
            hy.push((format!("bvrefl(U32, #cast_{}_u32({}), #count_ones_{}(x))", a.s, self.rhs("x"), w.s), st));
        }
        let goal = format!("Eq({}, s{n}, {})", a.t, self.rhs("x"));
        let body = p.lin(hy, &goal);
        (p, body)
    }
}

/// `rules::bs_bit_<w>_<acc>`.
pub fn bs_bit_name(w: Width, acc: Width) -> String {
    format!("rules::bs_bit_{}_{}", wd(w).s, wd(acc).s)
}

/// `rules::bs_bit_<w>_<acc> : (y : W) → (y & 1) as Acc ≤ 1` (the summand
/// of bit `i` is its instance at `y = x >> i`).
fn bs_bit_rule(env: &mut Env, w: Width, acc: Width) -> Result<Rule, String> {
    let (d, a) = (wd(w), wd(acc));
    let bit = format!("#and_{s}(y, {one})", s = d.s, one = d.lit(1));
    let abit = if w == acc { bit.clone() } else { format!("#cast_{}_{}({bit})", d.s, a.s) };
    let goal = format!("Eq(Bool, #le_{}({abit}, {}), true)", a.s, a.lit(1));
    let mut p = Proof::default();
    p.param("y", d.t);
    let hy = if a.bits < d.bits { vec![(format!("bvrefl({}, #cast_{}_{}({abit}), {bit})", d.t, a.s, d.s), format!("Eq({}, #cast_{}_{}({abit}), {bit})", d.t, a.s, d.s))] } else { vec![] };
    let body = p.lin(hy, &goal);
    finish(env, &p, &bs_bit_name(w, acc), &goal, &body, &format!("A bit of a {} word, as a {} summand, is at most 1.", d.s, a.s))
}

/// `rules::bs_step_<a>` and `rules::bs_bound_<a>`: for `s ≤ k < MAX` and
/// `b ≤ 1`, `wadd(s, b)` is `s + b` in `Int` and is at most `k + 1`.
fn bs_step_rules(env: &mut Env, acc: Width) -> Result<Vec<Rule>, String> {
    let a = wd(acc);
    let hyps = [
        (".hs", format!("Eq(Bool, #le_{}(s, k), true)", a.s)),
        (".hb", format!("Eq(Bool, #le_{}(b, {}), true)", a.s, a.lit(1))),
        (".hk", format!("Eq(Bool, #lt_{}(k, {}), true)", a.s, a.lit(a.max()))),
    ];
    let mut out = Vec::new();
    for bound in [false, true] {
        let mut p = Proof::default();
        for v in ["s", "b", "k"] {
            p.param(v, a.t);
        }
        for (n, t) in &hyps {
            p.param(n, t);
        }
        let hyp = |n: &str| (n.trim_start_matches('.').to_string(), hyps.iter().find(|(m, _)| m == &n).unwrap().1.clone());
        let hgoal = format!("Eq(Bool, #le_int(#iadd(#cast_{s}_int(s), #cast_{s}_int(b)), {m}int), true)", s = a.s, m = a.max());
        let hv = p.lin(vec![hyp(".hs"), hyp(".hb"), hyp(".hk")], &hgoal);
        p.let_fact("h", &hgoal, &hv);
        let exact = (format!("bits::wadd_exact_{} s b .h", a.s), format!("Eq({}, #wadd_{}(s, b), #add_{}(s, b; h))", a.t, a.s, a.s));
        let (name, goal, hy, what) = if bound {
            let kgoal = format!("Eq(Bool, #le_int(#iadd(#cast_{s}_int(k), #cast_{s}_int({one})), {m}int), true)", s = a.s, one = a.lit(1), m = a.max());
            let kv = p.lin(vec![hyp(".hk")], &kgoal);
            p.let_fact("h2", &kgoal, &kv);
            let kexact = (format!("bits::wadd_exact_{} k {} .h2", a.s, a.lit(1)), format!("Eq({}, #wadd_{}(k, {one}), #add_{}(k, {one}; h2))", a.t, a.s, a.s, one = a.lit(1)));
            (
                format!("rules::bs_bound_{}", a.s),
                format!("Eq(Bool, #le_{}(#wadd_{}(s, b), #wadd_{}(k, {})), true)", a.s, a.s, a.s, a.lit(1)),
                vec![exact, kexact, relevant(&hyp(".hs")), relevant(&hyp(".hb"))],
                "the partial sum after the step is at most k + 1",
            )
        } else {
            (format!("rules::bs_step_{}", a.s), format!("Eq(Int, #cast_{s}_int(#wadd_{s}(s, b)), #iadd(#cast_{s}_int(s), #cast_{s}_int(b)))", s = a.s), vec![exact], "the wrapping add of a bit to a partial sum is exact")
        };
        let body = p.lin(hy, &goal);
        out.push(finish(env, &p, &name, &goal, &body, &format!("Bit sums in {}: {what} (s ≤ k < MAX, b ≤ 1).", a.s))?);
    }
    Ok(out)
}

/// A relevant proof of `Eq(Bool, B, true)` from an irrelevant one `h`
/// (usable as a hypothesis of a `linarith` in a relevant position): `h`
/// moves into the irrelevant equation of a transport.
fn relevant(h: &(String, String)) -> (String, String) {
    let b = h.1.trim_start_matches("Eq(Bool, ").trim_end_matches(", true)");
    (format!("transport(Bool, true, {b}, eq::sym Bool {b} true {}, y. Eq(Bool, y, true), refl(Bool, true))", h.0), h.1.clone())
}

/// Certifies, checks (loads) and returns a generated lemma.
fn finish(env: &mut Env, p: &Proof, name: &str, goal: &str, body: &str, comment: &str) -> Result<Rule, String> {
    let text = p.text(name, goal, body, comment);
    let mut b = Budget { steps: 4_000_000_000 };
    let text = certify(env, p, &text, &mut b).map_err(|e| format!("{name}: {e}"))?;
    env.load_core(&text, &mut b).map_err(|e| format!("{name}: the kernel rejected the generated proof: {e}"))?;
    Ok(Rule { name: name.to_string(), text })
}

/// The instances of the bit-sum template rulegen v0 enumerates: every
/// source width with the `u32` accumulator (`count_ones`'s own type) and
/// with its own width; and two wrong controls per source width.
pub fn bitsum_candidates() -> Vec<BitSum> {
    let mut v = Vec::new();
    for w in WIDTHS {
        let accs = vec![Width::U32, w];
        let mut seen = Vec::new();
        for acc in accs {
            if seen.contains(&acc) {
                continue;
            }
            seen.push(acc);
            v.push(BitSum { w, acc, variant: BitSumVariant::All });
        }
        v.push(BitSum { w, acc: Width::U32, variant: BitSumVariant::DropFirst });
        v.push(BitSum { w, acc: Width::U32, variant: BitSumVariant::LastTwice });
    }
    v
}

/// Test inputs of a width: corners (0, 1, all ones, the top bit, alternating
/// patterns, every single bit) and pseudo-random values (a fixed xorshift
/// seed: deterministic).
pub fn test_inputs(w: Width) -> Vec<u128> {
    let d = wd(w);
    let mut v: Vec<u128> = vec![0, 1, d.max(), 1 << (d.bits - 1), d.max() / 3, (d.max() / 3) << 1];
    v.extend((0..d.bits).map(|i| 1u128 << i));
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..64 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        v.push(u128::from(s) & d.max());
    }
    v
}

/// Evaluates a closed term (core text) in the kernel's reference evaluator:
/// `Some(value)` for an integer literal result.
fn eval_lit(env: &Env, src: &str) -> Result<Option<String>, String> {
    let t: Tm = env.parse_term(&[], src).map_err(|e| format!("`{src}`: {e}"))?;
    let mut b = Budget { steps: 10_000_000 };
    let v = env.eval(&VEnv::default(), Lvl(0), &t, &mut b).map_err(|e| format!("{e:?}"))?;
    Ok(match &*v {
        Value::Lit { n, .. } => Some(n.to_string()),
        _ => None,
    })
}

/// The filter: both sides agree on every test input.
pub fn agrees(env: &Env, c: &BitSum) -> Result<bool, String> {
    for x in test_inputs(c.w) {
        let lit = wd(c.w).lit(x);
        let l = eval_lit(env, &c.lhs(&lit))?;
        let r = eval_lit(env, &c.rhs(&lit))?;
        if l.is_none() || l != r {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The proven rule of a candidate (certified, then checked by loading it
/// into `env`).
pub fn bitsum_rule(env: &mut Env, c: &BitSum) -> Result<Rule, String> {
    let (p, body) = c.proof();
    let (w, a) = (wd(c.w), wd(c.acc));
    let comment = format!("Σ_{{i<{}}} ((x >> i) & 1) = count_ones(x), x : {}, summed in {} (bit 0 first, left-nested).", w.bits, w.s, a.s);
    finish(env, &p, &c.name(), &c.statement("x"), &body, &comment)
}

// ---------------------------------------------------------------- cong_irr

/// The checked operations whose proof slot mentions an operand, and the
/// operands it mentions: rewriting such an operand inside the operation
/// needs a congruence lemma that moves the proof along (`cong_irr`).
pub const CONG_OPS: &[(&str, &[usize])] = &[("add", &[0, 1]), ("sub", &[0, 1]), ("mul", &[0, 1]), ("div", &[1]), ("rem", &[1]), ("shl", &[1]), ("shr", &[1])];

/// The proof slot's proposition of `#<op>_<w>(a, b; _)`.
pub fn obligation(op: &str, d: Wd, a: &str, b: &str) -> String {
    match op {
        "add" => format!("Eq(Bool, #le_int(#iadd(#cast_{s}_int({a}), #cast_{s}_int({b})), {m}int), true)", s = d.s, m = d.max()),
        "mul" => format!("Eq(Bool, #le_int(#imul(#cast_{s}_int({a}), #cast_{s}_int({b})), {m}int), true)", s = d.s, m = d.max()),
        "sub" => format!("Eq(Bool, #le_{}({b}, {a}), true)", d.s),
        "div" | "rem" => format!("Eq(Bool, #ne_{}({b}, {}), true)", d.s, d.lit(0)),
        _ => format!("Eq(Bool, #lt_u32({b}, {}u32), true)", d.bits),
    }
}

/// `cong::<op>_<l|r>_<w>`: `(a b a2 : W) (.e : a = a2) (.p : P(a, b))
/// (.p2 : P(a2, b)) → op(a, b; p) = op(a2, b; p2)` (left operand; the right
/// one alike), by transport of `e` into a function of the new proof.
pub fn cong_rule(op: &str, side: usize, w: Width) -> Rule {
    let d = wd(w);
    let (bt, name) = if (op == "shl" || op == "shr") && side == 1 { ("U32", format!("cong::{op}_r_{}", d.s)) } else { (d.t, format!("cong::{op}_{}_{}", if side == 0 { "l" } else { "r" }, d.s)) };
    let (ta, tb) = if side == 0 { (d.t, bt) } else { (d.t, bt) };
    // the rewritten operand is `y` (was `a` on the left, `b` on the right)
    let (old, new, other) = ("y", "y2", "z");
    let args = |v: &str| if side == 0 { (v.to_string(), other.to_string()) } else { (other.to_string(), v.to_string()) };
    let (a0, b0) = args(old);
    let (a1, b1) = args(new);
    let yt = if side == 0 { ta } else { tb };
    let zt = if side == 0 { tb } else { ta };
    let p0 = obligation(op, d, &a0, &b0);
    let p1 = obligation(op, d, &a1, &b1);
    let (am, bm) = args("m");
    let pm = obligation(op, d, &am, &bm);
    let stmt = format!("Eq({t}, #{op}_{s}({a0}, {b0}; p), #{op}_{s}({a1}, {b1}; p2))", t = d.t, s = d.s);
    let text = format!(
        "-- Rewrite the {which} operand of a checked `{op}` (its proof moves along).\n\
def[lemma] {name} : ({old} : {yt}) -> ({new} : {yt}) -> ({other} : {zt}) -> (.e : Eq({yt}, {old}, {new})) -> (.p : {p0}) -> (.p2 : {p1}) -> {stmt} :=\n  \
fun ({old} : {yt}) ({new} : {yt}) ({other} : {zt}) (.e : Eq({yt}, {old}, {new})) (.p : {p0}) (.p2 : {p1}) =>\n    \
(transport({yt}, {old}, {new}, e, m. (.q : {pm}) -> Eq({t}, #{op}_{s}({a0}, {b0}; p), #{op}_{s}({am}, {bm}; q)), fun (.q : {p0}) => refl({t}, #{op}_{s}({a0}, {b0}; p)))) .p2\n",
        which = if side == 0 { "left" } else { "right" },
        t = d.t,
        s = d.s
    );
    Rule { name, text }
}

/// Every `cong_irr` lemma.
pub fn cong_rules() -> Vec<Rule> {
    let mut v = Vec::new();
    for w in WIDTHS {
        for (op, sides) in CONG_OPS {
            for &side in *sides {
                v.push(cong_rule(op, side, w));
            }
        }
    }
    v
}

// ---------------------------------------------------------------- files

pub const BITSUM_HEADER: &str = "\
-- sandblaster rule library: bit-sum idioms (optimizer design §10.1, §10.5; plan O8).
--
-- GENERATED by `sandblaster-rulegen` (sandblaster/rulegen, offline); do
-- not edit. Regenerate with `cargo run -p sandblaster-rulegen --release`;
-- `cargo test -p sandblaster-rulegen` fails when this file is stale.
--
-- Checked, untrusted: rulegen enumerated the template's instances, dropped
-- the ones that disagree on corner and random inputs (the wrong controls:
-- bit 0 dropped, the top bit counted twice), and proved the rest from the
-- kernel's K1 definition `count_ones_def` with BvRefl and linarith (the
-- certificates were found by `auto`'s simplex). The optimizer loads this
-- file when its aegraph first needs a rule, and the kernel checks every
-- lemma again then (`opt::egraph::rules::ensure`).
";

pub const CONG_HEADER: &str = "\
-- sandblaster lemma library: congruence under irrelevant proof slots
-- (`cong_irr`, optimizer design §10.1; plan O8).
--
-- GENERATED by `sandblaster-rulegen`; do not edit (see lemmas/rules/bitsum.core).
--
-- A checked operation's proof slot states a fact about its operands, so an
-- aegraph explanation cannot abstract an operand of `op(a, b; p)` in a
-- transport motive (the proof `p` would no longer have its type). These
-- lemmas rewrite the whole operation instead: from `a = a2` and a proof for
-- the new operands, `op(a, b; p) = op(a2, b; p2)`.
";

/// The generated files: `(path relative to sandblaster/front, text)`.
/// Needs an environment with the prelude and the lemma library (`bits.core`
/// for `wadd_exact`, `cnt_sum`).
pub fn generate(env: &mut Env, log: &mut dyn FnMut(String)) -> Result<Vec<(String, String)>, String> {
    let mut bitsum = String::from(BITSUM_HEADER);
    let cands = bitsum_candidates();
    let mut accs: Vec<Width> = Vec::new();
    for c in cands.iter().filter(|c| c.variant == BitSumVariant::All) {
        if !accs.contains(&c.acc) {
            accs.push(c.acc);
        }
    }
    accs.sort_by_key(|w| WIDTHS.iter().position(|x| x == w));
    for acc in &accs {
        for r in bs_step_rules(env, *acc)? {
            bitsum.push('\n');
            bitsum.push_str(&r.text);
        }
    }
    for c in cands.iter().filter(|c| c.variant == BitSumVariant::All) {
        let r = bs_bit_rule(env, c.w, c.acc)?;
        bitsum.push('\n');
        bitsum.push_str(&r.text);
    }
    for c in cands {
        let ok = agrees(env, &c)?;
        let label = format!("{} ({:?})", c.name(), c.variant);
        match (c.variant, ok) {
            (BitSumVariant::All, true) => {
                let r = bitsum_rule(env, &c)?;
                log(format!("proved {label}"));
                bitsum.push('\n');
                bitsum.push_str(&r.text);
            }
            (BitSumVariant::All, false) => return Err(format!("{label}: the idiom disagrees with count_ones on a test input")),
            (_, false) => log(format!("dropped {label}: disagrees on a test input (a wrong control)")),
            (_, true) => return Err(format!("{label}: a wrong control passed the filter")),
        }
    }
    let mut cong = String::from(CONG_HEADER);
    for r in cong_rules() {
        let mut b = Budget { steps: 100_000_000 };
        env.load_core(&r.text, &mut b).map_err(|e| format!("{}: {e}", r.name))?;
        cong.push('\n');
        cong.push_str(&r.text);
    }
    log(format!("{} cong_irr lemmas", cong_rules().len()));
    Ok(vec![("lemmas/rules/bitsum.core".into(), bitsum), ("lemmas/cong.core".into(), cong)])
}

/// An environment with the prelude and the lemma library.
pub fn library_env() -> Result<Env, String> {
    let mut env = Env::with_prelude();
    sandblaster_front::auto::lemmas::load(&mut env).map_err(|e| e.to_string())?;
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The checked-in files are what rulegen generates.
    #[test]
    fn rule_files_are_generated() {
        sandblaster_front::elab::with_big_stack(|| {
            let mut env = library_env().unwrap();
            let files = generate(&mut env, &mut |_| {}).unwrap_or_else(|e| panic!("{e}"));
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../front");
            for (rel, text) in files {
                let on_disk = std::fs::read_to_string(root.join(&rel)).unwrap_or_default();
                assert!(on_disk == text, "{rel} is stale: run `cargo run -p sandblaster-rulegen --release`");
            }
        });
    }

    #[test]
    fn the_filter_drops_the_wrong_controls() {
        sandblaster_front::elab::with_big_stack(|| {
            let env = library_env().unwrap();
            for c in bitsum_candidates().into_iter().filter(|c| c.w == Width::U8 || c.w == Width::U16) {
                assert_eq!(agrees(&env, &c).unwrap(), c.variant == BitSumVariant::All, "{c:?}");
            }
        });
    }
}
