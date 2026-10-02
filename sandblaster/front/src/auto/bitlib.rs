//! The bit-count lemma library (optimizer design §11.4, plan O3): checked
//! lemmas derived from the kernel's K1 definitions (`count_ones_def`,
//! `leading_zeros_def`, `trailing_zeros_def`), generated as core text.
//!
//! * [`bits_core_text`] generates `sandblaster/front/lemmas/bits.core`
//!   (checked in and loaded with the other lemma files; the test
//!   `auto_lemmas::bits_core_is_generated` compares it with the
//!   generator): the K1 sums as transparent helper definitions, the
//!   indicator lemmas, the bounds that used to be axioms (`count_ones_le`,
//!   `leading/trailing_zeros_le/lt`, which `auto` step 7 instantiates),
//!   `a ≠ 0 ⇒ 0 < a` (fact normalization), `lz_ge_one`, the popcount shift
//!   identity and the exactness of wrapping operations, per width.
//! * The per-literal families ([`Family`]: `lz_range_k`, `popcnt_step_k`,
//!   `popcnt_shr_zero_k`, `mask_split_k`, `clz_xor_prefix_k`,
//!   `wshl_exact_k`) are generated on demand ([`family_item`]) and added
//!   with [`ensure`]: there are `O(w)` of them per width, each with an
//!   `O(w)`-hypothesis proof — too many to check on every build.
//!
//! **Certificates.** Every `linarith` of a generated proof is written as a
//! hole ([`Hole`]); [`certify`] linearizes it with the kernel
//! (`Env::linearize`) and fills in the certificate found by `auto`'s
//! simplex, so loading a lemma only runs the kernel's exact check (the
//! kernel's own search would also succeed, but a dense search over the
//! w-summand systems takes seconds to tens of seconds per lemma at 64 bits).
//!
//! Everything here is untrusted: each lemma is checked by the kernel when it
//! is loaded, so a wrong statement, proof or certificate cannot be added.
//!
//! Notation (the K1 statements): `[b]` is `match b : Bool return Int with
//! false => 0int | true => 1int end`; sums are left-nested `iadd`.

use std::rc::Rc;

use sandblaster_kernel::api::{Ctx, CtxEntry, Env, KernelError, KernelErrorKind};
use sandblaster_kernel::term::{GlobalId, Rel, Tm, Width};
use sandblaster_kernel::value::Budget;

/// The machine widths, in the order the library lists them.
pub const WIDTHS: [Width; 5] = [Width::U8, Width::U16, Width::U32, Width::U64, Width::Usize];

/// A `linarith` of a generated proof whose certificate is computed by
/// [`certify`]: the binders in scope (`.name` for irrelevant ones), the
/// hypotheses `(proof, stated)` and the goal, all core text.
#[derive(Clone, Debug)]
pub struct Hole {
    binders: Vec<(String, String)>,
    hyps: Vec<(String, String)>,
    goal: String,
}

/// One generated definition: its name, its text (certificates are the
/// markers `@@CERT<i>@@` of its holes) and the holes.
#[derive(Clone, Debug)]
pub struct Item {
    pub name: String,
    text: String,
    holes: Vec<Hole>,
}

impl Item {
    fn plain(name: String, text: String) -> Item {
        Item { name, text, holes: Vec::new() }
    }

    /// The text with empty certificates (the kernel searches them).
    pub fn uncertified(&self) -> String {
        let mut t = self.text.clone();
        for i in 0..self.holes.len() {
            t = t.replace(&marker(i), "[]");
        }
        t
    }
}

fn marker(i: usize) -> String {
    format!("@@CERT{i}@@")
}

/// Generator state of one item: the binders in scope and the holes so far.
#[derive(Default)]
struct Gen {
    binders: Vec<(String, String)>,
    holes: Vec<Hole>,
}

impl Gen {
    fn new(binders: &[(&str, &str)]) -> Gen {
        Gen { binders: binders.iter().map(|(n, t)| (n.to_string(), t.to_string())).collect(), holes: Vec::new() }
    }

    /// `linarith(hyps; goal; <certificate>)`.
    fn lin(&mut self, hyps: Vec<(String, String)>, goal: &str) -> String {
        let i = self.holes.len();
        let text = hyps.iter().map(|(p, s)| format!("{p} : {s}")).collect::<Vec<_>>().join(", ");
        self.holes.push(Hole { binders: self.binders.clone(), hyps, goal: goal.to_string() });
        format!("linarith([{text}]; {goal}; {})", marker(i))
    }

    fn item(self, name: String, text: String) -> Item {
        Item { name, text, holes: self.holes }
    }
}

/// `def[lemma] name : (b₁) -> … -> goal := fun (b₁) … => body` over the
/// generator's binders.
fn lemma(g: Gen, name: String, goal: &str, body: &str) -> Item {
    let pis: String = g.binders.iter().map(|(n, t)| format!("({n} : {t}) -> ")).collect();
    let lams: String = g.binders.iter().map(|(n, t)| format!("({n} : {t})")).collect::<Vec<_>>().join(" ");
    let text = format!("def[lemma] {name} : {pis}{goal} :=\n  fun {lams} =>\n    {body}\n");
    g.item(name, text)
}

/// Text helpers for one width.
#[derive(Clone, Copy)]
struct Wd {
    /// `u64`
    s: &'static str,
    /// `U64`
    t: &'static str,
    n: u32,
}

fn wd(w: Width) -> Wd {
    let (s, t) = match w {
        Width::U8 => ("u8", "U8"),
        Width::U16 => ("u16", "U16"),
        Width::U32 => ("u32", "U32"),
        Width::U64 => ("u64", "U64"),
        Width::Usize => ("usize", "Usize"),
        Width::Int => panic!("bitlib: no Int instance"),
    };
    Wd { s, t, n: w.bits().unwrap_or(0) }
}

fn ind(c: &str) -> String {
    format!("match {c} : Bool as _ return Int with | false => 0int | true => 1int end")
}

fn sum(terms: impl IntoIterator<Item = String>) -> String {
    let mut it = terms.into_iter();
    let first = it.next().expect("non-empty sum");
    it.fold(first, |acc, t| format!("#iadd({acc}, {t})"))
}

type Hyp = (String, String);

impl Wd {
    fn max(self) -> u128 {
        (1u128 << self.n) - 1
    }
    fn lit(self, v: u128) -> String {
        format!("{v}{}", self.s)
    }
    fn pow(self, k: u32) -> String {
        self.lit(1u128 << k)
    }
    /// `2^k − 1` (`k ≤ n`).
    fn mask(self, k: u32) -> String {
        self.lit((1u128 << k) - 1)
    }
    fn shr(self, x: &str, k: u32) -> String {
        format!("#wshr_{}({x}, {k}u32)", self.s)
    }
    fn and(self, x: &str, m: &str) -> String {
        format!("#and_{}({x}, {m})", self.s)
    }
    /// `(x >> k) & 1`
    fn bit(self, x: &str, k: u32) -> String {
        self.and(&self.shr(x, k), &self.lit(1))
    }
    fn int(self, x: &str) -> String {
        format!("#cast_{}_int({x})", self.s)
    }
    fn op(self, op: &str, args: &[&str]) -> String {
        format!("#{op}_{}({})", self.s, args.join(", "))
    }
    fn cnt(self, x: &str) -> String {
        format!("#count_ones_{}({x})", self.s)
    }
    fn lz(self, x: &str) -> String {
        format!("#leading_zeros_{}({x})", self.s)
    }
    fn tz(self, x: &str) -> String {
        format!("#trailing_zeros_{}({x})", self.s)
    }
    fn holds(self, op: &str, a: &str, b: &str) -> String {
        format!("Eq(Bool, #{op}_{}({a}, {b}), true)", self.s)
    }
    fn fails(self, op: &str, a: &str, b: &str) -> String {
        format!("Eq(Bool, #{op}_{}({a}, {b}), false)", self.s)
    }
    fn eq(self, a: &str, b: &str) -> String {
        format!("Eq({}, {a}, {b})", self.t)
    }
    /// The right sides of the K1 statements at `x` (as the kernel states them).
    fn cnt_sum(self, x: &str) -> String {
        sum((0..self.n).map(|i| self.int(&self.bit(x, i))))
    }
    fn lz_cond(self, x: &str, m: u32) -> String {
        format!("#lt_{}({x}, {})", self.s, self.pow(m))
    }
    fn lz_sum(self, x: &str) -> String {
        sum((0..self.n).map(|m| ind(&self.lz_cond(x, m))))
    }
    /// `x & (2^m − 1) = 0` (`1 ≤ m ≤ n`).
    fn tz_cond(self, x: &str, m: u32) -> String {
        format!("#eq_{}({}, {})", self.s, self.and(x, &self.mask(m)), self.lit(0))
    }
    fn tz_sum(self, x: &str) -> String {
        sum((1..=self.n).map(|m| ind(&self.tz_cond(x, m))))
    }
    /// `axiom[<schema>_<w>](x)` with its statement, written with the sum
    /// helper `bits::<cnt|lz|tz>_sum_<w>` (a transparent definition: it
    /// unfolds to the kernel's sum, so linarith sees the same atoms).
    fn def_hyp(self, schema: &str, x: &str) -> Hyp {
        let (op, helper) = match schema {
            "count_ones_def" => (self.cnt(x), "cnt_sum"),
            "leading_zeros_def" => (self.lz(x), "lz_sum"),
            _ => (self.tz(x), "tz_sum"),
        };
        (format!("axiom[{schema}_{}]({x})", self.s), format!("Eq(Int, #cast_u32_int({op}), bits::{helper}_{} ({x}))", self.s))
    }
    /// `bvrefl(W, a, b) : Eq(W, a, b)`
    fn bv(self, a: &str, b: &str) -> Hyp {
        (format!("bvrefl({}, {a}, {b})", self.t), self.eq(a, b))
    }
    /// `count(x) (≤|<) upper` over `U32`.
    fn bound(self, count: &str, upper: u32, strict: bool) -> String {
        format!("Eq(Bool, #{}_u32({count}, {upper}u32), true)", if strict { "lt" } else { "le" })
    }
}

/// `[c] = 1` from `c = true` / `[c] = 0` from `c = false` (`pf` proves it).
fn ind_is(c: &str, b: bool, pf: &str) -> Hyp {
    let (lem, v) = if b { ("bits::ind_true", "1int") } else { ("bits::ind_false", "0int") };
    (format!("{lem} {c} .{pf}"), format!("Eq(Int, {}, {v})", ind(c)))
}

fn ind_bound(c: &str, upper: bool) -> Hyp {
    if upper {
        (format!("bits::ind_le_one {c}"), format!("Eq(Bool, #le_int({}, 1int), true)", ind(c)))
    } else {
        (format!("bits::ind_ge_zero {c}"), format!("Eq(Bool, #le_int(0int, {}), true)", ind(c)))
    }
}

const HEADER: &str = "\
-- sandblaster lemma library: bit counting (optimizer design §11.4, plan O3).
--
-- GENERATED by `sandblaster_front::auto::bitlib::bits_core_text`; do not edit
-- (the test `auto_lemmas::bits_core_is_generated` compares this file with
-- the generator; `SANDBLASTER_REGEN_BITS=1` rewrites it). The linarith
-- certificates were found by `auto`'s simplex; the kernel checks them.
--
-- Checked, untrusted: every lemma is derived from the kernel's K1
-- definitions `count_ones_def`, `leading_zeros_def`, `trailing_zeros_def`
-- (sums in Int of the bits / of one comparison per candidate count), with
-- linarith, BvRefl and the indicator lemmas below. The per-literal
-- families (`lz_range_k`, `popcnt_step_k`, `mask_split_k`,
-- `clz_xor_prefix_k`, `wshl_exact_k`, …) are generated on demand
-- (`bitlib::ensure`).
";

/// The items of `lemmas/bits.core`, in order (uncertified).
pub fn bits_core_items() -> Vec<Item> {
    let (ib, iy) = (ind("b"), ind("y"));
    let mut items = vec![
        Item::plain(
            "bits::ind_le_one".into(),
            format!(
                "-- The indicator [b] of the K1 statements: 0 ≤ [b] ≤ 1, [true] = 1, [false] = 0.
def[lemma] bits::ind_le_one : (b : Bool) -> Eq(Bool, #le_int({ib}, 1int), true) :=
  fun (b : Bool) =>
    match b : Bool as y return Eq(Bool, #le_int({iy}, 1int), true) with
    | false => refl(Bool, true)
    | true => refl(Bool, true)
    end
"
            ),
        ),
        Item::plain(
            "bits::ind_ge_zero".into(),
            format!(
                "def[lemma] bits::ind_ge_zero : (b : Bool) -> Eq(Bool, #le_int(0int, {ib}), true) :=
  fun (b : Bool) =>
    match b : Bool as y return Eq(Bool, #le_int(0int, {iy}), true) with
    | false => refl(Bool, true)
    | true => refl(Bool, true)
    end
"
            ),
        ),
    ];
    for (b, v) in [("true", "1int"), ("false", "0int")] {
        items.push(Item::plain(
            format!("bits::ind_{b}"),
            format!(
                "def[lemma] bits::ind_{b} : (b : Bool) -> (.h : Eq(Bool, b, {b})) -> Eq(Int, {ib}, {v}) :=
  fun (b : Bool) (.h : Eq(Bool, b, {b})) =>
    transport(Bool, {b}, b, eq::sym Bool b {b} h, y. Eq(Int, {iy}, {v}), refl(Int, {v}))
"
            ),
        ));
    }
    // [a] = [b] for two booleans that imply each other (the indicators of
    // two K1 conditions that say the same thing, `tz_shr1`).
    let (ia, iz) = (ind("a"), ind("z"));
    let (ta, tb) = ("Eq(Bool, a, true)", "Eq(Bool, b, true)");
    items.push(Item::plain(
        "bits::ind_iff".into(),
        format!(
            "-- [a] = [b] when a and b imply each other.
def[lemma] bits::ind_iff : (a : Bool) -> (b : Bool) -> (.ab : (h : {ta}) -> {tb}) -> (.ba : (h : {tb}) -> {ta}) -> Eq(Int, {ia}, {ib}) :=
  fun (a : Bool) (b : Bool) (.ab : (h : {ta}) -> {tb}) (.ba : (h : {tb}) -> {ta}) =>
    (match a : Bool as y return (.e : Eq(Bool, a, y)) -> Eq(Int, {iy}, {ib}) with
     | false => fun (.e : Eq(Bool, a, false)) =>
         (match b : Bool as z return (.f : Eq(Bool, b, z)) -> Eq(Int, 0int, {iz}) with
          | false => fun (.f : Eq(Bool, b, false)) => refl(Int, 0int)
          | true => fun (.f : {tb}) => absurd(Eq(Int, 0int, 1int), bool::false_ne_true (eq::trans Bool false a true (eq::sym Bool a false e) (ba f)))
          end) .refl(Bool, b)
     | true => fun (.e : {ta}) => eq::sym Int ({ib}) 1int (bits::ind_true b .(ab e))
     end) .refl(Bool, a)
"
        ),
    ));
    for w in WIDTHS {
        items.extend(width_items(wd(w)));
    }
    items
}

/// The per-width part of `bits.core`.
fn width_items(d: Wd) -> Vec<Item> {
    let (s, t, n) = (d.s, d.t, d.n);
    let z = d.lit(0);
    let one = d.lit(1);
    let mut out = Vec::new();
    // The K1 sums (transparent: they unfold to the kernel's statements).
    for (helper, what, body) in
        [("cnt_sum", "count_ones", d.cnt_sum("x")), ("lz_sum", "leading_zeros", d.lz_sum("x")), ("tz_sum", "trailing_zeros", d.tz_sum("x"))]
    {
        let head = if helper == "cnt_sum" {
            format!("-- ---------------------------------------------------------------- {t}\n\n")
        } else {
            String::new()
        };
        out.push(Item::plain(
            format!("bits::{helper}_{s}"),
            format!("{head}-- The right side of `{what}_def_{s}`.\ndef[spec] bits::{helper}_{s} : (x : {t}) -> Int :=\n  fun (x : {t}) => {body}\n"),
        ));
    }
    // a ≠ 0 ⇒ 0 < a; (a == 0) = false ⇒ 0 < a (fact normalization). In the
    // `false` arm (a ≤ 0, so a = 0) the hypothesis evaluates to a clash.
    for (name, hyp_op) in [("ne_zero_pos", "ne"), ("eq_zero_false_pos", "eq")] {
        let hyp = if hyp_op == "ne" { d.holds("ne", "a", &z) } else { d.fails("eq", "a", &z) };
        let at_y = if hyp_op == "ne" { d.holds("ne", "y", &z) } else { d.fails("eq", "y", &z) };
        let mut g = Gen::new(&[("a", t), (".h", &hyp), (".e", &d.fails("lt", &z, "a"))]);
        let a_zero = g.lin(vec![("e".into(), d.fails("lt", &z, "a"))], &d.eq("a", &z));
        g.binders.pop();
        let moved = format!("transport({t}, a, {z}, {a_zero}, y. {at_y}, h)");
        let clash = if hyp_op == "ne" { moved } else { format!("eq::sym Bool true false ({moved})") };
        let body = format!(
            "(match #lt_{s}({z}, a) : Bool as y return (.e : Eq(Bool, #lt_{s}({z}, a), y)) -> Eq(Bool, y, true) with
     | false => fun (.e : {ef}) => absurd(Eq(Bool, false, true), bool::false_ne_true ({clash}))
     | true => fun (.e : {et}) => refl(Bool, true)
     end) .refl(Bool, #lt_{s}({z}, a))",
            ef = d.fails("lt", &z, "a"),
            et = d.holds("lt", &z, "a"),
        );
        out.push(lemma(g, format!("bits::{name}_{s}"), &d.holds("lt", &z, "a"), &body));
    }
    // The retired bound axioms, as lemmas. count_ones(a) ≤ w: the bits are
    // remainders mod 2, each at most 1.
    let mut g = Gen::new(&[("a", t)]);
    let goal = d.bound(&d.cnt("a"), n, false);
    let p = g.lin(vec![d.def_hyp("count_ones_def", "a")], &goal);
    out.push(lemma(g, format!("bits::count_ones_le_{s}"), &goal, &p));
    // leading_zeros(a) ≤ w: w indicators.
    let lz_bounds: Vec<Hyp> = (0..n).map(|m| ind_bound(&d.lz_cond("a", m), true)).collect();
    let mut g = Gen::new(&[("a", t)]);
    let goal = d.bound(&d.lz("a"), n, false);
    let mut hs = vec![d.def_hyp("leading_zeros_def", "a")];
    hs.extend(lz_bounds.iter().cloned());
    let p = g.lin(hs, &goal);
    out.push(lemma(g, format!("bits::leading_zeros_le_{s}"), &goal, &p));
    // a ≠ 0 ⇒ leading_zeros(a) < w: the indicator [a < 1] is 0.
    let hne = d.holds("ne", "a", &z);
    let pos: Hyp = (format!("bits::ne_zero_pos_{s} a .h"), d.holds("lt", &z, "a"));
    let mut g = Gen::new(&[("a", t), (".h", &hne)]);
    let goal = d.bound(&d.lz("a"), n, true);
    let c0 = d.lz_cond("a", 0);
    let pf = g.lin(vec![pos.clone()], &format!("Eq(Bool, {c0}, false)"));
    let mut hs = vec![d.def_hyp("leading_zeros_def", "a"), ind_is(&c0, false, &pf)];
    hs.extend(lz_bounds[1..].iter().cloned());
    let p = g.lin(hs, &goal);
    out.push(lemma(g, format!("bits::leading_zeros_lt_{s}"), &goal, &p));
    // trailing_zeros(a) ≤ w: w indicators.
    let tz_bounds: Vec<Hyp> = (1..=n).map(|m| ind_bound(&d.tz_cond("a", m), true)).collect();
    let mut g = Gen::new(&[("a", t)]);
    let goal = d.bound(&d.tz("a"), n, false);
    let mut hs = vec![d.def_hyp("trailing_zeros_def", "a")];
    hs.extend(tz_bounds.iter().cloned());
    let p = g.lin(hs, &goal);
    out.push(lemma(g, format!("bits::trailing_zeros_le_{s}"), &goal, &p));
    // a ≠ 0 ⇒ trailing_zeros(a) < w: the indicator [a & (2^w − 1) = 0] is 0.
    let mut g = Gen::new(&[("a", t), (".h", &hne)]);
    let goal = d.bound(&d.tz("a"), n, true);
    let cn = d.tz_cond("a", n);
    let pf = g.lin(vec![pos.clone()], &format!("Eq(Bool, {cn}, false)"));
    let mut hs = vec![d.def_hyp("trailing_zeros_def", "a")];
    hs.extend(tz_bounds[..n as usize - 1].iter().cloned());
    hs.push(ind_is(&cn, false, &pf));
    let p = g.lin(hs, &goal);
    out.push(lemma(g, format!("bits::trailing_zeros_lt_{s}"), &goal, &p));
    // x < 2^(w−1) ⇒ leading_zeros(x) ≥ 1.
    let top = d.lz_cond("x", n - 1);
    let mut g = Gen::new(&[("x", t), (".h", &format!("Eq(Bool, {top}, true)"))]);
    let goal = format!("Eq(Bool, #le_u32(1u32, {}), true)", d.lz("x"));
    let mut hs = vec![d.def_hyp("leading_zeros_def", "x"), ind_is(&top, true, "h")];
    hs.extend((0..n - 1).map(|m| ind_bound(&d.lz_cond("x", m), false)));
    let p = g.lin(hs, &goal);
    out.push(lemma(g, format!("bits::lz_ge_one_{s}"), &goal, &p));
    // count_ones(x) = count_ones(x >> 1) + (x & 1).
    let x1 = d.shr("x", 1);
    let mut g = Gen::new(&[("x", t)]);
    let mut hs = vec![d.def_hyp("count_ones_def", "x"), d.def_hyp("count_ones_def", &x1), d.bv(&d.bit("x", 0), &d.and("x", &one))];
    for i in 1..n {
        hs.push(d.bv(&d.bit(&x1, i - 1), &d.bit("x", i)));
    }
    hs.push(d.bv(&d.bit(&x1, n - 1), &z));
    let goal = format!("Eq(Int, #cast_u32_int({}), #iadd(#cast_u32_int({}), {}))", d.cnt("x"), d.cnt(&x1), d.int(&d.and("x", &one)));
    let p = g.lin(hs, &goal);
    out.push(lemma(g, format!("bits::popcnt_shr1_{s}"), &goal, &p));
    out.push(bit1_flip(d));
    out.push(not_val(d));
    // Exactness of wrapping operations: equal to the checked operation when
    // it is in its domain (so linarith reads them exactly).
    for (name, hyp, wop, cop) in [
        ("wadd_exact", format!("Eq(Bool, #le_int(#iadd({}, {}), {}int), true)", d.int("a"), d.int("b"), d.max()), "wadd", "add"),
        ("wsub_exact", d.holds("le", "b", "a"), "wsub", "sub"),
        ("wmul_exact", format!("Eq(Bool, #le_int(#imul({}, {}), {}int), true)", d.int("a"), d.int("b"), d.max()), "wmul", "mul"),
    ] {
        let lhs = d.op(wop, &["a", "b"]);
        let rhs = format!("#{cop}_{s}(a, b; h)");
        let g = Gen::new(&[("a", t), ("b", t), (".h", &hyp)]);
        let mut it = lemma(g, format!("bits::{name}_{s}"), &d.eq(&lhs, &rhs), &format!("bvrefl({t}, {lhs}, {rhs})"));
        it.text = format!("-- {wop}(a, b) is the checked {cop} when that is in its domain.\n{}", it.text);
        out.push(it);
    }
    out
}

/// `b ^ 1 = 1 − b` in `Int` for a bit `b ≤ 1` (by cases on `b == 0`: in
/// each arm the value is moved in and both sides compute).
fn bit1_flip(d: Wd) -> Item {
    let (s, t) = (d.s, d.t);
    let (z, one) = (d.lit(0), d.lit(1));
    let hyp = d.holds("le", "b", &one);
    let stmt = |b: &str| format!("Eq(Int, {}, #isub(1int, {}))", d.int(&d.op("xor", &[b, &one])), d.int(b));
    let goal = stmt("b");
    let test = d.op("eq", &["b", &z]);
    let mut g = Gen::new(&[("b", t), (".h", &hyp), (".e", &format!("Eq(Bool, {test}, true)"))]);
    let is0 = g.lin(vec![("e".into(), format!("Eq(Bool, {test}, true)"))], &d.eq(&z, "b"));
    g.binders.pop();
    g.binders.push((".e".into(), format!("Eq(Bool, {test}, false)")));
    let pos: Hyp = (format!("bits::eq_zero_false_pos_{s} b .e"), d.holds("lt", &z, "b"));
    let is1 = g.lin(vec![pos, ("h".into(), hyp.clone())], &d.eq(&one, "b"));
    g.binders.pop();
    let body = format!(
        "(match {test} : Bool as y return (.e : Eq(Bool, {test}, y)) -> {goal} with
     | false => fun (.e : Eq(Bool, {test}, false)) => transport({t}, {one}, b, {is1}, y. {sy}, refl(Int, 0int))
     | true => fun (.e : Eq(Bool, {test}, true)) => transport({t}, {z}, b, {is0}, y. {sy}, refl(Int, 1int))
     end) .refl(Bool, {test})",
        sy = stmt("y"),
    );
    let mut it = lemma(g, format!("bits::bit1_flip_{s}"), &goal, &body);
    it.text = format!("-- b ^ 1 = 1 − b for a bit b.\n{}", it.text);
    it
}

/// `!x = MAX − x` in `Int` (`auto` adds it for every `!x` it meets, so
/// linear arithmetic reads a complement exactly). By measure recursion on
/// `x`: `!x` is twice `(!x) >> 1` plus its bit 0; `(!x) >> 1` is `!(x >> 1)`
/// without its top bit, which is set (word identities), so it is
/// `MAX − (x >> 1) − 2^(w−1)` by the recursive call; and bit 0 of `!x` is
/// `1 −` bit 0 of `x` (`bits::bit1_flip`). `x = 0`: both sides compute.
fn not_val(d: Wd) -> Item {
    let (s, t, n) = (d.s, d.t, d.n);
    let (z, one) = (d.lit(0), d.lit(1));
    let not = |x: &str| d.op("not", &[x]);
    let stmt = |x: &str| format!("Eq(Int, {}, #isub({}int, {}))", d.int(&not(x)), d.max(), d.int(x));
    let goal = stmt("x");
    let test = d.op("eq", &["x", &z]);
    let x1 = d.shr("x", 1);
    let mut g = Gen::new(&[("x", t), (".e", &format!("Eq(Bool, {test}, true)"))]);
    let is0 = g.lin(vec![("e".into(), format!("Eq(Bool, {test}, true)"))], &d.eq(&z, "x"));
    g.binders.pop();
    let ef = format!("Eq(Bool, {test}, false)");
    g.binders.push((".e".into(), ef.clone()));
    let pos: Hyp = (format!("bits::eq_zero_false_pos_{s} x .e"), d.holds("lt", &z, "x"));
    let dec = g.lin(vec![pos], &d.holds("lt", &x1, "x"));
    let bit0 = d.and("x", &one);
    let le1 = g.lin(vec![], &d.holds("le", &bit0, &one));
    let hs: Vec<Hyp> = vec![
        (format!("rec({x1}; {dec})"), stmt(&x1)),
        d.bv(&d.shr(&not("x"), 1), &d.and(&not(&x1), &d.lit(d.max() >> 1))),
        d.bv(&d.shr(&not(&x1), n - 1), &one),
        d.bv(&d.and(&not("x"), &one), &d.op("xor", &[&bit0, &one])),
        (format!("bits::bit1_flip_{s} ({bit0}) .{le1}"), format!("Eq(Int, {}, #isub(1int, {}))", d.int(&d.op("xor", &[&bit0, &one])), d.int(&bit0))),
    ];
    let step = g.lin(hs, &goal);
    g.binders.pop();
    let body = format!(
        "(match {test} : Bool as y return (.e : Eq(Bool, {test}, y)) -> {goal} with
     | false => fun (.e : {ef}) => {step}
     | true => fun (.e : Eq(Bool, {test}, true)) => transport({t}, {z}, x, {is0}, y. {sy}, refl(Int, {max}int))
     end) .refl(Bool, {test})",
        sy = stmt("y"),
        max = d.max(),
    );
    let mut it = lemma(g, format!("bits::not_val_{s}"), &goal, &body);
    it.text = format!("-- !x = MAX − x.\n{} measure (x)\n", it.text.trim_end());
    it
}

/// `tz(x) = tz(x >> 1) + 1` in `Int` for an even `x ≠ 0` (the step of the
/// trailing-zeros induction of `stdlib::bits`, which states the trailing
/// zeros of a word for every count at once). The K1 sums of `x` and of
/// `y = x >> 1` agree term by term — the low `m + 1` bits of `x` are zero
/// exactly when the low `m` bits of `y` are, bit 0 of `x` being zero
/// (`bits::ind_iff`, each direction by linarith over two word identities)
/// — except `x`'s first term (`x & 1 = 0`: 1) and `y`'s last (`y ≠ 0`: 0).
fn tz_shr1(d: Wd) -> Item {
    let (s, t, n) = (d.s, d.t, d.n);
    let z = d.lit(0);
    let one = d.lit(1);
    let y = d.shr("x", 1);
    let h1 = d.eq(&d.and("x", &one), &z);
    let h2 = d.holds("ne", "x", &z);
    let mut g = Gen::new(&[("x", t), (".h1", &h1), (".h2", &h2)]);
    let mut hs = vec![d.def_hyp("trailing_zeros_def", "x"), d.def_hyp("trailing_zeros_def", &y)];
    // x's first term: x & 1 = 0
    let c1 = d.tz_cond("x", 1);
    let pf = g.lin(vec![("h1".into(), h1.clone())], &format!("Eq(Bool, {c1}, true)"));
    hs.push(ind_is(&c1, true, &pf));
    // y's last term: y & (2^w − 1) is y, not 0 (x ≥ 1 is even, so y ≥ 1)
    let cn = d.tz_cond(&y, n);
    let pos: Hyp = (format!("bits::ne_zero_pos_{s} x .h2"), d.holds("lt", &z, "x"));
    let pf = g.lin(vec![pos, ("h1".into(), h1.clone())], &format!("Eq(Bool, {cn}, false)"));
    hs.push(ind_is(&cn, false, &pf));
    // the other terms in pairs: [x & (2^(m+1) − 1) = 0] = [y & (2^m − 1) = 0]
    for m in 1..n {
        let (a, b) = (d.tz_cond("x", m + 1), d.tz_cond(&y, m));
        let xm = d.and("x", &d.mask(m + 1));
        // y & (2^m − 1) is (x & (2^(m+1) − 1)) >> 1, and x & 1 its lowest bit
        let link1 = d.bv(&d.and(&y, &d.mask(m)), &d.shr(&xm, 1));
        let link2 = d.bv(&d.and("x", &one), &d.and(&xm, &one));
        let (ha, hb) = (format!("Eq(Bool, {a}, true)"), format!("Eq(Bool, {b}, true)"));
        g.binders.push(("h".into(), ha.clone()));
        let ab = g.lin(vec![("h".into(), ha.clone()), link1.clone()], &hb);
        g.binders.pop();
        g.binders.push(("h".into(), hb.clone()));
        let ba = g.lin(vec![("h".into(), hb.clone()), link1, link2, ("h1".into(), h1.clone())], &ha);
        g.binders.pop();
        hs.push((format!("bits::ind_iff ({a}) ({b}) .(fun (h : {ha}) => {ab}) .(fun (h : {hb}) => {ba})"), format!("Eq(Int, {}, {})", ind(&a), ind(&b))));
    }
    let goal = format!("Eq(Int, #cast_u32_int({}), #iadd(#cast_u32_int({}), 1int))", d.tz("x"), d.tz(&y));
    let p = g.lin(hs, &goal);
    let mut it = lemma(g, format!("bits::tz_shr1_{s}"), &goal, &p);
    it.text = format!("-- tz(x) = tz(x >> 1) + 1 for an even x ≠ 0.\n{}", it.text);
    it
}

/// Fill in the certificates of an item (each hole is linearized in the
/// scope of its binders with the globals of `env`, which must contain
/// everything the item mentions). A hole without a certificate keeps `[]`
/// (the kernel then searches one itself).
pub fn certify(env: &Env, item: &Item, b: &mut Budget) -> Result<String, String> {
    let mut certs: Vec<String> = Vec::new();
    let fill = |s: &str, certs: &[String]| {
        let mut s = s.to_string();
        for (i, c) in certs.iter().enumerate() {
            s = s.replace(&marker(i), c);
        }
        s
    };
    for h in &item.holes {
        let mut names: Vec<String> = Vec::new();
        let mut ctx = Ctx::default();
        let parse = |names: &[String], src: &str| -> Result<Tm, String> {
            let ns: Vec<&str> = names.iter().map(|n| n.as_str()).collect();
            env.parse_term(&ns, src).map_err(|e| format!("{}: `{src}`: {e}", item.name))
        };
        for (n, ty) in &h.binders {
            let rel = if n.starts_with('.') { Rel::Irr } else { Rel::Rel };
            let n = n.trim_start_matches('.').to_string();
            let tyt = parse(&names, &fill(ty, &certs))?;
            let tyv = env.eval(&env.ctx_venv(&ctx), ctx.depth(), &tyt, b).map_err(|e| format!("{}: {e:?}", item.name))?;
            ctx = ctx.push(CtxEntry { name: Rc::from(n.as_str()), rel, ty: tyv, def: None });
            names.push(n);
        }
        let mut hyps = Vec::new();
        for (p, st) in &h.hyps {
            hyps.push((parse(&names, &fill(p, &certs))?, parse(&names, &fill(st, &certs))?));
        }
        let goal = parse(&names, &fill(&h.goal, &certs))?;
        let sys = env.linearize(&ctx, &hyps, &goal, b).map_err(|e| format!("{}: {e}", item.name))?;
        let cert = match super::simplex::certificate(&sys) {
            Some(c) => format!(
                "[{}]",
                c.iter()
                    .map(|r| if r.den == num_bigint::BigInt::from(1) { r.num.to_string() } else { format!("{}/{}", r.num, r.den) })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            None => "[]".to_string(),
        };
        certs.push(cert);
    }
    Ok(fill(&item.text, &certs))
}

/// Certify and load an item.
fn load_item(env: &mut Env, item: &Item, b: &mut Budget) -> Result<String, KernelError> {
    let text = certify(env, item, b).map_err(|m| KernelError { kind: KernelErrorKind::IllFormed, message: m })?;
    env.load_core(&text, b).map_err(|e| KernelError { kind: e.kind, message: format!("{}: {}", item.name, e.message) })?;
    Ok(text)
}

thread_local! {
    /// The certificates of the last certified family member, by family
    /// stem (plan O6: consecutive members of a family — `lz_range_k`,
    /// `lz_range_{k+1}` — usually have the same multipliers; they are tried
    /// first).
    static FAMILY_CERTS: std::cell::RefCell<std::collections::HashMap<String, Vec<String>>> = std::cell::RefCell::new(std::collections::HashMap::new());
    /// Families whose reused certificates did not load (not tried again).
    static FAMILY_NO_REUSE: std::cell::RefCell<std::collections::HashSet<String>> = std::cell::RefCell::new(std::collections::HashSet::new());
}

/// Certificates are reused only for items with at least this many holes.
/// A reused certificate the kernel does not accept is not a failure: the
/// kernel's `linarith` searches one of its own and the load succeeds, at
/// several times the cost of checking a correct one. That pays only where
/// certifying the item is dear: `lz_range` (65 holes, the last with 65
/// hypotheses; certified 5 ms, loaded with the previous member's
/// certificates 1.35 ms, QMDB N = 32). Items with one or two holes
/// (`clz_xor_prefix`, `mask_split`, `popcnt_step`, `shl_exact`) certify in
/// 0.05–0.2 ms, and their certificates depend on `k`, so a reused one fails
/// and the load takes 0.5–1 ms: they are certified every time.
const REUSE_MIN_HOLES: usize = 8;

/// [`load_item`] for a family member: first with the certificates of the
/// family's last certified member when it has at least
/// [`REUSE_MIN_HOLES`] holes (no simplex search; the kernel checks them),
/// else certified as usual.
fn load_family_item(env: &mut Env, stem: &str, item: &Item, b: &mut Budget) -> Result<String, KernelError> {
    if item.holes.len() >= REUSE_MIN_HOLES
        && let Some(certs) = FAMILY_CERTS.with(|m| m.borrow().get(stem).cloned())
        && certs.len() == item.holes.len()
        && !FAMILY_NO_REUSE.with(|m| m.borrow().contains(stem))
    {
        let mut text = item.text.clone();
        for (i, c) in certs.iter().enumerate() {
            text = text.replace(&marker(i), c);
        }
        // a failed attempt charges its steps, but adds nothing
        let mut tb = Budget { steps: b.steps };
        if env.load_core(&text, &mut tb).is_ok() {
            b.steps = tb.steps;
            return Ok(text);
        }
        FAMILY_NO_REUSE.with(|m| m.borrow_mut().insert(stem.to_string()));
    }
    let text = certify(env, item, b).map_err(|m| KernelError { kind: KernelErrorKind::IllFormed, message: m })?;
    env.load_core(&text, b).map_err(|e| KernelError { kind: e.kind, message: format!("{}: {}", item.name, e.message) })?;
    if item.holes.len() < REUSE_MIN_HOLES {
        return Ok(text);
    }
    // remember its certificates (the `[...]` that replaced the markers)
    let mut certs = Vec::new();
    let mut rest = item.text.as_str();
    let mut out = text.as_str();
    for i in 0..item.holes.len() {
        let m = marker(i);
        let Some(pos) = rest.find(&m) else { break };
        let prefix = &rest[..pos];
        if !out.starts_with(prefix) {
            break;
        }
        let after = &out[prefix.len()..];
        // the certificate is the bracketed list at the marker's place
        let Some(end) = after.find(']') else { break };
        certs.push(after[..=end].to_string());
        rest = &rest[pos + m.len()..];
        out = &after[end + 1..];
    }
    if certs.len() == item.holes.len() {
        FAMILY_CERTS.with(|m| m.borrow_mut().insert(stem.to_string(), certs));
    }
    Ok(text)
}

/// The text of `lemmas/bits.core`: the items of [`bits_core_items`],
/// certified and loaded one by one into `env` (which must hold the prelude
/// and the lemma files that precede `bits.core`).
pub fn bits_core_text(env: &mut Env, b: &mut Budget) -> Result<String, KernelError> {
    let mut out = String::from(HEADER);
    for item in bits_core_items() {
        out.push('\n');
        out.push_str(&load_item(env, &item, b)?);
    }
    Ok(out)
}

/// Per-literal lemma families (generated on demand).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    /// `2^k ≤ x < 2^(k+1) ⇒ lz(x) = w−1−k` (`k < w`; no upper bound at `k = w−1`).
    LzRange,
    /// `cnt(x >> k) = cnt(x >> (k+1)) + ((x >> k) & 1)` in `Int` (`k ≤ w−2`);
    /// at `k = w−1`: `cnt(x >> (w−1)) = (x >> (w−1)) & 1`.
    PopcntStep,
    /// `x < 2^k ⇒ cnt(x >> k) = 0` (`1 ≤ k < w`).
    PopcntShrZero,
    /// `x & (2^(k+1)−1) = x & (2^k−1) + 2^k·((x >> k) & 1)` in `Int` (`k < w`).
    MaskSplit,
    /// `x >> (k+1) = y >> (k+1)`, bit `k` of `x` set and of `y` clear ⇒
    /// `lz(x ^ y) = w−1−k` (`k < w`; no prefix hypothesis at `k = w−1`).
    ClzXorPrefix,
    /// `a ≤ MAX >> k ⇒ a << k` is the checked `a · 2^k` (`1 ≤ k < w`).
    WshlExact,
    /// The same for the checked shift (`<<` with its width obligation):
    /// `a ≤ MAX >> k ⇒ shl(a, k) = a · 2^k` (`1 ≤ k < w`; plan O5: the
    /// accumulated groups of a varint reader).
    ShlExact,
    /// `cnt(x) = cnt(x >> k) + cnt(x & (2^k − 1))` in `Int` (`1 ≤ k < w`).
    PopcntSplit,
    /// `cnt(x & (2^(k+1) − 1)) = cnt(x & (2^k − 1)) + ((x >> k) & 1)` in
    /// `Int` (`k < w`): the ascending bit-sum idiom (corpus P3/P13, the
    /// design's `count_ones_sum`).
    PopcntLowStep,
    /// `x & (2^(k+1) − 1) = 2^k ⇒ tz(x) = k` (`k < w`).
    TzRange,
    /// `x < 2^k ⇒ cnt(x) ≤ k` (`k < w`; plan O6: the bounds on popcount
    /// fields a loop summary exports, e.g. `before + after ≤ 61`).
    PopcntLe,
    /// `x < 2^k ⇒ w − k ≤ lz(x)` (`k < w`; plan O6: the set-bit rung's jump
    /// target).
    LzLower,
    /// `w − k ≤ lz(x) ⇒ x < 2^k` (`k < w`; plan O6: the set-bit rung's idle
    /// runs).
    LzGe,
    /// `cnt(x) ≤ cnt(x >> k) + k` in `Int` (`1 ≤ k < w`; the steps of
    /// `popcnt_le_k`, each from the previous one).
    PopcntShrLe,
    /// `tz(x) = tz(x >> 1) + 1` in `Int` for an even `x ≠ 0`: one lemma per
    /// width, no `k` ([`Family::fixed`]; named `bits::tz_shr1_<w>`). The
    /// step of the trailing-zeros induction of `stdlib::bits`, which states
    /// a word's trailing zeros for every count at once. On demand: its
    /// proof compares the K1 sums term by term (`w − 1` pairs).
    TzShr1,
}

impl Family {
    pub const ALL: [Family; 15] = [
        Family::LzRange,
        Family::PopcntStep,
        Family::PopcntShrZero,
        Family::MaskSplit,
        Family::ClzXorPrefix,
        Family::WshlExact,
        Family::ShlExact,
        Family::PopcntSplit,
        Family::PopcntLowStep,
        Family::TzRange,
        Family::PopcntLe,
        Family::LzLower,
        Family::LzGe,
        Family::PopcntShrLe,
        Family::TzShr1,
    ];

    /// One lemma per width, with no literal parameter: named
    /// `bits::<stem>_<w>`, valid at `k = 0` only.
    pub fn fixed(self) -> bool {
        matches!(self, Family::TzShr1)
    }

    pub fn stem(self) -> &'static str {
        match self {
            Family::LzRange => "lz_range",
            Family::PopcntStep => "popcnt_step",
            Family::PopcntShrZero => "popcnt_shr_zero",
            Family::MaskSplit => "mask_split",
            Family::ClzXorPrefix => "clz_xor_prefix",
            Family::WshlExact => "wshl_exact",
            Family::ShlExact => "shl_exact",
            Family::PopcntSplit => "popcnt_split",
            Family::PopcntLowStep => "popcnt_low_step",
            Family::TzRange => "tz_range",
            Family::PopcntLe => "popcnt_le",
            Family::LzLower => "lz_lower",
            Family::LzGe => "lz_ge",
            Family::PopcntShrLe => "popcnt_shr_le",
            Family::TzShr1 => "tz_shr1",
        }
    }

    /// Is `k` in the family's range at width `w`?
    pub fn valid(self, w: Width, k: u32) -> bool {
        let n = w.bits().unwrap_or(0);
        match self {
            Family::LzRange | Family::MaskSplit | Family::ClzXorPrefix | Family::PopcntStep | Family::PopcntLowStep | Family::TzRange | Family::PopcntLe | Family::LzLower | Family::LzGe => {
                k < n
            }
            Family::PopcntShrZero | Family::WshlExact | Family::ShlExact | Family::PopcntSplit | Family::PopcntShrLe => k >= 1 && k < n,
            Family::TzShr1 => k == 0 && n >= 2,
        }
    }
}

/// The family instance a lemma name denotes (`bits::lz_ge_u16_9`, or
/// without the `bits::` prefix), when it is one: proof scripts name them as
/// `sandblaster::lemmas::bits::lz_ge_u16_9(x)` and the resolver and the
/// elaborator generate them on demand ([`ensure`]).
pub fn parse_lemma_name(name: &str) -> Option<(Family, Width, u32)> {
    let n = name.strip_prefix("bits::").unwrap_or(name);
    // a fixed family: `<stem>_<w>`
    for f in Family::ALL.into_iter().filter(|f| f.fixed()) {
        if let Some(ws) = n.strip_prefix(f.stem()).and_then(|r| r.strip_prefix('_'))
            && let Some(w) = WIDTHS.into_iter().find(|w| wd(*w).s == ws)
            && f.valid(w, 0)
        {
            return Some((f, w, 0));
        }
    }
    const FAMS: [Family; 15] = [
        Family::LzRange, Family::PopcntStep, Family::PopcntShrZero, Family::MaskSplit, Family::ClzXorPrefix, Family::WshlExact, Family::ShlExact,
        Family::PopcntSplit, Family::PopcntLowStep, Family::TzRange, Family::PopcntLe, Family::LzLower, Family::LzGe, Family::PopcntShrLe, Family::LzRange,
    ];
    for f in FAMS {
        let Some(rest) = n.strip_prefix(f.stem()).and_then(|r| r.strip_prefix('_')) else { continue };
        let (ws, ks) = rest.rsplit_once('_')?;
        let w = match ws {
            "u8" => Width::U8,
            "u16" => Width::U16,
            "u32" => Width::U32,
            "u64" => Width::U64,
            "usize" => Width::Usize,
            _ => continue,
        };
        let k: u32 = ks.parse().ok()?;
        if f.valid(w, k) {
            return Some((f, w, k));
        }
    }
    None
}

/// `bits::<stem>_<w>_<k>` (`bits::<stem>_<w>` for a fixed family).
pub fn lemma_name(f: Family, w: Width, k: u32) -> String {
    if f.fixed() {
        return format!("bits::{}_{}", f.stem(), wd(w).s);
    }
    format!("bits::{}_{}_{k}", f.stem(), wd(w).s)
}

/// The lemmas a family member's proof uses (added first by [`ensure`]).
fn deps(f: Family, w: Width, k: u32) -> Vec<(Family, Width, u32)> {
    match f {
        Family::ClzXorPrefix => vec![(Family::LzRange, w, k)],
        Family::PopcntLe if k >= 1 => vec![(Family::PopcntShrLe, w, k), (Family::PopcntShrZero, w, k)],
        Family::PopcntShrLe if k >= 2 => vec![(Family::PopcntShrLe, w, k - 1), (Family::PopcntStep, w, k - 1)],
        _ => vec![],
    }
}

/// One family member (`None` outside its range), uncertified.
pub fn family_item(f: Family, w: Width, k: u32) -> Option<Item> {
    if !f.valid(w, k) {
        return None;
    }
    let d = wd(w);
    let (s, t, n) = (d.s, d.t, d.n);
    let name = lemma_name(f, w, k);
    let z = d.lit(0);
    let one = d.lit(1);
    Some(match f {
        Family::LzRange => {
            let lo = d.holds("le", &d.pow(k), "x");
            let hi = (k + 1 < n).then(|| d.holds("lt", "x", &d.pow(k + 1)));
            let mut binders = vec![("x", t), (".h1", lo.as_str())];
            if let Some(hi) = &hi {
                binders.push((".h2", hi.as_str()));
            }
            let mut g = Gen::new(&binders);
            let mut hs = vec![d.def_hyp("leading_zeros_def", "x")];
            for m in 0..n {
                let c = d.lz_cond("x", m);
                if m <= k {
                    let pf = g.lin(vec![("h1".into(), lo.clone())], &format!("Eq(Bool, {c}, false)"));
                    hs.push(ind_is(&c, false, &pf));
                } else {
                    let hi = hi.as_ref().expect("k < w−1");
                    let pf = g.lin(vec![("h2".into(), hi.clone())], &format!("Eq(Bool, {c}, true)"));
                    hs.push(ind_is(&c, true, &pf));
                }
            }
            let goal = format!("Eq(U32, {}, {}u32)", d.lz("x"), n - 1 - k);
            let p = g.lin(hs, &goal);
            lemma(g, name, &goal, &p)
        }
        Family::PopcntStep => {
            let xk = d.shr("x", k);
            let y1 = d.shr(&xk, 1);
            // cnt(x >> (k+1)), or 0 at the top bit (`x >> w` would be `x >> 0`)
            let (xk1, rest) = if k + 1 < n {
                let t1 = d.shr("x", k + 1);
                (t1.clone(), format!("#cast_u32_int({})", d.cnt(&t1)))
            } else {
                (z.clone(), "0int".to_string())
            };
            let goal = if k + 1 < n {
                format!("Eq(Int, #cast_u32_int({}), #iadd({rest}, {}))", d.cnt(&xk), d.int(&d.bit("x", k)))
            } else {
                format!("Eq(Int, #cast_u32_int({}), {})", d.cnt(&xk), d.int(&d.bit("x", k)))
            };
            let step: Hyp = (
                format!("bits::popcnt_shr1_{s} ({xk})"),
                format!("Eq(Int, #cast_u32_int({}), #iadd(#cast_u32_int({}), {}))", d.cnt(&xk), d.cnt(&y1), d.int(&d.and(&xk, &one))),
            );
            let cong: Hyp = (
                format!("eq::cong {t} U32 (fun (y : {t}) => {}) ({y1}) ({xk1}) (bvrefl({t}, {y1}, {xk1}))", d.cnt("y")),
                format!("Eq(U32, {}, {})", d.cnt(&y1), d.cnt(&xk1)),
            );
            let mut g = Gen::new(&[("x", t)]);
            let p = g.lin(vec![step, cong], &goal);
            lemma(g, name, &goal, &p)
        }
        Family::PopcntShrZero => {
            let xk = d.shr("x", k);
            let hyp = d.holds("lt", "x", &d.pow(k));
            let mut g = Gen::new(&[("x", t), (".h", &hyp)]);
            let zero_eq = g.lin(vec![("h".into(), hyp.clone())], &d.eq(&xk, &z));
            let goal = format!("Eq(U32, {}, 0u32)", d.cnt(&xk));
            let body =
                format!("transport({t}, {z}, {xk}, eq::sym {t} ({xk}) {z} ({zero_eq}), y. Eq(U32, {}, 0u32), refl(U32, 0u32))", d.cnt("y"));
            lemma(g, name, &goal, &body)
        }
        Family::MaskSplit => {
            let link = if k + 1 < n { d.bv(&d.shr(&d.shr("x", k), 1), &d.shr("x", k + 1)) } else { d.bv(&d.shr(&d.shr("x", k), 1), &z) };
            let mut hs = vec![link];
            if k == 0 {
                // `x >> 0` is not `x` up to conversion: relate its quotient too.
                hs.push(d.bv(&d.shr("x", 1), &d.shr(&d.shr("x", 0), 1)));
            }
            let goal = format!(
                "Eq(Int, {}, #iadd({}, #imul({}int, {})))",
                d.int(&d.and("x", &d.mask(k + 1))),
                d.int(&d.and("x", &d.mask(k))),
                1u128 << k,
                d.int(&d.bit("x", k))
            );
            let mut g = Gen::new(&[("x", t)]);
            let p = g.lin(hs, &goal);
            lemma(g, name, &goal, &p)
        }
        Family::ClzXorPrefix => {
            let xy = d.op("xor", &["x", "y"]);
            let h1 = (k + 1 < n).then(|| d.eq(&d.shr("x", k + 1), &d.shr("y", k + 1)));
            let h2 = d.eq(&d.bit("x", k), &one);
            let h3 = d.eq(&d.bit("y", k), &z);
            let mut binders = vec![("x", t), ("y", t)];
            if let Some(h1) = &h1 {
                binders.push((".h1", h1.as_str()));
            }
            binders.push((".h2", h2.as_str()));
            binders.push((".h3", h3.as_str()));
            let mut g = Gen::new(&binders);
            let mut hs = Vec::new();
            // bit k of x ^ y: (x ^ y) >> k & 1 = (x >> k & 1) ^ (y >> k & 1) = 1 ^ 0.
            let (bx, by) = (d.bit("x", k), d.bit("y", k));
            let xk_bits = d.op("xor", &[&bx, &by]);
            hs.push(d.bv(&d.bit(&xy, k), &xk_bits));
            hs.push((
                format!(
                    "transport({t}, {one}, {bx}, eq::sym {t} ({bx}) {one} h2, u. Eq({t}, #xor_{s}(u, {by}), {one}), transport({t}, {z}, {by}, eq::sym {t} ({by}) {z} h3, v. Eq({t}, #xor_{s}({one}, v), {one}), refl({t}, {one})))"
                ),
                d.eq(&xk_bits, &one),
            ));
            // no bit above k: (x ^ y) >> (k+1) = (x >> (k+1)) ^ (y >> (k+1)) = 0.
            if h1.is_some() {
                let (hx, hy) = (d.shr("x", k + 1), d.shr("y", k + 1));
                let hixy = d.op("xor", &[&hx, &hy]);
                hs.push(d.bv(&d.shr(&xy, k + 1), &hixy));
                hs.push((
                    format!(
                        "transport({t}, {hy}, {hx}, eq::sym {t} ({hx}) ({hy}) h1, u. Eq({t}, #xor_{s}(u, {hy}), {z}), bvrefl({t}, #xor_{s}({hy}, {hy}), {z}))"
                    ),
                    d.eq(&hixy, &z),
                ));
                hs.push(d.bv(&d.shr(&d.shr(&xy, k), 1), &d.shr(&xy, k + 1)));
            } else {
                hs.push(d.bv(&d.shr(&d.shr(&xy, k), 1), &z));
            }
            if k == 0 {
                hs.push(d.bv(&d.shr(&xy, 1), &d.shr(&d.shr(&xy, 0), 1)));
            }
            let lo = g.lin(hs.clone(), &d.holds("le", &d.pow(k), &xy));
            let mut app = format!("bits::lz_range_{s}_{k} ({xy}) .{lo}");
            if k + 1 < n {
                let hi = g.lin(hs, &d.holds("lt", &xy, &d.pow(k + 1)));
                app.push_str(&format!(" .{hi}"));
            }
            let goal = format!("Eq(U32, {}, {}u32)", d.lz(&xy), n - 1 - k);
            lemma(g, name, &goal, &app)
        }
        Family::PopcntSplit => {
            // bit i of x >> k is bit i+k of x (0 past the top); bit i of
            // x & (2^k − 1) is bit i of x below k (0 above)
            let (hi, lo) = (d.shr("x", k), d.and("x", &d.mask(k)));
            let mut hs = vec![d.def_hyp("count_ones_def", "x"), d.def_hyp("count_ones_def", &hi), d.def_hyp("count_ones_def", &lo)];
            for i in 0..n {
                hs.push(d.bv(&d.bit(&hi, i), &if i + k < n { d.bit("x", i + k) } else { z.clone() }));
                hs.push(d.bv(&d.bit(&lo, i), &if i < k { d.bit("x", i) } else { z.clone() }));
            }
            let goal =
                format!("Eq(Int, #cast_u32_int({}), #iadd(#cast_u32_int({}), #cast_u32_int({})))", d.cnt("x"), d.cnt(&hi), d.cnt(&lo));
            let mut g = Gen::new(&[("x", t)]);
            let p = g.lin(hs, &goal);
            lemma(g, name, &goal, &p)
        }
        Family::PopcntLowStep => {
            let (m1, m0) = (d.and("x", &d.mask(k + 1)), d.and("x", &d.mask(k)));
            let mut hs = vec![d.def_hyp("count_ones_def", &m1), d.def_hyp("count_ones_def", &m0)];
            for i in 0..n {
                hs.push(d.bv(&d.bit(&m1, i), &if i <= k { d.bit("x", i) } else { z.clone() }));
                hs.push(d.bv(&d.bit(&m0, i), &if i < k { d.bit("x", i) } else { z.clone() }));
            }
            let goal = format!("Eq(Int, #cast_u32_int({}), #iadd(#cast_u32_int({}), {}))", d.cnt(&m1), d.cnt(&m0), d.int(&d.bit("x", k)));
            let mut g = Gen::new(&[("x", t)]);
            let p = g.lin(hs, &goal);
            lemma(g, name, &goal, &p)
        }
        Family::TzRange => {
            // m ≤ k: x & (2^m − 1) = (x & (2^(k+1) − 1)) & (2^m − 1) = 2^k & (2^m − 1) = 0;
            // m > k: (x & (2^m − 1)) & (2^(k+1) − 1) = 2^k, so x & (2^m − 1) ≠ 0.
            let low = d.and("x", &d.mask(k + 1));
            let hyp = d.eq(&low, &d.pow(k));
            let mut g = Gen::new(&[("x", t), (".h", &hyp)]);
            let mut hs = vec![d.def_hyp("trailing_zeros_def", "x")];
            for m in 1..=n {
                let xm = d.and("x", &d.mask(m));
                let c = d.tz_cond("x", m);
                if m <= k {
                    let inner = format!(
                        "transport({t}, {pk}, {low}, eq::sym {t} ({low}) {pk} h, y. Eq({t}, #and_{s}(y, {mm}), {z}), refl({t}, {z}))",
                        pk = d.pow(k),
                        mm = d.mask(m)
                    );
                    let em = format!(
                        "eq::trans {t} ({xm}) (#and_{s}({low}, {mm})) {z} (bvrefl({t}, {xm}, #and_{s}({low}, {mm}))) ({inner})",
                        mm = d.mask(m)
                    );
                    let pf = format!(
                        "transport({t}, {z}, {xm}, eq::sym {t} ({xm}) {z} ({em}), y. Eq(Bool, #eq_{s}(y, {z}), true), refl(Bool, true))"
                    );
                    hs.push(ind_is(&c, true, &pf));
                } else {
                    let link = d.bv(&d.and(&xm, &d.mask(k + 1)), &low);
                    let pf = g.lin(vec![link, ("h".into(), hyp.clone())], &format!("Eq(Bool, {c}, false)"));
                    hs.push(ind_is(&c, false, &pf));
                }
            }
            let goal = format!("Eq(U32, {}, {k}u32)", d.tz("x"));
            let p = g.lin(hs, &goal);
            lemma(g, name, &goal, &p)
        }
        Family::PopcntLe => {
            let hyp = d.holds("lt", "x", &d.pow(k));
            let goal = d.bound(&d.cnt("x"), k, false);
            let mut g = Gen::new(&[("x", t), (".h", &hyp)]);
            if k == 0 {
                // x < 1: x = 0, and cnt(0) computes to 0
                let zero_eq = g.lin(vec![("h".into(), hyp.clone())], &d.eq("x", &z));
                let body = format!("transport({t}, {z}, x, eq::sym {t} x {z} ({zero_eq}), y. {}, refl(Bool, true))", d.bound(&d.cnt("y"), 0, false));
                lemma(g, name, &goal, &body)
            } else {
                // cnt(x) ≤ cnt(x >> k) + k (`popcnt_shr_le_k`), the shift 0
                // (x < 2^k, `popcnt_shr_zero_k`)
                let shr_le = |k: u32| format!("Eq(Bool, #le_int(#cast_u32_int({}), #iadd(#cast_u32_int({}), {k}int)), true)", d.cnt("x"), d.cnt(&d.shr("x", k)));
                let hs: Vec<Hyp> = vec![
                    (format!("bits::popcnt_shr_le_{s}_{k} x"), shr_le(k)),
                    (format!("bits::popcnt_shr_zero_{s}_{k} x .h"), format!("Eq(U32, {}, 0u32)", d.cnt(&d.shr("x", k)))),
                ];
                let p = g.lin(hs, &goal);
                lemma(g, name, &goal, &p)
            }
        }
        Family::PopcntShrLe => {
            // cnt(x) ≤ cnt(x >> (k−1)) + (k − 1) and cnt(x >> (k−1)) =
            // cnt(x >> k) + bit_(k−1) ≤ cnt(x >> k) + 1 (k = 1: `popcnt_shr1`)
            let shr_le = |k: u32| format!("Eq(Bool, #le_int(#cast_u32_int({}), #iadd(#cast_u32_int({}), {k}int)), true)", d.cnt("x"), d.cnt(&d.shr("x", k)));
            let mut hs: Vec<Hyp> = Vec::new();
            if k == 1 {
                hs.push((
                    format!("bits::popcnt_shr1_{s} x"),
                    format!("Eq(Int, #cast_u32_int({}), #iadd(#cast_u32_int({}), {}))", d.cnt("x"), d.cnt(&d.shr("x", 1)), d.int(&d.and("x", &one))),
                ));
            } else {
                let (xi, xi1) = (d.shr("x", k - 1), d.shr("x", k));
                hs.push((format!("bits::popcnt_shr_le_{s}_{} x", k - 1), shr_le(k - 1)));
                hs.push((
                    format!("bits::popcnt_step_{s}_{} x", k - 1),
                    format!("Eq(Int, #cast_u32_int({}), #iadd(#cast_u32_int({}), {}))", d.cnt(&xi), d.cnt(&xi1), d.int(&d.bit("x", k - 1))),
                ));
            }
            let goal = shr_le(k);
            let mut g = Gen::new(&[("x", t)]);
            let p = g.lin(hs, &goal);
            lemma(g, name, &goal, &p)
        }
        Family::LzLower => {
            // [x < 2^m] = 1 for m ≥ k: lz(x) = Σ_m [x < 2^m] ≥ w − k
            let hyp = d.holds("lt", "x", &d.pow(k));
            let mut g = Gen::new(&[("x", t), (".h", &hyp)]);
            let mut hs = vec![d.def_hyp("leading_zeros_def", "x")];
            for m in 0..n {
                let c = d.lz_cond("x", m);
                if m >= k {
                    let pf = g.lin(vec![("h".into(), hyp.clone())], &format!("Eq(Bool, {c}, true)"));
                    hs.push(ind_is(&c, true, &pf));
                } else {
                    hs.push(ind_bound(&c, false));
                }
            }
            let goal = format!("Eq(Bool, #le_u32({}u32, {}), true)", n - k, d.lz("x"));
            let p = g.lin(hs, &goal);
            lemma(g, name, &goal, &p)
        }
        Family::LzGe => {
            // by cases on x < 2^k: in the `false` arm, [x < 2^m] = 0 for
            // m ≤ k, so lz(x) ≤ w − 1 − k, against the hypothesis
            let hyp = format!("Eq(Bool, #le_u32({}u32, {}), true)", n - k, d.lz("x"));
            let test = format!("#lt_{s}(x, {})", d.pow(k));
            let ef = format!("Eq(Bool, {test}, false)");
            let mut g = Gen::new(&[("x", t), (".h", &hyp), (".e", &ef)]);
            let mut hs = vec![d.def_hyp("leading_zeros_def", "x"), ("h".into(), hyp.clone())];
            for m in 0..n {
                let c = d.lz_cond("x", m);
                if m <= k {
                    let pf = g.lin(vec![("e".into(), ef.clone())], &format!("Eq(Bool, {c}, false)"));
                    hs.push(ind_is(&c, false, &pf));
                } else {
                    hs.push(ind_bound(&c, true));
                }
            }
            let empty = g.lin(hs, "Empty");
            g.binders.pop();
            let goal = d.holds("lt", "x", &d.pow(k));
            let body = format!(
                "(match {test} : Bool as y return (.e : Eq(Bool, {test}, y)) -> Eq(Bool, y, true) with
     | false => fun (.e : {ef}) => absurd(Eq(Bool, false, true), {empty})
     | true => fun (.e : Eq(Bool, {test}, true)) => refl(Bool, true)
     end) .refl(Bool, {test})"
            );
            lemma(g, name, &goal, &body)
        }
        Family::TzShr1 => tz_shr1(d),
        Family::WshlExact => {
            let bound = d.lit(d.max() >> k);
            let hyp = d.holds("le", "a", &bound);
            let p = d.pow(k);
            let mut g = Gen::new(&[("a", t), (".h", &hyp)]);
            let pf = g.lin(
                vec![("h".into(), hyp.clone())],
                &format!("Eq(Bool, #le_int(#imul({}, {}), {}int), true)", d.int("a"), d.int(&p), d.max()),
            );
            let lhs = format!("#wshl_{s}(a, {k}u32)");
            let rhs = format!("#mul_{s}(a, {p}; {pf})");
            lemma(g, name, &d.eq(&lhs, &rhs), &format!("bvrefl({t}, {lhs}, {rhs})"))
        }
        Family::ShlExact => {
            let bound = d.lit(d.max() >> k);
            let hyp = d.holds("le", "a", &bound);
            let p = d.pow(k);
            let mut g = Gen::new(&[("a", t), (".h", &hyp)]);
            let pf = g.lin(
                vec![("h".into(), hyp.clone())],
                &format!("Eq(Bool, #le_int(#imul({}, {}), {}int), true)", d.int("a"), d.int(&p), d.max()),
            );
            let lhs = format!("#shl_{s}(a, {k}u32; refl(Bool, #lt_u32({k}u32, {n}u32)))");
            let rhs = format!("#mul_{s}(a, {p}; {pf})");
            lemma(g, name, &d.eq(&lhs, &rhs), &format!("bvrefl({t}, {lhs}, {rhs})"))
        }
    })
}

/// Add a family member (and the members its proof uses) to `env` unless
/// it is already there; returns its global.
pub fn ensure(env: &mut Env, f: Family, w: Width, k: u32, b: &mut Budget) -> Result<GlobalId, KernelError> {
    let name = lemma_name(f, w, k);
    if let Some(g) = env.lookup_global(&name) {
        return Ok(g);
    }
    for (df, dw, dk) in deps(f, w, k) {
        ensure(env, df, dw, dk, b)?;
    }
    let Some(item) = family_item(f, w, k) else {
        return Err(KernelError { kind: KernelErrorKind::IllFormed, message: format!("{name}: out of range") });
    };
    load_family_item(env, &format!("{}_{}", f.stem(), wd(w).s), &item, b)?;
    env.lookup_global(&name).ok_or_else(|| KernelError { kind: KernelErrorKind::IllFormed, message: format!("{name}: not added") })
}
