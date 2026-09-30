//! The word-algebra normal forms of `bvnorm` (DESIGN.md §9.8, rules 1–7).
//! **TRUSTED.**
//!
//! Every rule is an exact identity on `w`-bit words (`n = bits(w)`,
//! `~0 = 2^n − 1`, all arithmetic mod `2^n`); the builders apply them to
//! argument *classes* and return the class of the canonical result.
//!
//! 1. **Constants and amounts.** Every total primitive on literal classes is
//!    folded with the kernel's own literal semantics
//!    ([`crate::prim::eval_lits`]); shift and rotation amounts are reduced
//!    mod `n` (`wshl/wshr/rotl/rotr` take their amount mod `n`, §5.7), so
//!    `rotr(x, 0) = x` and `rotl(x, k) = rotr(x, (n − k) mod n)`. Checked
//!    `add/sub/mul` are treated as their wrapping forms and checked
//!    `shl/shr` as `wshl/wshr`: the checked forms only occur with a proof
//!    that they are in their domain, where they agree (the same reading as
//!    the §5.7 simplifications and linarith). `gt/ge(a, b)` are `lt/le(b,
//!    a)`; commutative operators sort their arguments; `eq/le(a, a) = true`,
//!    `ne/lt(a, a) = false`.
//! 2. `not(x) = x ⊕ ~0`.
//! 3. **GF(2)-linear forms** ([`Lin`]): `c ⊕ ⨁ᵢ (rotr(aᵢ, rᵢ) & mᵢ)`, one
//!    term per `(atom, rotation)`, sorted by `(class, rotation)`, masks
//!    nonzero. `rotr(x, r)` is the term `(x, r, ~0)`; `wshr(x, s) =
//!    rotr(x, s) & (~0 >> s)`; `wshl(x, s) = rotr(x, n − s) & (~0 << s)`.
//!    Rotations distribute over `⊕` and `&` (a bit permutation), and `&`
//!    distributes over `⊕`, so shifts and rotations of a linear form act on
//!    every term and on the constant; `⊕` merges terms with the same `(atom,
//!    r)` by `(x & m₁) ⊕ (x & m₂) = x & (m₁ ⊕ m₂)` and drops zero masks. A
//!    literal mask keeps a form linear (`L & k` masks every term and the
//!    constant; `L | k = (L & ~k) ⊕ k`). Shifts never pass through `not`
//!    except through rule 2 (the constant `~0` is shifted too).
//!    **Known-zero bits:** every integer class has a support mask (bits that
//!    may be nonzero); term masks are reduced to the support of their
//!    rotated atom, so equal functions get equal masks.
//! 4. **`and`/`or` sets** sorted by class id, flattened through nested sets
//!    (and through truth tables that are plain conjunctions/disjunctions of
//!    their variables), idempotent; `x & 0 = 0`, `x & ~0 = x`, `x | 0 = x`,
//!    `x | ~0 = ~0` (literal masks, rule 3); operands with disjoint supports
//!    give `x & y = 0` and `x | y = x ⊕ y`.
//! 5. **Truth tables** ([`Tt`]): a bitwise combination (`and/or/xor/not`,
//!    constants `0/~0`) whose operands expand to ≤ 4 distinct variables —
//!    atoms, or single rotated/masked linear terms — is the truth table of
//!    the function over its variables sorted by class id, reduced to its
//!    essential variables. An affine table (`c ⊕ x₁ ⊕ … ⊕ xₖ`) becomes the
//!    linear form of its variables, so rules 3 and 5 agree (Ch:
//!    `(e & f) ⊕ (¬e & g) = ((f ⊕ g) & e) ⊕ g`; Maj: `(x&y) ⊕ (x&z) ⊕ (y&z) =
//!    (x & y) | ((x | y) & z)`).
//! 6. **Sums** ([`SumF`]): `wadd/wsub/wneg`, `wmul` by a literal and `wshl(x,
//!    k)` (as the coefficient `2^k`: a linear term that is exactly `x << k`)
//!    give `c + Σ kᵢ·aᵢ mod 2^n` with atoms sorted by class id and nonzero
//!    coefficients, flattened through child sums. `wshr`, `rotr` and
//!    zero-extension never enter or distribute over sums (a shifted or
//!    rotated sum is a linear term *of* the sum; a zero-extended sum is a
//!    view of it); truncation passes through sums (a ring homomorphism).
//! 7. **Bit-slice concatenation**, realized on linear forms: `|`, `⊕` and
//!    `+` of operands with **provably disjoint** supports are the same word
//!    (no bit is set in both, so there is no carry), so a sum whose
//!    coefficients are powers of two and whose shifted summands have
//!    pairwise disjoint supports is the linear form `⨁ (aᵢ << kᵢ)`, and a
//!    linear form whose terms are pairwise disjoint expands back into a sum
//!    when it is added to something. Segments are terms: adjacent segments
//!    of the same atom at consecutive offsets are one term (their masks
//!    merge), so `(x >> 2) | (x << 30) = rotr(x, 2)` and the four bytes of
//!    `x` in order are `x`. Width changes are exact bit maps: every bit of a
//!    *base atom* `B` has one canonical home at each width — `B` itself,
//!    the zero-extension view `Zext(W, B)` (bits above `B`'s width known
//!    zero), or the chunk view `Chunk(W, B, k)` (bits `[k·W, (k+1)·W)` of a
//!    wider `B`) — and truncation or zero-extension of a linear form moves
//!    every bit of every term to its home at the new width. Views of
//!    `and/or` sets and truth tables distribute (bitwise operators commute
//!    with truncation, and with zero-extension when `f(0, …, 0) = 0`), and
//!    the low chunk of a sum is the sum of the truncated summands. A class
//!    that such a distribution *creates* (a sum, set or truth table that did
//!    not exist before) is the low chunk of its base `B` and is recorded as
//!    such (`lows`): its bits resolve to `B`'s bits, so zero-extending or
//!    re-chunking it returns to `B`'s homes (the low byte of a sum `s`,
//!    zero-extended beside the byte `(s >> 8) as u8`, is the low half of
//!    `s`; the four bytes of `s` regrouped into two 16-bit halves and back
//!    are `s`). A class that existed before keeps its own views.

use super::{ClassId, Key, Norm};
use crate::prim::{LitOut, PrimTy, prim_sig};
use crate::term::{BigInt, PrimOp, Width};

/// Number of bits of a machine width.
pub(crate) fn bits(w: Width) -> u32 {
    w.bits().unwrap_or(0)
}

fn maskn(n: u32) -> u64 {
    if n >= 64 { u64::MAX } else { (1u64 << n) - 1 }
}

/// `2^bits(w) − 1`.
pub(crate) fn mask(w: Width) -> u64 {
    maskn(bits(w))
}

fn rotr(x: u64, k: u32, n: u32) -> u64 {
    let k = k % n;
    if k == 0 { x } else { ((x >> k) | (x << (n - k))) & maskn(n) }
}

/// All bits up to the highest set bit of `m`.
fn smear(m: u64) -> u64 {
    if m == 0 { 0 } else { u64::MAX >> m.leading_zeros() }
}

/// View kinds of [`Norm::view_class`] besides chunk indices.
const IDENT: u32 = u32::MAX - 1;
const ZEXT: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// Linear forms (rules 2, 3, 7).
// ---------------------------------------------------------------------------

/// `c ⊕ ⨁ (rotr(atom, r) & m)`: out bit `j` of a term is `m_j ∧
/// atom_{(j + r) mod n}`.
#[derive(Clone, Debug, Default)]
pub(crate) struct Lin {
    pub c: u64,
    pub t: Vec<(ClassId, u32, u64)>,
}

impl Lin {
    fn konst(c: u64) -> Lin {
        Lin { c, t: Vec::new() }
    }

    /// Sort by `(atom, rotation)`, merge equal pairs, drop zero masks.
    fn normalize(mut self) -> Lin {
        self.t.sort_unstable_by_key(|&(a, r, _)| (a, r));
        let mut out: Vec<(ClassId, u32, u64)> = Vec::with_capacity(self.t.len());
        for (a, r, m) in self.t {
            match out.last_mut() {
                Some(last) if last.0 == a && last.1 == r => last.2 ^= m,
                _ => out.push((a, r, m)),
            }
        }
        out.retain(|t| t.2 != 0);
        Lin { c: self.c, t: out }
    }

    fn rotr(&self, k: u32, n: u32) -> Lin {
        let k = k % n;
        if k == 0 {
            return self.clone();
        }
        Lin { c: rotr(self.c, k, n), t: self.t.iter().map(|&(a, r, m)| (a, (r + k) % n, rotr(m, k, n))).collect() }.normalize()
    }

    fn and_mask(&self, m: u64) -> Lin {
        Lin { c: self.c & m, t: self.t.iter().map(|&(a, r, x)| (a, r, x & m)).collect() }.normalize()
    }

    fn xor(&self, o: &Lin) -> Lin {
        let mut t = self.t.clone();
        t.extend_from_slice(&o.t);
        Lin { c: self.c ^ o.c, t }.normalize()
    }

    fn wshr(&self, s: u32, n: u32) -> Lin {
        self.rotr(s, n).and_mask(maskn(n) >> s)
    }

    fn wshl(&self, s: u32, n: u32) -> Lin {
        self.rotr((n - s) % n, n).and_mask((maskn(n) << s) & maskn(n))
    }

    /// Bits that may be nonzero.
    fn supp(&self) -> u64 {
        self.t.iter().fold(self.c, |a, t| a | t.2)
    }

    /// Are the constant and the term masks pairwise disjoint?
    fn disjoint(&self) -> bool {
        let mut used = self.c;
        for t in &self.t {
            if used & t.2 != 0 {
                return false;
            }
            used |= t.2;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Truth tables (rule 5).
// ---------------------------------------------------------------------------

/// A boolean function of ≤ 4 variables sorted by class id: bit `idx` of `tt`
/// is the value on the assignment where variable `i` is bit `i` of `idx`.
#[derive(Clone, Debug)]
pub(crate) struct Tt {
    pub vars: Vec<ClassId>,
    pub tt: u16,
}

fn full(k: usize) -> u16 {
    if k >= 4 { 0xFFFF } else { ((1u32 << (1u32 << k)) - 1) as u16 }
}

/// The table of `x₁ ∧ … ∧ xₖ`.
fn and_all(k: usize) -> u16 {
    1u16 << ((1usize << k) - 1)
}

/// The table of `x₁ ∨ … ∨ xₖ`.
fn or_all(k: usize) -> u16 {
    full(k) & !1
}

impl Tt {
    fn var(c: ClassId) -> Tt {
        Tt { vars: vec![c], tt: 0b10 }
    }

    fn konst(b: bool) -> Tt {
        Tt { vars: Vec::new(), tt: b as u16 }
    }

    /// The table over the (sorted) superset `u` of `self.vars`.
    fn expand(&self, u: &[ClassId]) -> u16 {
        let pos: Vec<usize> = self.vars.iter().map(|v| u.iter().position(|x| x == v).expect("superset")).collect();
        let mut out = 0u16;
        for idx in 0..(1usize << u.len()) {
            let mut sub = 0usize;
            for (i, &p) in pos.iter().enumerate() {
                if (idx >> p) & 1 == 1 {
                    sub |= 1 << i;
                }
            }
            if (self.tt >> sub) & 1 == 1 {
                out |= 1 << idx;
            }
        }
        out
    }

    fn compose(a: &Tt, b: &Tt, f: fn(u16, u16) -> u16) -> Option<Tt> {
        let mut u = a.vars.clone();
        u.extend_from_slice(&b.vars);
        u.sort_unstable();
        u.dedup();
        if u.len() > 4 {
            return None;
        }
        let tt = f(a.expand(&u), b.expand(&u)) & full(u.len());
        Some(Tt { vars: u, tt }.reduce())
    }

    /// Drop the variables the function does not depend on.
    fn reduce(mut self) -> Tt {
        let mut i = 0;
        while i < self.vars.len() {
            let k = self.vars.len();
            let essential =
                (0..(1usize << k)).any(|idx| (idx >> i) & 1 == 0 && ((self.tt >> idx) & 1) != ((self.tt >> (idx | (1 << i))) & 1));
            if essential {
                i += 1;
                continue;
            }
            let mut nt = 0u16;
            for ni in 0..(1usize << (k - 1)) {
                let lo = ni & ((1 << i) - 1);
                let hi = ni >> i;
                if (self.tt >> (lo | (hi << (i + 1)))) & 1 == 1 {
                    nt |= 1 << ni;
                }
            }
            self.vars.remove(i);
            self.tt = nt;
        }
        self
    }

    /// `Some(c)` iff the (reduced) function is `c ⊕ x₁ ⊕ … ⊕ xₖ`.
    fn affine(&self) -> Option<bool> {
        let c = self.tt & 1 == 1;
        for idx in 0..(1usize << self.vars.len()) {
            let parity = idx.count_ones() & 1 == 1;
            if ((self.tt >> idx) & 1 == 1) != (c ^ parity) {
                return None;
            }
        }
        Some(c)
    }
}

// ---------------------------------------------------------------------------
// Sums (rule 6).
// ---------------------------------------------------------------------------

/// `c + Σ k·atom mod 2^n`.
#[derive(Clone, Debug, Default)]
pub(crate) struct SumF {
    pub c: u64,
    pub t: Vec<(ClassId, u64)>,
}

impl SumF {
    fn normalize(mut self, w: Width) -> SumF {
        let m = mask(w);
        self.t.sort_unstable_by_key(|x| x.0);
        let mut out: Vec<(ClassId, u64)> = Vec::with_capacity(self.t.len());
        for (a, k) in self.t {
            match out.last_mut() {
                Some(last) if last.0 == a => last.1 = last.1.wrapping_add(k) & m,
                _ => out.push((a, k & m)),
            }
        }
        out.retain(|x| x.1 != 0);
        SumF { c: self.c & m, t: out }
    }

    /// Sum of two normalized sums (a linear merge of the sorted terms).
    fn add(self, o: SumF, w: Width) -> SumF {
        let m = mask(w);
        let mut t = Vec::with_capacity(self.t.len() + o.t.len());
        let (mut i, mut j) = (0, 0);
        while i < self.t.len() || j < o.t.len() {
            let take_left = j >= o.t.len() || (i < self.t.len() && self.t[i].0 < o.t[j].0);
            let take_right = i >= self.t.len() || (j < o.t.len() && o.t[j].0 < self.t[i].0);
            if take_left {
                t.push(self.t[i]);
                i += 1;
            } else if take_right {
                t.push(o.t[j]);
                j += 1;
            } else {
                let k = self.t[i].1.wrapping_add(o.t[j].1) & m;
                if k != 0 {
                    t.push((self.t[i].0, k));
                }
                i += 1;
                j += 1;
            }
        }
        SumF { c: self.c.wrapping_add(o.c) & m, t }
    }

    fn scale(self, k: u64, w: Width) -> SumF {
        SumF { c: self.c.wrapping_mul(k), t: self.t.into_iter().map(|(a, x)| (a, x.wrapping_mul(k))).collect() }.normalize(w)
    }
}

// ---------------------------------------------------------------------------
// Builders.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum ShiftKind {
    Shl,
    Shr,
    Rotr,
    Rotl,
}

impl Norm<'_> {
    pub(crate) fn lit(&mut self, w: Width, n: u64) -> ClassId {
        let n = n & mask(w);
        self.intern(Key::Lit(w, n), Some(w), Some(n))
    }

    fn lit_val(&self, c: ClassId) -> Option<u64> {
        match self.key(c) {
            Key::Lit(_, n) => Some(*n),
            _ => None,
        }
    }

    pub(crate) fn width(&self, c: ClassId) -> Option<Width> {
        self.classes[c as usize].width
    }

    /// Record the width `c` is used at; a second, different width sets
    /// `width_clash` (the problem is then rejected, see the module `bvnorm`).
    fn note_width(&mut self, c: ClassId, w: Width) {
        let info = &mut self.classes[c as usize];
        match info.width {
            None => info.width = Some(w),
            Some(w0) => self.width_clash |= w0 != w,
        }
    }

    /// Bits of `c` (used at width `w`) that may be nonzero.
    pub(crate) fn supp(&self, c: ClassId, w: Width) -> u64 {
        let m = mask(w);
        match self.classes[c as usize].supp {
            Some(s) => s & m,
            None => m,
        }
    }

    fn is_and(&self, c: ClassId) -> bool {
        matches!(self.key(c), Key::And(..))
    }

    fn is_or(&self, c: ClassId) -> bool {
        matches!(self.key(c), Key::Or(..))
    }

    // ---- linear forms ----

    /// The linear form of `c` at width `w` (an atom is the term `(c, 0,
    /// supp c)`).
    fn lin_of(&mut self, c: ClassId, w: Width) -> Lin {
        self.note_width(c, w);
        match self.key(c) {
            Key::Lit(_, n) => Lin::konst(*n),
            Key::Lin(_, k, t) => Lin { c: *k, t: t.clone() },
            _ => {
                let s = self.supp(c, w);
                if s == 0 { Lin::konst(0) } else { Lin { c: 0, t: vec![(c, 0, s)] } }
            }
        }
    }

    /// The class of a (normalized) linear form.
    fn lin_class(&mut self, w: Width, l: Lin) -> ClassId {
        if l.t.is_empty() {
            return self.lit(w, l.c);
        }
        if l.c == 0 && l.t.len() == 1 {
            let (a, r, m) = l.t[0];
            if r == 0 && m == self.supp(a, w) {
                return a;
            }
            // Rule 6: `wshl(s, k)` of a sum `s` is the sum `2^k·s`.
            let n = bits(w);
            let sh = (n - r) % n;
            if matches!(self.key(a), Key::Sum(..)) && m == (self.supp(a, w) << sh) & mask(w) {
                let s = self.sum_of(a, w).scale(1u64 << sh, w);
                return self.sum_class(w, s);
            }
        }
        let s = l.supp();
        self.intern(Key::Lin(w, l.c, l.t), Some(w), Some(s))
    }

    fn term_class(&mut self, w: Width, t: (ClassId, u32, u64)) -> ClassId {
        self.lin_class(w, Lin { c: 0, t: vec![t] })
    }

    fn shift(&mut self, kind: ShiftKind, a: ClassId, k: u64, w: Width) -> ClassId {
        let n = bits(w);
        let k = (k % n as u64) as u32;
        let l = self.lin_of(a, w);
        let r = match kind {
            ShiftKind::Rotr => l.rotr(k, n),
            ShiftKind::Rotl => l.rotr((n - k) % n, n),
            ShiftKind::Shr => l.wshr(k, n),
            ShiftKind::Shl => l.wshl(k, n),
        };
        self.lin_class(w, r)
    }

    // ---- truth tables ----

    /// The truth-table view of `c`: its expansion into ≤ 4 variables if it
    /// is a bitwise combination, else `c` itself as a variable; `None` for a
    /// literal other than `0`/`~0`.
    fn ttv(&mut self, c: ClassId, w: Width) -> Option<Tt> {
        match self.key(c).clone() {
            Key::Lit(_, n) => {
                if n == 0 {
                    Some(Tt::konst(false))
                } else if n == mask(w) {
                    Some(Tt::konst(true))
                } else {
                    None
                }
            }
            Key::Tt(_, vars, tt) => Some(Tt { vars, tt }),
            Key::Lin(_, k, t) if k == 0 || k == mask(w) => {
                let mut acc = Tt::konst(k != 0);
                for (a, r, m) in t {
                    let tv = if r == 0 && m == self.supp(a, w) { self.ttv(a, w) } else { Some(Tt::var(self.term_class(w, (a, r, m)))) };
                    match tv.and_then(|tv| Tt::compose(&acc, &tv, |x, y| x ^ y)) {
                        Some(x) => acc = x,
                        None => return Some(Tt::var(c)),
                    }
                }
                Some(acc)
            }
            _ => Some(Tt::var(c)),
        }
    }

    /// The class of a truth table (affine tables become linear forms).
    fn tt_class(&mut self, w: Width, t: Tt) -> ClassId {
        let t = t.reduce();
        if t.vars.is_empty() {
            return self.lit(w, if t.tt & 1 == 1 { mask(w) } else { 0 });
        }
        if let Some(c) = t.affine() {
            let mut l = Lin::konst(if c { mask(w) } else { 0 });
            for &v in &t.vars {
                let lv = self.lin_of(v, w);
                l = l.xor(&lv);
            }
            return self.lin_class(w, l);
        }
        let s = self.tt_supp(&t, w);
        self.intern(Key::Tt(w, t.vars, t.tt), Some(w), Some(s))
    }

    /// Bits a truth table may set, given its variables' supports.
    fn tt_supp(&self, t: &Tt, w: Width) -> u64 {
        let k = t.vars.len();
        let sv: Vec<u64> = t.vars.iter().map(|&v| self.supp(v, w)).collect();
        let mut any = [false; 16];
        for (s, slot) in any.iter_mut().enumerate().take(1 << k) {
            *slot = (0..(1usize << k)).any(|idx| idx & !s == 0 && (t.tt >> idx) & 1 == 1);
        }
        let mut out = 0u64;
        for j in 0..bits(w) {
            let s = (0..k).filter(|&i| (sv[i] >> j) & 1 == 1).fold(0usize, |a, i| a | (1 << i));
            if any[s] {
                out |= 1 << j;
            }
        }
        out
    }

    /// Apply the table `f` (over `ops.len()` variables) to operand classes.
    fn tt_apply(&mut self, ops: &[ClassId], f: u16, w: Width) -> Option<ClassId> {
        let mut tvs = Vec::with_capacity(ops.len());
        for &o in ops {
            tvs.push(self.ttv(o, w)?);
        }
        let mut u: Vec<ClassId> = tvs.iter().flat_map(|t| t.vars.iter().copied()).collect();
        u.sort_unstable();
        u.dedup();
        if u.len() > 4 {
            return None;
        }
        let ex: Vec<u16> = tvs.iter().map(|t| t.expand(&u)).collect();
        let mut tt = 0u16;
        for idx in 0..(1usize << u.len()) {
            let mut sub = 0usize;
            for (i, e) in ex.iter().enumerate() {
                if (e >> idx) & 1 == 1 {
                    sub |= 1 << i;
                }
            }
            if (f >> sub) & 1 == 1 {
                tt |= 1 << idx;
            }
        }
        Some(self.tt_class(w, Tt { vars: u, tt }))
    }

    // ---- bitwise operators ----

    fn xor_c(&mut self, a: ClassId, b: ClassId, w: Width) -> ClassId {
        if a == b {
            return self.lit(w, 0);
        }
        if self.lit_val(a).is_none()
            && self.lit_val(b).is_none()
            && let (Some(ta), Some(tb)) = (self.ttv(a, w), self.ttv(b, w))
            && let Some(t) = Tt::compose(&ta, &tb, |x, y| x ^ y)
        {
            return self.tt_class(w, t);
        }
        let (la, lb) = (self.lin_of(a, w), self.lin_of(b, w));
        self.lin_class(w, la.xor(&lb))
    }

    fn and_c(&mut self, a: ClassId, b: ClassId, w: Width) -> ClassId {
        for (x, y) in [(a, b), (b, a)] {
            if let Some(k) = self.lit_val(y) {
                let l = self.lin_of(x, w).and_mask(k);
                return self.lin_class(w, l);
            }
        }
        if self.supp(a, w) & self.supp(b, w) == 0 {
            return self.lit(w, 0);
        }
        if a == b {
            return a;
        }
        if !self.is_and(a)
            && !self.is_and(b)
            && let (Some(ta), Some(tb)) = (self.ttv(a, w), self.ttv(b, w))
            && let Some(t) = Tt::compose(&ta, &tb, |x, y| x & y)
        {
            return self.tt_class(w, t);
        }
        let mut ops = self.set_ops(a, true);
        ops.extend(self.set_ops(b, true));
        ops.sort_unstable();
        ops.dedup();
        if ops.len() == 1 {
            return ops[0];
        }
        let s = ops.iter().fold(mask(w), |acc, &o| acc & self.supp(o, w));
        self.intern(Key::And(w, ops), Some(w), Some(s))
    }

    fn or_c(&mut self, a: ClassId, b: ClassId, w: Width) -> ClassId {
        for (x, y) in [(a, b), (b, a)] {
            if let Some(k) = self.lit_val(y) {
                let l = self.lin_of(x, w).and_mask(!k & mask(w)).xor(&Lin::konst(k));
                return self.lin_class(w, l);
            }
        }
        if self.supp(a, w) & self.supp(b, w) == 0 {
            return self.xor_c(a, b, w);
        }
        if a == b {
            return a;
        }
        if !self.is_or(a)
            && !self.is_or(b)
            && let (Some(ta), Some(tb)) = (self.ttv(a, w), self.ttv(b, w))
            && let Some(t) = Tt::compose(&ta, &tb, |x, y| x | y)
        {
            return self.tt_class(w, t);
        }
        let mut ops = self.set_ops(a, false);
        ops.extend(self.set_ops(b, false));
        ops.sort_unstable();
        ops.dedup();
        if ops.len() == 1 {
            return ops[0];
        }
        let s = ops.iter().fold(0, |acc, &o| acc | self.supp(o, w));
        self.intern(Key::Or(w, ops), Some(w), Some(s))
    }

    /// The operands of an `and` (`is_and`) or `or` set, flattening nested
    /// sets and truth tables that are the plain conjunction/disjunction of
    /// their variables.
    fn set_ops(&self, c: ClassId, is_and: bool) -> Vec<ClassId> {
        match self.key(c) {
            Key::And(_, ops) if is_and => ops.clone(),
            Key::Or(_, ops) if !is_and => ops.clone(),
            Key::Tt(_, vars, tt) if *tt == if is_and { and_all(vars.len()) } else { or_all(vars.len()) } => vars.clone(),
            _ => vec![c],
        }
    }

    // ---- sums ----

    fn sum_of(&mut self, c: ClassId, w: Width) -> SumF {
        self.note_width(c, w);
        match self.key(c).clone() {
            Key::Lit(_, n) => SumF { c: n, t: Vec::new() },
            Key::Sum(_, k, t) => SumF { c: k, t },
            Key::Lin(_, k, t) if (Lin { c: k, t: t.clone() }).disjoint() => {
                let n = bits(w);
                let mut s = SumF { c: k, t: Vec::new() };
                for (a, r, m) in t {
                    let sh = (n - r) % n;
                    if m == (self.supp(a, w) << sh) & mask(w) {
                        let sa = self.sum_of(a, w).scale(1u64 << sh, w);
                        s = s.add(sa, w);
                    } else {
                        let tc = self.term_class(w, (a, r, m));
                        s = s.add(SumF { c: 0, t: vec![(tc, 1)] }, w);
                    }
                }
                s
            }
            _ => SumF { c: 0, t: vec![(c, 1)] },
        }
    }

    fn sum_class(&mut self, w: Width, s: SumF) -> ClassId {
        let s = s.normalize(w);
        if s.t.is_empty() {
            return self.lit(w, s.c);
        }
        let n = bits(w);
        // Rule 7: power-of-two coefficients with disjoint shifted supports.
        if s.t.iter().all(|x| x.1.is_power_of_two()) {
            let mut used = s.c;
            let mut ok = true;
            for &(a, k) in &s.t {
                let sp = (self.supp(a, w) << k.trailing_zeros()) & mask(w);
                if sp & used != 0 {
                    ok = false;
                    break;
                }
                used |= sp;
            }
            if ok {
                let mut l = Lin::konst(s.c);
                for &(a, k) in &s.t {
                    let la = self.lin_of(a, w).wshl(k.trailing_zeros(), n);
                    l = l.xor(&la);
                }
                return self.lin_class(w, l);
            }
        }
        // Support: without wraparound the value is at most the bound.
        let mut total: u128 = s.c as u128;
        for &(a, k) in &s.t {
            total = total.saturating_add((k as u128).saturating_mul(smear(self.supp(a, w)) as u128));
        }
        let supp = if total <= mask(w) as u128 { smear(total as u64) } else { mask(w) };
        self.intern(Key::Sum(w, s.c, s.t), Some(w), Some(supp))
    }

    // ---- width changes (rule 7) ----

    /// `(base, bit)` of bit `src` of a term atom (views and distributed low
    /// chunks resolve to their base).
    fn base_of(&self, v: ClassId, src: u32) -> (ClassId, u32) {
        match self.key(v) {
            Key::Zext(_, b) => (*b, src),
            Key::Chunk(w, b, k) => (*b, k * bits(*w) + src),
            _ => match self.lows.get(&v) {
                Some(&b) => (b, src),
                None => (v, src),
            },
        }
    }

    /// Truncate or zero-extend (or retype) `a` from `from` to `to`.
    fn resize(&mut self, a: ClassId, from: Width, to: Width) -> ClassId {
        if from == to {
            return a;
        }
        let l = self.lin_of(a, from);
        let l2 = self.resize_lin(&l, from, to);
        self.lin_class(to, l2)
    }

    fn resize_lin(&mut self, l: &Lin, from: Width, to: Width) -> Lin {
        let (n, nn) = (bits(from), bits(to));
        let out_bits = n.min(nn);
        let mut groups: std::collections::BTreeMap<(ClassId, u32, u32), u64> = std::collections::BTreeMap::new();
        for &(v, r, m) in &l.t {
            let mut mm = m & maskn(out_bits);
            while mm != 0 {
                let j = mm.trailing_zeros();
                mm &= mm - 1;
                let (bse, i) = self.base_of(v, (j + r) % n);
                let bw = self.width(bse).unwrap_or(from);
                let (kind, src2) = if bw == to {
                    (IDENT, i)
                } else if bits(bw) <= nn {
                    (ZEXT, i)
                } else {
                    (i / nn, i % nn)
                };
                let r2 = (src2 + nn - j) % nn;
                *groups.entry((bse, kind, r2)).or_default() |= 1u64 << j;
            }
        }
        let mut out = Lin::konst(l.c & maskn(out_bits));
        for ((bse, kind, r2), m) in groups {
            let vc = self.view_class(bse, to, kind);
            let vl = self.lin_of(vc, to).rotr(r2, nn).and_mask(m);
            out = out.xor(&vl);
        }
        out
    }

    /// The class of the view of base atom `b` at width `to`: `IDENT`, `ZEXT`
    /// or chunk `k`. Views of `and`/`or` sets and truth tables distribute,
    /// and the low chunk of a sum is the sum of the truncated summands; a
    /// low chunk distributed into a new class is recorded in `lows`.
    fn view_class(&mut self, b: ClassId, to: Width, kind: u32) -> ClassId {
        if kind == IDENT {
            return b;
        }
        if let Some(&c) = self.views.get(&(b, to, kind)) {
            return c;
        }
        let bw = self.width(b).unwrap_or(to);
        let key = self.key(b).clone();
        let first_new = self.classes.len() as ClassId;
        let distributed = match (kind, key) {
            (ZEXT, Key::And(_, ops)) | (0, Key::And(_, ops)) => {
                let rs: Vec<ClassId> = ops.iter().map(|&o| self.resize(o, bw, to)).collect();
                let mut acc = rs[0];
                for &x in &rs[1..] {
                    acc = self.and_c(acc, x, to);
                }
                Some(acc)
            }
            (ZEXT, Key::Or(_, ops)) | (0, Key::Or(_, ops)) => {
                let rs: Vec<ClassId> = ops.iter().map(|&o| self.resize(o, bw, to)).collect();
                let mut acc = rs[0];
                for &x in &rs[1..] {
                    acc = self.or_c(acc, x, to);
                }
                Some(acc)
            }
            (ZEXT, Key::Tt(_, vars, tt)) if tt & 1 == 0 => {
                let rs: Vec<ClassId> = vars.iter().map(|&o| self.resize(o, bw, to)).collect();
                self.tt_apply(&rs, tt, to)
            }
            (0, Key::Tt(_, vars, tt)) => {
                let rs: Vec<ClassId> = vars.iter().map(|&o| self.resize(o, bw, to)).collect();
                self.tt_apply(&rs, tt, to)
            }
            (0, Key::Sum(_, c, t)) => {
                let mut s = SumF { c: c & mask(to), t: Vec::new() };
                for (a, k) in t {
                    let ra = self.resize(a, bw, to);
                    let sa = self.sum_of(ra, to).scale(k, to);
                    s = s.add(sa, to);
                }
                Some(self.sum_class(to, s))
            }
            _ => None,
        };
        let c = match distributed {
            Some(c) => {
                // `c` is the low chunk of `b` (its value is `b mod
                // 2^bits(to)` by the identities above). If this call created
                // it, no view of it exists yet: from here on its bits are
                // `b`'s. (A nested distribution that created it first, from
                // an operand of `b` with the same low chunk, keeps its entry.)
                if kind == 0 && c >= first_new && matches!(self.key(c), Key::Sum(..) | Key::And(..) | Key::Or(..) | Key::Tt(..)) {
                    self.lows.entry(c).or_insert(b);
                }
                c
            }
            None if kind == ZEXT => {
                let s = self.supp(b, bw);
                self.intern(Key::Zext(to, b), Some(to), Some(s))
            }
            None => {
                let s = (self.supp(b, bw) >> (kind * bits(to))) & mask(to);
                self.intern(Key::Chunk(to, b, kind), Some(to), Some(s))
            }
        };
        self.views.insert((b, to, kind), c);
        c
    }

    // ---- primitives ----

    /// The class of `op(args)` (argument classes), memoized.
    pub(crate) fn prim(&mut self, op: PrimOp, args: &[ClassId]) -> ClassId {
        if let Some(sig) = prim_sig(op) {
            for (&a, &w) in args.iter().zip(&sig.args) {
                self.note_width(a, w);
            }
        }
        let rk = (op, args.to_vec());
        if let Some(&c) = self.raw.get(&rk) {
            return c;
        }
        let c = self.prim_uncached(op, args);
        self.raw.insert(rk, c);
        c
    }

    fn prim_uncached(&mut self, op: PrimOp, a: &[ClassId]) -> ClassId {
        use PrimOp::*;
        if prim_sig(op).is_none_or(|s| s.args.len() != a.len()) {
            return self.intern(Key::Prim(op, a.to_vec()), None, None);
        }
        let neg1 = |w: Width| mask(w);
        match op {
            WAdd(w) | Add(w) => {
                let s = self.sum_of(a[0], w).add(self.sum_of(a[1], w), w);
                self.sum_class(w, s)
            }
            WSub(w) | Sub(w) => {
                let s = self.sum_of(a[0], w).add(self.sum_of(a[1], w).scale(neg1(w), w), w);
                self.sum_class(w, s)
            }
            WNeg(w) => {
                let s = self.sum_of(a[0], w).scale(neg1(w), w);
                self.sum_class(w, s)
            }
            WMul(w) | Mul(w) => {
                if let Some(k) = self.lit_val(a[1]) {
                    let s = self.sum_of(a[0], w).scale(k, w);
                    self.sum_class(w, s)
                } else if let Some(k) = self.lit_val(a[0]) {
                    let s = self.sum_of(a[1], w).scale(k, w);
                    self.sum_class(w, s)
                } else {
                    self.generic(WMul(w), a)
                }
            }
            And(w) => self.and_c(a[0], a[1], w),
            Or(w) => self.or_c(a[0], a[1], w),
            Xor(w) => self.xor_c(a[0], a[1], w),
            Not(w) => {
                let ones = self.lit(w, mask(w));
                self.xor_c(a[0], ones, w)
            }
            WShl(w) | Shl(w) => match self.lit_val(a[1]) {
                Some(k) => self.shift(ShiftKind::Shl, a[0], k, w),
                None => self.generic(WShl(w), a),
            },
            WShr(w) | Shr(w) => match self.lit_val(a[1]) {
                Some(k) => self.shift(ShiftKind::Shr, a[0], k, w),
                None => self.generic(WShr(w), a),
            },
            Rotr(w) => match self.lit_val(a[1]) {
                Some(k) => self.shift(ShiftKind::Rotr, a[0], k, w),
                None => self.generic(op, a),
            },
            Rotl(w) => match self.lit_val(a[1]) {
                Some(k) => self.shift(ShiftKind::Rotl, a[0], k, w),
                None => self.generic(op, a),
            },
            Cast { from, to } if from != Width::Int && to != Width::Int => self.resize(a[0], from, to),
            _ => self.generic(op, a),
        }
    }

    /// Any other primitive: constant folding, argument normalization, and a
    /// structural key.
    fn generic(&mut self, op: PrimOp, a: &[ClassId]) -> ClassId {
        use PrimOp::*;
        // Rule 1: constant folding with the kernel's literal semantics.
        let lits: Option<Vec<BigInt>> = a
            .iter()
            .map(|&c| match self.key(c) {
                Key::Lit(_, n) => Some(BigInt::from(*n)),
                Key::IntLit(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        if let Some(lits) = lits {
            let refs: Vec<&BigInt> = lits.iter().collect();
            match crate::prim::eval_lits(op, &refs) {
                Ok(Some(LitOut::Int(Width::Int, n))) => return self.intern(Key::IntLit(n), Some(Width::Int), None),
                Ok(Some(LitOut::Int(w, n))) => {
                    use num_traits::ToPrimitive;
                    return self.lit(w, n.to_u64().unwrap_or(0));
                }
                Ok(Some(LitOut::Bool(b))) => return self.bool_class(b),
                _ => {}
            }
        }
        let mut args = a.to_vec();
        let op = match op {
            Gt(w) => {
                args.swap(0, 1);
                Lt(w)
            }
            Ge(w) => {
                args.swap(0, 1);
                Le(w)
            }
            Shl(w) => WShl(w),
            Shr(w) => WShr(w),
            Mul(w) => WMul(w),
            o => o,
        };
        if matches!(op, WMul(_) | Min(_) | Max(_) | SatAdd(_) | SatMul(_) | Eq(_) | Ne(_) | IAdd | IMul) && args.len() == 2 {
            args.sort_unstable();
        }
        if args.len() == 2 && args[0] == args[1] {
            match op {
                Eq(_) | Le(_) => return self.bool_class(true),
                Ne(_) | Lt(_) => return self.bool_class(false),
                Min(_) | Max(_) => return args[0],
                _ => {}
            }
        }
        let sig = prim_sig(op);
        let width = match sig.as_ref().map(|s| s.result) {
            Some(PrimTy::Int(w)) => Some(w),
            _ => None,
        };
        let supp = match (op, width) {
            (CountOnes(_) | LeadingZeros(_) | TrailingZeros(_), _) => Some(0x7F),
            (Min(w), _) => Some(smear(self.supp(args[0], w)) & smear(self.supp(args[1], w))),
            (Max(w), _) => Some(smear(self.supp(args[0], w) | self.supp(args[1], w))),
            (Div(w) | WShr(w) | SatSub(w), _) => Some(smear(self.supp(args[0], w))),
            (Rem(w), _) => Some(smear(self.supp(args[0], w)) & smear(self.supp(args[1], w))),
            _ => None,
        };
        self.intern(Key::Prim(op, args), width, supp)
    }
}
