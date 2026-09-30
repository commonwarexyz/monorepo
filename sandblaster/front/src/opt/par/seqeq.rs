//! The SIMD `seq::eq` candidate (plan O10; optimizer design §12.4
//! "Alternatives").
//!
//! A comparison of two byte arrays of a static length `16m` (`[u8; 32] ==
//! [u8; 32]`, QMDB's `sha256::equal`) is lowered by the `Word` step
//! (`opt/drive/word.rs`) to its word form
//! `((W(a,0) ⊕ W(b,0)) | …) == 0` over `u64::from_le_bytes` words. On
//! aarch64 the NEON candidate is
//!
//! ```text
//! L(v) = vgetq_lane_u64::<0>(u64 v) | vgetq_lane_u64::<1>(u64 v)
//! (L(veorq_u8(vld1q_u8(a[0..16]), vld1q_u8(b[0..16]))) | L(… a[16..32] …) | …) == 0
//! ```
//!
//! (the cheaper form that combines the blocks with `vorrq_u8` before one
//! lane reduction is priced too, but not proven: `bvrefl` has no rule
//! moving `|` through a byte concatenation).
//!
//! It is generated for every such comparison of the crate's exec
//! functions, proven equal to the word form by one `bvrefl` lemma per
//! length (`seqeq::neon_word_<n>`; the word form is linked to `seq::eq` by
//! the `Word` step's lemmas), and priced against the word form with the
//! `{neon}` tables. The word form wins on the M5 (the NEON form moves the
//! result back to a general register, and the loads are as many), so the
//! candidate is reported and not emitted; a target whose tables price it
//! cheaper would need its emission, which is not built.

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{Term, Tm};
use sandblaster_kernel::value::Budget;

use crate::hir::*;
use crate::opt::cost::model::SetModel;
use crate::opt::cost::tables::Op;

/// One comparison length's candidate, for the report.
#[derive(Clone, Debug)]
pub struct SeqEqReport {
    /// The functions comparing arrays of this length.
    pub functions: Vec<String>,
    pub bytes: u64,
    /// The checked lemma `NEON form = word form`, or why it failed.
    pub lemma: Result<String, String>,
    pub neon_cost: u64,
    /// The unproven `vorrq_u8` form's cost (the cheapest NEON form; equal
    /// to `neon_cost` at 16 bytes).
    pub neon_orr_cost: u64,
    pub word_cost: u64,
    pub chosen: bool,
    pub note: String,
}

/// Largest compared length (bytes) considered (the `Word` step's bound).
pub const MAX_BYTES: u64 = 256;

fn idx(x: &str, n: u64, k: u64) -> String {
    format!("(array::index U8 {n}usize {x} {k}usize .refl(Bool, true))")
}

/// The word form over `a b : Array U8 n` (`n = 8m`).
pub fn word_form(n: u64) -> String {
    let w = |x: &str, j: u64| {
        let mut list = "Nil[U8]".to_string();
        for k in (0..8).rev() {
            list = format!("Cons[U8]({}, {list})", idx(x, n, 8 * j + k));
        }
        format!("u64::from_le_bytes (pair(Array U8 8usize, {list}, refl(Int, 8int)))")
    };
    let m = n / 8;
    let mut acc = format!("#xor_u64({}, {})", w("a", m - 1), w("b", m - 1));
    for j in (0..m - 1).rev() {
        acc = format!("#or_u64(#xor_u64({}, {}), {acc})", w("a", j), w("b", j));
    }
    format!("#eq_u64({acc}, 0u64)")
}

fn neon_block(x: &str, n: u64, j: u64) -> String {
    let elems: Vec<String> = (0..16).map(|k| idx(x, n, 16 * j + k)).collect();
    format!("(aarch64::vld1q_u8 (aarch64::u8x16 {}))", elems.join(" "))
}

fn lanes_or(v: &str) -> String {
    let w = format!("(aarch64::vreinterpretq_u64_u8 {v})");
    format!("#or_u64(aarch64::vgetq_lane_u64 0u32 .refl(Bool, true) {w}, aarch64::vgetq_lane_u64 1u32 .refl(Bool, true) {w})")
}

/// The NEON form over `a b : Array U8 n` (`n = 16m`) that is proven: each
/// 16-byte block's `veorq_u8`, its two `u64` lanes or-ed, the blocks'
/// words or-ed (right-nested, as the word form).
pub fn neon_form(n: u64) -> String {
    let m = n / 16;
    let blk = |j: u64| lanes_or(&format!("(aarch64::veorq_u8 {} {})", neon_block("a", n, j), neon_block("b", n, j)));
    let mut acc = blk(m - 1);
    for j in (0..m - 1).rev() {
        acc = format!("#or_u64({}, {acc})", blk(j));
    }
    format!("#eq_u64({acc}, 0u64)")
}

/// The NEON form that combines the blocks with `vorrq_u8` before one lane
/// reduction (one lane move per comparison instead of two per block):
/// priced only — `bvrefl` does not prove it equal to the word form (the
/// word algebra has no rule moving `|` through a byte concatenation).
pub fn neon_form_orr(n: u64) -> String {
    let m = n / 16;
    let mut v = format!("(aarch64::veorq_u8 {} {})", neon_block("a", n, 0), neon_block("b", n, 0));
    for j in 1..m {
        v = format!("(aarch64::vorrq_u8 {v} (aarch64::veorq_u8 {} {}))", neon_block("a", n, j), neon_block("b", n, j));
    }
    format!("#eq_u64({}, 0u64)", lanes_or(&v))
}

/// `seqeq::neon_word_<n> : Π a b. Eq(Bool, NEON form, word form)`.
pub fn lemma_text(n: u64) -> String {
    let (nf, wf) = (neon_form(n), word_form(n));
    format!(
        "-- the NEON seq::eq candidate equals the word form (plan O10; opt/par/seqeq.rs)\n\
def[lemma, opaque] seqeq::neon_word_{n} : (a : Array U8 {n}usize) -> (b : Array U8 {n}usize) -> Eq(Bool, {nf}, {wf}) :=\n  fun (a : Array U8 {n}usize) (b : Array U8 {n}usize) => bvrefl(Bool, {nf}, {wf})\n"
    )
}

/// The byte lengths of `[u8; n] == [u8; n]` comparisons in the crate's
/// exec functions (`16 | n`, `n ≤ MAX_BYTES`), with the functions.
pub fn comparisons(krate: &Crate) -> Vec<(u64, Vec<String>)> {
    struct V {
        found: Vec<u64>,
    }
    impl crate::visit::Visitor for V {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Binary(BinOp::Eq, a, b) = &e.kind {
                let arr = |t: &Ty| match t.peel_refs() {
                    Ty::Array(el, n) if **el == Ty::u8() => Some(*n),
                    _ => None,
                };
                if let (Some(n), Some(m)) = (arr(&a.ty), arr(&b.ty))
                    && n == m
                    && n % 16 == 0
                    && n > 0
                    && n <= MAX_BYTES
                {
                    self.found.push(n);
                }
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut by: std::collections::BTreeMap<u64, Vec<String>> = Default::default();
    for it in &krate.items {
        let ItemKind::Fn(f) = &it.kind else { continue };
        if it.ghost || f.kind != FnKind::Exec {
            continue;
        }
        let FnBody::Exec(b) = &f.body else { continue };
        let mut v = V { found: vec![] };
        crate::visit::Visitor::expr(&mut v, b);
        for n in v.found {
            let e = by.entry(n).or_default();
            if !e.contains(&it.path.to_string()) {
                e.push(it.path.to_string());
            }
        }
    }
    by.into_iter().collect()
}

/// The cost of a form under `model`: intrinsics at their table cost, a
/// `u64::from_le_bytes` of array elements as one scalar load, element
/// reads and array constructors free (the loads are counted once, as the
/// vector or word load that reads them).
fn form_cost(env: &Env, model: &SetModel, t: &Tm) -> u64 {
    let callee = |head: &Tm| -> Option<u64> {
        let Term::Global(g) = &**head else { return None };
        let name = env.global_name(*g)?;
        let worst = |f: &dyn Fn(&crate::opt::cost::tables::Table) -> u64| model.tables.iter().map(f).max();
        if let Some(i) = name.strip_prefix("aarch64::") {
            if i == "u8x16" || i == "u8x8" {
                return Some(0);
            }
            return worst(&|tb| tb.intrinsic(i).lat);
        }
        match &*name {
            "u64::from_le_bytes" => worst(&|tb| tb.op(Op::Load).lat),
            "array::index" => Some(0),
            _ => None,
        }
    };
    model.term_cost(t, &callee)
}

/// Builds, proves and prices the candidate for `n`-byte comparisons
/// (`env` must have the aarch64 core loaded).
pub fn candidate(env: &mut Env, model: &SetModel, n: u64, functions: Vec<String>) -> SeqEqReport {
    let name = format!("seqeq::neon_word_{n}");
    let lemma = if env.lookup_global(&name).is_some() {
        Ok(name.clone())
    } else {
        let mut b = Budget { steps: 200_000_000 };
        env.load_core(&lemma_text(n), &mut b).map(|_| name.clone()).map_err(|e| e.to_string().chars().take(600).collect::<String>())
    };
    let names = ["a", "b"];
    let parse = |env: &Env, s: &str| env.parse_term(&names, s);
    let cost = |env: &Env, s: &str| parse(env, s).map(|t| form_cost(env, model, &t)).unwrap_or(0);
    let (neon_cost, neon_orr_cost, word_cost) = (cost(env, &neon_form(n)), cost(env, &neon_form_orr(n)), cost(env, &word_form(n)));
    let chosen = lemma.is_ok() && neon_cost > 0 && crate::opt::cost::model::beats(neon_cost, word_cost);
    let fmt = crate::opt::cost::model::fmt_mc;
    let note = match &lemma {
        Err(e) => format!("SIMD seq::eq candidate ({n} bytes): not proven: {e}"),
        Ok(l) if chosen => format!("SIMD seq::eq candidate ({n} bytes, NEON): proven equal to the word form by `{l}`; cost {} vs {} for the word form: cheaper, but its emission is not built (the word form stays)", fmt(neon_cost), fmt(word_cost)),
        Ok(l) if n == 16 => format!("SIMD seq::eq candidate ({n} bytes, NEON): proven equal to the word form by `{l}`; rejected by the cost model: {} vs {} for the word form", fmt(neon_cost), fmt(word_cost)),
        Ok(l) => format!(
            "SIMD seq::eq candidate ({n} bytes, NEON, a lane reduction per 16-byte block): proven equal to the word form by `{l}`; rejected by the cost model: {} vs {} for the word form (the vorrq_u8 form, not proven, would cost {})",
            fmt(neon_cost),
            fmt(word_cost),
            fmt(neon_orr_cost)
        ),
    };
    SeqEqReport { functions, bytes: n, lemma, neon_cost, neon_orr_cost, word_cost, chosen, note }
}
