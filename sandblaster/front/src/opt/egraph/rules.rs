//! The aegraph's rule library (optimizer design §10.1, §10.5; plan O8).
//!
//! Rules are **kernel-checked lemmas** `Π(v̄ : W̄). Eq(τ, lhs v̄, rhs v̄)`
//! from `lemmas/rules/*.core`, written by the offline tool
//! `sandblaster/rulegen` (never by the build). The optimizer loads the
//! files — and with them the `cong_irr` lemmas of `lemmas/cong.core` — the
//! first time its aegraph needs a rule ([`ensure`]); the kernel checks every
//! lemma again then, in every build that uses one.
//!
//! **Triggers.** Before anything is loaded, a candidate region is compared
//! with each rule's [`Signature`] (the operation histogram and size of its
//! left side, read from the file's statement text): only a region whose
//! histogram covers at least half of every operation class of the left
//! side, and whose size is within a factor 2, reaches `bvnorm` and the
//! library. Regions of other code (QMDB's SHA-256 rounds, varint readers)
//! never do.

use std::cell::RefCell;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, PrimOp, Rel, Term, Tm, Width};
use sandblaster_kernel::value::Budget;

/// The bit-sum idioms (rulegen output).
pub const BITSUM_CORE: &str = include_str!("../../../lemmas/rules/bitsum.core");
/// The `cong_irr` lemmas (rulegen output).
pub const CONG_CORE: &str = include_str!("../../../lemmas/cong.core");

/// The rule files, in load order.
pub const FILES: &[(&str, &str)] = &[("cong.core", CONG_CORE), ("rules/bitsum.core", BITSUM_CORE)];

/// Operation classes of a histogram.
pub const KINDS: usize = 12;

/// The histogram bucket of a primitive.
pub fn kind(op: &PrimOp) -> usize {
    use PrimOp::*;
    match op {
        WAdd(_) | Add(_) | IAdd => 0,
        WSub(_) | Sub(_) | ISub | WNeg(_) | INeg => 1,
        And(_) => 2,
        Or(_) | Xor(_) | Not(_) => 3,
        WShr(_) | Shr(_) => 4,
        WShl(_) | Shl(_) => 5,
        Rotl(_) | Rotr(_) => 6,
        Cast { .. } | IntToSat(_) | OfInt(_) => 7,
        WMul(_) | Mul(_) | IMul => 8,
        CountOnes(_) | LeadingZeros(_) | TrailingZeros(_) | SwapBytes(_) => 9,
        Eq(_) | Ne(_) | Lt(_) | Le(_) | Gt(_) | Ge(_) => 10,
        _ => 11,
    }
}

/// Per-kind operation counts (tree counts, saturating).
pub type Hist = [u16; KINDS];

/// What a region must look like to be matched against a rule.
#[derive(Clone, Debug)]
pub struct Signature {
    pub hist: Hist,
    /// Primitive nodes of the left side.
    pub size: u32,
}

impl Signature {
    /// `true` when a region with histogram `h` and `size` primitive nodes
    /// may match (see the module docs).
    pub fn admits(&self, h: &Hist, size: u32) -> bool {
        if size * 2 < self.size || size > self.size * 2 {
            return false;
        }
        self.hist.iter().zip(h.iter()).all(|(want, have)| u32::from(*have) * 2 >= u32::from(*want))
    }
}

/// A rule as the matcher sees it (from the file's statement text; the
/// checked lemma is looked up by name after [`ensure`]).
#[derive(Clone, Debug)]
pub struct RuleSig {
    pub name: String,
    /// The pattern variables' widths.
    pub vars: Vec<Width>,
    /// The equation's type.
    pub ty: Width,
    /// Left and right sides, under the pattern variables' binders.
    pub lhs: Tm,
    pub rhs: Tm,
    pub sig: Signature,
}

/// Histogram and primitive count of a term (tree counts).
pub fn histogram(t: &Tm) -> (Hist, u32) {
    let mut h: Hist = [0; KINDS];
    let mut n = 0u32;
    crate::elab::tm::any_node(t, &mut |x| {
        if let Term::Prim { op, .. } = x {
            let k = kind(op);
            h[k] = h[k].saturating_add(1);
            n += 1;
        }
        false
    });
    (h, n)
}

thread_local! {
    static INDEX: RefCell<Option<Vec<RuleSig>>> = const { RefCell::new(None) };
}

/// The rule index (parsed once per thread from the statement texts of
/// [`FILES`]; parsing checks nothing and loads nothing).
pub fn index(env: &Env) -> Vec<RuleSig> {
    if let Some(v) = INDEX.with(|i| i.borrow().clone()) {
        return v;
    }
    let mut out = Vec::new();
    for (_, text) in FILES {
        for line in text.lines() {
            let Some(rest) = line.strip_prefix("def[lemma] rules::") else { continue };
            let Some((name, ty)) = rest.split_once(" : ") else { continue };
            // rules proper (not the helper lemmas `bs_*`) state `Eq(τ, lhs, rhs)`
            if name.starts_with("bs_") {
                continue;
            }
            let Some(ty) = ty.strip_suffix(" :=") else { continue };
            let Ok(t) = env.parse_term(&[], ty) else { continue };
            if let Some(r) = rule_sig(&format!("rules::{name}"), &t) {
                out.push(r);
            }
        }
    }
    INDEX.with(|i| *i.borrow_mut() = Some(out.clone()));
    out
}

/// A rule's signature from its statement `Π(v̄ : W̄). Eq(IntTy τ, lhs, rhs)`.
pub fn rule_sig(name: &str, stmt: &Tm) -> Option<RuleSig> {
    let mut vars = Vec::new();
    let mut t = stmt.clone();
    while let Term::Pi { rel: Rel::Rel, dom, cod, .. } = &*t {
        match &**dom {
            Term::IntTy(w) => vars.push(*w),
            _ => return None,
        }
        let c = cod.clone();
        t = c;
    }
    let Term::Eq { ty, lhs, rhs } = &*t else { return None };
    let Term::IntTy(tw) = &**ty else { return None };
    let (hist, size) = histogram(lhs);
    Some(RuleSig { name: name.to_string(), vars, ty: *tw, lhs: lhs.clone(), rhs: rhs.clone(), sig: Signature { hist, size } })
}

/// Loads the committed rule library ([`FILES`]) into `env`; the kernel
/// checks every lemma. A failing file leaves the lemmas before the failure
/// loaded, so the optimizer records the result in its context and never
/// uses a library that failed.
pub fn ensure(env: &mut Env) -> Result<(), String> {
    ensure_files(env, FILES.iter().copied())
}

/// [`ensure`] with the files `files` (`(name, text)`, in load order). `Ok`
/// without loading when every lemma of the files is already in `env` (the
/// kernel checked each when it was added); an error when only some are (a
/// load that failed part way).
pub fn ensure_files<'a>(env: &mut Env, files: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<(), String> {
    let files: Vec<(&str, &str)> = files.into_iter().collect();
    let names: Vec<&str> = files.iter().flat_map(|(_, text)| def_names(text)).collect();
    let present = names.iter().filter(|n| env.lookup_global(n).is_some()).count();
    if present == names.len() && present > 0 {
        return Ok(());
    }
    if present > 0 {
        return Err(format!("the rule library is partly loaded ({present} of {} lemmas): an earlier load failed", names.len()));
    }
    let mut b = Budget { steps: 4_000_000_000 };
    for (file, text) in files {
        env.load_core(text, &mut b).map_err(|e| format!("lemmas/{file}: {e}"))?;
    }
    Ok(())
}

/// The names a `.core` text defines (`def name : ..` / `def[lemma] name : ..`).
fn def_names(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter_map(|l| l.strip_prefix("def")).filter_map(|r| r.split_once(' ')).filter_map(|(_, r)| r.split_once(" : ")).map(|(n, _)| n)
}

/// The checked lemma of a rule (after [`ensure`]).
pub fn lemma(env: &Env, name: &str) -> Option<GlobalId> {
    env.lookup_global(name)
}
