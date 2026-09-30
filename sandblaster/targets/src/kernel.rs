//! The kernel side of the target semantics (feature `kernel`; DESIGN.md
//! §9.2, §10.3 "Target models").
//!
//! * [`load`] / [`env_with_models`] load the core-text models of
//!   [`crate::coretext`] into a kernel [`Env`] (after the prelude);
//! * [`Kit`] builds kernel terms: closed lane arrays and words
//!   ([`CoreValue`]) and **calls of a core model** ([`Kit::apply`]: the
//!   immediates as `U32` literals with `.refl(Bool, true)` range proofs, then
//!   the value arguments) — the term the elaborator emits for an intrinsic
//!   call;
//! * campaigns over many models run on worker threads of one process
//!   ([`crosscheck_all`], [`default_threads`]);
//! * the **K-style cross-checks**: [`crosscheck_model`] evaluates a core model
//!   with the kernel evaluator on the inputs of a [`crate::diff`] campaign
//!   (corner values, random cases, every immediate) and compares the result
//!   with the executable Rust model, and [`compress_checks`] compares the
//!   SHA-256 compressions assembled in core text from the core models
//!   (`core/checks/*.core`) with a core-text FIPS 180-4 compression and with
//!   the executable models. Together with the hardware campaigns
//!   ([`crate::hw`]) this tests the chain hardware ↔ Rust model ↔ kernel
//!   model end to end.
//!
//! Kernel evaluation of an intrinsic model happens only on closed arguments
//! (the `DefKind::Intrinsic` unfolding policy, §5.6), which is exactly what a
//! cross-check provides.
#![forbid(unsafe_code)]

use std::fmt::Debug;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use sandblaster_kernel::api::{Ctx, Env, KernelError};
use sandblaster_kernel::term::{GlobalId, IndId, Lvl, Name, Rel, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, V, VEnv, Value};

use crate::aarch64 as a64;
use crate::compress;
use crate::coretext::{self, CoreModel, Lane, Role};
use crate::diff::{self, Config, Outcome, Sample};
use crate::fips;
use crate::registry::Arch;
use crate::x86_64 as x86;

/// Evaluation budget for one kernel call (steps).
pub const STEPS: u64 = 1 << 30;

/// Base seed of the kernel cross-check campaigns (distinct from the hardware
/// campaigns' [`diff::DEFAULT_SEED`]).
pub const KERNEL_SEED: u64 = 0x5eed_2026_0924_c0de;

/// Random cases per model of the kernel cross-checks (split over the
/// immediates for immediate models, at least one per immediate).
pub const RANDOM_PER_MODEL: u64 = 1000;

/// Random cases of the compression cross-checks in the tests (on top of the
/// 15 corner inputs; each case evaluates three core compressions).
pub const RANDOM_PER_COMPRESSION: u64 = 64;

/// Random cases of the compression cross-checks recorded in the evidence.
pub const EVIDENCE_RANDOM_PER_COMPRESSION: u64 = 256;

/// The default kernel cross-check configuration.
pub fn config() -> Config {
    Config {
        random_per_model: RANDOM_PER_MODEL,
        seed: KERNEL_SEED,
    }
}

fn budget() -> Budget {
    Budget { steps: STEPS }
}

/// Load an architecture's core models into `env` (which must contain the prelude).
pub fn load(env: &mut Env, arch: Arch) -> Result<Vec<Name>, KernelError> {
    env.load_core(coretext::core_text(arch), &mut budget())
}

/// A fresh environment with the prelude and the core models of `archs`.
pub fn env_with_models(archs: &[Arch]) -> Result<Env, KernelError> {
    let mut env = Env::try_with_prelude()?;
    for &arch in archs {
        load(&mut env, arch)?;
    }
    Ok(env)
}

/// Load the (untrusted) compression fixtures of `core/checks/` into an
/// environment that holds both architectures' models.
pub fn load_checks(env: &mut Env) -> Result<(), KernelError> {
    env.load_core(coretext::checks::FIPS180_4, &mut budget())?;
    env.load_core(coretext::checks::AARCH64_SHA2_COMPRESS, &mut budget())?;
    env.load_core(coretext::checks::X86_64_SHANI_COMPRESS, &mut budget())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Terms and values

fn width(lane: Lane) -> Width {
    match lane {
        Lane::U8 => Width::U8,
        Lane::U16 => Width::U16,
        Lane::U32 => Width::U32,
        Lane::U64 => Width::U64,
    }
}

/// Builds kernel terms against one environment.
pub struct Kit {
    array: GlobalId,
    list: IndId,
    bool_ind: IndId,
}

impl Kit {
    /// The builder for `env` (which must contain the prelude).
    pub fn new(env: &Env) -> Result<Kit, String> {
        Ok(Kit {
            array: env.lookup_global("Array").ok_or("prelude global `Array` missing")?,
            list: env.lookup_ind("List").ok_or("prelude inductive `List` missing")?,
            bool_ind: env.bool_ind(),
        })
    }

    /// A machine-word literal.
    pub fn word(&self, lane: Lane, n: u64) -> Tm {
        mk::lit(width(lane), n)
    }

    /// The type `Array <lane> <n>usize`.
    pub fn array_ty(&self, lane: Lane, n: usize) -> Tm {
        mk::apps(mk::global(self.array), [(Rel::Rel, mk::int_ty(width(lane))), (Rel::Rel, mk::lit(Width::Usize, n as u64))])
    }

    /// A closed lane array `pair(Array T N, [x0, ..], refl(Int, N int))`.
    pub fn array(&self, lane: Lane, xs: &[u64]) -> Tm {
        let t = mk::int_ty(width(lane));
        let list = xs.iter().rev().fold(mk::ctor(self.list, 0, vec![t.clone()], vec![]), |tail, &x| {
            mk::ctor(self.list, 1, vec![t.clone()], vec![self.word(lane, x), tail])
        });
        let n = xs.len() as u64;
        mk::pair(self.array_ty(lane, xs.len()), list, mk::refl(mk::int_ty(Width::Int), mk::lit(Width::Int, n)))
    }

    /// `.refl(Bool, true)`, the proof of a range check on a literal.
    pub fn refl_true(&self) -> Tm {
        mk::refl(mk::bool_ty(self.bool_ind), mk::bool_lit(self.bool_ind, true))
    }

    /// The call of core model `m` with immediates `imms` (range-checked) and
    /// value arguments `args`: `global imm .refl(Bool, true) .. arg ..`.
    pub fn apply(&self, env: &Env, m: &CoreModel, imms: &[u32], args: Vec<Tm>) -> Result<Tm, String> {
        let g = env.lookup_global(m.global).ok_or_else(|| format!("core model {} is not loaded", m.global))?;
        if imms.len() != m.imms.len() || args.len() != m.params.len() {
            return Err(format!(
                "{} takes {} immediate(s) and {} argument(s), got {} and {}",
                m.global,
                m.imms.len(),
                m.params.len(),
                imms.len(),
                args.len()
            ));
        }
        let mut out = Vec::new();
        for b in m.telescope() {
            match b.role {
                Role::Imm { index } => {
                    let (v, imm) = (imms[index], m.imms[index]);
                    if v < imm.lo || v > imm.hi {
                        return Err(format!("{}: immediate {} = {v} out of range {}..={}", m.global, imm.name, imm.lo, imm.hi));
                    }
                    out.push((Rel::Rel, mk::lit(Width::U32, v)));
                }
                Role::ImmProof { .. } => out.push((Rel::Irr, self.refl_true())),
                Role::Value { index } => out.push((Rel::Rel, args[index].clone())),
            }
        }
        Ok(mk::apps(mk::global(g), out))
    }

    /// `global a0 a1 ..` with relevant arguments (for the fixtures).
    pub fn apply_global(&self, env: &Env, name: &str, args: Vec<Tm>) -> Result<Tm, String> {
        let g = env.lookup_global(name).ok_or_else(|| format!("global {name} is not loaded"))?;
        Ok(mk::apps(mk::global(g), args.into_iter().map(|a| (Rel::Rel, a))))
    }
}

/// Evaluate a closed term.
pub fn eval_closed(env: &Env, t: &Tm) -> Result<V, String> {
    env.eval(&VEnv::default(), Lvl(0), t, &mut budget()).map_err(|e| format!("evaluation failed: {e:?}"))
}

/// A literal value as `u64`.
pub fn read_word(v: &V) -> Option<u64> {
    match &**v {
        Value::Lit { n, .. } => u64::try_from(n).ok(),
        _ => None,
    }
}

/// The lanes of a closed array value (`Pair` of a concrete `List`).
pub fn read_array(v: &V) -> Option<Vec<u64>> {
    let Value::Pair { fst, .. } = &**v else { return None };
    let mut out = Vec::new();
    let mut cur = fst.clone();
    loop {
        let next = match &*cur {
            Value::Ctor { ctor: 0, args, .. } if args.is_empty() => return Some(out),
            Value::Ctor { ctor: 1, args, .. } if args.len() == 2 => match (&args[0], &args[1]) {
                (Arg::Rel(h), Arg::Rel(t)) => {
                    out.push(read_word(h)?);
                    t.clone()
                }
                _ => return None,
            },
            _ => return None,
        };
        cur = next;
    }
}

/// Rust values with a closed core representation (§9.2 vector
/// representation; signed stdarch scalars as their two's-complement bits).
pub trait CoreValue: Sized {
    /// The closed kernel term.
    fn to_term(&self, kit: &Kit) -> Tm;
    /// Decode a kernel value (`None` if it is not closed or has the wrong shape).
    fn from_value(v: &V) -> Option<Self>;
}

macro_rules! word_value {
    ($t:ty, $lane:expr, $bits:ty) => {
        impl CoreValue for $t {
            fn to_term(&self, kit: &Kit) -> Tm {
                kit.word($lane, *self as $bits as u64)
            }
            fn from_value(v: &V) -> Option<Self> {
                Some(<$bits>::try_from(read_word(v)?).ok()? as $t)
            }
        }
        impl<const N: usize> CoreValue for [$t; N] {
            fn to_term(&self, kit: &Kit) -> Tm {
                let xs: Vec<u64> = self.iter().map(|x| *x as $bits as u64).collect();
                kit.array($lane, &xs)
            }
            fn from_value(v: &V) -> Option<Self> {
                let xs = read_array(v)?;
                if xs.len() != N {
                    return None;
                }
                let mut out = [0 as $t; N];
                for (o, x) in out.iter_mut().zip(xs) {
                    *o = <$bits>::try_from(x).ok()? as $t;
                }
                Some(out)
            }
        }
    };
}

word_value!(u8, Lane::U8, u8);
word_value!(u16, Lane::U16, u16);
word_value!(u32, Lane::U32, u32);
word_value!(u64, Lane::U64, u64);
word_value!(i32, Lane::U32, u32);
word_value!(i64, Lane::U64, u64);

// ---------------------------------------------------------------------------
// Checker

/// An environment with both architectures' core models and the compression
/// fixtures, plus a term builder.
pub struct Checker {
    /// The environment.
    pub env: Env,
    /// The term builder.
    pub kit: Kit,
}

impl Checker {
    /// Load the prelude, both core files and the fixtures.
    pub fn new() -> Result<Checker, String> {
        let mut env = env_with_models(&[Arch::Aarch64, Arch::X86_64]).map_err(|e| e.to_string())?;
        load_checks(&mut env).map_err(|e| e.to_string())?;
        let kit = Kit::new(&env)?;
        Ok(Checker { env, kit })
    }

    /// An environment with the prelude and the given core texts (in place of
    /// the committed `core/*.core`; no fixtures), e.g. to show that the
    /// cross-checks catch a mutated model.
    pub fn from_core_texts(texts: &[&str]) -> Result<Checker, String> {
        let mut env = Env::try_with_prelude().map_err(|e| e.to_string())?;
        for t in texts {
            env.load_core(t, &mut budget()).map_err(|e| e.to_string())?;
        }
        let kit = Kit::new(&env)?;
        Ok(Checker { env, kit })
    }

    /// Evaluate core model `m` on closed arguments and decode the result.
    pub fn call<R: CoreValue>(&self, m: &CoreModel, imms: &[u32], args: Vec<Tm>) -> Result<R, String> {
        let t = self.kit.apply(&self.env, m, imms, args)?;
        let v = eval_closed(&self.env, &t)?;
        R::from_value(&v).ok_or_else(|| {
            let q = self.env.quote(Lvl(0), &v, false);
            format!("{} did not evaluate to a closed value: {}", m.global, self.env.print_term(&[], &q))
        })
    }

    /// Evaluate a global (a fixture) applied to closed relevant arguments.
    pub fn call_global<R: CoreValue>(&self, name: &str, args: Vec<Tm>) -> Result<R, String> {
        let t = self.kit.apply_global(&self.env, name, args)?;
        let v = eval_closed(&self.env, &t)?;
        R::from_value(&v).ok_or_else(|| format!("{name} did not evaluate to a closed value"))
    }

    /// Type-check the call `m imms args` against the model's result type
    /// (the terms [`Kit::apply`] builds are well-typed).
    pub fn check_call(&self, m: &CoreModel, imms: &[u32], args: Vec<Tm>) -> Result<(), String> {
        let t = self.kit.apply(&self.env, m, imms, args)?;
        let ty = self.env.parse_term(&[], &m.ret.text()).map_err(|e| e.to_string())?;
        let tyv = eval_closed(&self.env, &ty)?;
        self.env.check(&Ctx::default(), &t, &tyv, &mut budget()).map_err(|e| e.to_string())
    }

    /// Does the kernel type of `global` equal (by conversion) the core type
    /// `type_text` (the registry's signature)?
    pub fn type_matches(&self, global: &str, type_text: &str) -> Result<bool, String> {
        let g = self.env.lookup_global(global).ok_or_else(|| format!("{global} is not loaded"))?;
        let declared = self.env.global_type_value(g).ok_or("no type")?;
        let ty = self.env.parse_term(&[], type_text).map_err(|e| e.to_string())?;
        let tyv = eval_closed(&self.env, &ty)?;
        self.env.conv(Lvl(0), &declared, &tyv, &mut budget()).map_err(|e| format!("{e:?}"))
    }

    /// The core globals of `m`'s architecture that the checked body of the
    /// global `name` references (read back from the kernel, so this is an
    /// independent check of [`coretext::core_items`]).
    pub fn referenced_globals(&self, arch: Arch, name: &str) -> Vec<String> {
        let prefix = coretext::global_prefix(arch);
        let Some(g) = self.env.lookup_global(name) else { return vec![] };
        let Some(body) = self.env.global_body(g) else { return vec![] };
        let text = self.env.print_term(&[], &body);
        let mut out: Vec<String> = Vec::new();
        for tok in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':' || c == '\'')) {
            let tok = tok.trim_matches(':');
            if tok.starts_with(prefix) && tok != name && !out.iter().any(|o| o == tok) {
                out.push(tok.to_string());
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Per-model cross-checks

type Res<R> = Result<R, String>;

fn imm_range(m: &CoreModel) -> std::ops::RangeInclusive<i32> {
    let i = m.imms[0];
    i.lo as i32..=i.hi as i32
}

/// Random budget: at least one random case per immediate.
fn random_budget(m: &CoreModel, cfg: &Config) -> u64 {
    match m.imms.first() {
        Some(i) => cfg.random_per_model.max((i.hi - i.lo + 1) as u64),
        None => cfg.random_per_model,
    }
}

fn c1<A, R>(ck: &Checker, m: &CoreModel, cfg: &Config, f: fn(A) -> R) -> Outcome
where
    A: Sample + CoreValue,
    R: CoreValue + PartialEq + Debug,
{
    diff::diff1(
        m.name,
        random_budget(m, cfg),
        cfg.seed_for(m.name),
        |a: A| ck.call::<R>(m, &[], vec![a.to_term(&ck.kit)]),
        |a: A| Res::Ok(f(a)),
    )
}

fn c2<A, B, R>(ck: &Checker, m: &CoreModel, cfg: &Config, f: fn(A, B) -> R) -> Outcome
where
    A: Sample + CoreValue,
    B: Sample + CoreValue,
    R: CoreValue + PartialEq + Debug,
{
    diff::diff2(
        m.name,
        random_budget(m, cfg),
        cfg.seed_for(m.name),
        |a: A, b: B| ck.call::<R>(m, &[], vec![a.to_term(&ck.kit), b.to_term(&ck.kit)]),
        |a: A, b: B| Res::Ok(f(a, b)),
    )
}

fn c3<A, B, C, R>(ck: &Checker, m: &CoreModel, cfg: &Config, f: fn(A, B, C) -> R) -> Outcome
where
    A: Sample + CoreValue,
    B: Sample + CoreValue,
    C: Sample + CoreValue,
    R: CoreValue + PartialEq + Debug,
{
    diff::diff3(
        m.name,
        random_budget(m, cfg),
        cfg.seed_for(m.name),
        |a: A, b: B, c: C| ck.call::<R>(m, &[], vec![a.to_term(&ck.kit), b.to_term(&ck.kit), c.to_term(&ck.kit)]),
        |a: A, b: B, c: C| Res::Ok(f(a, b, c)),
    )
}

fn c4<A, R>(ck: &Checker, m: &CoreModel, cfg: &Config, f: fn(A, A, A, A) -> R) -> Outcome
where
    A: Sample + CoreValue,
    R: CoreValue + PartialEq + Debug,
{
    diff::diff4(
        m.name,
        random_budget(m, cfg),
        cfg.seed_for(m.name),
        |a: A, b: A, c: A, d: A| {
            ck.call::<R>(m, &[], vec![a.to_term(&ck.kit), b.to_term(&ck.kit), c.to_term(&ck.kit), d.to_term(&ck.kit)])
        },
        |a: A, b: A, c: A, d: A| Res::Ok(f(a, b, c, d)),
    )
}

fn ci1<A, R>(ck: &Checker, m: &CoreModel, cfg: &Config, part: &Part, f: fn(A, i32) -> R) -> Outcome
where
    A: Sample + CoreValue,
    R: CoreValue + PartialEq + Debug,
{
    diff::diff_imm1(
        m.name,
        part.imms.clone(),
        part.random,
        part.seed(m, cfg),
        |a: A, imm: i32| ck.call::<R>(m, &[imm as u32], vec![a.to_term(&ck.kit)]),
        |a: A, imm: i32| Res::Ok(f(a, imm)),
    )
}

fn ci2<A, B, R>(ck: &Checker, m: &CoreModel, cfg: &Config, part: &Part, f: fn(A, B, i32) -> R) -> Outcome
where
    A: Sample + CoreValue,
    B: Sample + CoreValue,
    R: CoreValue + PartialEq + Debug,
{
    diff::diff_imm2(
        m.name,
        part.imms.clone(),
        part.random,
        part.seed(m, cfg),
        |a: A, b: B, imm: i32| ck.call::<R>(m, &[imm as u32], vec![a.to_term(&ck.kit), b.to_term(&ck.kit)]),
        |a: A, b: B, imm: i32| Res::Ok(f(a, b, imm)),
    )
}

fn ci3<A, B, C, R>(ck: &Checker, m: &CoreModel, cfg: &Config, part: &Part, f: fn(A, B, C, i32) -> R) -> Outcome
where
    A: Sample + CoreValue,
    B: Sample + CoreValue,
    C: Sample + CoreValue,
    R: CoreValue + PartialEq + Debug,
{
    diff::diff_imm3(
        m.name,
        part.imms.clone(),
        part.random,
        part.seed(m, cfg),
        |a: A, b: B, c: C, imm: i32| ck.call::<R>(m, &[imm as u32], vec![a.to_term(&ck.kit), b.to_term(&ck.kit), c.to_term(&ck.kit)]),
        |a: A, b: B, c: C, imm: i32| Res::Ok(f(a, b, c, imm)),
    )
}

/// A slice of an immediate model's campaign: a sub-range of its immediates
/// with that sub-range's share of the random budget (so that campaigns of
/// 256-immediate models can run in parallel; [`merge_parts`] reassembles them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    /// The immediates of this part.
    pub imms: std::ops::RangeInclusive<i32>,
    /// Random cases of this part.
    pub random: u64,
}

impl Part {
    /// The whole campaign of an immediate model.
    pub fn whole(m: &CoreModel, cfg: &Config) -> Part {
        Part {
            imms: imm_range(m),
            random: random_budget(m, cfg),
        }
    }

    /// The model's campaign split into parts of at most `chunk` immediates;
    /// every immediate gets the same number of random cases as in [`Part::whole`].
    pub fn split(m: &CoreModel, cfg: &Config, chunk: i32) -> Vec<Part> {
        let full = imm_range(m);
        let per = diff::per_immediate(random_budget(m, cfg), &full);
        let mut out = Vec::new();
        let mut lo = *full.start();
        while lo <= *full.end() {
            let hi = (lo + chunk - 1).min(*full.end());
            out.push(Part {
                imms: lo..=hi,
                random: per * (hi - lo + 1) as u64,
            });
            lo = hi + 1;
        }
        out
    }

    /// The part's seed: the model's seed, mixed with the first immediate for
    /// parts that do not start at the range's start.
    fn seed(&self, m: &CoreModel, cfg: &Config) -> u64 {
        let base = cfg.seed_for(m.name);
        if *self.imms.start() == *imm_range(m).start() {
            base
        } else {
            base ^ (*self.imms.start() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        }
    }
}

/// Reassemble the outcomes of the parts of one model's campaign.
pub fn merge_parts(m: &CoreModel, cfg: &Config, parts: Vec<Outcome>) -> Outcome {
    let mut o = Outcome {
        name: m.name.to_string(),
        random: 0,
        corner: 0,
        immediates: m.imms.first().map(|_| imm_range(m)),
        mismatches: 0,
        first_mismatch: None,
        skipped: None,
        seed: cfg.seed_for(m.name),
    };
    for p in parts {
        o.random += p.random;
        o.corner += p.corner;
        o.mismatches += p.mismatches;
        if o.first_mismatch.is_none() {
            o.first_mismatch = p.first_mismatch;
        }
        if o.skipped.is_none() {
            o.skipped = p.skipped;
        }
    }
    o
}

type U8x16 = [u8; 16];
type U32x4 = [u32; 4];

/// A byte vector (`__m128i`, `__m256i`, `__m512i`) in the kernel cross-checks
/// of the 256/512-bit models (MODELS.md §10.8): the random generator of
/// `[u8; N]`, and as corners the curated subset [`kernel_wide_corners`] of
/// [`diff::wide_vector_corners`] instead of all of them. Kernel evaluation of
/// a 64-byte model is costly (and the kernel's counting allocator makes it
/// scale poorly across threads), so the kernel campaign keeps ≥ 1000 random
/// cases and every immediate but fewer corners per immediate; the hardware
/// campaign and the reference consistency use every corner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kv<const N: usize>(pub [u8; N]);

/// The kernel corners of an `N`-byte vector: the byte splats 0, 0xff, 0x80,
/// 1, 0x7f; the sign bit, largest value, 1 and alternating all-ones of every
/// element width; the permute index patterns; and a single 0x80 in the first
/// and in the last byte.
pub fn kernel_wide_corners<const N: usize>() -> Vec<[u8; N]> {
    let all = diff::wide_vector_corners::<N>();
    let splats = diff::byte_corners().len();
    let mut v: Vec<[u8; N]> = all[..5].to_vec();
    v.extend_from_slice(&all[splats..splats + 21]);
    let mut first = [0u8; N];
    first[0] = 0x80;
    let mut last = [0u8; N];
    last[N - 1] = 0x80;
    v.push(first);
    v.push(last);
    v
}

impl<const N: usize> Sample for Kv<N>
where
    [u8; N]: Sample,
{
    fn random(rng: &mut crate::rng::Rng) -> Self {
        Kv(<[u8; N] as Sample>::random(rng))
    }
    fn corners() -> Vec<Self> {
        kernel_wide_corners::<N>().into_iter().map(Kv).collect()
    }
}

impl<const N: usize> CoreValue for Kv<N> {
    fn to_term(&self, kit: &Kit) -> Tm {
        self.0.to_term(kit)
    }
    fn from_value(v: &V) -> Option<Self> {
        <[u8; N]>::from_value(v).map(Kv)
    }
}

/// Cross-check one core model against its executable model: the kernel's
/// evaluation of the core global on every input of a [`diff`] campaign
/// (corners, `cfg.random_per_model` random cases, every immediate) must equal
/// the Rust model's result. The outcome is named after the model.
pub fn crosscheck_model(ck: &Checker, m: &CoreModel, cfg: &Config) -> Outcome {
    let part = m.imms.first().map(|_| Part::whole(m, cfg));
    crosscheck_part(ck, m, cfg, part.as_ref())
}

/// [`crosscheck_model`] restricted to one [`Part`] of an immediate model
/// (`part` must be `Some` exactly for immediate models).
pub fn crosscheck_part(ck: &Checker, m: &CoreModel, cfg: &Config, part: Option<&Part>) -> Outcome {
    let p = || part.expect("immediate models take a part");
    match (m.arch, m.name) {
        (Arch::Aarch64, "vld1q_u8") => c1(ck, m, cfg, |a: U8x16| a64::vld1q_u8(&a)),
        (Arch::Aarch64, "vld1q_u32") => c1(ck, m, cfg, |a: U32x4| a64::vld1q_u32(&a)),
        (Arch::Aarch64, "vld1_u8") => c1(ck, m, cfg, |a: [u8; 8]| a64::vld1_u8(&a)),
        (Arch::Aarch64, "vst1q_u8") => c1(ck, m, cfg, a64::vst1q_u8),
        (Arch::Aarch64, "vst1q_u32") => c1(ck, m, cfg, a64::vst1q_u32),
        (Arch::Aarch64, "vrev32q_u8") => c1(ck, m, cfg, a64::vrev32q_u8),
        (Arch::Aarch64, "vreinterpretq_u32_u8") => c1(ck, m, cfg, a64::vreinterpretq_u32_u8),
        (Arch::Aarch64, "vreinterpretq_u8_u32") => c1(ck, m, cfg, a64::vreinterpretq_u8_u32),
        (Arch::Aarch64, "vaddq_u32") => c2(ck, m, cfg, a64::vaddq_u32),
        (Arch::Aarch64, "veorq_u32") => c2(ck, m, cfg, a64::veorq_u32),
        (Arch::Aarch64, "vandq_u32") => c2(ck, m, cfg, a64::vandq_u32),
        (Arch::Aarch64, "vorrq_u32") => c2(ck, m, cfg, a64::vorrq_u32),
        (Arch::Aarch64, "vshlq_n_u32") => ci1(ck, m, cfg, p(), a64::vshlq_n_u32),
        (Arch::Aarch64, "vshrq_n_u32") => ci1(ck, m, cfg, p(), a64::vshrq_n_u32),
        (Arch::Aarch64, "vextq_u32") => ci2(ck, m, cfg, p(), a64::vextq_u32),
        (Arch::Aarch64, "vdupq_n_u32") => c1(ck, m, cfg, a64::vdupq_n_u32),
        (Arch::Aarch64, "vgetq_lane_u32") => ci1(ck, m, cfg, p(), a64::vgetq_lane_u32),
        (Arch::Aarch64, "vsetq_lane_u32") => ci2(ck, m, cfg, p(), a64::vsetq_lane_u32),
        (Arch::Aarch64, "vsetq_lane_u8") => ci2(ck, m, cfg, p(), a64::vsetq_lane_u8),
        (Arch::Aarch64, "vsha256hq_u32") => c3(ck, m, cfg, a64::vsha256hq_u32),
        (Arch::Aarch64, "vsha256h2q_u32") => c3(ck, m, cfg, a64::vsha256h2q_u32),
        (Arch::Aarch64, "vsha256su0q_u32") => c2(ck, m, cfg, a64::vsha256su0q_u32),
        (Arch::Aarch64, "vsha256su1q_u32") => c3(ck, m, cfg, a64::vsha256su1q_u32),
        (Arch::Aarch64, "vld1q_u64") => c1(ck, m, cfg, |a: [u64; 2]| a64::vld1q_u64(&a)),
        (Arch::Aarch64, "vst1q_u64") => c1(ck, m, cfg, a64::vst1q_u64),
        (Arch::Aarch64, "veorq_u8") => c2(ck, m, cfg, a64::veorq_u8),
        (Arch::Aarch64, "vandq_u8") => c2(ck, m, cfg, a64::vandq_u8),
        (Arch::Aarch64, "vorrq_u8") => c2(ck, m, cfg, a64::vorrq_u8),
        (Arch::Aarch64, "vdupq_n_u8") => c1(ck, m, cfg, a64::vdupq_n_u8),
        (Arch::Aarch64, "vshrq_n_u8") => ci1(ck, m, cfg, p(), a64::vshrq_n_u8),
        (Arch::Aarch64, "vcltq_u8") => c2(ck, m, cfg, a64::vcltq_u8),
        (Arch::Aarch64, "vcgeq_u8") => c2(ck, m, cfg, a64::vcgeq_u8),
        (Arch::Aarch64, "vceqq_u8") => c2(ck, m, cfg, a64::vceqq_u8),
        (Arch::Aarch64, "vqtbl1q_u8") => c2(ck, m, cfg, a64::vqtbl1q_u8),
        (Arch::Aarch64, "vcntq_u8") => c1(ck, m, cfg, a64::vcntq_u8),
        (Arch::Aarch64, "vaddvq_u8") => c1(ck, m, cfg, a64::vaddvq_u8),
        (Arch::Aarch64, "vmaxvq_u8") => c1(ck, m, cfg, a64::vmaxvq_u8),
        (Arch::Aarch64, "vreinterpretq_u16_u8") => c1(ck, m, cfg, a64::vreinterpretq_u16_u8),
        (Arch::Aarch64, "vreinterpretq_u64_u8") => c1(ck, m, cfg, a64::vreinterpretq_u64_u8),
        (Arch::Aarch64, "vcombine_u8") => c2(ck, m, cfg, a64::vcombine_u8),
        (Arch::Aarch64, "vgetq_lane_u64") => ci1(ck, m, cfg, p(), a64::vgetq_lane_u64),
        (Arch::Aarch64, "vshrn_n_u16") => ci1(ck, m, cfg, p(), a64::vshrn_n_u16),
        (Arch::Aarch64, "vshrn_n_u64") => ci1(ck, m, cfg, p(), a64::vshrn_n_u64),
        (Arch::Aarch64, "vmovn_u64") => c1(ck, m, cfg, a64::vmovn_u64),
        (Arch::Aarch64, "vaddq_u64") => c2(ck, m, cfg, a64::vaddq_u64),
        (Arch::Aarch64, "vsraq_n_u64") => ci2(ck, m, cfg, p(), a64::vsraq_n_u64),
        (Arch::Aarch64, "vbslq_u64") => c3(ck, m, cfg, a64::vbslq_u64),
        (Arch::Aarch64, "vbslq_u32") => c3(ck, m, cfg, a64::vbslq_u32),
        (Arch::Aarch64, "vmull_u32") => c2(ck, m, cfg, a64::vmull_u32),
        (Arch::Aarch64, "vmlal_u32") => c3(ck, m, cfg, a64::vmlal_u32),
        (Arch::Aarch64, "veor3q_u8") => c3(ck, m, cfg, a64::veor3q_u8),
        (Arch::Aarch64, "vbcaxq_u8") => c3(ck, m, cfg, a64::vbcaxq_u8),
        (Arch::Aarch64, "vrax1q_u64") => c2(ck, m, cfg, a64::vrax1q_u64),
        (Arch::Aarch64, "vxarq_u64") => ci2(ck, m, cfg, p(), a64::vxarq_u64),
        (Arch::Aarch64, "vsha512hq_u64") => c3(ck, m, cfg, a64::vsha512hq_u64),
        (Arch::Aarch64, "vsha512h2q_u64") => c3(ck, m, cfg, a64::vsha512h2q_u64),
        (Arch::Aarch64, "vsha512su0q_u64") => c2(ck, m, cfg, a64::vsha512su0q_u64),
        (Arch::Aarch64, "vsha512su1q_u64") => c3(ck, m, cfg, a64::vsha512su1q_u64),
        (Arch::X86_64, "_mm_loadu_si128") => c1(ck, m, cfg, |a: U8x16| x86::_mm_loadu_si128(&a)),
        (Arch::X86_64, "_mm_storeu_si128") => c1(ck, m, cfg, x86::_mm_storeu_si128),
        (Arch::X86_64, "_mm_shuffle_epi8") => c2(ck, m, cfg, x86::_mm_shuffle_epi8),
        (Arch::X86_64, "_mm_shuffle_epi32") => ci1(ck, m, cfg, p(), x86::_mm_shuffle_epi32),
        (Arch::X86_64, "_mm_alignr_epi8") => ci2(ck, m, cfg, p(), x86::_mm_alignr_epi8),
        (Arch::X86_64, "_mm_blend_epi16") => ci2(ck, m, cfg, p(), x86::_mm_blend_epi16),
        (Arch::X86_64, "_mm_add_epi32") => c2(ck, m, cfg, x86::_mm_add_epi32),
        (Arch::X86_64, "_mm_set_epi32") => c4(ck, m, cfg, x86::_mm_set_epi32),
        (Arch::X86_64, "_mm_set_epi64x") => c2(ck, m, cfg, x86::_mm_set_epi64x),
        (Arch::X86_64, "_mm_xor_si128") => c2(ck, m, cfg, x86::_mm_xor_si128),
        (Arch::X86_64, "_mm_and_si128") => c2(ck, m, cfg, x86::_mm_and_si128),
        (Arch::X86_64, "_mm_or_si128") => c2(ck, m, cfg, x86::_mm_or_si128),
        (Arch::X86_64, "_mm_sha256rnds2_epu32") => c3(ck, m, cfg, x86::_mm_sha256rnds2_epu32),
        (Arch::X86_64, "_mm_sha256msg1_epu32") => c2(ck, m, cfg, x86::_mm_sha256msg1_epu32),
        (Arch::X86_64, "_mm_sha256msg2_epu32") => c2(ck, m, cfg, x86::_mm_sha256msg2_epu32),
        // 256/512-bit families (MODELS.md §10), vectors as `Kv<N>`.
        (Arch::X86_64, "_mm512_loadu_si512") => c1(ck, m, cfg, |mem: Kv<64>| Kv(x86::_mm512_loadu_si512(&mem.0))),
        (Arch::X86_64, "_mm512_storeu_si512") => c1(ck, m, cfg, |a: Kv<64>| Kv(x86::_mm512_storeu_si512(a.0))),
        (Arch::X86_64, "_mm512_add_epi32") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_add_epi32(a.0, b.0))),
        (Arch::X86_64, "_mm512_add_epi64") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_add_epi64(a.0, b.0))),
        (Arch::X86_64, "_mm512_sub_epi32") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_sub_epi32(a.0, b.0))),
        (Arch::X86_64, "_mm512_sub_epi64") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_sub_epi64(a.0, b.0))),
        (Arch::X86_64, "_mm512_xor_si512") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_xor_si512(a.0, b.0))),
        (Arch::X86_64, "_mm512_and_si512") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_and_si512(a.0, b.0))),
        (Arch::X86_64, "_mm512_or_si512") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_or_si512(a.0, b.0))),
        (Arch::X86_64, "_mm512_andnot_si512") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_andnot_si512(a.0, b.0))),
        (Arch::X86_64, "_mm512_ternarylogic_epi32") => ci3(ck, m, cfg, p(), |a: Kv<64>, b: Kv<64>, c: Kv<64>, imm: i32| Kv(x86::_mm512_ternarylogic_epi32(a.0, b.0, c.0, imm))),
        (Arch::X86_64, "_mm512_ternarylogic_epi64") => ci3(ck, m, cfg, p(), |a: Kv<64>, b: Kv<64>, c: Kv<64>, imm: i32| Kv(x86::_mm512_ternarylogic_epi64(a.0, b.0, c.0, imm))),
        (Arch::X86_64, "_mm512_rol_epi32") => ci1(ck, m, cfg, p(), |a: Kv<64>, imm: i32| Kv(x86::_mm512_rol_epi32(a.0, imm))),
        (Arch::X86_64, "_mm512_ror_epi32") => ci1(ck, m, cfg, p(), |a: Kv<64>, imm: i32| Kv(x86::_mm512_ror_epi32(a.0, imm))),
        (Arch::X86_64, "_mm512_rol_epi64") => ci1(ck, m, cfg, p(), |a: Kv<64>, imm: i32| Kv(x86::_mm512_rol_epi64(a.0, imm))),
        (Arch::X86_64, "_mm512_ror_epi64") => ci1(ck, m, cfg, p(), |a: Kv<64>, imm: i32| Kv(x86::_mm512_ror_epi64(a.0, imm))),
        (Arch::X86_64, "_mm512_rolv_epi32") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_rolv_epi32(a.0, b.0))),
        (Arch::X86_64, "_mm512_rorv_epi32") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_rorv_epi32(a.0, b.0))),
        (Arch::X86_64, "_mm512_rolv_epi64") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_rolv_epi64(a.0, b.0))),
        (Arch::X86_64, "_mm512_rorv_epi64") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_rorv_epi64(a.0, b.0))),
        (Arch::X86_64, "_mm512_slli_epi32") => ci1(ck, m, cfg, p(), |a: Kv<64>, imm: i32| Kv(x86::_mm512_slli_epi32(a.0, imm))),
        (Arch::X86_64, "_mm512_srli_epi32") => ci1(ck, m, cfg, p(), |a: Kv<64>, imm: i32| Kv(x86::_mm512_srli_epi32(a.0, imm))),
        (Arch::X86_64, "_mm512_slli_epi64") => ci1(ck, m, cfg, p(), |a: Kv<64>, imm: i32| Kv(x86::_mm512_slli_epi64(a.0, imm))),
        (Arch::X86_64, "_mm512_srli_epi64") => ci1(ck, m, cfg, p(), |a: Kv<64>, imm: i32| Kv(x86::_mm512_srli_epi64(a.0, imm))),
        (Arch::X86_64, "_mm512_sllv_epi64") => c2(ck, m, cfg, |a: Kv<64>, count: Kv<64>| Kv(x86::_mm512_sllv_epi64(a.0, count.0))),
        (Arch::X86_64, "_mm512_srlv_epi64") => c2(ck, m, cfg, |a: Kv<64>, count: Kv<64>| Kv(x86::_mm512_srlv_epi64(a.0, count.0))),
        (Arch::X86_64, "_mm512_shuffle_epi8") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_shuffle_epi8(a.0, b.0))),
        (Arch::X86_64, "_mm512_permutexvar_epi32") => c2(ck, m, cfg, |idx: Kv<64>, a: Kv<64>| Kv(x86::_mm512_permutexvar_epi32(idx.0, a.0))),
        (Arch::X86_64, "_mm512_permutexvar_epi64") => c2(ck, m, cfg, |idx: Kv<64>, a: Kv<64>| Kv(x86::_mm512_permutexvar_epi64(idx.0, a.0))),
        (Arch::X86_64, "_mm512_permutex2var_epi64") => c3(ck, m, cfg, |a: Kv<64>, idx: Kv<64>, b: Kv<64>| Kv(x86::_mm512_permutex2var_epi64(a.0, idx.0, b.0))),
        (Arch::X86_64, "_mm512_shuffle_i32x4") => ci2(ck, m, cfg, p(), |a: Kv<64>, b: Kv<64>, imm: i32| Kv(x86::_mm512_shuffle_i32x4(a.0, b.0, imm))),
        (Arch::X86_64, "_mm512_shuffle_i64x2") => ci2(ck, m, cfg, p(), |a: Kv<64>, b: Kv<64>, imm: i32| Kv(x86::_mm512_shuffle_i64x2(a.0, b.0, imm))),
        (Arch::X86_64, "_mm512_unpacklo_epi32") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_unpacklo_epi32(a.0, b.0))),
        (Arch::X86_64, "_mm512_unpackhi_epi32") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_unpackhi_epi32(a.0, b.0))),
        (Arch::X86_64, "_mm512_unpacklo_epi64") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_unpacklo_epi64(a.0, b.0))),
        (Arch::X86_64, "_mm512_unpackhi_epi64") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_unpackhi_epi64(a.0, b.0))),
        (Arch::X86_64, "_mm512_set1_epi32") => c1(ck, m, cfg, |a: i32| Kv(x86::_mm512_set1_epi32(a))),
        (Arch::X86_64, "_mm512_set1_epi64") => c1(ck, m, cfg, |a: i64| Kv(x86::_mm512_set1_epi64(a))),
        (Arch::X86_64, "_mm512_mask_blend_epi32") => c3(ck, m, cfg, |k: u16, a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_mask_blend_epi32(k, a.0, b.0))),
        (Arch::X86_64, "_mm512_mask_blend_epi64") => c3(ck, m, cfg, |k: u8, a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_mask_blend_epi64(k, a.0, b.0))),
        (Arch::X86_64, "_mm512_cmplt_epu64_mask") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| x86::_mm512_cmplt_epu64_mask(a.0, b.0)),
        (Arch::X86_64, "_mm512_cmpeq_epi64_mask") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| x86::_mm512_cmpeq_epi64_mask(a.0, b.0)),
        (Arch::X86_64, "_mm512_cmpeq_epi32_mask") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| x86::_mm512_cmpeq_epi32_mask(a.0, b.0)),
        (Arch::X86_64, "_mm512_maskz_mov_epi32") => c2(ck, m, cfg, |k: u16, a: Kv<64>| Kv(x86::_mm512_maskz_mov_epi32(k, a.0))),
        (Arch::X86_64, "_mm512_mask_mov_epi32") => c3(ck, m, cfg, |src: Kv<64>, k: u16, a: Kv<64>| Kv(x86::_mm512_mask_mov_epi32(src.0, k, a.0))),
        (Arch::X86_64, "_mm512_maskz_mov_epi64") => c2(ck, m, cfg, |k: u8, a: Kv<64>| Kv(x86::_mm512_maskz_mov_epi64(k, a.0))),
        (Arch::X86_64, "_mm512_mask_mov_epi64") => c3(ck, m, cfg, |src: Kv<64>, k: u8, a: Kv<64>| Kv(x86::_mm512_mask_mov_epi64(src.0, k, a.0))),
        (Arch::X86_64, "_mm512_mullo_epi64") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_mullo_epi64(a.0, b.0))),
        (Arch::X86_64, "_mm512_mul_epu32") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_mul_epu32(a.0, b.0))),
        (Arch::X86_64, "_mm256_ternarylogic_epi32") => ci3(ck, m, cfg, p(), |a: Kv<32>, b: Kv<32>, c: Kv<32>, imm: i32| Kv(x86::_mm256_ternarylogic_epi32(a.0, b.0, c.0, imm))),
        (Arch::X86_64, "_mm256_ternarylogic_epi64") => ci3(ck, m, cfg, p(), |a: Kv<32>, b: Kv<32>, c: Kv<32>, imm: i32| Kv(x86::_mm256_ternarylogic_epi64(a.0, b.0, c.0, imm))),
        (Arch::X86_64, "_mm256_rol_epi32") => ci1(ck, m, cfg, p(), |a: Kv<32>, imm: i32| Kv(x86::_mm256_rol_epi32(a.0, imm))),
        (Arch::X86_64, "_mm256_ror_epi32") => ci1(ck, m, cfg, p(), |a: Kv<32>, imm: i32| Kv(x86::_mm256_ror_epi32(a.0, imm))),
        (Arch::X86_64, "_mm256_rol_epi64") => ci1(ck, m, cfg, p(), |a: Kv<32>, imm: i32| Kv(x86::_mm256_rol_epi64(a.0, imm))),
        (Arch::X86_64, "_mm256_ror_epi64") => ci1(ck, m, cfg, p(), |a: Kv<32>, imm: i32| Kv(x86::_mm256_ror_epi64(a.0, imm))),
        (Arch::X86_64, "_mm512_madd52lo_epu64") => c3(ck, m, cfg, |a: Kv<64>, b: Kv<64>, c: Kv<64>| Kv(x86::_mm512_madd52lo_epu64(a.0, b.0, c.0))),
        (Arch::X86_64, "_mm512_madd52hi_epu64") => c3(ck, m, cfg, |a: Kv<64>, b: Kv<64>, c: Kv<64>| Kv(x86::_mm512_madd52hi_epu64(a.0, b.0, c.0))),
        (Arch::X86_64, "_mm256_madd52lo_epu64") => c3(ck, m, cfg, |a: Kv<32>, b: Kv<32>, c: Kv<32>| Kv(x86::_mm256_madd52lo_epu64(a.0, b.0, c.0))),
        (Arch::X86_64, "_mm256_madd52hi_epu64") => c3(ck, m, cfg, |a: Kv<32>, b: Kv<32>, c: Kv<32>| Kv(x86::_mm256_madd52hi_epu64(a.0, b.0, c.0))),
        (Arch::X86_64, "_mm512_gf2p8mul_epi8") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_gf2p8mul_epi8(a.0, b.0))),
        (Arch::X86_64, "_mm256_gf2p8mul_epi8") => c2(ck, m, cfg, |a: Kv<32>, b: Kv<32>| Kv(x86::_mm256_gf2p8mul_epi8(a.0, b.0))),
        (Arch::X86_64, "_mm_gf2p8mul_epi8") => c2(ck, m, cfg, |a: Kv<16>, b: Kv<16>| Kv(x86::_mm_gf2p8mul_epi8(a.0, b.0))),
        (Arch::X86_64, "_mm512_gf2p8affine_epi64_epi8") => ci2(ck, m, cfg, p(), |x: Kv<64>, a: Kv<64>, imm: i32| Kv(x86::_mm512_gf2p8affine_epi64_epi8(x.0, a.0, imm))),
        (Arch::X86_64, "_mm256_gf2p8affine_epi64_epi8") => ci2(ck, m, cfg, p(), |x: Kv<32>, a: Kv<32>, imm: i32| Kv(x86::_mm256_gf2p8affine_epi64_epi8(x.0, a.0, imm))),
        (Arch::X86_64, "_mm_gf2p8affine_epi64_epi8") => ci2(ck, m, cfg, p(), |x: Kv<16>, a: Kv<16>, imm: i32| Kv(x86::_mm_gf2p8affine_epi64_epi8(x.0, a.0, imm))),
        (Arch::X86_64, "_mm512_gf2p8affineinv_epi64_epi8") => ci2(ck, m, cfg, p(), |x: Kv<64>, a: Kv<64>, imm: i32| Kv(x86::_mm512_gf2p8affineinv_epi64_epi8(x.0, a.0, imm))),
        (Arch::X86_64, "_mm256_gf2p8affineinv_epi64_epi8") => ci2(ck, m, cfg, p(), |x: Kv<32>, a: Kv<32>, imm: i32| Kv(x86::_mm256_gf2p8affineinv_epi64_epi8(x.0, a.0, imm))),
        (Arch::X86_64, "_mm_gf2p8affineinv_epi64_epi8") => ci2(ck, m, cfg, p(), |x: Kv<16>, a: Kv<16>, imm: i32| Kv(x86::_mm_gf2p8affineinv_epi64_epi8(x.0, a.0, imm))),
        (Arch::X86_64, "_mm512_permutexvar_epi8") => c2(ck, m, cfg, |idx: Kv<64>, a: Kv<64>| Kv(x86::_mm512_permutexvar_epi8(idx.0, a.0))),
        (Arch::X86_64, "_mm512_permutex2var_epi8") => c3(ck, m, cfg, |a: Kv<64>, idx: Kv<64>, b: Kv<64>| Kv(x86::_mm512_permutex2var_epi8(a.0, idx.0, b.0))),
        (Arch::X86_64, "_mm512_multishift_epi64_epi8") => c2(ck, m, cfg, |a: Kv<64>, b: Kv<64>| Kv(x86::_mm512_multishift_epi64_epi8(a.0, b.0))),
        (Arch::X86_64, "_mm512_shldv_epi64") => c3(ck, m, cfg, |a: Kv<64>, b: Kv<64>, c: Kv<64>| Kv(x86::_mm512_shldv_epi64(a.0, b.0, c.0))),
        (Arch::X86_64, "_mm512_shrdv_epi64") => c3(ck, m, cfg, |a: Kv<64>, b: Kv<64>, c: Kv<64>| Kv(x86::_mm512_shrdv_epi64(a.0, b.0, c.0))),
        (Arch::X86_64, "_mm512_shldv_epi32") => c3(ck, m, cfg, |a: Kv<64>, b: Kv<64>, c: Kv<64>| Kv(x86::_mm512_shldv_epi32(a.0, b.0, c.0))),
        (Arch::X86_64, "_mm512_shrdv_epi32") => c3(ck, m, cfg, |a: Kv<64>, b: Kv<64>, c: Kv<64>| Kv(x86::_mm512_shrdv_epi32(a.0, b.0, c.0))),
        (Arch::X86_64, "_mm512_shldi_epi64") => ci2(ck, m, cfg, p(), |a: Kv<64>, b: Kv<64>, imm: i32| Kv(x86::_mm512_shldi_epi64(a.0, b.0, imm))),
        (Arch::X86_64, "_mm512_shldi_epi32") => ci2(ck, m, cfg, p(), |a: Kv<64>, b: Kv<64>, imm: i32| Kv(x86::_mm512_shldi_epi32(a.0, b.0, imm))),
        (Arch::X86_64, "_mm512_popcnt_epi64") => c1(ck, m, cfg, |a: Kv<64>| Kv(x86::_mm512_popcnt_epi64(a.0))),
        (Arch::X86_64, "_mm512_popcnt_epi32") => c1(ck, m, cfg, |a: Kv<64>| Kv(x86::_mm512_popcnt_epi32(a.0))),
        (Arch::X86_64, "_mm512_popcnt_epi8") => c1(ck, m, cfg, |a: Kv<64>| Kv(x86::_mm512_popcnt_epi8(a.0))),
        (Arch::X86_64, "_mm512_popcnt_epi16") => c1(ck, m, cfg, |a: Kv<64>| Kv(x86::_mm512_popcnt_epi16(a.0))),
        (Arch::X86_64, "_mm256_loadu_si256") => c1(ck, m, cfg, |mem: Kv<32>| Kv(x86::_mm256_loadu_si256(&mem.0))),
        (Arch::X86_64, "_mm256_storeu_si256") => c1(ck, m, cfg, |a: Kv<32>| Kv(x86::_mm256_storeu_si256(a.0))),
        (Arch::X86_64, "_mm256_add_epi32") => c2(ck, m, cfg, |a: Kv<32>, b: Kv<32>| Kv(x86::_mm256_add_epi32(a.0, b.0))),
        (Arch::X86_64, "_mm256_add_epi64") => c2(ck, m, cfg, |a: Kv<32>, b: Kv<32>| Kv(x86::_mm256_add_epi64(a.0, b.0))),
        (Arch::X86_64, "_mm256_xor_si256") => c2(ck, m, cfg, |a: Kv<32>, b: Kv<32>| Kv(x86::_mm256_xor_si256(a.0, b.0))),
        (Arch::X86_64, "_mm256_and_si256") => c2(ck, m, cfg, |a: Kv<32>, b: Kv<32>| Kv(x86::_mm256_and_si256(a.0, b.0))),
        (Arch::X86_64, "_mm256_or_si256") => c2(ck, m, cfg, |a: Kv<32>, b: Kv<32>| Kv(x86::_mm256_or_si256(a.0, b.0))),
        (Arch::X86_64, "_mm256_shuffle_epi8") => c2(ck, m, cfg, |a: Kv<32>, b: Kv<32>| Kv(x86::_mm256_shuffle_epi8(a.0, b.0))),
        (Arch::X86_64, "_mm256_permutevar8x32_epi32") => c2(ck, m, cfg, |a: Kv<32>, idx: Kv<32>| Kv(x86::_mm256_permutevar8x32_epi32(a.0, idx.0))),
        (Arch::X86_64, "_mm256_slli_epi32") => ci1(ck, m, cfg, p(), |a: Kv<32>, imm: i32| Kv(x86::_mm256_slli_epi32(a.0, imm))),
        (Arch::X86_64, "_mm256_srli_epi32") => ci1(ck, m, cfg, p(), |a: Kv<32>, imm: i32| Kv(x86::_mm256_srli_epi32(a.0, imm))),
        (Arch::X86_64, "_mm256_slli_epi64") => ci1(ck, m, cfg, p(), |a: Kv<32>, imm: i32| Kv(x86::_mm256_slli_epi64(a.0, imm))),
        (Arch::X86_64, "_mm256_srli_epi64") => ci1(ck, m, cfg, p(), |a: Kv<32>, imm: i32| Kv(x86::_mm256_srli_epi64(a.0, imm))),
        (Arch::X86_64, "_mm256_blend_epi32") => ci2(ck, m, cfg, p(), |a: Kv<32>, b: Kv<32>, imm: i32| Kv(x86::_mm256_blend_epi32(a.0, b.0, imm))),
        (Arch::X86_64, "_mm256_alignr_epi8") => ci2(ck, m, cfg, p(), |a: Kv<32>, b: Kv<32>, imm: i32| Kv(x86::_mm256_alignr_epi8(a.0, b.0, imm))),
        (Arch::X86_64, "_mm256_set1_epi32") => c1(ck, m, cfg, |a: i32| Kv(x86::_mm256_set1_epi32(a))),
        (Arch::X86_64, "_mm256_set1_epi64x") => c1(ck, m, cfg, |a: i64| Kv(x86::_mm256_set1_epi64x(a))),

        _ => Outcome::skipped(m.name, "no kernel cross-check for this model"),
    }
}

/// Run `jobs` on `threads` worker threads, each with its own [`Checker`]
/// (kernel environments are not `Send`) and a large stack; results in job order.
fn parallel<J: Sync, T: Send>(jobs: &[J], threads: usize, work: impl Fn(&Checker, &J) -> T + Sync) -> Vec<T> {
    const STACK: usize = 256 << 20;
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<T>>> = Mutex::new((0..jobs.len()).map(|_| None).collect());
    let threads = threads.clamp(1, jobs.len().max(1));
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                std::thread::Builder::new()
                    .stack_size(STACK)
                    .spawn_scoped(s, || {
                        sandblaster_kernel::util::set_stack_limit(STACK - (16 << 20));
                        let ck = Checker::new().unwrap_or_else(|e| panic!("loading the core models failed: {e}"));
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            if i >= jobs.len() {
                                break;
                            }
                            let r = work(&ck, &jobs[i]);
                            results.lock().unwrap()[i] = Some(r);
                        }
                    })
                    .expect("spawn worker")
            })
            .collect();
        for h in handles {
            h.join().expect("kernel cross-check worker panicked");
        }
    });
    results.into_inner().unwrap().into_iter().map(|r| r.expect("every job ran")).collect()
}

/// The most kernel workers of [`default_threads`].
pub const MAX_KERNEL_THREADS: usize = 16;

/// The default worker count: available parallelism, at most
/// [`MAX_KERNEL_THREADS`]; `SANDBLASTER_KERNEL_THREADS=N` overrides it (to
/// limit the parallelism on a shared machine). Kernel threads scale since
/// the counting allocator the kernel links (`sandblaster-memguard`) accounts
/// per thread: 16 cross-check jobs of `_mm512_add_epi32` take 15 s on one
/// thread and 1.3 s on 16 (Apple M5 Pro; 23.7 s on 16 with the former
/// process-wide counters, which made campaigns run in shard processes).
pub fn default_threads() -> usize {
    if let Some(n) = std::env::var("SANDBLASTER_KERNEL_THREADS").ok().and_then(|v| v.parse::<usize>().ok()).filter(|&n| n > 0) {
        return n;
    }
    std::thread::available_parallelism().map_or(4, |n| n.get()).min(MAX_KERNEL_THREADS)
}

/// Immediates per job of an immediate model (its campaign is split into
/// [`Part`]s so that jobs balance across workers).
const CHUNK: i32 = 16;

/// The models of `archs`, in registry order.
fn campaign_models(archs: &[Arch]) -> Vec<&'static CoreModel> {
    archs.iter().flat_map(|&a| coretext::models(a)).collect()
}

/// The jobs of a campaign over `models`: one per model without immediates,
/// one per [`Part`] (at most [`CHUNK`] immediates) of an immediate model.
fn campaign_jobs(models: &[&'static CoreModel], cfg: &Config) -> Vec<(usize, Option<Part>)> {
    let mut jobs: Vec<(usize, Option<Part>)> = Vec::new();
    for (i, m) in models.iter().enumerate() {
        if m.imms.is_empty() {
            jobs.push((i, None));
        } else {
            jobs.extend(Part::split(m, cfg, CHUNK).into_iter().map(|p| (i, Some(p))));
        }
    }
    jobs
}

/// Reassemble job outcomes (in job order) into one outcome per model.
fn reassemble(models: &[&'static CoreModel], cfg: &Config, jobs: &[(usize, Option<Part>)], results: Vec<Outcome>) -> Vec<Outcome> {
    let mut per_model: Vec<Vec<Outcome>> = models.iter().map(|_| Vec::new()).collect();
    for ((i, _), o) in jobs.iter().zip(results) {
        per_model[*i].push(o);
    }
    models
        .iter()
        .zip(per_model)
        .map(|(m, parts)| if m.imms.is_empty() { parts.into_iter().next().expect("one job") } else { merge_parts(m, cfg, parts) })
        .collect()
}

/// Cross-check every core model of `archs` ([`crosscheck_model`]) on
/// `threads` worker threads of this process; outcomes in registry order.
pub fn crosscheck_all(archs: &[Arch], cfg: &Config, threads: usize) -> Vec<Outcome> {
    let models = campaign_models(archs);
    let jobs = campaign_jobs(&models, cfg);
    let results = parallel(&jobs, threads, |ck, (i, part)| crosscheck_part(ck, models[*i], cfg, part.as_ref()));
    reassemble(&models, cfg, &jobs, results)
}

// ---------------------------------------------------------------------------
// Compression cross-checks

pub use crate::coretext::checks::{COMPRESS_CHECKS, compress_check_arch};

type State = [u32; 8];
type Block = [u8; 64];

/// The inputs of the compression cross-checks: the corner states (H0,
/// all-zero, all-one) × corner blocks (the padded "abc" block, all-zero,
/// all-one, the fixed padding block of a 64-byte message, 0..63), then `n`
/// random `(state, block)` pairs from `seed` (lanes drawn like the [`diff`]
/// campaigns).
pub fn compress_inputs(n: u64, seed: u64) -> (Vec<(State, Block)>, usize) {
    let mut abc = [0u8; 64];
    abc[..3].copy_from_slice(b"abc");
    abc[3] = 0x80;
    abc[63] = 24;
    let mut pad = [0u8; 64];
    pad[0] = 0x80;
    pad[62] = 0x02;
    let states = [fips::H0, [0; 8], [u32::MAX; 8]];
    let blocks = [abc, [0; 64], [0xff; 64], pad, core::array::from_fn(|i| i as u8)];
    let mut cases: Vec<(State, Block)> = states.iter().flat_map(|s| blocks.iter().map(move |b| (*s, *b))).collect();
    let corners = cases.len();
    let mut rng = crate::rng::Rng::new(seed);
    for _ in 0..n {
        cases.push((State::random(&mut rng), Block::random(&mut rng)));
    }
    (cases, corners)
}

/// Evaluate the three core compressions on one input and compare them with
/// each other and with the executable models; returns, per
/// [`COMPRESS_CHECKS`] entry, `None` (agree) or a mismatch description.
fn compress_case(ck: &Checker, s: State, b: Block) -> [Option<String>; 5] {
    let core = |g: &str| ck.call_global::<State>(g, vec![s.to_term(&ck.kit), b.to_term(&ck.kit)]);
    let (core_fips, core_sha2, core_shani) =
        (core("checks::fips::compress"), core("checks::aarch64::compress_sha2"), core("checks::x86_64::compress_shani"));
    let exe_fips: Res<State> = Ok(fips::compress(s, &b));
    let exe_sha2: Res<State> = Ok(compress::compress_aarch64_models(s, &b));
    let exe_shani: Res<State> = Ok(compress::compress_x86_models(s, &b));
    let cmp = |x: &Res<State>, y: &Res<State>| {
        (x != y).then(|| format!("state = {s:08x?}, block = {b:02x?}: {x:08x?} != {y:08x?}"))
    };
    [
        cmp(&core_fips, &exe_fips),
        cmp(&core_sha2, &core_fips),
        cmp(&core_sha2, &exe_sha2),
        cmp(&core_shani, &core_fips),
        cmp(&core_shani, &exe_shani),
    ]
}

/// The compression cross-checks, by kernel evaluation on the inputs of
/// [`compress_inputs`] (`cfg.random_per_model` random ones), on `threads`
/// workers. One outcome per [`COMPRESS_CHECKS`] entry:
///
/// * `core_fips_vs_executable_fips`: the core-text FIPS 180-4 compression
///   (`checks::fips::compress`) = [`fips::compress`];
/// * `core_compress_sha2_vs_core_fips` / `_vs_executable_model`: the
///   compression assembled in core text from the aarch64 core models
///   (`checks::aarch64::compress_sha2`, the `sha2` crate's sequence) = the
///   core FIPS compression, and = [`compress::compress_aarch64_models`];
/// * the same two for SHA-NI (`checks::x86_64::compress_shani`).
pub fn compress_checks(cfg: &Config, threads: usize) -> Vec<Outcome> {
    const CHUNK: usize = 4;
    let seed = cfg.seed_for("core_compress");
    let (cases, corners) = compress_inputs(cfg.random_per_model, seed);
    let chunks: Vec<(usize, &[(State, Block)])> = cases.chunks(CHUNK).enumerate().map(|(i, c)| (i * CHUNK, c)).collect();
    let results = parallel(&chunks, threads, |ck, (start, chunk)| {
        chunk.iter().enumerate().map(|(k, (s, b))| (start + k, compress_case(ck, *s, *b))).collect::<Vec<_>>()
    });
    COMPRESS_CHECKS
        .iter()
        .enumerate()
        .map(|(j, name)| {
            let mut o = Outcome {
                name: name.to_string(),
                random: cfg.random_per_model,
                corner: corners as u64,
                immediates: None,
                mismatches: 0,
                first_mismatch: None,
                skipped: None,
                seed,
            };
            for (idx, r) in results.iter().flatten() {
                if let Some(m) = &r[j] {
                    o.mismatches += 1;
                    if o.first_mismatch.is_none() {
                        let phase = if *idx < corners { "corner" } else { "random" };
                        o.first_mismatch = Some(format!("{name} ({phase} case {idx}, seed {seed:#x}): {m}"));
                    }
                }
            }
            o
        })
        .collect()
}

/// The compression check configuration: [`RANDOM_PER_COMPRESSION`] random cases.
pub fn compress_config() -> Config {
    Config {
        random_per_model: RANDOM_PER_COMPRESSION,
        seed: KERNEL_SEED,
    }
}
