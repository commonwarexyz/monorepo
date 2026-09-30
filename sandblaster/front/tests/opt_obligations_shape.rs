//! D1 prototype (optimizer plan O3; design §7.5, §12.1): the per-literal
//! loop-summary lemmas `lemma_0 … lemma_K` of two loops, generated and
//! proven with `auto` plus the bit library (`lemmas/bits.core` and the
//! per-literal families of `auto::bitlib`) through a hand-rolled builder,
//! with the step count of every obligation recorded by class.
//!
//! * `shape_go` — QMDB's MMR peak search (`sandblaster/fixtures/qmdb/sandblaster/merkle.rs`, read
//!   from the file: the items are elaborated exactly as written), K = 63;
//! * `find_block_go` — corpus P4, the same pattern without the `2^62`
//!   bound (`tests/opt_corpus/dsl/mod.rs`, imported by O1 from
//!   `research/optdesign/corpus`), K = 64.
//!
//! **The lemmas.** For fuel `f` with ghost entry value `L` (leaves / `n`)
//! and target `t`, the invariant (design §12.1 classes) is
//!
//! ```text
//! width = 2^(f−1)               (Geometric;   f ≥ 1)
//! rem   = L & (2^f − 1)         (BitDigit)
//! start + rem = L               (Conserved, in Int)
//! before = count_ones(L >> f)   (GuardCount; 0 at f = 64)
//! pos + before = 2·start        (Linear, in Int; shape only)
//! found = if t < start { Some(F(L, t)) } else { None }   (FirstMatch)
//! ```
//!
//! and `lemma_f : Π state L (requires) (L ≤ 2^62, shape only) (inv).
//! loop(f, state) = if t < L { Some(F(L, t)) } else { None }` where `F` is
//! the closed form of the design's residual (`h = 63 − lz(L ^ t)`, …),
//! defined once as a transparent helper (`d1::shape_cf`, `d1::block_cf`).
//!
//! **The builder.** `lemma_0` is one `auto` call. For `f ≥ 1`: `Delta` of
//! the loop at the literal fuel, a dependent split on the guard
//! `rem < width` (auto's `case_split_with`), and in each arm an application
//! of `lemma_{f−1}` to the recursive call's arguments whose irrelevant
//! arguments — the callee's requires and the invariant at the new state —
//! are the obligations, each proven by one `auto` call (after a
//! conversion/assumption fast path) with the library lemma instances of
//! its class as hints. The peak arm's `found` obligation is split further
//! on the outermost test of the new `found` (`t < start`, then
//! `t − start < width` for `shape_go`; the conjunction for P4) until it is
//! `Some(..)` (the hit) or the old `found` (a miss, one `auto` call). The
//! hit leaf derives `t >> f = L >> f`, bit `f−1` of `L` set and of `t`
//! clear (three `auto` calls), `lz(L ^ t) = 64 − f` by
//! `clz_xor_prefix_{f−1}` (a library instance), rewrites `lz(L ^ t)` in the
//! goal (a transport: the closed form's shifts become literal), decides the
//! closed form's guard `t < start + width` (one call, then a transport),
//! and proves `Some(C(x̄)) = Some(C(ȳ))` field by field (one call per field;
//! `cnt(a) = cnt(b)` through `a = b` and `eq::cong`), assembled by one
//! transport per field. Every lemma is hash-consed (identical subterms
//! shared; the proofs repeat the quoted loop body and the requires proofs
//! heavily), added with `Env::add_def` (the kernel checks it) and used by
//! the next one; the call-site lemma (`shape`, `find_block` equal their
//! closed forms) applies `lemma_K` at the entry state.
//!
//! The test prints the step counts per obligation class and per lemma (the
//! D1 record of the O3 report: `cargo test --test opt_obligations_shape --
//! --nocapture`; `D1_TRACE=1` traces every obligation, `D1_MAX_F=k` stops
//! after `lemma_k`) and asserts the D1 thresholds: every lemma closes, each
//! within 5·10^6 steps (obligations, skeleton and the kernel check), each
//! loop within 5·10^8.

use std::collections::BTreeMap;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use sandblaster_front::auto::bitlib::{self, Family};
use sandblaster_front::auto::lemmas::LemmaDb;
use sandblaster_front::auto::search::{Engine, R};
use sandblaster_front::auto::state::St;
use sandblaster_front::auto::util::{apps, as_eq, irr_entry, prefix, venv_push};
use sandblaster_front::auto::{Auto, AutoConfig};
use sandblaster_front::driver;
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::prover::{Goal, Hint, ObligationId, ObligationKind, Prover};
use sandblaster_front::span::Span;
use sandblaster_front::target::TargetInfo;
use sandblaster_kernel::api::{Ctx, Env};
use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, Name, PrimOp, Recursion, Rel, Term, Tm, Width};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, EnvEntry, Head, Neutral, V, Value};

/// Step budget of one obligation (a failure beyond it is recorded).
const OBLIGATION_BUDGET: u64 = 100_000_000;
/// D1 thresholds (plan O3).
const PER_LEMMA: u64 = 5_000_000;
const PER_LOOP: u64 = 500_000_000;

// ---------------------------------------------------------------------------
// Sources.
// ---------------------------------------------------------------------------

/// A top-level item (with its doc comments and attributes) of a source file,
/// found by the start of its first line.
fn item(src: &str, marker: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let i = lines.iter().position(|l| l.starts_with(marker)).unwrap_or_else(|| panic!("no item `{marker}`"));
    let mut start = i;
    while start > 0 && (lines[start - 1].starts_with("///") || lines[start - 1].starts_with("#[")) {
        start -= 1;
    }
    let (mut depth, mut end, mut opened) = (0i32, i, false);
    for (j, l) in lines.iter().enumerate().skip(i) {
        for c in l.chars() {
            match c {
                '{' => {
                    depth += 1;
                    opened = true
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        end = j;
        if (opened && depth == 0) || (!opened && l.trim_end().ends_with(';')) {
            break;
        }
    }
    lines[start..=end].join("\n")
}

fn repo(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Elaborate the given items (a one-module crate) with the standard prover
/// chain; returns the elaborated environment (with the lemma files).
fn elaborate(items: &[String]) -> Env {
    let src = format!("#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n{}\n", items.join("\n\n"));
    let fs = MemFs::from_files([("r/mod.rs", src.as_str())]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let mut chain = ProverChain::standard();
    let out = elab::elaborate(c.krate.as_ref().unwrap(), &mut chain, &elab::Options { exec_only: true, ..Default::default() });
    for d in &out.defs {
        assert_eq!(d.status, elab::DefStatus::Checked, "{}", d.name);
    }
    out.env
}

// ---------------------------------------------------------------------------
// Statistics.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ClassStat {
    n: u32,
    ok: u32,
    steps: u64,
    max: u64,
    time: Duration,
    failure: Option<String>,
}

#[derive(Default)]
struct Stats {
    classes: BTreeMap<String, ClassStat>,
    /// Per lemma: (name, obligation steps, kernel check steps, time).
    lemmas: Vec<(String, u64, u64, Duration, bool)>,
    current: u64,
    /// Nodes of the obligation proofs of the current lemma.
    proof_nodes: usize,
}

impl Stats {
    fn record(&mut self, class: &str, steps: u64, time: Duration, failure: Option<String>) {
        let c = self.classes.entry(class.to_string()).or_default();
        c.n += 1;
        c.steps += steps;
        c.max = c.max.max(steps);
        c.time += time;
        self.current += steps;
        match failure {
            None => c.ok += 1,
            Some(f) => {
                if c.failure.is_none() {
                    c.failure = Some(f);
                }
            }
        }
    }

    fn report(&self, label: &str) -> String {
        let mut s = format!("\n== {label}: obligations by class (steps: total / max per obligation) ==\n");
        s.push_str(&format!("{:<22} {:>5} {:>5} {:>14} {:>12} {:>10}\n", "class", "n", "ok", "steps total", "max", "time"));
        for (k, c) in &self.classes {
            s.push_str(&format!("{:<22} {:>5} {:>5} {:>14} {:>12} {:>9.2?}\n", k, c.n, c.ok, c.steps, c.max, c.time));
        }
        let total: u64 = self.lemmas.iter().map(|l| l.1 + l.2).sum();
        let worst = self.lemmas.iter().map(|l| l.1 + l.2).max().unwrap_or(0);
        let time: Duration = self.lemmas.iter().map(|l| l.3).sum();
        let closed = self.lemmas.iter().filter(|l| l.4).count();
        s.push_str(&format!(
            "lemmas: {closed}/{} closed; steps total {total} (worst lemma {worst}, obligations + kernel check); time {time:.2?}\n",
            self.lemmas.len()
        ));
        for (k, c) in &self.classes {
            if let Some(f) = &c.failure {
                s.push_str(&format!("-- first failure of {k}:\n{f}\n"));
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Loop specifications.
// ---------------------------------------------------------------------------

/// A leaf of the peak arm's `found` split.
enum Leaf {
    Before,
    After,
    Hit,
}

trait Spec {
    fn label(&self) -> &'static str;
    /// The loop function.
    fn func(&self) -> &'static str;
    /// Its result type (core text).
    fn ret(&self) -> &'static str;
    fn k_max(&self) -> u32;
    /// Names of the data binders (the loop's parameters after the fuel) and
    /// of the ghost entry value.
    fn data(&self) -> &'static [&'static str];
    fn ghost(&self) -> &'static str;
    /// All binders of `lemma_f`: data, ghost, requires, invariant.
    fn binders(&self, f: u32) -> Vec<(String, String)>;
    /// The loop call of `lemma_f` (core text, in the lemma's binders).
    fn lhs(&self, f: u32) -> String;
    /// The closed-form result (core text).
    fn res(&self) -> String;
    /// Library lemma instances (core text) for an obligation class of
    /// `lemma_f` (the arm prefix is part of the class).
    fn hints(&self, f: u32, class: &str) -> Vec<String>;
    /// Which leaf of the `found` split a path (constructor indices) is.
    fn leaf(&self, path: &[u32]) -> Option<Leaf>;
    /// The payload's field names (obligation classes `hit.<field>`).
    fn field_names(&self) -> &'static [&'static str];
    /// The hit facts (`H1` quotient, `H2` bit of `L`, `H3` bit of `t`) an
    /// obligation class of the hit leaf uses.
    fn hit_facts(&self, class: &str) -> &'static [&'static str] {
        match class {
            "hit.bitT" => &["H1"],
            "hit.index" => &["H1", "H3"],
            "hit.after" => &["H2"],
            _ => &[],
        }
    }
    /// The call-site lemma: its name, statement and the entry function.
    fn entry(&self) -> (String, String);
    /// Family members the lemmas use.
    fn families(&self, f: u32) -> Vec<(Family, u32)> {
        let k = f.saturating_sub(1);
        let mut v =
            vec![(Family::MaskSplit, k), (Family::PopcntStep, k), (Family::LzRange, k), (Family::ClzXorPrefix, k), (Family::WshlExact, 1)];
        if k >= 1 {
            v.push((Family::WshlExact, k));
        }
        v.push((Family::PopcntShrZero, 63));
        v
    }
}

fn opt(ty: &str, c: &str, some: &str) -> String {
    format!("match {c} : Bool as _ return Option({ty}) with | false => None[{ty}] | true => Some[{ty}]({some}) end")
}

struct ShapeSpec;

impl Spec for ShapeSpec {
    fn label(&self) -> &'static str {
        "shape_go (QMDB merkle.rs)"
    }
    fn func(&self) -> &'static str {
        "crate::shape_go"
    }
    fn ret(&self) -> &'static str {
        "Option(crate::Shape)"
    }
    fn k_max(&self) -> u32 {
        63
    }
    fn data(&self) -> &'static [&'static str] {
        &["t", "rem", "w", "pos", "s", "b", "found"]
    }
    fn ghost(&self) -> &'static str {
        "L"
    }
    fn binders(&self, f: u32) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = ["t", "rem", "w", "pos", "s"].iter().map(|n| (n.to_string(), "U64".to_string())).collect();
        v.push(("b".into(), "U32".into()));
        v.push(("found".into(), "Option(crate::Shape)".into()));
        v.push(("L".into(), "U64".into()));
        v.push((".r0".into(), format!("Eq(Bool, #le_u32({f}u32, 63u32), true)")));
        v.push((
            ".r1".into(),
            "Eq(Bool, #le_int(#iadd(#cast_u64_int(s), #cast_u64_int(rem)), #cast_u64_int(crate::MAX_LEAVES)), true)".into(),
        ));
        v.push((".r2".into(), "Eq(Bool, #le_int(#cast_u64_int(pos), #imul(2int, #cast_u64_int(s))), true)".into()));
        v.push((".r3".into(), format!("Eq(Bool, #le_int(#iadd(#cast_u32_int(b), #cast_u32_int({f}u32)), 63int), true)")));
        v.push((".hL".into(), "Eq(Bool, #le_u64(L, 4611686018427387904u64), true)".into()));
        if f >= 1 {
            v.push((".iw".into(), format!("Eq(U64, w, {}u64)", 1u128 << (f - 1))));
        }
        v.push((".irem".into(), format!("Eq(U64, rem, #and_u64(L, {}u64))", (1u128 << f) - 1)));
        v.push((".is".into(), "Eq(Int, #iadd(#cast_u64_int(s), #cast_u64_int(rem)), #cast_u64_int(L))".into()));
        v.push((".ib".into(), format!("Eq(U32, b, #count_ones_u64(#wshr_u64(L, {f}u32)))")));
        v.push((".ipos".into(), "Eq(Int, #iadd(#cast_u64_int(pos), #cast_u32_int(b)), #imul(2int, #cast_u64_int(s)))".into()));
        v.push((
            ".ifound".into(),
            format!("Eq(Option(crate::Shape), found, {})", opt("crate::Shape", "#lt_u64(t, s)", "d1::shape_cf L t")),
        ));
        v
    }
    fn lhs(&self, f: u32) -> String {
        format!("crate::shape_go {f}u32 t rem w pos s b found .r0 .r1 .r2 .r3")
    }
    fn res(&self) -> String {
        opt("crate::Shape", "#lt_u64(t, L)", "d1::shape_cf L t")
    }
    fn hints(&self, f: u32, class: &str) -> Vec<String> {
        let k = f.saturating_sub(1);
        let split = |x: &str| format!("bits::mask_split_u64_{k} {x}");
        let step = format!("bits::popcnt_step_u64_{k} L");
        let hi = format!("#wshr_u64(#wshr_u64(L, {k}u32), 1u32)");
        let lf = format!("#wshr_u64(L, {f}u32)");
        match class {
            "idle.irem" | "peak.irem" | "hit.bitL" => vec![split("L")],
            "idle.ib" | "peak.ib" => vec![step, split("L")],
            "hit.bitT" | "hit.index" => vec![split("t")],
            "hit.after" => vec![split("L")],
            "hit.position" => vec![
                format!("bvrefl(U64, {hi}, {lf})"),
                format!("eq::cong U64 U32 (fun (y : U64) => #count_ones_u64(y)) ({hi}) ({lf}) (bvrefl(U64, {hi}, {lf}))"),
            ],
            "hit.before" => vec![format!("eq::cong U64 U32 (fun (y : U64) => #count_ones_u64(y)) ({hi}) ({lf}) (bvrefl(U64, {hi}, {lf}))")],
            "entry.ib" => {
                vec!["bits::popcnt_shr_zero_u64_63 L .(linarith([]; Eq(Bool, #lt_u64(L, 9223372036854775808u64), true); []))".into()]
            }
            _ => vec![],
        }
    }
    fn field_names(&self) -> &'static [&'static str] {
        &["height", "width", "position", "index", "before", "after"]
    }
    fn leaf(&self, path: &[u32]) -> Option<Leaf> {
        // FOUND' = if t < start { found } else if t − start < width { Some(..) } else { found }
        match path {
            [1] => Some(Leaf::Before),
            [0, 0] => Some(Leaf::After),
            [0, 1] => Some(Leaf::Hit),
            _ => None,
        }
    }
    fn entry(&self) -> (String, String) {
        (
            "(L : U64) -> (t : U64) -> ".into(),
            format!(
                "Eq(Option(crate::Shape), crate::shape L t, match #gt_u64(L, 4611686018427387904u64) : Bool as _ return Option(crate::Shape) with | false => {} | true => None[crate::Shape] end)",
                self.res()
            ),
        )
    }
}

struct BlockSpec;

impl Spec for BlockSpec {
    fn label(&self) -> &'static str {
        "find_block_go (corpus P4)"
    }
    fn func(&self) -> &'static str {
        "crate::find_block_go"
    }
    fn ret(&self) -> &'static str {
        "Option(crate::Block)"
    }
    fn k_max(&self) -> u32 {
        64
    }
    fn data(&self) -> &'static [&'static str] {
        &["t", "rem", "w", "s", "b", "found"]
    }
    fn ghost(&self) -> &'static str {
        "L"
    }
    fn binders(&self, f: u32) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = ["t", "rem", "w", "s"].iter().map(|n| (n.to_string(), "U64".to_string())).collect();
        v.push(("b".into(), "U32".into()));
        v.push(("found".into(), "Option(crate::Block)".into()));
        v.push(("L".into(), "U64".into()));
        v.push((".r0".into(), format!("Eq(Bool, #le_u32({f}u32, 64u32), true)")));
        v.push((".r1".into(), "Eq(Bool, #le_int(#iadd(#cast_u64_int(s), #cast_u64_int(rem)), 18446744073709551615int), true)".into()));
        v.push((".r2".into(), format!("Eq(Bool, #le_int(#iadd(#cast_u32_int(b), #cast_u32_int({f}u32)), 64int), true)")));
        if f >= 1 {
            v.push((".iw".into(), format!("Eq(U64, w, {}u64)", 1u128 << (f - 1))));
        }
        v.push((".irem".into(), format!("Eq(U64, rem, #and_u64(L, {}u64))", (1u128 << f) - 1)));
        v.push((".is".into(), "Eq(Int, #iadd(#cast_u64_int(s), #cast_u64_int(rem)), #cast_u64_int(L))".into()));
        if f < 64 {
            v.push((".ib".into(), format!("Eq(U32, b, #count_ones_u64(#wshr_u64(L, {f}u32)))")));
        } else {
            v.push((".ib".into(), "Eq(U32, b, 0u32)".into()));
        }
        v.push((
            ".ifound".into(),
            format!("Eq(Option(crate::Block), found, {})", opt("crate::Block", "#lt_u64(t, s)", "d1::block_cf L t")),
        ));
        v
    }
    fn lhs(&self, f: u32) -> String {
        format!("crate::find_block_go {f}u32 t rem w s b found .r0 .r1 .r2")
    }
    fn res(&self) -> String {
        opt("crate::Block", "#lt_u64(t, L)", "d1::block_cf L t")
    }
    fn hints(&self, f: u32, class: &str) -> Vec<String> {
        let k = f.saturating_sub(1);
        let split = |x: &str| format!("bits::mask_split_u64_{k} {x}");
        let step = format!("bits::popcnt_step_u64_{k} L");
        let hi = format!("#wshr_u64(#wshr_u64(L, {k}u32), 1u32)");
        let lf = if f < 64 { format!("#wshr_u64(L, {f}u32)") } else { "0u64".to_string() };
        match class {
            "idle.irem" | "peak.irem" | "hit.bitL" => vec![split("L")],
            "idle.ib" | "peak.ib" => vec![step, split("L")],
            "hit.bitT" => vec![split("t")],
            "hit.start" => vec![format!("bvrefl(U64, {hi}, {lf})")],
            "hit.rank" => vec![format!("eq::cong U64 U32 (fun (y : U64) => #count_ones_u64(y)) ({hi}) ({lf}) (bvrefl(U64, {hi}, {lf}))")],
            _ => vec![],
        }
    }
    fn field_names(&self) -> &'static [&'static str] {
        &["level", "start", "rank"]
    }
    fn leaf(&self, path: &[u32]) -> Option<Leaf> {
        // FOUND' = if idx >= start && idx − start < width { Some(..) } else { found }:
        // one split on the conjunction; its false arm is either miss
        match path {
            [0] => None,
            [1] => Some(Leaf::Hit),
            _ => None,
        }
    }
    fn entry(&self) -> (String, String) {
        ("(L : U64) -> (t : U64) -> ".into(), format!("Eq(Option(crate::Block), crate::find_block L t, {})", self.res()))
    }
    fn families(&self, f: u32) -> Vec<(Family, u32)> {
        let k = f.saturating_sub(1);
        let mut v =
            vec![(Family::MaskSplit, k), (Family::PopcntStep, k), (Family::LzRange, k), (Family::ClzXorPrefix, k), (Family::WshlExact, 1)];
        if k >= 1 {
            v.push((Family::WshlExact, k));
        }
        if k == 63 {
            v.push((Family::PopcntShrZero, 63));
        }
        v
    }
}

// ---------------------------------------------------------------------------
// The builder.
// ---------------------------------------------------------------------------

fn names_of(ctx: &Ctx) -> Vec<String> {
    ctx.entries.iter().map(|e| e.name.to_string()).collect()
}

fn parse_in(env: &Env, ctx: &Ctx, src: &str) -> Tm {
    let names = names_of(ctx);
    let ns: Vec<&str> = names.iter().map(|n| n.as_str()).collect();
    env.parse_term(&ns, src).unwrap_or_else(|e| panic!("parse `{src}`: {e}"))
}

fn eval_in(env: &Env, ctx: &Ctx, t: &Tm) -> V {
    env.eval(&env.ctx_venv(ctx), ctx.depth(), t, &mut Budget { steps: 100_000_000 }).expect("eval")
}

/// `refl` when the sides of an equation convert, or an assumption of the
/// context (promoted, so the proof is valid in any position).
fn trivial(env: &Env, ctx: &Ctx, target: &V, b: &mut Budget) -> Option<Tm> {
    let d = ctx.depth();
    let (ty, l, r) = as_eq(target)?;
    let ty_tm = env.quote_typed(ctx, ty, None, false);
    if env.conv(d, l, r, b).ok()? {
        return Some(mk::refl(ty_tm, env.quote_typed(ctx, l, Some(ty), false)));
    }
    for (i, e) in ctx.entries.iter().enumerate().rev() {
        if matches!(&*e.ty, Value::Eq { .. }) && env.conv(d, &e.ty, target, b).ok()? {
            let promote = env.lookup_global("eq::promote")?;
            let v = mk::var(d.0 - 1 - i as u32);
            let v = if e.rel == Rel::Irr {
                apps(
                    mk::global(promote),
                    [
                        (Rel::Rel, ty_tm.clone()),
                        (Rel::Rel, env.quote_typed(ctx, l, Some(ty), false)),
                        (Rel::Rel, env.quote_typed(ctx, r, Some(ty), false)),
                        (Rel::Irr, v),
                    ],
                )
            } else {
                v
            };
            return Some(v);
        }
    }
    None
}

/// The scrutinee of the first stuck match of a value.
fn first_scrut(v: &V) -> Option<V> {
    let Value::Neu(n) = &**v else { return None };
    let i = n.spine.iter().position(|e| matches!(e, sandblaster_kernel::value::Elim::Match { .. }))?;
    Some(prefix(n, i))
}

/// The scrutinee of the last (outermost) stuck match of a value.
fn last_scrut(v: &V) -> Option<V> {
    let Value::Neu(n) = &**v else { return None };
    let i = n.spine.iter().rposition(|e| matches!(e, sandblaster_kernel::value::Elim::Match { .. }))?;
    Some(prefix(n, i))
}

/// The global application `func args` a value is, if any.
fn call_args(v: &V, func: GlobalId) -> Option<Vec<Arg>> {
    match &**v {
        Value::Neu(Neutral { head: Head::Global { def, args }, spine }) if *def == func && spine.is_empty() => Some(args.clone()),
        _ => None,
    }
}

struct Builder<'s> {
    spec: &'s dyn Spec,
    auto: Auto,
    stats: Stats,
    f: u32,
    trace: bool,
    /// Diagnostics (`D1_NO_CUTS`): continue after a failed obligation with a
    /// placeholder proof, so every class is tried (the lemma stays open).
    keep_going: bool,
}

impl<'s> Builder<'s> {
    /// Prove `target` (a value in `ctx`) with one `auto` call, recording the
    /// steps under `class`.
    fn obligation(&mut self, env: &Env, ctx: &Ctx, target: &V, class: &str, extra: &[Tm]) -> Option<Tm> {
        // Conversion or an assumption first (no search).
        let mut cb = Budget { steps: OBLIGATION_BUDGET };
        let t0 = Instant::now();
        if let Some(p) = trivial(env, ctx, target, &mut cb) {
            self.stats.record(class, OBLIGATION_BUDGET - cb.steps, t0.elapsed(), None);
            return Some(p);
        }
        let mut hints: Vec<Hint> = self.spec.hints(self.f, class).iter().map(|h| Hint::Lemma(parse_in(env, ctx, h))).collect();
        hints.extend(extra.iter().cloned().map(Hint::Lemma));
        let goal = Goal {
            id: ObligationId(0),
            kind: ObligationKind::LawGoal,
            span: Span::DUMMY,
            ctx: ctx.clone(),
            facts: vec![],
            target: target.clone(),
            hints,
        };
        let mut b = Budget { steps: OBLIGATION_BUDGET };
        let t0 = Instant::now();
        let r = self.auto.prove(env, &goal, &mut b);
        let steps = OBLIGATION_BUDGET - b.steps;
        let failure = r.as_ref().err().map(|f| {
            let names: Vec<Name> = ctx.entries.iter().map(|e| e.name.clone()).collect();
            format!(
                "  lemma_{} goal: {}\n  tried: {:?}\n  stuck: {:?}",
                self.f,
                elab::show::value(env, &names, target, 600),
                f.tried.iter().take(12).collect::<Vec<_>>(),
                f.stuck
            )
        });
        if self.trace {
            eprintln!("[d1] lemma_{} {class}: {} ({steps} steps)", self.f, if r.is_ok() { "ok" } else { "FAILED" });
        }
        self.stats.record(class, steps, t0.elapsed(), failure);
        if let Ok(p) = &r {
            self.stats.proof_nodes += sandblaster_front::elab::tm::size_capped(p, 100_000_000);
        }
        if r.is_err() && self.keep_going {
            return Some(Rc::new(Term::Erased));
        }
        r.ok()
    }

    /// Apply `lemma_prev` (a global) to the call `call` (a value in the
    /// arm), proving its irrelevant arguments as obligations `<arm>.<binder>`.
    fn apply_lemma(&mut self, e: &mut Engine<'_>, arm: &mut St, lemma_prev: GlobalId, call: &[Arg], arm_name: &str) -> R<Option<Tm>> {
        let env = e.env;
        let Some(mut cur) = env.global_type_value(lemma_prev) else { return Ok(None) };
        let mut rel_vals: Vec<V> = call.iter().skip(1).filter_map(|a| if let Arg::Rel(v) = a { Some(v.clone()) } else { None }).collect();
        rel_vals.push(eval_in(env, &arm.ctx, &parse_in(env, &arm.ctx, self.spec.ghost())));
        let mut ri = 0;
        let mut args: Vec<(Rel, Tm)> = Vec::new();
        while let Value::Pi { name, rel, dom, cod } = &*cur.clone() {
            let entry = match rel {
                Rel::Rel => {
                    let v = rel_vals[ri].clone();
                    ri += 1;
                    args.push((Rel::Rel, arm.quote(env, &v)));
                    EnvEntry::Rel(v)
                }
                Rel::Irr => {
                    let class = format!("{arm_name}.{name}");
                    let p = if arm_name == "peak" && &**name == "ifound" {
                        self.found(e, arm, dom, &[])?
                    } else {
                        self.obligation(env, &arm.ctx, dom, &class, &[])
                    };
                    let Some(p) = p else { return Ok(None) };
                    args.push((Rel::Irr, p.clone()));
                    irr_entry(&arm.venv, &p)
                }
            };
            let Some(next) = e.inst(cod, vec![entry], arm.depth())? else { return Ok(None) };
            cur = next;
        }
        Ok(Some(apps(mk::global(lemma_prev), args)))
    }

    /// The peak arm's `found` obligation: split on the stuck tests of the
    /// new `found` value, then the leaves.
    fn found(&mut self, e: &mut Engine<'_>, arm: &mut St, target: &V, path: &[u32]) -> R<Option<Tm>> {
        let env = e.env;
        let Some((_, lhs, _)) = as_eq(target) else { return Ok(None) };
        // The leaves: the new `found` is `Some(..)` (the target is in this
        // peak), or no longer a test (the old `found`: a miss).
        if let Value::Ctor { ctor: 1, .. } = &**lhs {
            return self.hit(e, arm, target);
        }
        if self.trace {
            let names: Vec<Name> = arm.ctx.entries.iter().map(|e| e.name.clone()).collect();
            eprintln!("[d1] found path {path:?}: {}", elab::show::value(env, &names, lhs, 400));
        }
        // Split on the outermost test (for `a && b` that is the conjunction
        // itself: auto's saturation reads `a`, `b` off `(a && b) = true`;
        // splitting on `b` after `a` would abstract `b` inside the proof
        // the first split transported, and the motive would not type-check).
        let Some(c) = last_scrut(lhs) else {
            let class = match self.spec.leaf(path) {
                Some(Leaf::Before) => "found.before",
                Some(Leaf::After) => "found.after",
                _ => "found.miss",
            };
            return Ok(self.obligation(env, &arm.ctx, target, class, &[]));
        };
        let bi = env.bool_ind();
        let path = path.to_vec();
        let depth = arm.depth_left;
        let mut arm_fn = |e2: &mut Engine<'_>, arm2: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
            let mut p2 = path.clone();
            p2.push(k);
            self.found(e2, arm2, &tk, &p2)
        };
        e.case_split_with(arm, &c, bi, &[], target, true, depth, &mut arm_fn)
    }

    /// The hit leaf: `t >> f = L >> f`, the two bits, `lz(L ^ t) = 64 − f`,
    /// the rewrite, the fields.
    fn hit(&mut self, e: &mut Engine<'_>, arm: &mut St, target: &V) -> R<Option<Tm>> {
        let env = e.env;
        let (f, n) = (self.f, 64u32);
        let k = f - 1;
        let ev = |s: &str, arm: &St| eval_in(env, &arm.ctx, &parse_in(env, &arm.ctx, s));
        let mut named: Vec<(&str, Tm)> = Vec::new();
        let h1 = if f < n {
            let g = ev(&format!("Eq(U64, #wshr_u64(t, {f}u32), #wshr_u64(L, {f}u32))"), arm);
            let Some(p) = self.obligation(env, &arm.ctx, &g, "hit.quot", &[]) else { return Ok(None) };
            named.push(("H1", p.clone()));
            Some(p)
        } else {
            None
        };
        let pick = |named: &[(&str, Tm)], spec: &dyn Spec, class: &str| -> Vec<Tm> {
            named.iter().filter(|(n, _)| spec.hit_facts(class).contains(n)).map(|(_, t)| t.clone()).collect()
        };
        let g2 = ev(&format!("Eq(U64, #and_u64(#wshr_u64(L, {k}u32), 1u64), 1u64)"), arm);
        let Some(h2) = self.obligation(env, &arm.ctx, &g2, "hit.bitL", &pick(&named, self.spec, "hit.bitL")) else { return Ok(None) };
        named.push(("H2", h2.clone()));
        let g3 = ev(&format!("Eq(U64, #and_u64(#wshr_u64(t, {k}u32), 1u64), 0u64)"), arm);
        let Some(h3) = self.obligation(env, &arm.ctx, &g3, "hit.bitT", &pick(&named, self.spec, "hit.bitT")) else { return Ok(None) };
        named.push(("H3", h3.clone()));
        // lz(L ^ t) = 63 − k by clz_xor_prefix_k (library)
        let clz = env.lookup_global(&bitlib::lemma_name(Family::ClzXorPrefix, Width::U64, k)).expect("clz lemma loaded");
        let (lv, tv) = (parse_in(env, &arm.ctx, "L"), parse_in(env, &arm.ctx, "t"));
        let mut cargs = vec![(Rel::Rel, lv.clone()), (Rel::Rel, tv.clone())];
        if let Some(h1) = &h1 {
            // h1 : t >> f = L >> f; the lemma wants L >> f = t >> f
            let (tf, lf) =
                (parse_in(env, &arm.ctx, &format!("#wshr_u64(t, {f}u32)")), parse_in(env, &arm.ctx, &format!("#wshr_u64(L, {f}u32)")));
            let sym = env.lookup_global("eq::sym").unwrap();
            cargs.push((
                Rel::Irr,
                apps(mk::global(sym), [(Rel::Rel, mk::int_ty(Width::U64)), (Rel::Rel, tf), (Rel::Rel, lf), (Rel::Rel, h1.clone())]),
            ));
        }
        cargs.push((Rel::Irr, h2));
        cargs.push((Rel::Irr, h3));
        let h4 = apps(mk::global(clz), cargs);
        let t0 = Instant::now();
        let mut kb = Budget { steps: 10_000_000 };
        let h4_ok = env.infer(&arm.ctx, &h4, &mut kb);
        self.stats.record("hit.clz (library)", 10_000_000 - kb.steps, t0.elapsed(), h4_ok.as_ref().err().map(|e| format!("{e}")));
        if h4_ok.is_err() {
            return Ok(None);
        }
        // Rewrite lz(L ^ t) := 63 − k in the goal: the closed form's shifts
        // become literal.
        let lz_tm = parse_in(env, &arm.ctx, "#leading_zeros_u64(#xor_u64(L, t))");
        let lit = mk::lit(Width::U32, 63 - k);
        let sym = env.lookup_global("eq::sym").unwrap();
        let eq_lz =
            apps(mk::global(sym), [(Rel::Rel, mk::int_ty(Width::U32)), (Rel::Rel, lz_tm.clone()), (Rel::Rel, lit.clone()), (Rel::Rel, h4)]);
        let Some((t1, k1)) = rewrite(env, arm, target, &lz_tm, &lit, mk::int_ty(Width::U32), eq_lz) else { return Ok(None) };
        // Decide the closed form's guard `t < start + width` (true in the hit).
        let Some((_, _, rhs)) = as_eq(&t1) else { return Ok(None) };
        let Some(c) = first_scrut(rhs) else { return Ok(None) };
        let bt = mk::bool_ty(env.bool_ind());
        let tt = mk::bool_lit(env.bool_ind(), true);
        let c_tm = arm.quote(env, &c);
        let gc = eval_in(env, &arm.ctx, &mk::eq(bt.clone(), c_tm.clone(), tt.clone()));
        let Some(pc) = self.obligation(env, &arm.ctx, &gc, "hit.guard", &pick(&named, self.spec, "hit.guard")) else { return Ok(None) };
        let eq_c = apps(mk::global(sym), [(Rel::Rel, bt.clone()), (Rel::Rel, c_tm.clone()), (Rel::Rel, tt.clone()), (Rel::Rel, pc)]);
        let Some((t2, k2)) = rewrite(env, arm, &t1, &c_tm, &tt, bt, eq_c) else { return Ok(None) };
        // `Some(Shape(x̄)) = Some(Shape(ȳ))`: one obligation per field.
        let Some(p) = self.fields(env, arm, &t2, &named) else { return Ok(None) };
        Ok(Some(k1(k2(p))))
    }

    /// Constructor congruence for `Eq(Option(S), Some(C(x̄)), Some(C(ȳ)))`:
    /// each differing field `xᵢ = yᵢ` is an obligation `hit.<field>`, and a
    /// chain of transports (one per field, from `refl`) proves the goal.
    fn fields(&mut self, env: &Env, arm: &St, target: &V, named: &[(&str, Tm)]) -> Option<Tm> {
        let (oty, l, r) = as_eq(target)?;
        let (Value::Ctor { args: la, params: op, .. }, Value::Ctor { args: ra, .. }) = (&**l, &**r) else { return None };
        let (Arg::Rel(lx), Arg::Rel(rx)) = (&la[0], &ra[0]) else { return None };
        let (Value::Ctor { ind, ctor, args: xs, .. }, Value::Ctor { args: ys, .. }) = (&**lx, &**rx) else { return None };
        let decl = env.inductive_decl(*ind)?;
        let oty_tm = arm.quote(env, oty);
        let sty = &op[0];
        let sty_tm = arm.quote(env, sty);
        let field_vals =
            |a: &[Arg]| -> Vec<V> { a.iter().filter_map(|x| if let Arg::Rel(v) = x { Some(v.clone()) } else { None }).collect() };
        let (xv, yv) = (field_vals(xs), field_vals(ys));
        let mut xt = Vec::new();
        let mut yt = Vec::new();
        let mut tys = Vec::new();
        for (i, (name, _, fty)) in decl.ctors[*ctor as usize].fields.iter().enumerate() {
            let ftv = eval_in(env, &arm.ctx, fty);
            xt.push(arm.quote_at(env, &xv[i], &ftv));
            yt.push(arm.quote_at(env, &yv[i], &ftv));
            tys.push((name.clone(), ftv));
        }
        let some = |fs: Vec<Tm>| {
            mk::ctor(
                env.lookup_ind("Option").unwrap_or_else(|| panic!("Option")),
                1,
                vec![sty_tm.clone()],
                vec![mk::ctor(*ind, *ctor, vec![], fs)],
            )
        };
        let lhs = some(xt.clone());
        let mut proof = mk::refl(oty_tm.clone(), lhs.clone());
        for i in 0..xt.len() {
            let (_, ftv) = &tys[i];
            let name = self.spec.field_names().get(i).copied().unwrap_or("field");
            let class = format!("hit.{name}");
            let facts: Vec<Tm> = named.iter().filter(|(n, _)| self.spec.hit_facts(&class).contains(n)).map(|(_, t)| t.clone()).collect();
            let facts = &facts[..];
            let pi = match (unary_bitcount(&xv[i]), unary_bitcount(&yv[i])) {
                // `cnt(a) = cnt(b)` from `a = b` (auto has no congruence under
                // primitives): the obligation is on the arguments.
                (Some((op, a)), Some((op2, b2))) if op == op2 => {
                    let w = match op {
                        PrimOp::CountOnes(w) | PrimOp::LeadingZeros(w) | PrimOp::TrailingZeros(w) => w,
                        _ => unreachable!(),
                    };
                    let wt = Rc::new(Value::IntTy(w));
                    let goal = Rc::new(Value::Eq { ty: wt.clone(), lhs: a.clone(), rhs: b2.clone() });
                    let p = self.obligation(env, &arm.ctx, &goal, &format!("hit.{name}"), facts)?;
                    let cong = env.lookup_global("eq::cong").unwrap();
                    let f = mk::lam("y", Rel::Rel, mk::int_ty(w), mk::prim(op, vec![mk::var(0)], vec![]));
                    let (at, bt) = (arm.quote_at(env, &a, &wt), arm.quote_at(env, &b2, &wt));
                    apps(
                        mk::global(cong),
                        [
                            (Rel::Rel, mk::int_ty(w)),
                            (Rel::Rel, arm.quote(env, ftv)),
                            (Rel::Rel, f),
                            (Rel::Rel, at),
                            (Rel::Rel, bt),
                            (Rel::Rel, p),
                        ],
                    )
                }
                _ => {
                    let goal = Rc::new(Value::Eq { ty: ftv.clone(), lhs: xv[i].clone(), rhs: yv[i].clone() });
                    self.obligation(env, &arm.ctx, &goal, &format!("hit.{name}"), facts)?
                }
            };
            let sh = |t: &Tm| sandblaster_front::auto::util::shift(t, 1);
            let mut mid: Vec<Tm> = (0..xt.len()).map(|j| if j < i { sh(&yt[j]) } else { sh(&xt[j]) }).collect();
            mid[i] = mk::var(0);
            let motive = mk::eq(sh(&oty_tm), sh(&lhs), some_sh(env, *ind, *ctor, &sh(&sty_tm), mid));
            let fty_tm = arm.quote(env, ftv);
            proof = Rc::new(Term::Transport { ty: fty_tm, lhs: xt[i].clone(), rhs: yt[i].clone(), eq: pi, motive, val: proof });
        }
        Some(proof)
    }
}

/// `op(a)` for a bit-count primitive `op`.
fn unary_bitcount(v: &V) -> Option<(PrimOp, V)> {
    match &**v {
        Value::Neu(Neutral { head: Head::Prim { op, args, .. }, spine })
            if spine.is_empty() && matches!(op, PrimOp::CountOnes(_) | PrimOp::LeadingZeros(_) | PrimOp::TrailingZeros(_)) =>
        {
            Some((*op, args[0].clone()))
        }
        _ => None,
    }
}

fn some_sh(env: &Env, ind: sandblaster_kernel::term::IndId, ctor: u32, sty: &Tm, fs: Vec<Tm>) -> Tm {
    mk::ctor(env.lookup_ind("Option").unwrap(), 1, vec![sty.clone()], vec![mk::ctor(ind, ctor, vec![], fs)])
}

/// Rewrite `target` (a value in `arm`) with `eq : Eq(ty, lit, t)` —
/// occurrences of `t` become `lit`: the new target and the continuation
/// turning its proof into one of `target` (a transport).
fn rewrite(env: &Env, arm: &St, target: &V, t: &Tm, lit: &Tm, ty: Tm, eq: Tm) -> Option<(V, Box<dyn FnOnce(Tm) -> Tm>)> {
    let tv = eval_in(env, &arm.ctx, t);
    let litv = eval_in(env, &arm.ctx, lit);
    let motive = env.abstract_occurrences(&arm.ctx, target, &tv, &mut Budget { steps: 100_000_000 }).ok()?;
    let t2 = env
        .eval(
            &venv_push(&arm.venv, EnvEntry::Rel(litv)),
            sandblaster_kernel::term::Lvl(arm.ctx.depth().0 + 1),
            &motive,
            &mut Budget { steps: 100_000_000 },
        )
        .ok()?;
    let (t, lit) = (t.clone(), lit.clone());
    Some((t2, Box::new(move |p: Tm| Rc::new(Term::Transport { ty, lhs: lit, rhs: t, eq, motive, val: p }))))
}

/// `lemma_f`'s statement (a closed Π term).
fn lemma_type(env: &Env, spec: &dyn Spec, f: u32) -> Tm {
    let bs = spec.binders(f);
    let pis: String = bs.iter().map(|(n, t)| format!("({n} : {t}) -> ")).collect();
    let src = format!("{pis}Eq({}, {}, {})", spec.ret(), spec.lhs(f), spec.res());
    env.parse_term(&[], &src).unwrap_or_else(|e| panic!("lemma_{f} statement: {e}"))
}

/// Open a Π type into a state (binders as λ wrappers); returns the body.
fn open(e: &mut Engine<'_>, st: &mut St, ty: &Tm) -> V {
    let env = e.env;
    let mut cur = eval_in(env, &st.ctx, ty);
    while let Value::Pi { name, rel, dom, cod } = &*cur.clone() {
        let is_prop = e.is_prop(dom, st.depth());
        let entry = st.push_lam(env, name.clone(), *rel, dom.clone(), is_prop);
        cur = e.inst(cod, vec![entry], st.depth()).unwrap().unwrap();
    }
    cur
}

/// Prove `Eq(R, call, RES)` in `st` by `Delta` of the call's head, then
/// `arms` (a split on the body's first stuck test, or one arm).
fn delta_then<F>(e: &mut Engine<'_>, st: &mut St, goal: &V, func: GlobalId, split: bool, arm_fn: &mut F) -> R<Option<Tm>>
where
    F: for<'b> FnMut(&mut Engine<'b>, &mut St, V, u32) -> R<Option<Tm>>,
{
    let env = e.env;
    let Some((ty, lhs, rhs)) = as_eq(goal) else { return Ok(None) };
    let (ty, lhs, rhs) = (ty.clone(), lhs.clone(), rhs.clone());
    if call_args(&lhs, func).is_none() {
        // a non-recursive function: evaluation already unfolded it
        if !split {
            return arm_fn(e, st, goal.clone(), 0);
        }
        let Some(c) = first_scrut(&lhs) else { return Ok(None) };
        let depth = st.depth_left;
        return e.case_split_with(st, &c, env.bool_ind(), &[], goal, true, depth, arm_fn);
    }
    let lhs_tm = st.quote(env, &lhs);
    let (ty_tm, rhs_tm) = (st.quote(env, &ty), st.quote(env, &rhs));
    // the application's arguments
    let mut args = Vec::new();
    let mut h = &lhs_tm;
    while let Term::App { rel, fun, arg } = &**h {
        args.push((*rel, arg.clone()));
        h = fun;
    }
    args.reverse();
    let body = apps(env.global_body(func).unwrap(), args.clone());
    let delta = Rc::new(Term::Delta { def: func, args: args.into_iter().map(|(_, a)| a).collect() });
    let g1 = eval_in(env, &st.ctx, &mk::eq(ty_tm.clone(), body.clone(), rhs_tm.clone()));
    let split_pf = if split {
        let Some((_, l1, _)) = as_eq(&g1) else { return Ok(None) };
        let Some(c) = first_scrut(l1) else { return Ok(None) };
        let depth = st.depth_left;
        e.case_split_with(st, &c, env.bool_ind(), &[], &g1, true, depth, arm_fn)?
    } else {
        arm_fn(e, st, g1, 0)?
    };
    let Some(split_pf) = split_pf else { return Ok(None) };
    let trans = env.lookup_global("eq::trans").unwrap();
    Ok(Some(apps(
        mk::global(trans),
        [(Rel::Rel, ty_tm), (Rel::Rel, lhs_tm), (Rel::Rel, body), (Rel::Rel, rhs_tm), (Rel::Rel, delta), (Rel::Rel, split_pf)],
    )))
}

/// Structural hash-consing of a proof term: identical subterms become one
/// shared node (the committed term is the same term; the kernel checks and
/// stores it as a DAG). The proofs repeat subterms heavily — the quoted
/// loop body in the split's motive, the requires proofs at every call.
fn hashcons(t: &Tm) -> Tm {
    use std::collections::HashMap;
    struct H {
        canon: HashMap<String, Tm>,
        seen: HashMap<usize, Tm>,
        keep: Vec<Tm>,
    }
    fn p(t: &Tm) -> usize {
        Rc::as_ptr(t) as *const () as usize
    }
    impl H {
        fn go(&mut self, t: &Tm) -> Tm {
            if let Some(c) = self.seen.get(&p(t)) {
                return c.clone();
            }
            let mut kids: Vec<Tm> = Vec::new();
            let mut sub = |this: &mut H, x: &Tm| {
                let c = this.go(x);
                kids.push(c.clone());
                c
            };
            let rebuilt: Term = match &**t {
                Term::Var(i) => Term::Var(*i),
                Term::Global(g) => Term::Global(*g),
                Term::Sort(s) => Term::Sort(*s),
                Term::Pi { name, rel, dom, cod } => Term::Pi { name: name.clone(), rel: *rel, dom: sub(self, dom), cod: sub(self, cod) },
                Term::Lam { name, rel, dom, body } => {
                    Term::Lam { name: name.clone(), rel: *rel, dom: sub(self, dom), body: sub(self, body) }
                }
                Term::App { rel, fun, arg } => Term::App { rel: *rel, fun: sub(self, fun), arg: sub(self, arg) },
                Term::Let { name, rel, ty, val, body } => {
                    Term::Let { name: name.clone(), rel: *rel, ty: sub(self, ty), val: sub(self, val), body: sub(self, body) }
                }
                Term::Sigma { name, snd_rel, fst, snd } => {
                    Term::Sigma { name: name.clone(), snd_rel: *snd_rel, fst: sub(self, fst), snd: sub(self, snd) }
                }
                Term::Pair { ty, fst, snd } => Term::Pair { ty: sub(self, ty), fst: sub(self, fst), snd: sub(self, snd) },
                Term::Fst(x) => Term::Fst(sub(self, x)),
                Term::Snd(x) => Term::Snd(sub(self, x)),
                Term::Eq { ty, lhs, rhs } => Term::Eq { ty: sub(self, ty), lhs: sub(self, lhs), rhs: sub(self, rhs) },
                Term::Refl { ty, val } => Term::Refl { ty: sub(self, ty), val: sub(self, val) },
                Term::Transport { ty, lhs, rhs, eq, motive, val } => Term::Transport {
                    ty: sub(self, ty),
                    lhs: sub(self, lhs),
                    rhs: sub(self, rhs),
                    eq: sub(self, eq),
                    motive: sub(self, motive),
                    val: sub(self, val),
                },
                Term::Ind { ind, params } => Term::Ind { ind: *ind, params: params.iter().map(|x| sub(self, x)).collect() },
                Term::Ctor { ind, ctor, params, args } => Term::Ctor {
                    ind: *ind,
                    ctor: *ctor,
                    params: params.iter().map(|x| sub(self, x)).collect(),
                    args: args.iter().map(|x| sub(self, x)).collect(),
                },
                Term::Match { ind, params, scrut, motive, arms } => Term::Match {
                    ind: *ind,
                    params: params.iter().map(|x| sub(self, x)).collect(),
                    scrut: sub(self, scrut),
                    motive: sub(self, motive),
                    arms: arms.iter().map(|a| sandblaster_kernel::term::Arm { names: a.names.clone(), body: sub(self, &a.body) }).collect(),
                },
                Term::IntTy(w) => Term::IntTy(*w),
                Term::Lit { w, n } => Term::Lit { w: *w, n: n.clone() },
                Term::Prim { op, args, proofs } => Term::Prim {
                    op: *op,
                    args: args.iter().map(|x| sub(self, x)).collect(),
                    proofs: proofs.iter().map(|x| sub(self, x)).collect(),
                },
                Term::Rec { args, proof } => {
                    Term::Rec { args: args.iter().map(|x| sub(self, x)).collect(), proof: proof.as_ref().map(|x| sub(self, x)) }
                }
                Term::Delta { def, args } => Term::Delta { def: *def, args: args.iter().map(|x| sub(self, x)).collect() },
                Term::Unfold { def, args, to_body, val } => {
                    Term::Unfold { def: *def, args: args.iter().map(|x| sub(self, x)).collect(), to_body: *to_body, val: sub(self, val) }
                }
                Term::Linarith { hyps, goal, cert } => Term::Linarith {
                    hyps: hyps.iter().map(|(a, b)| (sub(self, a), sub(self, b))).collect(),
                    goal: sub(self, goal),
                    cert: cert.clone(),
                },
                Term::BvRefl { ty, lhs, rhs } => Term::BvRefl { ty: sub(self, ty), lhs: sub(self, lhs), rhs: sub(self, rhs) },
                Term::Absurd { ty, proof } => Term::Absurd { ty: sub(self, ty), proof: sub(self, proof) },
                Term::Axiom { ax, args } => Term::Axiom { ax: *ax, args: args.iter().map(|x| sub(self, x)).collect() },
                Term::Erased => Term::Erased,
            };
            // key: the node's own payload and its (canonical) children
            let head: String = match &rebuilt {
                Term::Pi { name, rel, .. } => format!("Pi{name}{rel:?}"),
                Term::Lam { name, rel, .. } => format!("Lam{name}{rel:?}"),
                Term::App { rel, .. } => format!("App{rel:?}"),
                Term::Let { name, rel, .. } => format!("Let{name}{rel:?}"),
                Term::Sigma { name, snd_rel, .. } => format!("Sig{name}{snd_rel:?}"),
                Term::Ind { ind, .. } => format!("Ind{}", ind.0),
                Term::Ctor { ind, ctor, params, .. } => format!("Ctor{}.{ctor}.{}", ind.0, params.len()),
                Term::Match { ind, params, arms, .. } => {
                    format!("Match{}.{}.{:?}", ind.0, params.len(), arms.iter().map(|a| a.names.clone()).collect::<Vec<_>>())
                }
                Term::Prim { op, args, .. } => format!("Prim{op:?}.{}", args.len()),
                Term::Rec { proof, .. } => format!("Rec{}", proof.is_some()),
                Term::Delta { def, .. } => format!("Delta{}", def.0),
                Term::Unfold { def, to_body, .. } => format!("Unfold{}{to_body}", def.0),
                Term::Linarith { cert, hyps, .. } => {
                    format!("Lin{}.{:?}", hyps.len(), cert.iter().map(|r| format!("{}/{}", r.num, r.den)).collect::<Vec<_>>())
                }
                Term::Axiom { ax, .. } => format!("Ax{}", ax.0),
                other => {
                    format!("{:?}", std::mem::discriminant(other))
                        + &match other {
                            Term::Var(i) => format!("v{}", i.0),
                            Term::Global(g) => format!("g{}", g.0),
                            Term::Sort(s) => format!("{s:?}"),
                            Term::IntTy(w) => format!("{w:?}"),
                            Term::Lit { w, n } => format!("{w:?}{n}"),
                            _ => String::new(),
                        }
                }
            };
            let key = format!("{head}|{}", kids.iter().map(|k| p(k).to_string()).collect::<Vec<_>>().join(","));
            let c = match self.canon.get(&key) {
                Some(c) => c.clone(),
                None => {
                    let c: Tm = Rc::new(rebuilt);
                    self.canon.insert(key, c.clone());
                    c
                }
            };
            self.seen.insert(p(t), c.clone());
            self.keep.push(t.clone());
            c
        }
    }
    let mut h = H { canon: HashMap::new(), seen: HashMap::new(), keep: Vec::new() };
    h.go(t)
}

fn add_lemma(env: &mut Env, name: &str, ty: Tm, body: Tm) -> Result<(GlobalId, u64), String> {
    let body = hashcons(&body);
    let arity = {
        let mut n = 0;
        let mut t = &ty;
        while let Term::Pi { cod, .. } = &**t {
            n += 1;
            t = cod;
        }
        n
    };
    let mut b = Budget { steps: 2_000_000_000 };
    let g = env
        .add_def(DefDecl { name: Rc::from(name), kind: DefKind::Lemma, ty, body, recursion: Recursion::None, arity, opaque: true }, &mut b)
        .map_err(|e| format!("{name}: {e}"))?;
    Ok((g, 2_000_000_000 - b.steps))
}

/// Generate and prove `lemma_0 … lemma_K` and the call-site lemma of one
/// loop. Returns the statistics.
fn run_loop(env: &mut Env, spec: &dyn Spec) -> Stats {
    let trace = std::env::var_os("D1_TRACE").is_some();
    let only: Option<u32> = std::env::var("D1_MAX_F").ok().and_then(|s| s.parse().ok());
    let func = env.lookup_global(spec.func()).unwrap();
    // `D1_NO_CUTS=1`: without integer cuts (shows which classes need them)
    let auto = if std::env::var_os("D1_NO_CUTS").is_some() { Auto::with_config(AutoConfig { int_cuts: 0, ..AutoConfig::default() }) } else { Auto::new() };
    let keep_going = std::env::var_os("D1_NO_CUTS").is_some();
    let mut b = Builder { spec, auto, stats: Stats::default(), f: 0, trace, keep_going };
    let mut prev: Option<GlobalId> = None;
    let k_max = only.unwrap_or(spec.k_max()).min(spec.k_max());
    for f in 0..=k_max {
        // the library members this lemma uses
        for (fam, k) in spec.families(f) {
            if fam.valid(Width::U64, k) {
                bitlib::ensure(env, fam, Width::U64, k, &mut Budget { steps: 4_000_000_000 }).unwrap_or_else(|e| panic!("{e}"));
            }
        }
        b.f = f;
        b.stats.current = 0;
        b.stats.proof_nodes = 0;
        let t0 = Instant::now();
        let ty = lemma_type(env, spec, f);
        let cfg = AutoConfig::default();
        let mut db = LemmaDb::default();
        db.refresh(env);
        let mut sb = Budget { steps: 1_000_000_000 };
        let proof = {
            let mut e = Engine::new(env, &mut sb, &cfg, &db, vec![], 0);
            let mut st = St::new(env, &Ctx::default(), cfg.max_split_depth);
            let goal = open(&mut e, &mut st, &ty);
            let p = if f == 0 {
                b.obligation(env, &st.ctx, &goal, "exit", &[])
            } else {
                let prev_g = prev.expect("lemma_{f-1}");
                let mut arm_fn = |e2: &mut Engine<'_>, arm: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
                    let Some((_, lhs, _)) = as_eq(&tk) else { return Ok(None) };
                    let call = match call_args(lhs, func) {
                        Some(call) => call,
                        // `loop(0, s̄)` of the idle arm of lemma_1 computes to
                        // `found` (§5.6: the speculation is not stuck): apply
                        // lemma_0 at the unchanged state (its conclusion
                        // converts with the arm's goal).
                        None if k == 1 && f == 1 => {
                            let mut v = vec![Arg::Rel(Rc::new(Value::Lit { w: Width::U32, n: 0.into() }))];
                            for n in spec.data() {
                                v.push(Arg::Rel(eval_in(e2.env, &arm.ctx, &parse_in(e2.env, &arm.ctx, n))));
                            }
                            v
                        }
                        None => return Ok(None),
                    };
                    b.apply_lemma(e2, arm, prev_g, &call, if k == 1 { "idle" } else { "peak" })
                };
                delta_then(&mut e, &mut st, &goal, func, true, &mut arm_fn).ok().flatten()
            };
            p.map(|p| st.finish(p))
        };
        let skeleton = 1_000_000_000 - sb.steps;
        let name = format!("d1::{}::lemma_{f}", spec.func().trim_start_matches("crate::"));
        let (ok, check) = match proof {
            Some(p) => match add_lemma(env, &name, ty, p) {
                Ok((g, steps)) => {
                    prev = Some(g);
                    (true, steps)
                }
                Err(m) => {
                    b.stats.record("kernel check", 0, Duration::ZERO, Some(m));
                    (false, 0)
                }
            },
            None => (false, 0),
        };
        let obl = b.stats.current + skeleton;
        b.stats.lemmas.push((name.clone(), obl, check, t0.elapsed(), ok));
        let body_nodes = prev
            .filter(|_| ok)
            .and_then(|g| env.global_body(g))
            .map(|t| sandblaster_front::elab::tm::size_capped(&t, 100_000_000))
            .unwrap_or(0);
        eprintln!(
            "[d1] {name}: {} ({obl} obligation + skeleton steps, {check} check steps, {:.2?}; proof {body_nodes} nodes shared (obligation proofs {} before sharing); heap {} MiB)",
            if ok { "closed" } else { "OPEN" },
            t0.elapsed(),
            b.stats.proof_nodes,
            sandblaster_front::memguard::allocated() >> 20
        );
        if !ok && !keep_going {
            break;
        }
    }
    // The call-site lemma: the entry function equals its closed form.
    let all_closed = b.stats.lemmas.iter().all(|l| l.4) && b.stats.lemmas.len() as u32 == spec.k_max() + 1;
    if all_closed && only.is_none() {
        let (pis, stmt) = spec.entry();
        let ty = env.parse_term(&[], &format!("{pis}{stmt}")).unwrap_or_else(|e| panic!("entry statement: {e}"));
        let t0 = Instant::now();
        b.f = spec.k_max() + 1;
        b.stats.current = 0;
        let cfg = AutoConfig::default();
        let mut db = LemmaDb::default();
        db.refresh(env);
        let mut sb = Budget { steps: 1_000_000_000 };
        let entry_fn = env.lookup_global(&format!("{}", spec.func().trim_end_matches("_go"))).unwrap();
        let lemma_k = prev.unwrap();
        let proof = {
            let mut e = Engine::new(env, &mut sb, &cfg, &db, vec![], 0);
            let mut st = St::new(env, &Ctx::default(), cfg.max_split_depth);
            let goal = open(&mut e, &mut st, &ty);
            let guarded = spec.k_max() == 63;
            let mut arm_fn = |e2: &mut Engine<'_>, arm: &mut St, tk: V, k: u32| -> R<Option<Tm>> {
                let Some((_, lhs, _)) = as_eq(&tk) else { return Ok(None) };
                match call_args(lhs, func) {
                    Some(call) => b.apply_lemma(e2, arm, lemma_k, &call, "entry"),
                    None => {
                        let _ = k;
                        Ok(b.obligation(e2.env, &arm.ctx, &tk, "entry.guard", &[]))
                    }
                }
            };
            delta_then(&mut e, &mut st, &goal, entry_fn, guarded, &mut arm_fn).ok().flatten().map(|p| st.finish(p))
        };
        let skeleton = 1_000_000_000 - sb.steps;
        let name = format!("d1::{}::summary", spec.func().trim_start_matches("crate::"));
        let (ok, check) = match proof {
            Some(p) => match add_lemma(env, &name, ty, p) {
                Ok((_, s)) => (true, s),
                Err(m) => {
                    b.stats.record("kernel check", 0, Duration::ZERO, Some(m));
                    (false, 0)
                }
            },
            None => (false, 0),
        };
        b.stats.lemmas.push((name.clone(), b.stats.current + skeleton, check, t0.elapsed(), ok));
        eprintln!("[d1] {name}: {}", if ok { "closed" } else { "OPEN" });
    }
    b.stats
}

/// The closed form agrees with the loop on sample inputs (the design's
/// trace check, §7.4: candidates are validated before any proof work).
fn check_closed_form(env: &Env, call: &str, cf: &str, samples: &[(u64, u64)]) {
    for (l, t) in samples {
        let a = env
            .eval_closed(
                &env.parse_term(&[], &call.replace("$L", &format!("{l}u64")).replace("$T", &format!("{t}u64"))).unwrap(),
                &mut Budget { steps: 100_000_000 },
            )
            .unwrap();
        let b = env
            .eval_closed(
                &env.parse_term(&[], &cf.replace("$L", &format!("{l}u64")).replace("$T", &format!("{t}u64"))).unwrap(),
                &mut Budget { steps: 100_000_000 },
            )
            .unwrap();
        assert_eq!(env.print_term(&[], &a), env.print_term(&[], &b), "closed form differs at L = {l}, t = {t}");
    }
}

fn samples(bound: u64) -> Vec<(u64, u64)> {
    let mut s = vec![
        (0, 0),
        (1, 0),
        (1, 1),
        (2, 1),
        (3, 2),
        (bound, 0),
        (bound, bound - 1),
        (bound - 1, bound - 2),
        (0b1011_0110, 0b1011_0000),
        (0b1011_0110, 0b1001_1111),
    ];
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..40 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let l = x % (bound.saturating_add(1)).max(1);
        let t = (x.rotate_left(17)) % (l.saturating_add(8)).max(1);
        s.push((l, t));
    }
    s
}

fn shape_env() -> Env {
    let merkle = repo("sandblaster/fixtures/qmdb/sandblaster/merkle.rs");
    let mut env = elaborate(&[
        item(&merkle, "pub const MAX_LEAVES"),
        item(&merkle, "pub struct Shape"),
        item(&merkle, "pub fn shape("),
        item(&merkle, "pub(crate) fn shape_go("),
    ]);
    env.load_core(
        "def[spec] d1::shape_cf : (L : U64) -> (t : U64) -> crate::Shape :=
  fun (L : U64) (t : U64) =>
    let h : U32 = #wsub_u32(63u32, #leading_zeros_u64(#xor_u64(L, t)));
    let width : U64 = #wshl_u64(1u64, h);
    let hi : U64 = #wshr_u64(#wshr_u64(L, h), 1u32);
    let before : U32 = #count_ones_u64(hi);
    let start : U64 = #wshl_u64(#wshl_u64(hi, h), 1u32);
    Shape(h, width, #wsub_u64(#wsub_u64(#wmul_u64(#wadd_u64(start, width), 2u64), #cast_u32_u64(before)), 2u64), #and_u64(t, #wsub_u64(width, 1u64)), before, #count_ones_u64(#and_u64(L, #wsub_u64(width, 1u64))))
",
        &mut Budget { steps: 100_000_000 },
    )
    .unwrap();
    env
}

fn block_env() -> Env {
    let p4 = repo("sandblaster/front/tests/opt_corpus/dsl/mod.rs");
    let mut env = elaborate(&[item(&p4, "pub struct Block"), item(&p4, "fn find_block_go("), item(&p4, "pub fn find_block(")]);
    env.load_core(
        "def[spec] d1::block_cf : (L : U64) -> (t : U64) -> crate::Block :=
  fun (L : U64) (t : U64) =>
    let h : U32 = #wsub_u32(63u32, #leading_zeros_u64(#xor_u64(L, t)));
    let hi : U64 = #wshr_u64(#wshr_u64(L, h), 1u32);
    Block(h, #wshl_u64(#wshl_u64(hi, h), 1u32), #count_ones_u64(hi))
",
        &mut Budget { steps: 100_000_000 },
    )
    .unwrap();
    env
}

/// The resident set size of this process (`ps`), in MiB (0 if unknown).
fn rss_mib() -> u64 {
    std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

fn big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || {
            sandblaster_kernel::util::set_stack_limit(900 << 20);
            f()
        })
        .unwrap()
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e))
}

fn assert_d1(stats: &Stats, k_max: u32) {
    let open: Vec<&String> = stats.lemmas.iter().filter(|l| !l.4).map(|l| &l.0).collect();
    assert!(open.is_empty(), "open lemmas: {open:?}");
    assert_eq!(stats.lemmas.len() as u32, k_max + 2, "lemma_0 … lemma_K and the summary");
    let total: u64 = stats.lemmas.iter().map(|l| l.1 + l.2).sum();
    for l in &stats.lemmas {
        assert!(l.1 + l.2 <= PER_LEMMA, "{} took {} steps (> {PER_LEMMA})", l.0, l.1 + l.2);
    }
    assert!(total <= PER_LOOP, "{total} steps for the loop (> {PER_LOOP})");
}

#[test]
fn d1_shape_go() {
    let (stats, k) = big_stack(|| {
        let mut env = shape_env();
        let bound = 1u64 << 62;
        check_closed_form(
            &env,
            "crate::shape $L $T",
            &format!(
                "match #le_u64($L, {bound}u64) : Bool as _ return Option(crate::Shape) with | false => None[crate::Shape] | true => {} end",
                opt("crate::Shape", "#lt_u64($T, $L)", "d1::shape_cf $L $T")
            ),
            &samples(bound),
        );
        let stats = run_loop(&mut env, &ShapeSpec);
        eprintln!("{}", stats.report(ShapeSpec.label()));
        eprintln!("heap: {} MiB; process RSS: {} MiB", sandblaster_front::memguard::allocated() >> 20, rss_mib());
        (stats, ShapeSpec.k_max())
    });
    if std::env::var_os("D1_MAX_F").is_none() {
        assert_d1(&stats, k);
    }
}

#[test]
fn d1_find_block_go() {
    let (stats, k) = big_stack(|| {
        let mut env = block_env();
        check_closed_form(
            &env,
            "crate::find_block $L $T",
            &opt("crate::Block", "#lt_u64($T, $L)", "d1::block_cf $L $T"),
            &samples(u64::MAX),
        );
        let stats = run_loop(&mut env, &BlockSpec);
        eprintln!("{}", stats.report(BlockSpec.label()));
        eprintln!("heap: {} MiB; process RSS: {} MiB", sandblaster_front::memguard::allocated() >> 20, rss_mib());
        (stats, BlockSpec.k_max())
    });
    if std::env::var_os("D1_MAX_F").is_none() {
        assert_d1(&stats, k);
    }
}
