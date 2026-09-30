//! Incremental spec mutation (North star principle 5; DESIGN.md §15.8
//! *Gate mode*): the per-mutant verdict cache of the spec-mutation gate.
//!
//! A spec mutant's gate verdict is a deterministic function of what its
//! re-check reads (module docs of [`super`], *Gate mode*): the mutant
//! (item, operator, site, diff), its plan (the gate part of its closure,
//! its known answers in order, its observation points and suggestions),
//! the HIR of every item the batch's elaboration of it can reach — the
//! reference closure of the clones, the law checkers and the compared
//! functions (without the `proof!` blocks of exec functions, and without
//! the lemmas those name), through statements only for laws, lemmas and
//! proofs
//! ([`crate::elab::order::statement_refs`], [`statement_only`]: proofs are
//! irrelevant to every stored verdict) — the crate-level facts (and the
//! statements of `#[bridges]` lemmas, rules of `auto`) the
//! elaborator reads (target, boundary, reachable items), the gate's fixed
//! options and the toolchain. [`mutant_key`] hashes exactly that, with
//! each item's HIR **fingerprinted position-independently** ([`Fps`]: the
//! item's `Debug` form with spans removed and item and module indices
//! replaced by paths), so an edit elsewhere in a file does not invalidate
//! the mutants below it.
//!
//! [`super::run_from`] (gate mode, with a cache) looks every spec mutant up
//! before planning its batches, runs only the misses, and stores every
//! decided verdict: killed by the specification, by safety or by proofs,
//! invalid, a counterexample, possibly equivalent. A mutant not run or
//! killed only by budget (resource outcomes) is never stored. An entry
//! restores the [`Outcome`] (with its witnesses) and the mutant's LR8
//! records (the laws that had it in scope, which ones it killed and
//! whether each law is evaluable), so the report and every diagnostic are
//! the same as a cold run's. An entry that does not decode (or names an
//! item the crate no longer has) is a miss.
//!
//! Implementation mutants (which re-prove the implementation) are never
//! cached: they run only when a section is not fully specified, a failing
//! build.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};

use super::{gate_cloned, ExSlot, Mutant, Outcome, Plan, Verdict, Witness};
use crate::hir::*;
use crate::surface::{hex, sha256};

/// The cache namespace of spec mutants.
pub const NS: &str = "mutant";

/// Position-independent fingerprints of the crate's items, memoized.
pub struct Fps<'k> {
    krate: &'k Crate,
    fp: RefCell<HashMap<ItemId, String>>,
    refs: RefCell<HashMap<ItemId, BTreeSet<ItemId>>>,
    /// The crate-level facts every elaboration reads.
    pub crate_fp: String,
}

/// `Debug` text with every span removed and every item, module and file
/// index replaced by a stable name (so the text does not change when code
/// above the item moves, or items are added elsewhere).
pub fn normalize_debug(krate: &Crate, s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let num = |i: usize| -> Option<(u32, usize)> {
        let mut j = i;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == i || j >= b.len() || b[j] != b')' {
            return None;
        }
        s[i..j].parse::<u32>().ok().map(|n| (n, j + 1))
    };
    while i < b.len() {
        let rest = &s[i..];
        if rest.starts_with("Span { file: FileId(")
            && let Some(end) = rest.find(" }")
        {
            out.push('S');
            i += end + 2;
            continue;
        }
        let mut replaced = false;
        for (tag, kind) in [("ItemId(", 0u8), ("ModId(", 1u8), ("FileId(", 2u8)] {
            if rest.starts_with(tag)
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
                && let Some((n, next)) = num(i + tag.len())
            {
                match kind {
                    0 if (n as usize) < krate.items.len() => out.push_str(&format!("Item({})", krate.item(ItemId(n)).path)),
                    1 if (n as usize) < krate.modules.len() => out.push_str(&format!("Mod({})", krate.module(ModId(n)).path)),
                    2 => out.push_str("File"),
                    _ => out.push_str(&s[i..next]),
                }
                i = next;
                replaced = true;
                break;
            }
        }
        if replaced {
            continue;
        }
        let ch = rest.chars().next().expect("non-empty");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

impl<'k> Fps<'k> {
    pub fn new(krate: &'k Crate) -> Fps<'k> {
        let mut reach: Vec<String> = krate.reachable.iter().map(|x| krate.item(*x).path.to_string()).collect();
        reach.sort();
        let mut t = format!("target {:?}\nboundary {}\nreachable {}\n", krate.target, normalize_debug(krate, &format!("{:?}", krate.boundary)), reach.join(" "));
        let mut fps = Fps { krate, fp: RefCell::new(HashMap::new()), refs: RefCell::new(HashMap::new()), crate_fp: String::new() };
        // the statements of `#[bridges]` lemmas: rules of `auto` in every
        // elaboration, whether or not a mutant reaches them
        for it in krate.items.iter().filter(|it| krate.in_bridges_module(it.id)) {
            t.push_str(&format!("bridge {} {}\n", it.path, fps.item(it.id)));
        }
        fps.crate_fp = hex(&sha256(t.as_bytes()));
        fps
    }

    /// The fingerprint of one item: its HIR and the flags of its module;
    /// for a law, lemma or proof item only its statement (see
    /// [`statement_only`]).
    pub fn item(&self, id: ItemId) -> String {
        if let Some(f) = self.fp.borrow().get(&id) {
            return f.clone();
        }
        let it = self.krate.item(id);
        let m = self.krate.module(it.module);
        let shown = statement_only(it);
        let mut body = normalize_debug(self.krate, &format!("{shown:?}"));
        if is_exec(it) {
            body = strip_proofs(&body);
        }
        let text = format!("module {} ghost {} spec {} model {} bridges {} cfg {:?}\n{body}", m.path, m.ghost, m.spec, m.model, m.bridges, m.cfg);
        let f = hex(&sha256(text.as_bytes()));
        self.fp.borrow_mut().insert(id, f.clone());
        f
    }

    fn refs(&self, id: ItemId) -> BTreeSet<ItemId> {
        if let Some(r) = self.refs.borrow().get(&id) {
            return r.clone();
        }
        let mut r = crate::elab::order::statement_refs(self.krate, id);
        // an exec function names lemmas, laws and proofs only in its
        // `proof!` blocks, which no evaluation reads
        if is_exec(self.krate.item(id)) {
            r.retain(|x| !self.krate.fn_def(*x).is_some_and(|f| matches!(f.kind, FnKind::Law | FnKind::Lemma | FnKind::Proof)));
        }
        self.refs.borrow_mut().insert(id, r.clone());
        r
    }

    /// Every item reachable from `seeds` by references (the seeds
    /// included).
    pub fn reach(&self, seeds: impl IntoIterator<Item = ItemId>) -> BTreeSet<ItemId> {
        let mut out = BTreeSet::new();
        let mut work: Vec<ItemId> = seeds.into_iter().collect();
        while let Some(x) = work.pop() {
            if (x.0 as usize) < self.krate.items.len() && out.insert(x) {
                work.extend(self.refs(x).into_iter().filter(|y| !out.contains(y)));
            }
        }
        out
    }
}

fn is_exec(it: &Item) -> bool {
    matches!(&it.kind, ItemKind::Fn(f) if f.kind == FnKind::Exec)
}

/// `Debug` text of an exec function without its `proof! { .. }` blocks
/// (`Proof([..])` statements): ghost, never evaluated, never printed. A
/// proof that no longer goes through makes the mutant *not run* in its
/// batch (never stored), so a stored verdict never depends on one.
pub fn strip_proofs(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if s[i..].starts_with("Proof([") && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) {
            // skip to the matching `])`, outside string literals
            let mut depth = 0i64;
            let mut j = i + "Proof(".len();
            let mut in_str = false;
            while j < b.len() {
                let c = b[j];
                if in_str {
                    if c == b'\\' {
                        j += 1;
                    } else if c == b'"' {
                        in_str = false;
                    }
                } else if c == b'"' {
                    in_str = true;
                } else if c == b'[' || c == b'(' || c == b'{' {
                    depth += 1;
                } else if c == b']' || c == b')' || c == b'}' {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                j += 1;
            }
            out.push_str("Proof(..)");
            // past the `]` and the closing `)`
            i = (j + 2).min(b.len());
            continue;
        }
        let ch = s[i..].chars().next().expect("non-empty");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// The part of an item a gate verdict can depend on: the whole item, but
/// for a law, lemma or proof item only its statement (its body is a
/// `Claim`, the `#[proof]` link of a law dropped). Proofs are irrelevant
/// terms: no example, law checker or distinguishing input evaluates them,
/// and a proof that fails in a mutant's batch makes that mutant *not run*
/// (a resource outcome, never stored), so no stored verdict depends on a
/// proof's text.
pub fn statement_only(it: &Item) -> std::borrow::Cow<'_, Item> {
    match &it.kind {
        ItemKind::Fn(f) if matches!(f.kind, FnKind::Law | FnKind::Lemma | FnKind::Proof) => {
            let mut c = it.clone();
            if let ItemKind::Fn(g) = &mut c.kind {
                g.body = FnBody::Claim;
                g.law_proof = None;
                // the locals the statement uses (the body's are the proof's)
                let stmt = format!("{:?}{:?}{:?}{:?}{:?}", g.params, g.requires, g.ensures, g.decreases, g.spec);
                let used = stmt.match_indices("LocalId(").filter_map(|(i, t)| stmt[i + t.len()..].split(')').next().and_then(|n| n.parse::<usize>().ok())).max();
                g.locals.truncate(used.map_or(0, |n| n + 1));
            }
            std::borrow::Cow::Owned(c)
        }
        _ => std::borrow::Cow::Borrowed(it),
    }
}

/// The key of a spec mutant's gate verdict (module docs). `toolchain` is
/// the verifier's identity, `opts` the gate options' `Debug` form.
pub(super) fn mutant_key(toolchain: &str, opts: &str, fps: &Fps, m: &Mutant, p: &Plan) -> String {
    let krate = fps.krate;
    let path = |x: ItemId| krate.item(x).path.to_string();
    let is_law = |x: ItemId| krate.fn_def(x).is_some_and(|f| f.kind == FnKind::Law);
    let gate: BTreeSet<ItemId> = p.closure.iter().copied().filter(|x| gate_cloned(krate, *x) || is_law(*x)).collect();
    let mut seeds: BTreeSet<ItemId> = gate.clone();
    seeds.extend(p.compared.iter().copied());
    seeds.insert(m.item);
    seeds.extend(p.slots.iter().map(|s| s.item));
    seeds.extend(p.suggest.iter().copied());
    seeds.extend(p.obs.iter().flat_map(|o| std::iter::once(o.x).chain(o.via)));
    let reach = fps.reach(seeds);
    let mut t = String::from("sandblaster-mutant-verdict/1\n");
    t.push_str(&format!("toolchain {toolchain}\ncrate {}\noptions {opts}\n", fps.crate_fp));
    t.push_str(&format!("mutant {} {:?} {}\ndesc {}\nsite {}\n", path(m.item), m.target, m.family, m.desc, normalize_debug(krate, &format!("{:?}", m.site))));
    for d in &m.diff {
        t.push_str(&format!("diff {d}\n"));
    }
    let slot = |s: &ExSlot| format!("{}{}#{}", path(s.item), if s.file { " file" } else { "" }, s.index);
    t.push_str(&format!("plan gate {}\n", gate.iter().map(|x| path(*x)).collect::<Vec<_>>().join(" ")));
    t.push_str(&format!("plan compared {}\n", p.compared.iter().map(|x| path(*x)).collect::<Vec<_>>().join(" ")));
    t.push_str(&format!("plan slots {}\n", p.slots.iter().map(slot).collect::<Vec<_>>().join(" ")));
    t.push_str(&format!("plan obs {}\n", p.obs.iter().map(|o| format!("{}{}", path(o.x), o.via.map(|v| format!(" via {}", path(v))).unwrap_or_default())).collect::<Vec<_>>().join(", ")));
    t.push_str(&format!("plan suggest {}\nplan no_obs {:?}\n", p.suggest.iter().map(|x| path(*x)).collect::<Vec<_>>().join(" "), p.no_obs));
    let mut items: Vec<(String, String)> = reach.iter().map(|x| (path(*x), fps.item(*x))).collect();
    items.sort();
    for (p, f) in items {
        t.push_str(&format!("item {p} {f}\n"));
    }
    hex(&sha256(t.as_bytes()))
}

// ---------------------------------------------------------------------------
// the entry: a length-prefixed encoding of the outcome and the LR8 records
// ---------------------------------------------------------------------------

#[derive(Default)]
struct W(String);

impl W {
    fn s(&mut self, s: &str) -> &mut Self {
        self.0.push_str(&format!("{}:{s}", s.len()));
        self
    }
    fn n(&mut self, n: usize) -> &mut Self {
        self.s(&n.to_string())
    }
    fn b(&mut self, b: bool) -> &mut Self {
        self.s(if b { "1" } else { "0" })
    }
    fn list(&mut self, v: &[String]) -> &mut Self {
        self.n(v.len());
        for x in v {
            self.s(x);
        }
        self
    }
}

struct R<'a>(&'a str);

impl<'a> R<'a> {
    fn s(&mut self) -> Option<&'a str> {
        let colon = self.0.find(':')?;
        let len: usize = self.0[..colon].parse().ok()?;
        let start = colon + 1;
        let v = self.0.get(start..start.checked_add(len)?)?;
        self.0 = &self.0[start + len..];
        Some(v)
    }
    fn n(&mut self) -> Option<usize> {
        self.s()?.parse().ok()
    }
    fn b(&mut self) -> Option<bool> {
        match self.s()? {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    }
    fn list(&mut self) -> Option<Vec<String>> {
        let n = self.n()?;
        (0..n).map(|_| self.s().map(str::to_string)).collect()
    }
}

/// One LR8 record of a mutant: the law (by path), whether the mutant
/// killed it, whether the law is evaluable.
pub type LawRecord = (String, bool, bool);

fn put_witness(w: &mut W, krate: &Crate, x: &Option<Witness>) {
    let Some(x) = x else {
        w.b(false);
        return;
    };
    w.b(true).s(&x.function).s(&krate.item(x.item).path.to_string()).s(&x.input).s(&x.original).s(&x.mutant).list(&x.differs_at).s(&x.evaluator);
    match x.section {
        Some(s) => w.b(true).n(s),
        None => w.b(false),
    };
    match &x.dependency {
        Some((id, n)) => w.b(true).s(&krate.item(*id).path.to_string()).s(n),
        None => w.b(false),
    };
    match &x.refutation {
        Some(Ok(s)) => w.s("ok").s(s),
        Some(Err(s)) => w.s("err").s(s),
        None => w.s("none"),
    };
}

fn get_witness(r: &mut R, paths: &HashMap<String, ItemId>) -> Option<Option<Witness>> {
    if !r.b()? {
        return Some(None);
    }
    let function = r.s()?.to_string();
    let item = *paths.get(r.s()?)?;
    let input = r.s()?.to_string();
    let original = r.s()?.to_string();
    let mutant = r.s()?.to_string();
    let differs_at = r.list()?;
    let evaluator = r.s()?.to_string();
    let section = if r.b()? { Some(r.n()?) } else { None };
    let dependency = if r.b()? { Some((*paths.get(r.s()?)?, r.s()?.to_string())) } else { None };
    let refutation = match r.s()? {
        "ok" => Some(Ok(r.s()?.to_string())),
        "err" => Some(Err(r.s()?.to_string())),
        "none" => None,
        _ => return None,
    };
    Some(Some(Witness { function, item, input, original, mutant, differs_at, evaluator, section, dependency, refutation }))
}

/// Whether a verdict is a result (stored), not a resource outcome.
pub fn cacheable(v: Verdict) -> bool {
    !matches!(v, Verdict::NotRun | Verdict::KilledByBudget)
}

/// The entry text of an outcome and its LR8 records.
pub fn encode(krate: &Crate, o: &Outcome, laws: &[LawRecord]) -> String {
    let mut w = W::default();
    w.s("sandblaster-mutant-outcome/1").s(o.verdict.word()).list(&o.by).list(&o.notes);
    put_witness(&mut w, krate, &o.witness);
    put_witness(&mut w, krate, &o.suggestion);
    w.n(o.law_counterexamples.len());
    for (l, i) in &o.law_counterexamples {
        w.s(&krate.item(*l).path.to_string()).s(i);
    }
    w.n(laws.len());
    for (l, killed, evaluable) in laws {
        w.s(l).b(*killed).b(*evaluable);
    }
    w.0
}

/// Decodes an entry (`None`: not an entry of this format, or it names an
/// item the crate does not have — a miss). `closure` is left 0 (the
/// caller sets it from the fresh plan).
pub fn decode(text: &str, paths: &HashMap<String, ItemId>) -> Option<(Outcome, Vec<(ItemId, LawRecord)>)> {
    let mut r = R(text);
    if r.s()? != "sandblaster-mutant-outcome/1" {
        return None;
    }
    let word = r.s()?;
    let verdict = Verdict::ALL.into_iter().find(|v| v.word() == word)?;
    let by = r.list()?;
    let notes = r.list()?;
    let witness = get_witness(&mut r, paths)?;
    let suggestion = get_witness(&mut r, paths)?;
    let n = r.n()?;
    let mut law_counterexamples = Vec::with_capacity(n);
    for _ in 0..n {
        let l = *paths.get(r.s()?)?;
        law_counterexamples.push((l, r.s()?.to_string()));
    }
    let n = r.n()?;
    let mut laws = Vec::with_capacity(n);
    for _ in 0..n {
        let p = r.s()?.to_string();
        let id = *paths.get(&p)?;
        let killed = r.b()?;
        let evaluable = r.b()?;
        laws.push((id, (p, killed, evaluable)));
    }
    if !r.0.is_empty() {
        return None;
    }
    Some((Outcome { verdict, by, witness, suggestion, closure: 0, notes, law_counterexamples }, laws))
}
