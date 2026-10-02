//! Profiles (`PROFILE.json`, optimizer design §10.4; plan O6).
//!
//! `sandblaster profile` runs the portable semantics — the kernel's
//! reference evaluator — over a crate's declared corpora (benchmark
//! fixtures, test vectors) and records, for every **loop head** (a user
//! recursion that some body calls with a literal measure the driver does not
//! unroll, `drive::unroll_pays`: what Σ2 summarizes), the argument values it is entered
//! with. The entry function is evaluated with the loop heads folded and
//! then resumed application by application ([`collect`]), so every loop
//! call is observed with its actual arguments; the program is not changed.
//!
//! The file is checked in next to the DSL root directory (for QMDB,
//! `qmdb/PROFILE.json`, one entry per root: production and N = 1), is part
//! of the build's determinism key (the build re-runs when it changes), and
//! changes choices only: Σ2's trace inputs start with these samples (design
//! §7.3 (a)). Without it the traces are the seeded corner samples alone.
//! Untrusted: a profile can only change which candidates are tried, never
//! what is admitted.
//!
//! **Train ≠ test** (fairness audit of 2026-10-02, J8). A corpus is a
//! directory of fixtures or a **split manifest** (a `.txt` file: one fixture
//! path per line, relative to the manifest, `#` comments; QMDB's are
//! `fixtures/qmdb/splits/*-profile.txt`, every second fixture by name). The
//! profile is recorded on a profile half only and the benchmark times the
//! other half: [`Profile::check_timed`] refuses any timed input that lies in
//! a corpus an entry was recorded on, and every report states whether a
//! profile was used (its hash keys the proof cache and is reported).
//!
//! Format (`sandblaster-profile/1`): `{"format", "entries": [{"root",
//! "entry", "corpora", "fixtures", "loops": [{"loop": "<path>", "calls": n,
//! "samples": [["<arg>", …], …]}]}]}` — each sample is the loop call's
//! relevant arguments (decimal integers; `"_"` for a non-integer argument),
//! deduplicated, at most [`MAX_SAMPLES`] per loop and entry in a
//! deterministic spread (sorted, then evenly strided).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use num_traits::ToPrimitive;
use sandblaster_kernel::term::{GlobalId, Lvl, Rel, Term, Tm};
use sandblaster_kernel::util::mk;
use sandblaster_kernel::value::{Arg, Budget, Closure, Elim, EnvEntry, Head, Neutral, VEnv, Value};

use crate::elab::{self, value::J};
use crate::hir::*;

/// Samples kept per loop.
pub const MAX_SAMPLES: usize = 64;

pub const FORMAT: &str = "sandblaster-profile/1";

/// Per loop head path: (calls seen, distinct argument vectors).
pub type Loops = BTreeMap<String, (usize, BTreeSet<Vec<String>>)>;

/// One corpus run recorded in the file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub root: String,
    pub entry: String,
    pub corpora: Vec<String>,
    pub fixtures: usize,
    pub loops: Loops,
}

/// A profile (see the module docs).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    pub entries: Vec<Entry>,
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn str_field(fs: &[(String, J)], k: &str) -> Option<String> {
    fs.iter().find(|(n, _)| n == k).and_then(|(_, v)| if let J::Str(s) = v { Some(s.clone()) } else { None })
}

fn num_field(fs: &[(String, J)], k: &str) -> usize {
    fs.iter().find(|(n, _)| n == k).and_then(|(_, v)| if let J::Num(n) = v { n.parse().ok() } else { None }).unwrap_or(0)
}

impl Profile {
    /// The deterministic JSON text.
    pub fn to_json(&self) -> String {
        let mut out = format!("{{\n  \"format\": {},\n  \"entries\": [", quote(FORMAT));
        for (i, e) in self.entries.iter().enumerate() {
            out.push_str(if i == 0 { "\n" } else { ",\n" });
            out.push_str(&format!(
                "    {{\n      \"root\": {},\n      \"entry\": {},\n      \"corpora\": [{}],\n      \"fixtures\": {},\n      \"loops\": [",
                quote(&e.root),
                quote(&e.entry),
                e.corpora.iter().map(|c| quote(c)).collect::<Vec<_>>().join(", "),
                e.fixtures
            ));
            for (k, (l, (calls, samples))) in e.loops.iter().enumerate() {
                out.push_str(if k == 0 { "\n" } else { ",\n" });
                out.push_str(&format!("        {{\"loop\": {}, \"calls\": {calls}, \"samples\": [", quote(l)));
                for (m, s) in spread(samples).iter().enumerate() {
                    if m > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&format!("[{}]", s.iter().map(|a| quote(a)).collect::<Vec<_>>().join(", ")));
                }
                out.push_str("]}");
            }
            out.push_str(if e.loops.is_empty() { "]\n    }" } else { "\n      ]\n    }" });
        }
        out.push_str("\n  ]\n}\n");
        out
    }

    /// Parses a profile.
    pub fn parse(text: &str) -> Result<Profile, String> {
        let J::Obj(fields) = J::parse(text)? else { return Err("a profile must be a JSON object".into()) };
        if str_field(&fields, "format").as_deref() != Some(FORMAT) {
            return Err(format!("not a `{FORMAT}` profile"));
        }
        let mut p = Profile::default();
        let Some((_, J::Arr(es))) = fields.iter().find(|(n, _)| n == "entries") else { return Ok(p) };
        for e in es {
            let J::Obj(ef) = e else { return Err("an entry that is not an object".into()) };
            let corpora = match ef.iter().find(|(n, _)| n == "corpora") {
                Some((_, J::Arr(a))) => a.iter().filter_map(|x| if let J::Str(s) = x { Some(s.clone()) } else { None }).collect(),
                _ => Vec::new(),
            };
            let mut loops = Loops::new();
            if let Some((_, J::Arr(ls))) = ef.iter().find(|(n, _)| n == "loops") {
                for l in ls {
                    let J::Obj(lf) = l else { return Err("a loop that is not an object".into()) };
                    let name = str_field(lf, "loop").ok_or("a loop without its name")?;
                    let mut samples = BTreeSet::new();
                    if let Some((_, J::Arr(ss))) = lf.iter().find(|(n, _)| n == "samples") {
                        for s in ss {
                            let J::Arr(xs) = s else { return Err("a sample that is not an array".into()) };
                            samples.insert(xs.iter().map(|x| if let J::Str(s) = x { s.clone() } else { "_".into() }).collect());
                        }
                    }
                    loops.insert(name, (num_field(lf, "calls"), samples));
                }
            }
            p.entries.push(Entry { root: str_field(ef, "root").unwrap_or_default(), entry: str_field(ef, "entry").unwrap_or_default(), corpora, fixtures: num_field(ef, "fixtures"), loops });
        }
        Ok(p)
    }

    /// Adds another profile's entries (an entry for the same root and entry
    /// function replaces the old one).
    pub fn merge(&mut self, o: Profile) {
        for e in o.entries {
            match self.entries.iter_mut().find(|x| x.root == e.root && x.entry == e.entry) {
                Some(x) => *x = e,
                None => self.entries.push(e),
            }
        }
    }

    /// The loop samples as Σ2 reads them: loop path → argument vectors
    /// (`None` for a non-integer argument), every entry's kept samples.
    pub fn loop_samples(&self) -> BTreeMap<String, Vec<Vec<Option<u128>>>> {
        let mut all: BTreeMap<String, BTreeSet<Vec<String>>> = BTreeMap::new();
        for e in &self.entries {
            for (l, (_, ss)) in &e.loops {
                all.entry(l.clone()).or_default().extend(spread(ss));
            }
        }
        all.into_iter().map(|(l, ss)| (l, ss.into_iter().map(|s| s.iter().map(|a| a.parse::<u128>().ok()).collect()).collect())).collect()
    }
}

/// At most [`MAX_SAMPLES`] of a sorted set, evenly strided (deterministic).
fn spread(ss: &BTreeSet<Vec<String>>) -> Vec<Vec<String>> {
    let v: Vec<&Vec<String>> = ss.iter().collect();
    if v.len() <= MAX_SAMPLES {
        return v.into_iter().cloned().collect();
    }
    (0..MAX_SAMPLES).map(|i| v[i * v.len() / MAX_SAMPLES].clone()).collect()
}

/// The profile of a crate: `PROFILE.json` in the parent directory of the
/// DSL root's directory (`sandblaster/fixtures/qmdb/sandblaster/mod.rs` and `sandblaster/fixtures/qmdb/sandblaster/n1.rs`
/// → `qmdb/PROFILE.json`), when the file exists: its path and its parse.
pub fn for_root(fs: &dyn crate::loader::FileProvider, root: &Path) -> Option<(PathBuf, Result<Profile, String>)> {
    let path = root.parent()?.parent()?.join("PROFILE.json");
    if !fs.exists(&path) {
        return None;
    }
    let parsed = fs.read(&path).map_err(|e| e.to_string()).and_then(|t| Profile::parse(&t));
    Some((path, parsed))
}

/// The loop heads of a crate (see the module docs): user recursions with a
/// measure parameter that some body calls with a literal trip count the
/// driver does not unroll (`drive::unroll_pays` under `cfg`).
pub fn loop_heads(krate: &Crate, fn_globals: &HashMap<ItemId, GlobalId>, cfg: &crate::opt::drive::DriveConfig) -> HashSet<GlobalId> {
    let mut measure: HashMap<ItemId, usize> = HashMap::new();
    for it in &krate.items {
        if let ItemKind::Fn(f) = &it.kind
            && f.kind == FnKind::Exec
            && let Some(crate::opt::drive::Measure::Param(i)) = crate::opt::drive::measure_of(it.id, f)
        {
            measure.insert(it.id, i - f.generics.len());
        }
    }
    struct V<'a> {
        krate: &'a Crate,
        measure: &'a HashMap<ItemId, usize>,
        cfg: &'a crate::opt::drive::DriveConfig,
        out: HashSet<ItemId>,
    }
    impl crate::visit::Visitor for V<'_> {
        fn expr(&mut self, e: &Expr) {
            if let ExprKind::Call { callee: Callee::Item(c, _), args } = &e.kind
                && let Some(&i) = self.measure.get(c)
                && let Some(ExprKind::Lit(Lit::Int(n))) = args.get(i).map(|a| &a.kind)
                && let Some(f) = self.krate.fn_def(*c)
                && !u32::try_from(*n).is_ok_and(|t| crate::opt::drive::unroll_pays(self.krate, *c, f, t, self.cfg))
            {
                self.out.insert(*c);
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V { krate, measure: &measure, cfg, out: HashSet::new() };
    for it in &krate.items {
        if let ItemKind::Fn(f) = &it.kind {
            crate::visit::walk_fn(&mut v, f);
        }
    }
    v.out.iter().filter_map(|i| fn_globals.get(i).copied()).collect()
}

/// Evaluates `entry(args)` (a JSON argument array, `sandblaster eval`'s
/// format) and returns every loop head application it performs: (loop
/// path, its relevant arguments as decimal text, `"_"` for a non-integer).
///
/// The entry is evaluated with the loop heads folded; the result is then
/// **resumed** ([`Resume`]): a value stuck on a loop application records
/// the application, replaces it by its value (evaluated in full) and
/// continues its eliminations, again with the heads folded, until no loop
/// application is left. The final value is the entry's value (checked
/// against a plain evaluation by the caller's tests).
pub fn collect(out: &elab::Output, krate: &Crate, entry: &str, args: &str, heads: &HashSet<GlobalId>) -> Result<(Vec<(String, Vec<String>)>, V), String> {
    let path = if entry.starts_with("crate::") { entry.to_string() } else { format!("crate::{entry}") };
    let id = krate.find(&path).ok_or_else(|| format!("no item `{path}`"))?;
    let f = krate.fn_def(id).ok_or_else(|| format!("`{path}` is not a function"))?;
    let g = *out.fn_globals.get(&id).ok_or_else(|| format!("`{path}` was not elaborated"))?;
    let rels = out.env.global_param_rels(g).ok_or("no parameter list")?;
    let J::Arr(vals) = J::parse(args)? else { return Err("arguments must be a JSON array".into()) };
    let vparams: Vec<&Param> = f.params.iter().filter(|p| !p.ghost).collect();
    if vals.len() != vparams.len() {
        return Err(format!("`{path}` takes {} argument(s), got {}", vparams.len(), vals.len()));
    }
    let conv = elab::value::Conv { env: &out.env, krate, adts: &out.adts };
    let mut rel_args = vparams.iter().zip(&vals).map(|(p, x)| conv.term(&p.ty, x));
    let mut targs: Vec<(Rel, Tm)> = Vec::new();
    for r in rels {
        let a = match r {
            Rel::Rel => rel_args.next().ok_or("argument mismatch")??,
            Rel::Irr => std::rc::Rc::new(Term::Erased),
        };
        targs.push((r, a));
    }
    let term = mk::apps(mk::global(g), targs);
    let mut r = Resume { env: &out.env, heads, budget: Budget { steps: 50_000_000_000 }, found: Vec::new() };
    let opaque = |x: GlobalId| heads.contains(&x);
    let v = out.env.eval_opaque(&VEnv::default(), Lvl(0), &term, &opaque, &mut r.budget).map_err(|e| format!("evaluation failed: {e:?}"))?;
    let v = r.force(&v)?;
    let found = r.found.into_iter().map(|(d, a)| (out.env.global_name(d).map(|s| s.to_string()).unwrap_or_default(), a)).collect();
    Ok((found, v))
}

/// The resumption of a value stuck on loop applications (see [`collect`]).
struct Resume<'a> {
    env: &'a sandblaster_kernel::api::Env,
    heads: &'a HashSet<GlobalId>,
    budget: Budget,
    found: Vec<(GlobalId, Vec<String>)>,
}

type V = sandblaster_kernel::value::V;

impl Resume<'_> {
    fn eval_folded(&mut self, env: &VEnv, t: &Tm) -> Result<V, String> {
        let heads = self.heads;
        let opaque = |x: GlobalId| heads.contains(&x);
        self.env.eval_opaque(env, Lvl(0), t, &opaque, &mut self.budget).map_err(|e| format!("evaluation failed: {e:?}"))
    }

    /// `v` with every loop application it is stuck on replaced by its value.
    fn force(&mut self, v: &V) -> Result<V, String> {
        match &**v {
            Value::Neu(n) => {
                let head = match &n.head {
                    Head::Global { def, args } if self.heads.contains(def) => {
                        let args = self.force_args(args)?;
                        let text: Vec<String> = args
                            .iter()
                            .filter_map(|a| match a {
                                Arg::Rel(v) => Some(match &**v {
                                    Value::Lit { n, .. } => n.to_u128().map(|x| x.to_string()).unwrap_or_else(|| "_".into()),
                                    _ => "_".into(),
                                }),
                                Arg::Irr(_) => None,
                            })
                            .collect();
                        self.found.push((*def, text));
                        let t = mk::apps(mk::global(*def), args.iter().map(|a| self.quote_arg(a)).collect::<Vec<_>>());
                        self.env.eval_opaque(&VEnv::default(), Lvl(0), &t, &|_| false, &mut self.budget).map_err(|e| format!("evaluation failed: {e:?}"))?
                    }
                    Head::Prim { op, args, proofs } => {
                        let forced: Vec<V> = args.iter().map(|a| self.force(a)).collect::<Result<_, _>>()?;
                        if forced.iter().zip(args).all(|(a, b)| std::rc::Rc::ptr_eq(a, b)) {
                            return Ok(v.clone());
                        }
                        let ps: Vec<Tm> = proofs.iter().map(|_| std::rc::Rc::new(Term::Erased)).collect();
                        let t = std::rc::Rc::new(Term::Prim { op: *op, args: forced.iter().map(|a| self.env.quote(Lvl(0), a, false)).collect(), proofs: ps });
                        self.eval_folded(&VEnv::default(), &t)?
                    }
                    Head::Global { def, args } => {
                        // stuck on an argument that may be a loop application
                        let forced = self.force_args(args)?;
                        let same = forced.iter().zip(args).all(|(a, b)| match (a, b) {
                            (Arg::Rel(x), Arg::Rel(y)) => std::rc::Rc::ptr_eq(x, y),
                            _ => true,
                        });
                        if same {
                            return Ok(v.clone());
                        }
                        let t = mk::apps(mk::global(*def), forced.iter().map(|a| self.quote_arg(a)).collect::<Vec<_>>());
                        self.eval_folded(&VEnv::default(), &t)?
                    }
                    _ => return Ok(v.clone()),
                };
                let mut cur = self.force(&head)?;
                for e in &n.spine {
                    cur = self.elim(&cur, e)?;
                    cur = self.force(&cur)?;
                }
                Ok(cur)
            }
            Value::Ctor { ind, ctor, params, args } => {
                let args2 = self.force_args(args)?;
                Ok(std::rc::Rc::new(Value::Ctor { ind: *ind, ctor: *ctor, params: params.clone(), args: args2 }))
            }
            Value::Pair { fst, snd } => {
                let fst = self.force(fst)?;
                let snd = match snd {
                    Arg::Rel(x) => Arg::Rel(self.force(x)?),
                    a => a.clone(),
                };
                Ok(std::rc::Rc::new(Value::Pair { fst, snd }))
            }
            _ => Ok(v.clone()),
        }
    }

    fn force_args(&mut self, args: &[Arg]) -> Result<Vec<Arg>, String> {
        args.iter()
            .map(|a| match a {
                Arg::Rel(x) => Ok(Arg::Rel(self.force(x)?)),
                a => Ok(a.clone()),
            })
            .collect()
    }

    fn quote_arg(&self, a: &Arg) -> (Rel, Tm) {
        match a {
            Arg::Rel(v) => (Rel::Rel, self.env.quote(Lvl(0), v, false)),
            Arg::Irr(_) => (Rel::Irr, std::rc::Rc::new(Term::Erased)),
        }
    }

    /// One elimination applied to a value.
    fn elim(&mut self, v: &V, e: &Elim) -> Result<V, String> {
        let ext = |c: &Closure, es: Vec<EnvEntry>| {
            let mut xs: Vec<EnvEntry> = c.env.0.as_ref().clone();
            xs.extend(es);
            VEnv(std::rc::Rc::new(xs))
        };
        let entry = |a: &Arg| match a {
            Arg::Rel(x) => EnvEntry::Rel(x.clone()),
            Arg::Irr(c) => EnvEntry::Irr(c.clone()),
        };
        match (e, &**v) {
            (Elim::App(a), Value::Lam { body, .. }) => {
                let env = ext(body, vec![entry(a)]);
                self.eval_folded(&env, &body.body)
            }
            (Elim::Fst, Value::Pair { fst, .. }) => Ok(fst.clone()),
            (Elim::Snd, Value::Pair { snd: Arg::Rel(x), .. }) => Ok(x.clone()),
            (Elim::Match { arms, .. }, Value::Ctor { ctor, args, .. }) => {
                let arm = arms.get(*ctor as usize).ok_or("a match without the constructor's arm")?;
                let env = ext(arm, args.iter().map(entry).collect());
                self.eval_folded(&env, &arm.body)
            }
            (_, Value::Neu(n)) => {
                let mut spine: Vec<Elim> = n.spine.iter().map(clone_elim).collect();
                spine.push(clone_elim(e));
                Ok(std::rc::Rc::new(Value::Neu(Neutral { head: clone_head(&n.head), spine })))
            }
            _ => Err("an elimination of a value of the wrong shape".into()),
        }
    }
}

fn clone_elim(e: &Elim) -> Elim {
    match e {
        Elim::App(a) => Elim::App(a.clone()),
        Elim::Fst => Elim::Fst,
        Elim::Snd => Elim::Snd,
        Elim::Match { ind, params, motive, arms } => Elim::Match { ind: *ind, params: params.clone(), motive: motive.clone(), arms: arms.clone() },
    }
}

fn clone_head(h: &Head) -> Head {
    match h {
        Head::Var(l) => Head::Var(*l),
        Head::Global { def, args } => Head::Global { def: *def, args: args.clone() },
        Head::Prim { op, args, proofs } => Head::Prim { op: *op, args: args.clone(), proofs: proofs.clone() },
        Head::Absurd { ty } => Head::Absurd { ty: ty.clone() },
        Head::Transport { ty, lhs, rhs, motive, val } => Head::Transport { ty: ty.clone(), lhs: lhs.clone(), rhs: rhs.clone(), motive: motive.clone(), val: val.clone() },
        Head::Axiom { ax, args } => Head::Axiom { ax: *ax, args: args.clone() },
    }
}

/// The fixture files of a corpus: a directory's `*.json` files (sorted), or
/// the files a split manifest lists (a `.txt` file: one path per line,
/// relative to the manifest's directory; blank lines and `#` comments
/// skipped), in its order.
pub fn corpus_files(corpus: &Path) -> Result<Vec<PathBuf>, String> {
    if corpus.is_dir() {
        let mut files: Vec<PathBuf> = std::fs::read_dir(corpus).map_err(|e| format!("{}: {e}", corpus.display()))?.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
        files.sort();
        return Ok(files);
    }
    let text = std::fs::read_to_string(corpus).map_err(|e| format!("{}: {e}", corpus.display()))?;
    let base = corpus.parent().unwrap_or(Path::new("."));
    Ok(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(|l| base.join(l)).collect())
}

impl Profile {
    /// Refuses timed inputs a profile was recorded on (train ≠ test, see the
    /// module docs): every file of `timed` is compared with every file of
    /// every entry's corpora (`base`: the directory the corpora are relative
    /// to, `PROFILE.json`'s), by canonical path. `Err` names the overlap.
    pub fn check_timed(&self, base: &Path, timed: &[PathBuf]) -> Result<(), String> {
        let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let timed: Vec<PathBuf> = timed.iter().map(|p| canon(p)).collect();
        let mut overlap = Vec::new();
        for e in &self.entries {
            for c in &e.corpora {
                for f in corpus_files(&base.join(c))? {
                    let f = canon(&f);
                    if timed.contains(&f) {
                        overlap.push(format!("{} (profile entry `{}` / `{}`, corpus `{c}`)", f.display(), e.root, e.entry));
                    }
                }
            }
        }
        if overlap.is_empty() { Ok(()) } else { Err(format!("{} timed input(s) are profile inputs (record the profile on a disjoint split): {}", overlap.len(), overlap.join(", "))) }
    }
}

/// The profile of `entry` over the corpora `corpora` (fixture directories or
/// split manifests, [`corpus_files`]): each fixture is a JSON object whose
/// fields `fields` (hex strings) are the entry's arguments, as byte slices,
/// in order.
pub fn run(out: &elab::Output, krate: &Crate, root: &str, entry: &str, corpora: &[PathBuf], fields: &[String], cfg: &crate::opt::drive::DriveConfig) -> Result<Profile, String> {
    let heads = loop_heads(krate, &out.fn_globals, cfg);
    let mut loops = Loops::new();
    let mut n = 0usize;
    for dir in corpora {
        for f in corpus_files(dir)? {
            let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
            let J::Obj(fx) = J::parse(&text)? else { return Err(format!("{}: not a JSON object", f.display())) };
            let mut args = Vec::new();
            let mut ok = true;
            for k in fields {
                match fx.iter().find(|(n, _)| n == k) {
                    Some((_, J::Str(s))) => args.push(format!("\"0x{}\"", s.trim_start_matches("0x"))),
                    _ => ok = false,
                }
            }
            if !ok {
                continue;
            }
            n += 1;
            let (calls, _) = collect(out, krate, entry, &format!("[{}]", args.join(", ")), &heads).map_err(|e| format!("{}: {e}", f.display()))?;
            for (l, a) in calls {
                let slot = loops.entry(l).or_default();
                slot.0 += 1;
                slot.1.insert(a);
            }
        }
    }
    Ok(Profile { entries: vec![Entry { root: root.to_string(), entry: entry.to_string(), corpora: corpora.iter().map(|c| c.display().to_string()).collect(), fixtures: n, loops }] })
}

/// `sandblaster profile`: elaborates the checked crate and runs [`run`]
/// over the corpora. The whole crate is elaborated (not the test-only
/// exec-only mode, which `VerifyOptions::exec_only` reserves for tests):
/// exec code may call proof lemmas (QMDB's verifier does since its §15
/// spec), and an exec-only elaboration leaves such a function unelaborated.
pub fn profile_crate(c: &crate::driver::Checked, root: &str, entry: &str, corpora: &[PathBuf], fields: &[String]) -> Result<Profile, String> {
    let k = c.krate.as_ref().ok_or("the crate has front-end errors")?;
    if !c.ok() {
        return Err("the crate has front-end errors".into());
    }
    let opts = crate::driver::VerifyOptions { exec_only: false, ..Default::default() };
    let cfg = crate::opt::drive::DriveConfig::default();
    crate::driver::stage::with_elaboration(k, &opts, |out| run(out, k, root, entry, corpora, fields, &cfg))
}
