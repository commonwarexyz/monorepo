//! Determinacy (DESIGN.md §15.5; stage **S3**): computed sections, their
//! published functions and hypotheses, `complete_p(R)` built by the
//! kernel's `Env::abstract_section` and proven by `auto` or a
//! `#[proof(complete = p)]` item, well-foundedness over the computed
//! `Deps(R)`, and `#[section(with = [..])]` merges.
//!
//! # Sections (§15.5 "Sections are computed, never declared")
//!
//! * **Must be determined** (the candidates): every function host code
//!   can call ([`crate::validate::boundary_functions`]: the exported
//!   functions, the `pub` methods of every type reachable through their
//!   signatures, and any other `pub` function reachable from the root),
//!   every exec function a law
//!   mentions, every exec function an exported function's contract
//!   mentions, and — transitively — every exec function the hypotheses of a
//!   candidate mention. "Mentions" is `Refs*` of the statement with every
//!   exec function in the stop set: direct occurrences and occurrences
//!   through spec function bodies (a law reaching `f` through a spec fn),
//!   never through another exec body.
//! * **Determined by `#[refines]`**: a checked refinement whose record says
//!   it determines the function (S1/S2 verdicts: identity or injective
//!   result view, `view_inj`, `Abstract(T)`, an established representation
//!   relation). These are fully specified and form no section.
//! * **Sections**: the strongly connected components of the graph `f → g`
//!   ("a hypothesis of `f` mentions the candidate `g`") over the remaining
//!   candidates, after the merges of `#[section(with = [..])]` (merge only:
//!   a union of two nodes, never a removed edge), emitted by Tarjan's
//!   algorithm in the well-founded order ≺: every section after the
//!   sections it depends on.
//! * **`P(R)`**: the members referenced from outside `R` — exported, named by
//!   a law or a spec item, by a contract (any contract, a member's own
//!   included: contracts are on the surface, and a `#[section(with)]` merge
//!   never unpublishes), by the code of an exec function outside `R` — plus
//!   every member in the `requires` of a published member (the kernel
//!   requires them published with a view-free `obs_eq`). A one-member
//!   section publishes its member. Only the published members of a fully
//!   specified section join the stop set of later sections.
//! * **`H(R)`**: the laws mentioning a member (item order; never a
//!   `#[definitional]` law, which is not a guarantee), then per member (id
//!   order) its `ensures` lemma, its refinement lemma (a refinement that
//!   does not determine by itself, e.g. up to a domain) and the invariant
//!   lemmas `S::inv#k` of the struct types of its signature. A law or
//!   contract that mentions a member but did not verify blocks the section.
//!   The kernel abstracts each (the members become `F'` binders; spec
//!   definitions that reach `R` are λ-lifted); a law whose proof slots do
//!   not re-check after abstraction is re-elaborated with the section
//!   abstracted and the earlier hypotheses as facts (`Elab::restate_law`,
//!   abstractability) and passed to the kernel as a restatement; a slot that
//!   still fails is located, with the proposition it needs.
//!
//! # Obligations
//!
//! For each section (in ≺), [`Elab::sections_hook`] calls
//! `Env::abstract_section` with the stop set of every exec function fully
//! specified so far (determined by refinement, a member of an earlier fully
//! specified section, an exec constant, whose value is locked on the
//! surface, or a derived `PartialEq`), then checks well-foundedness: every
//! exec global in the returned `deps` must be in that set, or a trusted
//! primitive (prelude, intrinsic model). A dependency fully specified only
//! up to the lossy view of an `Abstract` type is not accepted (a hypothesis
//! could observe what the view hides; DESIGN.md §15.5's
//! "`obs_eq`-respecting positions" is not checked, so this fails closed),
//! and neither is a function that did not verify. An error of the kernel naming a function outside `R`
//! that "reaches the section" becomes "establish it in an earlier section or
//! merge it into this one". Each returned `complete_p` is proven by the
//! `#[proof(complete = p)]` item of `p` (its script, with the hypotheses as
//! facts and `p`'s parameters as the item's parameters), else by
//! [`crate::auto::complete::prove`] (refinement, bool split, induction),
//! and added as the lemma `p::complete` whose type is exactly the kernel's
//! statement (`ObligationKind::Completeness`).
//!
//! # Enforcement
//!
//! A section is **fully specified** when every `complete_p` is
//! kernel-checked and it is well founded. Sections are recorded
//! (`Output::sections`: the report, the spec sheet and the `SPEC.lock`
//! entries and header), and the §15.8 gate [`spec15_gate_s3`], which the
//! crate path (`driver::gates`) runs with the other gates, turns every
//! section that is not fully specified into an error. An explicit annotation
//! whose meaning is now defined is checked at once: a failing
//! `#[proof(complete = p)]` script, a proof item for a function with no
//! completeness obligation, and a `#[section(with = [g])]` naming a
//! function determined by its refinement are errors.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use sandblaster_kernel::api::{Section, SectionHyp, SectionView};
use sandblaster_kernel::term::{DefDecl, DefKind, GlobalId, Rel, Term, Tm};
use sandblaster_kernel::util::shift;
use sandblaster_kernel::value::Budget;

use super::{DefRecord, DefStatus, Elab, FnState, Mode, Val};
use crate::diag::{DiagKind, Diagnostic, Diagnostics};
use crate::hir::{Crate, FnDef, FnKind, ItemId, ItemKind, PatKind, ProofKind, Ty};
use crate::prover::{FactOrigin, ObligationKind};
use crate::span::Span;

/// How a section ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SectionStatus {
    /// Every `complete_p` kernel-checked; every dependency fully specified
    /// earlier or trusted.
    FullySpecified,
    /// The statements were built; some `complete_p` is not proven.
    Unproven,
    /// A dependency is not fully specified in an earlier section (the
    /// statements are only relative to it).
    NotWellFounded,
    /// The kernel could not state the section (`abstract_section` error).
    Unstated,
    /// A member or a hypothesis did not verify.
    Blocked,
}

impl SectionStatus {
    pub fn word(&self) -> &'static str {
        match self {
            SectionStatus::FullySpecified => "fully specified",
            SectionStatus::Unproven => "not determined (a completeness statement is unproven)",
            SectionStatus::NotWellFounded => "not well founded (a dependency is not fully specified in an earlier section)",
            SectionStatus::Unstated => "not stated (the kernel rejected the section)",
            SectionStatus::Blocked => "blocked (a member or hypothesis did not verify)",
        }
    }
}

/// One `complete_p(R)`.
#[derive(Clone, Debug)]
pub struct CompleteRecord {
    pub item: ItemId,
    /// The lemma's name (`crate::p::complete`).
    pub name: String,
    /// The kernel statement (exactly `abstract_section`'s term).
    pub statement: Tm,
    /// The statement in core syntax.
    pub text: String,
    /// The statement in surface syntax (a de-elaborated rendering, bounded).
    pub surface: String,
    pub status: DefStatus,
    /// How it was proven: the discharge of `auto`, or the proof item.
    pub proof: String,
    pub lemma: Option<GlobalId>,
    /// What the provers tried (prover internals, for the report).
    pub notes: Vec<String>,
    /// Why it is not proven, for a reader: a claim about the specification
    /// only when no hypothesis constrains the function; otherwise which
    /// attempt failed and how (search failed, budget exhausted, proof
    /// rejected). Empty when proven.
    pub why: String,
    /// The goal `auto`'s discharges got stuck on, in surface syntax: the
    /// conclusion with the real function's application unfolded once.
    pub stuck: Option<String>,
    /// An attempt ran out of its step budget.
    pub exhausted: bool,
}

/// How a dependency is specified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DepHow {
    /// Determined by its `#[refines]`.
    Refines,
    /// Fully specified in the section at this position of ≺.
    Section(usize),
    /// An exec constant (its value is locked on the surface).
    Constant,
    /// A derived `PartialEq` (determined by its type, §7.7).
    Derived,
    /// A function of the lift prelude (`crate::__lift`: core's
    /// definitions transcribed, SEMANTICS.md §19), a trusted primitive of
    /// the toolchain whose definition the lock header pins (§15.5: a
    /// dependency may be "a trusted primitive (prelude, intrinsic model)").
    Prelude,
    /// Fully specified only up to the lossy view of an `Abstract` type (by
    /// its refinement, or in the section at this position of ≺ when it is
    /// `Some`): not accepted as a dependency, since a hypothesis may observe
    /// what the view hides (DESIGN.md §15.5 "obs_eq-respecting positions",
    /// which is not checked: fail closed).
    UpToView(Option<usize>),
    /// Not fully specified in an earlier section.
    Unspecified,
}

/// One computed section `R` (for the report, the spec sheet and the lock).
#[derive(Clone, Debug)]
pub struct SectionRecord {
    /// The members `R` (exec functions not determined by `#[refines]`).
    pub members: Vec<ItemId>,
    /// `P(R)`: the members referenced from outside `R`.
    pub published: Vec<ItemId>,
    /// `Deps(R)`: exec functions its hypotheses mention outside `R`.
    pub deps: Vec<ItemId>,
    /// `complete_p(R)` per published `p`, and how it ended.
    pub complete: Vec<(ItemId, DefStatus)>,
    /// Position in the well-founded order ≺ (dependencies first).
    pub index: usize,
    /// `H(R)`: the hypothesis lemmas, in binder order (kind and name).
    pub hyps: Vec<(String, String)>,
    /// Merged by `#[section(with = ..)]`.
    pub merged: bool,
    pub statements: Vec<CompleteRecord>,
    /// Every exec dependency and how it is specified.
    pub dep_status: Vec<(ItemId, DepHow)>,
    pub status: SectionStatus,
    /// Why the section is not fully specified (readable).
    pub problems: Vec<String>,
    /// The first published member's span.
    pub span: Span,
    /// `#[definitional]` laws that mention a member: not hypotheses.
    pub definitional: Vec<String>,
    /// Where a problem is (a proof slot of a hypothesis that does not
    /// re-check with the section abstracted), with what it needs.
    pub problem_spans: Vec<(Span, String)>,
}

impl SectionRecord {
    pub fn fully_specified(&self) -> bool {
        self.status == SectionStatus::FullySpecified
    }
}

/// The §15 S3 state of an elaboration.
#[derive(Default)]
pub struct S3State {
    pub sections: Vec<SectionRecord>,
}

/// What the section computation reads from the elaboration.
struct Info {
    /// Exec function items with their (checked) globals.
    exec: BTreeMap<ItemId, GlobalId>,
    item_of: HashMap<GlobalId, ItemId>,
    /// Loop helpers, by owner.
    helper_owner: HashMap<GlobalId, ItemId>,
    /// Exec function items without a checked global (failed or deferred).
    failed: BTreeSet<ItemId>,
    /// Every exec and loop-helper global (the stop set of "mentions").
    stop_all: Vec<GlobalId>,
    /// Exec constants (value locked on the surface).
    consts: BTreeMap<GlobalId, ItemId>,
    determined: BTreeSet<ItemId>,
    exported: BTreeSet<ItemId>,
    /// Checked laws: item, global, mentioned exec items.
    laws: Vec<(ItemId, GlobalId, BTreeSet<ItemId>)>,
    /// `#[definitional]` laws: they restate a definition and are never a
    /// guarantee (DESIGN.md §15.1 LR6), so they are no hypothesis of a
    /// section — the functions they mention must still be determined.
    definitional: BTreeSet<ItemId>,
    /// Laws that did not verify, with the exec items their statements
    /// mention (HIR level: directly and through spec function bodies): a
    /// section they mention is blocked (its `H(R)` would be incomplete).
    failed_laws: Vec<(ItemId, BTreeSet<ItemId>)>,
    /// Per exec item: its contract lemmas that did not verify (readable).
    failed_contracts: BTreeMap<ItemId, Vec<String>>,
    /// Per exec item: its contract lemmas (kind, global) and what they mention.
    contract: BTreeMap<ItemId, Vec<(&'static str, GlobalId)>>,
    contract_mentions: BTreeMap<ItemId, BTreeSet<ItemId>>,
    /// Exec items the code of an exec item (body and loop helpers) calls.
    code_mentions: BTreeMap<ItemId, BTreeSet<ItemId>>,
    /// Exec items mentioned by spec definitions of the crate.
    spec_mentions: BTreeSet<ItemId>,
    /// Exec functions of the lift prelude (`crate::__lift::…`): trusted
    /// primitives, never candidates (their definitions are the toolchain's).
    prelude: BTreeSet<ItemId>,
}

impl<'a> Elab<'a> {
    /// Computes and proves the sections of the crate (see the module docs);
    /// run once after every item has been elaborated.
    pub fn sections_hook(&mut self) {
        if !self.s1.on {
            return;
        }
        let krate = self.krate;
        let info = self.section_info();
        let (groups, merged) = self.section_plan(&info);
        // fully specified exec globals so far (the stop set)
        let mut fully: BTreeMap<GlobalId, DepHow> = BTreeMap::new();
        for id in &info.determined {
            if let Some(g) = info.exec.get(id) {
                // established: an identity or injective view (exact)
                let how = if self.s1.established.contains(g) { DepHow::Refines } else { DepHow::UpToView(None) };
                fully.insert(*g, how);
            }
        }
        for g in info.consts.keys() {
            fully.insert(*g, DepHow::Constant);
        }
        for id in &info.prelude {
            if let Some(g) = info.exec.get(id) {
                fully.insert(*g, DepHow::Prelude);
            }
        }
        for e in self.eq_fns.values() {
            fully.insert(e.eq, DepHow::Derived);
        }
        let mut records = Vec::new();
        let trace = std::env::var_os("SANDBLASTER_TRACE_SECTIONS").is_some();
        for (index, members) in groups.iter().enumerate() {
            let t0 = std::time::Instant::now();
            let rec = self.run_section(index, members, merged.contains(&index), &info, &mut fully);
            if trace {
                eprintln!("section #{index} {{{}}}: {} in {:?}", members.iter().map(|m| krate.item(*m).path.to_string()).collect::<Vec<_>>().join(", "), rec.status.word(), t0.elapsed());
                for p in &rec.problems {
                    eprintln!("    {p}");
                }
            }
            records.push(rec);
        }
        // explicit proof items for functions with no completeness obligation
        let published: BTreeSet<ItemId> = records.iter().flat_map(|r| r.statements.iter().map(|s| s.item)).collect();
        for it in &krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            let Some(p) = f.spec.proof_of.filter(|p| p.kind == ProofKind::Complete) else { continue };
            if published.contains(&p.target) {
                continue;
            }
            let target = krate.item(p.target).path.to_string();
            let why = if info.determined.contains(&p.target) {
                format!("`{target}` is determined by its `#[refines]` (§15.2): it has no completeness obligation")
            } else if records.iter().any(|r| r.members.contains(&p.target)) {
                format!("`{target}` is not published by its section (nothing outside the section refers to it), so it has no statement of its own")
            } else if info.exec.contains_key(&p.target) {
                format!("`{target}` needs no determinacy proof: it is not exported, and no law or exported contract mentions it (§15.5)")
            } else {
                format!("`{target}` did not verify, so its section could not be stated")
            };
            self.diag(Diagnostic::error(DiagKind::Completeness, p.span, format!("`#[proof(complete = {target})]` (`{}`) proves nothing: {why}", it.path)).note("remove the proof item, or make the function part of a section (DESIGN.md §15.5)"));
        }
        self.s3.sections = records;
    }

    /// Precomputes what the section computation needs.
    fn section_info(&mut self) -> Info {
        let krate = self.krate;
        let env = &self.env;
        let mut exec = BTreeMap::new();
        let mut item_of = HashMap::new();
        let mut failed = BTreeSet::new();
        let mut consts = BTreeMap::new();
        for it in &krate.items {
            match &it.kind {
                ItemKind::Fn(f) if f.kind == FnKind::Exec => match self.globals.get(&it.id) {
                    Some(super::ItemGlobal::Def(g)) if !self.s1.placeholders.contains_key(g) => {
                        exec.insert(it.id, *g);
                        item_of.insert(*g, it.id);
                    }
                    _ => {
                        failed.insert(it.id);
                    }
                },
                ItemKind::Const(_) if !it.ghost => {
                    if let Some(super::ItemGlobal::Def(g)) = self.globals.get(&it.id) {
                        consts.insert(*g, it.id);
                    }
                }
                _ => {}
            }
        }
        // loop helpers: named `<fn path>::loop#k…`
        let mut helper_owner = HashMap::new();
        let mut stop_all = Vec::new();
        let by_name: HashMap<String, ItemId> = exec.keys().map(|id| (krate.item(*id).path.to_string(), *id)).collect();
        for gi in 0..env.num_globals() {
            let g = GlobalId(gi);
            match env.global_kind(g) {
                Some(DefKind::Exec) => stop_all.push(g),
                Some(DefKind::LoopHelper) => {
                    stop_all.push(g);
                    if let Some(n) = env.global_name(g)
                        && let Some((owner, _)) = n.split_once("::loop#")
                        && let Some(id) = by_name.get(owner)
                    {
                        helper_owner.insert(g, *id);
                    }
                }
                _ => {}
            }
        }
        let owner_of = |g: GlobalId| item_of.get(&g).or_else(|| helper_owner.get(&g)).copied();
        let mentions = |t: &Tm| -> BTreeSet<ItemId> { env.refs_closure(t, &stop_all).into_iter().filter_map(owner_of).collect() };
        // determined by refinement (S1/S2 verdicts)
        let determined: BTreeSet<ItemId> = self.s1.refinements.iter().filter(|r| r.status == DefStatus::Checked && r.up_to.is_none() && r.lemma.is_some()).map(|r| r.item).filter(|id| exec.contains_key(id)).collect();
        // every host-callable function (not only the law vocabulary of
        // `exported_functions`): a `pub` method of a type that an exported
        // function returns is callable whether or not the type is exported
        let exported: BTreeSet<ItemId> = crate::validate::boundary_functions(krate).into_iter().filter(|id| krate.fn_def(*id).is_some_and(|f| f.kind == FnKind::Exec)).collect();
        // checked laws
        let mut laws = Vec::new();
        for d in &self.defs {
            if d.kind == DefKind::Law && d.status == DefStatus::Checked
                && let (Some(item), Some(g)) = (d.item, d.global)
                && let Some(ty) = env.global_type(g)
            {
                laws.push((item, g, mentions(&ty)));
            }
        }
        let definitional: BTreeSet<ItemId> = laws.iter().map(|(i, _, _)| *i).filter(|i| krate.fn_def(*i).is_some_and(|f| f.spec.definitional.is_some())).collect();
        // laws that did not verify: what their statements mention
        let mut failed_laws = Vec::new();
        for it in &krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            if f.kind != FnKind::Law || laws.iter().any(|(i, _, _)| *i == it.id) {
                continue;
            }
            let mut exprs: Vec<&crate::hir::Expr> = f.requires.iter().collect();
            if let Some(en) = &f.ensures {
                exprs.push(&en.prop);
            }
            failed_laws.push((it.id, hir_exec_mentions(krate, &exprs)));
        }
        // contracts: `f::ensures`, `f::refines` (not determining), invariant lemmas
        let mut contract: BTreeMap<ItemId, Vec<(&'static str, GlobalId)>> = BTreeMap::new();
        let mut contract_mentions: BTreeMap<ItemId, BTreeSet<ItemId>> = BTreeMap::new();
        let mut failed_contracts: BTreeMap<ItemId, Vec<String>> = BTreeMap::new();
        for &id in exec.keys() {
            let path = krate.item(id).path.to_string();
            let mut cs: Vec<(&'static str, GlobalId)> = Vec::new();
            if krate.fn_def(id).is_some_and(|f| f.ensures.is_some()) {
                match env.lookup_global(&format!("{path}::ensures")) {
                    Some(g) if self.defs.iter().any(|d| d.global == Some(g) && d.status == DefStatus::Checked) => cs.push(("ensures", g)),
                    _ => failed_contracts.entry(id).or_default().push(format!("the `#[ensures]` of `{path}` did not verify")),
                }
            }
            match self.s1.refinements.iter().find(|r| r.item == id && r.status == DefStatus::Checked) {
                Some(r) => {
                    if let Some(g) = r.lemma {
                        cs.push(("refines", g));
                    }
                }
                None if krate.fn_def(id).is_some_and(|f| f.spec.refines.is_some()) => failed_contracts.entry(id).or_default().push(format!("the `#[refines]` of `{path}` did not verify")),
                None => {}
            }
            if let Some(f) = krate.fn_def(id) {
                let mut tys: BTreeSet<ItemId> = BTreeSet::new();
                for t in f.params.iter().map(|p| &p.ty).chain(std::iter::once(&f.ret)) {
                    struct_ids(t, &mut tys);
                }
                for s in tys {
                    let n = self.s1.s2.invariants.get(&s).map(|v| v.len()).unwrap_or(0);
                    let spath = krate.item(s).path.to_string();
                    for kk in 0..n {
                        if let Some(g) = env.lookup_global(&format!("{spath}::inv#{kk}")) {
                            cs.push(("invariant", g));
                        }
                    }
                }
            }
            let mut ms = BTreeSet::new();
            for (_, g) in &cs {
                if let Some(ty) = env.global_type(*g) {
                    ms.extend(mentions(&ty));
                }
            }
            ms.remove(&id);
            contract_mentions.insert(id, ms);
            contract.insert(id, cs);
        }
        // the code of each exec item (its body and its loop helpers)
        let mut code_mentions: BTreeMap<ItemId, BTreeSet<ItemId>> = BTreeMap::new();
        for &g in &stop_all {
            let Some(o) = owner_of(g) else { continue };
            if let Some(body) = env.global_body(g) {
                let mut ms = mentions(&body);
                ms.remove(&o);
                code_mentions.entry(o).or_default().extend(ms);
            }
        }
        // spec definitions of the crate (bodies and types), and the checked
        // examples (surface items: an exec function they name is referred
        // to from outside any section)
        let mut spec_mentions = BTreeSet::new();
        for ex in &self.s1.examples {
            if let Some(t) = &ex.term {
                spec_mentions.extend(mentions(t));
            }
        }
        for it in &krate.items {
            if let ItemKind::Fn(f) = &it.kind
                && f.kind == FnKind::Spec
                && let Some(super::ItemGlobal::Def(g)) = self.globals.get(&it.id)
            {
                for t in [env.global_body(*g), env.global_type(*g)].into_iter().flatten() {
                    spec_mentions.extend(mentions(&t));
                }
            }
        }
        let prelude: BTreeSet<ItemId> = exec.keys().copied().filter(|id| krate.item(*id).path.to_string().starts_with("crate::__lift::")).collect();
        Info { exec, item_of, helper_owner, failed, stop_all, consts, determined, exported, laws, definitional, failed_laws, failed_contracts, contract, contract_mentions, code_mentions, spec_mentions, prelude }
    }

    /// The candidates, the graph, the merges and its SCCs in ≺ (see the
    /// module docs). Returns the sections' members and the indices of the
    /// sections a `#[section(with = ..)]` merged.
    fn section_plan(&mut self, info: &Info) -> (Vec<Vec<ItemId>>, BTreeSet<usize>) {
        let krate = self.krate;
        // seeds: exported functions, law mentions, exported contracts
        let mut cand: BTreeSet<ItemId> = info.exported.clone();
        for (_, _, ms) in &info.laws {
            cand.extend(ms.iter().copied());
        }
        // a law that did not verify still names what must be determined
        for (_, ms) in &info.failed_laws {
            cand.extend(ms.iter().copied().filter(|m| info.exec.contains_key(m) || info.failed.contains(m)));
        }
        for id in &info.exported {
            if let Some(ms) = info.contract_mentions.get(id) {
                cand.extend(ms.iter().copied());
            }
        }
        // `#[section(with = ..)]`: merge only (checked here)
        let mut merges: Vec<(ItemId, ItemId)> = Vec::new();
        for it in &krate.items {
            let ItemKind::Fn(f) = &it.kind else { continue };
            for (g, sp) in &f.spec.section_with {
                let (fp, gp) = (it.path.to_string(), krate.item(*g).path.to_string());
                for (x, xp) in [(it.id, &fp), (*g, &gp)] {
                    if info.determined.contains(&x) {
                        self.diag(
                            Diagnostic::error(DiagKind::Section, *sp, format!("`#[section(with = ..)]` on `{fp}` names `{xp}`, which is determined by its `#[refines]` and belongs to no section"))
                                .note("a function determined by its refinement is fully specified by itself (DESIGN.md §15.2); remove it from the list"),
                        );
                    }
                }
                if info.determined.contains(&it.id) || info.determined.contains(g) {
                    continue;
                }
                cand.insert(it.id);
                cand.insert(*g);
                merges.push((it.id, *g));
            }
        }
        // close under the hypotheses of the (undetermined) candidates
        let mut work: Vec<ItemId> = cand.iter().copied().collect();
        while let Some(f) = work.pop() {
            if info.determined.contains(&f) || info.prelude.contains(&f) {
                continue;
            }
            for g in self.hyp_mentions(info, f) {
                if cand.insert(g) {
                    work.push(g);
                }
            }
        }
        let cand: BTreeSet<ItemId> = cand.into_iter().filter(|id| !info.determined.contains(id) && !info.prelude.contains(id)).collect();
        // union-find of the merges
        let mut parent: BTreeMap<ItemId, ItemId> = cand.iter().map(|c| (*c, *c)).collect();
        fn find(p: &mut BTreeMap<ItemId, ItemId>, x: ItemId) -> ItemId {
            let mut r = x;
            while p[&r] != r {
                r = p[&r];
            }
            let mut y = x;
            while p[&y] != r {
                let n = p[&y];
                p.insert(y, r);
                y = n;
            }
            r
        }
        let mut merged_roots = BTreeSet::new();
        for (a, b) in merges {
            if !(parent.contains_key(&a) && parent.contains_key(&b)) {
                continue;
            }
            let (ra, rb) = (find(&mut parent, a), find(&mut parent, b));
            let (lo, hi) = if ra < rb { (ra, rb) } else { (rb, ra) };
            parent.insert(hi, lo);
            merged_roots.insert(lo);
        }
        let root_of: BTreeMap<ItemId, ItemId> = cand.iter().map(|c| (*c, find(&mut parent, *c))).collect();
        let mut group: BTreeMap<ItemId, Vec<ItemId>> = BTreeMap::new();
        for (c, r) in &root_of {
            group.entry(*r).or_default().push(*c);
        }
        let merged_groups: BTreeSet<ItemId> = merged_roots.iter().map(|r| root_of[r]).collect();
        // edges between groups
        let mut edges: BTreeMap<ItemId, BTreeSet<ItemId>> = BTreeMap::new();
        for (r, ms) in &group {
            let e = edges.entry(*r).or_default();
            for m in ms {
                for g in self.hyp_mentions(info, *m) {
                    if let Some(rg) = root_of.get(&g)
                        && rg != r
                    {
                        e.insert(*rg);
                    }
                }
            }
        }
        // Tarjan: SCCs emitted after every SCC they reach (dependencies first)
        let nodes: Vec<ItemId> = group.keys().copied().collect();
        let sccs = tarjan(&nodes, &edges);
        let mut out = Vec::new();
        let mut merged = BTreeSet::new();
        for scc in sccs {
            let mut members: Vec<ItemId> = scc.iter().flat_map(|r| group[r].iter().copied()).collect();
            members.sort();
            if scc.iter().any(|r| merged_groups.contains(r)) {
                merged.insert(out.len());
            }
            out.push(members);
        }
        (out, merged)
    }

    /// The exec items the hypotheses of `f` mention (laws naming `f`, and
    /// its contract), other than `f`. A `#[definitional]` law is no
    /// hypothesis.
    fn hyp_mentions(&self, info: &Info, f: ItemId) -> BTreeSet<ItemId> {
        let mut out = BTreeSet::new();
        for (l, _, ms) in &info.laws {
            if info.definitional.contains(l) {
                continue;
            }
            if ms.contains(&f) {
                out.extend(ms.iter().copied());
            }
        }
        if let Some(ms) = info.contract_mentions.get(&f) {
            out.extend(ms.iter().copied());
        }
        out.remove(&f);
        out
    }

    /// States, checks and proves one section.
    fn run_section(&mut self, index: usize, members: &[ItemId], merged: bool, info: &Info, fully: &mut BTreeMap<GlobalId, DepHow>) -> SectionRecord {
        let krate = self.krate;
        let rset: BTreeSet<ItemId> = members.iter().copied().collect();
        let path = |id: ItemId| krate.item(id).path.to_string();
        // P(R)
        let mut published: BTreeSet<ItemId> = if members.len() == 1 {
            rset.clone()
        } else {
            members
                .iter()
                .copied()
                .filter(|m| {
                    info.exported.contains(m)
                        || info.spec_mentions.contains(m)
                        || info.laws.iter().any(|(_, _, ms)| ms.contains(m))
                        // a contract is on the surface: one of a member of
                        // `R` refers to the other member from outside it
                        // (`#[section(with)]` merges only, never unpublishes)
                        || info.contract_mentions.values().any(|ms| ms.contains(m))
                        || info.code_mentions.iter().any(|(g, ms)| !rset.contains(g) && ms.contains(m))
                })
                .collect()
        };
        if published.is_empty() {
            published = rset.clone();
        }
        // members in the requires of a published member
        loop {
            let mut more = Vec::new();
            for p in &published {
                let Some(g) = info.exec.get(p) else { continue };
                let Some(ty) = self.env.global_type(*g) else { continue };
                for (_, rel, dom) in crate::auto::complete::telescope(&ty).0 {
                    if rel != Rel::Irr {
                        continue;
                    }
                    for x in self.env.refs_closure(&dom, &info.stop_all) {
                        if let Some(id) = info.item_of.get(&x)
                            && rset.contains(id)
                            && !published.contains(id)
                        {
                            more.push(*id);
                        }
                    }
                }
            }
            if more.is_empty() {
                break;
            }
            published.extend(more);
        }
        let published: Vec<ItemId> = published.into_iter().collect();
        let span = published.first().map(|p| krate.item(*p).span).unwrap_or(Span::DUMMY);
        let mut rec = SectionRecord {
            members: members.to_vec(),
            published: published.clone(),
            deps: vec![],
            complete: vec![],
            index,
            hyps: vec![],
            merged,
            statements: vec![],
            dep_status: vec![],
            status: SectionStatus::Unproven,
            problems: vec![],
            span,
            definitional: vec![],
            problem_spans: vec![],
        };
        // a member that did not verify blocks the section, and so does a
        // hypothesis that did not verify (a law naming a member, a
        // member's contract): without it `H(R)` would be incomplete
        let blocked: Vec<ItemId> = members.iter().copied().filter(|m| info.failed.contains(m)).collect();
        let mut hyp_problems: Vec<String> = Vec::new();
        for (l, ms) in &info.failed_laws {
            let named: Vec<String> = ms.iter().filter(|m| rset.contains(m)).map(|m| format!("`{}`", path(*m))).collect();
            if !named.is_empty() {
                hyp_problems.push(format!("the law `{}` mentions {} but did not verify (see its error): `H(R)` is incomplete without it", path(*l), named.join(", ")));
            }
        }
        for m in members {
            for why in info.failed_contracts.get(m).into_iter().flatten() {
                hyp_problems.push(format!("{why} (see its error): `H(R)` is incomplete without it"));
            }
        }
        if !blocked.is_empty() || !hyp_problems.is_empty() {
            rec.status = SectionStatus::Blocked;
            rec.problems = blocked.iter().map(|b| if self.hw_items.contains(b) { format!("`{}` is a hardware function whose core model is deferred (§9.2)", path(*b)) } else { format!("`{}` did not verify", path(*b)) }).collect();
            rec.problems.extend(hyp_problems);
            let why = if blocked.is_empty() { "a hypothesis did not verify" } else { "a member did not verify" };
            rec.complete = published.iter().map(|p| (*p, DefStatus::Blocked(why.into()))).collect();
            return rec;
        }
        // H(R): laws (item order), then per member ensures, refines, invariants
        let mut hyps: Vec<(String, GlobalId, String)> = Vec::new();
        let mut seen = BTreeSet::new();
        let mut definitional: Vec<String> = Vec::new();
        for (item, g, ms) in &info.laws {
            if !ms.iter().any(|m| rset.contains(m)) {
                continue;
            }
            // a definitional law restates a definition: never a hypothesis
            if info.definitional.contains(item) {
                definitional.push(path(*item));
                continue;
            }
            if seen.insert(*g) {
                hyps.push(("law".into(), *g, path(*item)));
            }
        }
        for m in members {
            for (kind, g) in info.contract.get(m).into_iter().flatten() {
                if seen.insert(*g) {
                    let n = self.env.global_name(*g).map(|n| n.to_string()).unwrap_or_default();
                    hyps.push((kind.to_string(), *g, n));
                }
            }
        }
        rec.hyps = hyps.iter().map(|(k, _, n)| (k.clone(), n.clone())).collect();
        rec.definitional = definitional;
        let mglobals: Vec<GlobalId> = members.iter().map(|m| info.exec[m]).collect();
        let pglobals: Vec<GlobalId> = published.iter().map(|p| info.exec[p]).collect();
        let mut shyps: Vec<SectionHyp> = hyps.iter().map(|(_, g, _)| SectionHyp { lemma: *g, restated: None }).collect();
        let views = self.section_views(&published);
        let established: Vec<GlobalId> = fully.keys().copied().collect();
        // abstractability (DESIGN.md §15.5): a law whose proof slots do not
        // re-check with the section abstracted is re-elaborated with the
        // members abstracted and the earlier hypotheses as facts (its slots
        // re-proven by `auto`), and handed to the kernel as a restatement
        let mut restated: BTreeSet<usize> = BTreeSet::new();
        let st = loop {
            let mut b = Budget { steps: self.opts.def_budget };
            let st = self.env.abstract_section(&Section { members: &mglobals, published: &pglobals, hyps: &shyps, views: &views, established: &established }, &mut b);
            let e = match st {
                Ok(st) => break st,
                Err(e) => e,
            };
            let slot_failure = abstractability_failure(&e.message).filter(|i| !restated.contains(i));
            let mut located: Option<Vec<(Span, String)>> = None;
            if let Some(i) = slot_failure
                && hyps[i].0 == "law"
                && let Some(law) = info.laws.iter().find(|(_, g, _)| *g == hyps[i].1).map(|(l, _, _)| *l)
            {
                restated.insert(i);
                match self.restate_law(law, i, &shyps, &mglobals, &pglobals, &views, &established, info) {
                    Ok(t) => {
                        shyps[i].restated = Some(t);
                        continue;
                    }
                    Err(slots) => located = Some(slots),
                }
            }
            rec.status = SectionStatus::Unstated;
            rec.problems.push(self.unstated_problem(&e.message, &hyps, info, &rset, located.as_deref()));
            if let Some(slots) = located {
                rec.problem_spans.extend(slots);
            }
            rec.complete = published.iter().map(|p| (*p, DefStatus::Unsupported("the section could not be stated".into()))).collect();
            self.complete_items_unstated(&rec);
            return rec;
        };

        // Deps(R) and well-foundedness
        let mut unspecified = Vec::new();
        let mut up_to_view = Vec::new();
        let mut failed_deps = false;
        let mut deps = BTreeSet::new();
        for g in &st.deps {
            let owner = info.item_of.get(g).copied().or_else(|| info.helper_owner.get(g).copied());
            match self.env.global_kind(*g) {
                Some(DefKind::Exec) | Some(DefKind::LoopHelper) => {
                    if let Some(c) = info.consts.get(g) {
                        deps.insert(*c);
                        rec.dep_status.push((*c, DepHow::Constant));
                        continue;
                    }
                    // a derived `PartialEq`: determined by its type
                    if fully.get(g) == Some(&DepHow::Derived) {
                        continue;
                    }
                    let Some(o) = owner else {
                        // an exec global of no verified function: a
                        // placeholder of a definition that did not verify
                        let n = self.env.global_name(*g).map(|n| n.to_string()).unwrap_or_default();
                        rec.problems.push(format!("depends on `{n}`, which did not verify"));
                        failed_deps = true;
                        continue;
                    };
                    if !deps.insert(o) {
                        continue;
                    }
                    match info.exec.get(&o).and_then(|og| fully.get(og)) {
                        Some(DepHow::UpToView(k)) => {
                            rec.dep_status.push((o, DepHow::UpToView(*k)));
                            up_to_view.push(o);
                        }
                        Some(how) => rec.dep_status.push((o, how.clone())),
                        None => {
                            rec.dep_status.push((o, DepHow::Unspecified));
                            unspecified.push(o);
                        }
                    }
                }
                _ => {}
            }
        }
        rec.deps = deps.into_iter().collect();
        for u in &unspecified {
            let why = if info.determined.contains(u) {
                "its refinement does not determine it".to_string()
            } else if self.s3.sections.iter().any(|s| s.members.contains(u)) {
                "its section is not fully specified".to_string()
            } else {
                "it is in no fully specified section (no law, refinement or contract determines it)".to_string()
            };
            rec.problems.push(format!("depends on `{}`, which is not fully specified in an earlier section: {why}", path(*u)));
        }
        for u in &up_to_view {
            rec.problems.push(format!(
                "depends on `{}`, which is fully specified only up to the lossy view of an `Abstract` type: a hypothesis may observe what the view hides (DESIGN.md §15.5 requires dependencies in `obs_eq`-respecting positions, which is not checked here) — give it an injective view or state the hypothesis over its specification",
                path(*u)
            ));
        }
        let unspecified: Vec<ItemId> = unspecified.into_iter().chain(up_to_view).collect();
        // prove each complete_p
        let mut all = true;
        for (j, p) in published.iter().enumerate() {
            let stmt = st.statements[j].clone();
            let member_p = st.members.iter().position(|g| *g == info.exec[p]).unwrap_or(0);
            let lay = crate::auto::complete::Layout { members: st.members.len(), member_p, real: hyps.iter().map(|(_, g, _)| *g).collect() };
            let member_items: Vec<ItemId> = st.members.iter().filter_map(|g| info.item_of.get(g).copied()).collect();
            let c = self.prove_complete(*p, &stmt, &lay, &member_items, info);
            if c.status != DefStatus::Checked {
                all = false;
            }
            rec.complete.push((*p, c.status.clone()));
            rec.statements.push(c);
        }
        rec.status = if !all {
            for c in &rec.statements {
                if c.status != DefStatus::Checked {
                    rec.problems.push(format!("`complete_{}` is not proven: {}", path(c.item), c.why));
                }
            }
            SectionStatus::Unproven
        } else if !unspecified.is_empty() || failed_deps {
            SectionStatus::NotWellFounded
        } else {
            SectionStatus::FullySpecified
        };
        // twins: no member is determined, the laws only relate them
        if members.len() > 1 && rec.status == SectionStatus::Unproven && !rec.statements.iter().any(|c| c.status == DefStatus::Checked) {
            rec.problems.push(format!(
                "no member of {} is proven determined: if the hypotheses only relate the members to each other, they are constrained only jointly, and a section is determined relative to earlier sections, never to itself (DESIGN.md §15.5: from `f(x) == g(x)` alone neither is determined)",
                members.iter().map(|m| format!("`{}`", path(*m))).collect::<Vec<_>>().join(", ")
            ));
        }
        if rec.status != SectionStatus::FullySpecified {
            for d in &rec.definitional {
                rec.problems.push(format!("the law `{d}` mentions the section but is `#[definitional]`: it restates a definition, is never a guarantee (DESIGN.md §15.1 LR6) and is not a hypothesis — state what the function guarantees in terms of `spec::` items"));
            }
        }
        if rec.status == SectionStatus::FullySpecified {
            // determined through a lossy view: only up to it. Only the
            // published members are determined (their `complete_p` are
            // proven); the others only relative to them
            let how = if views.is_empty() { DepHow::Section(index) } else { DepHow::UpToView(Some(index)) };
            for p in &published {
                fully.insert(info.exec[p], how.clone());
            }
        }
        rec
    }

    /// The views `obs_eq` goes through (DESIGN.md §15.5): the lossy views of
    /// `Abstract` types in the published functions' results (an injective
    /// view is equivalent to equality, which is what is stated).
    fn section_views(&mut self, published: &[ItemId]) -> Vec<SectionView> {
        let krate = self.krate;
        let mut tys = BTreeSet::new();
        for p in published {
            if let Some(f) = krate.fn_def(*p) {
                struct_ids(&f.ret, &mut tys);
            }
        }
        let mut out = Vec::new();
        for s in tys {
            let Some(v) = self.s1.views.get(&s).cloned() else { continue };
            let inj = v.injective || matches!(self.s1.s2.view_inj.get(&s), Some(Ok(_)));
            if inj || !crate::validate::abstract_reasons(krate, s, false).is_empty() {
                continue;
            }
            let generic = matches!(&krate.item(s).kind, ItemKind::Struct(sd) if !sd.generics.is_empty());
            if generic {
                continue;
            }
            let (Ok(ind), Ok(target)) = (self.adt(s, Span::DUMMY), self.ty_at(&v.target, 0, Span::DUMMY)) else { continue };
            out.push(SectionView { ty: sandblaster_kernel::util::mk::ind(ind, vec![]), target, map: sandblaster_kernel::util::mk::global(v.global) });
        }
        out
    }

    /// Re-elaborates the statement of law `law` (hypothesis `i`) with the
    /// section abstracted: the members are the `F'` binders (a call of a
    /// member denotes `F'`, as in a `#[proof(complete = p)]` script) and
    /// the earlier hypotheses `h₀..hᵢ₋₁` are facts, so `auto` re-proves its
    /// proof slots from them (DESIGN.md §15.5 "re-elaborated with `R`
    /// abstracted", "re-proves the proof slots of re-elaborated laws with
    /// auto"). The binders come from the kernel's own abstraction of the
    /// section with the hypotheses before `i`. Returns the statement (a
    /// term in the context of the `F'` binders and `h₀..hᵢ₋₁`), or the
    /// proof slots that still fail: their spans and what each needs, in
    /// surface syntax. Nothing it elaborates is recorded; the kernel checks
    /// the restatement against its own abstraction.
    #[allow(clippy::too_many_arguments)]
    fn restate_law(&mut self, law: ItemId, i: usize, shyps: &[SectionHyp], mglobals: &[GlobalId], pglobals: &[GlobalId], views: &[SectionView], established: &[GlobalId], info: &Info) -> Result<Tm, Vec<(Span, String)>> {
        let krate = self.krate;
        let it = krate.item(law);
        let Some(f): Option<&'a FnDef> = krate.fn_def(law) else { return Err(vec![]) };
        if !f.generics.is_empty() {
            return Err(vec![]);
        }
        let mut b = Budget { steps: self.opts.def_budget };
        let Ok(prefix) = self.env.abstract_section(&Section { members: mglobals, published: pglobals, hyps: &shyps[..i], views, established }, &mut b) else { return Err(vec![]) };
        let Some(first) = prefix.statements.first() else { return Err(vec![]) };
        let (bs, _) = crate::auto::complete::telescope(first);
        let k = prefix.members.len();
        if bs.len() < k + i {
            return Err(vec![]);
        }
        let members: Vec<ItemId> = prefix.members.iter().filter_map(|g| info.item_of.get(g).copied()).collect();
        let span = it.span;
        let (n_obl, n_diag, n_defs, n_laws) = (self.obligations.len(), self.diags.list.len(), self.defs.len(), self.laws.len());
        let saved = std::mem::replace(&mut self.f, FnState::new(format!("{}::restated", it.path), Some(law), &f.locals, span));
        self.f.mode = Mode::Proof;
        self.f.fdef = Some(f);
        self.f.slot_failures = Some(Vec::new());
        let r = (|| -> super::R<Tm> {
            for (j, (n, rel, dom)) in bs[..k + i].iter().enumerate() {
                if j < k {
                    let lvl = self.push(n, *rel, dom, None)?;
                    if let Some(m) = members.get(j) {
                        self.f.abstracted.insert(*m, (lvl, dom.clone()));
                    }
                } else {
                    self.push_fact_rel(n, *rel, dom, None, FactOrigin::LemmaHyp, span)?;
                }
            }
            let base = self.depth();
            let (mut binders, _pending) = self.fn_params(f, span)?;
            // the earlier hypotheses instantiated at the law's parameters
            // (like the completeness discharges): hints of every proof slot,
            // never binders of the statement
            let params: Vec<u32> = (0..f.params.len() as u32).map(|j| base + j).collect();
            for j in 0..i {
                let lvl = (k + j) as u32;
                let hty = shift(&bs[k + j].2, (self.depth() - lvl) as i64);
                if let Some((t, ity)) = self.instantiate_at(self.f.scope.var(lvl), &hty, &params) {
                    let d = self.depth();
                    self.f.scope.hint_facts.push(super::scope::HintFact { ty: Val::new(ity, d), proof: Val::new(t, d), name: "h_hyp", origin: FactOrigin::LemmaHyp });
                }
            }
            self.fn_requires(f, &mut binders, Rel::Rel)?;
            let goal = match &f.ensures {
                Some(en) => self.prop(&en.prop)?,
                None => sandblaster_kernel::util::mk::ind(self.p.unit, vec![]),
            };
            Ok(super::items::pi_tele(&binders, goal))
        })();
        let failures = self.f.slot_failures.take().unwrap_or_default();
        let failed = self.f.failed;
        if std::env::var_os("SANDBLASTER_TRACE_SECTIONS").is_some() {
            for d in &self.diags.list[n_diag..] {
                eprintln!("  restating `{}`: {} {:?}", it.path, d.msg, d.notes);
            }
        }
        self.f = saved;
        self.obligations.truncate(n_obl);
        self.diags.list.truncate(n_diag);
        self.defs.truncate(n_defs);
        self.laws.truncate(n_laws);
        match r {
            Ok(t) if !failed => Ok(t),
            Ok(_) => Err(failures.into_iter().map(|(sp, kind, goal)| (sp, format!("this {} proof slot of `{}` needs `{goal}`, which does not follow from the earlier hypotheses with the section abstracted", super::obl::kind_name(&kind), it.path))).collect()),
            Err(e) => Err(vec![(e.span, format!("`{}` could not be re-elaborated with the section abstracted: {}", it.path, e.msg))]),
        }
    }

    /// A readable account of an `abstract_section` error (`slots`: the
    /// proof slots of a restated law that still fail, located).
    fn unstated_problem(&self, msg: &str, hyps: &[(String, GlobalId, String)], info: &Info, rset: &BTreeSet<ItemId>, slots: Option<&[(Span, String)]>) -> String {
        let krate = self.krate;
        let names = |ids: &BTreeSet<ItemId>| ids.iter().map(|i| format!("`{}`", krate.item(*i).path)).collect::<Vec<_>>().join(", ");
        if let Some(pos) = msg.find("reaches the section but is not a spec definition") {
            // "`g` (Kind) reaches the section …"
            let head = &msg[..pos];
            let g = head.rsplit('`').nth(1).unwrap_or("?");
            return format!(
                "`{g}` reaches this section ({}) through its body but is outside it: establish it in an earlier section (a determining `#[refines]`, or laws that determine it) or merge it into this one (`#[section(with = [{g}])]`) — an exec function outside the section is not a specification of its members (kernel: {})",
                names(rset),
                first_line(msg)
            );
        }
        if msg.contains("is recursive and reaches the section") {
            return format!("{} — state the hypothesis without the recursive spec function, or add the function it reaches to the section", first_line(msg));
        }
        if msg.contains("the restatement differs")
            && let Some((kind, _, name)) = hypothesis_index(msg).and_then(|i| hyps.get(i))
        {
            return format!(
                "the {kind} `{name}` does not re-check with the section abstracted (abstractability, DESIGN.md §15.5), and its re-elaboration with the section abstracted is not the kernel's abstraction of its statement (a spec function in it that reaches the section is inlined by the kernel); state the fact its proof slot needs as a `requires` of the law, or as a law placed before it (kernel: {})",
                first_line(msg)
            );
        }
        if let Some(i) = abstractability_failure(msg)
            && let Some((kind, _, name)) = hyps.get(i)
        {
            let earlier = if i == 0 { "the earlier hypotheses (none: it comes first)".to_string() } else { format!("the earlier hypotheses ({})", hyps[..i].iter().map(|(_, _, n)| format!("`{n}`")).collect::<Vec<_>>().join(", ")) };
            return match slots {
                Some(s) if !s.is_empty() => format!(
                    "the {kind} `{name}` does not re-check with the section abstracted (abstractability, DESIGN.md §15.5): {} of its proof slots, proven by unfolding a member, cannot be re-proven from {earlier} (each is located below with the proposition it needs); state that proposition as a `requires` of the law, or as a law placed before it",
                    s.len()
                ),
                _ if kind == "law" => format!(
                    "the {kind} `{name}` does not re-check with the section abstracted (abstractability, DESIGN.md §15.5): a proof slot of its statement was proven by unfolding a member, and its re-elaboration from {earlier} was not accepted; state the fact the slot needs as a `requires` of the law, or as a law placed before it (kernel: {})",
                    first_line(msg)
                ),
                _ => format!(
                    "the {kind} `{name}` does not re-check with the section abstracted (abstractability, DESIGN.md §15.5): a proof slot of its statement was proven by unfolding a member of the section, and only laws are re-elaborated with the section abstracted; restate it so that no proof slot needs the definition of a member (kernel: {})",
                    first_line(msg)
                ),
            };
        }
        let _ = info;
        format!("the kernel could not state the section: {}", first_line(msg))
    }

    /// A `#[proof(complete = p)]` for a member of a section the kernel
    /// could not state is an error now (it proves nothing).
    fn complete_items_unstated(&mut self, rec: &SectionRecord) {
        let krate = self.krate;
        for p in &rec.published {
            if let Some(pid) = krate.fn_def(*p).and_then(|f| f.spec.complete_proof) {
                let span = krate.item(pid).span;
                self.diag(Diagnostic::error(DiagKind::Completeness, span, format!("`complete_{}` could not be stated, so `{}` proves nothing", krate.item(*p).path, krate.item(pid).path)).note(rec.problems.join("; ")));
            }
        }
    }

    /// Proves one `complete_p`: the proof item's script, else `auto`.
    fn prove_complete(&mut self, p: ItemId, stmt: &Tm, lay: &crate::auto::complete::Layout, members: &[ItemId], info: &Info) -> CompleteRecord {
        let krate = self.krate;
        let it = krate.item(p);
        let name = format!("{}::complete", it.path);
        let text = sandblaster_kernel::syntax::printer::print_term_bounded(&self.env, &[], stmt, 16_000);
        let surface = {
            let s = render_statement(&self.env, stmt);
            if s.chars().count() > 4000 { format!("{}…", s.chars().take(4000).collect::<String>()) } else { s }
        };
        let mut rec = CompleteRecord { item: p, name: name.clone(), statement: stmt.clone(), text, surface, status: DefStatus::Unproven, proof: String::new(), lemma: None, notes: vec![], why: String::new(), stuck: None, exhausted: false };
        let proof_item = krate.fn_def(p).and_then(|f| f.spec.complete_proof);
        let suggest = format!("if the hypotheses do determine `{}`, prove it with `#[proof(complete = {})]` in PROOF.rs", it.path, it.path);
        let (body, recursion, arity) = match proof_item {
            Some(pid) => {
                rec.proof = krate.item(pid).path.to_string();
                match self.complete_script(pid, p, stmt, lay, members) {
                    Ok(body) => (body, sandblaster_kernel::term::Recursion::None, 0),
                    Err(why) => {
                        rec.why = format!("its proof item `{}` does not prove it: {}", krate.item(pid).path, first_line(&why));
                        rec.notes.push(why);
                        return rec;
                    }
                }
            }
            None if !constrains(stmt, lay) => {
                // no hypothesis mentions `F_p'`: every function of its type
                // satisfies them, so `complete_p` cannot hold (the result
                // type has two values) — not attempted. The only case where
                // the report claims the specification does not determine it.
                rec.why = format!("no hypothesis constrains `{}` (no law, `ensures` or refinement states what it returns), so every function of its type satisfies them and the specification does not determine it", it.path);
                rec.notes.push(rec.why.clone());
                return rec;
            }
            None => {
                let ind = self.induction_measure(p, info);
                let span = it.span;
                let budget = self.opts.complete_budget;
                let res = crate::auto::complete::prove(&self.env, self.prover, stmt, lay, ind.as_ref(), budget, span);
                match res {
                    Ok(pr) => {
                        rec.proof = pr.by.to_string();
                        (pr.body, pr.recursion, pr.arity)
                    }
                    Err(f) => {
                        rec.exhausted = f.tried.iter().any(|t| t.contains("budget exhausted"));
                        let rejected = f.tried.iter().any(|t| t.contains("rejected by the kernel"));
                        let how = if rec.exhausted {
                            format!("an attempt ran out of its step budget ({budget} steps per prover call)")
                        } else if rejected {
                            "a proof it found was rejected by the kernel (a prover bug)".to_string()
                        } else {
                            "the search failed".to_string()
                        };
                        rec.why = format!("`auto` could not prove it ({how}); this does not mean the hypotheses fail to determine `{}` — {suggest}", it.path);
                        rec.stuck = self.stuck_goal(stmt, info.exec.get(&p).copied());
                        rec.notes.extend(f.tried.iter().take(8).cloned());
                        if !f.goal.is_empty() {
                            rec.notes.push(format!("last goal: {}", first_line(&f.goal)));
                        }
                        return rec;
                    }
                }
            }
        };
        // the lemma's type is exactly the kernel's statement
        let d = DefDecl { name: Rc::from(name.as_str()), kind: DefKind::Lemma, ty: stmt.clone(), body, recursion, arity, opaque: false };
        let mut b = Budget { steps: self.opts.def_budget };
        match self.env.add_def(d, &mut b) {
            Ok(g) => {
                rec.status = DefStatus::Checked;
                rec.lemma = Some(g);
                // the obligation (a proof item's script recorded its own)
                if proof_item.is_none() {
                    let id = self.obligations.len() as u32;
                    self.obligations.push(super::ObligationRecord { id, kind: ObligationKind::Completeness, span: it.span, def: name.clone(), status: super::OblStatus::Proven { by: "auto".into() }, hinted: false, goal: String::new() });
                }
                self.defs.push(DefRecord { name, kind: DefKind::Lemma, item: Some(p), global: Some(g), status: DefStatus::Checked, span: it.span });
            }
            Err(e) => {
                let msg: String = e.to_string().chars().take(600).collect();
                rec.status = DefStatus::Rejected(msg.clone());
                rec.why = match proof_item {
                    Some(pid) => format!("the kernel rejected the proof built from the script of `{}` (an elaborator bug, not a verdict on the specification): {}", krate.item(pid).path, first_line(&msg)),
                    None => format!("the kernel rejected the proof `auto` found (a prover bug, not a verdict on the specification): {} — {suggest}", first_line(&msg)),
                };
                rec.notes.push(format!("the kernel rejected the proof (a prover bug; the statement stays unproven): {msg}"));
                if proof_item.is_some() {
                    self.diag(Diagnostic::error(DiagKind::Completeness, it.span, format!("the kernel rejected the proof of `{name}`: {msg}")));
                }
            }
        }
        rec
    }

    /// The conclusion of `stmt` with the application of the real function
    /// `g` unfolded once (its body instantiated), in surface syntax under
    /// the statement's binders: what `auto`'s discharges start from.
    fn stuck_goal(&self, stmt: &Tm, g: Option<GlobalId>) -> Option<String> {
        let (bs, concl) = crate::auto::complete::telescope(stmt);
        let g = g?;
        let ar = self.env.global_arity(g)? as usize;
        let body = self.env.global_body(g)?;
        let unfolded = super::tm::map_post(&concl, 0, &mut |node, _b| {
            let (head, args) = super::items::spine(&node);
            match &*head {
                Term::Global(h) if *h == g && args.len() == ar => Some(super::tm::subst_closed(&super::ensures::strip_lams(&body, ar as u32), &args)),
                _ => Some(node),
            }
        })
        .unwrap_or(concl);
        let names: Vec<String> = bs.iter().map(|(n, _, _)| n.to_string()).collect();
        let s = crate::deelab::KernelShow::new(&self.env, names).show(&unfolded);
        Some(if s.chars().count() > 800 { format!("{}…", s.chars().take(800).collect::<String>()) } else { s })
    }

    /// `p`'s termination measure in its own telescope (valid unchanged at
    /// the statement's depth: the section's binders come first), for the
    /// induction discharge; `None` for a non-recursive `p`.
    fn induction_measure(&mut self, p: ItemId, info: &Info) -> Option<crate::auto::complete::Induction> {
        let krate = self.krate;
        let g = *info.exec.get(&p)?;
        let body = self.env.global_body(g)?;
        if !super::tm::any_node(&body, &mut |n| matches!(n, Term::Global(h) if *h == g)) {
            return None;
        }
        let f: &'a FnDef = krate.fn_def(p)?;
        let span = krate.item(p).span;
        let saved = std::mem::replace(&mut self.f, FnState::new(format!("{}::complete", krate.item(p).path), Some(p), &f.locals, span));
        self.f.mode = Mode::Proof;
        self.f.fdef = Some(f);
        let r = (|| {
            let _ = self.fn_params(f, span).ok()?;
            match &f.decreases {
                Some(dec) => Some((self.pure_expr(&dec.measure).ok()?, self.width_of(&dec.measure.ty, dec.measure.span).ok()?)),
                None => self.infer_measure_pub(p, f),
            }
        })();
        self.f = saved;
        r.map(|(measure, width)| crate::auto::complete::Induction { measure, width })
    }

    /// The script of `#[proof(complete = p)]` item `pid` against the
    /// statement: the section's functions and hypotheses are in scope (the
    /// hypotheses and requires as facts), the item's parameters are `p`'s.
    fn complete_script(&mut self, pid: ItemId, p: ItemId, stmt: &Tm, lay: &crate::auto::complete::Layout, members: &[ItemId]) -> Result<Tm, String> {
        let krate = self.krate;
        let pf: &'a FnDef = krate.fn_def(pid).ok_or("the proof item is not a function")?;
        let f: &'a FnDef = krate.fn_def(p).ok_or("not a function")?;
        let crate::hir::FnBody::Script(steps) = &pf.body else { return Err("the proof item has no script".into()) };
        if !f.generics.is_empty() {
            let msg = format!("`#[proof(complete = {})]` is not supported for a generic function yet (auto proves generic sections)", krate.item(p).path);
            self.diag(Diagnostic::error(DiagKind::Completeness, krate.item(pid).span, msg.clone()));
            return Err(msg);
        }
        let span = krate.item(pid).span;
        let name = format!("{}::complete", krate.item(p).path);
        let ndiag = self.diags.list.len();
        let saved = std::mem::replace(&mut self.f, FnState::new(name.clone(), Some(pid), &pf.locals, span));
        self.f.mode = Mode::Proof;
        let (bs, concl) = crate::auto::complete::telescope(stmt);
        let (k, m) = (lay.members, lay.real.len());
        let r = (|| -> Result<Tm, String> {
            let mut j = 0;
            for (i, (n, rel, dom)) in bs.iter().enumerate() {
                if i < k {
                    let lvl = self.push(n, *rel, dom, None).map_err(|e| e.msg)?;
                    if let Some(m) = members.get(i) {
                        self.f.abstracted.insert(*m, (lvl, dom.clone()));
                    }
                } else if i < k + m || *rel == Rel::Irr {
                    let origin = if i < k + m { FactOrigin::LemmaHyp } else { FactOrigin::Requires };
                    self.push_fact_rel(n, *rel, dom, None, origin, span).map_err(|e| e.msg)?;
                } else {
                    let lvl = self.push(n, *rel, dom, None).map_err(|e| e.msg)?;
                    if let Some(pp) = pf.params.get(j)
                        && let PatKind::Binding { local, .. } = &pp.pat.kind
                    {
                        self.f.scope.locals.insert(*local, lvl);
                    }
                    j += 1;
                }
            }
            if j != pf.params.len() {
                return Err(format!("the proof item has {} parameter(s); `{}` has {j}", pf.params.len(), krate.item(p).path));
            }
            let n = self.depth();
            // the real statement of every hypothesis (about the real
            // functions) is a fact too, like in `auto`'s discharges
            // and every hypothesis and real statement instantiated at the
            // parameters (`auto`'s discharges do the same)
            let mut lets: Vec<(String, Tm, Tm)> = Vec::new();
            let params: Vec<u32> = (k + m..bs.len()).filter(|i| bs[*i].1 == Rel::Rel).map(|i| i as u32).collect();
            for (i, g) in lay.real.iter().enumerate() {
                let Some(ty) = self.env.global_type(*g) else { continue };
                let name = format!("l{i}");
                let pf_tm = sandblaster_kernel::util::mk::global(*g);
                self.push_fact_rel(&name, Rel::Irr, &ty, Some(&pf_tm), FactOrigin::LemmaHyp, span).map_err(|e| e.msg)?;
                lets.push((name, ty.clone(), pf_tm));
                // (level of the fact, its type term at that level)
                let hl = (k + i) as u32;
                let ll = self.depth() - 1;
                for (nm, lvl, ty_at) in [(format!("h{i}x"), hl, bs[k + i].2.clone()), (format!("l{i}x"), ll, ty.clone())] {
                    let head = self.f.scope.var(lvl);
                    let hty = shift(&ty_at, (self.depth() - lvl) as i64);
                    if let Some((t, ity)) = self.instantiate_at(head, &hty, &params) {
                        self.push_fact_rel(&nm, Rel::Irr, &ity, Some(&t), FactOrigin::LemmaHyp, span).map_err(|e| e.msg)?;
                        lets.push((nm, ity, t));
                    }
                }
            }
            let goal = Val::new(concl.clone(), n);
            let mut body = self.script(steps, goal, ObligationKind::Completeness, span).map_err(|e| e.msg)?;
            if self.f.failed {
                return Err("an obligation of the script is unproven (see the errors above)".into());
            }
            for (name, ty, pf_tm) in lets.into_iter().rev() {
                body = sandblaster_kernel::util::mk::let_(&name, Rel::Irr, ty, pf_tm, body);
            }
            Ok(crate::auto::complete::lams(&bs, body))
        })();
        self.f = saved;
        if let Err(msg) = &r
            && self.diags.list.len() == ndiag
        {
            self.diag(Diagnostic::error(DiagKind::Completeness, span, format!("`{}` does not prove `{name}`: {msg}", krate.item(pid).path)));
        }
        r
    }
}

impl<'a> Elab<'a> {
    /// `head : ty` (a Π type term at the current depth) applied, binder by
    /// binder, to the first context level of `args` not used yet whose type
    /// its leading relevant binder accepts (type-directed: a hypothesis over
    /// `k: u8` is instantiated at the parameter `k` of `(t: [u8; 4], k: u8)`);
    /// the application and its type term, when at least one argument was
    /// taken.
    fn instantiate_at(&self, head: Tm, ty: &Tm, args: &[u32]) -> Option<(Tm, Tm)> {
        let mut t = head;
        let mut cur = ty.clone();
        let mut used: Vec<u32> = Vec::new();
        while let Term::Pi { rel: Rel::Rel, dom, cod, .. } = &*cur.clone() {
            let Ok(dv) = self.eval(dom) else { break };
            let pick = args.iter().copied().find(|a| {
                let mut b = Budget { steps: self.opts.goal_budget };
                !used.contains(a) && self.env.conv(sandblaster_kernel::term::Lvl(self.depth()), &dv, &self.f.scope.ctx.entries[*a as usize].ty, &mut b).unwrap_or(false)
            });
            let Some(a) = pick else { break };
            used.push(a);
            t = sandblaster_kernel::util::mk::app(t, self.f.scope.var(a));
            cur = super::tm::subst0(cod, &self.f.scope.var(a));
        }
        (!used.is_empty()).then_some((t, cur))
    }
}

/// A statement in surface syntax (DESIGN.md §15.6 "a de-elaborated form"):
/// a data binder is `for all x: T,`, a proposition binder (a hypothesis, a
/// `requires`) is `P ⇒`; the atoms are rendered by
/// [`crate::deelab::KernelShow`].
pub fn render_statement(env: &sandblaster_kernel::api::Env, t: &Tm) -> String {
    render_prop(env, t, &mut Vec::new())
}

fn occurs0(t: &Tm) -> bool {
    super::tm::any_node_depth(t, &mut |n, k| matches!(n, Term::Var(i) if i.0 == k))
}

fn paren(s: String) -> String {
    if s.contains(" ⇒ ") || s.starts_with("for all") || s.contains(" -> ") { format!("({s})") } else { s }
}

fn render_prop(env: &sandblaster_kernel::api::Env, t: &Tm, names: &mut Vec<String>) -> String {
    match &**t {
        Term::Pi { name, rel, dom, cod } => {
            let implication = *rel == Rel::Irr || !occurs0(cod);
            let d = if implication { paren(render_prop(env, dom, names)) } else { render_ty(env, dom, names) };
            names.push(name.to_string());
            let c = render_prop(env, cod, names);
            names.pop();
            if implication { format!("{d} ⇒ {c}") } else { format!("for all {name}: {d}, {c}") }
        }
        _ => crate::deelab::KernelShow::new(env, names.clone()).show(t),
    }
}

fn render_ty(env: &sandblaster_kernel::api::Env, t: &Tm, names: &mut Vec<String>) -> String {
    match &**t {
        Term::Pi { name, dom, cod, .. } => {
            let dependent = occurs0(cod);
            let d = render_ty(env, dom, names);
            names.push(name.to_string());
            let c = render_ty(env, cod, names);
            names.pop();
            if dependent { format!("({name}: {d}) -> {c}") } else { format!("{} -> {c}", if d.contains(" -> ") { format!("({d})") } else { d }) }
        }
        Term::IntTy(sandblaster_kernel::term::Width::Int) => "Int".to_string(),
        Term::IntTy(w) => sandblaster_kernel::prim::width_suffix(*w).to_string(),
        Term::Ind { ind, params } if *ind == env.bool_ind() && params.is_empty() => "bool".to_string(),
        Term::Sort(_) => "Type".to_string(),
        Term::Var(i) => names.len().checked_sub(1 + i.0 as usize).and_then(|l| names.get(l)).cloned().unwrap_or_else(|| "?".into()),
        _ => crate::deelab::KernelShow::new(env, names.clone()).show(t),
    }
}

/// The index of the hypothesis an `abstract_section` error is about.
fn hypothesis_index(msg: &str) -> Option<usize> {
    let pos = msg.find("hypothesis ")?;
    msg[pos + 11..].split(' ').next()?.parse::<usize>().ok()
}

/// The hypothesis whose abstracted statement the kernel rejected in the
/// type check (a proof slot that does not re-check: abstractability), not
/// in the placement (a global reaching the section) nor a restatement.
fn abstractability_failure(msg: &str) -> Option<usize> {
    let i = hypothesis_index(msg)?;
    let placement = ["reaches the section but is not a spec definition", "is recursive and reaches the section", "occurs before its binder", "the restatement differs", "is not a known global", "unbound variable in a placed term"];
    (!placement.iter().any(|p| msg.contains(p))).then_some(i)
}

/// Whether some hypothesis of the statement mentions `F_p'` (the variable
/// of member `lay.member_p`).
fn constrains(stmt: &Tm, lay: &crate::auto::complete::Layout) -> bool {
    let (bs, _) = crate::auto::complete::telescope(stmt);
    let k = lay.members;
    (0..lay.real.len()).any(|i| {
        let Some((_, _, dom)) = bs.get(k + i) else { return false };
        let at = (k + i) as u32;
        let target = at - 1 - lay.member_p as u32;
        super::tm::any_node_depth(dom, &mut |n, local| matches!(n, Term::Var(x) if x.0 >= local && x.0 - local == target))
    })
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or("")
}

/// The exec functions `exprs` call, directly or through the bodies of the
/// spec functions they call (HIR level, for statements that did not
/// elaborate).
fn hir_exec_mentions(krate: &Crate, exprs: &[&crate::hir::Expr]) -> BTreeSet<ItemId> {
    struct V<'k> {
        krate: &'k Crate,
        out: BTreeSet<ItemId>,
        seen: BTreeSet<ItemId>,
        work: Vec<ItemId>,
    }
    impl crate::visit::Visitor for V<'_> {
        fn expr(&mut self, e: &crate::hir::Expr) {
            if let crate::hir::ExprKind::Call { callee: crate::hir::Callee::Item(id, _), .. } = &e.kind
                && let Some(f) = self.krate.fn_def(*id)
            {
                match f.kind {
                    FnKind::Exec => {
                        self.out.insert(*id);
                    }
                    FnKind::Spec if self.seen.insert(*id) => self.work.push(*id),
                    _ => {}
                }
            }
            crate::visit::walk_expr(self, e);
        }
    }
    let mut v = V { krate, out: BTreeSet::new(), seen: BTreeSet::new(), work: vec![] };
    for e in exprs {
        crate::visit::Visitor::expr(&mut v, e);
    }
    while let Some(s) = v.work.pop() {
        if let Some(f) = krate.fn_def(s)
            && let crate::hir::FnBody::Spec(b) = &f.body
        {
            crate::visit::Visitor::expr(&mut v, b);
        }
    }
    v.out
}

/// The user struct and enum types occurring in `t` (through references,
/// options, tuples, arrays, slices and sequences).
fn struct_ids(t: &Ty, out: &mut BTreeSet<ItemId>) {
    match t {
        Ty::Adt(id, args) => {
            out.insert(*id);
            for a in args {
                struct_ids(a, out);
            }
        }
        Ty::Ref(x) | Ty::Option(x) | Ty::Array(x, _) | Ty::Slice(x) | Ty::Seq(x) => struct_ids(x, out),
        Ty::Tuple(ts) => ts.iter().for_each(|x| struct_ids(x, out)),
        _ => {}
    }
}

/// Tarjan's SCC algorithm (deterministic: nodes and successors in order);
/// every SCC is emitted after the SCCs it reaches.
fn tarjan(nodes: &[ItemId], edges: &BTreeMap<ItemId, BTreeSet<ItemId>>) -> Vec<Vec<ItemId>> {
    struct T<'e> {
        edges: &'e BTreeMap<ItemId, BTreeSet<ItemId>>,
        index: BTreeMap<ItemId, usize>,
        low: BTreeMap<ItemId, usize>,
        on: BTreeSet<ItemId>,
        stack: Vec<ItemId>,
        next: usize,
        out: Vec<Vec<ItemId>>,
    }
    impl T<'_> {
        fn go(&mut self, v: ItemId) {
            self.index.insert(v, self.next);
            self.low.insert(v, self.next);
            self.next += 1;
            self.stack.push(v);
            self.on.insert(v);
            let succ: Vec<ItemId> = self.edges.get(&v).map(|s| s.iter().copied().collect()).unwrap_or_default();
            for w in succ {
                if !self.index.contains_key(&w) {
                    self.go(w);
                    let l = self.low[&v].min(self.low[&w]);
                    self.low.insert(v, l);
                } else if self.on.contains(&w) {
                    let l = self.low[&v].min(self.index[&w]);
                    self.low.insert(v, l);
                }
            }
            if self.low[&v] == self.index[&v] {
                let mut scc = Vec::new();
                while let Some(w) = self.stack.pop() {
                    self.on.remove(&w);
                    scc.push(w);
                    if w == v {
                        break;
                    }
                }
                scc.sort();
                self.out.push(scc);
            }
        }
    }
    let mut t = T { edges, index: BTreeMap::new(), low: BTreeMap::new(), on: BTreeSet::new(), stack: vec![], next: 0, out: vec![] };
    for &v in nodes {
        if !t.index.contains_key(&v) {
            t.go(v);
        }
    }
    t.out
}

/// The §15.8 gate for sections (run by the crate path with the other gates):
/// every section that is not fully specified is an error, with why.
pub fn spec15_gate_s3(out: &super::Output, krate: &Crate, diags: &mut Diagnostics) {
    let path = |id: ItemId| krate.item(id).path.to_string();
    for s in &out.sections {
        if s.fully_specified() {
            continue;
        }
        let members = s.members.iter().map(|m| format!("`{}`", path(*m))).collect::<Vec<_>>().join(", ");
        let kind = if s.status == SectionStatus::Unproven { DiagKind::Completeness } else { DiagKind::Section };
        let head = match s.status {
            SectionStatus::Unproven => {
                let unproven: Vec<String> = s.statements.iter().filter(|c| c.status != DefStatus::Checked).map(|c| format!("`{}`", path(c.item))).collect();
                format!("{} not determined by the specification: `complete_p(R)` is unproven for the section {{{members}}}", if unproven.len() == 1 { format!("{} is", unproven[0]) } else { format!("{} are", unproven.join(", ")) })
            }
            _ => format!("the section {{{members}}} is {}", s.status.word()),
        };
        let mut d = Diagnostic::error(kind, s.span, head);
        // the stuck goals first (surface syntax), then why, then the rest;
        // the provers' internal notes stay in the report
        for c in &s.statements {
            if c.status != DefStatus::Checked
                && let Some(g) = &c.stuck
            {
                d = d.note(format!("`auto` got stuck on `complete_{}` at the goal (with `{}` unfolded once): {g}", path(c.item), path(c.item)));
            }
        }
        for p in &s.problems {
            d = d.note(p.clone());
        }
        for (sp, what) in &s.problem_spans {
            d = d.note_at(*sp, what.clone());
        }
        if !s.hyps.is_empty() {
            d = d.note(format!("hypotheses H(R): {}", s.hyps.iter().map(|(k, n)| format!("{k} `{n}`")).collect::<Vec<_>>().join(", ")));
        } else if !s.definitional.is_empty() {
            d = d.note(format!("hypotheses H(R): none — only `#[definitional]` laws mention the section ({}), and they are not hypotheses", s.definitional.iter().map(|x| format!("`{x}`")).collect::<Vec<_>>().join(", ")));
        } else if s.status != SectionStatus::Blocked {
            d = d.note("hypotheses H(R): none — no law, `ensures` or refinement mentions the section".to_string());
        }
        for c in &s.statements {
            if c.status == DefStatus::Checked {
                continue;
            }
            d = d.note(format!("complete_{}: {}", path(c.item), c.surface));
        }
        d = d.note("to determine a function: give it `#[refines(spec::..)]` with an injective view, or laws that pin its result on every valid input (for a `bool` function, both directions: `f(x) ⇒ P(x)` and `P(x) ⇒ f(x)`), or prove `complete_p` with `#[proof(complete = f)]` in PROOF.rs (DESIGN.md §15.5)");
        diags.push(d);
    }
}
