//! Checked-structuring driver for debugging (docs/checked-structuring.md):
//!
//! `cs_proto <root.rs> <items> [<mir key>..]`
//!
//! * the front end, then the elaboration of the items named in `<items>`
//!   (comma-separated suffixes, `^prefix`; `-`: only the declarations);
//! * the literal reading (`mir::literal`) of the named MIR instances (none:
//!   every instance) of the lifted MIR modules, loaded into that environment;
//! * the theorems of `CS_THM` (`fn:<key>=<global>;helper:<key>=<global>|<header>|<slot>=p<k>|code,..`),
//!   in order (`while:<key>=<helper>`: a `while` loop's lemma). `CS_FAULT=<key substring>|<old>|<new>` changes integer
//!   constants of the MIR first (a negative test), `CS_DUMP=<dir>` writes
//!   the reading and the statements, `CS_TRACE` traces the walker
//!   (`CS_TRACE_CALLS`, `CS_TRACE_SPLIT`, `CS_TRACE_LSPLIT`, `CS_TRACE_TAIL`
//!   for more), `CS_CHECK` checks every proof node as it is built,
//!   `CS_PROFILE` reports where a proof's nodes are, `CS_FULL` prints
//!   failures whole, `CS_BUDGET_SECS`/`CS_BUDGET_STEPS` set the per-function
//!   budget, `CS_SHOW=<suffix>,..` prints structured definitions
//!   (`CS_SKEL`: without their proofs).
//! * `CS_GATE=1`: the gate's run instead (every lifted function of the root
//!   read from MIR, in dependency order; `CS_CACHE=<dir>` a verdict cache).
//!   More traces: `CS_DIFF` (the first differing subterms at a tail
//!   mismatch), `CS_TRACE_S` (S at each split), `CS_TRACE_ETA` (array eta
//!   repairs), `CS_TRACE_ERASED` (erased pairs), `CS_TRACE_ABS` (ill-typed
//!   abstractions), `CS_TRACE_FACT` (tests decided by facts),
//!   `CS_TRACE_BRIDGE`, `CS_TRACE_ARITH` (failed arithmetic),
//!   `CS_TRACE_PRIMS` (a `let`'s primitive facts), `CS_TRACE_RW` (facts
//!   rewritten by a literal split), `CS_TRACE_TAIL_RAW`, `CS_CHECK_FACTS`,
//!   `CS_FIND_BAD` / `CS_DUMP_MOTIVE=<file>` (an ill-formed motive's
//!   innermost bad node), `CS_ONLY=<text>` (only the planned entries whose
//!   global contains it, and what they need). The gate run elaborates the
//!   prover's bridges and library (`^words::`, `^stdlib::`, `^sha256::`) as
//!   the build does. Entries: `model:<key>=<prelude model>` too.
//! * `CS_HOOK=<rule>`: the front end runs with a deliberately wrong rule of
//!   `lift::test_hook` (`WritebackSnapshot`, `SnapshotOwnValue`, ..).

use std::path::Path;
use std::time::Instant;

use sandblaster_front::driver;
use sandblaster_front::loader::RealFs;
use sandblaster_front::mir::checked::{self, Entry, Prover};
use sandblaster_front::mir::ir;
use sandblaster_front::target::TargetInfo;

fn main() {
    sandblaster_front::memguard::init_from_env();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let items: Vec<String> = if args[1] == "-" { vec![] } else { args[1].split(',').map(str::to_string).collect() };
    let keys: Vec<String> = args[2..].to_vec();
    let t0 = Instant::now();
    // `CS_HOOK=<rule>`: the front end with a deliberately wrong reading rule
    // (`lift::test_hook`, `Debug` name: `WritebackSnapshot`, ..)
    use sandblaster_front::lift::test_hook::{self, WrongRule};
    let hook = std::env::var("CS_HOOK").ok().map(|h| {
        [WrongRule::SignedShrLogical, WrongRule::InclusiveRangeAsExclusive, WrongRule::SnapshotOwnValue, WrongRule::WritebackSnapshot, WrongRule::ExtraRequires].into_iter().find(|r| format!("{r:?}") == h).unwrap_or_else(|| panic!("no rule `{h}`"))
    });
    test_hook::set(hook);
    let c = driver::check(Path::new(&args[0]), &RealFs, &TargetInfo::host());
    test_hook::set(None);
    if !c.ok() {
        eprintln!("{}", c.render());
        std::process::exit(1);
    }
    let k = c.krate.as_ref().unwrap();
    let dump = std::env::var("CS_DUMP").ok().map(std::path::PathBuf::from);
    eprintln!("front end {:.1}s", t0.elapsed().as_secs_f64());
    sandblaster_front::elab::with_big_stack(|| {
        let t1 = Instant::now();
        // `CS_GATE`: the gate's run (every lifted function read from MIR, in
        // dependency order); items `ALL`: the whole crate elaborated, `-`:
        // the lifted functions and their helpers
        let gate = std::env::var("CS_GATE").is_ok();
        let mut items = items.clone();
        if gate && items.is_empty() {
            items = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).chain(c.lift_facts.mir_helpers.iter().map(|x| x.global.trim_start_matches("crate::").to_string())).collect();
            // (the prover's bridges and library, as the build elaborates them)
            items.extend(["^words::", "^stdlib::", "^sha256::"].map(String::from));
        }
        let mut out = if items.first().is_some_and(|i| i == "ALL") {
            let mut chain = sandblaster_front::elab::ProverChain::standard();
            sandblaster_front::elab::elaborate(k, &mut chain, &sandblaster_front::elab::Options::default())
        } else {
            checked::elaborate_names(k, &items)
        };
        eprintln!("structured reading elaborated in {:.1}s ({} defs, {} obligations, {} unproven)", t1.elapsed().as_secs_f64(), out.defs.len(), out.obligations.len(), out.obligations.iter().filter(|o| !o.proven()).count());
        show(&out);
        if gate {
            let t2 = Instant::now();
            let mut opts = checked::GateOptions::default();
            if let Some(x) = std::env::var("CS_BUDGET_SECS").ok().and_then(|v| v.parse().ok()) {
                opts.budget_secs = x;
            }
            opts.trace = std::env::var("CS_TRACE").is_ok();
            opts.only = std::env::var("CS_ONLY").ok();
            // `CS_CACHE=<dir>`: the theorems' verdict cache in `dir`
            let vc = std::env::var("CS_CACHE").ok().map(|d| sandblaster_front::driver::cache::VerdictCache::new(sandblaster_front::driver::cache::Store::open(d.into(), sandblaster_front::surface::sha256(b"cs_proto")), "cs_proto"));
            opts.cache = vc.as_ref();
            let reps = checked::prove_lifted(&mut out, &c.lift_facts, &opts);
            for r in &reps {
                eprintln!("{}: literal reading of {} functions ({} items) in {:.2}s", r.dsl, r.literal_fns, r.literal_items, r.literal_secs);
                for o in &r.outcomes {
                    match &o.result {
                        Ok(p) => eprintln!("  OK   {} `{}` ({}): walk {:.3}s, kernel {:.3}s, {} nodes", p.kind, o.global, o.key, p.walk_secs, p.check_secs, p.nodes),
                        Err(e) => {
                            let lim = if std::env::var("CS_FULL").is_ok() { e.len() } else { e.len().min(1500) };
                            eprintln!("  FAIL {} `{}` ({}): {}", o.kind, o.global, o.key, &e[..e.floor_char_boundary(lim)]);
                        }
                    }
                }
                for (g, why) in r.missing.iter().filter(|(g, _)| !r.outcomes.iter().any(|o| &o.global == g)) {
                    eprintln!("  MISSING `{g}`: {why}");
                }
                eprintln!("{}: {} of {} lifted functions proven in {:.1}s ({} from the cache)", r.dsl, r.proven(), r.functions(), r.secs, r.cached());
            }
            eprintln!("gate total {:.1}s", t2.elapsed().as_secs_f64());
            return;
        }
        let mut seen = std::collections::BTreeSet::new();
        for mm in &c.lift_facts.mir_loaded {
            // (several lifted modules of one extraction share its MIR)
            if !seen.insert(mm.loaded.m.module.clone()) {
                continue;
            }
            let mut m: ir::Sbmir = mm.loaded.m.clone();
            fault(&mut m);
            let ks: Vec<String> = if keys.is_empty() { vec![] } else { keys.iter().filter(|k| m.fns.contains_key(*k)).cloned().collect() };
            if !keys.is_empty() && ks.is_empty() {
                continue;
            }
            let lit = match checked::load_literal(&mut out.env, &m, &mm.loaded.names, &ks, dump.as_ref().map(|d| d.join("literal.core")).as_deref()) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("{}: {e}", mm.dsl);
                    std::process::exit(1);
                }
            };
            let (nf, np) = (lit.state.fns.values().map(|f| f.faults.len()).sum::<usize>(), lit.state.fns.values().map(|f| f.panics.len()).sum::<usize>());
            eprintln!("{}: literal reading of {} functions: {} items, {} lines, {} bytes, checked in {:.2}s; {} refused, {nf} constructs read as None, {np} panic blocks", mm.dsl, lit.state.fns.len(), lit.items, lit.lines, lit.bytes, lit.check_secs, lit.refused.len());
            for (k, e) in &lit.refused {
                eprintln!("  REFUSED {k}: {e}");
            }
            if std::env::var("CS_FAULTS").is_ok() {
                for (k, fs) in checked::faults(&lit) {
                    for f in fs {
                        eprintln!("  NONE {k}: {f}");
                    }
                }
            }
            let mut entries = parse_entries(&std::env::var("CS_THM").unwrap_or_default());
            // (`while:<key>=<helper>`: the names of the locals from the lift)
            for e in entries.iter_mut() {
                if let Entry::While { s_global, header, local_names, .. } = e
                    && let Some(h) = c.lift_facts.mir_helpers.iter().find(|h| &h.global == s_global)
                {
                    *header = h.header;
                    *local_names = h.local_names.clone();
                }
            }
            let mut pv = Prover::new(&mut out.env, &m, &mm.loaded.names, &lit, &out.pre_commit, &c.lift_facts.mir_contracts);
            pv.trace = std::env::var("CS_TRACE").is_ok();
            pv.dump = dump.clone();
            if let Some(x) = std::env::var("CS_BUDGET_SECS").ok().and_then(|v| v.parse().ok()) {
                pv.budget_secs = x;
            }
            if let Some(x) = std::env::var("CS_BUDGET_STEPS").ok().and_then(|v| v.parse().ok()) {
                pv.max_steps = x;
            }
            let (mut walk, mut check, mut nodes) = (0.0, 0.0, 0);
            for e in entries.iter().filter(|e| match e { Entry::Fn { key, .. } | Entry::Helper { key, .. } | Entry::While { key, .. } | Entry::Model { key, .. } => m.fns.contains_key(key) }) {
                match pv.prove(e) {
                    Ok(p) => {
                        eprintln!("{} `{}` checked: walk {:.3}s, kernel {:.3}s, proof {} nodes, {}", p.kind.to_uppercase(), p.s_global, p.walk_secs, p.check_secs, p.nodes, p.stats);
                        (walk, check, nodes) = (walk + p.walk_secs, check + p.check_secs, nodes + p.nodes);
                    }
                    Err(err) => {
                        let lim = if std::env::var("CS_FULL").is_ok() { err.len() } else { err.len().min(6000) };
                        eprintln!("FAILED: {}", &err[..err.floor_char_boundary(lim)]);
                        std::process::exit(1);
                    }
                }
            }
            eprintln!("TOTAL: walk {walk:.3}s, kernel check {check:.3}s, proof {nodes} nodes");
        }
    });
}

/// `CS_SHOW=<suffix>,..`: prints the structured reading's definitions whose
/// names end so (type, body, and the pre-commit body of a recursive one).
fn show(out: &sandblaster_front::elab::Output) {
    let Ok(spec) = std::env::var("CS_SHOW") else { return };
    let env = &out.env;
    for g in (0..env.num_globals()).map(sandblaster_kernel::term::GlobalId) {
        let nm = env.global_name(g).map(|n| n.to_string()).unwrap_or_default();
        // `~sub`: every name containing `sub`, listed only
        if spec.split(',').any(|s| s.strip_prefix('~').is_some_and(|x| nm.contains(x))) {
            println!("GLOBAL {nm}");
            continue;
        }
        if !spec.split(',').any(|s| !s.is_empty() && !s.starts_with('~') && nm.ends_with(s)) {
            continue;
        }
        println!("==== {nm} opaque={:?} kind={:?}", env.global_opaque(g), env.global_kind(g));
        let sk = |t: &sandblaster_kernel::term::Tm| if std::env::var("CS_SKEL").is_ok() { skeleton(env, t) } else { t.clone() };
        if let Some(t) = env.global_type(g) {
            println!("TYPE {}", env.print_term(&[], &t));
        }
        if let Some(b) = env.global_body(g) {
            println!("BODY {}", env.print_term(&[], &sk(&b)));
        }
        if let Some(pc) = out.pre_commit.get(&g) {
            println!("PRE-COMMIT {}\nMEASURE {}", env.print_term(&[], &sk(&pc.body)), env.print_term(&[], &pc.measure));
        }
    }
}

/// `t` with its proofs elided (`CS_SKEL`): an irrelevant `let` is its body
/// (the proof variable read as `tt`), a primitive's proofs and an
/// irrelevant argument are dropped or `tt`.
fn skeleton(env: &sandblaster_kernel::api::Env, t: &sandblaster_kernel::term::Tm) -> sandblaster_kernel::term::Tm {
    use sandblaster_kernel::term::{Rel, Term};
    use std::rc::Rc;
    let unit = env.lookup_ind("Unit").unwrap();
    let tt: sandblaster_kernel::term::Tm = Rc::new(Term::Ctor { ind: unit, ctor: 0, params: vec![], args: vec![] });
    sandblaster_front::auto::util::map_term(t, 0, &mut |x, _d| match &**x {
        Term::Let { rel: Rel::Irr, body, .. } => Some(skeleton(env, &sandblaster_front::elab::tm::subst0(body, &tt))),
        Term::Prim { op, args, proofs } if !proofs.is_empty() => Some(Rc::new(Term::Prim { op: *op, args: args.iter().map(|a| skeleton(env, a)).collect(), proofs: vec![] })),
        Term::App { rel: Rel::Irr, fun, arg } if !matches!(&**fun, Term::Match { .. }) => {
            let _ = arg;
            Some(Rc::new(Term::App { rel: Rel::Irr, fun: skeleton(env, fun), arg: tt.clone() }))
        }
        Term::Rec { args, .. } => Some(Rc::new(Term::Rec { args: args.iter().map(|a| skeleton(env, a)).collect(), proof: None })),
        _ => None,
    })
}

fn parse_entries(spec: &str) -> Vec<Entry> {
    spec.split(';').filter(|x| !x.is_empty()).map(|e| {
        let (kind, rest) = e.split_once(':').expect("kind:..");
        let (key, srest) = rest.split_once('=').expect("key=global");
        let mut parts = srest.split('|');
        let s_global = parts.next().unwrap().to_string();
        if kind == "fn" {
            return Entry::Fn { key: key.into(), s_global };
        }
        if kind == "model" {
            return Entry::Model { key: key.into(), s_global };
        }
        if kind == "while" {
            return Entry::While { key: key.into(), s_global, header: 0, local_names: vec![] };
        }
        let header = parts.next().expect("header").parse().unwrap();
        let slots = parts.next().unwrap_or("").split(',').filter(|x| !x.is_empty()).map(|kv| { let (a, b) = kv.split_once('=').unwrap(); (a.to_string(), b.to_string()) }).collect();
        Entry::Helper { key: key.into(), s_global, header, slots }
    }).collect()
}

/// `CS_FAULT=<key substring>|<old>|<new>`: every integer constant `old` of
/// the matching functions' statements becomes `new`.
fn fault(m: &mut ir::Sbmir) {
    let Ok(spec) = std::env::var("CS_FAULT") else { return };
    let parts: Vec<&str> = spec.split('|').collect();
    let (pat, old, new) = (parts[0], parts[1].parse::<i128>().unwrap(), parts[2].parse::<i128>().unwrap());
    let mut n = 0;
    for (k, f) in m.fns.iter_mut().filter(|(k, _)| k.contains(pat)) {
        let _ = k;
        for st in f.blocks.iter_mut().flat_map(|b| b.stmts.iter_mut()) {
            if let ir::Stmt::Assign(_, rv, _) = st {
                let ops: Vec<&mut ir::Operand> = match rv {
                    ir::Rvalue::Bin(_, a, b) | ir::Rvalue::Checked(_, a, b) => vec![a, b],
                    ir::Rvalue::Use(a) => vec![a],
                    _ => vec![],
                };
                for o in ops {
                    if let ir::Operand::Const(c) = o
                        && let ir::Const::Int(t, x) = c.value().clone()
                        && x == old
                    {
                        *c = ir::Const::Int(t, new);
                        n += 1;
                    }
                }
            }
        }
    }
    eprintln!("fault injected: {n} constants {old} -> {new} in functions matching `{pat}`");
}
