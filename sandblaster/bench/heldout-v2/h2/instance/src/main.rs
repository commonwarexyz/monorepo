//! `sb-h2v2-instance`: H2-v2's rule-chosen instance (RULE.md section 3.1),
//! asked of rustc itself.
//!
//! It runs as cargo's `RUSTC_WORKSPACE_WRAPPER` on the pinned nightly of
//! `sandblaster/mirx/rust-toolchain.toml`, like `sandblaster-mirx`, whose
//! wrapper logic (pass-through for other crates, stubs for the verifying
//! build scripts of codec and storage) it copies. For the library of the
//! crate named by `SBI_CRATE` it runs rustc with a callback after analysis
//! that, for every generic candidate listed in `SBI_IN` (one
//! `rank<TAB>file<TAB>line<TAB>name` per line, from candidates.tsv):
//!
//! 1. builds each type parameter's list: the fixed primitive list, then the
//!    workspace types (public, non-generic, of a workspace crate reached
//!    through public modules, defined outside test, mock and fuzz files)
//!    that satisfy every bound of the parameter that names no other
//!    parameter (rustc's trait solver, `predicate_must_hold_modulo_regions`),
//!    in the order of `sha256("<seed>:instance:<full type path>")`, at most
//!    16 of them; each const parameter's list is the rule's fixed values;
//! 2. takes the combinations in lexicographic order of the lists, at most
//!    256, and keeps those at which every predicate of the function (its
//!    impl's and its own) holds and the function resolves
//!    (`Instance::try_resolve`): what type-checking a monomorphic wrapper
//!    asks. Lifetimes are erased.
//!
//! It writes one JSON object per candidate to `SBI_OUT`. instance.py then
//! type-checks a wrapper for the first kept combination (RULE.md 3.1 step
//! 3, literally), falling back to the next kept one if rustc refuses it.
//!
//! With `SBI_REPLACE="path=text,.."` it compiles `path` as if its text were
//! `text`'s (the wrappers appended to a copy of a candidate's file) and does
//! nothing after analysis: rustc's own errors are the verdict.
#![feature(rustc_private, never_type)]

extern crate rustc_driver;
extern crate rustc_hir;
extern crate rustc_infer;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;
extern crate rustc_trait_selection;
extern crate sha2;

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::DefId;
use rustc_infer::infer::TyCtxtInferExt;
use rustc_infer::traits::{Obligation, ObligationCause};
use rustc_middle::ty::{self, GenericArg, Ty, TyCtxt, TypeSuperVisitable, TypeVisitable, TypeVisitor};
use rustc_trait_selection::traits::query::evaluate_obligation::InferCtxtExt as _;

const MAX_COMBOS: usize = 256;
const MAX_WORKSPACE: usize = 16;
const KEEP: usize = 8;
const TEST_PARTS: &[&str] = &["tests", "test", "mocks", "mock", "test_utils", "fuzz", "benches", "bench", "examples"];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("sb-h2v2-instance: run as RUSTC_WORKSPACE_WRAPPER (see ../instance.py)");
        std::process::exit(2);
    }
    let rustc = &args[1];
    let rest = &args[2..];
    let crate_name = rest.iter().position(|a| a == "--crate-name").map(|i| rest[i + 1].clone()).unwrap_or_default();
    let want = std::env::var("SBI_CRATE").unwrap_or_default();
    let pkg = std::env::var("CARGO_PKG_NAME").ok().map(|n| n.replace('-', "_")).unwrap_or_default();
    if crate_name == "build_script_build" {
        for entry in std::env::var("SBI_STUBS").unwrap_or_default().split(';').filter(|e| !e.is_empty()) {
            let (c, map) = entry.split_once(':').unwrap_or((entry, ""));
            if c.replace('-', "_") == pkg {
                stub_build_script(rustc, rest, map);
            }
        }
    }
    let is_lib = rest.windows(2).any(|w| w[0] == "--crate-type" && w[1] == "lib") || rest.iter().any(|a| a == "--crate-type=lib");
    if crate_name != want || !is_lib || rest.iter().any(|a| a == "--test") {
        let st = std::process::Command::new(rustc).args(rest).status().expect("run rustc");
        std::process::exit(st.code().unwrap_or(1));
    }
    let mut dargs = vec![rustc.clone()];
    dargs.extend(rest.iter().cloned());
    if !rest.iter().any(|a| a.starts_with("--cap-lints")) {
        dargs.extend(["--cap-lints".to_string(), "allow".to_string()]);
    }
    let mut cb = Driver { done: false };
    let ran = rustc_driver::catch_fatal_errors(|| rustc_driver::run_compiler(&dargs, &mut cb));
    if ran.is_err() || !cb.done {
        eprintln!("sb-h2v2-instance: the compilation failed before analysis ended");
        std::process::exit(1);
    }
}

struct Driver {
    done: bool,
}

impl rustc_driver::Callbacks for Driver {
    fn config(&mut self, config: &mut rustc_interface::interface::Config) {
        config.file_loader = Some(Box::new(Sources));
    }

    fn after_analysis<'tcx>(&mut self, _c: &rustc_interface::interface::Compiler, tcx: TyCtxt<'tcx>) -> rustc_driver::Compilation {
        if std::env::var("SBI_IN").is_ok() {
            run(tcx);
        }
        self.done = true;
        rustc_driver::Compilation::Continue
    }
}

fn replacements() -> Vec<(std::path::PathBuf, std::path::PathBuf)> {
    let canon = |p: &str| std::fs::canonicalize(p).unwrap_or_else(|_| std::path::PathBuf::from(p));
    std::env::var("SBI_REPLACE").unwrap_or_default().split(',').filter_map(|e| e.split_once('=')).map(|(a, b)| (canon(a), canon(b))).collect()
}

fn source_path(path: &std::path::Path) -> std::path::PathBuf {
    let c = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    replacements().into_iter().find(|(a, _)| *a == c).map(|(_, b)| b).unwrap_or_else(|| path.to_path_buf())
}

struct Sources;

impl rustc_span::source_map::FileLoader for Sources {
    fn file_exists(&self, path: &std::path::Path) -> bool {
        path.exists()
    }

    fn read_file(&self, path: &std::path::Path) -> std::io::Result<String> {
        std::fs::read_to_string(source_path(path))
    }

    fn read_binary_file(&self, path: &std::path::Path) -> std::io::Result<std::sync::Arc<[u8]>> {
        std::fs::read(source_path(path)).map(Into::into)
    }

    fn current_directory(&self) -> std::io::Result<std::path::PathBuf> {
        std::env::current_dir()
    }
}

/// The verifying build scripts of codec and storage, stubbed as
/// sandblaster-mirx stubs them (their real ones run the verifier).
fn stub_build_script(rustc: &str, rest: &[String], stub: &str) -> ! {
    let mut body = String::from("#![allow(warnings)]\nfn main() {\n    println!(\"cargo::rustc-check-cfg=cfg(rust_analyzer)\");\n    let out = std::env::var(\"OUT_DIR\").unwrap();\n");
    for pair in stub.split(',').filter(|p| !p.is_empty()) {
        let (o, src) = pair.split_once('=').expect("SBI_STUBS: out.rs=src.rs");
        let _ = writeln!(
            body,
            "    {{ let t = std::fs::read_to_string({src:?}).unwrap(); let t: String = t.lines().skip_while(|l| l.starts_with(\"//!\")).map(|l| format!(\"{{l}}\\n\")).collect(); std::fs::write(std::path::Path::new(&out).join({o:?}), t).unwrap(); }}"
        );
    }
    body.push_str("}\n");
    let dir = std::env::temp_dir().join(format!("sbi-stub-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("stub dir");
    let f = dir.join("build.rs");
    std::fs::write(&f, body).expect("stub");
    let args: Vec<String> = rest.iter().map(|a| if a.ends_with("build.rs") { f.display().to_string() } else { a.clone() }).collect();
    let st = std::process::Command::new(rustc).args(&args).status().expect("run rustc");
    std::process::exit(st.code().unwrap_or(1));
}

fn q(s: &str) -> String {
    format!("{s:?}")
}

fn sha_hex(s: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// The type parameters (`ty::Param` indices) and const parameters a value names.
struct Params(Vec<u32>);

impl<'tcx> TypeVisitor<TyCtxt<'tcx>> for Params {
    fn visit_ty(&mut self, t: Ty<'tcx>) {
        if let ty::Param(p) = t.kind() {
            self.0.push(p.index);
        }
        t.super_visit_with(self)
    }

    fn visit_const(&mut self, c: ty::Const<'tcx>) {
        if let ty::ConstKind::Param(p) = c.kind() {
            self.0.push(p.index);
        }
        c.super_visit_with(self)
    }
}

fn params_of<'tcx, T: TypeVisitable<TyCtxt<'tcx>>>(v: &T) -> Vec<u32> {
    let mut p = Params(Vec::new());
    v.visit_with(&mut p);
    p.0.sort();
    p.0.dedup();
    p.0
}

/// Whether a fully monomorphic clause holds (rustc's trait solver).
fn holds<'tcx>(tcx: TyCtxt<'tcx>, clause: ty::Clause<'tcx>) -> bool {
    let env = ty::TypingEnv::fully_monomorphized();
    let clause = match tcx.try_normalize_erasing_regions(env, ty::Unnormalized::new_wip(clause)) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let (infcx, param_env) = tcx.infer_ctxt().build_with_typing_env(env);
    let ob = Obligation::new(tcx, ObligationCause::dummy(), param_env, clause);
    infcx.predicate_must_hold_modulo_regions(&ob)
}

/// A file path's components below the crate's `src/` directory.
fn below_src(path: &str) -> Vec<String> {
    match path.rfind("/src/") {
        Some(i) => path[i + 5..].split('/').map(|s| s.to_string()).collect(),
        None => path.split('/').map(|s| s.to_string()).collect(),
    }
}

fn file_of<'tcx>(tcx: TyCtxt<'tcx>, sp: rustc_span::Span) -> (String, usize) {
    let loc = tcx.sess.source_map().lookup_char_pos(sp.lo());
    let name = format!("{}", loc.file.name.prefer_local_unconditionally());
    let name = if std::path::Path::new(&name).is_relative() { std::env::current_dir().map(|d| d.join(&name).display().to_string()).unwrap_or(name) } else { name };
    (name, loc.line)
}

/// The workspace types (RULE.md 3.1 step 1): structs, enums and unions of a
/// workspace crate (a `commonware_*` crate whose sources are under
/// `SBI_REPO`), public and reached from the crate's root through public
/// modules, non-generic, defined outside test, mock and fuzz files. Each
/// with the path it is reached by (nameable) and its full definition path
/// (the seeded order's key).
fn workspace_types<'tcx>(tcx: TyCtxt<'tcx>) -> Vec<(DefId, String, String)> {
    let repo = std::env::var("SBI_REPO").unwrap_or_default();
    let mut out: HashMap<DefId, (String, String)> = HashMap::new();
    let mut roots: Vec<(DefId, String)> = vec![(rustc_hir::def_id::CRATE_DEF_ID.to_def_id(), "crate".to_string())];
    for &cnum in tcx.crates(()) {
        let name = tcx.crate_name(cnum).to_string();
        if name.starts_with("commonware_") {
            roots.push((cnum.as_def_id(), name));
        }
    }
    let local_name = tcx.crate_name(rustc_hir::def_id::LOCAL_CRATE).to_string();
    for (root, rname) in roots {
        let mut seen: HashSet<DefId> = HashSet::new();
        let mut stack = vec![(root, rname.clone())];
        while let Some((m, path)) = stack.pop() {
            if !seen.insert(m) {
                continue;
            }
            let children: Vec<(Res<!>, String, bool)> = if let Some(l) = m.as_local() {
                tcx.module_children_local(l).iter().map(|c| (c.res, c.ident.to_string(), c.vis.is_public())).collect()
            } else {
                tcx.module_children(m).iter().map(|c| (c.res, c.ident.to_string(), c.vis.is_public())).collect()
            };
            for (res, ident, public) in children {
                if !public {
                    continue;
                }
                let Res::Def(kind, did) = res else { continue };
                match kind {
                    DefKind::Mod => stack.push((did, format!("{path}::{ident}"))),
                    DefKind::Struct | DefKind::Enum | DefKind::Union => {
                        if out.contains_key(&did) || tcx.generics_of(did).count() != 0 {
                            continue;
                        }
                        // a workspace crate's own type (not a re-export of a library type)
                        let krate = tcx.crate_name(did.krate).to_string();
                        if !(krate.starts_with("commonware_") || did.is_local()) {
                            continue;
                        }
                        let (file, _) = file_of(tcx, tcx.def_span(did));
                        if !repo.is_empty() && !file.starts_with(&repo) {
                            continue;
                        }
                        let parts = below_src(&file);
                        if parts.iter().any(|p| TEST_PARTS.contains(&p.as_str()) || TEST_PARTS.contains(&p.trim_end_matches(".rs"))) {
                            continue;
                        }
                        let full = rustc_middle::ty::print::with_no_visible_paths!(rustc_middle::ty::print::with_no_trimmed_paths!(tcx.def_path_str(did)));
                        let full = if did.is_local() { format!("{local_name}::{full}") } else { full };
                        out.insert(did, (format!("{path}::{ident}"), full));
                    }
                    _ => {}
                }
            }
        }
    }
    out.into_iter().map(|(d, (p, f))| (d, p, f)).collect()
}

/// One entry of a parameter's list: its argument and how a wrapper names it.
#[derive(Clone)]
struct Choice<'tcx> {
    arg: GenericArg<'tcx>,
    text: String,
    workspace: bool,
}

fn primitives<'tcx>(tcx: TyCtxt<'tcx>) -> Vec<Choice<'tcx>> {
    let vec_of = |t: Ty<'tcx>| -> Option<Ty<'tcx>> {
        let did = tcx.get_diagnostic_item(rustc_span::sym::Vec)?;
        let adt = tcx.adt_def(did);
        // Vec<T, A = Global>
        let global = tcx.lang_items().global_alloc_ty()?;
        let g = Ty::new_adt(tcx, tcx.adt_def(global), ty::List::empty());
        Some(Ty::new_adt(tcx, adt, tcx.mk_args(&[t.into(), g.into()])))
    };
    let string = tcx.lang_items().string().or_else(|| tcx.get_diagnostic_item(rustc_span::sym::String)).map(|d| Ty::new_adt(tcx, tcx.adt_def(d), ty::List::empty()));
    let mut v: Vec<(Option<Ty<'tcx>>, &str)> = vec![
        (Some(tcx.types.u64), "u64"),
        (Some(tcx.types.u32), "u32"),
        (Some(tcx.types.u8), "u8"),
        (Some(tcx.types.usize), "usize"),
        (Some(tcx.types.i64), "i64"),
        (Some(tcx.types.bool), "bool"),
        (Some(tcx.types.unit), "()"),
        (Some(Ty::new_array(tcx, tcx.types.u8, 32)), "[u8; 32]"),
        (vec_of(tcx.types.u8), "Vec<u8>"),
        (vec_of(tcx.types.u64), "Vec<u64>"),
        (string, "String"),
    ];
    v.drain(..).map(|(t, s)| Choice { arg: t.unwrap_or_else(|| panic!("primitive {s} not found")).into(), text: s.to_string(), workspace: false }).collect()
}

fn const_values<'tcx>(tcx: TyCtxt<'tcx>, cty: Ty<'tcx>) -> Vec<Choice<'tcx>> {
    let env = ty::TypingEnv::fully_monomorphized();
    match cty.kind() {
        ty::Int(_) | ty::Uint(_) => [32u128, 1, 8, 64].iter().map(|&n| Choice { arg: ty::Const::from_bits(tcx, n, env, cty).into(), text: n.to_string(), workspace: false }).collect(),
        ty::Bool => [false, true].iter().map(|&b| Choice { arg: ty::Const::from_bool(tcx, b).into(), text: b.to_string(), workspace: false }).collect(),
        ty::Char => vec![Choice { arg: ty::Const::from_bits(tcx, 'a' as u128, env, cty).into(), text: "'a'".into(), workspace: false }],
        _ => vec![],
    }
}

fn run<'tcx>(tcx: TyCtxt<'tcx>) {
    let seed = std::env::var("SBI_SEED").expect("SBI_SEED");
    let input = std::fs::read_to_string(std::env::var("SBI_IN").unwrap()).expect("SBI_IN");
    let out_path = std::env::var("SBI_OUT").expect("SBI_OUT");
    // candidates by (file suffix, line, name)
    let wanted: Vec<(String, String, usize, String)> = input
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f[0].to_string(), f[1].to_string(), f[2].parse().unwrap_or(0), f[3].to_string())
        })
        .collect();
    let mut by_loc: HashMap<(String, usize, String), Vec<DefId>> = HashMap::new();
    for d in tcx.hir_crate_items(()).definitions() {
        let did = d.to_def_id();
        if !matches!(tcx.def_kind(did), DefKind::Fn | DefKind::AssocFn) {
            continue;
        }
        let (file, line) = file_of(tcx, tcx.def_span(did));
        by_loc.entry((file, line, tcx.item_name(did).to_string())).or_default().push(did);
    }
    let mut ws: Vec<(DefId, String, String, String)> = workspace_types(tcx).into_iter().map(|(d, p, f)| {
        let key = sha_hex(&format!("{seed}:instance:{f}"));
        (d, p, f, key)
    }).collect();
    ws.sort_by(|a, b| (a.3.as_str(), a.2.as_str()).cmp(&(b.3.as_str(), b.2.as_str())));
    let prims = primitives(tcx);
    let mut out = String::new();
    let _ = writeln!(out, "{{\"workspace_types\":{}}}", ws.len());
    for (rank, file, line, name) in &wanted {
        let found: Vec<DefId> = by_loc.iter().filter(|((f, l, n), _)| f.ends_with(&format!("/{file}")) && l == line && n == name).flat_map(|(_, v)| v.clone()).collect();
        let Some(&did) = found.first() else {
            let _ = writeln!(out, "{{\"rank\":{rank},\"found\":false}}");
            continue;
        };
        let g = tcx.generics_of(did);
        let preds: Vec<ty::Clause<'tcx>> = tcx.predicates_of(did).instantiate_identity(tcx).predicates.into_iter().map(|c| c.skip_norm_wip()).collect();
        let identity = ty::GenericArgs::identity_for_item(tcx, did);
        // per parameter: its list
        let mut lists: Vec<Vec<Choice<'tcx>>> = Vec::new();
        let mut pinfo = String::new();
        let mut bad: Option<String> = None;
        for i in 0..g.count() {
            let p = g.param_at(i, tcx);
            match p.kind {
                ty::GenericParamDefKind::Lifetime => lists.push(vec![Choice { arg: tcx.lifetimes.re_erased.into(), text: "'_".into(), workspace: false }]),
                ty::GenericParamDefKind::Type { .. } => {
                    if p.name == rustc_span::symbol::kw::SelfUpper {
                        bad = Some("a trait's own item (Self)".into());
                        break;
                    }
                    let own: Vec<ty::Clause<'tcx>> = preds.iter().copied().filter(|c| params_of(c) == vec![p.index]).collect();
                    let traits: Vec<String> = own.iter().filter_map(|c| c.as_trait_clause()).map(|t| tcx.def_path_str(t.skip_binder().def_id())).collect();
                    let mut list = prims.clone();
                    let mut taken = 0;
                    for (wd, wpath, _, _) in &ws {
                        if taken == MAX_WORKSPACE {
                            break;
                        }
                        let wty = tcx.type_of(*wd).instantiate_identity().skip_norm_wip();
                        let args = tcx.mk_args_from_iter(identity.iter().enumerate().map(|(k, a)| if k as u32 == p.index { wty.into() } else { a }));
                        if own.iter().all(|c| holds(tcx, ty::EarlyBinder::bind(*c).instantiate(tcx, args).skip_norm_wip())) {
                            list.push(Choice { arg: wty.into(), text: wpath.clone(), workspace: true });
                            taken += 1;
                        }
                    }
                    let _ = write!(
                        pinfo,
                        "{}{{\"index\":{},\"name\":{},\"kind\":\"type\",\"synthetic\":{},\"traits\":[{}],\"list\":[{}]}}",
                        if pinfo.is_empty() { "" } else { "," },
                        p.index,
                        q(p.name.as_str()),
                        matches!(p.kind, ty::GenericParamDefKind::Type { synthetic: true, .. }),
                        traits.iter().map(|t| q(t)).collect::<Vec<_>>().join(","),
                        list.iter().map(|c| q(&c.text)).collect::<Vec<_>>().join(",")
                    );
                    lists.push(list);
                }
                ty::GenericParamDefKind::Const { .. } => {
                    let cty = tcx.type_of(p.def_id).instantiate_identity().skip_norm_wip();
                    let list = const_values(tcx, cty);
                    let _ = write!(
                        pinfo,
                        "{}{{\"index\":{},\"name\":{},\"kind\":\"const\",\"ty\":{},\"list\":[{}]}}",
                        if pinfo.is_empty() { "" } else { "," },
                        p.index,
                        q(p.name.as_str()),
                        q(&cty.to_string()),
                        list.iter().map(|c| q(&c.text)).collect::<Vec<_>>().join(",")
                    );
                    lists.push(list);
                }
            }
        }
        if let Some(why) = bad {
            let _ = writeln!(out, "{{\"rank\":{rank},\"found\":true,\"skip\":{}}}", q(&why));
            continue;
        }
        // combinations in lexicographic order of the lists (the first parameter slowest)
        let mut idx = vec![0usize; lists.len()];
        let mut checked = 0;
        let mut kept: Vec<Vec<usize>> = Vec::new();
        let empty = lists.iter().any(|l| l.is_empty());
        while !empty && checked < MAX_COMBOS {
            // lifetimes have one entry: only type and const parameters count
            checked += 1;
            let args = tcx.mk_args_from_iter(idx.iter().enumerate().map(|(k, &j)| lists[k][j].arg));
            let ok = preds.iter().all(|c| holds(tcx, ty::EarlyBinder::bind(*c).instantiate(tcx, args).skip_norm_wip()))
                && matches!(ty::Instance::try_resolve(tcx, ty::TypingEnv::fully_monomorphized(), did, args), Ok(Some(_)));
            if ok {
                kept.push(idx.clone());
                if kept.len() == KEEP {
                    break;
                }
            }
            // the next combination (the last parameter fastest); done when every one wraps
            let mut carried = true;
            for k in (0..lists.len()).rev() {
                idx[k] += 1;
                if idx[k] < lists[k].len() {
                    carried = false;
                    break;
                }
                idx[k] = 0;
            }
            if carried {
                break;
            }
        }
        // the kept combinations name the type and const parameters only (as `params` does)
        let is_lt: Vec<bool> = (0..g.count()).map(|i| matches!(g.param_at(i, tcx).kind, ty::GenericParamDefKind::Lifetime)).collect();
        let kept_json: Vec<String> = kept.iter().map(|v| format!("[{}]", v.iter().enumerate().filter(|(k, _)| !is_lt[*k]).map(|(k, &j)| q(&lists[k][j].text)).collect::<Vec<_>>().join(","))).collect();
        let ws_used: Vec<bool> = kept.first().map(|v| v.iter().enumerate().filter(|(k, _)| !is_lt[*k]).map(|(k, &j)| lists[k][j].workspace).collect()).unwrap_or_default();
        let _ = writeln!(
            out,
            "{{\"rank\":{rank},\"found\":true,\"def\":{},\"params\":[{pinfo}],\"checked\":{checked},\"kept\":[{}],\"first_uses_workspace\":[{}]}}",
            q(&tcx.def_path_str(did)),
            kept_json.join(","),
            ws_used.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",")
        );
    }
    std::fs::write(&out_path, out).expect("write SBI_OUT");
}
