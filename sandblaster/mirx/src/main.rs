//! `sandblaster-mirx`: writes rustc's MIR of a lifted module to a `.sbmir`
//! file (sandblaster/front/src/mir/mod.rs is the reader; `docs/mir-lift.md` §20).
//!
//! It runs as cargo's `RUSTC_WORKSPACE_WRAPPER` on the pinned nightly of
//! `rust-toolchain.toml` (rustc-dev: `rustc_public`). For every crate but
//! the one asked for it runs rustc unchanged; for that crate's library it
//! runs rustc with a callback after analysis that
//!
//! 1. instantiates every function of the module (free functions, inherent
//!    and trait-impl methods) at the impl types of the **sealed** traits
//!    bounding its type parameters (a local trait all of whose impls are
//!    local: rustc's coherence and privacy make that set exact), minus the
//!    types named by `SBMIR_EXCLUDE`; a parameter bounded by the host
//!    buffer traits (`Buf`, `BufMut`) is instantiated at `&[u8]` /
//!    `&mut [u8]` (the reader never looks at that type: it reads the calls
//!    of the buffer traits as the buffer model, whatever the receiver); a
//!    parameter bounded by an open trait is instantiated at its declared
//!    instance (`SBMIR_INSTANCE`), the trait's provided methods are
//!    extracted at that instance, and `SBMIR_ITEMS`/`SBMIR_SKIP_FNS` keep
//!    only the items the lift lifts;
//! 2. takes each instance's MIR from rustc (`Instance::body`: rustc's
//!    optimized MIR, monomorphized, constants evaluated), and follows its
//!    calls: an instance of the module, a closure, or a library function
//!    with a body is extracted too (to a depth bound); the calls the reader
//!    treats as leaves (the buffer traits, indexing of arrays and slices,
//!    `Vec::push`, an open trait's methods at a library instance, intrinsics,
//!    functions returning `!`) are recorded, not followed;
//! 3. prints everything as S-expressions (`.sbmir`), with the source
//!    files' SHA-256 and the compiler's version, so a stale extraction is
//!    refused by the reader.
//!
//! For the extracted crate's build script it compiles a stub instead
//! (`SBMIR_STUB="out.rs=src.rs,.."`: write each source file minus its
//! leading `//!` lines to `OUT_DIR/out.rs`, which is what `compile_module`
//! emits), because the real one verifies with the stable toolchain.
//!
//! This program is part of the trusted base of the MIR path (it prints
//! rustc's data; a misprint is a misreading): it is plain transcription,
//! and every construct it does not print is written `(unsupported "..")`,
//! which the reader refuses.
#![feature(rustc_private)]

extern crate rustc_driver;
extern crate rustc_interface;
extern crate rustc_middle;
extern crate rustc_span;
extern crate rustc_hir;
extern crate rustc_session;
extern crate rustc_abi;
extern crate rustc_target;
extern crate rustc_public;
extern crate sha2;
extern crate rustc_public_bridge;

use rustc_public_bridge::IndexedVal;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt::Write as _;
use std::ops::ControlFlow;

use rustc_public::mir::mono::{Instance, InstanceKind};
use rustc_public::mir::*;
use rustc_public::ty::{AdtDef, AdtKind, ConstantKind, GenericArgKind, GenericArgs, IntTy, MirConst, RigidTy, Ty, TyConst, TyConstKind, TyKind, UintTy};
use rustc_public::{CrateDef, CrateDefType};

/// The `.sbmir` format version.
const FORMAT: u32 = 1;
/// Depth bound for following library calls.
const MAX_DEPTH: usize = 8;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("sandblaster-mirx: run as RUSTC_WORKSPACE_WRAPPER (see sandblaster/mirx/README.md)");
        std::process::exit(2);
    }
    let rustc = &args[1];
    let rest = &args[2..];
    let crate_name = rest.iter().position(|a| a == "--crate-name").map(|i| rest[i + 1].clone()).unwrap_or_default();
    let want = std::env::var("SBMIR_CRATE").unwrap_or_default();
    let pkg = std::env::var("CARGO_PKG_NAME").ok().map(|n| n.replace('-', "_")).unwrap_or_default();
    if crate_name == "build_script_build" {
        // the extracted crate's build script, and those of the workspace
        // crates it depends on that verify with sandblaster
        // (`SBMIR_STUBS="crate:out.rs=src.rs;crate2:"`), are stubs
        if pkg == want {
            stub_build_script(rustc, rest, &std::env::var("SBMIR_STUB").unwrap_or_default());
        }
        for entry in std::env::var("SBMIR_STUBS").unwrap_or_default().split(';').filter(|e| !e.is_empty()) {
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
    // lints change no MIR: a denied lint must not stop the extraction
    if !rest.iter().any(|a| a.starts_with("--cap-lints")) {
        dargs.extend(["--cap-lints".to_string(), "warn".to_string()]);
    }
    // the MIR optimization level is pinned (`SBMIR_MIR_OPT_LEVEL`, by default
    // 1, `cargo check`'s own) and recorded; the build refuses another
    // (`docs/mir-lift.md` §20.1). Last on the command line, so it wins.
    let level = std::env::var("SBMIR_MIR_OPT_LEVEL").unwrap_or_else(|_| "1".into());
    if level.parse::<u8>().is_err() {
        eprintln!("sandblaster-mirx: SBMIR_MIR_OPT_LEVEL={level:?} is no MIR optimization level");
        std::process::exit(2);
    }
    dargs.push(format!("-Zmir-opt-level={level}"));
    let mut cb = Driver { done: false };
    let ran = rustc_driver::catch_fatal_errors(|| rustc_driver::run_compiler(&dargs, &mut cb));
    if ran.is_err() || !cb.done {
        eprintln!("sandblaster-mirx: the compilation failed before the extraction");
        std::process::exit(1);
    }
}

/// The driver's callbacks: the injected modules (`SBMIR_INJECT`) and the
/// extraction after analysis.
struct Driver {
    done: bool,
}

impl rustc_driver::Callbacks for Driver {
    fn config(&mut self, config: &mut rustc_interface::interface::Config) {
        let root = match &config.input {
            rustc_session::config::Input::File(p) => Some(p.clone()),
            _ => None,
        };
        config.file_loader = Some(Box::new(Sources { root }));
    }

    fn after_analysis<'tcx>(&mut self, _c: &rustc_interface::interface::Compiler, tcx: rustc_middle::ty::TyCtxt<'tcx>) -> rustc_driver::Compilation {
        rustc_public::rustc_internal::run(tcx, || {
            let _ = extract(tcx);
        })
        .expect("rustc_public");
        self.done = true;
        rustc_driver::Compilation::Continue
    }
}

/// The file loader: every file as it is on disk, except the crate root,
/// which gets `mod name;` of each `SBMIR_INJECT="name=path,.."` file (a DSL
/// module compiled in the crate's context: the verifier's `instances.rs`).
/// Nothing else is changed.
struct Sources {
    root: Option<std::path::PathBuf>,
}

impl rustc_span::source_map::FileLoader for Sources {
    fn file_exists(&self, path: &std::path::Path) -> bool {
        path.exists()
    }

    fn read_file(&self, path: &std::path::Path) -> std::io::Result<String> {
        let mut text = std::fs::read_to_string(path)?;
        let canon = |p: &std::path::Path| std::fs::canonicalize(p).ok();
        if self.root.as_deref().and_then(canon).is_some_and(|r| Some(r) == canon(path)) {
            for e in std::env::var("SBMIR_INJECT").unwrap_or_default().split(',').filter(|e| !e.is_empty()) {
                let (name, file) = e.split_once('=').expect("SBMIR_INJECT: name=path");
                let _ = write!(text, "\n#[path = {file:?}]\n#[allow(dead_code, unused)]\npub(crate) mod {name};\n");
            }
        }
        Ok(text)
    }

    fn read_binary_file(&self, path: &std::path::Path) -> std::io::Result<std::sync::Arc<[u8]>> {
        std::fs::read(path).map(Into::into)
    }

    fn current_directory(&self) -> std::io::Result<std::path::PathBuf> {
        std::env::current_dir()
    }
}

fn stub_build_script(rustc: &str, rest: &[String], stub: &str) -> ! {
    let mut body = String::from("#![allow(warnings)]\nfn main() {\n    let out = std::env::var(\"OUT_DIR\").unwrap();\n");
    for pair in stub.split(',').filter(|p| !p.is_empty()) {
        let (o, src) = pair.split_once('=').expect("SBMIR_STUB: out.rs=src.rs");
        let _ = writeln!(
            body,
            "    {{ let t = std::fs::read_to_string({src:?}).unwrap(); let t: String = t.lines().skip_while(|l| l.starts_with(\"//!\")).map(|l| format!(\"{{l}}\\n\")).collect(); std::fs::write(std::path::Path::new(&out).join({o:?}), t).unwrap(); }}"
        );
    }
    body.push_str("}\n");
    let dir = std::env::temp_dir().join(format!("sbmir-stub-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("stub dir");
    let f = dir.join("build.rs");
    std::fs::write(&f, body).expect("stub");
    let args: Vec<String> = rest.iter().map(|a| if a.ends_with("build.rs") { f.display().to_string() } else { a.clone() }).collect();
    let st = std::process::Command::new(rustc).args(&args).status().expect("run rustc");
    std::process::exit(st.code().unwrap_or(1));
}

/// Where the reader finds a function's source: the stub's `OUT_DIR` copy
/// is the source file minus its leading `//!` lines.
struct SpanMap {
    /// `(OUT_DIR file name, source path as given, doc lines skipped)`.
    stubs: Vec<(String, String, usize)>,
    /// Source files met, path relative to the crate → SHA-256.
    files: BTreeMap<String, String>,
    /// The crate's manifest directory (paths are printed relative to it).
    manifest: String,
}

impl SpanMap {
    fn new() -> SpanMap {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        let mut stubs = Vec::new();
        for pair in std::env::var("SBMIR_STUB").unwrap_or_default().split(',').filter(|p| !p.is_empty()) {
            if let Some((o, src)) = pair.split_once('=') {
                let text = std::fs::read_to_string(src).unwrap_or_default();
                let skipped = text.lines().take_while(|l| l.starts_with("//!")).count();
                stubs.push((o.to_string(), src.to_string(), skipped));
            }
        }
        SpanMap { stubs, files: BTreeMap::new(), manifest }
    }

    /// `(file, line, col)` of a span, the file relative to the crate;
    /// `None` outside the crate's own files.
    fn loc(&mut self, sp: rustc_public::ty::Span) -> Option<(String, usize, usize)> {
        let f = sp.get_filename();
        // rustc names the package's files relative to the workspace root (cargo's cwd)
        let f = if std::path::Path::new(&f).is_relative() { std::env::current_dir().map(|d| d.join(&f).display().to_string()).unwrap_or(f) } else { f };
        let li = sp.get_lines();
        // a dummy span (compiler-made code) has no source position
        if li.start_line == 0 {
            return None;
        }
        let (path, line) = match self.stubs.iter().find(|(o, _, _)| f.ends_with(&format!("/out/{o}"))) {
            Some((_, src, skipped)) => (src.clone(), li.start_line + skipped),
            None if !self.manifest.is_empty() && f.starts_with(&format!("{}/", self.manifest)) => (f.clone(), li.start_line),
            None => return None,
        };
        let rel = path.strip_prefix(&format!("{}/", self.manifest)).unwrap_or(&path).to_string();
        if !self.files.contains_key(&rel) {
            let text = std::fs::read(&path).unwrap_or_default();
            use sha2::Digest;
            let h = sha2::Sha256::digest(&text);
            let hex: String = h.iter().map(|b| format!("{b:02x}")).collect();
            self.files.insert(rel.clone(), hex);
        }
        Some((rel, line, li.start_col))
    }
}

fn q(s: &str) -> String {
    format!("{s:?}")
}

/// Extraction state.
struct Ex<'tcx> {
    tcx: rustc_middle::ty::TyCtxt<'tcx>,
    /// The locals of the body being printed (for place types).
    cur_locals: Vec<LocalDecl>,
    spans: SpanMap,
    queue: VecDeque<(Instance, &'static str, usize)>,
    seen: BTreeSet<String>,
    adts: BTreeMap<String, (AdtDef, GenericArgs)>,
    notes: Vec<String>,
    /// The constant items of the body being printed, by span ([`Ex::provenance`]).
    prov: HashMap<rustc_span::Span, Option<(String, String, bool)>>,
    /// Open traits declared at a library type (`SBMIR_INSTANCE`): a host
    /// model (`commonware_cryptography::Hasher` at `Sha256`) or a model of
    /// core (`Iterator` at `Copied<slice::Iter<&[u8]>>`). Their methods
    /// called at that type are leaves, read by the reader's model.
    models: Vec<(String, Ty)>,
}

fn inst_key(i: &Instance) -> String {
    stable_names(&i.name())
}

/// rustc prints a closure type as `{closure@<file>:<line>:<col>: ..}` with
/// the file's full path (the build's `OUT_DIR`): keep its base name, so the
/// extraction does not depend on where it ran.
fn stable_names(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("{closure@") {
        out.push_str(&rest[..i + "{closure@".len()]);
        rest = &rest[i + "{closure@".len()..];
        let end = rest.find(':').unwrap_or(0);
        let path = &rest[..end];
        out.push_str(path.rsplit('/').next().unwrap_or(path));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn extract<'tcx>(tcx: rustc_middle::ty::TyCtxt<'tcx>) -> ControlFlow<(), ()> {
    use rustc_middle::ty::{self as mty, TypingEnv};
    let module = std::env::var("SBMIR_MODULE").expect("SBMIR_MODULE");
    let exclude: Vec<String> = std::env::var("SBMIR_EXCLUDE").unwrap_or_default().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let out_path = std::env::var("SBMIR_OUT").expect("SBMIR_OUT");
    // `SBMIR_ITEMS="merkle::proof=Subtree,ReconstructionError;.."`: in that
    // module only these items (structs, enums, traits, functions) and the
    // impls whose self type is one of them; `SBMIR_SKIP_FNS="Type::m,.."`
    let items: Vec<(String, Vec<String>)> = std::env::var("SBMIR_ITEMS").unwrap_or_default().split(';').filter_map(|e| e.split_once('=')).map(|(m, l)| (format!("{}::{}", rustc_public::local_crate().name, m.trim()), l.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())).collect();
    let skip_fns: Vec<String> = std::env::var("SBMIR_SKIP_FNS").unwrap_or_default().split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let skip_traits: Vec<String> = std::env::var("SBMIR_SKIP_TRAITS").unwrap_or_else(|_| "Debug,Display,Hash,PartialOrd,Ord".into()).split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let krate = rustc_public::local_crate();
    // one module, or several (`a,b::c`): calls between them are calls by name
    let prefixes: Vec<String> = module.split(',').map(|m| format!("{}::{}", krate.name, m.trim())).collect();
    let prefix = prefixes.join(", ");
    let pfxs = prefixes.clone();
    let in_module = move |p: &str| {
        pfxs.iter().any(|pfx| p == pfx || p.starts_with(&format!("{pfx}::")) || p.starts_with(&format!("<{pfx}::")) || p.contains(&format!(" as {pfx}::")) || p.contains(&format!(" for {pfx}::")))
    };
    // open traits read at one declared instance (SEMANTICS.md §19.6):
    // `SBMIR_INSTANCE="Family=merkle::mmr::Family,.."` (paths in the crate).
    // A trait named by one word matches by its last segment, a path by the
    // trait's whole path; the instance is a struct, an enum or a type alias
    // of the crate (an alias names a concrete instance: a generic struct at
    // its arguments, or a library type)
    let instances: Vec<(String, String)> = std::env::var("SBMIR_INSTANCE").unwrap_or_default().split(',').filter_map(|p| p.split_once('=').map(|(a, b)| (a.trim().to_string(), format!("{}::{}", krate.name, b.trim())))).collect();
    let mut inst_tys: Vec<(String, mty::Ty<'_>)> = Vec::new();
    let mut early_notes: Vec<String> = Vec::new();
    for (t, inst) in &instances {
        let local = inst.trim_start_matches(&format!("{}::", krate.name));
        let found = tcx.hir_crate_items(()).definitions().map(|d| d.to_def_id()).find(|d| tcx.def_path_str(*d) == local && matches!(tcx.def_kind(*d), rustc_hir::def::DefKind::Struct | rustc_hir::def::DefKind::Enum | rustc_hir::def::DefKind::TyAlias));
        match found {
            Some(d) => inst_tys.push((t.clone(), tcx.type_of(d).instantiate_identity().skip_norm_wip())),
            None => early_notes.push(format!("SBMIR_INSTANCE: no struct, enum or type alias `{inst}` for `{t}`")),
        }
    }
    let inst_of = |tpath: &str| inst_tys.iter().find(|(t, _)| trait_matches(t, tpath)).map(|(_, ty)| *ty);

    // sealed traits: traits of the module whose impls are all local, with
    // their impl self types (a trait read at a declared instance is not)
    let mut sealed: HashMap<rustc_span::def_id::DefId, Vec<mty::Ty<'_>>> = HashMap::new();
    for t in krate.trait_decls() {
        if !in_module(&t.name()) {
            continue;
        }
        let tid = rustc_public::rustc_internal::internal(tcx, t.def_id());
        if inst_of(&tcx.def_path_str(tid)).is_some() {
            continue;
        }
        let mut tys = Vec::new();
        let mut all_local = true;
        for imp in tcx.all_impls(tid) {
            if !imp.is_local() {
                all_local = false;
            }
            tys.push(tcx.type_of(imp).instantiate_identity().skip_norm_wip());
        }
        if all_local {
            sealed.insert(tid, tys);
        }
    }
    let slice_u8 = mty::Ty::new_slice(tcx, tcx.types.u8);
    let buf = mty::Ty::new_imm_ref(tcx, tcx.lifetimes.re_erased, slice_u8);
    let bufmut = mty::Ty::new_mut_ref(tcx, tcx.lifetimes.re_erased, slice_u8);

    let models: Vec<(String, Ty)> = inst_tys.iter().filter(|(_, ty)| !ty.ty_adt_def().is_some_and(|d| d.did().is_local())).map(|(t, ty)| (t.clone(), rustc_public::rustc_internal::stable(*ty))).collect();
    let mut ex = Ex { tcx, cur_locals: Vec::new(), spans: SpanMap::new(), queue: VecDeque::new(), seen: BTreeSet::new(), adts: BTreeMap::new(), notes: early_notes, prov: HashMap::new(), models };
    let mut roots: Vec<String> = Vec::new();
    for f in krate.fn_defs() {
        let name = f.name();
        if !in_module(&name) {
            continue;
        }
        let did = rustc_public::rustc_internal::internal(tcx, f.def_id());
        if tcx.is_closure_like(did) {
            continue;
        }
        // impls of the traits the lift leaves out (their code is host-only)
        if let Some(imp) = tcx.impl_of_assoc(did)
            && let Some(tr) = tcx.impl_opt_trait_ref(imp)
        {
            let tname = tcx.item_name(tr.skip_binder().def_id).to_string();
            if skip_traits.contains(&tname) {
                ex.notes.push(format!("{name}: not extracted: an impl of `{tname}` (SBMIR_SKIP_TRAITS)"));
                continue;
            }
        }
        if mentions_excluded(&name, &exclude) {
            continue;
        }
        // the items asked for (`SBMIR_ITEMS`) minus the functions left to the
        // host (`SBMIR_SKIP_FNS`), as the lift's `items`/`unverified_fns`
        if let Some(why) = left_out(tcx, did, &items, &skip_fns) {
            ex.notes.push(format!("{name}: not extracted: {why}"));
            continue;
        }
        let g = tcx.generics_of(did);
        let preds = tcx.predicates_of(did).instantiate_identity(tcx);
        let mut choices: Vec<Vec<mty::GenericArg<'_>>> = Vec::new();
        let mut skip: Option<String> = None;
        for i in 0..g.count() {
            let p = g.param_at(i, tcx);
            match p.kind {
                mty::GenericParamDefKind::Lifetime => choices.push(vec![tcx.lifetimes.re_erased.into()]),
                mty::GenericParamDefKind::Type { .. } => {
                    if p.name == rustc_span::symbol::kw::SelfUpper {
                        // a provided method of an open trait read at its
                        // declared instance: at that instance
                        let inst = tcx.trait_of_assoc(did).and_then(|tr| inst_of(&tcx.def_path_str(tr)));
                        match inst {
                            Some(ty) if tcx.defaultness(did).has_value() => {
                                choices.push(vec![ty.into()]);
                                continue;
                            }
                            _ => {
                                skip = Some("a trait's own method (its impls are extracted)".into());
                                break;
                            }
                        }
                    }
                    let pty = mty::Ty::new_param(tcx, p.index, p.name);
                    let mut opts: Option<Vec<mty::Ty<'_>>> = None;
                    for (clause, _) in preds.predicates.iter().zip(preds.spans.iter()) {
                        let Some(tp) = clause.as_trait_clause() else { continue };
                        let tp = tp.skip_binder();
                        if tp.self_ty() != pty {
                            continue;
                        }
                        let tpath = tcx.def_path_str(tp.def_id());
                        if let Some(tys) = sealed.get(&tp.def_id()) {
                            opts = Some(tys.iter().copied().filter(|t| !exclude.contains(&t.to_string())).collect());
                            break;
                        }
                        if let Some(ty) = inst_of(&tpath) {
                            opts = Some(vec![ty]);
                            break;
                        }
                        if tpath.ends_with("BufMut") {
                            opts = Some(vec![bufmut]);
                            break;
                        }
                        if tpath.ends_with("::Buf") || tpath == "Buf" {
                            opts = Some(vec![buf]);
                            break;
                        }
                    }
                    match opts {
                        Some(o) => choices.push(o.into_iter().map(|t| t.into()).collect()),
                        None => {
                            skip = Some(format!("type parameter `{}` has no sealed or buffer bound", p.name));
                            break;
                        }
                    }
                }
                mty::GenericParamDefKind::Const { .. } => {
                    skip = Some("const generic".into());
                    break;
                }
            }
        }
        if let Some(why) = skip {
            ex.notes.push(format!("{name}: not instantiated: {why}"));
            continue;
        }
        let mut combos: Vec<Vec<mty::GenericArg<'_>>> = vec![vec![]];
        for c in &choices {
            let mut next = Vec::new();
            for pre in &combos {
                for a in c {
                    let mut v = pre.clone();
                    v.push(*a);
                    next.push(v);
                }
            }
            combos = next;
        }
        // an impl of a local open trait for another type than its declared
        // instance (a reference, a blanket impl, another type) is another
        // instance: host code (SEMANTICS.md §19.6, §19.10)
        let other_instance = |args: rustc_middle::ty::GenericArgsRef<'tcx>| -> bool {
            let Some(imp) = tcx.impl_of_assoc(did) else { return false };
            let Some(tr) = tcx.impl_opt_trait_ref(imp) else { return false };
            let tid = tr.skip_binder().def_id;
            let Some(ity) = (if tid.is_local() { inst_of(&tcx.def_path_str(tid)) } else { None }) else { return false };
            let st = tcx.type_of(imp).instantiate(tcx, args).skip_norm_wip();
            tcx.erase_and_anonymize_regions(st) != tcx.erase_and_anonymize_regions(ity)
        };
        for args in combos {
            let args = tcx.mk_args(&args);
            if other_instance(args) {
                ex.notes.push(format!("{name}: not extracted: an impl of an open trait for another type than its declared instance"));
                continue;
            }
            match mty::Instance::try_resolve(tcx, TypingEnv::fully_monomorphized(), did, args) {
                Ok(Some(inst)) => {
                    let si: Instance = rustc_public::rustc_internal::stable(inst);
                    if mentions_excluded(&inst_key(&si), &exclude) {
                        continue;
                    }
                    roots.push(inst_key(&si));
                    ex.queue.push_back((si, "root", 0));
                }
                other => ex.notes.push(format!("{name}: does not resolve at {args:?}: {other:?}")),
            }
        }
    }

    let mut fns = String::new();
    while let Some((inst, why, depth)) = ex.queue.pop_front() {
        let key = inst_key(&inst);
        if !ex.seen.insert(key.clone()) {
            continue;
        }
        let text = ex.function(&inst, why, depth, &in_module);
        fns.push_str(&text);
    }

    let mut out = String::new();
    let _ = writeln!(out, ";; rustc's MIR of `{prefix}`, written by sandblaster-mirx: do not edit (re-run the extraction)");
    let _ = writeln!(out, "(sbmir {FORMAT})");
    let _ = writeln!(out, "(rustc {})", q(&rustc_version()));
    let _ = writeln!(out, "(crate {})", q(&krate.name));
    let _ = writeln!(out, "(module {})", q(&prefix));
    let _ = writeln!(out, "(overflow-checks {})", if tcx.sess.overflow_checks() { "on" } else { "off" });
    // the MIR optimization passes that ran (what the MIR is the image of)
    let _ = writeln!(out, "(mir-opt-level {})", tcx.sess.mir_opt_level());
    // the target the MIR was built for (its `core::arch` and `cfg(target_*)`
    // code is that target's): the build refuses MIR of another architecture
    let _ = writeln!(out, "(target {} {})", q(&tcx.sess.target.llvm_target), q(&tcx.sess.target.arch.to_string()));
    // the reading of existing `unsafe` (docs/DESIGN-UNSAFE-SIMD.md): this
    // printer writes raw pointer types, `&raw`, pointer casts, each
    // function's `unsafe` and locality, and the target's static facts
    let _ = writeln!(out, "(unsafe-reading 1)");
    // the statically enabled target features (`cfg(target_feature)`, as the
    // build's `CARGO_CFG_TARGET_FEATURE` lists them), the byte order, and
    // the flags they come from (`-C target-cpu`, `-C target-feature`): the
    // build refuses an extraction whose features are not its own
    // (the stable ones: the nightly's `cfg` also lists unstable features,
    // which the stable build's `CARGO_CFG_TARGET_FEATURE` leaves out)
    let stable: BTreeSet<&str> = tcx.sess.target.rust_target_features().iter().filter(|(_, s, _)| matches!(s, rustc_target::target_features::Stability::Stable)).map(|(n, _, _)| *n).collect();
    let mut statics: Vec<String> = tcx.sess.target_features.iter().map(|f| f.to_string()).filter(|f| stable.contains(f.as_str())).collect();
    statics.sort();
    let _ = writeln!(out, "(target-static-features{})", statics.iter().map(|f| format!(" {}", q(f))).collect::<String>());
    let _ = writeln!(out, "(endian {})", tcx.sess.target.endian.as_str());
    let _ = writeln!(out, "(target-cpu {} {})", tcx.sess.opts.cg.target_cpu.as_deref().map(q).unwrap_or_else(|| "default".into()), q(&tcx.sess.target.cpu));
    let _ = writeln!(out, "(target-feature-flags {})", q(&tcx.sess.opts.cg.target_feature));
    let _ = writeln!(out, "(exclude{})", exclude.iter().map(|e| format!(" {}", q(e))).collect::<String>());
    for (f, h) in &ex.spans.files {
        let _ = writeln!(out, "(source {} {})", q(f), q(h));
    }
    for r in &roots {
        let _ = writeln!(out, "(root {})", q(r));
    }
    for n in &ex.notes {
        let _ = writeln!(out, "(note {})", q(n));
    }
    // ADT definitions (the field types may add more ADTs: iterate to a fixpoint)
    let mut done: BTreeSet<String> = BTreeSet::new();
    loop {
        let todo: Vec<(String, (AdtDef, GenericArgs))> = ex.adts.iter().filter(|(k, _)| !done.contains(*k)).map(|(k, v)| (k.clone(), v.clone())).collect();
        if todo.is_empty() {
            break;
        }
        for (k, (def, args)) in todo {
            done.insert(k.clone());
            let text = ex.adt_def(&k, def, &args);
            out.push_str(&text);
        }
    }
    out.push_str(&fns);
    std::fs::write(&out_path, out).expect("write .sbmir");
    eprintln!("sandblaster-mirx: wrote {out_path} ({} functions, {} roots)", ex.seen.len(), roots.len());
    ControlFlow::Continue(())
}

/// Whether a trait at path `tpath` is the one `SBMIR_INSTANCE` names by
/// `key`: one word is the trait's last segment, a path its whole path.
fn trait_matches(key: &str, tpath: &str) -> bool {
    if key.contains("::") { tpath == key || tpath.ends_with(&format!("::{key}")) } else { tpath.rsplit("::").next() == Some(key) }
}

/// Why the function `did` is left out by `SBMIR_ITEMS` / `SBMIR_SKIP_FNS`
/// (`None`: extracted). Its item is the self type of its impl (an ADT; an
/// impl for any other type is no item), the trait it is declared in, or
/// itself.
fn left_out(tcx: rustc_middle::ty::TyCtxt<'_>, did: rustc_span::def_id::DefId, items: &[(String, Vec<String>)], skip_fns: &[String]) -> Option<String> {
    let item = match (tcx.impl_of_assoc(did), tcx.trait_of_assoc(did)) {
        (Some(imp), _) => match tcx.type_of(imp).instantiate_identity().skip_norm_wip().kind() {
            rustc_middle::ty::TyKind::Adt(d, _) => Some(d.did()),
            _ => None,
        },
        (None, Some(tr)) => Some(tr),
        (None, None) => Some(did),
    };
    let item_name = item.map(|d| tcx.item_name(d).to_string());
    if let Some(n) = &item_name
        && item != Some(did)
        && skip_fns.iter().any(|s| *s == format!("{n}::{}", tcx.item_name(did)))
    {
        return Some("a host function (SBMIR_SKIP_FNS)".into());
    }
    let module = format!("{}::{}", tcx.crate_name(rustc_span::def_id::LOCAL_CRATE), tcx.def_path_str(tcx.parent_module_from_def_id(did.as_local()?).to_def_id()));
    let (_, list) = items.iter().find(|(m, _)| *m == module)?;
    match item_name {
        Some(n) if list.contains(&n) => None,
        _ => Some("not among the items asked for (SBMIR_ITEMS)".into()),
    }
}

/// Whether a path names an excluded type as a whole word (`u128` in
/// `<u128 as Tr>::m`, `UInt<u128>`).
fn mentions_excluded(path: &str, exclude: &[String]) -> bool {
    path.split(|c: char| !c.is_alphanumeric() && c != '_').any(|w| exclude.iter().any(|e| e == w))
}

fn rustc_version() -> String {
    format!("rustc {}", rustc_interface::util::rustc_version_str().unwrap_or("unknown"))
}

impl<'tcx> Ex<'tcx> {
    fn function(&mut self, inst: &Instance, why: &'static str, depth: usize, in_module: &dyn Fn(&str) -> bool) -> String {
        let key = inst_key(inst);
        let mut s = String::new();
        let _ = writeln!(s, "(fn {}", q(&key));
        let a = if key.contains("{closure") { "()".to_string() } else { self.args(&inst.args()) };
        let _ = writeln!(s, "  (kind {why}) (def {}) (args {a})", q(&inst.def.name()));
        let item = self.item(inst, in_module);
        let _ = writeln!(s, "  {item}");
        if let Some((f, l, c)) = self.spans.loc(inst.def.span()) {
            let _ = writeln!(s, "  (span {} {l} {c})", q(&f));
        }
        // a function of the extracted crate (`local`; the narrow reading of
        // pointers applies to crate code only), and a declared `unsafe fn`
        // (`unsafe`; a call from crate code to a library one outside the
        // admitted pointer operations is refused)
        let (local, unsafe_fn) = self.fn_marks(inst);
        if local {
            let _ = writeln!(s, "  (local)");
        }
        if unsafe_fn {
            let _ = writeln!(s, "  (unsafe)");
        }
        // the target features rustc compiles the body with (its own
        // `#[target_feature]` and what they imply; a closure's inherited):
        // a call of a `core::arch` intrinsic needs the intrinsic's
        if let Some(fs) = self.fn_features(inst)
            && !fs.is_empty()
        {
            let _ = writeln!(s, "  (target-features{})", fs.iter().map(|f| format!(" {}", q(f))).collect::<String>());
        }
        let Some(body) = inst.body() else {
            let _ = writeln!(s, "  (nobody))");
            return s;
        };
        self.cur_locals = body.locals().to_vec();
        self.provenance(inst);
        let _ = writeln!(s, "  (argc {})", body.arg_locals().len());
        if let Some(sa) = body.spread_arg() {
            let _ = writeln!(s, "  (spread-arg {sa})");
        }
        let _ = write!(s, "  (locals");
        for (i, l) in body.locals().iter().enumerate() {
            let t = self.ty(l.ty);
            let _ = write!(s, "\n    ({i} {t} {})", if matches!(l.mutability, Mutability::Mut) { "mut" } else { "imm" });
        }
        let _ = writeln!(s, ")");
        for d in &body.var_debug_info {
            match &d.value {
                VarDebugInfoContents::Place(p) if d.composite.is_none() => {
                    let pl = self.place(p);
                    let _ = writeln!(s, "  (debug {} {pl}{})", q(&d.name), d.argument_index.map(|a| format!(" (arg {a})")).unwrap_or_default());
                }
                _ => {
                    let _ = writeln!(s, "  (debug-other {})", q(&d.name));
                }
            }
        }
        for (bi, bb) in body.blocks.iter().enumerate() {
            let _ = writeln!(s, "  (bb {bi}");
            for st in &bb.statements {
                if let Some(t) = self.stmt(st) {
                    let _ = writeln!(s, "    {t}");
                }
            }
            let t = self.term(&bb.terminator, depth, in_module);
            let _ = writeln!(s, "    {t})");
        }
        s.push_str(")\n");
        s
    }

    /// What the instance is in the source: a free function, an inherent
    /// method (with its self type), a trait-impl method (self type, trait,
    /// trait arguments), a closure or a compiler shim.
    fn item(&mut self, inst: &Instance, in_module: &dyn Fn(&str) -> bool) -> String {
        let tcx = self.tcx;
        if matches!(inst.kind, InstanceKind::Shim) {
            return "(item shim)".into();
        }
        let ii = rustc_public::rustc_internal::internal(tcx, inst.clone());
        let did = ii.def_id();
        if tcx.is_closure_like(did) {
            return "(item closure)".into();
        }
        let name = tcx.item_name(did).to_string();
        match tcx.impl_of_assoc(did) {
            Some(imp) => {
                let st = tcx.type_of(imp).instantiate(tcx, ii.args).skip_norm_wip();
                let sts: Ty = rustc_public::rustc_internal::stable(st);
                let sty = self.ty(sts);
                match tcx.impl_opt_trait_ref(imp) {
                    Some(tr) => {
                        let tr = tr.instantiate(tcx, ii.args).skip_norm_wip();
                        let tname = tcx.item_name(tr.def_id).to_string();
                        let mut targs = Vec::new();
                        for a in tr.args.iter().skip(1) {
                            if let Some(t) = a.as_type() {
                                let t: Ty = rustc_public::rustc_internal::stable(t);
                                targs.push(self.ty(t));
                            }
                        }
                        format!("(item impl {sty} {} ({}) {})", q(&tname), targs.join(" "), q(&name))
                    }
                    None => format!("(item inherent {sty} {})", q(&name)),
                }
            }
            None => match tcx.trait_of_assoc(did) {
                // a provided method of a trait of the module at its instance
                Some(tr) if in_module(&tcx.def_path_str(tr)) || in_module(&format!("{}::{}", tcx.crate_name(rustc_span::def_id::LOCAL_CRATE), tcx.def_path_str(tr))) => {
                    let st: Ty = rustc_public::rustc_internal::stable(ii.args.type_at(0));
                    let sty = self.ty(st);
                    let mut targs = Vec::new();
                    for a in ii.args.iter().skip(1).take(tcx.generics_of(tr).count() - 1) {
                        if let Some(t) = a.as_type() {
                            let t: Ty = rustc_public::rustc_internal::stable(t);
                            targs.push(self.ty(t));
                        }
                    }
                    format!("(item provided {sty} {} ({}) {})", q(&tcx.item_name(tr).to_string()), targs.join(" "), q(&name))
                }
                _ => format!("(item fn {})", q(&name)),
            },
        }
    }

    fn at(&mut self, sp: rustc_public::ty::Span) -> String {
        match self.spans.loc(sp) {
            Some((f, l, c)) => format!(" (at {} {l} {c})", q(&f)),
            None => String::new(),
        }
    }

    fn args(&mut self, a: &GenericArgs) -> String {
        let mut parts = Vec::new();
        for k in &a.0 {
            match k {
                GenericArgKind::Lifetime(_) => {}
                GenericArgKind::Type(t) => parts.push(self.ty(*t)),
                GenericArgKind::Const(c) => parts.push(self.tyconst(c)),
            }
        }
        format!("({})", parts.join(" "))
    }

    fn tyconst(&mut self, c: &TyConst) -> String {
        match c.eval_target_usize() {
            Ok(n) => format!("{n}"),
            Err(_) => format!("(unsupported {})", q(&format!("const {c:?}"))),
        }
    }

    fn ty(&mut self, t: Ty) -> String {
        match t.kind() {
            TyKind::RigidTy(r) => match r {
                RigidTy::Bool => "bool".into(),
                RigidTy::Char => "char".into(),
                RigidTy::Int(i) => match i {
                    IntTy::Isize => "isize",
                    IntTy::I8 => "i8",
                    IntTy::I16 => "i16",
                    IntTy::I32 => "i32",
                    IntTy::I64 => "i64",
                    IntTy::I128 => "i128",
                }
                .into(),
                RigidTy::Uint(u) => match u {
                    UintTy::Usize => "usize",
                    UintTy::U8 => "u8",
                    UintTy::U16 => "u16",
                    UintTy::U32 => "u32",
                    UintTy::U64 => "u64",
                    UintTy::U128 => "u128",
                }
                .into(),
                RigidTy::Str => "str".into(),
                RigidTy::Never => "never".into(),
                RigidTy::Tuple(ts) => {
                    if ts.is_empty() {
                        "unit".into()
                    } else {
                        let inner: Vec<String> = ts.iter().map(|t| self.ty(*t)).collect();
                        format!("(tuple {})", inner.join(" "))
                    }
                }
                RigidTy::Array(e, n) => {
                    let e = self.ty(e);
                    let n = self.tyconst(&n);
                    format!("(array {e} {n})")
                }
                RigidTy::Slice(e) => format!("(slice {})", self.ty(e)),
                RigidTy::Ref(_, e, m) => {
                    let e = self.ty(e);
                    format!("(ref {} {e})", if matches!(m, Mutability::Mut) { "mut" } else { "shared" })
                }
                // a raw pointer (`*const T`, `*mut T`): the reader decides
                // which pointee types it reads (docs/DESIGN-UNSAFE-SIMD.md §1.2)
                RigidTy::RawPtr(e, m) => {
                    let e = self.ty(e);
                    format!("(ptr {} {e})", if matches!(m, Mutability::Mut) { "mut" } else { "const" })
                }
                RigidTy::Adt(def, args) => {
                    // a `#[repr(simd)]` vector (stdarch's `uint8x16_t`,
                    // `__m128i`): its path, lane type and lane count
                    if let Some(s) = self.simd_ty(t, def) {
                        return s;
                    }
                    let k = stable_names(&format!("{t}"));
                    self.adts.entry(k.clone()).or_insert((def, args.clone()));
                    format!("(adt {})", q(&k))
                }
                RigidTy::Closure(def, args) => {
                    // named by definition (never by the source path rustc
                    // prints, which is the build's `OUT_DIR`); the value is
                    // the tuple of its captures (the last generic argument)
                    let up = match args.0.last() {
                        Some(GenericArgKind::Type(u)) => self.ty(*u),
                        _ => "(unsupported \"closure captures\")".into(),
                    };
                    format!("(closure {} {up})", q(&def.name()))
                }
                RigidTy::FnDef(def, args) => {
                    let a = self.args(&args);
                    format!("(fndef {} {a})", q(&def.name()))
                }
                other => format!("(unsupported {})", q(&format!("type {other:?}"))),
            },
            other => format!("(unsupported {})", q(&format!("type {other:?}"))),
        }
    }

    fn adt_def(&mut self, key: &str, def: AdtDef, args: &GenericArgs) -> String {
        let mut s = String::new();
        let kind = match def.kind() {
            AdtKind::Struct => "struct",
            AdtKind::Enum => "enum",
            AdtKind::Union => "union",
        };
        let a = self.args(args);
        let _ = write!(s, "(adt-def {} (path {}) (kind {kind}) (args {a})", q(key), q(&def.name()));
        // whether dropping a value of the variant runs code (a `Drop` impl of
        // the type, or a field with drop glue): `(no-glue)` when it does not
        let tcx = self.tcx;
        let idef = rustc_public::rustc_internal::internal(tcx, def);
        let iargs = rustc_public::rustc_internal::internal(tcx, args.clone());
        let dtor = idef.has_dtor(tcx);
        for v in def.variants_iter() {
            let d = if matches!(def.kind(), AdtKind::Enum) { def.discriminant_for_variant(v.idx()).val } else { 0 };
            let _ = write!(s, "\n  (variant {} {} {d}", v.idx().to_index(), q(&v.name()));
            for f in v.fields() {
                let t = self.ty(f.ty_with_args(args));
                let _ = write!(s, " (field {} {t})", q(&f.name));
            }
            let iv = idef.variant(rustc_abi::VariantIdx::from_usize(v.idx().to_index()));
            let glue = dtor || iv.fields.iter().any(|f| f.ty(tcx, iargs).skip_norm_wip().needs_drop(tcx, rustc_middle::ty::TypingEnv::fully_monomorphized()));
            if !glue {
                s.push_str(" (no-glue)");
            }
            s.push(')');
        }
        s.push_str(")\n");
        s
    }

    fn place(&mut self, p: &Place) -> String {
        let mut s = format!("(p {}", p.local);
        for pe in &p.projection {
            match pe {
                ProjectionElem::Deref => s.push_str(" deref"),
                ProjectionElem::Field(i, t) => {
                    let t = self.ty(*t);
                    let _ = write!(s, " (field {i} {t})");
                }
                ProjectionElem::Index(l) => {
                    let _ = write!(s, " (index {l})");
                }
                ProjectionElem::ConstantIndex { offset, min_length, from_end } => {
                    let _ = write!(s, " (cindex {offset} {min_length} {from_end})");
                }
                ProjectionElem::Subslice { from, to, from_end } => {
                    let _ = write!(s, " (subslice {from} {to} {from_end})");
                }
                ProjectionElem::Downcast(v) => {
                    let _ = write!(s, " (downcast {})", v.to_index());
                }
                other => {
                    let _ = write!(s, " (unsupported {})", q(&format!("{other:?}")));
                }
            }
        }
        s.push(')');
        s
    }

    /// A constant operand; a named constant item keeps its name (see
    /// [`Ex::provenance`]).
    fn const_operand(&mut self, c: &ConstOperand) -> String {
        let v = self.mirconst(&c.const_);
        let sp = rustc_public::rustc_internal::internal(self.tcx, c.span);
        match self.prov.get(&sp) {
            Some(Some((owner, name, false))) => format!("(const-item {owner} {} {v})", q(name)),
            Some(Some((owner, name, true))) if v.starts_with("(const-ref ") && v.ends_with(')') => {
                format!("(const-ref (const-item {owner} {} {}))", q(name), &v["(const-ref ".len()..v.len() - 1])
            }
            _ => v,
        }
    }

    /// rustc_public evaluates every constant of an instance's body; the
    /// constant items they came from (`Family::MAX_NODES`, `u64::MAX`) are in
    /// rustc's own MIR of the instance, at the operand's span: span →
    /// `(self type of the defining impl or none, name, a promoted reference
    /// to it)`, `None` where a span carries any other constant operand too
    /// (another item, an evaluated constant, a constant that is not an
    /// item), so a name is only ever given to the one operand it came from.
    fn provenance(&mut self, inst: &Instance) {
        use rustc_middle::mir::visit::Visitor;
        use rustc_middle::ty as mty;
        self.prov.clear();
        let tcx = self.tcx;
        let ii = rustc_public::rustc_internal::internal(tcx, inst.clone());
        let mty::InstanceKind::Item(did) = ii.def else { return };
        if !tcx.is_mir_available(did) {
            return;
        }
        // every constant operand with its span (`None`: not an unevaluated item)
        struct V<'tcx> {
            out: Vec<(rustc_span::Span, Option<rustc_middle::mir::UnevaluatedConst<'tcx>>)>,
        }
        impl<'tcx> Visitor<'tcx> for V<'tcx> {
            fn visit_const_operand(&mut self, c: &rustc_middle::mir::ConstOperand<'tcx>, _l: rustc_middle::mir::Location) {
                let uc = match c.const_ {
                    rustc_middle::mir::Const::Unevaluated(uc, _) => Some(uc),
                    _ => None,
                };
                self.out.push((c.span, uc));
            }
        }
        // the operands of the blocks' statements and terminators only (not
        // `required_consts` or debug info, which `visit_body` also visits)
        fn operands<'tcx>(b: &rustc_middle::mir::Body<'tcx>) -> V<'tcx> {
            let mut v = V { out: Vec::new() };
            for (bb, data) in b.basic_blocks.iter_enumerated() {
                v.visit_basic_block_data(bb, data);
            }
            v
        }
        let v = operands(tcx.instance_mir(ii.def));
        let env = mty::TypingEnv::fully_monomorphized();
        let mut found: Vec<(rustc_span::Span, Option<(String, String, bool)>)> = Vec::new();
        for (sp, uc) in v.out {
            let Some(uc) = uc else {
                found.push((sp, None));
                continue;
            };
            // a promoted `&C`: its body reads one named constant
            let (uc, is_ref) = match uc.promoted {
                None => (uc, false),
                Some(p) => {
                    let pb = &tcx.promoted_mir(uc.def)[p];
                    let pv = operands(pb);
                    match pv.out.as_slice() {
                        [(_, Some(inner))] if inner.promoted.is_none() && pb.local_decls.len() == 2 => (*inner, true),
                        _ => {
                            found.push((sp, None));
                            continue;
                        }
                    }
                }
            };
            let args = ii.instantiate_mir_and_normalize_erasing_regions(tcx, env, mty::EarlyBinder::bind(uc.args));
            let (d2, a2) = match mty::Instance::try_resolve(tcx, env, uc.def, args) {
                Ok(Some(i)) => (i.def_id(), i.args),
                _ => (uc.def, args),
            };
            if !matches!(tcx.def_kind(d2), rustc_hir::def::DefKind::AssocConst { .. } | rustc_hir::def::DefKind::Const { .. }) {
                found.push((sp, None));
                continue;
            }
            let owner = match tcx.impl_of_assoc(d2) {
                Some(imp) => {
                    let st = tcx.type_of(imp).instantiate(tcx, a2).skip_norm_wip();
                    let sts: Ty = rustc_public::rustc_internal::stable(st);
                    self.ty(sts)
                }
                None => "none".to_string(),
            };
            found.push((sp, Some((owner, tcx.item_name(d2).to_string(), is_ref))));
        }
        for (sp, x) in found {
            match self.prov.get(&sp) {
                Some(y) if *y != x => {
                    self.prov.insert(sp, None);
                }
                _ => {
                    self.prov.insert(sp, x);
                }
            }
        }
    }

    fn mirconst(&mut self, c: &MirConst) -> String {
        let t = c.ty();
        let ts = self.ty(t);
        if !matches!(c.kind(), ConstantKind::ZeroSized) {
            let tcx = self.tcx;
            let ic = rustc_public::rustc_internal::internal(tcx, c.clone());
            let ity = rustc_public::rustc_internal::internal(tcx, t);
            match ic.eval(tcx, rustc_middle::ty::TypingEnv::fully_monomorphized(), rustc_span::DUMMY_SP) {
                Ok(cv) => return self.cval(cv, ity),
                Err(_) => return format!("(unsupported {})", q(&format!("constant of type {ts} does not evaluate"))),
            }
        }
        match c.kind() {
            ConstantKind::ZeroSized => format!("(zst {ts})"),
            ConstantKind::Allocated(a) if a.provenance.ptrs.is_empty() => {
                let k = t.kind();
                if k.is_integral() || k.is_bool() || k.is_char() {
                    let v = if k.is_signed() { a.read_int().map(|v| v.to_string()) } else { a.read_uint().map(|v| v.to_string()) };
                    match v {
                        Ok(v) => format!("(int {ts} {v})"),
                        Err(e) => format!("(unsupported {})", q(&format!("constant {e:?}"))),
                    }
                } else {
                    let bytes: Vec<String> = a.bytes.iter().map(|b| b.map(|b| b.to_string()).unwrap_or_else(|| "u".into())).collect();
                    format!("(bytes {ts} {})", bytes.join(" "))
                }
            }
            ConstantKind::Ty(tc) => match tc.kind() {
                TyConstKind::ZSTValue(_) => format!("(zst {ts})"),
                _ => format!("(unsupported {})", q(&format!("constant {c:?}"))),
            },
            _ => format!("(unsupported {})", q(&format!("constant of type {ts}"))),
        }
    }

    /// An evaluated constant: an integer, a unit value, or an aggregate
    /// destructured by rustc (variant and fields).
    fn cval(&mut self, cv: rustc_middle::mir::ConstValue, ty: rustc_middle::ty::Ty<'tcx>) -> String {
        use rustc_middle::ty::TyKind as K;
        let tcx = self.tcx;
        let st: Ty = rustc_public::rustc_internal::stable(ty);
        let ts = self.ty(st);
        match ty.kind() {
            K::Bool | K::Int(_) | K::Uint(_) | K::Char => {
                let Some(si) = cv.try_to_scalar_int() else { return format!("(unsupported {})", q(&format!("constant of type {ts}"))) };
                let v = if matches!(ty.kind(), K::Int(_)) { si.to_int(si.size()).to_string() } else { si.to_uint(si.size()).to_string() };
                format!("(int {ts} {v})")
            }
            _ if matches!(cv, rustc_middle::mir::ConstValue::ZeroSized) => format!("(zst {ts})"),
            // a shared reference to a constant (a promoted `&0`): its pointee
            K::Ref(_, inner, rustc_middle::ty::Mutability::Not) => {
                let rustc_middle::mir::ConstValue::Scalar(rustc_middle::mir::interpret::Scalar::Ptr(ptr, _)) = cv else {
                    return format!("(unsupported {})", q(&format!("constant of type {ts}")));
                };
                let (prov, offset) = ptr.prov_and_relative_offset();
                let alloc_id = prov.alloc_id();
                let inner = *inner;
                let inner_s = if inner.is_integral() || inner.is_bool() || inner.is_char() {
                    let alloc = tcx.global_alloc(alloc_id).unwrap_memory();
                    let size = match tcx.layout_of(rustc_middle::ty::TypingEnv::fully_monomorphized().as_query_input(inner)) {
                        Ok(l) => l.size,
                        Err(_) => return format!("(unsupported {})", q(&format!("constant of type {ts}"))),
                    };
                    match alloc.inner().read_scalar(&tcx, rustc_middle::mir::interpret::alloc_range(offset, size), false) {
                        Ok(sc) => self.cval(rustc_middle::mir::ConstValue::Scalar(sc), inner),
                        Err(_) => format!("(unsupported {})", q(&format!("constant of type {ts}"))),
                    }
                } else {
                    self.cval(rustc_middle::mir::ConstValue::Indirect { alloc_id, offset }, inner)
                };
                format!("(const-ref {inner_s})")
            }
            K::Array(..) | K::Tuple(..) | K::Adt(..) => match tcx.try_destructure_mir_constant_for_user_output(cv, ty) {
                Some(d) => {
                    let fields: Vec<(rustc_middle::mir::ConstValue, rustc_middle::ty::Ty<'tcx>)> = d.fields.to_vec();
                    let v = d.variant.map(|v| v.as_usize().to_string()).unwrap_or_else(|| "0".into());
                    let fs: Vec<String> = fields.into_iter().map(|(c, t)| self.cval(c, t)).collect();
                    format!("(const-agg {ts} {v}{})", fs.iter().map(|f| format!(" {f}")).collect::<String>())
                }
                None => format!("(unsupported {})", q(&format!("constant of type {ts}"))),
            },
            _ => format!("(unsupported {})", q(&format!("constant of type {ts}"))),
        }
    }

    fn operand(&mut self, o: &Operand) -> String {
        match o {
            Operand::Copy(p) => format!("(copy {})", self.place(p)),
            Operand::Move(p) => format!("(move {})", self.place(p)),
            Operand::Constant(c) => self.const_operand(c),
            Operand::RuntimeChecks(r) => format!(
                "(runtime-checks {})",
                match r {
                    RuntimeChecks::UbChecks => "ub",
                    RuntimeChecks::ContractChecks => "contract",
                    RuntimeChecks::OverflowChecks => "overflow",
                }
            ),
        }
    }

    fn binop(b: &BinOp) -> &'static str {
        match b {
            BinOp::Add => "add",
            BinOp::AddUnchecked => "add-unchecked",
            BinOp::Sub => "sub",
            BinOp::SubUnchecked => "sub-unchecked",
            BinOp::Mul => "mul",
            BinOp::MulUnchecked => "mul-unchecked",
            BinOp::Div => "div",
            BinOp::Rem => "rem",
            BinOp::BitXor => "xor",
            BinOp::BitAnd => "and",
            BinOp::BitOr => "or",
            BinOp::Shl => "shl",
            BinOp::ShlUnchecked => "shl-unchecked",
            BinOp::Shr => "shr",
            BinOp::ShrUnchecked => "shr-unchecked",
            BinOp::Eq => "eq",
            BinOp::Lt => "lt",
            BinOp::Le => "le",
            BinOp::Ne => "ne",
            BinOp::Ge => "ge",
            BinOp::Gt => "gt",
            BinOp::Cmp => "cmp",
            BinOp::Offset => "offset",
        }
    }

    fn rvalue(&mut self, r: &Rvalue) -> String {
        match r {
            Rvalue::Use(o, _) => format!("(use {})", self.operand(o)),
            Rvalue::BinaryOp(b, x, y) => {
                let (x, y) = (self.operand(x), self.operand(y));
                format!("(bin {} {x} {y})", Self::binop(b))
            }
            Rvalue::CheckedBinaryOp(b, x, y) => {
                let (x, y) = (self.operand(x), self.operand(y));
                format!("(checked {} {x} {y})", Self::binop(b))
            }
            Rvalue::UnaryOp(u, x) => {
                let x = self.operand(x);
                let op = match u {
                    UnOp::Not => "not",
                    UnOp::Neg => "neg",
                    UnOp::PtrMetadata => "ptr-metadata",
                };
                format!("(un {op} {x})")
            }
            Rvalue::Cast(k, x, t) => {
                let kind = match k {
                    CastKind::IntToInt => "int-to-int".to_string(),
                    CastKind::PointerCoercion(PointerCoercion::Unsize) => "unsize".to_string(),
                    CastKind::PointerCoercion(PointerCoercion::ReifyFnPointer(_)) => "reify-fn-pointer".to_string(),
                    CastKind::Transmute => "transmute".to_string(),
                    // between raw pointers (`*mut u8 as *const u8`, `p.cast()`)
                    CastKind::PtrToPtr => "ptr-to-ptr".to_string(),
                    other => format!("(unsupported {})", q(&format!("{other:?}"))),
                };
                let (x, t) = (self.operand(x), self.ty(*t));
                format!("(cast {kind} {x} {t})")
            }
            Rvalue::Ref(_, bk, p) => {
                let k = match bk {
                    BorrowKind::Shared => "shared",
                    BorrowKind::Mut { .. } => "mut",
                    BorrowKind::Fake(_) => "fake",
                };
                format!("(ref {k} {})", self.place(p))
            }
            Rvalue::Reborrow(_, m, p) => {
                let k = if matches!(m, Mutability::Mut) { "mut" } else { "shared" };
                format!("(ref {k} {})", self.place(p))
            }
            Rvalue::CopyForDeref(p) => format!("(use (copy {}))", self.place(p)),
            // `&raw const place` / `&raw mut place` (rustc's pointer formation)
            Rvalue::AddressOf(k, p) => match k {
                RawPtrKind::Mut => format!("(addr-of mut {})", self.place(p)),
                RawPtrKind::Const => format!("(addr-of const {})", self.place(p)),
                // a raw borrow whose only use is its metadata (a slice's
                // length: rustc's `s.len()` of a `&mut [T]`, without a reborrow)
                RawPtrKind::FakeForPtrMetadata => format!("(addr-of fake {})", self.place(p)),
            },
            Rvalue::Discriminant(p) => format!("(discr {})", self.place(p)),
            Rvalue::Len(p) => format!("(len {})", self.place(p)),
            Rvalue::Repeat(o, n) => {
                let o = self.operand(o);
                format!("(repeat {o} {})", self.tyconst(n))
            }
            Rvalue::Aggregate(k, ops) => {
                let kind = match k {
                    AggregateKind::Tuple => "(tuple)".to_string(),
                    AggregateKind::Array(t) => format!("(array {})", self.ty(*t)),
                    AggregateKind::Adt(def, v, args, _, active) => {
                        let ts = self.ty(def.ty_with_args(args));
                        format!("(adt {ts} {}{})", v.to_index(), active.map(|f| format!(" (union-field {f})")).unwrap_or_default())
                    }
                    AggregateKind::Closure(def, args) => format!("(closure {})", self.ty(Ty::new_closure(*def, args.clone()))),
                    other => format!("(unsupported {})", q(&format!("{other:?}"))),
                };
                let ops: Vec<String> = ops.iter().map(|o| self.operand(o)).collect();
                format!("(agg {kind}{})", ops.iter().map(|o| format!(" {o}")).collect::<String>())
            }
            other => format!("(unsupported {})", q(&format!("rvalue {other:?}"))),
        }
    }

    fn stmt(&mut self, st: &Statement) -> Option<String> {
        let at = self.at(st.span);
        match &st.kind {
            StatementKind::Assign(p, r) => {
                let (p, r) = (self.place(p), self.rvalue(r));
                Some(format!("(assign {p} {r}{at})"))
            }
            // storage markers, in the unoptimized window extraction only
            // (`-Zmir-opt-level=0`): the window rule reads a local's death
            // inside a pointer's window (docs/DESIGN-UNSAFE-SIMD.md §2.6);
            // the readings give them no meaning
            StatementKind::StorageLive(l) if self.tcx.sess.mir_opt_level() == 0 => Some(format!("(storage-live {l})")),
            StatementKind::StorageDead(l) if self.tcx.sess.mir_opt_level() == 0 => Some(format!("(storage-dead {l})")),
            // no runtime meaning: storage markers, borrow-checker-only
            // statements, coverage counters
            StatementKind::StorageLive(_)
            | StatementKind::StorageDead(_)
            | StatementKind::FakeRead(..)
            | StatementKind::PlaceMention(_)
            | StatementKind::AscribeUserType { .. }
            | StatementKind::Coverage(_)
            | StatementKind::ConstEvalCounter
            | StatementKind::Nop => None,
            StatementKind::Intrinsic(NonDivergingIntrinsic::Assume(o)) => Some(format!("(assume {}{at})", self.operand(o))),
            StatementKind::SetDiscriminant { place, variant_index } => Some(format!("(set-discriminant {} {})", self.place(place), variant_index.to_index())),
            other => Some(format!("(unsupported {})", q(&format!("statement {other:?}")))),
        }
    }

    fn term(&mut self, t: &Terminator, depth: usize, in_module: &dyn Fn(&str) -> bool) -> String {
        let at = self.at(t.span);
        match &t.kind {
            TerminatorKind::Goto { target } => format!("(goto {target}{at})"),
            TerminatorKind::SwitchInt { discr, targets } => {
                let d = self.operand(discr);
                let arms: String = targets.branches().map(|(v, b)| format!(" ({v} {b})")).collect();
                format!("(switch {d}{arms} (otherwise {}){at})", targets.otherwise())
            }
            TerminatorKind::Return => format!("(return{at})"),
            TerminatorKind::Unreachable => format!("(unreachable{at})"),
            TerminatorKind::Resume => "(resume)".into(),
            TerminatorKind::Abort => "(abort)".into(),
            TerminatorKind::Drop { place, target, .. } => {
                // whether the dropped value has drop glue (a type without
                // it is a no-op to drop)
                let pt = place.ty(&self.cur_locals).ok();
                let glue = match pt {
                    Some(pt) => {
                        let it = rustc_public::rustc_internal::internal(self.tcx, pt);
                        if it.needs_drop(self.tcx, rustc_middle::ty::TypingEnv::fully_monomorphized()) { "glue" } else { "no-glue" }
                    }
                    None => "unknown",
                };
                format!("(drop {} {glue} {target}{at})", self.place(place))
            }
            TerminatorKind::Assert { cond, expected, msg, target, .. } => {
                let kind = match msg {
                    AssertMessage::BoundsCheck { .. } => "bounds",
                    AssertMessage::Overflow(..) => "overflow",
                    AssertMessage::OverflowNeg(_) => "overflow-neg",
                    AssertMessage::DivisionByZero(_) => "div-zero",
                    AssertMessage::RemainderByZero(_) => "rem-zero",
                    _ => "other",
                };
                format!("(assert {} {expected} {kind} {target}{at})", self.operand(cond))
            }
            TerminatorKind::Call { func, args, destination, target, .. } => {
                let callee = self.callee(func, depth, in_module);
                let args: Vec<String> = args.iter().map(|a| self.operand(a)).collect();
                let dest = self.place(destination);
                let tgt = target.map(|b| b.to_string()).unwrap_or_else(|| "none".into());
                format!("(call {callee} (args{}) {dest} {tgt}{at})", args.iter().map(|a| format!(" {a}")).collect::<String>())
            }
            other => format!("(unsupported {})", q(&format!("terminator {other:?}"))),
        }
    }

    /// A call's callee: an extracted instance, a leaf, an intrinsic or a
    /// diverging function.
    fn callee(&mut self, func: &Operand, depth: usize, in_module: &dyn Fn(&str) -> bool) -> String {
        // the callee's type: a function item (a constant, or a local of a
        // function-item type, which is zero-sized: its value is its type)
        let t = match func {
            Operand::Constant(c) => c.const_.ty(),
            Operand::Copy(p) | Operand::Move(p) => match p.ty(&self.cur_locals) {
                Ok(t) if t.kind().fn_def().is_some() => t,
                _ => return format!("(unsupported {})", q("call through a function pointer")),
            },
            Operand::RuntimeChecks(_) => return format!("(unsupported {})", q("call of a runtime check")),
        };
        let tk = t.kind();
        let Some((def, args)) = tk.fn_def() else {
            return format!("(unsupported {})", q("call of a non-function constant"));
        };
        let dname = def.name();
        // a `core::arch` intrinsic (by its definition in core's `core_arch`):
        // a leaf the reader gives the meaning of its target model, never followed
        if let Some(leaf) = self.arch_leaf(def, args) {
            return leaf;
        }
        let a = self.args(args);
        if is_leaf_trait_method(&dname) || self.is_model_call(def, args) {
            return format!("(leaf {} {a})", q(&dname));
        }
        let inst = match Instance::resolve(def, args) {
            Ok(i) => i,
            Err(e) => return format!("(unsupported {})", q(&format!("does not resolve: {dname}: {e:?}"))),
        };
        let key = inst_key(&inst);
        let never = inst.ty().kind().fn_sig().is_some_and(|s| matches!(s.skip_binder().output().kind(), TyKind::RigidTy(RigidTy::Never)));
        if never {
            return format!("(diverge {})", q(&key));
        }
        if matches!(inst.kind, InstanceKind::Intrinsic) {
            return format!("(intrinsic {} {a})", q(&inst.intrinsic_name().unwrap_or_default()));
        }
        if is_leaf_fn(&dname, &key) {
            return format!("(leaf {} {a})", q(&dname));
        }
        if matches!(inst.kind, InstanceKind::Virtual { .. }) || (matches!(inst.kind, InstanceKind::Shim) && inst.body().is_none()) {
            return format!("(unsupported {})", q(&format!("virtual call or shim without a body: {key}")));
        }
        let local = in_module(&dname) || in_module(&key);
        let why = if matches!(inst.kind, InstanceKind::Shim) {
            "shim"
        } else if local {
            "root"
        } else if key.contains("{closure") {
            "closure"
        } else {
            "callee"
        };
        if local || depth < MAX_DEPTH {
            if !self.seen.contains(&key) {
                self.queue.push_back((inst, why, depth + 1));
            }
            format!("(fn {})", q(&key))
        } else {
            format!("(unextracted {})", q(&key))
        }
    }
}

impl Ex<'_> {
    /// A call of a method of an open trait declared at a library type, at
    /// that type ([`Ex::models`]).
    fn is_model_call(&self, def: rustc_public::ty::FnDef, args: &GenericArgs) -> bool {
        let tcx = self.tcx;
        let did = rustc_public::rustc_internal::internal(tcx, def.def_id());
        let Some(tr) = tcx.trait_of_assoc(did) else { return false };
        let tpath = tcx.def_path_str(tr);
        let Some(GenericArgKind::Type(st)) = args.0.first() else { return false };
        let erase = |t: &Ty| tcx.erase_and_anonymize_regions(rustc_public::rustc_internal::internal(tcx, *t));
        self.models.iter().any(|(k, ty)| trait_matches(k, &tpath) && erase(ty) == erase(st))
    }

    /// `(local, unsafe)` of an instance: its definition is in the extracted
    /// crate; it is a declared `unsafe fn` (a safe `#[target_feature]`
    /// function is not: its signature is `unsafe` only for function
    /// pointers). Shims and closures are neither.
    fn fn_marks(&self, inst: &Instance) -> (bool, bool) {
        let tcx = self.tcx;
        let ii = rustc_public::rustc_internal::internal(tcx, inst.clone());
        let did = ii.def_id();
        let rustc_middle::ty::InstanceKind::Item(_) = ii.def else { return (did.is_local(), false) };
        if !matches!(tcx.def_kind(did), rustc_hir::def::DefKind::Fn | rustc_hir::def::DefKind::AssocFn) {
            return (did.is_local(), false);
        }
        let declared_unsafe = matches!(tcx.fn_sig(did).skip_binder().skip_binder().safety(), rustc_hir::Safety::Unsafe);
        (did.is_local(), declared_unsafe && !tcx.codegen_fn_attrs(did).safe_target_features)
    }

    /// The target features rustc compiles an item instance's body with
    /// (`codegen_fn_attrs`: its own `#[target_feature]` with the features
    /// they imply, a closure's inherited ones), sorted.
    fn fn_features(&self, inst: &Instance) -> Option<Vec<String>> {
        let tcx = self.tcx;
        let ii = rustc_public::rustc_internal::internal(tcx, inst.clone());
        let rustc_middle::ty::InstanceKind::Item(did) = ii.def else { return None };
        let mut fs: Vec<String> = tcx.codegen_fn_attrs(did).target_features.iter().map(|f| f.name.to_string()).collect();
        fs.sort();
        fs.dedup();
        Some(fs)
    }

    /// A `#[repr(simd)]` vector type: `(simd "core::arch::<arch>::<name>"
    /// <lane type> <lanes>)`, its lanes as rustc lays them out
    /// (`simd_size_and_type`); `None` for any other ADT. Only stdarch's
    /// vector types are written by their `core::arch` path; any other
    /// `#[repr(simd)]` type is unsupported.
    fn simd_ty(&mut self, t: Ty, def: AdtDef) -> Option<String> {
        let tcx = self.tcx;
        let did = rustc_public::rustc_internal::internal(tcx, def.def_id());
        if !tcx.adt_def(did).repr().simd() {
            return None;
        }
        let Some(path) = arch_path(tcx, did) else {
            return Some(format!("(unsupported {})", q(&format!("the SIMD type `{t}` (not one of core::arch)"))));
        };
        let it = rustc_public::rustc_internal::internal(tcx, t);
        let (n, elem) = it.simd_size_and_type(tcx);
        let e = self.ty(rustc_public::rustc_internal::stable(elem));
        Some(format!("(simd {} {e} {n})", q(&path)))
    }

    /// A call of a `core::arch` intrinsic: `(arch "core::arch::<arch>::<name>"
    /// (imms ..) (features ..) safe|unsafe value|pointer)` — its const
    /// generic immediates (stdarch's `const N: i32`, by value), the target
    /// features the intrinsic itself is compiled with (`codegen_fn_attrs`),
    /// whether it is an `unsafe fn` and whether a parameter or its result
    /// is a raw pointer (the loads and stores). `None`: not an intrinsic of
    /// `core::arch` (by the definition's crate and module, and its public
    /// path).
    fn arch_leaf(&mut self, def: rustc_public::ty::FnDef, args: &GenericArgs) -> Option<String> {
        let tcx = self.tcx;
        let did = rustc_public::rustc_internal::internal(tcx, def.def_id());
        let path = arch_path(tcx, did)?;
        let mut imms = Vec::new();
        for a in &args.0 {
            match a {
                GenericArgKind::Lifetime(_) => {}
                GenericArgKind::Const(c) => imms.push(match c.kind() {
                    TyConstKind::Value(ty, alloc) => {
                        let v = if ty.kind().is_signed() { alloc.read_int().map(|v| v.to_string()) } else { alloc.read_uint().map(|v| v.to_string()) };
                        match v {
                            Ok(v) if ty.kind().is_integral() => v,
                            _ => format!("(unsupported {})", q("a non-integer immediate")),
                        }
                    }
                    other => format!("(unsupported {})", q(&format!("immediate {other:?}"))),
                }),
                GenericArgKind::Type(t) => return Some(format!("(unsupported {})", q(&format!("the intrinsic `{path}` at the type {t:?}")))),
            }
        }
        let attrs = tcx.codegen_fn_attrs(did);
        let mut feats: Vec<String> = attrs.target_features.iter().map(|f| f.name.to_string()).collect();
        feats.sort();
        feats.dedup();
        let sig = tcx.fn_sig(did).skip_binder().skip_binder();
        // (a safe `#[target_feature]` function's signature is `unsafe` for
        // function pointers; rustc's own unsafety check reads it as declared
        // safe through `safe_target_features`)
        let safe = matches!(sig.safety(), rustc_hir::Safety::Safe) || attrs.safe_target_features;
        let pointer = sig.inputs_and_output.iter().any(|t| t.is_raw_ptr() || t.is_fn_ptr());
        Some(format!(
            "(arch {} (imms{}) (features{}) {} {})",
            q(&path),
            imms.iter().map(|i| format!(" {i}")).collect::<String>(),
            feats.iter().map(|f| format!(" {}", q(f))).collect::<String>(),
            if safe { "safe" } else { "unsafe" },
            if pointer { "pointer" } else { "value" }
        ))
    }
}

/// The public `core::arch` path of an item of core's `core_arch` module
/// (`core::arch::aarch64::vandq_u8`, `core::arch::x86_64::__m128i`), from
/// the path rustc shows for it (`std::arch::..` through std's re-export):
/// `None` for an item of any other crate or module.
fn arch_path(tcx: rustc_middle::ty::TyCtxt<'_>, did: rustc_span::def_id::DefId) -> Option<String> {
    use rustc_middle::ty::print::{with_no_trimmed_paths, with_no_visible_paths};
    if tcx.crate_name(did.krate).as_str() != "core" {
        return None;
    }
    let def = with_no_visible_paths!(with_no_trimmed_paths!(tcx.def_path_str(did)));
    if !def.starts_with("core::core_arch::") {
        return None;
    }
    let shown = with_no_trimmed_paths!(tcx.def_path_str(did));
    let rest = shown.strip_prefix("std::arch::").or_else(|| shown.strip_prefix("core::arch::"))?;
    Some(format!("core::arch::{rest}"))
}

/// Trait methods the reader treats as leaves whatever the receiver: the
/// host buffer traits (the buffer model).
fn is_leaf_trait_method(d: &str) -> bool {
    d.starts_with("bytes::Buf::") || d.starts_with("bytes::BufMut::") || d.starts_with("bytes::buf::")
}

/// Library functions the reader treats as leaves (their bodies use raw
/// pointers): indexing of arrays and slices.
fn is_leaf_fn(d: &str, key: &str) -> bool {
    ((d.ends_with("::index") || d.ends_with("::index_mut")) && key.contains('[') && key.contains("Index"))
        // `Vec::push` (the reader's `vec_push` model of a `Vec` state)
        || d == "std::vec::Vec::<T, A>::push"
        || d == "alloc::vec::Vec::<T, A>::push"
        // runtime CPU feature detection (`is_x86_feature_detected!`,
        // `is_aarch64_feature_detected!` of a feature the target does not
        // enable statically): a cache in a static, never followed; the reader
        // refuses it by name (a statically enabled feature's detection is
        // the constant `true` in the MIR already)
        || d.starts_with("std_detect::")
}
