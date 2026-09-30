//! Generated names never capture (canon *Generated names*, roundtrip *Name
//! resolution*).
//!
//! The printer renames every local `l{id}_{name}`, every temporary
//! `t{n}__{what}` and every tail-loop / dispatcher argument `a{k}__arg`. A
//! module-level name with the same spelling — a `pub use` re-export (renames
//! included), a source item, a variant re-exported into the module, a prelude
//! name — would turn the printed binding into a constant / unit-constructor
//! pattern in rustc (a *capture*: `l1_y if l1_y > 3 => l1_y` with a constant
//! `l1_y` in scope matches only that constant), silently changing what the
//! verified code computes.
//!
//! Every probe below builds a source, finds every generated name of its
//! output, then rebuilds the source with module-level names spelled exactly
//! like them and requires one of two outcomes — never a verified,
//! round-tripped build that computes something else:
//!
//! * printed without capture: the output passes the round trip, no printed
//!   binding has the name of a module-scope name of its module (an oracle
//!   independent of the printer and of the round trip, reading the printed
//!   text with `syn`), and compiled with rustc it computes the source's
//!   results (execution check against the expected outputs);
//! * rejected with a clear error.
//!
//! Since optimizer O4 the Σ1 driver specializes functions that tier 0
//! finds stuck, e.g. a guard `y if y > 3 => y` becomes `if x > 3 { x } else
//! { 0 }` — no binding is printed. The probes therefore run with the driver
//! kept off the functions it would specialize (a hints-cache test hook,
//! [`driver_off`]), so the guard bindings they are about are printed, and
//! again with the default pipeline: the driven output must be capture-free
//! too and compute the source's results.
//!
//! Probes cover match guards, `let`, `let … else`, `if let`, nested matches,
//! parameters, `for`/`while` loop helpers, tail-recursion loops (arguments
//! and temporaries), methods, specialized residuals, multiversioned clones
//! (`sha2` set) and their dispatchers, unit variants (`None`, user enums)
//! re-exported under binding names, root and nested-module re-exports and
//! the phase-1 printer's temporaries. Two more groups check the source side
//! and the round trip:
//!
//! * a constant or constructor brought into scope by a `use` under the name
//!   of a *source* local (the source, read as Rust, has a constant pattern
//!   there) and prelude names re-exported in a module are rejected by the
//!   front end;
//! * the fixed output mutated back to the captured spelling is rejected by
//!   the round trip's own name resolution and shadowing check.
//!
//! Run: `cargo test -p sandblaster-front --test codegen_capture -- --nocapture`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use sandblaster_front::driver::{self, VerifyOptions};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::hooks::{self, CacheEntry, OptTestHooks};
use sandblaster_front::opt::{OptOptions, Rung};
use sandblaster_front::target::TargetInfo;

const ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\npub mod a;\n";

/// How the optimizer treats a probe's functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Drive {
    /// The default pipeline: the Σ1 driver specializes what tier 0 finds
    /// stuck (guards on a parameter become `if`s: no binding is printed).
    On,
    /// The driver kept off every function it would specialize: their
    /// source, with its guard bindings, is printed.
    Off,
}

/// Strict optimizer options that keep the Σ1 driver off `fns`, through an
/// existing test hook (production builds have none): a hints-cache entry
/// without a candidate (the untampered conversion skeleton) makes tier 0 a
/// function's only rung, and tier 0 finds these functions stuck, so their
/// source is printed.
fn driver_off(fns: &BTreeSet<String>) -> OptOptions {
    let cache = fns.iter().map(|f| (f.clone(), CacheEntry { candidate: None, proof: hooks::refl_skeleton() })).collect();
    OptOptions { strict: true, hooks: Some(Arc::new(OptTestHooks { cache, ..Default::default() })), ..Default::default() }
}

/// A build's generated code, the functions the driver specialized, and
/// the multiversioned clones of each function.
struct Built {
    code: String,
    driven: BTreeSet<String>,
    clones: BTreeMap<String, Vec<String>>,
}

/// Verifies, optimizes (strict) and round-trips `files` (see [`Drive`]);
/// the generated code, or why the build was rejected (front end,
/// verification, optimizer or round trip).
fn build_mode(files: &[(String, String)], drive: Drive) -> Result<Built, String> {
    match drive {
        Drive::On => build_with(files, &OptOptions { strict: true, ..Default::default() }),
        Drive::Off => {
            // the driven functions of the default pipeline and their clones
            // (a clone is driven on its own when its original is not)
            let on = build_with(files, &OptOptions { strict: true, ..Default::default() })?;
            let mut off = BTreeSet::new();
            let add = |b: &Built, off: &mut BTreeSet<String>| {
                for f in &b.driven {
                    off.insert(f.clone());
                    off.extend(b.clones.get(f).into_iter().flatten().cloned());
                }
            };
            add(&on, &mut off);
            loop {
                let b = build_with(files, &driver_off(&off))?;
                if b.driven.is_empty() {
                    return Ok(b);
                }
                assert!(b.driven.is_disjoint(&off), "the hook did not keep the driver off {:?}", b.driven);
                add(&b, &mut off);
            }
        }
    }
}

/// The generated code with the driver kept off (the probes' subject).
fn build(files: &[(String, String)]) -> Result<String, String> {
    build_mode(files, Drive::Off).map(|b| b.code)
}

fn build_with(files: &[(String, String)], opts: &OptOptions) -> Result<Built, String> {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new(files[0].0.as_str()), &fs, &TargetInfo::aarch64_apple_darwin());
    if !c.ok() {
        return Err(format!("front end: {}", c.render()));
    }
    let built = driver::stage::verify_and_optimize(&c, &VerifyOptions::default(), opts, "r/mod.rs");
    if !built.v.proofs_ok {
        return Err(format!("verification: {}", built.v.diags.render(&c.sm)));
    }
    let em = match built.emit {
        Some(Ok(em)) => em,
        Some(Err(e)) => return Err(format!("emit: {e}")),
        None => return Err("not emitted".into()),
    };
    if !em.opt.errors.is_empty() {
        return Err(format!("optimizer: {:?}", em.opt.errors));
    }
    if !em.roundtrip.is_empty() {
        return Err(format!("round trip: {}", em.roundtrip.join("\n  ")));
    }
    let driven = em.opt.fns.iter().filter(|f| f.rung == Some(Rung::Driven)).map(|f| f.name.clone()).collect();
    let mut clones: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in em.opt.fns.iter().filter(|f| f.set.is_some()) {
        if let Some(orig) = em.opt.fns.iter().find(|o| o.set.is_none() && f.name.starts_with(&format!("{}__", o.name))) {
            clones.entry(orig.name.clone()).or_default().push(f.name.clone());
        }
    }
    Ok(Built { code: em.code, driven, clones })
}

/// The phase-1 (UNVERIFIED) output of `files` (the printer's guard and `?`
/// desugarings use temporaries), or the front end's rejection.
fn emit_phase1(files: &[(String, String)]) -> Result<String, String> {
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new(files[0].0.as_str()), &fs, &TargetInfo::aarch64_apple_darwin());
    if !c.ok() {
        return Err(format!("front end: {}", c.render()));
    }
    driver::stage::emit(&c, "r/mod.rs").ok_or_else(|| "not emitted".into())
}

/// Compiles the generated `code` with a `main` printing each of `calls`
/// (`{:?}`) and runs it: the output lines, or the compiler error.
fn run(tag: &str, code: &str, calls: &[&str]) -> Result<Vec<String>, String> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("codegen-capture").join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sandblaster.rs"), code).unwrap();
    let mut main = String::from("include!(\"sandblaster.rs\");\nfn main() {\n");
    for call in calls {
        main.push_str(&format!("    println!(\"{{:?}}\", {call});\n"));
    }
    main.push_str("}\n");
    std::fs::write(dir.join("main.rs"), main).unwrap();
    let st = Command::new("rustc")
        .args(["--edition", "2024", "--cap-lints", "allow", "-C", "overflow-checks=on", "-C", "debug-assertions=on", "-o"])
        .arg(dir.join("gen"))
        .arg(dir.join("main.rs"))
        .output()
        .expect("rustc");
    if !st.status.success() {
        return Err(String::from_utf8_lossy(&st.stderr).to_string());
    }
    let out = Command::new(dir.join("gen")).output().unwrap();
    if !out.status.success() {
        return Err(format!("run failed ({}): {}", out.status, String::from_utf8_lossy(&out.stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect())
}

/// Whether `s` has a generated form: `l{digits}_…`, `t{digits}__…`,
/// `a{digits}__arg…`.
fn is_generated(s: &str) -> bool {
    let mut cs = s.chars();
    let Some(first) = cs.next() else { return false };
    let rest: String = cs.collect();
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    if digits == 0 {
        return false;
    }
    let tail = &rest[digits..];
    match first {
        'l' => tail.starts_with('_') && tail.len() > 1,
        't' => tail.starts_with("__") && tail.len() > 2,
        'a' => tail.starts_with("__arg"),
        _ => false,
    }
}

/// Every generated name of a printed file.
fn generated_names(code: &str) -> BTreeSet<String> {
    code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).filter(|w| is_generated(w)).map(str::to_string).collect()
}

/// The type a generated name is printed with (`name: ty` in a parameter or
/// a typed `let`), if any.
fn printed_type(code: &str, name: &str) -> Option<String> {
    let pat = format!("{name}: ");
    let i = code.find(&pat)?;
    let rest = &code[i + pat.len()..];
    Some(rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect())
}

// ---------------------------------------------------------------------------
// the independent oracle: printed bindings vs module-scope names
// ---------------------------------------------------------------------------

/// Names bound at module level in each module of `mod __sandblaster` (items
/// of every kind and `use` bindings), read with `syn`.
fn module_names(items: &[syn::Item], path: &str, out: &mut BTreeMap<String, BTreeSet<String>>) {
    fn use_names(t: &syn::UseTree, out: &mut BTreeSet<String>) {
        match t {
            syn::UseTree::Path(p) => use_names(&p.tree, out),
            syn::UseTree::Name(n) => {
                out.insert(n.ident.to_string());
            }
            syn::UseTree::Rename(r) => {
                out.insert(r.rename.to_string());
            }
            syn::UseTree::Glob(_) => {
                out.insert("*".into());
            }
            syn::UseTree::Group(g) => g.items.iter().for_each(|t| use_names(t, out)),
        }
    }
    let mut names = BTreeSet::new();
    for it in items {
        let n = match it {
            syn::Item::Const(x) => Some(x.ident.to_string()),
            syn::Item::Static(x) => Some(x.ident.to_string()),
            syn::Item::Fn(x) => Some(x.sig.ident.to_string()),
            syn::Item::Struct(x) => Some(x.ident.to_string()),
            syn::Item::Enum(x) => Some(x.ident.to_string()),
            syn::Item::Type(x) => Some(x.ident.to_string()),
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    module_names(inner, &format!("{path}::{}", m.ident), out);
                }
                Some(m.ident.to_string())
            }
            syn::Item::Use(u) => {
                use_names(&u.tree, &mut names);
                None
            }
            _ => None,
        };
        names.extend(n);
    }
    out.insert(path.to_string(), names);
}

struct Pats(Vec<String>);
impl<'ast> syn::visit::Visit<'ast> for Pats {
    fn visit_pat_ident(&mut self, p: &'ast syn::PatIdent) {
        self.0.push(p.ident.to_string());
        syn::visit::visit_pat_ident(self, p);
    }
}

/// `(module, function, binding)` for every identifier pattern of a printed
/// function whose name is a module-level name of its module or one of the
/// prelude names that are patterns (`None`, `Some`, `Ok`, `Err`).
fn captures(code: &str) -> Vec<(String, String, String)> {
    let file = syn::parse_file(code).expect("the generated file parses");
    let Some(syn::Item::Mod(root)) = file.items.iter().find(|i| matches!(i, syn::Item::Mod(m) if m.ident == "__sandblaster")) else { panic!("no `mod __sandblaster`") };
    let content = &root.content.as_ref().unwrap().1;
    let mut scopes = BTreeMap::new();
    module_names(content, "", &mut scopes);
    let mut out = Vec::new();
    fn go(items: &[syn::Item], path: &str, scopes: &BTreeMap<String, BTreeSet<String>>, out: &mut Vec<(String, String, String)>) {
        let names = &scopes[path];
        let check = |owner: String, pats: Vec<String>, out: &mut Vec<(String, String, String)>| {
            for p in pats {
                if names.contains(&p) || names.contains("*") || ["None", "Some", "Ok", "Err"].contains(&p.as_str()) {
                    out.push((path.to_string(), owner.clone(), p));
                }
            }
        };
        for it in items {
            match it {
                syn::Item::Fn(f) => {
                    let mut v = Pats(vec![]);
                    syn::visit::Visit::visit_item_fn(&mut v, f);
                    check(f.sig.ident.to_string(), v.0, out);
                }
                syn::Item::Impl(im) => {
                    for ii in &im.items {
                        if let syn::ImplItem::Fn(f) = ii {
                            let mut v = Pats(vec![]);
                            syn::visit::Visit::visit_impl_item_fn(&mut v, f);
                            check(f.sig.ident.to_string(), v.0, out);
                        }
                    }
                }
                syn::Item::Mod(m) => {
                    if let Some((_, inner)) = &m.content {
                        go(inner, &format!("{path}::{}", m.ident), scopes, out);
                    }
                }
                _ => {}
            }
        }
    }
    go(content, "", &scopes, &mut out);
    out
}

// ---------------------------------------------------------------------------
// probes
// ---------------------------------------------------------------------------

/// A probe: module `a` of a crate (`body`), calls on it and the source's
/// results (hand-computed).
struct Probe {
    tag: &'static str,
    body: String,
    calls: &'static [&'static str],
    expected: &'static [&'static str],
}

/// How module-level names spelled like the generated names are added.
#[derive(Clone, Copy, Debug)]
enum Collide {
    /// `pub use self::K as <name>;` (a constant of the name's printed type).
    ReExport,
    /// `pub const <name>: T = …;` (a source item).
    Item,
}

/// The constant of each printed type the probes re-export.
const CONSTS: &str = "
pub const K: u32 = 5;
pub const KU: usize = 1;
pub const K8: u8 = 2;
pub const K64: u64 = 6;
";

fn const_for(ty: &str) -> (&'static str, &'static str, &'static str) {
    match ty {
        "usize" => ("KU", "usize", "1"),
        "u8" => ("K8", "u8", "2"),
        "u64" => ("K64", "u64", "6"),
        _ => ("K", "u32", "5"),
    }
}

fn files(body: &str) -> Vec<(String, String)> {
    vec![("r/mod.rs".into(), ROOT.into()), ("r/a.rs".into(), format!("use sandblaster::prelude::*;\n{CONSTS}\n{body}"))]
}

/// What a collision variant produced.
#[derive(Debug)]
enum Outcome {
    /// Printed without capture and computing the source's results.
    Printed { renamed: Vec<String> },
    Rejected(String),
}

/// Runs `p` clean, then with every generated name taken by a module-level
/// name of module `a` (`how`), with the driver on or off (`drive`); asserts
/// the outcome is never a verified build that computes something else.
/// With the driver on, the names of the undriven output (the guard
/// bindings) are taken too. Returns the outcome.
fn run_probe(p: &Probe, how: Collide, drive: Drive) -> Outcome {
    let code0 = build_mode(&files(&p.body), drive).unwrap_or_else(|e| panic!("{}: the clean source must build: {e}", p.tag)).code;
    let out0 = run(&format!("{}-{drive:?}-clean", p.tag), &code0, p.calls).unwrap_or_else(|e| panic!("{}: the clean output must compile: {e}\n{code0}", p.tag));
    assert_eq!(out0, p.expected, "{} ({drive:?}): the clean output computes the source's results\n{code0}", p.tag);
    let undriven = if drive == Drive::On { build(&files(&p.body)).unwrap_or_else(|e| panic!("{}: {e}", p.tag)) } else { String::new() };
    let mut names = generated_names(&code0);
    names.extend(generated_names(&undriven));
    assert!(!names.is_empty(), "{}: no generated names", p.tag);
    let mut extra = String::new();
    for n in &names {
        let (k, ty, v) = const_for(printed_type(&code0, n).or_else(|| printed_type(&undriven, n)).as_deref().unwrap_or("u32"));
        match how {
            Collide::ReExport => extra.push_str(&format!("pub use self::{k} as {n};\n")),
            Collide::Item => extra.push_str(&format!("#[allow(non_upper_case_globals)]\npub const {n}: {ty} = {v};\n")),
        }
    }
    let body = format!("{}\n{extra}", p.body);
    println!("=== {} ({how:?}, driver {drive:?}): {} generated names taken: {names:?}", p.tag, names.len());
    match build_mode(&files(&body), drive) {
        Ok(Built { code, .. }) => {
            let caps = captures(&code);
            assert!(caps.is_empty(), "{}: printed bindings captured by module-level names: {caps:?}\n{code}", p.tag);
            let out = run(&format!("{}-{how:?}-{drive:?}", p.tag), &code, p.calls);
            assert_eq!(out.as_ref().ok(), Some(&out0), "{}: VERIFIED and round-tripped, but rustc computes something else:\n{out:?}\n{code}", p.tag);
            let now = generated_names(&code);
            let renamed: Vec<String> = now.iter().filter(|n| !names.contains(*n)).cloned().collect();
            println!("    printed without capture; renamed: {renamed:?}");
            Outcome::Printed { renamed }
        }
        Err(e) => {
            println!("    rejected: {}", e.lines().next().unwrap_or(""));
            assert!(!e.trim().is_empty(), "{}: rejected without a message", p.tag);
            Outcome::Rejected(e)
        }
    }
}

/// Both collision variants must be printed without capture: with the
/// driver kept off the functions it specializes (their bindings are printed
/// and must be renamed), and with the default pipeline (whatever the driver
/// prints must be capture-free and compute the source's results). Returns
/// the functions the driver specializes in the clean source.
fn assert_printed(p: &Probe) -> BTreeSet<String> {
    for how in [Collide::ReExport, Collide::Item] {
        match run_probe(p, how, Drive::Off) {
            Outcome::Printed { renamed } => assert!(!renamed.is_empty(), "{} ({how:?}): no generated name was renamed", p.tag),
            Outcome::Rejected(e) => panic!("{} ({how:?}): expected to print without capture, rejected: {e}", p.tag),
        }
        if let Outcome::Rejected(e) = run_probe(p, how, Drive::On) {
            panic!("{} ({how:?}, driven): expected to print without capture, rejected: {e}", p.tag);
        }
    }
    build_mode(&files(&p.body), Drive::On).unwrap_or_else(|e| panic!("{}: {e}", p.tag)).driven
}

/// The default pipeline on `files`: the driver specializes something (the
/// output is driven), nothing printed is captured, and rustc computes the
/// source's results.
fn assert_driven_capture_free(tag: &str, files: &[(String, String)], calls: &[&str], expected: &[&str]) -> BTreeSet<String> {
    let b = build_mode(files, Drive::On).unwrap_or_else(|e| panic!("{tag} (driven): expected to print without capture: {e}"));
    println!("--- {tag} (driven: {:?}) ---\n{}", b.driven, b.code);
    assert!(!b.driven.is_empty(), "{tag}: the driver specializes nothing, so this is not the driven output:\n{}", b.code);
    assert!(captures(&b.code).is_empty(), "{tag} (driven): {:?}\n{}", captures(&b.code), b.code);
    assert_eq!(run(&format!("{tag}-driven"), &b.code, calls).unwrap_or_else(|e| panic!("{tag} (driven): {e}")), expected, "{tag} (driven)\n{}", b.code);
    b.driven
}

/// The checker's probe: a guard on a binding re-exported as a constant.
#[test]
fn guard_binding_reexport() {
    // the exact reproduction first
    let body = "pub fn f(x: u32) -> u32 {\n    match x {\n        y if y > 3 => y,\n        _ => 0,\n    }\n}\n";
    let code0 = build(&files(body)).unwrap();
    assert!(code0.contains("l1_y if l1_y > 3u32 => l1_y"), "{code0}");
    let code = build(&files(&format!("{body}\npub use self::K as l1_y;\n"))).expect("printed without capture");
    println!("{code}");
    assert!(!code.contains("l1_y if"), "the arm still binds `l1_y`:\n{code}");
    assert!(code.contains("l1_y_ if l1_y_ > 3u32 => l1_y_"), "{code}");
    assert_eq!(run("repro", &code, &["a::f(4)", "a::f(5)", "a::f(2)"]).unwrap(), ["4", "5", "0"]);
    // the driven `f` (`if l0_x > 3u32 { l0_x } else { 0u32 }`) next to the re-export
    let driven = assert_driven_capture_free("repro", &files(&format!("{body}\npub use self::K as l1_y;\n")), &["a::f(4)", "a::f(5)", "a::f(2)"], &["4", "5", "0"]);
    assert!(driven.contains("crate::a::f"), "{driven:?}");
    let driven = assert_printed(&Probe { tag: "guard", body: body.into(), calls: &["a::f(4)", "a::f(5)", "a::f(2)"], expected: &["4", "5", "0"] });
    assert!(driven.contains("crate::a::f"), "the driver specializes `f`: {driven:?}");
}

/// `let`, `let … else`, `if let`, nested matches, parameters, locals named
/// like prelude functions.
#[test]
fn lets_nested_matches_and_parameters() {
    let body = r#"
pub fn lets(x: u32) -> u32 {
    let y = x.wrapping_add(1);
    let drop = y.wrapping_mul(2);
    let align_of = drop ^ y;
    align_of
}

pub fn let_else(o: Option<u32>) -> u32 {
    let Some(v) = o else { return 7; };
    v
}

pub fn if_let(o: Option<u32>) -> u32 {
    if let Some(v) = o { v } else { 9 }
}

pub fn nested(x: u32, y: u32) -> u32 {
    match x {
        a if a > 10 => match y {
            b if b > a => b - a,
            b => b,
        },
        a => a,
    }
}

pub fn param(x: u32, y: u32) -> u32 {
    x.wrapping_add(y)
}
"#;
    assert_printed(&Probe {
        tag: "lets",
        body: body.into(),
        calls: &["a::lets(4)", "a::let_else(Some(3))", "a::let_else(None)", "a::if_let(Some(2))", "a::if_let(None)", "a::nested(20, 25)", "a::nested(20, 3)", "a::nested(4, 9)", "a::param(1, 2)"],
        expected: &["15", "3", "7", "2", "9", "5", "3", "4", "3"],
    });
}

/// Loop helpers (`for`, `while`) and their variables.
#[test]
fn loops() {
    let body = r#"
pub fn sum(xs: &[u32; 8]) -> u32 {
    let mut s: u32 = 0;
    for i in 0usize..8 {
        let v = xs[i];
        s = match v {
            w if w > 3 => s.wrapping_add(w),
            _ => s,
        };
    }
    s
}

pub fn count_down(n: u32) -> u32 {
    let mut i = n;
    let mut steps: u32 = 0;
    while i > 0 {
        proof! { decreases(i); }
        i -= 1;
        steps = steps.wrapping_add(1);
    }
    steps
}
"#;
    assert_printed(&Probe { tag: "loops", body: body.into(), calls: &["a::sum(&[1, 2, 3, 4, 5, 6, 7, 8])", "a::count_down(5)"], expected: &["30", "5"] });
}

/// Tail recursion printed as the canonical loop (`a{k}__arg` arguments,
/// `t{n}__next` temporaries).
#[test]
fn tail_recursion_loops() {
    let body = r#"
pub fn tail_sum(s: &[u8], acc: u32) -> u32 {
    match s {
        [] => acc,
        [h, t @ ..] => tail_sum(t, acc.wrapping_add(*h as u32)),
    }
}

#[decreases(b)]
pub fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}
"#;
    assert_printed(&Probe { tag: "tail", body: body.into(), calls: &["a::tail_sum(&[1, 2, 3], 10)", "a::gcd(48, 18)"], expected: &["16", "6"] });
}

/// Methods and specialized residuals (straight-line arithmetic).
#[test]
fn methods_and_specialized_residuals() {
    let body = r#"
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct P {
    pub v: u32,
}

impl P {
    pub fn pick(&self, y: u32) -> u32 {
        match y {
            z if z > self.v => z,
            _ => self.v,
        }
    }
}

pub fn mix(a: u32, b: u32) -> u32 {
    let c = a.wrapping_sub(b);
    c ^ (a >> 3u32)
}

pub fn mix_pick(a: u32, b: u32) -> u32 {
    let c = a.wrapping_sub(b);
    match c {
        d if d > 100 => d ^ (a >> 3u32),
        d => d,
    }
}
"#;
    assert_printed(&Probe {
        tag: "methods",
        body: body.into(),
        calls: &["a::P { v: 3 }.pick(5)", "a::P { v: 3 }.pick(2)", "a::mix(100, 7)", "a::mix_pick(300, 7)", "a::mix_pick(50, 7)"],
        expected: &["5", "3", "81", "256", "43"],
    });
}

/// A multiversioned call tree (the `sha2` variant set on aarch64): clones
/// `f__sha2`, the portable `f__portable` and the boundary dispatcher
/// (`a{k}__arg` arguments).
#[test]
fn multiversion_clones_and_dispatchers() {
    let body = r#"
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use core::arch::aarch64::vaddq_u32;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use sandblaster::arch::aarch64::{load_u32x4, store_u32x4};

pub fn add4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1]), a[2].wrapping_add(b[2]), a[3].wrapping_add(b[3])]
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[target_feature(enable = "sha2")]
#[implements(crate::a::add4)]
pub fn add4_sha2(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    store_u32x4(vaddq_u32(load_u32x4(&a), load_u32x4(&b)))
}

pub fn top(x: [u32; 4], k: u32) -> u32 {
    let r = add4(x, [1, 2, 3, 4]);
    match r[0] {
        y if y > k => y,
        _ => k,
    }
}
"#;
    let p = Probe { tag: "mv", body: body.into(), calls: &["a::top([7, 0, 0, 0], 3)", "a::top([1, 0, 0, 0], 3)"], expected: &["8", "3"] };
    let code0 = build(&files(&p.body)).expect("clean build");
    assert!(code0.contains("fn top__sha2(") && code0.contains("fn top__portable(") && code0.contains("pub fn top(a0__arg"), "a multiversioned tree with a dispatcher:\n{code0}");
    assert_printed(&p);
}

/// A unit variant (`None`, a user enum's variant) or a unit struct
/// re-exported under the name of a printed binding of its type: rustc
/// would read the binding as a constructor pattern.
#[test]
fn unit_constructors_reexported_as_binding_names() {
    let body = r#"
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum E {
    A,
    B,
}

pub fn keep(o: Option<u32>) -> u32 {
    match o {
        y if y.is_some() => 1,
        _ => 0,
    }
}

pub fn which(e: E, x: u32) -> u32 {
    match e {
        f if x > 3 => match f {
            E::A => 1,
            E::B => 2,
        },
        _ => 0,
    }
}
"#;
    let calls: &[&str] = &["a::keep(Some(3))", "a::keep(None)", "a::which(a::E::B, 5)", "a::which(a::E::A, 5)", "a::which(a::E::B, 1)"];
    let expected = ["1", "0", "2", "1", "0"];
    let code0 = build(&files(body)).unwrap();
    assert_eq!(run("unit-clean", &code0, calls).unwrap(), expected);
    let y = generated_names(&code0).into_iter().find(|n| n.ends_with("_y")).expect("`y`");
    let f = generated_names(&code0).into_iter().find(|n| n.ends_with("_f")).expect("`f`");
    let extra = format!("pub use core::option::Option::None as {y};\npub use self::E::A as {f};\n");
    match build(&files(&format!("{body}\n{extra}"))) {
        Ok(code) => {
            println!("{code}");
            assert!(captures(&code).is_empty(), "{:?}\n{code}", captures(&code));
            assert_eq!(run("unit-collide", &code, calls).unwrap(), expected, "{code}");
        }
        Err(e) => panic!("expected to print without capture: {e}"),
    }
    // the driven output next to the same re-exports
    assert_driven_capture_free("unit-collide", &files(&format!("{body}\n{extra}")), calls, &expected);
}

/// Re-exports in the root (printed at the top level) and in a nested
/// module, named like generated names of the functions next to them.
#[test]
fn root_and_nested_module_reexports() {
    let root = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\npub mod a;\npub const K: u32 = 5;\npub fn g(x: u32) -> u32 {\n    match x {\n        y if y > 3 => y,\n        _ => 0,\n    }\n}\npub use self::K as l1_y;\n";
    let a = "use sandblaster::prelude::*;\npub mod b;\n";
    let b = "use sandblaster::prelude::*;\npub const K: u32 = 5;\npub fn h(x: u32) -> u32 {\n    match x {\n        y if y > 3 => y,\n        _ => 0,\n    }\n}\npub use self::K as l1_y;\n";
    let fs = vec![("r/mod.rs".to_string(), root.to_string()), ("r/a.rs".to_string(), a.to_string()), ("r/a/b.rs".to_string(), b.to_string())];
    let code = build(&fs).expect("printed without capture");
    println!("{code}");
    assert!(captures(&code).is_empty(), "{:?}", captures(&code));
    assert!(code.contains("l1_y_ if l1_y_ > 3u32"), "the nested module's binding is renamed:\n{code}");
    let calls = ["g(4)", "g(2)", "a::b::h(4)", "a::b::h(2)"];
    assert_eq!(run("root-nested", &code, &calls).unwrap(), ["4", "0", "4", "0"]);
    let driven = assert_driven_capture_free("root-nested", &fs, &calls, &["4", "0", "4", "0"]);
    assert!(driven.contains("crate::g") && driven.contains("crate::a::b::h"), "{driven:?}");
}

/// The phase-1 printer's temporaries (`?` and guard desugarings:
/// `t{n}__v`, `t{n}__scrut`) never capture either.
#[test]
fn phase1_temporaries() {
    let body = r#"
pub fn two(s: &[u8]) -> Option<u16> {
    let (a, rest) = s.split_first()?;
    let (b, _) = rest.split_first()?;
    Some(((*a as u16) << 8u32) | (*b as u16))
}

pub fn g(x: u32, y: u32) -> u32 {
    match x.wrapping_add(y) {
        z if z > 3 => z,
        _ => 0,
    }
}
"#;
    let calls: &[&str] = &["a::two(&[1, 2, 3])", "a::two(&[1])", "a::g(2, 3)", "a::g(1, 1)"];
    let expected = ["Some(258)", "None", "5", "0"];
    let code0 = emit_phase1(&files(body)).unwrap();
    assert_eq!(run("p1-clean", &code0, calls).unwrap(), expected, "{code0}");
    let names = generated_names(&code0);
    assert!(names.iter().any(|n| n.starts_with('t')), "phase 1 prints temporaries: {names:?}\n{code0}");
    let mut extra = String::new();
    for n in &names {
        let (k, _, _) = const_for(printed_type(&code0, n).as_deref().unwrap_or("u32"));
        extra.push_str(&format!("pub use self::{k} as {n};\n"));
    }
    let code = emit_phase1(&files(&format!("{body}\n{extra}"))).expect("phase 1 prints");
    assert!(captures(&code).is_empty(), "{:?}\n{code}", captures(&code));
    assert_eq!(run("p1-collide", &code, calls).unwrap(), expected, "{code}");
}

// ---------------------------------------------------------------------------
// source-level names (the front end's reading of the source)
// ---------------------------------------------------------------------------

/// A constant or unit constructor brought into scope by a `use` under the
/// name of a *source* local (`pub use self::K as y;` next to `y if y > 3 =>
/// y`): in the source, read as Rust, the identifier pattern `y` is that
/// constant / constructor, not a binding. The front end must reject it
/// (DESIGN.md §3.3, extended to `use` bindings by
/// `Checker::check_imported_pattern_names` in `typeck::pat`) — never build
/// a verified crate whose meaning is the binding's.
#[test]
fn use_bound_constant_named_like_a_source_local() {
    let enum_e = "#[derive(Clone, Copy, PartialEq, Eq, Debug)]\npub enum E {\n    A,\n    B,\n}\n";
    let guard = "pub fn f(x: u32) -> u32 {\n    match x {\n        y if y > 3 => y,\n        _ => 0,\n    }\n}\n";
    let cases: Vec<(&str, String)> = vec![
        ("pub use, match guard", format!("{guard}pub use self::K as y;\n")),
        ("private use, match guard", format!("{guard}use self::K as y;\n")),
        ("pub use, let", "pub fn f(x: u32) -> u32 {\n    let y = x;\n    y\n}\npub use self::K as y;\n".into()),
        ("pub use, parameter", "pub fn f(y: u32) -> u32 {\n    y\n}\npub use self::K as y;\n".into()),
        ("pub use, for variable", "pub fn f(n: usize) -> usize {\n    let mut s: usize = 0;\n    for y in 0usize..n {\n        s = s.wrapping_add(y);\n    }\n    s\n}\npub use self::KU as y;\n".into()),
        ("unit variant", format!("{enum_e}pub fn f(e: E, x: u32) -> u32 {{\n    match e {{\n        y if x > 3 => 1,\n        _ => 0,\n    }}\n}}\nuse self::E::A as y;\n")),
        ("`None` under another name", "pub fn f(o: Option<u32>) -> u32 {\n    match o {\n        y if y.is_some() => 1,\n        _ => 0,\n    }\n}\npub use core::option::Option::None as y;\n".into()),
    ];
    for (label, body) in cases {
        match build(&files(&body)) {
            Ok(code) => panic!("{label}: the source's `y` is not a binding in Rust, yet it built VERIFIED:\n{code}"),
            Err(e) => {
                println!("{label}: rejected: {}", e.lines().next().unwrap_or(""));
                assert!(e.contains("identifier pattern `y`"), "{label}: rejected, but not by the identifier-pattern rule: {e}");
            }
        }
    }
}

/// Prelude names re-exported in a module (`pub use self::K as None;`,
/// `… as Some;`): the source, read as Rust, no longer means `Option::None`
/// in that module. Either rejected, or the output computes the source's
/// Rust meaning; the printer's absolute paths are unaffected.
#[test]
fn prelude_names_reexported() {
    for name in ["None", "Some"] {
        let body = format!("pub fn f(o: Option<u32>) -> u32 {{\n    match o {{\n        Some(v) => v,\n        None => 0,\n    }}\n}}\npub use self::K as {name};\n");
        match build(&files(&body)) {
            Ok(code) => {
                println!("{code}");
                // rustc rejects the source itself (`None`/`Some` name the u32 constant)
                panic!("`pub use self::K as {name};` makes the source ill-typed Rust, yet it built VERIFIED:\n{code}");
            }
            Err(e) => {
                println!("`{name}`: rejected: {}", e.lines().take(3).collect::<Vec<_>>().join(" | "));
                assert!(!e.trim().is_empty());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// the round trip's independent resolution
// ---------------------------------------------------------------------------

/// The round trip rejects a capture on its own: the fixed printer's output
/// mutated back to the old printer's spelling (the binding named like the
/// module's re-export) fails with the capture (identifier-pattern
/// resolution) and the shadowing check — before and independently of the
/// spelling check.
#[test]
fn round_trip_rejects_captures_independently() {
    use sandblaster_front::elab::{self, ProverChain};
    use sandblaster_front::roundtrip;
    let body = "pub fn f(x: u32) -> u32 {\n    match x {\n        y if y > 3 => y,\n        _ => 0,\n    }\n}\n\
                pub fn g(o: Option<u32>) -> u32 {\n    match o {\n        z if z.is_some() => 1,\n        _ => 0,\n    }\n}\n\
                pub fn h(s: &[u8], acc: u32) -> u32 {\n    match s {\n        [] => acc,\n        [c, t @ ..] => h(t, acc.wrapping_add(*c as u32)),\n    }\n}\n\
                pub use self::K as l1_y;\npub use core::option::Option::None as l1_z;\npub use self::K as a1__arg;\n";
    let fs = files(body);
    let mfs = MemFs::from_files(fs.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    let c = driver::check(Path::new("r/mod.rs"), &mfs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let emit = |opts: &OptOptions| {
            let mut chain = ProverChain::standard();
            let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
            let em = driver::stage::optimize_emit(&c, &mut out, "r/mod.rs", "", opts).unwrap();
            (out, em)
        };
        // the default pipeline: the driver specializes `f` and `g` (their
        // guards become `if`s); the output is capture-free and computes the
        // source's results
        let (_, em) = emit(&OptOptions { strict: true, ..Default::default() });
        let driven: BTreeSet<String> = em.opt.fns.iter().filter(|f| f.rung == Some(Rung::Driven)).map(|f| f.name.clone()).collect();
        assert!(driven.contains("crate::a::f") && driven.contains("crate::a::g"), "{driven:?}");
        assert!(em.roundtrip.is_empty() && em.opt.errors.is_empty(), "{:?} {:?}\n{}", em.roundtrip, em.opt.errors, em.code);
        assert!(captures(&em.code).is_empty(), "{:?}\n{}", captures(&em.code), em.code);
        let calls = ["a::f(4)", "a::f(2)", "a::g(Some(1))", "a::g(None)", "a::h(&[1, 2, 3], 10)"];
        assert_eq!(run("rt-driven", &em.code, &calls).unwrap(), ["4", "0", "1", "0", "16"], "{}", em.code);
        // with the driver kept off them, their guard bindings are printed
        let (mut out, em) = emit(&driver_off(&driven));
        assert!(em.roundtrip.is_empty(), "{:?}\n{}", em.roundtrip, em.code);
        let code = em.code.clone();
        assert!(code.contains("l1_y_ if l1_y_ > 3u32 => l1_y_") && code.contains("l1_z_ if") && code.contains("mut a1__arg_:"), "{code}");
        let cases = [
            ("constant re-export", code.replace("l1_y_", "l1_y"), "names the constant `crate::__sandblaster::a::K`"),
            ("`None` re-export", code.replace("l1_z_", "l1_z"), "names the unit variant `::core::option::Option::None`"),
            ("tail-loop argument", code.replace("a1__arg_", "a1__arg"), "`a1__arg`"),
        ];
        for (label, mutated, needle) in cases {
            assert_ne!(mutated, code, "{label}: mutation site");
            let failures = match roundtrip::check(&mutated, &em.opt, &mut out, &c.sm, &c.reexports) {
                Ok(s) => s.failures,
                Err(e) => vec![e],
            };
            println!("{label}:\n  {}", failures.join("\n  "));
            assert!(failures.iter().any(|f| f.contains("(a capture)") && f.contains(needle)), "{label}: no capture failure naming {needle:?}: {failures:?}");
            assert!(failures.iter().any(|f| f.contains("must not shadow or be shadowed by a module-scope name")), "{label}: the shadowing check did not fire: {failures:?}");
        }
    });
}

/// A call returning a slice, let-bound by the straight-line residual
/// (O7 verifier, `dsl2`): the printer used to bind the unsized value
/// (`let l1_s1: [u64] = *crate::__sandblaster::skip_small(..)`, rustc E0277),
/// which the round trip cannot see. It now binds the reference
/// (`let l1_s1: &[u64] = skip_small(..)`), and the output compiles and
/// computes the source's results.
#[test]
fn slice_results_are_bound_by_reference() {
    let body = r#"
fn mix(acc: u64, x: u64) -> u64 {
    (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29)
}

#[decreases(xs.len())]
fn skip_small(xs: &[u64]) -> &[u64] {
    match xs {
        [h, t @ ..] if *h < 4 => skip_small(t),
        _ => xs,
    }
}

#[decreases(xs.len())]
fn fold_mix(xs: &[u64], acc: u64) -> u64 {
    match xs {
        [] => acc,
        [h, t @ ..] => fold_mix(t, mix(acc, *h)),
    }
}

pub fn skip_then_fold(xs: &[u64]) -> u64 {
    fold_mix(skip_small(xs), 11)
}

pub fn skip_twice(xs: &[u64]) -> u64 {
    let s = skip_small(xs);
    fold_mix(s, fold_mix(s, 1))
}
"#;
    let b = build_with(&files(body), &OptOptions { strict: true, ..Default::default() }).unwrap_or_else(|e| panic!("slice results: {e}"));
    println!("{}", b.code);
    assert!(!b.code.contains(": [u64] ="), "an unsized local is printed:\n{}", b.code);
    // the plain-Rust source computes the expected values
    fn mix(acc: u64, x: u64) -> u64 {
        (acc ^ x).wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(29)
    }
    fn skip_small(xs: &[u64]) -> &[u64] {
        match xs {
            [h, t @ ..] if *h < 4 => skip_small(t),
            _ => xs,
        }
    }
    fn fold_mix(xs: &[u64], acc: u64) -> u64 {
        match xs {
            [] => acc,
            [h, t @ ..] => fold_mix(t, mix(acc, *h)),
        }
    }
    let inputs: [&[u64]; 5] = [&[], &[1, 2, 3], &[1, 9, 2], &[7, 0, 5, 1], &[0, 0, 0, 0, 99, 3]];
    let mut calls = Vec::new();
    let mut expected = Vec::new();
    for xs in inputs {
        calls.push(format!("a::skip_then_fold(&{xs:?})"));
        expected.push(fold_mix(skip_small(xs), 11).to_string());
        calls.push(format!("a::skip_twice(&{xs:?})"));
        let s = skip_small(xs);
        expected.push(fold_mix(s, fold_mix(s, 1)).to_string());
    }
    let calls: Vec<&str> = calls.iter().map(String::as_str).collect();
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    let out = run("slice-results", &b.code, &calls).unwrap_or_else(|e| panic!("the output must compile: {e}\n{}", b.code));
    assert_eq!(out, expected, "{}", b.code);
}

/// A multiversioned function whose original is not driven while its clone
/// is (maintenance report "quote", issue 1): the build used to fail the
/// round trip ("`crate::a::top__sha2`: arguments of `vaddq_u32`"). The
/// driver is kept off the original only (the hints-cache hook); the clone
/// is driven on its own, and the output must round-trip, compile and
/// compute the source's results.
#[test]
fn clone_driven_while_its_original_is_not() {
    let body = r#"
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use core::arch::aarch64::vaddq_u32;
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
use sandblaster::arch::aarch64::{load_u32x4, store_u32x4};

pub fn add4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [a[0].wrapping_add(b[0]), a[1].wrapping_add(b[1]), a[2].wrapping_add(b[2]), a[3].wrapping_add(b[3])]
}

#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[target_feature(enable = "sha2")]
#[implements(crate::a::add4)]
pub fn add4_sha2(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    store_u32x4(vaddq_u32(load_u32x4(&a), load_u32x4(&b)))
}

pub fn top(x: [u32; 4], k: u32) -> u32 {
    let r = add4(x, [1, 2, 3, 4]);
    match r[0] {
        y if y > k => y,
        _ => k,
    }
}
"#;
    let off: BTreeSet<String> = ["crate::a::top".to_string()].into_iter().collect();
    let b = build_with(&files(body), &driver_off(&off)).unwrap_or_else(|e| panic!("the original kept off the driver, its clone driven: {e}"));
    println!("{}", b.code);
    assert!(!b.driven.contains("crate::a::top"), "the hook keeps the driver off the original");
    assert!(b.code.contains("fn top__sha2(") && b.code.contains("pub fn top(a0__arg"), "a multiversioned tree with a dispatcher:\n{}", b.code);
    let out = run("mv-clone-driven", &b.code, &["a::top([7, 0, 0, 0], 3)", "a::top([1, 0, 0, 0], 3)", "a::top([u32::MAX, 0, 0, 0], 5)"]).unwrap_or_else(|e| panic!("the output must compile: {e}\n{}", b.code));
    assert_eq!(out, ["8", "3", "5"], "{}", b.code);
}

/// A message assembled from an integer's bytes and a digest (optimizer
/// design §6.7, *assembled arrays*): symbolic execution turns
/// `m[0..8].copy_from_slice(&n.to_be_bytes()); m[8..40].copy_from_slice(&d)`
/// into a spine of 40 element values, which used to print as an array
/// literal of eight shifted bytes and 32 single-byte reads (40 byte stores
/// that LLVM does not merge). The residual now prints the buffer as it was
/// built: a zeroed local filled by `copy_from_slice` from
/// `n.to_be_bytes()`, `x.to_le_bytes()` and `&d`. The output must
/// round-trip, compile and compute the source's results.
#[test]
fn assembled_messages_print_as_buffers() {
    let body = r#"
fn digest40(m: &[u8; 40]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for i in 0usize..40 {
        h = (h ^ m[i] as u64).wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn digest48(m: &[u8; 48]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for i in 0usize..48 {
        h = (h ^ m[i] as u64).wrapping_mul(0x0100_0000_01b3);
    }
    h
}

pub fn seal(n: u64, extra: u64, d: [u8; 32]) -> u64 {
    if extra == 0 {
        let mut m = [0u8; 40];
        m[0..8].copy_from_slice(&n.to_be_bytes());
        m[8..40].copy_from_slice(&d);
        digest40(&m)
    } else {
        let mut m = [0u8; 48];
        m[0..8].copy_from_slice(&n.to_be_bytes());
        m[8..16].copy_from_slice(&extra.to_le_bytes());
        m[16..48].copy_from_slice(&d);
        digest48(&m)
    }
}

pub fn window(b: &[u8; 64], k: u64) -> u64 {
    if k == 0 {
        return 0;
    }
    let mut m = [0u8; 40];
    m[0..8].copy_from_slice(&k.to_be_bytes());
    m[8..40].copy_from_slice(&b[16..48]);
    digest40(&m)
}

pub fn seal_opt(n: u64, extra: u64, d: Option<[u8; 32]>) -> u64 {
    match d {
        None => 0,
        Some(d) => seal(n, extra, d),
    }
}
"#;
    let b = build_with(&files(body), &OptOptions { strict: true, ..Default::default() }).unwrap_or_else(|e| panic!("assembled messages: {e}"));
    println!("{}", b.code);
    // the plain-Rust source computes the expected values
    fn digest(m: &[u8]) -> u64 {
        m.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ *b as u64).wrapping_mul(0x0100_0000_01b3))
    }
    fn seal(n: u64, extra: u64, d: [u8; 32]) -> u64 {
        let mut m = n.to_be_bytes().to_vec();
        if extra != 0 {
            m.extend_from_slice(&extra.to_le_bytes());
        }
        m.extend_from_slice(&d);
        digest(&m)
    }
    let ds: [[u8; 32]; 2] = [std::array::from_fn(|i| i as u8 * 7 + 1), [0xff; 32]];
    let mut calls = Vec::new();
    let mut expected = Vec::new();
    for (n, extra) in [(0u64, 0u64), (1, 0), (0x0102_0304_0506_0708, 0), (u64::MAX, 9), (77, 0x1122_3344_5566_7788)] {
        for d in &ds {
            calls.push(format!("a::seal({n}, {extra}, {d:?})"));
            expected.push(seal(n, extra, *d).to_string());
            calls.push(format!("a::seal_opt({n}, {extra}, Some({d:?}))"));
            expected.push(seal(n, extra, *d).to_string());
        }
        calls.push(format!("a::seal_opt({n}, {extra}, None)"));
        expected.push("0".to_string());
        // (wrapping: `n` reaches `u64::MAX`, which overflows in the debug profile)
        let b: [u8; 64] = std::array::from_fn(|i| (i as u64).wrapping_mul(31).wrapping_add(n) as u8);
        calls.push(format!("a::window(&{b:?}, {extra})"));
        expected.push(if extra == 0 { "0".to_string() } else { seal(extra, 0, b[16..48].try_into().unwrap()).to_string() });
    }
    let calls: Vec<&str> = calls.iter().map(String::as_str).collect();
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    let out = run("assembled-messages", &b.code, &calls).unwrap_or_else(|e| panic!("the output must compile: {e}\n{}", b.code));
    assert_eq!(out, expected, "{}", b.code);
    // the driven residual builds the message as a buffer, not byte by byte
    assert!(b.driven.contains("crate::a::seal"), "`seal` is driven: {:?}\n{}", b.driven, b.code);
    let fn_text = |f: &str| {
        let at = b.code.find(&format!("fn {f}(")).unwrap_or_else(|| panic!("`{f}` is printed"));
        let end = b.code[at + 1..].find("\n        pub ").map_or(b.code.len(), |i| at + 1 + i);
        b.code[at..end].to_string()
    };
    let text = fn_text("seal");
    assert!(text.contains("to_be_bytes(l0_n)") && text.contains("to_le_bytes(l1_extra)") && text.matches("copy_from_slice").count() == 5 && !text.contains("wrapping_shr"), "`seal` assembles its messages:\n{text}");
    // a copy from a range of an array parameter
    assert!(b.driven.contains("crate::a::window"), "`window` is driven: {:?}", b.driven);
    let text = fn_text("window");
    assert!(text.contains("to_be_bytes(l1_k)") && text.contains("16usize..48usize") && !text.contains("wrapping_shr"), "`window` assembles its message:\n{text}");
}
