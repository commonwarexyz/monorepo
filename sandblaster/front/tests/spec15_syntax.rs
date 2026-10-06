//! §15 annotations (DESIGN.md §15, the S0 interface of §15.12): for every
//! annotation and placement, an accepted form with the HIR record it
//! produces and the rejected forms with their diagnostics; the elaborator's
//! "not implemented yet" errors (nothing is silently ignored); the
//! annotation-coverage test (every annotation the type checker accepts
//! changes the HIR) and the facade/macro/`Annot` agreement.

mod common;

use std::collections::BTreeSet;
use std::path::Path;

use common::*;
use sandblaster_front::diag::{DiagKind as K, Severity};
use sandblaster_front::driver::{self, Checked, ProverSet, VerifyOptions};
use sandblaster_front::hir::*;
use sandblaster_front::resolve::Annot;

fn fn_def<'a>(k: &'a Crate, path: &str) -> &'a FnDef {
    let id = k.find(path).unwrap_or_else(|| panic!("no item {path}"));
    k.fn_def(id).unwrap_or_else(|| panic!("{path} is not a function"))
}

fn struct_def<'a>(k: &'a Crate, path: &str) -> &'a StructDef {
    match &k.item(k.find(path).unwrap_or_else(|| panic!("no item {path}"))).kind {
        ItemKind::Struct(s) => s,
        _ => panic!("{path} is not a struct"),
    }
}

fn enum_def<'a>(k: &'a Crate, path: &str) -> &'a EnumDef {
    match &k.item(k.find(path).unwrap_or_else(|| panic!("no item {path}"))).kind {
        ItemKind::Enum(e) => e,
        _ => panic!("{path} is not an enum"),
    }
}

#[track_caller]
fn ok_files(files: &[(&str, &str)]) -> Checked {
    let c = check_files(files);
    assert!(c.ok(), "expected no errors, got:\n{}", c.render());
    c
}

/// Asserts an error of `kind` containing `needle` whose notes contain
/// `note`.
#[track_caller]
fn rejects_with_note(body: &str, kind: K, needle: &str, note: &str) {
    let c = check(body);
    let found = c.diags.list.iter().any(|d| d.severity == Severity::Error && d.kind == kind && d.msg.contains(needle) && d.notes.iter().any(|(_, n)| n.contains(note)));
    assert!(found, "expected error[{}] containing {needle:?} with a note containing {note:?}; got:\n{}", kind.code(), c.render());
}

const SPEC: &str = "#[cfg(sandblaster)] #[spec] fn add_spec(a: u8, b: u8) -> Int { (a as Int) + (b as Int) }\n";

// ---------------------------------------------------------------- #[spec] modules (§15.1)

#[test]
fn spec_modules_make_their_fns_spec_fns() {
    let root = format!("{HEADER}#[cfg(sandblaster)] #[spec] #[path = \"spec/mod.rs\"] mod spec;\npub fn f(x: u8) -> u8 {{ x }}\n");
    let c = ok_files(&[
        ("r/mod.rs", &root),
        ("r/spec/mod.rs", "pub mod sha;\npub fn twice(x: u8) -> Int { 2 * (x as Int) }\n#[lemma] fn twice_nonneg(x: u8) { ensures(twice(x) >= 0); }\n"),
        ("r/spec/sha.rs", "pub fn thrice(x: u8) -> Int { 3 * (x as Int) }\n#[derive(Clone, Copy)] pub struct State { pub h: Int }\n"),
    ]);
    let k = c.krate.as_ref().unwrap();
    let spec_mod = k.modules.iter().find(|m| m.name == "spec").unwrap();
    assert!(spec_mod.spec && spec_mod.ghost);
    assert!(k.modules.iter().find(|m| m.name == "sha").unwrap().spec, "submodules of a spec module are spec modules");
    assert!(!k.module(k.root).spec);
    assert_eq!(fn_def(k, "crate::spec::twice").kind, FnKind::Spec);
    assert_eq!(fn_def(k, "crate::spec::sha::thrice").kind, FnKind::Spec);
    assert_eq!(fn_def(k, "crate::spec::twice_nonneg").kind, FnKind::Lemma, "an explicit kind wins");
    assert!(k.in_spec_module(k.find("crate::spec::sha::State").unwrap()));
    // spec modules need no later stage: they elaborate
    let v = driver::stage::verify(k, &VerifyOptions { provers: ProverSet::Basic, exec_only: false });
    assert!(!v.diags.list.iter().any(|d| d.msg.contains("not implemented yet")), "{}", v.diags.render(&c.sm));
}

#[test]
fn spec_module_placement() {
    // not ghost
    let root = format!("{HEADER}#[spec] mod spec;\n");
    let c = check_files(&[("r/mod.rs", &root), ("r/spec.rs", "")]);
    rejects_checked(&c, K::Attribute, "a `#[spec]` module must be ghost");
    // cfg after spec
    let root = format!("{HEADER}#[spec] #[cfg(sandblaster)] mod spec;\n");
    let c = check_files(&[("r/mod.rs", &root), ("r/spec.rs", "")]);
    rejects_checked(&c, K::Attribute, "write `#[cfg(sandblaster)]` before `#[spec]`");
    // arguments
    let root = format!("{HEADER}#[cfg(sandblaster)] #[spec(x)] mod spec;\n");
    let c = check_files(&[("r/mod.rs", &root), ("r/spec.rs", "")]);
    rejects_checked(&c, K::Attribute, "takes no arguments");
    // inside a ghost module, no own cfg needed
    let root = format!("{HEADER}#[cfg(sandblaster)] #[path = \"g/mod.rs\"] mod g;\n");
    let c = ok_files(&[("r/mod.rs", &root), ("r/g/mod.rs", "#[spec] mod s;\n"), ("r/g/s.rs", "fn t(x: u8) -> u8 { x }\n")]);
    assert_eq!(fn_def(c.krate.as_ref().unwrap(), "crate::g::s::t").kind, FnKind::Spec);
}

// ---------------------------------------------------------------- #[refines] (§15.2)

#[test]
fn refines_forms_are_recorded() {
    let c = accepts(&format!(
        "{SPEC}#[refines(add_spec)]\nfn add(a: u8, b: u8) -> u64 {{ a as u64 + b as u64 }}\n\
         #[refines(add_spec(b, a), domain = a < 10)]\nfn add2(a: u8, b: u8) -> u64 {{ a as u64 + b as u64 }}\n\
         #[refines(crate::add_spec(a, 3))]\nfn add3(a: u8) -> u64 {{ a as u64 + 3 }}\n\
         pub fn api() -> u64 {{ add(1, 2) + add2(1, 2) + add3(1) }}\n"
    ));
    let k = c.krate.as_ref().unwrap();
    let spec = k.find("crate::add_spec").unwrap();
    let r = fn_def(k, "crate::add").spec.refines.as_ref().unwrap();
    assert_eq!(r.spec, spec);
    assert!(r.args.is_none() && r.domain.is_none());
    let r2 = fn_def(k, "crate::add2").spec.refines.as_ref().unwrap();
    let args = r2.args.as_ref().unwrap();
    assert_eq!(args.len(), 2);
    assert!(matches!(args[0].kind, ExprKind::Local(_)));
    assert_eq!(r2.domain.as_ref().unwrap().ty, Ty::Prop);
    // literals take the spec's parameter types
    let a3 = fn_def(k, "crate::add3").spec.refines.as_ref().unwrap().args.clone().unwrap();
    assert_eq!(a3[1].ty, Ty::u8());
}

#[test]
fn refines_on_a_type_is_an_error() {
    // it used to be accepted and ignored (§9.6)
    rejects_with_note("#[refines(x)]\n#[derive(Clone, Copy)] struct Fe(u64);", K::Attribute, "`#[refines]` is not allowed on a struct", "#[view(..)]");
    rejects_with_note("#[refines(x)]\n#[derive(Clone, Copy)] enum E { A }", K::Attribute, "`#[refines]` is not allowed on an enum", "#[invariant(..)]");
    rejects("#[refines(x)]\nconst C: u8 = 1;", K::Attribute, "`#[refines]` is not allowed on a constant");
    rejects("#[refines(x)]\ntype T = u8;", K::Attribute, "`#[refines]` is not allowed on a type alias");
}

#[test]
fn refines_targets_and_placement() {
    rejects_with_note("fn h(x: u8) -> u8 { x }\n#[refines(h)]\nfn f(x: u8) -> u8 { x }", K::Attribute, "must name a spec function; `crate::h` is an exec function", "proves nothing");
    rejects("#[cfg(sandblaster)] #[lemma] fn l(x: u8) { ensures(x == x); }\n#[refines(l)]\nfn f(x: u8) -> u8 { x }", K::Attribute, "is a lemma item");
    rejects("#[derive(Clone, Copy)] struct S(u8);\n#[refines(S)]\nfn f(x: u8) -> u8 { x }", K::Attribute, "is not a function");
    rejects("#[refines(nowhere)]\nfn f(x: u8) -> u8 { x }", K::Resolve, "cannot find `nowhere`");
    rejects(&format!("{SPEC}#[cfg(sandblaster)] #[lemma] #[refines(add_spec)] fn l(x: u8) {{ ensures(x == x); }}"), K::Attribute, "`#[refines]` is not allowed on a lemma");
    rejects(&format!("{SPEC}#[cfg(sandblaster)] #[spec] #[refines(add_spec)] fn s(x: u8) -> u8 {{ x }}"), K::Attribute, "`#[refines]` is not allowed on a spec function");
    rejects(&format!("{SPEC}#[refines(add_spec)]\n#[refines(add_spec)]\nfn f(a: u8, b: u8) -> u8 {{ a }}"), K::Attribute, "at most one `#[refines]`");
    // explicit argument map: the spec's arity
    rejects(&format!("{SPEC}#[refines(add_spec(a))]\nfn f(a: u8) -> u8 {{ a }}"), K::Attribute, "takes 2 argument(s)");
    // malformed
    rejects(&format!("{SPEC}#[refines(1 + 2)]\nfn f(a: u8) -> u8 {{ a }}"), K::Attribute, "malformed `#[refines]`");
    rejects(&format!("{SPEC}#[refines(add_spec, foo = 1)]\nfn f(a: u8) -> u8 {{ a }}"), K::Attribute, "expected `domain = P`");
    rejects(&format!("{SPEC}#[refines]\nfn f(a: u8) -> u8 {{ a }}"), K::Attribute, "malformed `#[refines]`");
    // a hardware variant (`#[implements]`, removed with the optimizer's
    // dispatch) is refused, with or without `#[refines]`
    rejects(&format!("{SPEC}fn f(x: u8) -> u8 {{ x }}\n#[implements(f)]\n#[refines(add_spec)]\nfn fv(x: u8) -> u8 {{ x }}"), K::Feature, "`#[implements]` (a hardware variant) is not supported");
}

// ---------------------------------------------------------------- #[proof(refines | complete = f)] (§15.2, §15.5)

#[test]
fn proof_items_pair_with_their_function() {
    let root = format!("{HEADER}{SPEC}#[refines(add_spec)]\nfn add(a: u8, b: u8) -> u64 {{ a as u64 + b as u64 }}\npub fn api() -> u64 {{ add(1, 2) }}\n#[cfg(sandblaster)] #[path = \"PROOF.rs\"] mod proof;\n");
    let c = ok_files(&[("r/mod.rs", &root), ("r/PROOF.rs", "#[proof(refines = super::add)]\nfn add_refines(a: u8, b: u8) { follows(); }\n#[proof(complete = super::add)]\nfn add_complete(a: u8, b: u8) { follows(); }\n")]);
    let k = c.krate.as_ref().unwrap();
    let pr = k.find("crate::proof::add_refines").unwrap();
    let pc = k.find("crate::proof::add_complete").unwrap();
    let add = k.find("crate::add").unwrap();
    let po = k.fn_def(pr).unwrap().spec.proof_of.unwrap();
    assert_eq!((po.kind, po.target), (ProofKind::Refines, add));
    assert_eq!(k.fn_def(pc).unwrap().spec.proof_of.unwrap().kind, ProofKind::Complete);
    assert_eq!(fn_def(k, "crate::add").spec.refines_proof, Some(pr));
    assert_eq!(fn_def(k, "crate::add").spec.complete_proof, Some(pc));
    // not paired with a law by name
    assert_eq!(k.fn_def(pr).unwrap().proves, None);
}

#[test]
fn proof_item_errors() {
    let run = |exec: &str, proof: &str| {
        let root = format!("{HEADER}{SPEC}{exec}\n#[cfg(sandblaster)] #[path = \"PROOF.rs\"] mod proof;\n");
        check_files(&[("r/mod.rs", &root), ("r/PROOF.rs", proof)])
    };
    let c = run("fn add(a: u8, b: u8) -> u8 { a }", "#[proof(refines = super::add)]\nfn p(a: u8, b: u8) { follows(); }\n");
    rejects_checked(&c, K::Law, "which has no `#[refines]`");
    let c = run("#[refines(add_spec)] fn add(a: u8, b: u8) -> u8 { a }", "#[proof(refines = super::add)]\nfn p(a: u8) { follows(); }\n");
    rejects_checked(&c, K::Law, "must have the parameters of `crate::add`");
    let c = run("#[refines(add_spec)] fn add(a: u8, b: u8) -> u8 { a }", "#[proof(refines = super::add)]\nfn p(a: u8, b: u8) { follows(); }\n#[proof(refines = super::add)]\nfn q(a: u8, b: u8) { follows(); }\n");
    rejects_checked(&c, K::Law, "more than one `#[proof(refines = ..)]`");
    let c = run("", "#[proof(refines = super::add_spec)]\nfn p(a: u8, b: u8) { follows(); }\n");
    rejects_checked(&c, K::Attribute, "must name an exec function; `crate::add_spec` is a spec item");
    let c = run("fn add(a: u8, b: u8) -> u8 { a }", "#[proof(proves = super::add)]\nfn p(a: u8, b: u8) { follows(); }\n");
    rejects_checked(&c, K::Attribute, "expected `#[proof]`, `#[proof(refines = path::f)]`");
    let no_cascade = |c: &Checked| assert!(!c.diags.list.iter().any(|d| d.msg.contains("does not prove any")), "no law-pairing cascade:\n{}", c.render());
    no_cascade(&c);
    // an unresolved target is reported once: the item is not a law's proof
    let c = run("fn add(a: u8, b: u8) -> u8 { a }", "#[proof(refines = super::nope)]\nfn p(a: u8, b: u8) { follows(); }\n");
    rejects_checked(&c, K::Resolve, "cannot find `nope`");
    no_cascade(&c);
    let c = run("#[derive(Clone, Copy)] pub struct S;\nimpl S { pub fn f(self) -> u8 { 1 } }", "#[proof(complete = super::S::g)]\nfn p(s: super::S) { follows(); }\n");
    rejects_checked(&c, K::Resolve, "no associated function named `g` found for `S`");
    no_cascade(&c);
}

#[test]
fn proof_and_section_targets_can_be_methods() {
    // review S0: `Type::f` names an inherent function (DESIGN.md §15.2's
    // `Mmr::push`, §15.3's state passing)
    let root = format!(
        "{HEADER}#[cfg(sandblaster)] #[spec] fn size_spec(m: Mmr) -> u64 {{ 0 }}\n\
         #[derive(Clone, Copy)]\npub struct Mmr {{ size: u64 }}\n\
         impl Mmr {{\n    pub fn new() -> Mmr {{ Mmr {{ size: 0 }} }}\n    #[refines(size_spec)]\n    pub fn size(self) -> u64 {{ self.size }}\n    \
         #[section(with = [Mmr::size, crate::Mmr::new])]\n    pub fn bump(self) -> Mmr {{ Mmr {{ size: self.size.wrapping_add(1) }} }}\n}}\n\
         #[cfg(sandblaster)] #[path = \"PROOF.rs\"] mod proof;\n"
    );
    let c = ok_files(&[("r/mod.rs", &root), ("r/PROOF.rs", "#[proof(refines = super::Mmr::size)]\nfn size_refines(m: super::Mmr) { follows(); }\n#[proof(complete = super::Mmr::bump)]\nfn bump_complete(m: super::Mmr) { follows(); }\n")]);
    let k = c.krate.as_ref().unwrap();
    let (size, new, bump) = (k.find("crate::Mmr::size").unwrap(), k.find("crate::Mmr::new").unwrap(), k.find("crate::Mmr::bump").unwrap());
    let pr = k.find("crate::proof::size_refines").unwrap();
    let pc = k.find("crate::proof::bump_complete").unwrap();
    assert_eq!(k.fn_def(pr).unwrap().spec.proof_of.map(|p| (p.kind, p.target)), Some((ProofKind::Refines, size)));
    assert_eq!(fn_def(k, "crate::Mmr::size").spec.refines_proof, Some(pr));
    assert_eq!(fn_def(k, "crate::Mmr::bump").spec.complete_proof, Some(pc));
    let with: Vec<ItemId> = k.fn_def(bump).unwrap().spec.section_with.iter().map(|x| x.0).collect();
    assert_eq!(with, vec![size, new]);
}

// ---------------------------------------------------------------- #[example], #[examples] (§15.7)

#[test]
fn examples_are_closed_bool_spec_expressions() {
    let c = accepts(
        "#[cfg(sandblaster)] #[spec] #[example(twice(3) == 6)] #[example(twice(0) == 0 && twice(1) == 2)]\nfn twice(x: u8) -> u8 { x.wrapping_mul(2) }\n\
         #[example(inc(1) == 2)]\nfn inc(x: u8) -> u8 { x.wrapping_add(1) }\npub fn api() -> u8 { inc(1) }",
    );
    let k = c.krate.as_ref().unwrap();
    let ex = &fn_def(k, "crate::twice").spec.examples;
    assert_eq!(ex.len(), 2);
    assert!(ex.iter().all(|e| e.expr.ty == Ty::Bool));
    assert_eq!(fn_def(k, "crate::inc").spec.examples.len(), 1);
    // closed: the parameters are not in scope
    rejects("#[example(x == 1)]\nfn f(x: u8) -> u8 { x }", K::Resolve, "cannot find `x`");
    // bool, not a proposition or another type
    rejects("#[example(1u8)]\nfn f(x: u8) -> u8 { x }", K::Type, "mismatched types");
    rejects("#[example(forall(|y: u8| y == y))]\nfn f(x: u8) -> u8 { x }", K::Type, "mismatched types");
    // placement
    rejects("#[cfg(sandblaster)] #[lemma] #[example(true)] fn l(x: u8) { ensures(x == x); }", K::Attribute, "`#[example]` is not allowed on a lemma");
    rejects("#[example(true)]\n#[derive(Clone, Copy)] struct S;", K::Attribute, "`#[example]` is not allowed on a struct");
}

#[test]
fn example_files_are_build_inputs() {
    let root = format!(
        "{HEADER}#[cfg(sandblaster)] #[spec]\n#[examples(file = \"vectors/v.json\", format = \"json\", provenance = independent)]\n#[examples(file = \"../SHA.rsp\", format = \"cavp\", provenance = self)]\nfn check(x: u8, y: u8) -> bool {{ x == y }}\n"
    );
    let c = ok_files(&[("r/mod.rs", &root), ("r/vectors/v.json", "[{\"x\": 1, \"y\": 1}]"), ("SHA.rsp", "Len = 0\n")]);
    let k = c.krate.as_ref().unwrap();
    let files = &fn_def(k, "crate::check").spec.example_files;
    assert_eq!(files.len(), 2);
    assert_eq!((files[0].format, files[0].provenance), (ExampleFormat::Json, Provenance::Independent));
    assert_eq!((files[1].format, files[1].provenance), (ExampleFormat::Cavp, Provenance::SelfDerived));
    // registered in the source map (so `cargo::rerun-if-changed` lists it)
    assert!(c.sm.path(files[0].file).ends_with("vectors/v.json"), "{}", c.sm.path(files[0].file).display());
    assert_eq!(c.sm.get(files[1].file).unwrap().text, "Len = 0\n");
    assert!(c.sm.files().any(|(_, f)| f.path.ends_with("SHA.rsp")));
}

#[test]
fn example_file_errors() {
    let one = |attr: &str, ret: &str, kind: &str| format!("#[cfg(sandblaster)] #[{kind}]\n{attr}\nfn check(x: u8) -> {ret} {{ x == x }}\n");
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}{}", one("#[examples(file = \"missing.json\", format = \"json\", provenance = production)]", "bool", "spec")))]);
    rejects_checked(&c, K::Load, "cannot read vector file");
    rejects(&one("#[examples(file = \"v.json\", format = \"json\")]", "bool", "spec"), K::Attribute, "is missing `provenance`");
    rejects(&one("#[examples(file = \"v.json\", format = \"xml\", provenance = self)]", "bool", "spec"), K::Attribute, "`format` must be");
    rejects(&one("#[examples(file = \"v.json\", format = \"json\", provenance = mine)]", "bool", "spec"), K::Attribute, "`provenance` must be");
    let c = check_files(&[("r/mod.rs", &format!("{HEADER}#[cfg(sandblaster)] #[spec]\n#[examples(file = \"v.json\", format = \"json\", provenance = self)]\nfn check(x: u8) -> u8 {{ x }}\n")), ("r/v.json", "[]")]);
    rejects_checked(&c, K::Attribute, "belongs on a checker");
    rejects("#[examples(file = \"v.json\", format = \"json\", provenance = self)]\nfn check(x: u8) -> bool { x == x }", K::Attribute, "`#[examples]` is not allowed on an exec function");
}

// ---------------------------------------------------------------- #[invariant] (§15.3)

#[test]
fn invariants_rewrite_self_fields() {
    let c = accepts(
        "const MAX: u64 = 1000;\n#[derive(Clone, Copy)]\n#[invariant(self.0 < MAX)]\npub struct Location(u64);\n\
         #[derive(Clone, Copy)]\n#[invariant(self.lo <= self.hi)]\n#[invariant(self.hi < 1000 && is_small(self.lo))]\nstruct Range { lo: u32, hi: u32 }\n\
         #[cfg(sandblaster)] #[spec] fn is_small(x: u32) -> bool { x < 10 }\n",
    );
    let k = c.krate.as_ref().unwrap();
    let inv = struct_def(k, "crate::Location").invariant.as_ref().unwrap();
    assert_eq!(inv.fields.len(), 1);
    assert_eq!(inv.locals[inv.fields[0].0 as usize].name, "self.0");
    assert_eq!(inv.props.len(), 1);
    let inv = struct_def(k, "crate::Range").invariant.as_ref().unwrap();
    assert_eq!(inv.fields.len(), 2);
    assert_eq!(inv.props.len(), 2);
    assert!(inv.locals.iter().all(|l| l.ghost));
    // `self.lo` became the binder of `lo`
    let ExprKind::Coerce(Coercion::BoolToProp, b) = &inv.props[0].0.kind else { panic!("{:?}", inv.props[0].0.kind) };
    let ExprKind::Binary(BinOp::Le, l, _) = &b.kind else { panic!() };
    assert!(matches!(l.kind, ExprKind::Local(x) if x == inv.fields[0]));
}

#[test]
fn invariant_errors() {
    rejects_with_note("#[derive(Clone, Copy)]\n#[invariant(self == self)]\nstruct S(u8);", K::Attribute, "bare `self` is not allowed in an invariant", "field values");
    rejects("#[derive(Clone, Copy)]\n#[invariant(self.ok())]\nstruct S(u8);\nimpl S { fn ok(&self) -> bool { self.0 < 3 } }", K::Attribute, "cannot use its method `ok`");
    rejects("#[derive(Clone, Copy)]\n#[invariant(S::small(self.0))]\nstruct S(u8);\nimpl S { fn small(x: u8) -> bool { x < 3 } }", K::Attribute, "cannot use its method `small`");
    rejects("#[derive(Clone, Copy)]\n#[invariant(Self::small(self.0))]\nstruct S(u8);\nimpl S { fn small(x: u8) -> bool { x < 3 } }", K::Attribute, "cannot use its method `small`");
    rejects("#[derive(Clone, Copy)]\n#[invariant(self.z < 3)]\nstruct S { a: u8 }", K::Type, "no field `z` on type `S`");
    rejects("#[derive(Clone, Copy)]\n#[invariant(true)]\nenum E { A }", K::Attribute, "`#[invariant]` is not allowed on an enum");
    rejects("#[invariant(true)]\nfn f() {}", K::Attribute, "`#[invariant]` is not allowed on an exec function");
    rejects("#[derive(Clone, Copy)]\n#[invariant(self.0 + 1)]\nstruct S(u8);", K::Type, "");
}

// ---------------------------------------------------------------- #[view], #[represents] (§15.3)

#[test]
fn views_and_representation_relations() {
    let root = format!(
        "{HEADER}#[cfg(sandblaster)] #[spec] mod spec;\n\
         #[view(spec::Pair)]\n#[derive(Clone, Copy)]\npub struct Q {{ a: u8, b: u8 }}\n\
         #[view(|s| s.0 as Int)]\n#[derive(Clone, Copy)]\nstruct W(u8);\n\
         #[view(|e: E| match e {{ E::A => 0u8, E::B => 1u8 }})]\n#[derive(Clone, Copy)]\nenum E {{ A, B }}\n\
         #[represents(|s: &H, m: u8| s.0 == m)]\n#[derive(Clone, Copy)]\nstruct H(u8);\n\
         #[represents(|s, m: Int| s.0 as Int == m)]\n#[derive(Clone, Copy)]\nstruct H2(u8);\n"
    );
    let c = ok_files(&[("r/mod.rs", &root), ("r/spec.rs", "#[derive(Clone, Copy)] pub struct Pair { pub a: Int, pub b: Int }\n")]);
    let k = c.krate.as_ref().unwrap();
    let pair = k.find("crate::spec::Pair").unwrap();
    assert!(matches!(struct_def(k, "crate::Q").view, Some(View::Struct { target, .. }) if target == pair));
    match &struct_def(k, "crate::W").view {
        Some(View::Fn { body, .. }) => assert_eq!(body.ty, Ty::Int),
        v => panic!("{v:?}"),
    }
    assert!(matches!(&enum_def(k, "crate::E").view, Some(View::Fn { body, .. }) if body.ty == Ty::u8()));
    let r = struct_def(k, "crate::H").represents.as_ref().unwrap();
    assert!(r.by_ref);
    assert_eq!(r.abs_ty, Ty::u8());
    assert_eq!(r.prop.ty, Ty::Prop);
    assert_eq!(struct_def(k, "crate::H2").represents.as_ref().unwrap().abs_ty, Ty::Int);
}

#[test]
fn view_and_represents_errors() {
    let with_spec = |body: &str, spec: &str| {
        let root = format!("{HEADER}#[cfg(sandblaster)] #[spec] mod spec;\n{body}");
        check_files(&[("r/mod.rs", &root), ("r/spec.rs", spec)])
    };
    let c = with_spec("#[view(spec::P)]\n#[derive(Clone, Copy)]\npub struct Q { a: u8, c: u8 }\n", "#[derive(Clone, Copy)] pub struct P { pub a: Int, pub b: Int }\n");
    rejects_checked(&c, K::Attribute, "must map every field to the same-named field");
    let c = with_spec("#[view(spec::P)]\n#[derive(Clone, Copy)]\npub enum Q { A }\n", "#[derive(Clone, Copy)] pub struct P { pub a: Int }\n");
    rejects_checked(&c, K::Attribute, "applies to structs only");
    rejects("#[derive(Clone, Copy)] pub struct P { a: u8 }\n#[view(P)]\n#[derive(Clone, Copy)]\npub struct Q { a: u8 }", K::Attribute, "`crate::P` is not a spec type");
    rejects("#[view(|a, b| a)]\n#[derive(Clone, Copy)]\nstruct W(u8);", K::Attribute, "exactly one parameter");
    rejects("#[view(|s: u8| s)]\n#[derive(Clone, Copy)]\nstruct W(u8);", K::Attribute, "the view parameter has type `W`");
    rejects("#[view(1 + 1)]\n#[derive(Clone, Copy)]\nstruct W(u8);", K::Attribute, "expected `#[view(spec::T)]`");
    rejects("#[view(|s| s.0)]\n#[view(|s| s.0)]\n#[derive(Clone, Copy)]\nstruct W(u8);", K::Attribute, "at most one `#[view]`");
    rejects("#[represents(|s: &H| true)]\n#[derive(Clone, Copy)]\nstruct H(u8);", K::Attribute, "takes the value and the abstract state");
    rejects("#[represents(|s: &H, m| true)]\n#[derive(Clone, Copy)]\nstruct H(u8);", K::Attribute, "annotate the abstract state");
    rejects("#[represents(|s: u8, m: u8| true)]\n#[derive(Clone, Copy)]\nstruct H(u8);", K::Attribute, "the first parameter of `#[represents]` is the value");
    rejects("#[represents(|s: &E, m: u8| true)]\n#[derive(Clone, Copy)]\nenum E { A }", K::Attribute, "`#[represents]` is not allowed on an enum");
}

// ---------------------------------------------------------------- #[ghost] parameters (§15.3)

#[test]
fn ghost_parameters() {
    let c = accepts("#[requires(k > 0)]\nfn f(x: u8, #[ghost] k: Int) -> u8 { x }\nfn g(y: u8) -> u8 { y }");
    let k = c.krate.as_ref().unwrap();
    let f = fn_def(k, "crate::f");
    assert_eq!(f.params.iter().map(|p| p.ghost).collect::<Vec<_>>(), vec![false, true]);
    assert_eq!(f.params[1].ty, Ty::Int, "ghost parameters may have ghost types");
    let PatKind::Binding { local, .. } = f.params[1].pat.kind else { panic!() };
    assert!(f.local(local).ghost);
    assert_eq!(f.irr_binders(), vec![IrrBinder::Requires, IrrBinder::GhostParam]);
    // exec code cannot read it
    rejects("#[requires(true)]\nfn f(x: u8, #[ghost] k: u8) -> u8 { k }", K::Ghost, "exec code refers to a ghost variable");
    // placement
    rejects("#[cfg(sandblaster)] #[spec] fn s(#[ghost] x: u8) -> u8 { x }", K::Attribute, "only allowed on parameters of exec functions");
    rejects_with_note("fn f(x: u8, #[ghost] k: u8) -> u8 { x }", K::Attribute, "needs a sandblaster function annotation", "baseline builds");
    rejects("#[derive(Clone, Copy)] struct S;\nimpl S { #[requires(true)] fn m(#[ghost] self) {} }", K::Attribute, "attributes are not allowed on `self`");
    rejects("fn f(#[inline] x: u8) -> u8 { x }", K::Attribute, "attribute `#[inline]` is not allowed on a parameter");
    rejects("#[requires(true)]\nfn f(#[ghost(1)] x: u8) -> u8 { 0 }", K::Attribute, "`#[ghost]` takes no arguments");
    rejects("#[ghost]\nfn f(x: u8) -> u8 { x }", K::Attribute, "`#[ghost]` is not allowed on an exec function");
}

// ---------------------------------------------------------------- #[section], #[mirrors_impl], #[fuel_sufficient], #[trusted_extern]

#[test]
fn section_mirrors_fuel_trusted() {
    let c = accepts(
        "fn g() -> u8 { 1 }\n#[section(with = [g, crate::h])]\nfn f() -> u8 { 2 }\nfn h() -> u8 { 3 }\n\
         #[cfg(sandblaster)] #[spec] #[mirrors_impl(justification = \"a one-line spec\")] fn s(x: u8) -> u8 { x }\n\
         #[cfg(sandblaster)] #[lemma] #[fuel_sufficient(s)] fn l(x: u8) { ensures(s(x) == x); }\n\
         #[cfg(sandblaster)] #[lemma] #[fuel_sufficient] fn l2(x: u8) { ensures(x == x); }\n\
         #[trusted_extern(justification = \"runtime clock\")]\n#[ensures(|r: u64| true)]\nfn now() -> u64 { 0 }\n",
    );
    let k = c.krate.as_ref().unwrap();
    let f = fn_def(k, "crate::f");
    assert_eq!(f.spec.section_with.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![k.find("crate::g").unwrap(), k.find("crate::h").unwrap()]);
    assert_eq!(fn_def(k, "crate::s").spec.mirrors_impl.as_ref().unwrap().justification, "a one-line spec");
    assert_eq!(fn_def(k, "crate::l").spec.fuel_sufficient.as_ref().unwrap().spec, k.find("crate::s"));
    assert_eq!(fn_def(k, "crate::l2").spec.fuel_sufficient.as_ref().unwrap().spec, None);
    assert_eq!(fn_def(k, "crate::now").spec.trusted_extern.as_ref().unwrap().justification, "runtime clock");

    rejects("#[cfg(sandblaster)] #[spec] fn s(x: u8) -> u8 { x }\n#[section(with = [s])]\nfn f() -> u8 { 2 }", K::Attribute, "must name an exec function; `crate::s` is a spec item");
    rejects("#[section(with = [f])]\nfn f() -> u8 { 2 }", K::Attribute, "always in its own section");
    rejects("#[section(g)]\nfn f() -> u8 { 2 }", K::Attribute, "expected `#[section(with = [f, g, ..])]`");
    rejects("#[cfg(sandblaster)] #[spec] #[mirrors_impl] fn s(x: u8) -> u8 { x }", K::Attribute, "expected `#[mirrors_impl(justification");
    rejects("#[cfg(sandblaster)] #[spec] #[mirrors_impl(justification = \"\")] fn s(x: u8) -> u8 { x }", K::Attribute, "non-empty string");
    rejects("#[mirrors_impl(justification = \"x\")]\nfn f() {}", K::Attribute, "`#[mirrors_impl]` is not allowed on an exec function");
    rejects("#[cfg(sandblaster)] #[spec] #[fuel_sufficient] fn s(x: u8) -> u8 { x }", K::Attribute, "`#[fuel_sufficient]` is not allowed on a spec function");
    rejects("fn e(x: u8) -> u8 { x }\n#[cfg(sandblaster)] #[lemma] #[fuel_sufficient(e)] fn l(x: u8) { ensures(x == x); }", K::Attribute, "must name a spec function; `crate::e` is an exec function");
    rejects_with_note("#[trusted_extern(justification = \"x\")]\nfn now() -> u64 { 0 }", K::Attribute, "needs a contract", "locked");
    rejects("#[fully_specified]\nfn f() {}", K::Attribute, "`#[fully_specified]` does not exist");
}

// ---------------------------------------------------------------- sandblaster::critical (§15.8)

#[test]
fn annotations_are_rejected_at_every_other_site() {
    // review S0: `use` items, inner attributes of impl blocks and function
    // bodies, and everything inside a body were silently accepted
    let root = format!("{HEADER}mod m;\n#[refines(m::g)]\n#[example(false)]\npub use m::g;\n");
    let c = check_files(&[("r/mod.rs", &root), ("r/m.rs", "pub fn g() -> u8 { 1 }\n")]);
    rejects_checked(&c, K::Attribute, "`#[refines]` is not allowed on a `use` item");
    rejects_checked(&c, K::Attribute, "`#[example]` is not allowed on a `use` item");
    rejects("#[derive(Clone, Copy)] pub struct S { a: u8 }\nimpl S { #![invariant(self.a == 3)] pub fn a(self) -> u8 { self.a } }\npub fn mk() -> S { S { a: 1 } }", K::Attribute, "`#![invariant]` is not allowed: sandblaster annotations are outer attributes");
    rejects("#[derive(Clone, Copy)] pub struct S;\nimpl S { #![inline] pub fn f(self) {} }", K::Attribute, "inner attribute `#![inline]` is not allowed on an `impl` block");
    rejects("pub fn f(x: u8) -> u8 { #![ensures(|r: u8| r == 0)] x }", K::Attribute, "`#![ensures]` is not allowed: sandblaster annotations are outer attributes");
    // an impl block without functions is checked too
    rejects("#[derive(Clone, Copy)] pub struct S;\n#[refines(x)]\nimpl S {}", K::Attribute, "`#[refines]` is not allowed on an `impl` block");
    // inside bodies
    let spec = "#[cfg(sandblaster)] #[spec] fn double(x: u8) -> Int { (x as Int) * 2 }\n";
    rejects(&format!("{spec}pub fn f(x: u8) -> u8 {{ match x {{ #[example(false)] 0 => 1, _ => 2 }} }}"), K::Attribute, "`#[example]` is not allowed on a match arm");
    rejects(&format!("{spec}pub fn f(x: u8) -> u8 {{ #[refines(double)] x }}"), K::Attribute, "`#[refines]` is not allowed on a statement or expression");
    rejects_with_note(
        "pub fn f(n: u32) -> u32 { let mut c: u32 = 0; #[invariant(false)] for i in 0..n { c = i; } c }",
        K::Attribute,
        "`#[invariant]` is not allowed on a statement or expression",
        "proof! { invariant(p); }",
    );
    rejects("pub fn f(x: u8) -> u8 { proof! { #[example(false)] assert(x == x); } x }", K::Attribute, "`#[example]` is not allowed on a statement or expression");
    rejects("pub fn f(x: u8) -> u8 { #[example(false)] proof! { assert(x == x); } x }", K::Attribute, "`#[example]` is not allowed on a statement or expression");
    rejects("#[cfg(sandblaster)] #[spec] fn s(x: u8) -> Int { #[example(false)] (x as Int) * 2 }", K::Attribute, "`#[example]` is not allowed on a statement or expression");
    rejects(&format!("{spec}#[cfg(sandblaster)] #[lemma] fn l(x: u8) {{ requires(x < 3); #[refines(double)] ensures(x < 4); }}"), K::Attribute, "`#[refines]` is not allowed on a statement or expression");
    rejects("#[ensures(|#[ghost] r: u8| r == x)]\npub fn f(x: u8) -> u8 { x }", K::Attribute, "`#[ghost]` is not allowed on a closure parameter");
    rejects("const C: u8 = #[example(false)] 1;\npub fn f() -> u8 { C }", K::Attribute, "`#[example]` is not allowed on a statement or expression");
    rejects("pub fn f(x: u8) -> u8 { #[allow(unused)] let y = x; y }", K::Attribute, "attributes on `let` statements are not allowed");
    rejects("pub fn f(x: u8) -> u8 { #[inline] x }", K::Attribute, "attribute `#[inline]` is not allowed on a statement or expression");
}

#[test]
fn critical_is_rejected_in_every_form() {
    const MSG: &str = "`sandblaster::critical` does not exist";
    let root = |text: &str| check_files(&[("r/mod.rs", text)]);
    for src in [
        "#![forbid(unsafe_code)]\n#![sandblaster::critical]\nuse sandblaster::prelude::*;\n",
        "#![forbid(unsafe_code)]\n#![cfg_attr(sandblaster, sandblaster::critical)]\nuse sandblaster::prelude::*;\n",
        "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n#[cfg_attr(sandblaster, sandblaster::critical)]\npub fn f() {}\n",
        "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n#[sandblaster::critical]\npub fn f() {}\n",
        "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n#[critical]\n#[derive(Clone, Copy)] pub struct S;\n",
        "#![forbid(unsafe_code)]\nuse sandblaster::critical;\n",
    ] {
        let c = root(src);
        let d = c.diags.list.iter().find(|d| d.severity == Severity::Error && d.msg.contains(MSG));
        let d = d.unwrap_or_else(|| panic!("no critical error for:\n{src}\ngot:\n{}", c.render()));
        assert!(d.notes.iter().any(|(_, n)| n.contains("§15.8")), "{}", c.render());
    }
    let c = check_files(&[("r/mod.rs", "#![forbid(unsafe_code)]\n#[sandblaster::critical] mod m;\n"), ("r/m.rs", "")]);
    rejects_checked(&c, K::Attribute, MSG);
}

// ---------------------------------------------------------------- not implemented yet (S2, S3): nothing is silently ignored

#[test]
fn later_stages_are_errors_not_silence() {
    let root = format!(
        "{HEADER}{SPEC}\
         #[refines(add_spec)]\nfn add(a: u8, b: u8) -> u64 {{ a as u64 + b as u64 }}\n\
         #[example(inc(1) == 2)]\n#[section(with = [add])]\nfn inc(x: u8) -> u8 {{ x.wrapping_add(1) }}\n\
         #[requires(k > 0)]\nfn gh(x: u8, #[ghost] k: Int) -> u8 {{ x }}\n\
         #[derive(Clone, Copy)]\n#[invariant(self.0 < 100)]\n#[view(|s| s.0 as Int)]\nstruct Small(u8);\n\
         #[derive(Clone, Copy)]\n#[represents(|s: &H, m: u8| s.0 == m)]\nstruct H(u8);\n\
         #[view(|e| 0u8)]\n#[derive(Clone, Copy)]\nenum E {{ A }}\n\
         #[cfg(sandblaster)] #[spec] #[mirrors_impl(justification = \"tiny\")]\n#[examples(file = \"v.json\", format = \"json\", provenance = independent)]\nfn same(x: u8, y: u8) -> bool {{ x == y }}\n\
         #[cfg(sandblaster)] #[lemma] #[fuel_sufficient] fn fuel(x: u8) {{ ensures(x == x); }}\n\
         #[trusted_extern(justification = \"clock\")]\n#[ensures(|r: u64| true)]\nfn now() -> u64 {{ 0 }}\n\
         pub fn api() -> u64 {{ add(1, 2) + now() }}\n\
         #[cfg(sandblaster)] #[path = \"PROOF.rs\"] mod proof;\n"
    );
    let c = ok_files(&[
        ("r/mod.rs", &root),
        ("r/v.json", "[]"),
        ("r/PROOF.rs", "#[proof(refines = super::add)]\nfn p(a: u8, b: u8) { follows(); }\n#[proof(complete = super::add)]\nfn q(a: u8, b: u8) { follows(); }\n"),
    ]);
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Basic, exec_only: false });
    assert!(!v.proofs_ok);
    let msgs: Vec<String> = v.diags.list.iter().filter(|d| d.severity == Severity::Error && d.kind == K::Elab).map(|d| d.msg.clone()).collect();
    // S1, S2 and S3 have landed: their annotations have their meaning
    // (tests/spec15_*.rs) and no S1/S2/S3 "not implemented yet" error remains
    assert!(!msgs.iter().any(|m| m.contains("not implemented yet") && (m.contains("S1") || m.contains("S2") || m.contains("S3"))), "S1/S2/S3 annotations must be elaborated now; got:\n{}", msgs.join("\n"));
    for (what, stage) in [("`#[trusted_extern]` on `crate::now`", "(§13, §15.8)")] {
        assert!(msgs.iter().any(|m| m.contains(what) && m.contains("not implemented yet") && m.contains(stage)), "missing {what} {stage}; got:\n{}", msgs.join("\n"));
    }
    // S3: `#[proof(complete = add)]` and `#[section(with = [add])]` are
    // checked (tests/spec15_complete.rs): here they are misused or do not
    // prove, which is an error, never silence
    let s3: Vec<String> = v.diags.list.iter().filter(|d| d.severity == Severity::Error && matches!(d.kind, K::Completeness | K::Section | K::Obligation)).map(|d| d.msg.clone()).collect();
    assert!(s3.iter().any(|m| m.contains("crate::add")), "the proof item of `add` must be checked; got:\n{}", s3.join("\n"));
}

// ---------------------------------------------------------------- annotation coverage

/// Removes every `Span { .. }` from a debug rendering (blanking an
/// annotation keeps positions, but spans of parameters include their
/// attributes).
fn strip_spans(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("Span {") {
        out.push_str(&rest[..i]);
        let mut depth = 0;
        let mut end = rest.len();
        for (j, ch) in rest[i..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = i + j + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn hir_text(c: &Checked) -> String {
    let k = c.krate.as_ref().expect("a crate");
    strip_spans(&format!("{:?}\n{:?}", k.modules, k.items))
}

/// A coverage sample: the annotation, the root body (after `HEADER`), the
/// exact annotation text (empty: `#[proof]` in the extra file), extra files.
type Sample = (Annot, &'static str, &'static str, Vec<(&'static str, &'static str)>);

/// One sample per annotation. Blanking the annotation (same length) must
/// change the HIR.
fn samples() -> Vec<Sample> {
    vec![
        (Annot::Requires, "#[allow(dead_code)]\n#[requires(x > 0)]\nfn f(x: u8) -> u8 { x - 1 }\n", "#[requires(x > 0)]", vec![]),
        (Annot::Ensures, "#[allow(dead_code)]\n#[ensures(|r: u8| r == x)]\nfn f(x: u8) -> u8 { x }\n", "#[ensures(|r: u8| r == x)]", vec![]),
        (Annot::Decreases, "#[allow(dead_code)]\n#[decreases(n)]\nfn f(n: u32) -> u32 { if n == 0 { 0 } else { f(n - 1) } }\n", "#[decreases(n)]", vec![]),
        (Annot::Implements, "fn f(x: u8) -> u8 { x }\n#[target_feature(enable = \"neon\")]\n#[implements(f)]\nfn g(x: u8) -> u8 { x }\n", "#[implements(f)]", vec![]),
        (Annot::Spec, "#[cfg(sandblaster)]\n#[spec]\nfn s(x: u8) -> Int { x as Int }\n", "#[spec]", vec![]),
        (Annot::Spec, "#[cfg(sandblaster)]\n#[spec]\nmod s;\n", "#[spec]", vec![("r/s.rs", "fn t(x: u8) -> u8 { x }\n")]),
        (Annot::Lemma, "#[cfg(sandblaster)]\n#[lemma]\nfn l(x: u8) { ensures(x == x); }\n", "#[lemma]", vec![]),
        (Annot::Law, "#[cfg(sandblaster)]\n#[law]\nfn l(x: u8) { ensures(x == x); }\n", "#[law]", vec![]),
        (Annot::Proof, "#[cfg(sandblaster)]\n#[law]\nfn l(x: u8) { ensures(x == x); }\n#[cfg(sandblaster)]\n#[path = \"P.rs\"]\nmod p;\n", "", vec![("r/P.rs", "#[proof]\nfn l(x: u8) { follows(); }\n")]),
        (Annot::Induction, "#[cfg(sandblaster)]\n#[lemma]\n#[induction(n)]\nfn l(n: u32) { ensures(n == n); if n == 0 { follows(); } else { ih(n - 1); follows(); } }\n", "#[induction(n)]", vec![]),
        (Annot::Refines, "#[cfg(sandblaster)] #[spec] fn s(x: u8) -> u8 { x }\n#[allow(dead_code)]\n#[refines(s)]\nfn f(x: u8) -> u8 { x }\n", "#[refines(s)]", vec![]),
        (Annot::Example, "#[allow(dead_code)]\n#[example(f(1) == 1)]\nfn f(x: u8) -> u8 { x }\n", "#[example(f(1) == 1)]", vec![]),
        (Annot::Examples, "#[cfg(sandblaster)]\n#[spec]\n#[examples(file = \"v.json\", format = \"json\", provenance = production)]\nfn c(x: u8) -> bool { x == x }\n", "#[examples(file = \"v.json\", format = \"json\", provenance = production)]", vec![("r/v.json", "[]")]),
        (Annot::Invariant, "#[derive(Clone, Copy)]\n#[invariant(self.0 < 9)]\nstruct S(u8);\n", "#[invariant(self.0 < 9)]", vec![]),
        (Annot::View, "#[derive(Clone, Copy)]\n#[view(|s| s.0)]\nstruct S(u8);\n", "#[view(|s| s.0)]", vec![]),
        (Annot::Represents, "#[derive(Clone, Copy)]\n#[represents(|s: &S, a: u8| s.0 == a)]\nstruct S(u8);\n", "#[represents(|s: &S, a: u8| s.0 == a)]", vec![]),
        (Annot::Ghost, "#[requires(true)]\nfn f(x: u8, #[ghost] k: u8) -> u8 { x }\n", "#[ghost]", vec![]),
        (Annot::Section, "fn g() -> u8 { 1 }\n#[allow(dead_code)]\n#[section(with = [g])]\nfn f() -> u8 { 2 }\n", "#[section(with = [g])]", vec![]),
        (Annot::MirrorsImpl, "#[cfg(sandblaster)]\n#[spec]\n#[mirrors_impl(justification = \"tiny\")]\nfn s(x: u8) -> u8 { x }\n", "#[mirrors_impl(justification = \"tiny\")]", vec![]),
        (Annot::FuelSufficient, "#[cfg(sandblaster)]\n#[lemma]\n#[fuel_sufficient]\nfn l(x: u8) { ensures(x == x); }\n", "#[fuel_sufficient]", vec![]),
        (Annot::TrustedExtern, "#[allow(dead_code)]\n#[ensures(|r: u64| true)]\n#[trusted_extern(justification = \"clock\")]\nfn now() -> u64 { 0 }\n", "#[trusted_extern(justification = \"clock\")]", vec![]),
        (Annot::ReducesTo, "#[cfg(sandblaster)]\n#[spec]\n#[assumption(class = computational, cite = \"c\")]\nfn a() {}\n#[cfg(sandblaster)]\n#[law]\n#[reduces_to(a)]\nfn l(x: u8) { ensures(x == x); }\n", "#[reduces_to(a)]", vec![]),
        (Annot::Assumption, "#[cfg(sandblaster)]\n#[spec]\n#[assumption(class = computational, cite = \"c\")]\nfn a() {}\n", "#[assumption(class = computational, cite = \"c\")]", vec![]),
        (Annot::Definitional, "#[cfg(sandblaster)]\n#[law]\n#[definitional(reason = \"r\")]\nfn l(x: u8) { ensures(x == x); }\n", "#[definitional(reason = \"r\")]", vec![]),
        (Annot::Corollary, "#[cfg(sandblaster)]\n#[law]\n#[corollary]\nfn l(x: u8) { ensures(x == x); }\n", "#[corollary]", vec![]),
        (Annot::Opaque, "#[cfg(sandblaster)]\n#[spec]\n#[opaque]\nfn s(x: u8) -> u8 { x }\n", "#[opaque]", vec![]),
    ]
}

#[test]
fn every_accepted_annotation_changes_the_hir() {
    let samples = samples();
    for a in Annot::ALL {
        assert!(samples.iter().any(|(b, ..)| b == a), "no coverage sample for `#[{}]`", a.name());
    }
    for (a, body, annot, extra) in samples {
        let build = |text: &str, extra: &[(&str, &str)]| {
            let root = format!("{HEADER}{text}");
            let mut files: Vec<(&str, &str)> = vec![("r/mod.rs", root.as_str())];
            files.extend(extra.iter().copied());
            check_files(&files)
        };
        // `#[proof]` sits in the extra file
        let (with, without) = if annot.is_empty() {
            let blanked: Vec<(&str, String)> = extra.iter().map(|(p, t)| (*p, t.replace("#[proof]", "        "))).collect();
            let blanked_ref: Vec<(&str, &str)> = blanked.iter().map(|(p, t)| (*p, t.as_str())).collect();
            (build(body, &extra), build(body, &blanked_ref))
        } else {
            assert!(body.contains(annot), "{annot} not in sample");
            (build(body, &extra), build(&body.replace(annot, &" ".repeat(annot.len())), &extra))
        };
        // hardware variants were removed with the optimizer's dispatch:
        // `#[implements]` is recognized, and refused
        if a == Annot::Implements {
            assert!(!with.ok() && with.render().contains("`#[implements]` (a hardware variant) is not supported"), "{}", with.render());
            continue;
        }
        assert!(with.ok(), "sample for `#[{}]` rejected:\n{}", a.name(), with.render());
        assert_ne!(hir_text(&with), hir_text(&without), "`#[{}]` is accepted but does not change the HIR", a.name());
    }
}

// ---------------------------------------------------------------- facade and macros agree with `Annot`

/// Names in `pub use sandblaster_macros::{..};` of a facade source file.
fn facade_exports(path: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let file = syn::parse_file(&text).unwrap();
    let mut out = BTreeSet::new();
    fn names(t: &syn::UseTree, under_macros: bool, out: &mut BTreeSet<String>) {
        match t {
            syn::UseTree::Path(p) => names(&p.tree, under_macros || p.ident == "sandblaster_macros", out),
            syn::UseTree::Name(n) if under_macros => {
                out.insert(n.ident.to_string());
            }
            syn::UseTree::Group(g) => g.items.iter().for_each(|i| names(i, under_macros, out)),
            _ => {}
        }
    }
    for it in &file.items {
        if let syn::Item::Use(u) = it {
            names(&u.tree, false, &mut out);
        }
    }
    out
}

#[test]
fn facade_exports_match_annotations() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let annots: BTreeSet<String> = Annot::ALL.iter().map(|a| a.name().to_string()).collect();
    for a in Annot::ALL {
        assert_eq!(Annot::from_name(a.name()), Some(*a));
    }
    assert_eq!(Annot::from_name("critical"), None, "there is no profile (§15.8)");
    // the erasing macros
    let text = std::fs::read_to_string(crates.join("macros/src/lib.rs")).unwrap();
    let file = syn::parse_file(&text).unwrap();
    let macros: BTreeSet<String> = file
        .items
        .iter()
        .filter_map(|i| match i {
            syn::Item::Fn(f) if f.attrs.iter().any(|a| a.path().is_ident("proc_macro_attribute")) => Some(f.sig.ident.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(macros, annots, "sandblaster-macros must define exactly one erasing macro per `Annot`");
    // the facade: the prelude exports every attribute but `proof` (the
    // `proof!` statement macro has that name there); `ghost` exports `proof`
    let prelude = facade_exports(&crates.join("sandblaster/src/prelude.rs"));
    let ghost = facade_exports(&crates.join("sandblaster/src/ghost.rs"));
    let mut expected = annots.clone();
    expected.remove("proof");
    assert_eq!(prelude, expected, "sandblaster::prelude must export every annotation but `proof`");
    assert!(ghost.contains("proof"));
    assert!(ghost.is_subset(&annots), "sandblaster::ghost exports only annotations: {ghost:?}");
    let all: BTreeSet<String> = prelude.union(&ghost).cloned().collect();
    assert_eq!(all, annots);
}
