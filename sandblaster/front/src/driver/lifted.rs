//! Lifted modules in module mode (DESIGN.md §2.1 "lifted modules",
//! SEMANTICS.md §19): a DSL crate whose code is existing Rust declared
//! `#[lift] mod m;` emits **that source file as-is**.
//!
//! The proofs are about the lift's reading of the file (the translation is
//! part of the elaboration semantics, TCB, SEMANTICS.md §19); the printed
//! lifted items are state-passing functions over the buffer model, not the
//! host's `Buf`/`BufMut` code, so they are never emitted. After every proof
//! and every §15 gate passed (the same `GatesPassed` seal as the printed
//! verdict), the emitted file is:
//!
//! 1. a header: the verdict status, what is verified (the boundary), what
//!    is not (instances declared `#[lift(unverified = ..)]`, items the lift
//!    dropped), the host-model modules and the `SPEC.lock` root;
//! 2. the lifted module's source text **byte for byte** after its leading
//!    `//!` lines — those are the module's inner docs, which an
//!    `include!`d file cannot carry: they live in the host's module file,
//!    whose `//!` lines must be exactly the source's
//!    ([`module_file_docs_ok`]), so module file + emitted body is the
//!    original file;
//! 3. a tail of `const _` items rustc checks in the host: every host fact
//!    the lift's reading assumed (`<T as FixedSize>::SIZE == size_of::<T>()`
//!    for each `T::SIZE` it read) and every variant of the
//!    `#[lift(host)]` enums (name and payload types), named through the
//!    source's own scope.
//!
//! Exactly one lifted exec module may be emitted (the others must be
//! `#[lift(host)]` models); a source whose text after its docs holds an
//! inner attribute (`#![..]`) is refused (an `include!`d file cannot carry
//! one). Crate mode (`sandblaster::build::compile`) refuses a lifted crate:
//! the source names host items through `crate::`.

use crate::lift::{LiftFacts, LiftedInfo};

/// The status line of an emitted lifted module.
pub const LIFTED: &str = "VERIFIED + LIFTED AS-IS (module mode)";
/// The status line of an emitted lifted module with functions rewritten to
/// their optimized residuals ([`super::lowered`]).
pub const LIFTED_OPTIMIZED: &str = "VERIFIED + LIFTED + OPTIMIZED (module mode)";

/// The lifted exec module to emit: `Ok(None)` for a crate without lifted
/// exec modules, an error for more than one that is not `#[lift(host)]` or
/// for lifted exec modules that are all host models.
pub fn emitted_module(lifted: &[LiftedInfo]) -> Result<Option<&LiftedInfo>, String> {
    // optimization alternatives (`#[lift(opt)]`) are never emitted
    let exec: Vec<&LiftedInfo> = lifted.iter().filter(|l| !l.ghost && !l.opt).collect();
    if exec.is_empty() {
        return Ok(None);
    }
    let emitted: Vec<&LiftedInfo> = exec.iter().copied().filter(|l| !l.host).collect();
    match emitted.as_slice() {
        [one] => Ok(Some(one)),
        [] => Err("lifted modules: every `#[lift]` exec module is `#[lift(host)]`; one must be the module to emit".into()),
        more => Err(format!(
            "lifted modules: {} `#[lift]` exec modules are not `#[lift(host)]` ({}): module mode emits exactly one lifted module; mark the host models `#[lift(host)]`",
            more.len(),
            more.iter().map(|l| format!("`{}`", l.name)).collect::<Vec<_>>().join(", ")
        )),
    }
}

/// Splits a source file into its leading `//!` lines (the module's inner
/// docs, each line with its newline) and the rest.
pub fn split_docs(text: &str) -> (&str, &str) {
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        if !line.starts_with("//!") {
            break;
        }
        at += line.len();
    }
    text.split_at(at)
}

/// The `//!` lines of a module file (in order, without newlines).
fn doc_lines(text: &str) -> Vec<&str> {
    text.lines().filter(|l| l.trim_start().starts_with("//!")).map(|l| l.trim_start().trim_end()).collect()
}

/// Whether the module file's `//!` lines are exactly the source's leading
/// `//!` lines (trailing whitespace aside).
pub fn module_file_docs_ok(module_text: &str, source_text: &str) -> bool {
    let (docs, _) = split_docs(source_text);
    doc_lines(module_text) == doc_lines(docs)
}

/// Whether the text after the docs has a top-level inner attribute or inner
/// doc comment before its first item (tokens, comments skipped).
fn has_inner_attribute(body: &str) -> bool {
    let mut rest = body;
    loop {
        let t = rest.trim_start();
        if let Some(r) = t.strip_prefix("//") {
            if r.starts_with('!') {
                return true;
            }
            rest = r.split_once('\n').map(|(_, b)| b).unwrap_or("");
            continue;
        }
        if let Some(r) = t.strip_prefix("/*") {
            if r.starts_with('!') {
                return true;
            }
            rest = r.split_once("*/").map(|(_, b)| b).unwrap_or("");
            continue;
        }
        return t.starts_with("#!");
    }
}

/// A lifted instance name as the source writes it: `UInt__u16` → `UInt<u16>`
/// (backquotes kept).
fn pretty_instance(name: &str) -> String {
    let (q, inner) = match name.strip_prefix('`').and_then(|n| n.strip_suffix('`')) {
        Some(n) => (true, n),
        None => (false, name),
    };
    let mut parts = inner.split("__");
    let head = parts.next().unwrap_or(inner);
    let args: Vec<&str> = parts.collect();
    let out = if args.is_empty() { head.to_string() } else { format!("{head}<{}>", args.join(", ")) };
    if q { format!("`{out}`") } else { out }
}

/// What the header lists besides the status.
pub struct HeaderInfo<'a> {
    pub root_display: &'a str,
    pub module_file: &'a str,
    pub source_display: &'a str,
    pub boundary: Vec<String>,
    pub host_models: Vec<String>,
    pub spec_root: String,
    pub summary: &'a str,
}

/// The emitted file of a lifted module (module docs), or why none is
/// emitted.
pub fn module_code(source_text: &str, info: &LiftedInfo, facts: &LiftFacts, h: &HeaderInfo<'_>) -> Result<String, Vec<String>> {
    module_code_with(source_text, info, facts, h, None)
}

/// [`module_code`] with the optimizer's lowering ([`super::lowered`]): when
/// functions were rewritten, the body is the lowered source (the source
/// with those bodies replaced and the checked helpers appended) and the
/// header lists them; otherwise the source as-is.
pub fn module_code_with(source_text: &str, info: &LiftedInfo, facts: &LiftFacts, h: &HeaderInfo<'_>, lowered: Option<&super::lowered::LoweredModule>) -> Result<String, Vec<String>> {
    let (_, src_body) = split_docs(source_text);
    let rewritten = lowered.filter(|l| l.lowered() > 0);
    let body: &str = match rewritten {
        Some(l) => &l.body,
        None => src_body,
    };
    if has_inner_attribute(body) {
        return Err(vec![format!(
            "lifted module `{}`: the source has an inner attribute or inner doc comment after its leading `//!` lines; an `include!`d file cannot carry one (move it to the module file `{}`)",
            info.name, h.module_file
        )]);
    }
    let mut s = String::new();
    s.push_str(&format!("// @generated by sandblaster from `{}`. Do not edit.\n", h.root_display));
    s.push_str(&format!("// STATUS: {}:\n", if rewritten.is_some() { LIFTED_OPTIMIZED } else { LIFTED }));
    s.push_str(&format!("//   {}\n", h.summary));
    match rewritten {
        None => s.push_str(&format!(
            "// The code below is `{}` byte for byte after its leading `//!` lines, which are the docs of the host's\n// module file `{}` (checked equal). The proofs are about the lift's reading of it (SEMANTICS.md §19).\n",
            h.source_display, h.module_file
        )),
        Some(l) => {
            s.push_str(&format!(
                "// The code below is `{}` after its leading `//!` lines (the docs of the host's module file `{}`, checked\n// equal), except the bodies of the functions listed here: each calls its optimized residual, appended at the end,\n// kernel-checked equal to the function and read back by the lift (the lifted round trip, DESIGN.md §2.1).\n",
                h.source_display, h.module_file
            ));
            for r in &l.records {
                if let super::lowered::LowerOutcome::Lowered { rung, cost_source, cost_residual, helpers, via } = &r.outcome {
                    let via = if via.is_empty() { String::new() } else { format!("; {via}") };
                    s.push_str(&format!("//   rewritten: `{}` (rung {rung}; portable cost {} -> {} milli-cycles; {}{via})\n", r.function, cost_source, cost_residual, helpers.join(", ")));
                }
            }
        }
    }
    s.push_str(&format!("// Verified (the DSL root's boundary, lifted instances as `Item<T>`): {}.\n", h.boundary.iter().map(|b| pretty_instance(b)).collect::<Vec<_>>().join(", ")));
    if info.unverified.is_empty() && facts.dropped.is_empty() {
        s.push_str("// Not verified: nothing in this file is outside the lift.\n");
    } else {
        if !info.unverified.is_empty() {
            s.push_str(&format!("// Not verified (declared `#[lift(unverified = ..)]`, unchecked host code): the {} instances.\n", info.unverified.join(", ")));
        }
        let mut listed: Vec<String> = Vec::new();
        for d in &facts.dropped {
            let line = format!("// Not verified (dropped by the lift, unchecked host code): {} ({}).\n", d.what.replace('\n', " "), d.why.replace('\n', " "));
            if !listed.contains(&line) {
                listed.push(line);
            }
        }
        for line in listed {
            s.push_str(&line);
        }
    }
    if !h.host_models.is_empty() {
        s.push_str(&format!("// Host models the proofs assume (checked by rustc at the end of this file): {}.\n", h.host_models.join(", ")));
    }
    s.push_str(&format!("// SPEC.lock root: {}\n", h.spec_root));
    s.push_str(body);
    if !body.ends_with('\n') {
        s.push('\n');
    }
    let tail = facts.tail_items();
    if !tail.is_empty() {
        s.push_str("\n// sandblaster: the host facts the lift's reading of this file assumes, checked by rustc.\n");
        for t in tail {
            s.push_str(&t);
            s.push('\n');
        }
    }
    Ok(s)
}

/// The status line of a crate verified in place.
pub const LIFTED_IN_PLACE: &str = "VERIFIED + LIFTED IN PLACE (module mode)";

/// What the in-place record lists besides the status.
pub struct InPlaceInfo<'a> {
    pub root_display: &'a str,
    /// Every in-place lifted file (as read) and the SHA-256 of its text.
    pub files: Vec<(String, String)>,
    pub boundary: Vec<String>,
    pub host_models: Vec<String>,
    pub spec_root: String,
    pub summary: &'a str,
}

/// The record of a crate verified in place (`OUT_DIR/<name>-verified.txt`):
/// the host compiles its own files, which are the lifted sources, so
/// nothing is emitted; the record says which files (with their hashes)
/// were verified, at which open-trait instances, what stays unchecked host
/// code (other instances, dropped items), and the preconditions the host
/// must meet at the boundary.
pub fn in_place_record(h: &InPlaceInfo<'_>, facts: &LiftFacts) -> String {
    let mut s = String::new();
    s.push_str(&format!("// @generated by sandblaster from `{}`. Do not edit.\n", h.root_display));
    s.push_str(&format!("// STATUS: {LIFTED_IN_PLACE}:\n"));
    s.push_str(&format!("//   {}\n", h.summary));
    s.push_str("// The host compiles these files as they are; they are the lifted sources (SEMANTICS.md §19):\n");
    for (p, d) in &h.files {
        s.push_str(&format!("//   {p} sha256 {d}\n"));
    }
    s.push_str(&format!("// Boundary (the DSL root's `pub use` list): {}.\n", if h.boundary.is_empty() { "(none)".to_string() } else { h.boundary.join(", ") }));
    for (t, p) in &facts.open_instances {
        s.push_str(&format!("// Verified at the instance {p} of the open trait `{t}`.\n"));
    }
    for (t, p) in &facts.unverified_instances {
        s.push_str(&format!("// Not verified (declared `unverified_instances`, unchecked host code): the instance {p} of `{t}`.\n"));
    }
    let mut listed: Vec<String> = Vec::new();
    for d in &facts.dropped {
        let line = format!("// Not verified (dropped by the lift, unchecked host code): {} ({}).\n", d.what.replace('\n', " "), d.why.replace('\n', " "));
        if !listed.contains(&line) {
            listed.push(line);
        }
    }
    for line in listed {
        s.push_str(&line);
    }
    for (f, r) in &facts.host_obligations {
        s.push_str(&format!("// Host obligation (a precondition, proven at every lifted call, unchecked at host calls): `{f}` requires `{r}`.\n"));
    }
    if !h.host_models.is_empty() {
        s.push_str(&format!("// Host models the proofs assume: {}.\n", h.host_models.join(", ")));
    }
    s.push_str(&format!("// SPEC.lock root: {}\n", h.spec_root));
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::span::FileId;

    fn info(name: &str, ghost: bool, host: bool) -> LiftedInfo {
        LiftedInfo { name: name.into(), file: FileId::default(), ghost, host, unverified: vec![], in_place: false, opt: false }
    }

    #[test]
    fn instance_names_print_as_the_source_writes_them() {
        assert_eq!(pretty_instance("`UInt__u16`"), "`UInt<u16>`");
        assert_eq!(pretty_instance("Error"), "Error");
    }

    #[test]
    fn exactly_one_emitted_module() {
        assert!(emitted_module(&[]).unwrap().is_none());
        assert!(emitted_module(&[info("proof", true, false)]).unwrap().is_none());
        assert_eq!(emitted_module(&[info("varint", false, false), info("error", false, true), info("proof", true, false)]).unwrap().unwrap().name, "varint");
        // negative twins: two emitted modules, only host models
        assert!(emitted_module(&[info("a", false, false), info("b", false, false)]).unwrap_err().contains("exactly one"));
        assert!(emitted_module(&[info("error", false, true)]).unwrap_err().contains("one must be the module to emit"));
    }

    #[test]
    fn docs_split_and_module_file_check() {
        let src = "//! A.\n//!\n//! B.\n\nuse x::y;\nfn f() {}\n";
        let (d, b) = split_docs(src);
        assert_eq!(d, "//! A.\n//!\n//! B.\n");
        assert_eq!(b, "\nuse x::y;\nfn f() {}\n");
        assert_eq!(format!("{d}{b}"), src);
        let inc = "include!(concat!(env!(\"OUT_DIR\"), \"/m.rs\"));\n";
        assert!(module_file_docs_ok(&format!("//! A.\n//!\n//! B.\n\n// note\n{inc}"), src));
        // negative twins: a changed, missing or extra doc line
        assert!(!module_file_docs_ok(&format!("//! A!\n//!\n//! B.\n{inc}"), src));
        assert!(!module_file_docs_ok(&format!("//! A.\n//! B.\n{inc}"), src));
        assert!(!module_file_docs_ok(&format!("//! A.\n//!\n//! B.\n//! C.\n{inc}"), src));
    }

    #[test]
    fn the_emitted_file_is_the_source_after_its_docs() {
        let src = "//! Docs.\n\nuse crate::{Error, FixedSize};\npub fn f() -> Error { Error::EndOfBuffer }\n";
        let mut facts = LiftFacts::default();
        facts.sizes.insert(("u16".into(), 2));
        facts.host_checks.push("const _: Error = Error::EndOfBuffer;".into());
        let h = HeaderInfo { root_display: "r/mod.rs", module_file: "src/m.rs", source_display: "r/m.rs", boundary: vec!["f".into()], host_models: vec!["error".into()], spec_root: "00".into(), summary: "ok" };
        let code = module_code(src, &info("m", false, false), &facts, &h).unwrap();
        assert!(code.starts_with("// @generated by sandblaster from `r/mod.rs`. Do not edit.\n// STATUS: VERIFIED + LIFTED AS-IS"));
        let (_, body) = split_docs(src);
        assert!(code.contains(body));
        assert!(code.ends_with("const _: () = assert!(<u16 as FixedSize>::SIZE == 2usize);\nconst _: Error = Error::EndOfBuffer;\n"));
        assert!(!code.lines().any(|l| l.starts_with("//!")));
        // negative twin: an inner attribute after the docs is refused
        let bad = "//! Docs.\n#![allow(dead_code)]\nfn f() {}\n";
        assert!(module_code(bad, &info("m", false, false), &facts, &h).unwrap_err()[0].contains("inner attribute"));
        let bad2 = "//! Docs.\n// c\n/*! inner */\nfn f() {}\n";
        assert!(module_code(bad2, &info("m", false, false), &facts, &h).is_err());
    }
}
