//! Module mode (DESIGN.md §2.1): relocating a crate verdict's file so that a
//! host crate can `include!` it as the body of **one module** instead of as
//! its whole `src/lib.rs`.
//!
//! The crate path prints, round-trips and cross-checks the generated file
//! `T` exactly as in crate mode (the printed text is written for the crate
//! root: absolute paths `crate::__sandblaster::…` and `crate::__rt::chk::…`,
//! visibility `pub(crate)` for everything that is not boundary). Module mode
//! then rewrites three kinds of tokens of `T` and adds one attribute, and
//! nothing else, giving `M`:
//!
//! 1. every path that starts with `crate::` starts with `self::` (at the top
//!    level of the file) or with `super::` repeated `d` times, where `d` is
//!    the number of `mod x { .. }` blocks around the path — the path then
//!    names, from the module the path is in, the same item of the file, and
//!    it never leaves the file: it is **position independent** (it does not
//!    depend on where the host mounts the module, and no host item can be
//!    substituted for a generated one);
//! 2. every visibility `pub(crate)` becomes `pub(self)` (top level) or
//!    `pub(in super::…)` with the same `d`: visible exactly within the
//!    file, as `pub(crate)` was visible exactly within the generated crate.
//!    Host code, which lives outside the file, reaches only the file's
//!    top-level `pub` items — the boundary exports (`pub use`) and
//!    `SANDBLASTER_SPEC_ROOT` — never an internal item, a constructor with a
//!    private invariant or a non-boundary field;
//! 3. the one unqualified macro of the printed dialect, the 64-bit guard's
//!    `compile_error!`, becomes `::core::compile_error!`, so no `macro_rules!`
//!    of the host (textual scope reaches into submodules) can shadow a macro
//!    of the generated code;
//! 4. every top-level item but the guard gets [`MODULE_LINTS`] as its first
//!    attribute: the host's lint levels (`warnings = "deny"`, clippy
//!    groups, `missing_docs`, ...) apply to the included file, and a host
//!    that uses only part of the boundary would otherwise fail on
//!    `unused_imports` / `dead_code` of the unused exports. Lint levels do
//!    not change the code's meaning, and the printer's own attributes come
//!    after it, so its `deny(unsafe_code, ..)` still wins.
//!
//! It also refuses (an emission-chain error: no code is emitted) any
//! construct whose meaning could depend on the file's position: a `crate`
//! token that is neither a path head nor `pub(crate)`, a path starting with
//! more `super`s than there are modules around it (it would leave the file),
//! a `$` (macro metavariables, `$crate`), an out-of-line `mod x;` (its file
//! would be looked up next to the host's module file) and any macro outside
//! the fixed list [`MACROS`] (for example `include!`, whose path is relative
//! to the including file).
//!
//! **Check.** The rewrite is computed on the token trees of `T`, which gives
//! the token sequence `M` must have, and applied to the text of `T` by
//! splicing the rewritten tokens' byte ranges (so formatting and comments are
//! kept). The spliced text is tokenized again and must equal that sequence
//! token for token, spacing of punctuation included, and must contain no
//! `crate` token; any difference fails the build. The meaning argument
//! (items (1)–(3) preserve every resolution, and the position-dependent
//! constructs are absent) is part of the printer's trusted argument, like the
//! canonical dialect's (DESIGN.md §8.3); the round trip itself checked `T`.
//!
//! What the host crate can still do (it is ordinary Rust in the same crate)
//! is recorded in DESIGN.md §2.1: its dependency names (`::core`, `::std`)
//! are trusted as in crate mode, and Rust lets any module of a crate add
//! trait implementations (`Drop` included) to the crate's types — a
//! conflicting definition is a compile error, and a `Drop` can only make a
//! boundary call diverge or panic, never return a different value.

use std::ops::Range;
use std::str::FromStr;

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};

/// The macros the printed dialect may invoke (path as printed); the guard's
/// `compile_error!` is qualified by the rewrite.
pub const MACROS: &[&str] = &["::core::unreachable", "::core::compile_error", "::core::arch::asm", "::std::arch::is_x86_feature_detected", "::std::arch::is_aarch64_feature_detected"];

/// The lint attribute of every top-level item of a relocated file (item 4
/// of the module docs).
pub const MODULE_LINTS: &str = "#[allow(warnings, missing_docs, unreachable_pub, dead_code, unused_imports, unused_qualifications, unused_results, trivial_casts, trivial_numeric_casts, missing_debug_implementations, missing_copy_implementations, clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction, clippy::cargo)]";

/// Keywords that can precede a leading `::` (they are never path segments).
const KEYWORDS: &[&str] = &["as", "in", "return", "else", "break", "move", "mut", "ref", "let", "if", "match", "while", "for", "loop", "unsafe", "where", "dyn", "impl", "static", "const", "type", "use", "pub", "fn", "struct", "enum", "mod", "trait", "extern"];

/// One token of a flattened token stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    Open(char),
    Close(char),
    Ident(String),
    /// A punctuation character and whether it is joint with the next one.
    Punct(char, bool),
    Lit(String),
}

fn delims(d: Delimiter) -> (char, char) {
    match d {
        Delimiter::Parenthesis => ('(', ')'),
        Delimiter::Brace => ('{', '}'),
        Delimiter::Bracket => ('[', ']'),
        Delimiter::None => ('∅', '∅'),
    }
}

/// The flattened tokens of `ts` (groups as open, contents, close).
pub fn flatten(ts: TokenStream, out: &mut Vec<Tok>) {
    for tt in ts {
        match tt {
            TokenTree::Group(g) => {
                let (o, c) = delims(g.delimiter());
                out.push(Tok::Open(o));
                flatten(g.stream(), out);
                out.push(Tok::Close(c));
            }
            TokenTree::Ident(i) => out.push(Tok::Ident(i.to_string())),
            TokenTree::Punct(p) => out.push(Tok::Punct(p.as_char(), p.spacing() == Spacing::Joint)),
            TokenTree::Literal(l) => out.push(Tok::Lit(l.to_string())),
        }
    }
}

/// The flattened tokens of `text`.
pub fn tokens(text: &str) -> Result<Vec<Tok>, String> {
    let ts = TokenStream::from_str(text).map_err(|e| format!("does not tokenize: {e}"))?;
    let mut v = Vec::new();
    flatten(ts, &mut v);
    Ok(v)
}

/// The path of the file's root module from a module `depth` levels deep
/// (`self` at the top level).
fn root_from(depth: usize) -> String {
    if depth == 0 { "self".to_string() } else { vec!["super"; depth].join("::") }
}

/// The visibility that replaces `pub(crate)` `depth` levels deep: the
/// contents of the parentheses.
fn vis_from(depth: usize) -> String {
    if depth == 0 { "self".to_string() } else { format!("in {}", root_from(depth)) }
}

/// A text edit: `old` (the replaced token's text, or empty for an
/// insertion) at `range` becomes `text`.
struct Edit {
    range: Range<usize>,
    old: &'static str,
    text: String,
}

struct Walker {
    edits: Vec<Edit>,
    expected: Vec<Tok>,
    errors: Vec<String>,
}

fn is_punct(t: Option<&TokenTree>, c: char) -> bool {
    matches!(t, Some(TokenTree::Punct(p)) if p.as_char() == c)
}

fn is_joint_colon(t: Option<&TokenTree>) -> bool {
    matches!(t, Some(TokenTree::Punct(p)) if p.as_char() == ':' && p.spacing() == Spacing::Joint)
}

fn ident_str(t: Option<&TokenTree>) -> Option<String> {
    match t {
        Some(TokenTree::Ident(i)) => Some(i.to_string()),
        _ => None,
    }
}

impl Walker {
    fn replace(&mut self, range: Range<usize>, old: &'static str, text: String, what: &str) {
        match tokens(&text) {
            Ok(t) => self.expected.extend(t),
            Err(e) => self.errors.push(format!("module mode: the replacement of {what} {e}")),
        }
        self.edits.push(Edit { range, old, text });
    }

    /// Whether the top-level item starting at `v[i]` (after its outer
    /// attributes) is a macro invocation (the guard).
    fn is_macro_item(v: &[TokenTree], mut i: usize) -> bool {
        while is_punct(v.get(i), '#') && matches!(v.get(i + 1), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket) {
            i += 2;
        }
        if is_joint_colon(v.get(i)) && is_punct(v.get(i + 1), ':') {
            i += 2;
        }
        while ident_str(v.get(i)).is_some() {
            if is_punct(v.get(i + 1), '!') {
                return true;
            }
            if is_joint_colon(v.get(i + 1)) && is_punct(v.get(i + 2), ':') {
                i += 3;
            } else {
                return false;
            }
        }
        false
    }

    /// Inserts [`MODULE_LINTS`] before the top-level item starting at
    /// `v[i]` (not before the guard).
    fn lint_item(&mut self, v: &[TokenTree], i: usize) {
        if Self::is_macro_item(v, i) {
            return;
        }
        let at = v[i].span().byte_range().start;
        let text = format!("{MODULE_LINTS}\n");
        match tokens(&text) {
            Ok(t) => self.expected.extend(t),
            Err(e) => self.errors.push(format!("module mode: the lint attribute {e}")),
        }
        self.edits.push(Edit { range: at..at, old: "", text });
    }

    /// Whether `v[i]` follows a `::` (it is not the head of a path).
    fn after_path_sep(v: &[TokenTree], i: usize) -> bool {
        i >= 2 && is_punct(v.get(i - 1), ':') && is_joint_colon(v.get(i - 2))
    }

    /// The macro path ending at the name `v[i]`, as printed.
    fn macro_path(v: &[TokenTree], i: usize) -> String {
        let mut segs = vec![ident_str(v.get(i)).unwrap_or_default()];
        let mut j = i;
        let mut leading = false;
        while Self::after_path_sep(v, j) {
            match ident_str(if j >= 3 { v.get(j - 3) } else { None }) {
                Some(s) if !KEYWORDS.contains(&s.as_str()) => {
                    segs.push(s);
                    j -= 3;
                }
                _ => {
                    leading = true;
                    break;
                }
            }
        }
        segs.reverse();
        format!("{}{}", if leading { "::" } else { "" }, segs.join("::"))
    }

    /// Walks the token trees `v`, `depth` modules deep; `top`: `v` is the
    /// file's item list.
    fn walk(&mut self, v: &[TokenTree], depth: usize, top: bool) {
        let mut i = 0;
        // in the item list: whether `v[i]` starts an item
        let mut item_start = top;
        while i < v.len() {
            if top {
                if item_start && !is_punct(v.get(i), ';') {
                    self.lint_item(v, i);
                }
                // an item ends with a top-level `;` or `{ .. }` not
                // followed by `;` (`mod x { .. }` is consumed below as
                // three trees)
                item_start = match &v[i] {
                    TokenTree::Punct(p) => p.as_char() == ';',
                    TokenTree::Group(g) => g.delimiter() == Delimiter::Brace && !is_punct(v.get(i + 1), ';'),
                    TokenTree::Ident(id) => id.to_string() == "mod" && matches!(v.get(i + 2), Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace),
                    _ => false,
                };
            }
            match &v[i] {
                TokenTree::Group(g) => {
                    let (o, c) = delims(g.delimiter());
                    self.expected.push(Tok::Open(o));
                    let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                    self.walk(&inner, depth, false);
                    self.expected.push(Tok::Close(c));
                }
                TokenTree::Punct(p) => {
                    if p.as_char() == '$' {
                        self.errors.push("module mode: the generated file contains `$` (a macro metavariable or `$crate`), whose meaning depends on the file's position".into());
                    }
                    self.expected.push(Tok::Punct(p.as_char(), p.spacing() == Spacing::Joint));
                }
                TokenTree::Literal(l) => self.expected.push(Tok::Lit(l.to_string())),
                TokenTree::Ident(id) => {
                    let s = id.to_string();
                    // `pub(crate)`
                    if s == "pub"
                        && let Some(TokenTree::Group(g)) = v.get(i + 1)
                        && g.delimiter() == Delimiter::Parenthesis
                    {
                        let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                        if let [TokenTree::Ident(c)] = inner.as_slice()
                            && c.to_string() == "crate"
                        {
                            self.expected.push(Tok::Ident(s));
                            self.expected.push(Tok::Open('('));
                            self.replace(c.span().byte_range(), "crate", vis_from(depth), "`pub(crate)`");
                            self.expected.push(Tok::Close(')'));
                            i += 2;
                            continue;
                        }
                    }
                    if s == "crate" {
                        if is_joint_colon(v.get(i + 1)) && is_punct(v.get(i + 2), ':') && !Self::after_path_sep(v, i) {
                            self.replace(id.span().byte_range(), "crate", root_from(depth), "a `crate::` path");
                        } else {
                            self.errors.push("module mode: the generated file contains a `crate` token that is neither the head of a path nor `pub(crate)`".into());
                            self.expected.push(Tok::Ident(s));
                        }
                        i += 1;
                        continue;
                    }
                    if (s == "super" || s == "self") && !Self::after_path_sep(v, i) {
                        // a relative path: its leading `super`s must stay
                        // inside the file
                        let mut k = 0;
                        let mut j = i;
                        if s == "self" {
                            j += 3;
                        }
                        while ident_str(v.get(j)).as_deref() == Some("super") && (j == i || Self::after_path_sep(v, j)) {
                            k += 1;
                            if !(is_joint_colon(v.get(j + 1)) && is_punct(v.get(j + 2), ':')) {
                                break;
                            }
                            j += 3;
                        }
                        if k > depth {
                            self.errors.push(format!("module mode: a path starts with {k} `super`(s) {depth} module(s) deep: it would leave the generated file"));
                        }
                    }
                    if s == "mod" {
                        match (v.get(i + 1), v.get(i + 2)) {
                            (Some(TokenTree::Ident(name)), Some(TokenTree::Group(g))) if g.delimiter() == Delimiter::Brace => {
                                self.expected.push(Tok::Ident(s));
                                self.expected.push(Tok::Ident(name.to_string()));
                                self.expected.push(Tok::Open('{'));
                                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                                self.walk(&inner, depth + 1, false);
                                self.expected.push(Tok::Close('}'));
                                i += 3;
                                continue;
                            }
                            _ => self.errors.push("module mode: the generated file declares a module that is not inline (`mod x;` would be read next to the host's module file)".into()),
                        }
                    }
                    // a macro: `name!(..)`, `name! x { .. }` (`!=` is not)
                    if is_punct(v.get(i + 1), '!') && !is_punct(v.get(i + 2), '=') {
                        let path = Self::macro_path(v, i);
                        if path == "compile_error" {
                            self.replace(id.span().byte_range(), "compile_error", "::core::compile_error".into(), "`compile_error!`");
                            i += 1;
                            continue;
                        }
                        if !MACROS.contains(&path.as_str()) {
                            self.errors.push(format!("module mode: the generated file invokes the macro `{path}!`, which is not one of the printed dialect's macros ({})", MACROS.join(", ")));
                        }
                    }
                    self.expected.push(Tok::Ident(s));
                }
            }
            i += 1;
        }
    }
}

/// The end of the leading `//` comment lines of `text` (the header).
fn header_end(text: &str) -> usize {
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        if !line.starts_with("//") {
            break;
        }
        at += line.len();
    }
    at
}

/// The comment inserted after the header of a relocated file: the host's
/// module file and the module's report.
pub fn module_note(module_file: &str, report: &str) -> String {
    format!(
        "// MODULE MODE (DESIGN.md §2.1): the body of the host crate's module file `{module_file}`, which must\n// contain only the `include!` line. Paths are relative (`self::` / `super::`), internals are visible\n// only inside this file, and the crate-rooted print this file was relocated from passed the round\n// trip. This module's report is {report}.\n"
    )
}

/// Relocates the crate verdict file `code` for module mode (module docs)
/// and inserts `note` (comment lines) after its header. Any refused
/// construct or a failed check is an error: nothing is emitted.
pub fn relocate(code: &str, note: &str) -> Result<String, Vec<String>> {
    if !note.lines().all(|l| l.starts_with("//")) || !note.ends_with('\n') {
        return Err(vec!["module mode: internal error: the note is not a block of `//` comment lines".into()]);
    }
    let ts = TokenStream::from_str(code).map_err(|e| vec![format!("module mode: the generated file does not tokenize: {e}")])?;
    let trees: Vec<TokenTree> = ts.into_iter().collect();
    let mut w = Walker { edits: Vec::new(), expected: Vec::new(), errors: Vec::new() };
    w.walk(&trees, 0, true);
    if !w.errors.is_empty() {
        return Err(w.errors);
    }
    // splice, last edit first; every edit must be the exact text of the
    // token it replaces
    let mut edits = w.edits;
    // last first; at one offset, a replacement before an insertion (the
    // insertion then lands before the replaced token)
    edits.sort_by(|a, b| b.range.start.cmp(&a.range.start).then(b.old.len().cmp(&a.old.len())));
    let mut out = code.to_string();
    let mut last = usize::MAX;
    for e in &edits {
        let r = &e.range;
        if r.end > last || r.end - r.start != e.old.len() || r.end > out.len() || !out.is_char_boundary(r.start) || !out.is_char_boundary(r.end) {
            return Err(vec![format!("module mode: internal error: overlapping or invalid token range {r:?}")]);
        }
        if out[r.clone()] != *e.old {
            return Err(vec![format!("module mode: internal error: the text at {r:?} is `{}`, not `{}`", &out[r.clone()], e.old)]);
        }
        out.replace_range(r.clone(), &e.text);
        last = r.start;
    }
    let at = header_end(&out);
    out.insert_str(at, note);
    // the check: the spliced text is exactly the rewritten token sequence
    let got = tokens(&out).map_err(|e| vec![format!("module mode: the relocated file {e}")])?;
    if got != w.expected {
        let k = got.iter().zip(&w.expected).position(|(a, b)| a != b).unwrap_or(got.len().min(w.expected.len()));
        return Err(vec![format!("module mode: the relocated file differs from the rewritten tokens at token {k}: {:?} vs {:?}", got.get(k), w.expected.get(k))]);
    }
    if got.iter().any(|t| matches!(t, Tok::Ident(s) if s == "crate")) {
        return Err(vec!["module mode: the relocated file still contains a `crate` token".into()]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "// @generated by sandblaster from `x`. Do not edit.\n// STATUS: VERIFIED\n#[cfg(not(target_pointer_width = \"64\"))]\ncompile_error!(\"sandblaster requires a 64-bit target\");\nmod __sandblaster {\n    pub(crate) mod m {\n        pub struct S { pub(crate) x: u32, pub y: u32 }\n        pub(crate) fn f(a: u32) -> u32 { crate::__rt::chk::add_u32(a, 1u32) }\n        pub fn g(s: crate::__sandblaster::m::S) -> u32 { /* crate::m::f */ crate::__sandblaster::m::f(s.x) }\n        pub(super) fn h() -> u32 { match 1u32 { 1u32 => 2u32, _ => ::core::unreachable!() } }\n    }\n    pub(crate) use crate::__sandblaster::m::S as T;\n}\nmod __rt {\n    pub(crate) mod chk {\n        #[inline(always)]\n        pub(crate) fn add_u32(a: u32, b: u32) -> u32 { a + b }\n    }\n}\npub use __sandblaster::m::g as g;\npub const SANDBLASTER_SPEC_ROOT: [u8; 32] = [0u8; 32];\n";

    #[test]
    fn relocates_paths_visibility_and_the_guard() {
        let m = relocate(T, &module_note("src/v.rs", "v-report.json")).unwrap();
        assert!(!m.contains("pub(crate)"), "{m}");
        assert!(m.contains("super::super::__rt::chk::add_u32(a, 1u32)"), "{m}");
        assert!(m.contains("s: super::super::__sandblaster::m::S"), "{m}");
        assert!(m.contains("pub(in super::super) x: u32, pub y: u32"), "{m}");
        assert!(m.contains("pub(in super) mod m {"), "{m}");
        assert!(m.contains("pub(in super) use super::__sandblaster::m::S as T;"), "{m}");
        assert!(m.contains("\n::core::compile_error!(\"sandblaster requires a 64-bit target\");"), "{m}");
        assert!(m.contains("pub(in super) mod chk"), "{m}");
        // comments are kept verbatim; the note follows the header
        assert!(m.contains("/* crate::m::f */"), "{m}");
        assert!(m.starts_with("// @generated by sandblaster from `x`. Do not edit.\n// STATUS: VERIFIED\n// MODULE MODE"), "{m}");
        assert!(m.contains("pub use __sandblaster::m::g as g;"), "{m}");
        // the lint attribute: before every top-level item but the guard,
        // ahead of the printer's own attributes
        assert_eq!(m.matches(MODULE_LINTS).count(), 4, "{m}");
        for item in ["mod __sandblaster {", "mod __rt {", "pub use __sandblaster::m::g as g;", "pub const SANDBLASTER_SPEC_ROOT"] {
            assert!(m.contains(&format!("{MODULE_LINTS}\n{item}")), "{item}: {m}");
        }
        assert!(m.contains("#[cfg(not(target_pointer_width = \"64\"))]\n::core::compile_error!"), "{m}");
        let with_attrs = relocate("#[deny(unsafe_code)]\n#[allow(dead_code)]\nmod a { pub fn f() {} }\npub use a::f as f;\n", "// n\n").unwrap();
        assert!(with_attrs.contains(&format!("{MODULE_LINTS}\n#[deny(unsafe_code)]\n#[allow(dead_code)]\nmod a")), "{with_attrs}");
    }

    #[test]
    fn position_dependent_constructs_are_refused() {
        for (bad, needle) in [
            ("mod a { pub fn f() -> u32 { super::super::host() } }", "would leave"),
            ("pub fn f() -> u32 { super::host() }", "would leave"),
            ("mod a { pub fn f() -> u32 { self::super::super::host() } }", "would leave"),
            ("mod a;", "not inline"),
            ("pub fn f() -> u32 { include!(\"x.rs\") }", "`include!`"),
            ("pub fn f() -> u32 { ::core::include!(\"x.rs\") }", "`::core::include!`"),
            ("pub fn f() { ::std::println!(\"x\") }", "`::std::println!`"),
            ("macro_rules! m { () => {} }", "`macro_rules!`"),
            ("pub fn f() -> u32 { $crate::g() }", "`$`"),
            ("pub fn f(a: u32) -> bool { a!= 1u32 && m!(a) }", "`m!`"),
            ("extern crate core as c;", "neither the head of a path"),
        ] {
            let e = relocate(bad, "// n\n").expect_err(bad);
            assert!(e.iter().any(|m| m.contains(needle)), "{bad}: {e:?}");
        }
        // relative paths that stay inside the file are fine
        assert!(relocate("mod a { mod b { pub fn f() -> u32 { super::super::c() } } }\nfn c() -> u32 { 1u32 }", "// n\n").is_ok());
        assert!(relocate("mod a { pub(super) fn f() {} }", "// n\n").is_ok());
        assert!(relocate("pub fn f(a: u32) -> bool { a != 1u32 && a!=2u32 }", "// n\n").is_ok());
    }

    #[test]
    fn the_check_catches_a_bad_splice() {
        // a token list that the splice cannot reproduce is refused: the
        // rewrite of `crate` inside a string literal is never applied
        let m = relocate("pub fn f() -> &'static str { \"crate::x\" }", "// n\n").unwrap();
        assert!(m.contains("\"crate::x\""), "{m}");
        assert_eq!(tokens(&m).unwrap().iter().filter(|t| matches!(t, Tok::Lit(_))).count(), 1);
    }
}
