//! §15 annotations: parsing, resolution, surface typing and placement
//! (DESIGN.md §15; the S0 interface of §15.12).
//!
//! This module turns the §15 attributes into the HIR records of
//! [`crate::hir`] ([`SpecAnnots`], [`TypeInvariant`], [`View`],
//! [`Represents`], [`Param::ghost`], [`Module::spec`]). It gives them no
//! meaning: the later stages do (S1–S3), and until they land the elaborator
//! reports every record as "not implemented yet" (`crate::elab`).
//!
//! | Annotation | Placement | Typed as |
//! | --- | --- | --- |
//! | `#[spec]` on `mod m;` | ghost module declaration, `cfg` first | every `fn` inside defaults to `#[spec]` |
//! | `#[refines(s)]`, `#[refines(s(e..))]`, `#[refines(s, domain = P)]` | exec fn (not a `#[implements]` variant) | `s` a spec fn; `eᵢ` ghost expressions over the parameters (expected: the spec's parameter types, not coerced); `P` a proposition |
//! | `#[proof(refines = f)]`, `#[proof(complete = f)]` | `#[proof]` item | `f` an exec fn (pairing: [`crate::validate`]) |
//! | `#[example(e)]` | spec or exec fn | a closed `bool` spec expression |
//! | `#[examples(file = "..", format = "cavp" \| "json", provenance = independent \| production \| self)]` | spec fn returning `bool` (a checker) | the file is a build input (read by the loader) |
//! | `#[invariant(p)]` | struct | a proposition over the fields (`self.f`); no bare `self`, no methods of the struct |
//! | `#[view(spec::T)]` | struct | `T` a struct of a `#[spec]` module with exactly the same field names |
//! | `#[view(\|s\| e)]` | struct or enum | `e` a ghost expression over `s : Self` |
//! | `#[represents(\|s: &S, a: A\| P)]` | struct | `P` a proposition; `A` annotated |
//! | `#[ghost] x: T` | exec fn parameter | an `Irr` binder of a ghost type |
//! | `#[section(with = [f, ..])]` | exec fn | exec fns |
//! | `#[mirrors_impl(justification = "..")]` | spec fn | a non-empty justification |
//! | `#[fuel_sufficient]`, `#[fuel_sufficient(s)]` | lemma | `s` a spec fn |
//! | `#[trusted_extern(justification = "..")]` | exec fn with a contract | a non-empty justification |
//! | `#[mirrors_impl(of = f, justification = "..")]` | spec fn | `f` an exec fn (the function it coincides with, §15.1 LR5) |
//! | `#[reduces_to(a)]` | law | `a` a spec fn (an `#[assumption]`: checked by the law rules, `elab::law_rules`) |
//! | `#[assumption(class = computational \| statistical \| environmental, cite = "..")]` | spec fn | a non-empty citation |
//! | `#[definitional(reason = "..")]` | law | a non-empty reason |
//! | `#[corollary]` | law | no arguments |
//! | `#[opaque]` | spec fn | no arguments (the definition is opaque in proofs) |
//!
//! `#[refines]` on a type is an error (DESIGN.md §9.6: representation types
//! use `#[view]` and `#[invariant]`), and so is any form of
//! `sandblaster::critical` (§15.8: §15 is always on; there is no profile).

use syn::spanned::Spanned;

use super::expr::Cx;
use super::{annotation_of, Checker, FnSig, GenScope};
use crate::diag::{DiagKind, Diagnostic};
use crate::hir::*;
use crate::resolve::{Annot, Def, ItemSrc, ItemTag, Ns};
use crate::span::Span;

/// The invariant being typed ([`Cx::inv_self`]): the struct and its field
/// binders, in declaration order.
#[derive(Clone, Debug)]
pub struct InvSelf {
    pub owner: ItemId,
    /// `(field name or None for tuple fields, binder)`.
    pub fields: Vec<(Option<String>, LocalId)>,
}

/// Whether `e` is the bare path `self`.
pub fn is_self_path(e: &syn::Expr) -> bool {
    match e {
        syn::Expr::Path(p) => p.qself.is_none() && p.path.is_ident("self"),
        syn::Expr::Paren(p) => is_self_path(&p.expr),
        syn::Expr::Group(g) => is_self_path(&g.expr),
        _ => false,
    }
}

/// `#[refines(..)]` as parsed.
#[derive(Clone)]
pub struct RefinesSyn {
    pub target: syn::Path,
    pub args: Option<Vec<syn::Expr>>,
    pub domain: Option<syn::Expr>,
    pub span: Span,
}

/// The §15 annotations of a function, parsed but not yet resolved/typed
/// (types need every signature; see [`Cx::lower_fn_spec`]).
#[derive(Clone, Default)]
pub struct FnSpecSyn {
    pub refines: Option<RefinesSyn>,
    pub proof_of: Option<(ProofKind, syn::Path, Span)>,
    /// `#[proof(..)]` with malformed arguments (reported).
    pub proof_malformed: bool,
    pub examples: Vec<(syn::Expr, Span)>,
    pub example_files: Vec<ExampleFile>,
    pub section: Option<(Vec<syn::Path>, Span)>,
    pub mirrors_impl: Option<Justified>,
    pub fuel_sufficient: Option<(Option<syn::Path>, Span)>,
    pub trusted_extern: Option<Justified>,
    /// `#[mirrors_impl(of = path, ..)]`.
    pub mirrors_of: Option<(syn::Path, Span)>,
    /// `#[reduces_to(path)]`.
    pub reduces_to: Option<(syn::Path, Span)>,
    pub assumption: Option<Assumption>,
    pub definitional: Option<Justified>,
    pub corollary: Option<Span>,
    /// `#[opaque]`.
    pub opaque: Option<Span>,
    /// `#[induction(x)]` (validated by the script checker).
    pub induction: Option<(String, Span)>,
    /// `#[rewrite]`.
    pub rewrite: bool,
}

/// Where an attribute is written (for placement diagnostics).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Site {
    Struct,
    Enum,
    Const,
    Alias,
    Field,
    Variant,
    Impl,
    /// A `use` item.
    Use,
    /// Inside a body: a statement, expression, match arm or pattern.
    Body,
    Fn(FnKind),
}

impl Site {
    pub fn text(self) -> &'static str {
        match self {
            Site::Struct => "a struct",
            Site::Enum => "an enum",
            Site::Const => "a constant",
            Site::Alias => "a type alias",
            Site::Field => "a field",
            Site::Variant => "an enum variant",
            Site::Impl => "an `impl` block",
            Site::Use => "a `use` item",
            Site::Body => "a statement or expression",
            Site::Fn(FnKind::Exec) => "an exec function",
            Site::Fn(FnKind::Spec) => "a spec function",
            Site::Fn(FnKind::Lemma) => "a lemma",
            Site::Fn(FnKind::Law) => "a law",
            Site::Fn(FnKind::Proof) => "a proof",
        }
    }
    fn is_type(self) -> bool {
        matches!(self, Site::Struct | Site::Enum | Site::Alias)
    }
}

/// Where each annotation belongs, as a note for a misplaced one.
pub fn placement_note(an: Annot, site: Site) -> String {
    match an {
        Annot::Refines if site.is_type() => "`#[refines]` applies to exec functions only; a representation type states its meaning with `#[view(..)]` and its invariant with `#[invariant(..)]`, and each operation on it carries `#[refines(spec::op)]` (DESIGN.md §9.6, §15.3)".into(),
        Annot::Refines => "`#[refines(spec::f)]` belongs on the exec function that implements the spec function `spec::f` (DESIGN.md §15.2)".into(),
        Annot::Example => "`#[example(e)]` belongs on a spec function, an exec function or a ghost constant (DESIGN.md §15.7)".into(),
        Annot::Examples => "`#[examples(file = ..)]` belongs on a ghost checker function (a spec function returning `bool`) whose parameters name the record fields (DESIGN.md §15.7)".into(),
        Annot::Invariant if site == Site::Body => "a loop invariant is a script statement, `proof! { invariant(p); }` at the top of the loop body (DESIGN.md §7.4); `#[invariant(p)]` belongs on a struct (§15.3)".into(),
        Annot::Invariant => "`#[invariant(p)]` belongs on a struct (DESIGN.md §15.3)".into(),
        Annot::View => "`#[view(..)]` belongs on a struct or an enum (DESIGN.md §15.3)".into(),
        Annot::Represents => "`#[represents(|s, a| P)]` belongs on a struct (DESIGN.md §15.3)".into(),
        Annot::Ghost => "`#[ghost]` belongs on a parameter of an exec function (DESIGN.md §15.3)".into(),
        Annot::Section => "`#[section(with = [..])]` belongs on an exec function (DESIGN.md §15.5)".into(),
        Annot::MirrorsImpl => "`#[mirrors_impl(justification = \"..\")]` belongs on a spec function (DESIGN.md §15.1)".into(),
        Annot::FuelSufficient => "`#[fuel_sufficient]` belongs on the lemma proving that a fuel-bounded spec function has enough fuel (DESIGN.md §15.1)".into(),
        Annot::TrustedExtern => "`#[trusted_extern(justification = \"..\")]` belongs on an exec function with a contract (DESIGN.md §15.8)".into(),
        Annot::ReducesTo => "`#[reduces_to(assumption)]` belongs on a `#[law]` stated in extraction form (DESIGN.md §15.1 LR4, §15.13)".into(),
        Annot::Assumption => "`#[assumption(class = .., cite = \"..\")]` belongs on a spec function without logical content, `fn name() {}` (DESIGN.md §15.13)".into(),
        Annot::Definitional => "`#[definitional(reason = \"..\")]` belongs on a `#[law]` that is intentionally one unfolding of a definition (DESIGN.md §15.1 LR6)".into(),
        Annot::Corollary => "`#[corollary]` belongs on a `#[law]` proven from other laws (DESIGN.md §15.1 LR7)".into(),
        Annot::Opaque => "`#[opaque]` belongs on a spec function (exec functions with loops, buffers or codec readers are opaque in proofs already, DESIGN.md §5.6)".into(),
        Annot::Spec => "`#[spec]` belongs on a ghost function or on a ghost module declaration `#[cfg(sandblaster)] #[spec] mod m;` (DESIGN.md §15.1)".into(),
        _ if site == Site::Body => format!("`#[{}]` belongs on an item; inside a body, state facts and loop annotations with `proof! {{ .. }}` statements (DESIGN.md §4, §7.4)", an.name()),
        _ if site == Site::Use => format!("`#[{}]` belongs on the item's declaration, not on its `use` (DESIGN.md §15)", an.name()),
        _ => format!("`#[{}]` is not allowed on {}", an.name(), site.text()),
    }
}

/// A `justification = ".."` argument (non-empty).
fn justification(ck: &mut Checker, m: ModId, a: &syn::Attribute, name: &str) -> Option<Justified> {
    let span = ck.sp(m, a.span());
    let nv = match a.parse_args::<syn::MetaNameValue>() {
        Ok(nv) if nv.path.is_ident("justification") => nv,
        _ => {
            ck.diags.push(Diagnostic::error(DiagKind::Attribute, span, format!("expected `#[{name}(justification = \"..\")]`")).note("the justification is part of the locked specification surface (DESIGN.md §15.6)"));
            return None;
        }
    };
    match &nv.value {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) if !s.value().trim().is_empty() => Some(Justified { justification: s.value(), span }),
        _ => {
            ck.err(DiagKind::Attribute, span, format!("`#[{name}]` needs a non-empty string `justification = \"..\"`"));
            None
        }
    }
}

/// `#[definitional(reason = "..")]` (non-empty).
fn reason(ck: &mut Checker, a: &syn::Attribute, span: Span) -> Option<Justified> {
    match a.parse_args::<syn::MetaNameValue>() {
        Ok(nv) if nv.path.is_ident("reason") => match &nv.value {
            syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) if !s.value().trim().is_empty() => Some(Justified { justification: s.value(), span }),
            _ => {
                ck.err(DiagKind::Attribute, span, "`#[definitional]` needs a non-empty string `reason = \"..\"`");
                None
            }
        },
        _ => {
            ck.diags.push(Diagnostic::error(DiagKind::Attribute, span, "expected `#[definitional(reason = \"..\")]`").note("a definitional law is printed under its own heading on the spec sheet and never counted as a guarantee; the reason says why it is stated at all (DESIGN.md §15.1 LR6)"));
            None
        }
    }
}

/// A string or bare-identifier attribute value.
fn word(e: &syn::Expr) -> Option<String> {
    match e {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => Some(s.value()),
        syn::Expr::Path(p) if p.qself.is_none() && p.path.segments.len() == 1 => Some(p.path.segments[0].ident.to_string()),
        _ => None,
    }
}

impl<'a> Checker<'a> {
    /// Parses the §15 annotations of a function (only those `allowed` for
    /// its kind; misplaced ones were reported by `common_attrs`).
    pub fn parse_fn_spec(&mut self, m: ModId, attrs: &[syn::Attribute], kind: FnKind, allowed: &[&str]) -> FnSpecSyn {
        let mut out = FnSpecSyn::default();
        for a in attrs {
            let Some((an, _)) = annotation_of(a.path()) else { continue };
            if !allowed.contains(&an.name()) {
                continue;
            }
            let span = self.sp(m, a.span());
            match an {
                Annot::Refines => {
                    if out.refines.is_some() {
                        self.err(DiagKind::Attribute, span, "at most one `#[refines]` per function");
                        continue;
                    }
                    out.refines = self.parse_refines(a, span);
                }
                Annot::Proof if kind == FnKind::Proof => {
                    if let syn::Meta::List(_) = &a.meta {
                        let parsed = a.parse_args::<syn::MetaNameValue>().ok().and_then(|nv| {
                            let k = if nv.path.is_ident("refines") {
                                ProofKind::Refines
                            } else if nv.path.is_ident("complete") {
                                ProofKind::Complete
                            } else if nv.path.is_ident("view_inj") {
                                ProofKind::ViewInj
                            } else {
                                return None;
                            };
                            match nv.value {
                                syn::Expr::Path(p) if p.qself.is_none() => Some((k, p.path)),
                                _ => None,
                            }
                        });
                        match parsed {
                            Some((k, p)) => out.proof_of = Some((k, p, span)),
                            None => {
                                out.proof_malformed = true;
                                self.diags.push(
                                    Diagnostic::error(DiagKind::Attribute, span, "expected `#[proof]`, `#[proof(refines = path::f)]`, `#[proof(complete = path::f)]` or `#[proof(view_inj = path::T)]`")
                                        .note("a plain `#[proof]` proves the law of the same name; `refines = f` proves `f::refines`, `complete = f` the completeness of `f`'s section, `view_inj = T` that the view of `T` is injective (DESIGN.md §15.2, §15.5)"),
                                )
                            }
                        }
                    }
                }
                Annot::Example => match a.parse_args::<syn::Expr>() {
                    Ok(e) => out.examples.push((e, span)),
                    Err(e) => self.err(DiagKind::Attribute, span, format!("malformed `#[example]`: {e} (expected a closed `bool` spec expression)")),
                },
                Annot::Examples => {
                    if let Some(f) = self.parse_examples(m, a, span) {
                        out.example_files.push(f);
                    }
                }
                Annot::Section => {
                    if out.section.is_some() {
                        self.err(DiagKind::Attribute, span, "at most one `#[section]` per function");
                        continue;
                    }
                    let paths = a.parse_args::<syn::MetaNameValue>().ok().filter(|nv| nv.path.is_ident("with")).and_then(|nv| match nv.value {
                        syn::Expr::Array(arr) => arr
                            .elems
                            .iter()
                            .map(|e| match e {
                                syn::Expr::Path(p) if p.qself.is_none() => Some(p.path.clone()),
                                _ => None,
                            })
                            .collect::<Option<Vec<_>>>(),
                        _ => None,
                    });
                    match paths {
                        Some(ps) if !ps.is_empty() => out.section = Some((ps, span)),
                        _ => self.diags.push(
                            Diagnostic::error(DiagKind::Attribute, span, "expected `#[section(with = [f, g, ..])]` naming exec functions")
                                .note("sections are computed (DESIGN.md §15.5); `#[section(with = ..)]` only merges this function's section with others"),
                        ),
                    }
                }
                Annot::MirrorsImpl => {
                    let (of, j) = self.parse_mirrors_impl(m, a, span);
                    out.mirrors_of = of;
                    out.mirrors_impl = j;
                }
                Annot::ReducesTo => match a.parse_args::<syn::Path>() {
                    Ok(p) => out.reduces_to = Some((p, span)),
                    Err(_) => self.diags.push(
                        Diagnostic::error(DiagKind::Attribute, span, "expected `#[reduces_to(assumption)]` naming an `#[assumption]` spec function")
                            .note("a law stated in extraction form names the assumption its break predicate refutes (DESIGN.md §15.1 LR4, LR9, §15.13)"),
                    ),
                },
                Annot::Assumption => out.assumption = self.parse_assumption(a, span),
                Annot::Definitional => out.definitional = reason(self, a, span),
                Annot::Corollary => match &a.meta {
                    syn::Meta::Path(_) => out.corollary = Some(span),
                    _ => self.err(DiagKind::Attribute, span, "expected `#[corollary]` (no arguments): the laws it follows from are the ones its proof applies"),
                },
                Annot::Opaque => match &a.meta {
                    syn::Meta::Path(_) => out.opaque = Some(span),
                    _ => self.err(DiagKind::Attribute, span, "expected `#[opaque]` (no arguments)"),
                },
                Annot::TrustedExtern => out.trusted_extern = justification(self, m, a, "trusted_extern"),
                Annot::FuelSufficient => match &a.meta {
                    syn::Meta::Path(_) => out.fuel_sufficient = Some((None, span)),
                    _ => match a.parse_args::<syn::Path>() {
                        Ok(p) => out.fuel_sufficient = Some((Some(p), span)),
                        Err(_) => self.err(DiagKind::Attribute, span, "expected `#[fuel_sufficient]` or `#[fuel_sufficient(spec_fn)]`"),
                    },
                },
                Annot::Induction => {
                    if let Ok(id) = a.parse_args::<syn::Ident>() {
                        out.induction = Some((id.to_string(), span));
                    }
                }
                Annot::Rewrite => out.rewrite = true,
                _ => {}
            }
        }
        out
    }

    /// `#[mirrors_impl(justification = "..")]` or `#[mirrors_impl(of =
    /// path, justification = "..")]` (the arguments in any order).
    fn parse_mirrors_impl(&mut self, m: ModId, a: &syn::Attribute, span: Span) -> (Option<(syn::Path, Span)>, Option<Justified>) {
        let usage = "expected `#[mirrors_impl(justification = \"..\")]` or `#[mirrors_impl(of = path::f, justification = \"..\")]`";
        let Ok(list) = a.parse_args_with(syn::punctuated::Punctuated::<syn::MetaNameValue, syn::Token![,]>::parse_terminated) else {
            return (None, justification(self, m, a, "mirrors_impl"));
        };
        let (mut of, mut just) = (None, None);
        for nv in list {
            if nv.path.is_ident("of") {
                match nv.value {
                    syn::Expr::Path(p) if p.qself.is_none() => of = Some((p.path, span)),
                    _ => self.err(DiagKind::Attribute, span, "`of` must be a path to the exec function the spec coincides with"),
                }
            } else if nv.path.is_ident("justification") {
                match &nv.value {
                    syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) if !s.value().trim().is_empty() => just = Some(Justified { justification: s.value(), span }),
                    _ => self.err(DiagKind::Attribute, span, "`#[mirrors_impl]` needs a non-empty string `justification = \"..\"`"),
                }
            } else {
                self.diags.push(Diagnostic::error(DiagKind::Attribute, span, usage).note("the justification is part of the locked specification surface (DESIGN.md §15.6)"));
            }
        }
        if just.is_none() {
            self.diags.push(Diagnostic::error(DiagKind::Attribute, span, usage).note("the justification is part of the locked specification surface (DESIGN.md §15.6)"));
        }
        (of, just)
    }

    /// `#[assumption(class = computational | statistical | environmental,
    /// cite = "..")]` (DESIGN.md §15.13).
    fn parse_assumption(&mut self, a: &syn::Attribute, span: Span) -> Option<Assumption> {
        let usage = "expected `#[assumption(class = computational | statistical | environmental, cite = \"..\")]`";
        let Ok(list) = a.parse_args_with(syn::punctuated::Punctuated::<syn::MetaNameValue, syn::Token![,]>::parse_terminated) else {
            self.err(DiagKind::Attribute, span, usage);
            return None;
        };
        let (mut class, mut cite) = (None, None);
        for nv in list {
            let key = nv.path.get_ident().map(|i| i.to_string()).unwrap_or_default();
            match key.as_str() {
                "class" => match word(&nv.value).as_deref() {
                    Some("computational") => class = Some(AssumptionClass::Computational),
                    Some("statistical") => class = Some(AssumptionClass::Statistical),
                    Some("environmental") => class = Some(AssumptionClass::Environmental),
                    _ => self.err(DiagKind::Attribute, span, "`class` must be `computational`, `statistical` or `environmental`"),
                },
                "cite" => match &nv.value {
                    syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) if !s.value().trim().is_empty() => cite = Some(s.value()),
                    _ => self.err(DiagKind::Attribute, span, "`cite` must be a non-empty string naming the source of the assumption"),
                },
                _ => {
                    self.err(DiagKind::Attribute, span, usage);
                    return None;
                }
            }
        }
        match (class, cite) {
            (Some(class), Some(cite)) => Some(Assumption { class, cite, span }),
            _ => {
                self.diags.push(Diagnostic::error(DiagKind::Attribute, span, usage).note("an assumption has no logical content: the spec sheet lists it with its class and citation next to every law that relies on it (DESIGN.md §15.13)"));
                None
            }
        }
    }

    fn parse_refines(&mut self, a: &syn::Attribute, span: Span) -> Option<RefinesSyn> {
        let bad = |ck: &mut Checker, why: &str| {
            ck.diags.push(
                Diagnostic::error(DiagKind::Attribute, span, format!("malformed `#[refines]`: {why}"))
                    .note("forms: `#[refines(spec::f)]`, `#[refines(spec::f(e1, .., en))]` (explicit arguments), `#[refines(spec::f, domain = P)]` (internal functions; DESIGN.md §15.2)"),
            );
            None
        };
        let args = match a.parse_args_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated) {
            Ok(a) => a.into_iter().collect::<Vec<_>>(),
            Err(e) => return bad(self, &e.to_string()),
        };
        let Some(first) = args.first() else { return bad(self, "missing the spec function") };
        let (target, call_args) = match first {
            syn::Expr::Path(p) if p.qself.is_none() => (p.path.clone(), None),
            syn::Expr::Call(c) => match &*c.func {
                syn::Expr::Path(p) if p.qself.is_none() => (p.path.clone(), Some(c.args.iter().cloned().collect::<Vec<_>>())),
                _ => return bad(self, "expected a path to a spec function"),
            },
            _ => return bad(self, "expected a path to a spec function"),
        };
        let mut domain = None;
        for extra in &args[1..] {
            match extra {
                syn::Expr::Assign(asg) if matches!(&*asg.left, syn::Expr::Path(p) if p.path.is_ident("domain")) => {
                    if domain.is_some() {
                        return bad(self, "`domain` given twice");
                    }
                    domain = Some((*asg.right).clone());
                }
                _ => return bad(self, "expected `domain = P` after the spec function"),
            }
        }
        Some(RefinesSyn { target, args: call_args, domain, span })
    }

    fn parse_examples(&mut self, m: ModId, a: &syn::Attribute, span: Span) -> Option<ExampleFile> {
        let usage = "expected `#[examples(file = \"..\", format = \"cavp\" | \"json\", provenance = independent | production | self)]`";
        let Ok(list) = a.parse_args_with(syn::punctuated::Punctuated::<syn::MetaNameValue, syn::Token![,]>::parse_terminated) else {
            self.err(DiagKind::Attribute, span, usage);
            return None;
        };
        let (mut file, mut format, mut provenance) = (None, None, None);
        for nv in list {
            let key = nv.path.get_ident().map(|i| i.to_string()).unwrap_or_default();
            match key.as_str() {
                "file" => match &nv.value {
                    syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(s), .. }) => file = Some(s.value()),
                    _ => self.err(DiagKind::Attribute, span, "`file` must be a string literal (a path relative to this file's directory)"),
                },
                "format" => match word(&nv.value).as_deref() {
                    Some("cavp") => format = Some(ExampleFormat::Cavp),
                    Some("json") => format = Some(ExampleFormat::Json),
                    _ => self.err(DiagKind::Attribute, span, "`format` must be \"cavp\" or \"json\""),
                },
                "provenance" => match word(&nv.value).as_deref() {
                    Some("independent") => provenance = Some(Provenance::Independent),
                    Some("production") => provenance = Some(Provenance::Production),
                    Some("self") => provenance = Some(Provenance::SelfDerived),
                    _ => self.err(DiagKind::Attribute, span, "`provenance` must be `independent`, `production` or `self`"),
                },
                _ => self.err(DiagKind::Attribute, span, format!("unknown `#[examples]` argument `{key}`; {usage}")),
            }
        }
        let (Some(path), Some(format), Some(provenance)) = (file.clone(), format, provenance) else {
            let missing: Vec<&str> = [(file.is_none(), "file"), (format.is_none(), "format"), (provenance.is_none(), "provenance")].iter().filter(|(b, _)| *b).map(|(_, n)| *n).collect();
            if !missing.is_empty() {
                self.diags.push(
                    Diagnostic::error(DiagKind::Attribute, span, format!("`#[examples]` is missing {}", missing.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(", ")))
                        .note(usage)
                        .note("the provenance is locked with the file's hash; self-derived vectors do not count as validation (DESIGN.md §15.7)"),
                );
            }
            return None;
        };
        match self.res.mods[m.0 as usize].data_files.get(&path) {
            Some(id) => Some(ExampleFile { path, file: *id, format, provenance, span, text: String::new() }),
            None => {
                self.err(DiagKind::Load, span, format!("vector file `{path}` could not be read"));
                None
            }
        }
    }

    /// Validates the attributes of a function parameter; returns whether
    /// it is `#[ghost]`.
    pub fn param_attrs(&mut self, m: ModId, attrs: &[syn::Attribute], kind: FnKind, item_ghost: bool) -> bool {
        let mut ghost = false;
        for a in attrs {
            let span = self.sp(m, a.span());
            if crate::resolve::is_critical_attr(a) {
                self.diags.push(crate::resolve::critical_diagnostic(span));
                continue;
            }
            match annotation_of(a.path()) {
                Some((Annot::Ghost, _)) => {
                    if !matches!(a.meta, syn::Meta::Path(_)) {
                        self.err(DiagKind::Attribute, span, "`#[ghost]` takes no arguments");
                    }
                    if kind != FnKind::Exec || item_ghost {
                        self.diags.push(Diagnostic::error(DiagKind::Attribute, span, "`#[ghost]` is only allowed on parameters of exec functions").note("every parameter of a ghost item is ghost already (DESIGN.md §15.3)"));
                    } else {
                        ghost = true;
                    }
                }
                Some((an, _)) => self.diags.push(Diagnostic::error(DiagKind::Attribute, span, format!("`#[{}]` is not allowed on a parameter", an.name())).note(placement_note(an, Site::Fn(kind)))),
                None => {
                    let n = quote::ToTokens::to_token_stream(a.path()).to_string().replace(' ', "");
                    self.diags.push(Diagnostic::error(DiagKind::Attribute, span, format!("attribute `#[{n}]` is not allowed on a parameter")).note("the only parameter attribute is `#[ghost]` (DESIGN.md §15.3)"));
                }
            }
        }
        ghost
    }

    /// Types the §15 annotations of struct/enum `id` (after all signatures).
    pub fn lower_type_spec(&mut self, id: ItemId) {
        let it = self.res.items[id.0 as usize].clone();
        let (attrs, is_struct) = match &it.src {
            ItemSrc::Struct(s) => (s.attrs.clone(), true),
            ItemSrc::Enum(e) => (e.attrs.clone(), false),
            _ => return,
        };
        let generics: Vec<TyParam> = match &self.hir_items[id.0 as usize] {
            Some(ItemKind::Struct(s)) => s.generics.clone(),
            Some(ItemKind::Enum(e)) => e.generics.clone(),
            _ => return,
        };
        let params: Vec<String> = generics.iter().map(|p| p.name.clone()).collect();
        let self_ty = Ty::Adt(id, generics.iter().enumerate().map(|(i, p)| Ty::Param(i as u32, p.name.clone())).collect());
        let g = GenScope { params, self_ty: Some(self_ty.clone()) };
        let mut inv_attrs = Vec::new();
        let mut view = None;
        let mut represents = None;
        for a in &attrs {
            let Some((an, _)) = annotation_of(a.path()) else { continue };
            let span = self.sp(it.module, a.span());
            match an {
                Annot::Invariant if is_struct => inv_attrs.push((a.clone(), span)),
                Annot::View => {
                    if view.is_some() {
                        self.err(DiagKind::Attribute, span, "at most one `#[view]` per type");
                        continue;
                    }
                    view = self.lower_view(id, it.module, a, span, &g, &self_ty, is_struct);
                }
                Annot::Represents if is_struct => {
                    if represents.is_some() {
                        self.err(DiagKind::Attribute, span, "at most one `#[represents]` per type");
                        continue;
                    }
                    represents = self.lower_represents(id, it.module, a, span, &g, &self_ty);
                }
                _ => {}
            }
        }
        let invariant = if inv_attrs.is_empty() { None } else { self.lower_invariants(id, it.module, &inv_attrs, &g) };
        match &mut self.hir_items[id.0 as usize] {
            Some(ItemKind::Struct(s)) => {
                s.invariant = invariant;
                s.view = view;
                s.represents = represents;
            }
            Some(ItemKind::Enum(e)) => e.view = view,
            _ => {}
        }
    }

    fn lower_invariants(&mut self, id: ItemId, m: ModId, attrs: &[(syn::Attribute, Span)], g: &GenScope) -> Option<TypeInvariant> {
        let Some(ItemKind::Struct(sd)) = self.hir_items[id.0 as usize].clone() else { return None };
        let mut cx = Cx::new(self, m, None, FnKind::Spec, true, Ty::Prop, g.clone(), vec![]);
        cx.push_scope();
        let mut fields = Vec::new();
        let mut binders = Vec::new();
        for (i, f) in sd.fields.iter().enumerate() {
            let name = match &f.name {
                Some(n) => format!("self.{n}"),
                None => format!("self.{i}"),
            };
            // not added to a scope: reachable only as `self.f`
            let l = LocalId(cx.locals.len() as u32);
            cx.locals.push(LocalDecl { name, ty: f.ty.clone(), mutable: false, ghost: true, span: f.span });
            fields.push((f.name.clone(), l));
            binders.push(l);
        }
        cx.inv_self = Some(InvSelf { owner: id, fields });
        let mut props = Vec::new();
        for (a, span) in attrs {
            match a.parse_args::<syn::Expr>() {
                Ok(e) => {
                    let p = cx.prop(&e);
                    props.push((p, *span));
                }
                Err(e) => cx.err(DiagKind::Attribute, *span, format!("malformed `#[invariant]`: {e} (expected a proposition over the fields, e.g. `#[invariant(self.0 < MAX)]`)")),
            }
        }
        cx.inv_self = None;
        cx.pop_scope();
        let locals = std::mem::take(&mut cx.locals);
        Some(TypeInvariant { fields: binders, props, locals })
    }

    #[allow(clippy::too_many_arguments)]
    fn lower_view(&mut self, id: ItemId, m: ModId, a: &syn::Attribute, span: Span, g: &GenScope, self_ty: &Ty, is_struct: bool) -> Option<View> {
        let usage = "expected `#[view(spec::T)]` (structural, onto a struct of a `#[spec]` module) or `#[view(|s| e)]` (DESIGN.md §15.3)";
        let arg = match a.parse_args::<syn::Expr>() {
            Ok(e) => e,
            Err(_) => {
                self.err(DiagKind::Attribute, span, usage);
                return None;
            }
        };
        match &arg {
            syn::Expr::Path(p) if p.qself.is_none() => {
                if !is_struct {
                    self.diags.push(Diagnostic::error(DiagKind::Attribute, span, "the structural view `#[view(spec::T)]` maps fields and applies to structs only").note("use `#[view(|s| e)]` for an enum"));
                    return None;
                }
                let segs: Vec<(String, Span)> = p.path.segments.iter().map(|s| (s.ident.to_string(), self.sp(m, s.ident.span()))).collect();
                let target = match self.res.resolve_path_defs(m, &segs, Ns::Type, p.path.leading_colon.is_some(), true) {
                    Ok(Def::Item(t)) if matches!(self.res.items[t.0 as usize].tag, ItemTag::Struct { .. }) => t,
                    Ok(_) => {
                        self.diags.push(Diagnostic::error(DiagKind::Attribute, span, "the structural view must name a struct").note(usage));
                        return None;
                    }
                    Err(d) => {
                        self.diags.push(d);
                        return None;
                    }
                };
                let tmod = self.res.items[target.0 as usize].module;
                if !self.res.mods[tmod.0 as usize].spec && !self.res.mods[tmod.0 as usize].model {
                    let tn = self.res.items[target.0 as usize].path.to_string();
                    self.diags.push(Diagnostic::error(DiagKind::Attribute, span, format!("`{tn}` is not a spec type")).note("the structural view maps onto a struct declared in a `#[spec]` or `#[model]` module (DESIGN.md §15.1, §15.3)"));
                    return None;
                }
                let (Some(ItemKind::Struct(s)), Some(ItemKind::Struct(t))) = (self.hir_items[id.0 as usize].clone(), self.hir_items[target.0 as usize].clone()) else { return None };
                let names = |fs: &[FieldDef]| fs.iter().enumerate().map(|(i, f)| f.name.clone().unwrap_or_else(|| i.to_string())).collect::<Vec<_>>();
                let (sn, tn) = (names(&s.fields), names(&t.fields));
                let missing: Vec<&String> = sn.iter().filter(|n| !tn.contains(n)).collect();
                let extra: Vec<&String> = tn.iter().filter(|n| !sn.contains(n)).collect();
                if s.shape != t.shape || !missing.is_empty() || !extra.is_empty() {
                    let tpath = self.res.items[target.0 as usize].path.to_string();
                    let mut d = Diagnostic::error(DiagKind::Attribute, span, format!("the structural view onto `{tpath}` must map every field to the same-named field"));
                    if !missing.is_empty() {
                        d = d.note(format!("`{tpath}` has no field {}", missing.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(", ")));
                    }
                    if !extra.is_empty() {
                        d = d.note(format!("fields of `{tpath}` not mapped: {}", extra.iter().map(|n| format!("`{n}`")).collect::<Vec<_>>().join(", ")));
                    }
                    if s.shape != t.shape {
                        d = d.note("the two structs have different shapes (named / tuple / unit)");
                    }
                    self.diags.push(d.note("mapping every field is what makes a structural view injective (DESIGN.md §15.3); use `#[view(|s| e)]` otherwise"));
                    return None;
                }
                Some(View::Struct { target, span })
            }
            syn::Expr::Closure(c) => {
                if c.inputs.len() != 1 {
                    self.err(DiagKind::Attribute, span, "a view closure takes exactly one parameter: `#[view(|s| e)]`");
                    return None;
                }
                let mut cx = Cx::new(self, m, None, FnKind::Spec, true, Ty::Error, g.clone(), vec![]);
                cx.push_scope();
                let binder = closure_binder(&mut cx, &c.inputs[0], self_ty, true, "view")?;
                let body = cx.infer(&c.body);
                let body = cx.autoderef_if_ref(body);
                cx.pop_scope();
                let locals = std::mem::take(&mut cx.locals);
                Some(View::Fn { binder, body, locals, span })
            }
            _ => {
                self.err(DiagKind::Attribute, span, usage);
                None
            }
        }
    }

    fn lower_represents(&mut self, _id: ItemId, m: ModId, a: &syn::Attribute, span: Span, g: &GenScope, self_ty: &Ty) -> Option<Represents> {
        let usage = "expected `#[represents(|s: &S, a: spec::A| P)]` (DESIGN.md §15.3)";
        let Ok(syn::Expr::Closure(c)) = a.parse_args::<syn::Expr>() else {
            self.err(DiagKind::Attribute, span, usage);
            return None;
        };
        if c.inputs.len() != 2 {
            self.diags.push(Diagnostic::error(DiagKind::Attribute, span, "a representation relation takes the value and the abstract state: `|s: &S, a: spec::A| P`").note(usage));
            return None;
        }
        let mut cx = Cx::new(self, m, None, FnKind::Spec, true, Ty::Prop, g.clone(), vec![]);
        cx.push_scope();
        // the representation: `S` or `&S`
        let (repr, by_ref) = match &c.inputs[0] {
            syn::Pat::Type(pt) => {
                let t = cx.ck.lower_ty(m, &pt.ty, g, true);
                let by_ref = match &t {
                    Ty::Ref(inner) if **inner == *self_ty => true,
                    t if t == self_ty => false,
                    Ty::Error => false,
                    other => {
                        let (x, y) = (cx.tys(other), cx.tys(self_ty));
                        cx.err(DiagKind::Attribute, span, format!("the first parameter of `#[represents]` is the value (`{y}` or `&{y}`), found `{x}`"));
                        false
                    }
                };
                let ty = if by_ref { Ty::reference(self_ty.clone()) } else { self_ty.clone() };
                (closure_pat_local(&mut cx, &pt.pat, &ty), by_ref)
            }
            p => (closure_pat_local(&mut cx, p, &Ty::reference(self_ty.clone())), true),
        };
        let repr = repr?;
        // the abstract state: annotated
        let syn::Pat::Type(pt) = &c.inputs[1] else {
            cx.push(Diagnostic::error(DiagKind::Attribute, span, "annotate the abstract state: `|s: &S, a: spec::A| P`").note(usage));
            cx.pop_scope();
            return None;
        };
        let abs_ty = cx.ck.lower_ty(m, &pt.ty, g, true);
        let abs = closure_pat_local(&mut cx, &pt.pat, &abs_ty)?;
        let prop = cx.prop(&c.body);
        cx.pop_scope();
        let locals = std::mem::take(&mut cx.locals);
        Some(Represents { repr, by_ref, abs, abs_ty, prop, locals, span })
    }
}

/// Binds the single-identifier parameter `p` of a view/represents closure
/// at type `ty` (an annotation, if any, must be `ty` or `&ty` when
/// `allow_ref`).
fn closure_binder(cx: &mut Cx, p: &syn::Pat, ty: &Ty, allow_ref: bool, what: &str) -> Option<LocalId> {
    match p {
        syn::Pat::Type(pt) => {
            let g = cx.g.clone();
            let t = cx.ck.lower_ty(cx.m, &pt.ty, &g, true);
            let ok = t == *ty || t.is_error() || (allow_ref && matches!(&t, Ty::Ref(inner) if **inner == *ty));
            if !ok {
                let (x, y) = (cx.tys(&t), cx.tys(ty));
                let span = cx.sp(pt.span());
                cx.err(DiagKind::Attribute, span, format!("the {what} parameter has type `{y}`, found `{x}`"));
            }
            closure_pat_local(cx, &pt.pat, &t)
        }
        p => closure_pat_local(cx, p, ty),
    }
}

/// A closure parameter must be a plain identifier.
fn closure_pat_local(cx: &mut Cx, p: &syn::Pat, ty: &Ty) -> Option<LocalId> {
    match p {
        syn::Pat::Ident(pi) if pi.subpat.is_none() && pi.by_ref.is_none() && pi.mutability.is_none() => {
            let span = cx.sp(pi.span());
            Some(cx.new_local(&pi.ident.to_string(), ty.clone(), false, true, span))
        }
        other => {
            let span = cx.sp(other.span());
            cx.err(DiagKind::Attribute, span, "expected a parameter name");
            None
        }
    }
}

impl<'c, 'a> Cx<'c, 'a> {
    /// Auto-dereferences a reference-typed view result (`&T ↦ T`).
    pub fn autoderef_if_ref(&mut self, e: Expr) -> Expr {
        if matches!(e.ty, Ty::Ref(_)) { self.autoderef(e) } else { e }
    }

    /// The view type of a user type with a `#[view]` (DESIGN.md §15.3):
    /// the spec struct of a structural view, the body type of `|s| e`, or
    /// (S2) the field of a one-field struct with an invariant.
    pub fn view_target(&self, t: &Ty) -> Option<Ty> {
        let Ty::Adt(id, args) = t else { return None };
        match &self.ck.hir_items[id.0 as usize] {
            Some(ItemKind::Struct(s)) => match &s.view {
                Some(View::Struct { target, .. }) => Some(Ty::Adt(*target, vec![])),
                Some(View::Fn { body, .. }) => Some(body.ty.subst(args)),
                None if s.invariant.is_some() && s.fields.len() == 1 => Some(s.fields[0].ty.subst(args)),
                None => None,
            },
            Some(ItemKind::Enum(e)) => match &e.view {
                Some(View::Fn { body, .. }) => Some(body.ty.subst(args)),
                _ => None,
            },
            _ => None,
        }
    }

    /// Whether the type-directed view coercion `from ↦ to` exists (ghost
    /// code only; DESIGN.md §15.3, [`Coercion::View`]): `&T ↦ α(T)`,
    /// `Nat ↦ Int`, `uN ↦ Nat | Int`, `&[T]`/`[T; N]`/`Seq<T>` ↦
    /// `Seq<α(T)>`, `[T; N] ↦ [α(T); N]`, `Option`/tuples componentwise, a
    /// type with a `#[view]` to its view type (and on through coercions).
    pub fn view_coercible(&self, from: &Ty, to: &Ty) -> bool {
        self.view_coercible_d(from, to, 0)
    }

    fn view_coercible_d(&self, from: &Ty, to: &Ty, depth: u32) -> bool {
        if depth > 16 || from.is_error() || to.is_error() || matches!(to, Ty::Ref(_) | Ty::Prop | Ty::Proof) {
            return false;
        }
        let f = from.peel_refs();
        if f == to {
            return true;
        }
        let sub = |a: &Ty, b: &Ty| a == b || self.view_coercible_d(a, b, depth + 1);
        match (f, to) {
            (Ty::Nat, Ty::Int) | (Ty::Uint(_), Ty::Nat | Ty::Int) => true,
            (Ty::Slice(e) | Ty::Array(e, _) | Ty::Seq(e), Ty::Seq(e2)) => sub(e, e2),
            (Ty::Array(e, n), Ty::Array(e2, m)) => n == m && sub(e, e2),
            (Ty::Option(a), Ty::Option(b)) => sub(a, b),
            (Ty::Tuple(xs), Ty::Tuple(ys)) => xs.len() == ys.len() && xs.iter().zip(ys).all(|(a, b)| sub(a, b)),
            (Ty::Adt(..), _) => match self.view_target(f) {
                Some(v) => sub(&v, to),
                None => false,
            },
            _ => false,
        }
    }

    /// Wraps `e` in a view coercion to `t` (the caller checked
    /// [`Cx::view_coercible`]).
    pub fn view_coerce_expr(&mut self, e: Expr, t: &Ty) -> Expr {
        if e.ty == *t {
            return e;
        }
        let span = e.span;
        Expr::new(ExprKind::Coerce(Coercion::View, Box::new(e)), t.clone(), span)
    }

    /// The ghost numeric join of two operands (§4.1): `uN < Nat < Int`, the
    /// smaller one coerced to the larger (identity on `Nat ↦ Int`, exact on
    /// `uN ↦ Nat | Int`). Machine operands of different widths are left
    /// for the operator check to report.
    pub fn numeric_join(&mut self, l: Expr, r: Expr) -> (Expr, Expr) {
        if !self.ghost {
            return (l, r);
        }
        let rank = |t: &Ty| match t.peel_refs() {
            Ty::Uint(_) => Some(0),
            Ty::Nat => Some(1),
            Ty::Int => Some(2),
            _ => None,
        };
        match (rank(&l.ty), rank(&r.ty)) {
            (Some(a), Some(b)) if a < b => {
                let t = r.ty.peel_refs().clone();
                (self.view_coerce_expr(l, &t), r)
            }
            (Some(a), Some(b)) if a > b => {
                let t = l.ty.peel_refs().clone();
                let r = self.view_coerce_expr(r, &t);
                (l, r)
            }
            _ => (l, r),
        }
    }

    /// Operands of a ghost (in)equality of different types: the one that
    /// view-coerces to the other's type is coerced (DESIGN.md §15.3; the
    /// refinement form `f(x) == spec::f(x)` with `f(x) : u64` and a `Nat`
    /// spec).
    pub fn view_join(&mut self, l: Expr, r: Expr) -> (Expr, Expr) {
        if !self.ghost || l.ty == r.ty || l.ty.is_error() || r.ty.is_error() || l.ty.is_never() || r.ty.is_never() || l.ty.peel_refs() == r.ty.peel_refs() {
            return (l, r);
        }
        if self.view_coercible(&l.ty, r.ty.peel_refs()) {
            let t = r.ty.peel_refs().clone();
            return (self.view_coerce_expr(l, &t), r);
        }
        if self.view_coercible(&r.ty, l.ty.peel_refs()) {
            let t = l.ty.peel_refs().clone();
            let r = self.view_coerce_expr(r, &t);
            return (l, r);
        }
        (l, r)
    }

    /// `self.f` inside an invariant: the binder of field `f`.
    pub fn invariant_field(&mut self, member: &syn::Member, span: Span) -> Expr {
        let inv = self.inv_self.clone().expect("in an invariant");
        let found = match member {
            syn::Member::Named(n) => inv.fields.iter().find(|(f, _)| f.as_deref() == Some(&n.to_string())).map(|(_, l)| *l),
            syn::Member::Unnamed(i) => inv.fields.get(i.index as usize).filter(|(f, _)| f.is_none()).map(|(_, l)| *l),
        };
        match found {
            Some(l) => {
                let ty = self.local_ty(l);
                Expr::new(ExprKind::Local(l), ty, span)
            }
            None => {
                let tn = self.ck.res.items[inv.owner.0 as usize].name.clone();
                let mn = match member {
                    syn::Member::Named(n) => n.to_string(),
                    syn::Member::Unnamed(i) => i.index.to_string(),
                };
                self.err(DiagKind::Type, span, format!("no field `{mn}` on type `{tn}`"));
                Expr::new(ExprKind::Tuple(vec![]), Ty::Error, span)
            }
        }
    }

    pub fn invariant_bare_self(&mut self, span: Span) {
        self.push(
            Diagnostic::error(DiagKind::Attribute, span, "bare `self` is not allowed in an invariant; refer to the fields (`self.f`, `self.0`)")
                .note("an invariant is a property of the field values (DESIGN.md §15.3)"),
        );
    }

    pub fn invariant_self_method(&mut self, name: &str, span: Span) {
        let tn = self.inv_self.as_ref().map(|i| self.ck.res.items[i.owner.0 as usize].name.clone()).unwrap_or_default();
        self.push(
            Diagnostic::error(DiagKind::Attribute, span, format!("the invariant of `{tn}` cannot use its method `{name}`"))
                .note("methods of the type receive a value that already satisfies the invariant; state it over the fields with spec functions instead (DESIGN.md §15.3)"),
        );
    }

    /// `Type::f` (a path whose prefix names a struct or enum): the inherent
    /// function `f` of `Type`, as for a `Type::f(..)` call. `None` when the
    /// prefix is not a user type; `Some(Err(..))` when it is but has no such
    /// function (or it is private here).
    fn assoc_fn_path(&mut self, segs: &[(String, Span)], leading_colon: bool) -> Option<Result<ItemId, Diagnostic>> {
        let (last, lspan) = segs.last()?.clone();
        if segs.len() < 2 {
            return None;
        }
        let Ok(Def::Item(owner)) = self.ck.res.resolve_path_defs(self.m, &segs[..segs.len() - 1], Ns::Type, leading_colon, true) else { return None };
        if !matches!(self.ck.res.items[owner.0 as usize].tag, ItemTag::Struct { .. } | ItemTag::Enum { .. }) {
            return None;
        }
        let found = self.ck.res.impls.iter().filter(|i| i.owner == Some(owner)).flat_map(|i| i.fns.iter().copied()).find(|f| self.ck.res.items[f.0 as usize].name == last);
        let tname = self.ck.res.items[owner.0 as usize].name.clone();
        Some(match found {
            Some(f) => {
                let fit = &self.ck.res.items[f.0 as usize];
                if self.ck.res.visible(fit.vis, fit.module, self.m) {
                    Ok(f)
                } else {
                    Err(Diagnostic::error(DiagKind::Privacy, lspan, format!("associated function `{tname}::{last}` is private")))
                }
            }
            None => Err(Diagnostic::error(DiagKind::Resolve, lspan, format!("no associated function named `{last}` found for `{tname}`"))),
        })
    }

    /// Resolves an exec function path (§15 attribute arguments): a free
    /// function, or an inherent function `Type::f`.
    fn exec_fn_path(&mut self, p: &syn::Path, what: &str, span: Span) -> Option<ItemId> {
        let segs: Vec<(String, Span)> = p.segments.iter().map(|s| (s.ident.to_string(), self.sp(s.ident.span()))).collect();
        let resolved = match self.ck.res.resolve_path_defs(self.m, &segs, Ns::Value, p.leading_colon.is_some(), true) {
            Err(d) => match self.assoc_fn_path(&segs, p.leading_colon.is_some()) {
                Some(Ok(f)) => Ok(Def::Item(f)),
                Some(Err(d2)) => Err(d2),
                None => Err(d),
            },
            r => r,
        };
        match resolved {
            Ok(Def::Item(id)) if self.ck.res.items[id.0 as usize].tag == ItemTag::Fn => {
                let kind = self.ck.sigs.get(&id).map(|s| s.kind);
                if kind == Some(FnKind::Exec) && !self.ck.res.items[id.0 as usize].ghost {
                    Some(id)
                } else {
                    let path = self.ck.res.items[id.0 as usize].path.to_string();
                    let k = kind.map(|k| k.name()).unwrap_or("fn");
                    self.push(Diagnostic::error(DiagKind::Attribute, span, format!("{what} must name an exec function; `{path}` is a {k} item")));
                    None
                }
            }
            Ok(_) => {
                self.err(DiagKind::Attribute, span, format!("{what} must name an exec function"));
                None
            }
            Err(d) => {
                self.push(d);
                None
            }
        }
    }

    /// Resolves the path of a struct (`#[proof(view_inj = T)]`); `what`
    /// names the attribute.
    fn struct_path(&mut self, p: &syn::Path, what: &str, span: Span) -> Option<ItemId> {
        let segs: Vec<(String, Span)> = p.segments.iter().map(|s| (s.ident.to_string(), self.sp(s.ident.span()))).collect();
        match self.ck.res.resolve_path_defs(self.m, &segs, Ns::Type, p.leading_colon.is_some(), true) {
            Ok(Def::Item(id)) if matches!(self.ck.res.items[id.0 as usize].tag, ItemTag::Struct { .. }) => Some(id),
            Ok(_) => {
                self.err(DiagKind::Attribute, span, format!("{what} must name a struct with a `#[view(|s| ..)]`"));
                None
            }
            Err(d) => {
                self.push(d);
                None
            }
        }
    }

    /// Resolves a spec function path; `what` names the attribute.
    fn spec_fn_path(&mut self, p: &syn::Path, what: &str, span: Span) -> Option<ItemId> {
        let segs: Vec<(String, Span)> = p.segments.iter().map(|s| (s.ident.to_string(), self.sp(s.ident.span()))).collect();
        match self.ck.res.resolve_path_defs(self.m, &segs, Ns::Value, p.leading_colon.is_some(), true) {
            Ok(Def::Item(id)) if self.ck.res.items[id.0 as usize].tag == ItemTag::Fn => {
                let kind = self.ck.sigs.get(&id).map(|s| s.kind);
                if kind == Some(FnKind::Spec) {
                    return Some(id);
                }
                let path = self.ck.res.items[id.0 as usize].path.to_string();
                let d = match kind {
                    Some(FnKind::Exec) => Diagnostic::error(DiagKind::Attribute, span, format!("{what} must name a spec function; `{path}` is an exec function"))
                        .note("a specification written in terms of the implementation proves nothing: transcribe the reference semantics into a `#[spec]` function (DESIGN.md §15.1, §15.2)"),
                    Some(k) => Diagnostic::error(DiagKind::Attribute, span, format!("{what} must name a spec function; `{path}` is a {} item", k.name()))
                        .note("spec functions are `#[spec] fn`s or the `fn`s of a `#[spec]` module (DESIGN.md §15.1)"),
                    None => Diagnostic::error(DiagKind::Attribute, span, format!("{what} must name a spec function")),
                };
                self.push(d);
                None
            }
            Ok(Def::Item(id)) => {
                let path = self.ck.res.items[id.0 as usize].path.to_string();
                self.push(Diagnostic::error(DiagKind::Attribute, span, format!("{what} must name a spec function; `{path}` is not a function")).note("spec functions are `#[spec] fn`s or the `fn`s of a `#[spec]` module (DESIGN.md §15.1)"));
                None
            }
            Ok(_) => {
                self.err(DiagKind::Attribute, span, format!("{what} must name a spec function"));
                None
            }
            Err(d) => {
                self.push(d);
                None
            }
        }
    }

    /// The bare form `#[refines(s)]` (DESIGN.md §15.2): the parameters map
    /// positionally onto the spec's through the view coercion, and so does
    /// the result — or, for a method of a struct with `#[represents]`, the
    /// simulation form (the spec takes the abstract state first). Checked
    /// here so a mismatch is a readable type error, not an elaboration
    /// failure.
    fn check_refines_shape(&mut self, sig: &FnSig, spec: ItemId, ss: &FnSig, span: Span) {
        let spath = self.ck.res.items[spec.0 as usize].path.to_string();
        let rep = sig.owner.and_then(|o| match &self.ck.hir_items[o.0 as usize] {
            Some(ItemKind::Struct(sd)) => sd.represents.as_ref().map(|r| (o, r.abs_ty.clone())),
            _ => None,
        });
        let has_param = |t: &Ty| {
            let mut p = false;
            t.walk(&mut |x| p |= matches!(x, Ty::Param(..)));
            p
        };
        let (fparams, sparams): (Vec<Ty>, Vec<Ty>) = match (&rep, sig.receiver) {
            (Some((_, a)), Some(_)) => {
                if ss.params.first() != Some(a) {
                    let at = self.tys(a);
                    self.push(Diagnostic::error(DiagKind::Type, span, format!("`{spath}` must take the abstract state `{at}` first")).note("a method of a struct with `#[represents]` refines a spec over the abstract state (DESIGN.md §15.3)"));
                    return;
                }
                (sig.params[1..].to_vec(), ss.params[1..].to_vec())
            }
            _ => (sig.params.clone(), ss.params.clone()),
        };
        if fparams.len() != sparams.len() {
            self.push(
                Diagnostic::error(DiagKind::Type, span, format!("`{spath}` takes {} argument(s), the function {}", sparams.len(), fparams.len()))
                    .note(format!("write the argument map explicitly: `#[refines({spath}(e1, .., en))]` (DESIGN.md §15.2)")),
            );
            return;
        }
        for (i, (a, b)) in fparams.iter().zip(&sparams).enumerate() {
            if has_param(b) || has_param(a) || a.peel_refs() == b || self.view_coercible(a, b) {
                continue;
            }
            let (x, y) = (self.tys(a), self.tys(b));
            self.push(Diagnostic::error(DiagKind::Type, span, format!("parameter {} of type `{x}` has no view coercion to `{y}`, the spec's parameter type", i + 1)).note("coercions: `&T ↦ α(T)`, `uN ↦ Nat | Int`, `&[T]`/`[T; N]` ↦ `Seq<α(T)>`, `Option`/tuples componentwise, a `#[view]` (DESIGN.md §15.3); or write the argument map explicitly"));
        }
        let ret_ok = |cx: &Self, a: &Ty, b: &Ty| has_param(a) || has_param(b) || a.peel_refs() == b || cx.view_coercible(a, b);
        let ret_check = match (&rep, sig.receiver) {
            // a method of a `#[represents]` struct returning the struct (or a
            // pair with it) refines through the relation
            (Some((o, _)), _) if matches!(sig.ret.peel_refs(), Ty::Adt(id, _) if id == o) => true,
            (Some((o, _)), _) if matches!(&sig.ret, Ty::Tuple(ts) if ts.len() == 2 && matches!(ts[0].peel_refs(), Ty::Adt(id, _) if id == o)) => {
                matches!((&sig.ret, &ss.ret), (Ty::Tuple(a), Ty::Tuple(b)) if b.len() == 2 && ret_ok(self, &a[1], &b[1]))
            }
            _ => ret_ok(self, &sig.ret, &ss.ret),
        };
        if !ret_check {
            let (x, y) = (self.tys(&sig.ret), self.tys(&ss.ret));
            self.push(Diagnostic::error(DiagKind::Type, span, format!("the result type `{x}` has no view coercion to `{y}`, the result type of `{spath}`")).note("the result refines through the type-directed view coercion or a `#[view]` (DESIGN.md §15.2, §15.3)"));
        }
    }

    /// Resolves and types the §15 annotations of the current function
    /// (ghost context, parameters in scope).
    pub fn lower_fn_spec(&mut self, sig: &FnSig) -> SpecAnnots {
        let syn = sig.spec.clone();
        let mut out = SpecAnnots::default();
        if let Some(r) = &syn.refines {
            if sig.contracts.implements.is_some() {
                self.push(
                    Diagnostic::error(DiagKind::Attribute, r.span, "`#[refines]` is not allowed on a hardware variant (`#[implements]`)")
                        .note("a variant inherits the refinement of its portable function through `VariantEquiv` (DESIGN.md §15.2)"),
                );
            } else if let Some(spec) = self.spec_fn_path(&r.target, "`#[refines]`", r.span) {
                let spec_sig = self.ck.sigs.get(&spec).cloned();
                let args = r.args.as_ref().map(|args| {
                    let params: Vec<Ty> = spec_sig.as_ref().map(|s| s.params.clone()).unwrap_or_default();
                    if args.len() != params.len() {
                        let path = self.ck.res.items[spec.0 as usize].path.to_string();
                        self.err(DiagKind::Attribute, r.span, format!("`{path}` takes {} argument(s) but the explicit argument map of `#[refines]` has {}", params.len(), args.len()));
                    }
                    args.iter()
                        .enumerate()
                        .map(|(i, a)| {
                            // expected: the spec's parameter type (guides literals);
                            // not coerced — the view coercion is S1's
                            // coerced to the spec's parameter type (the view
                            // coercion, DESIGN.md §15.3)
                            match params.get(i) {
                                Some(t) if !has_param(t) => self.check(a, t),
                                _ => self.infer(a),
                            }
                        })
                        .collect()
                });
                let domain = r.domain.as_ref().map(|d| self.prop(d));
                if args.is_none()
                    && let Some(ss) = &spec_sig
                {
                    self.check_refines_shape(sig, spec, ss, r.span);
                }
                out.refines = Some(Refines { spec, args, domain, span: r.span });
            }
        }
        out.proof_of_unresolved = syn.proof_malformed;
        if let Some((kind, p, span)) = &syn.proof_of {
            let what = match kind {
                ProofKind::Refines => "`#[proof(refines = ..)]`",
                ProofKind::Complete => "`#[proof(complete = ..)]`",
                ProofKind::ViewInj => "`#[proof(view_inj = ..)]`",
            };
            let target = if *kind == ProofKind::ViewInj { self.struct_path(p, what, *span) } else { self.exec_fn_path(p, what, *span) };
            match target {
                Some(target) => out.proof_of = Some(ProofOf { kind: *kind, target, span: *span }),
                // reported; the item is still not a law's proof
                None => out.proof_of_unresolved = true,
            }
        }
        for (e, span) in &syn.examples {
            // a closed expression: a fresh context without the parameters
            let m = self.m;
            let mut cx = Cx::new(&mut *self.ck, m, None, FnKind::Spec, true, Ty::Bool, GenScope::default(), vec![]);
            let x = cx.check(e, &Ty::Bool);
            let locals = std::mem::take(&mut cx.locals);
            out.examples.push(Example { expr: x, locals, span: *span, text: super::example_text(e) });
        }
        if !syn.example_files.is_empty() {
            if sig.ret != Ty::Bool || sig.kind != FnKind::Spec {
                self.push(
                    Diagnostic::error(DiagKind::Attribute, syn.example_files[0].span, "`#[examples(file = ..)]` belongs on a checker: a spec function returning `bool`")
                        .note("each record's fields bind the checker's parameters by name (DESIGN.md §15.7)"),
                );
            }
            out.example_files = syn.example_files.clone();
        }
        if let Some((paths, span)) = &syn.section {
            out.section_span = Some(*span);
            for p in paths {
                let sp = self.sp(p.span());
                if let Some(id) = self.exec_fn_path(p, "`#[section(with = ..)]`", sp) {
                    if Some(id) == self.item {
                        self.err(DiagKind::Attribute, sp, "a function is always in its own section");
                    } else {
                        out.section_with.push((id, sp));
                    }
                }
            }
        }
        out.mirrors_impl = syn.mirrors_impl.clone();
        if let Some((p, span)) = &syn.mirrors_of {
            out.mirrors_of = self.exec_fn_path(p, "`#[mirrors_impl(of = ..)]`", *span);
        }
        if let Some((p, span)) = &syn.reduces_to
            && let Some(a) = self.spec_fn_path(p, "`#[reduces_to(..)]`", *span)
        {
            out.reduces_to = Some((a, *span));
        }
        if let Some(a) = &syn.assumption {
            if !sig.params.is_empty() || sig.ret != Ty::unit() {
                self.push(
                    Diagnostic::error(DiagKind::Attribute, a.span, "an `#[assumption]` has no logical content: it is a spec function `fn name() {}` without parameters or result")
                        .note("laws that rely on it are stated in extraction form and name it with `#[reduces_to(name)]` (DESIGN.md §15.13)"),
                );
            }
            out.assumption = Some(a.clone());
        }
        out.definitional = syn.definitional.clone();
        out.corollary = syn.corollary;
        out.opaque = syn.opaque;
        if let Some((p, span)) = &syn.fuel_sufficient {
            let spec = p.as_ref().and_then(|p| self.spec_fn_path(p, "`#[fuel_sufficient(..)]`", *span));
            if p.is_none() || spec.is_some() {
                out.fuel_sufficient = Some(FuelSufficient { spec, span: *span });
            }
        }
        if let Some(j) = &syn.trusted_extern {
            if sig.contracts.ensures.is_none() && syn.refines.is_none() {
                self.push(Diagnostic::error(DiagKind::Attribute, j.span, "a `#[trusted_extern]` function needs a contract (`#[ensures]` or `#[refines]`)").note("its contract is what the rest of the crate may assume; it is locked with the justification (DESIGN.md §15.8)"));
            }
            out.trusted_extern = Some(j.clone());
        }
        out
    }
}

/// Whether a type mentions a type parameter.
fn has_param(t: &Ty) -> bool {
    let mut p = false;
    t.walk(&mut |x| p |= matches!(x, Ty::Param(..)));
    p
}

// ----------------------------------------------------------------------
// ghost arguments (DESIGN.md §15.3, S2)
// ----------------------------------------------------------------------

/// `ghost!(e)` (or `sandblaster::ghost!(e)`): the argument of a `#[ghost]`
/// parameter at a call site.
pub fn ghost_macro(e: &syn::Expr) -> Option<&syn::Macro> {
    match e {
        syn::Expr::Macro(m) if m.mac.path.segments.last().is_some_and(|s| s.ident == "ghost") => Some(&m.mac),
        syn::Expr::Paren(p) => ghost_macro(&p.expr),
        syn::Expr::Group(g) => ghost_macro(&g.expr),
        _ => None,
    }
}

/// Whether an exec function signature carries a sandblaster function
/// annotation (whose erasing macro removes `ghost!(..)` arguments and
/// `#[ghost]` parameters in baseline builds).
pub fn has_fn_annotation(sig: &super::FnSig) -> bool {
    let c = &sig.contracts;
    let s = &sig.spec;
    !c.requires.is_empty() || c.ensures.is_some() || c.decreases.is_some() || c.implements.is_some() || sig.specialize || s.refines.is_some() || !s.examples.is_empty() || s.section.is_some() || s.trusted_extern.is_some()
}

impl<'c, 'a> Cx<'c, 'a> {
    /// Types the arguments of a call of `sig` whose parameters from
    /// `offset` on match `args` (a method's receiver is typed already),
    /// with `#[ghost]` parameters (DESIGN.md §15.3): their arguments are
    /// ghost expressions, written `ghost!(e)` in exec code (the caller's
    /// erasing macro removes them in baseline builds, as the callee's
    /// removes the parameters; in ghost code `ghost!(e)` or `e`). The
    /// other arguments are typed by the usual generic call. Returns the
    /// arguments in order, the type arguments and the result type.
    #[allow(clippy::too_many_arguments)]
    pub fn call_with_ghosts(&mut self, callee: ItemId, sig: &super::FnSig, offset: usize, n: usize, explicit: Vec<Option<Ty>>, args: &[syn::Expr], exp: &super::expr::Exp, span: Span) -> (Vec<Expr>, Vec<Ty>, Ty) {
        let ghost_at = |i: usize| sig.ghost_params.get(offset + i).copied().unwrap_or(false);
        // a forgotten `ghost!(..)` argument (the `#[ghost]` parameters come
        // last): only the round trip's lowered code omits them, and it is
        // not typechecked here
        let np = sig.params.len().saturating_sub(offset);
        if args.len() < np && (args.len()..np).all(ghost_at) {
            self.missing_ghost_args(callee, sig, offset + args.len(), span);
        }
        if !(0..args.len()).any(ghost_at) && !args.iter().any(|a| ghost_macro(a).is_some()) {
            let params: Vec<Ty> = sig.params[offset.min(sig.params.len())..].to_vec();
            return self.generic_call_zst(n, explicit, &params, &sig.ret, args, exp, span, true);
        }
        let mut rel_args = Vec::new();
        let mut rel_params = Vec::new();
        let mut ghosts: Vec<(usize, syn::Expr)> = Vec::new();
        for (i, a) in args.iter().enumerate() {
            let asp = self.sp(syn::spanned::Spanned::span(a));
            let mac = ghost_macro(a);
            if ghost_at(i) {
                let inner = match mac {
                    Some(m) => match m.parse_body::<syn::Expr>() {
                        Ok(e) => e,
                        Err(e) => {
                            self.err(DiagKind::Macro, asp, format!("malformed `ghost!(..)`: {e} (expected a ghost expression)"));
                            a.clone()
                        }
                    },
                    None => {
                        if !self.ghost {
                            self.push(
                                Diagnostic::error(DiagKind::Ghost, asp, "the argument of a `#[ghost]` parameter is written `ghost!(e)` in exec code")
                                    .note("the ghost argument does not exist in the compiled code: the caller's sandblaster annotation removes `ghost!(..)` arguments in baseline builds, as the callee's removes the `#[ghost]` parameter (DESIGN.md §15.3)"),
                            );
                        }
                        a.clone()
                    }
                };
                ghosts.push((i, inner));
            } else {
                if mac.is_some() {
                    self.push(Diagnostic::error(DiagKind::Ghost, asp, "`ghost!(..)` is only the argument of a `#[ghost]` parameter").note("this parameter is not `#[ghost]`: pass the value itself"));
                }
                rel_args.push(a.clone());
                if let Some(p) = sig.params.get(offset + i) {
                    rel_params.push(p.clone());
                }
            }
        }
        if !ghosts.is_empty() && !self.ghost {
            // the caller's erasing macro removes the `ghost!(..)` arguments
            let annotated = self.item.and_then(|id| self.ck.sigs.get(&id)).is_some_and(has_fn_annotation);
            if !annotated {
                self.push(
                    Diagnostic::error(DiagKind::Attribute, span, "a function passing `ghost!(..)` arguments needs a sandblaster function annotation (e.g. `#[requires]`, `#[ensures]`, `#[refines]`)")
                        .note("that annotation's erasing macro removes the `ghost!(..)` arguments in baseline builds, matching the callee's removed `#[ghost]` parameters (DESIGN.md §2, §15.3)"),
                );
            }
        }
        let (es, ty_args, ret) = self.generic_call_zst(n, explicit, &rel_params, &sig.ret, &rel_args, exp, span, true);
        let saved = self.ghost;
        self.ghost = true;
        let mut ges = Vec::new();
        for (i, e) in ghosts {
            let pt = sig.params.get(offset + i).map(|p| p.subst(&ty_args)).unwrap_or(Ty::Error);
            ges.push((i, self.check(&e, &pt)));
        }
        self.ghost = saved;
        let mut out = Vec::with_capacity(args.len());
        let mut rel = es.into_iter();
        let mut gh = ges.into_iter().peekable();
        for i in 0..args.len() {
            if gh.peek().is_some_and(|(j, _)| *j == i) {
                out.push(gh.next().unwrap().1);
            } else if let Some(e) = rel.next() {
                out.push(e);
            }
        }
        (out, ty_args, ret)
    }

    /// `error[ghost]` for the `#[ghost]` parameters of `callee` from `from`
    /// (all of the remaining ones) that a call leaves out.
    fn missing_ghost_args(&mut self, callee: ItemId, sig: &super::FnSig, from: usize, span: Span) {
        let info = &self.ck.res.items[callee.0 as usize];
        let fname = info.name.clone();
        let inputs: Vec<syn::FnArg> = match &info.src {
            crate::resolve::ItemSrc::Fn(f) => f.sig.inputs.iter().cloned().collect(),
            crate::resolve::ItemSrc::ImplFn { f, .. } => f.sig.inputs.iter().cloned().collect(),
            _ => vec![],
        };
        let pname = |i: usize| match inputs.get(i) {
            Some(syn::FnArg::Typed(pt)) => match &*pt.pat {
                syn::Pat::Ident(pi) => format!("`{}`", pi.ident),
                _ => format!("#{}", i + 1),
            },
            Some(syn::FnArg::Receiver(_)) => "`self`".into(),
            None => format!("#{}", i + 1),
        };
        let names: Vec<String> = (from..sig.params.len()).map(pname).collect();
        let plural = if names.len() == 1 { "" } else { "s" };
        let mut d = Diagnostic::error(DiagKind::Ghost, span, format!("missing `ghost!(..)` argument{plural} for the `#[ghost]` parameter{plural} {} of `{fname}`", names.join(", ")))
            .note(format!("pass the ghost value{plural} last, as `ghost!(e)`: a ghost argument is checked like any other (its `requires` are obligations here) and is erased from the compiled code (DESIGN.md §15.3)"));
        let bare: Vec<String> = names.iter().map(|n| n.trim_matches('`').to_string()).collect();
        for r in &sig.contracts.requires {
            let text = quote::ToTokens::to_token_stream(r).to_string();
            let words: Vec<&str> = text.split(|c: char| !(c.is_alphanumeric() || c == '_')).collect();
            if bare.iter().any(|b| words.contains(&b.as_str())) {
                d = d.note(format!("`{fname}` requires `{text}`"));
            }
        }
        self.push(d);
    }
}
