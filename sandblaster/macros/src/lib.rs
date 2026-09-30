//! Erasing proc macros for sandblaster ghost annotations (DESIGN.md §2, §4,
//! §15).
//!
//! sandblaster sources are ordinary Rust files annotated with contracts
//! (`#[requires]`, `#[ensures]`, `#[decreases]`), hardware-variant markers
//! (`#[implements]`, `#[specialize]`), ghost items (`#[law]`, `#[lemma]`,
//! `#[spec]`, `#[proof]`, `#[rewrite]`, `#[induction]`) and the §15
//! specification annotations (`#[refines]`, `#[example]`, `#[examples]`,
//! `#[invariant]`, `#[view]`, `#[represents]`, `#[ghost]`, `#[section]`,
//! `#[mirrors_impl]`, `#[fuel_sufficient]`, `#[trusted_extern]`) and the
//! §15.1 law-rule annotations (`#[reduces_to]`, `#[assumption]`,
//! `#[definitional]`, `#[corollary]`). The
//! sandblaster checker reads these annotations with `syn` (§4); `rustc` must
//! never see them.
//!
//! This crate is used only by **baseline builds** (§2): the raw DSL sources
//! compiled directly by `rustc` for benchmarks and differential tests. There
//! every annotation is erased:
//!
//! * **Annotations of exec items** (`requires`, `ensures`, `decreases`,
//!   `implements`, `specialize`, `refines`, `example`, `section`,
//!   `trusted_extern` on functions; `invariant`, `view`, `represents` on
//!   types) return the annotated item unchanged. An attribute macro never
//!   receives its own attribute in its input, so the item comes back minus
//!   that one attribute and with every other attribute intact; several
//!   annotations therefore stack in any order.
//! * **`#[ghost]` parameters** (§15.3) are removed from the parameter list
//!   by every macro of a function annotation above: rustc accepts an
//!   attribute on a parameter only as an inert helper of an attribute macro
//!   on the function, and a ghost parameter (an `Irr` binder, possibly of a
//!   ghost type) does not exist in the compiled code. The checker requires a
//!   function with ghost parameters to carry such an annotation. `#[ghost]`
//!   anywhere else is an error.
//! * **Ghost-item attributes** (`law`, `lemma`, `spec`, `proof`, `rewrite`)
//!   erase the whole item. Ghost items normally also sit behind
//!   `#[cfg(sandblaster)]` (so `rustc` strips them before these macros run);
//!   erasing them here as well keeps a stray ghost item out of the build even
//!   when the `cfg` is forgotten. (`#[cfg(sandblaster)] #[spec] mod spec;`
//!   works because the `cfg` comes first; attribute macros on `mod m;` are
//!   unstable.) Annotations that only occur on ghost items (`induction`,
//!   `examples`, `mirrors_impl`, `fuel_sufficient`) erase themselves and
//!   leave the item to its ghost attribute; so do the law-rule annotations
//!   (`reduces_to`, `assumption`, `definitional`, `corollary`).
//!
//! There is deliberately no `critical` macro: §15 is mandatory for every
//! crate (§15.8), so `sandblaster::critical` fails to resolve under `rustc`
//! just as the checker rejects it.
//!
//! The macros perform only the light argument checks that are cheap to do
//! without a parser (e.g. `#[requires]` needs a condition, `#[specialize]`
//! takes none). The real validation is the front end's job (§3, §4.2, §15).
//! The list of macros must match the checker's `resolve::Annot::ALL` (a
//! front-end test compares them).
//!
//! `proof! { .. }` statements are not handled here: the facade defines
//! `proof!` as a `macro_rules!` macro that expands to nothing, because a
//! function-like proc macro and the `#[proof]` attribute cannot share a name
//! inside one proc-macro crate.

use proc_macro::{Delimiter, Group, Ident, Literal, Punct, Spacing, Span, TokenStream, TokenTree};

/// Build `compile_error!("msg");` at `span`, followed by the original item so
/// that later errors in the item are still reported.
fn error(span: Span, msg: &str, item: TokenStream) -> TokenStream {
    let mut literal = Literal::string(msg);
    literal.set_span(span);
    let mut bang = Punct::new('!', Spacing::Alone);
    bang.set_span(span);
    let mut semi = Punct::new(';', Spacing::Alone);
    semi.set_span(span);
    let mut group = Group::new(Delimiter::Parenthesis, TokenStream::from(TokenTree::Literal(literal)));
    group.set_span(span);
    let mut out: TokenStream = [
        TokenTree::Ident(Ident::new("compile_error", span)),
        TokenTree::Punct(bang),
        TokenTree::Group(group),
        TokenTree::Punct(semi),
    ]
    .into_iter()
    .collect();
    out.extend(item);
    out
}

/// Erase a contract/variant attribute that requires arguments (removing
/// `#[ghost]` parameters of an annotated function).
fn erase_with_args(name: &str, attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = strip_ghost_params(item);
    if attr.is_empty() {
        return error(
            Span::call_site(),
            &format!("#[{name}(..)] requires an argument (DESIGN.md §4.2, §15)"),
            item,
        );
    }
    item
}

/// Whether the tokens of an attribute's brackets are `ghost` /
/// `sandblaster::ghost` / `sandblaster::prelude::ghost`.
fn is_ghost_attr(inner: TokenStream) -> bool {
    let toks: Vec<TokenTree> = inner.into_iter().collect();
    match toks.last() {
        Some(TokenTree::Ident(id)) if id.to_string() == "ghost" => toks[..toks.len() - 1].iter().all(|t| match t {
            TokenTree::Ident(_) => true,
            TokenTree::Punct(p) => p.as_char() == ':',
            _ => false,
        }),
        _ => false,
    }
}

/// Whether a parameter's tokens start with attributes one of which is
/// `#[ghost]`.
fn is_ghost_param(param: &[TokenTree]) -> bool {
    let mut i = 0;
    while i + 1 < param.len() {
        match (&param[i], &param[i + 1]) {
            (TokenTree::Punct(p), TokenTree::Group(g)) if p.as_char() == '#' && g.delimiter() == Delimiter::Bracket => {
                if is_ghost_attr(g.stream()) {
                    return true;
                }
                i += 2;
            }
            _ => return false,
        }
    }
    false
}

/// Removes the `#[ghost]` parameters of a parameter list (commas at angle
/// depth 0 separate parameters; `->` is not an angle bracket).
fn strip_params(ts: TokenStream) -> TokenStream {
    let mut params: Vec<Vec<TokenTree>> = vec![vec![]];
    let mut angle = 0i32;
    let mut prev_minus = false;
    for t in ts {
        let mut minus = false;
        if let TokenTree::Punct(p) = &t {
            match p.as_char() {
                '<' => angle += 1,
                '>' if !prev_minus => angle -= 1,
                '-' => minus = p.spacing() == Spacing::Joint,
                ',' if angle <= 0 => {
                    params.last_mut().expect("nonempty").push(t);
                    params.push(vec![]);
                    prev_minus = false;
                    continue;
                }
                _ => {}
            }
        }
        prev_minus = minus;
        params.last_mut().expect("nonempty").push(t);
    }
    params.into_iter().filter(|p| !is_ghost_param(p)).flatten().collect()
}

/// Whether a comma-separated argument is `ghost!(..)` (optionally
/// path-qualified): the argument of a `#[ghost]` parameter at a call site
/// (DESIGN.md §15.3).
fn is_ghost_arg(seg: &[TokenTree]) -> bool {
    let n = seg.len();
    n >= 3
        && matches!(&seg[n - 1], TokenTree::Group(_))
        && matches!(&seg[n - 2], TokenTree::Punct(p) if p.as_char() == '!')
        && matches!(&seg[n - 3], TokenTree::Ident(id) if id.to_string() == "ghost")
        && seg[..n - 3].iter().all(|t| match t {
            TokenTree::Ident(_) => true,
            TokenTree::Punct(p) => p.as_char() == ':',
            _ => false,
        })
}

/// Removes every `ghost!(..)` argument (with its comma) from the
/// parenthesized groups of `ts`, at any depth: the caller's side of a
/// `#[ghost]` parameter, which the callee's annotation removes. Other
/// tokens come back unchanged (a segment that is not exactly `ghost!(..)`
/// is kept verbatim, so commas inside closures or generics do not matter).
fn strip_ghost_args(ts: TokenStream) -> TokenStream {
    ts.into_iter()
        .map(|t| match t {
            TokenTree::Group(g) => {
                let inner = if g.delimiter() == Delimiter::Parenthesis { strip_arg_list(g.stream()) } else { strip_ghost_args(g.stream()) };
                let mut ng = Group::new(g.delimiter(), inner);
                ng.set_span(g.span());
                TokenTree::Group(ng)
            }
            other => other,
        })
        .collect()
}

fn strip_arg_list(ts: TokenStream) -> TokenStream {
    let mut segs: Vec<Vec<TokenTree>> = vec![vec![]];
    let mut commas: Vec<TokenTree> = Vec::new();
    for t in ts {
        if let TokenTree::Punct(p) = &t
            && p.as_char() == ','
        {
            commas.push(t);
            segs.push(vec![]);
            continue;
        }
        segs.last_mut().expect("nonempty").push(t);
    }
    if !segs.iter().any(|s| is_ghost_arg(s)) {
        // unchanged structure: recurse, keep the original commas
        let mut out: Vec<TokenTree> = Vec::new();
        let mut cs = commas.into_iter();
        for (i, seg) in segs.into_iter().enumerate() {
            if i > 0
                && let Some(c) = cs.next()
            {
                out.push(c);
            }
            out.extend(strip_ghost_args(seg.into_iter().collect()));
        }
        return out.into_iter().collect();
    }
    let n = segs.len();
    let mut out: Vec<TokenTree> = Vec::new();
    let mut first = true;
    for (i, seg) in segs.into_iter().enumerate() {
        if is_ghost_arg(&seg) {
            continue;
        }
        if i == n - 1 && seg.is_empty() {
            // a trailing comma
            if !first {
                out.push(TokenTree::Punct(Punct::new(',', Spacing::Alone)));
            }
            continue;
        }
        if !first {
            out.push(TokenTree::Punct(Punct::new(',', Spacing::Alone)));
        }
        out.extend(strip_ghost_args(seg.into_iter().collect()));
        first = false;
    }
    out.into_iter().collect()
}

/// Removes the `#[ghost]` parameters of a function item, and the
/// `ghost!(..)` arguments of the calls in its body (other items are
/// returned unchanged).
fn strip_ghost_params(item: TokenStream) -> TokenStream {
    let mut out: Vec<TokenTree> = Vec::new();
    // 0: before `fn`, 1: the name, 2: generics until the parameter list, 3: done
    let mut state = 0;
    let mut angle = 0i32;
    for t in item {
        match state {
            0 => {
                if matches!(&t, TokenTree::Ident(id) if id.to_string() == "fn") {
                    state = 1;
                }
                out.push(t);
            }
            1 => {
                state = 2;
                out.push(t);
            }
            2 => match &t {
                TokenTree::Punct(p) if p.as_char() == '<' => {
                    angle += 1;
                    out.push(t);
                }
                TokenTree::Punct(p) if p.as_char() == '>' => {
                    angle -= 1;
                    out.push(t);
                }
                TokenTree::Group(g) if g.delimiter() == Delimiter::Parenthesis && angle <= 0 => {
                    let mut ng = Group::new(Delimiter::Parenthesis, strip_params(g.stream()));
                    ng.set_span(g.span());
                    out.push(TokenTree::Group(ng));
                    state = 3;
                }
                _ => out.push(t),
            },
            // the body: the calls' `ghost!(..)` arguments
            _ => out.extend(strip_ghost_args(TokenStream::from(t))),
        }
    }
    out.into_iter().collect()
}


/// `#[requires(p)]`: precondition of an exec function (§4.2). Erased.
#[proc_macro_attribute]
pub fn requires(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("requires", attr, item)
}

/// `#[ensures(|ret| p)]` / `#[ensures(p)]`: postcondition (§4.2). Erased.
#[proc_macro_attribute]
pub fn ensures(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("ensures", attr, item)
}

/// `#[decreases(e)]` / `#[decreases(e, max = C)]`: termination measure and
/// optional stack-depth bound (§3.7, §4.2). Erased.
#[proc_macro_attribute]
pub fn decreases(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("decreases", attr, item)
}

/// `#[implements(path)]`: marks a `#[target_feature]` function as a hardware
/// variant of the portable function `path` (§9.3). Erased.
#[proc_macro_attribute]
pub fn implements(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("implements", attr, item)
}

/// `#[specialize]`: failure to specialize this function is a build error
/// (§8.2). Takes no arguments. Erased.
#[proc_macro_attribute]
pub fn specialize(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = strip_ghost_params(item);
    if let Some(first) = attr.into_iter().next() {
        return error(first.span(), "#[specialize] takes no arguments (DESIGN.md §8.2)", item);
    }
    item
}

/// `#[law]`: a claim in `LAWS.rs` (§4.5). Ghost: the item is erased.
#[proc_macro_attribute]
pub fn law(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    TokenStream::new()
}

/// `#[lemma]`: a proven helper statement (§4.5). Ghost: the item is erased.
#[proc_macro_attribute]
pub fn lemma(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    TokenStream::new()
}

/// `#[spec]`: a specification function (§4.1, §4.5). Ghost: erased.
#[proc_macro_attribute]
pub fn spec(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    TokenStream::new()
}

/// `#[proof]`: the proof of a law in `PROOF.rs` (§4.5). Ghost: erased.
#[proc_macro_attribute]
pub fn proof(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    TokenStream::new()
}

/// `#[rewrite]`: lets the optimizer use an equational law (§4.5). Ghost:
/// erased (it only ever annotates a `#[law]`).
#[proc_macro_attribute]
pub fn rewrite(_attr: TokenStream, _item: TokenStream) -> TokenStream {
    TokenStream::new()
}

/// `#[induction(x)]`: the proof of a lemma/law recurses on `x` (§4.4). Only
/// on ghost items (which their own attribute erases); erased.
#[proc_macro_attribute]
pub fn induction(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("induction", attr, item)
}

/// `#[refines(spec::f)]` / `#[refines(spec::f(args..))]` /
/// `#[refines(spec::f, domain = P)]` on an exec function: its functional
/// specification (§15.2). Erased; the function is kept. (The checker
/// rejects `#[refines]` on a type, §9.6.)
#[proc_macro_attribute]
pub fn refines(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("refines", attr, item)
}

/// `#[example(e)]`: a known-answer example, a closed `bool` spec expression
/// (§15.7). Erased; the item is kept (a spec fn is erased by `#[spec]`).
#[proc_macro_attribute]
pub fn example(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("example", attr, item)
}

/// `#[examples(file = "..", format = "cavp" | "json", provenance = ..)]` on
/// a ghost checker function (§15.7). Erased.
#[proc_macro_attribute]
pub fn examples(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("examples", attr, item)
}

/// `#[invariant(p)]` on a struct: part of its kernel type (§15.3). Erased;
/// the type is kept.
#[proc_macro_attribute]
pub fn invariant(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("invariant", attr, item)
}

/// `#[view(spec::T)]` / `#[view(|s| e)]` on a type: its abstraction
/// function (§15.3). Erased; the type is kept.
#[proc_macro_attribute]
pub fn view(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("view", attr, item)
}

/// `#[represents(|s: &S, a: spec::A| P)]` on a struct: its representation
/// relation (§15.3). Erased; the type is kept.
#[proc_macro_attribute]
pub fn represents(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("represents", attr, item)
}

/// `#[ghost]` belongs on parameters of exec functions (§15.3), where the
/// macro of the function's sandblaster annotation removes the parameter. As an
/// item attribute it is an error.
#[proc_macro_attribute]
pub fn ghost(_attr: TokenStream, item: TokenStream) -> TokenStream {
    error(Span::call_site(), "#[ghost] marks parameters of exec functions (DESIGN.md §15.3); the function also needs a sandblaster annotation such as #[requires] or #[refines]", item)
}

/// `#[section(with = [f, ..])]` on an exec function: merges computed
/// sections (§15.5). Erased.
#[proc_macro_attribute]
pub fn section(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("section", attr, item)
}

/// `#[mirrors_impl(justification = "..")]` on a spec function (§15.1).
/// Erased (the spec fn itself is erased by `#[spec]`).
#[proc_macro_attribute]
pub fn mirrors_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("mirrors_impl", attr, item)
}

/// `#[fuel_sufficient]` / `#[fuel_sufficient(spec_fn)]` on a lemma (§15.1).
/// Erased (the lemma itself is erased by `#[lemma]`).
#[proc_macro_attribute]
pub fn fuel_sufficient(_attr: TokenStream, item: TokenStream) -> TokenStream {
    strip_ghost_params(item)
}

/// `#[trusted_extern(justification = "..")]` on an exec function with a
/// contract (§15.8). Erased; the function is kept.
#[proc_macro_attribute]
pub fn trusted_extern(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("trusted_extern", attr, item)
}

/// `#[reduces_to(assumption)]` on a law stated in extraction form (§15.1
/// LR4, §15.13). Erased (the law itself is erased by `#[law]`).
#[proc_macro_attribute]
pub fn reduces_to(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("reduces_to", attr, item)
}

/// `#[assumption(class = .., cite = "..")]` on a spec function without
/// logical content (§15.13). Erased (the spec fn itself is erased by
/// `#[spec]` or its spec module).
#[proc_macro_attribute]
pub fn assumption(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("assumption", attr, item)
}

/// `#[definitional(reason = "..")]` on a law that is intentionally one
/// unfolding of a definition (§15.1 LR6). Erased (the law itself is erased
/// by `#[law]`).
#[proc_macro_attribute]
pub fn definitional(attr: TokenStream, item: TokenStream) -> TokenStream {
    erase_with_args("definitional", attr, item)
}

/// `#[corollary]` on a law proven from other laws (§15.1 LR7). Erased (the
/// law itself is erased by `#[law]`).
#[proc_macro_attribute]
pub fn corollary(_attr: TokenStream, item: TokenStream) -> TokenStream {
    strip_ghost_params(item)
}

/// `#[opaque]` on a spec function: opaque in proofs (DESIGN.md §5.6, §15
/// S5). Erased (the spec fn itself is erased by `#[spec]` or its spec
/// module).
#[proc_macro_attribute]
pub fn opaque(_attr: TokenStream, item: TokenStream) -> TokenStream {
    strip_ghost_params(item)
}
