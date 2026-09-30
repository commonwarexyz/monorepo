//! Core text syntax (DESIGN.md §5.12): a lexer, a parser (named binders →
//! de Bruijn indices, names resolved against the environment) and a printer
//! whose output parses back to the same term. Used by the prelude
//! (`prelude/*.core`), kernel tests, automation tests and diagnostics. The
//! concrete syntax is documented with examples in `CORE_SYNTAX.md`.

pub mod lexer;
pub mod parser;
pub mod printer;

use crate::api::{Env, KernelError, KernelErrorKind};
use crate::term::Name;
use crate::value::Budget;
use parser::{Item, Parser};

/// Parse and add the items of `src` one at a time (later items may refer to
/// earlier ones). Returns the names of the added items.
pub(crate) fn load(env: &mut Env, src: &str, b: &mut Budget) -> Result<Vec<Name>, KernelError> {
    load_with(env, src, b, &mut |_| {})
}

/// [`load`] with a hook run after each added item.
pub(crate) fn load_with(env: &mut Env, src: &str, b: &mut Budget, after: &mut dyn FnMut(&mut Env)) -> Result<Vec<Name>, KernelError> {
    let perr = |e: String| KernelError { kind: KernelErrorKind::IllFormed, message: format!("parse error: {e}") };
    let mut toks = lexer::lex(src).map_err(perr)?;
    let mut pos = 0;
    let mut names = Vec::new();
    loop {
        let (item, t2, p2) = {
            let mut p = Parser::with_tokens(env, toks, pos);
            let it = p.item();
            let (t, q) = p.into_parts();
            (it, t, q)
        };
        toks = t2;
        pos = p2;
        match item.map_err(perr)? {
            None => return Ok(names),
            Some(Item::Ind(d)) => {
                let n = d.name.clone();
                env.add_inductive(d).map_err(|e| KernelError { kind: e.kind, message: format!("in `{n}`: {}", e.message) })?;
                after(env);
                names.push(n);
            }
            Some(Item::Def(d)) => {
                let n = d.name.clone();
                env.add_def(d, b).map_err(|e| KernelError { kind: e.kind, message: format!("in `{n}`: {}", e.message) })?;
                after(env);
                names.push(n);
            }
        }
    }
}
