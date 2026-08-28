//! Input grammars for the selection macros.
//!
//! Parsed values retain punctuation tokens and source spans so procedural macro
//! expansion and source formatting consume the same syntax.

use syn::{
    Error, Expr, Ident, Pat, Token,
    parse::{Parse, ParseStream, Result},
};

/// Input for `select!`.
#[derive(Clone)]
pub struct SelectInput {
    /// Branches in source order.
    pub branches: Vec<SelectBranch>,
}

/// A branch in `select!`.
#[derive(Clone)]
pub struct SelectBranch {
    /// Pattern bound to the completed future.
    pub pattern: Pat,
    /// Separator between the pattern and future.
    pub eq_token: Token![=],
    /// Future polled by the branch.
    pub future: Expr,
    /// Separator between the future and branch body.
    pub fat_arrow_token: Token![=>],
    /// Expression evaluated when the branch completes.
    pub body: Expr,
    /// Optional branch terminator.
    pub comma_token: Option<Token![,]>,
}

impl Parse for SelectInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut branches = Vec::new();

        while !input.is_empty() {
            let pattern = Pat::parse_single(input)?;
            let eq_token = input.parse()?;
            let future = input.parse()?;
            let fat_arrow_token = input.parse()?;
            let body = input.parse()?;
            let comma_token = input.peek(Token![,]).then(|| input.parse()).transpose()?;

            branches.push(SelectBranch {
                pattern,
                eq_token,
                future,
                fat_arrow_token,
                body,
                comma_token,
            });

            // A branch without a comma must be final. Stop here so the outer
            // parser can reject any unconsumed trailing tokens.
            if branches
                .last()
                .is_some_and(|branch| branch.comma_token.is_none())
            {
                break;
            }
        }

        Ok(Self { branches })
    }
}

/// A lifecycle expression in `select_loop!`.
#[derive(Clone)]
pub struct SelectLoopLifecycle {
    /// Lifecycle keyword.
    pub keyword: Ident,
    /// Separator between the keyword and expression.
    pub fat_arrow_token: Token![=>],
    /// Lifecycle expression.
    pub expression: Expr,
    /// Optional expression terminator.
    pub comma_token: Option<Token![,]>,
}

/// A branch in `select_loop!`.
#[derive(Clone)]
pub struct SelectLoopBranch {
    /// Pattern bound to the completed future.
    pub pattern: Pat,
    /// Separator between the pattern and future.
    pub eq_token: Token![=],
    /// Future polled by the branch.
    pub future: Expr,
    /// Optional divergence clause for a refutable pattern.
    pub else_clause: Option<SelectLoopElse>,
    /// Separator between the future and branch body.
    pub fat_arrow_token: Token![=>],
    /// Expression evaluated when the branch completes.
    pub body: Expr,
    /// Optional branch terminator.
    pub comma_token: Option<Token![,]>,
}

/// A divergence clause in `select_loop!`.
#[derive(Clone)]
pub struct SelectLoopElse {
    /// Divergence keyword.
    pub else_token: Token![else],
    /// Expression evaluated when the branch pattern does not match.
    pub expression: Expr,
}

/// Input for `select_loop!`.
#[derive(Clone)]
pub struct SelectLoopInput {
    /// Runtime context used to observe shutdown.
    pub context: Expr,
    /// Terminator after the context.
    pub context_comma_token: Token![,],
    /// Optional expression evaluated before each loop iteration.
    pub on_start: Option<SelectLoopLifecycle>,
    /// Required expression evaluated during shutdown.
    pub on_stopped: SelectLoopLifecycle,
    /// Selection branches in source order.
    pub branches: Vec<SelectLoopBranch>,
    /// Optional expression evaluated after each loop iteration.
    pub on_end: Option<SelectLoopLifecycle>,
}

impl SelectLoopInput {
    /// Validates semantic constraints that are shared by all consumers.
    ///
    /// Consumers must call this after parsing and before using the input.
    pub fn validate(&self) -> Result<()> {
        for branch in &self.branches {
            if branch.else_clause.is_none() && !is_irrefutable(&branch.pattern) {
                return Err(Error::new_spanned(
                    &branch.pattern,
                    "refutable patterns require an else clause: \
                     `Some(msg) = future else break => { ... }`",
                ));
            }
        }

        Ok(())
    }
}

impl Parse for SelectLoopInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let context = input.parse()?;
        let context_comma_token = input.parse()?;

        let on_start = if peek_keyword(input, "on_start")? {
            Some(parse_lifecycle(input, "on_start", true)?)
        } else {
            None
        };

        let on_stopped = parse_lifecycle(input, "on_stopped", true)?;

        let mut branches = Vec::new();
        // `on_end` begins with an identifier like many patterns, so recognize
        // the lifecycle keyword before attempting to parse another branch.
        while !input.is_empty() && !peek_keyword(input, "on_end")? {
            let pattern = Pat::parse_single(input)?;
            let eq_token = input.parse()?;
            let future = input.parse()?;
            let else_clause = if input.peek(Token![else]) {
                Some(SelectLoopElse {
                    else_token: input.parse()?,
                    expression: input.parse()?,
                })
            } else {
                None
            };
            let fat_arrow_token = input.parse()?;
            let body = input.parse()?;
            let comma_token = input.peek(Token![,]).then(|| input.parse()).transpose()?;

            branches.push(SelectLoopBranch {
                pattern,
                eq_token,
                future,
                else_clause,
                fat_arrow_token,
                body,
                comma_token,
            });

            // A branch without a comma must be final. Stop here so `on_end` or
            // any other trailing input is handled by the enclosing grammar.
            if branches
                .last()
                .is_some_and(|branch| branch.comma_token.is_none())
            {
                break;
            }
        }

        let on_end = if input.is_empty() {
            None
        } else {
            Some(parse_lifecycle(input, "on_end", false)?)
        };

        Ok(Self {
            context,
            context_comma_token,
            on_start,
            on_stopped,
            branches,
            on_end,
        })
    }
}

/// Checks for an identifier keyword without advancing the input stream.
fn peek_keyword(input: ParseStream<'_>, expected: &str) -> Result<bool> {
    if !input.peek(Ident) {
        return Ok(false);
    }

    let ident: Ident = input.fork().parse()?;
    Ok(ident == expected)
}

/// Parses one named lifecycle entry and its punctuation.
///
/// A comma is required when another entry may follow. The final `on_end` entry
/// may omit it.
fn parse_lifecycle(
    input: ParseStream<'_>,
    expected: &str,
    require_comma: bool,
) -> Result<SelectLoopLifecycle> {
    let keyword: Ident = input.parse()?;
    if keyword != expected {
        return Err(Error::new(
            keyword.span(),
            format!("expected `{expected}` keyword"),
        ));
    }

    let fat_arrow_token = input.parse()?;
    let expression = input.parse()?;
    let comma_token = if require_comma {
        Some(input.parse()?)
    } else {
        input.peek(Token![,]).then(|| input.parse()).transpose()?
    };

    Ok(SelectLoopLifecycle {
        keyword,
        fat_arrow_token,
        expression,
        comma_token,
    })
}

/// Conservatively reports whether a pattern is guaranteed to match.
fn is_irrefutable(pattern: &Pat) -> bool {
    // Irrefutability composes only through these structural pattern forms.
    // Treat every unsupported form as refutable.
    match pattern {
        Pat::Wild(_) | Pat::Rest(_) => true,
        Pat::Ident(ident) => ident
            .subpat
            .as_ref()
            .is_none_or(|(_, pattern)| is_irrefutable(pattern)),
        Pat::Type(typed) => is_irrefutable(&typed.pat),
        Pat::Tuple(tuple) => tuple.elems.iter().all(is_irrefutable),
        Pat::Reference(reference) => is_irrefutable(&reference.pat),
        Pat::Paren(paren) => is_irrefutable(&paren.pat),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_select_punctuation() {
        let input: SelectInput = syn::parse_str("value = future() => value, _ = done() => (),")
            .expect("select input should parse");

        assert_eq!(input.branches.len(), 2);
        assert!(
            input
                .branches
                .iter()
                .all(|branch| branch.comma_token.is_some())
        );
    }

    #[test]
    fn parses_select_without_trailing_comma() {
        let input: SelectInput =
            syn::parse_str("value = future() => value").expect("select input should parse");

        assert_eq!(input.branches.len(), 1);
        assert!(input.branches[0].comma_token.is_none());
    }

    #[test]
    fn rejects_top_level_or_pattern() {
        assert!(syn::parse_str::<SelectInput>("Some(value) | None = next() => value,").is_err());
    }

    #[test]
    fn parses_select_loop_lifecycle_and_branches() {
        let input: SelectLoopInput = syn::parse_str(
            "context, on_start => start(), on_stopped => stop(), \
             Some(value) = next() else break => value, on_end => end(),",
        )
        .expect("select_loop input should parse");

        assert!(input.on_start.is_some());
        assert_eq!(input.on_stopped.keyword, "on_stopped");
        assert_eq!(input.branches.len(), 1);
        assert!(input.branches[0].else_clause.is_some());
        assert!(input.on_end.is_some());
        input.validate().expect("input should be valid");
    }

    #[test]
    fn parses_select_loop_without_branches() {
        let input: SelectLoopInput =
            syn::parse_str("context, on_stopped => stop(), on_end => end()")
                .expect("select_loop input should parse");

        assert!(input.branches.is_empty());
        assert!(input.on_end.is_some());
        input.validate().expect("input should be valid");
    }

    #[test]
    fn rejects_refutable_pattern_without_else() {
        let input: SelectLoopInput =
            syn::parse_str("context, on_stopped => stop(), Some(value) = next() => value,")
                .expect("syntax should parse before validation");

        let error = input.validate().expect_err("input should be invalid");
        assert!(
            error
                .to_string()
                .contains("refutable patterns require an else clause")
        );
    }

    #[test]
    fn accepts_irrefutable_patterns_without_else() {
        let input: SelectLoopInput =
            syn::parse_str("context, on_stopped => stop(), (_, value) = next() => value,")
                .expect("select_loop input should parse");

        input.validate().expect("input should be valid");
    }

    #[test]
    fn requires_on_stopped() {
        let error = syn::parse_str::<SelectLoopInput>("context, value = next() => value,")
            .err()
            .expect("input should be invalid");

        assert!(error.to_string().contains("expected `on_stopped` keyword"));
    }

    #[test]
    fn requires_lifecycle_commas() {
        assert!(
            syn::parse_str::<SelectLoopInput>(
                "context, on_start => start() on_stopped => stop(),",
            )
            .is_err()
        );
        assert!(syn::parse_str::<SelectLoopInput>("context, on_stopped => stop()").is_err());
    }
}
