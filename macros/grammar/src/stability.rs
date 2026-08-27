//! Input grammars for the stability macros.

use syn::{
    Error, Ident, Item, LitInt, Meta, Token, Visibility, braced, parenthesized,
    parse::{Parse, ParseStream, Result},
    token::{Brace, Mod, Paren},
};

/// Source representation of a stability level.
#[derive(Clone)]
pub enum StabilityLevelSyntax {
    /// Integer level from zero through four.
    Literal(LitInt),
    /// Named stability level.
    Named(Ident),
}

/// Stability level accepted by Commonware macros.
#[derive(Clone)]
pub struct StabilityLevel {
    value: u8,
    syntax: StabilityLevelSyntax,
}

impl StabilityLevel {
    /// Returns the numeric value from zero through four.
    pub const fn value(&self) -> u8 {
        self.value
    }

    /// Returns the original source representation.
    pub const fn syntax(&self) -> &StabilityLevelSyntax {
        &self.syntax
    }
}

impl Parse for StabilityLevel {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(LitInt) {
            let literal: LitInt = input.parse()?;
            let value = literal.base10_parse().map_err(|_| {
                Error::new(literal.span(), "stability level must be 0, 1, 2, 3, or 4")
            })?;
            if value > 4 {
                return Err(Error::new(
                    literal.span(),
                    "stability level must be 0, 1, 2, 3, or 4",
                ));
            }
            Ok(Self {
                value,
                syntax: StabilityLevelSyntax::Literal(literal),
            })
        } else if lookahead.peek(Ident) {
            let ident: Ident = input.parse()?;
            let value = match ident.to_string().as_str() {
                "ALPHA" => 0,
                "BETA" => 1,
                "GAMMA" => 2,
                "DELTA" => 3,
                "EPSILON" => 4,
                _ => {
                    return Err(Error::new(
                        ident.span(),
                        "expected stability level: ALPHA, BETA, GAMMA, DELTA, EPSILON, or 0-4",
                    ));
                }
            };
            Ok(Self {
                value,
                syntax: StabilityLevelSyntax::Named(ident),
            })
        } else {
            Err(lookahead.error())
        }
    }
}

/// Input for `stability_mod!`.
#[derive(Clone)]
pub struct StabilityModInput {
    /// Stability level applied to the module.
    pub level: StabilityLevel,
    /// Separator after the stability level.
    pub comma_token: Token![,],
    /// Module visibility.
    pub visibility: Visibility,
    /// Module keyword.
    pub mod_token: Mod,
    /// Module name.
    pub name: Ident,
}

impl Parse for StabilityModInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        Ok(Self {
            level: input.parse()?,
            comma_token: input.parse()?,
            visibility: input.parse()?,
            mod_token: input.parse()?,
            name: input.parse()?,
        })
    }
}

/// Optional `cfg` predicate in `stability_scope!`.
#[derive(Clone)]
pub struct StabilityCfg {
    /// Separator before the predicate.
    pub comma_token: Token![,],
    /// The `cfg` identifier.
    pub cfg_ident: Ident,
    /// Parentheses around the predicate.
    pub paren_token: Paren,
    /// Parsed cfg predicate.
    pub predicate: Meta,
}

/// Input for `stability_scope!`.
#[derive(Clone)]
pub struct StabilityScopeInput {
    /// Stability level applied to each item.
    pub level: StabilityLevel,
    /// Optional cfg predicate.
    pub cfg: Option<StabilityCfg>,
    /// Braces around the items.
    pub brace_token: Brace,
    /// Items governed by the stability level and predicate.
    pub items: Vec<Item>,
}

impl Parse for StabilityScopeInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let level = input.parse()?;
        let cfg = if input.peek(Token![,]) {
            let comma_token = input.parse()?;
            let cfg_ident: Ident = input.parse()?;
            if cfg_ident != "cfg" {
                return Err(Error::new(cfg_ident.span(), "expected `cfg`"));
            }
            let content;
            let paren_token = parenthesized!(content in input);
            Some(StabilityCfg {
                comma_token,
                cfg_ident,
                paren_token,
                predicate: content.parse()?,
            })
        } else {
            None
        };

        let content;
        let brace_token = braced!(content in input);
        let mut items = Vec::new();
        while !content.is_empty() {
            items.push(content.parse()?);
        }

        Ok(Self {
            level,
            cfg,
            brace_token,
            items,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_and_numeric_levels() {
        for (source, expected) in [
            ("ALPHA", 0),
            ("BETA", 1),
            ("GAMMA", 2),
            ("DELTA", 3),
            ("EPSILON", 4),
            ("0", 0),
            ("1", 1),
            ("2", 2),
            ("3", 3),
            ("4", 4),
        ] {
            let level: StabilityLevel = syn::parse_str(source).expect("level should parse");
            assert_eq!(level.value(), expected);
        }
    }

    #[test]
    fn rejects_invalid_levels() {
        for source in ["5", "UNKNOWN"] {
            assert!(syn::parse_str::<StabilityLevel>(source).is_err());
        }
    }

    #[test]
    fn parses_module_input() {
        let input: StabilityModInput =
            syn::parse_str("BETA, pub(crate) mod example").expect("module input should parse");

        assert_eq!(input.level.value(), 1);
        assert_eq!(input.name, "example");
    }

    #[test]
    fn rejects_inline_module_input() {
        assert!(syn::parse_str::<StabilityModInput>("BETA, pub mod example {}").is_err());
    }

    #[test]
    fn parses_scope_with_cfg_and_items() {
        let input: StabilityScopeInput = syn::parse_str(
            "GAMMA, cfg(all(test, feature = \"std\")) { pub struct Example; fn hidden() {} }",
        )
        .expect("scope input should parse");

        assert_eq!(input.level.value(), 2);
        assert!(input.cfg.is_some());
        assert_eq!(input.items.len(), 2);
    }

    #[test]
    fn parses_empty_scope_without_cfg() {
        let input: StabilityScopeInput =
            syn::parse_str("ALPHA {}").expect("scope input should parse");

        assert!(input.cfg.is_none());
        assert!(input.items.is_empty());
    }

    #[test]
    fn rejects_non_cfg_predicate() {
        let error = syn::parse_str::<StabilityScopeInput>("ALPHA, other(test) {}");
        assert!(error.is_err());
    }
}
