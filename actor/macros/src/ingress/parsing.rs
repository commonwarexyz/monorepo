use proc_macro2::Span;
use syn::{
    braced,
    parse::{Parse, ParseStream},
    Attribute, Generics, Ident, Result, Token, Type,
};

mod kw {
    syn::custom_keyword!(tell);
    syn::custom_keyword!(ask);
    syn::custom_keyword!(unbounded);
}

#[derive(Clone, Copy)]
pub(crate) enum MailboxKind {
    Bounded,
    Unbounded,
}

pub(crate) enum ItemKind {
    Tell,
    Ask { response: Box<Type> },
}

impl ItemKind {
    pub(crate) const fn response(&self) -> Option<&Type> {
        match self {
            Self::Tell => None,
            Self::Ask { response } => Some(response),
        }
    }
}

pub(crate) struct Field {
    pub(crate) attrs: Vec<Attribute>,
    pub(crate) name: Ident,
    pub(crate) ty: Type,
}

pub(crate) struct Item {
    pub(crate) attrs: Vec<Attribute>,
    pub(crate) name: Ident,
    pub(crate) fields: Vec<Field>,
    pub(crate) expose_on_mailbox: bool,
    pub(crate) kind: ItemKind,
}

impl Item {
    pub(crate) const fn is_unit(&self) -> bool {
        self.fields.is_empty()
    }
}

pub(crate) struct IngressInput {
    pub(crate) mailbox_kind: MailboxKind,
    pub(crate) mailbox: Ident,
    pub(crate) generics: Generics,
    pub(crate) items: Vec<Item>,
}

impl Parse for Field {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let name: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let ty: Type = input.parse()?;
        Ok(Self { attrs, name, ty })
    }
}

fn parse_fields(input: ParseStream<'_>) -> Result<Vec<Field>> {
    if !input.peek(syn::token::Brace) {
        return Ok(Vec::new());
    }

    let content;
    braced!(content in input);
    Ok(content
        .parse_terminated(Field::parse, Token![,])?
        .into_iter()
        .collect())
}

fn parse_item(input: ParseStream<'_>) -> Result<Item> {
    let attrs = input.call(Attribute::parse_outer)?;
    let expose_on_mailbox = if input.peek(Token![pub]) {
        input.parse::<Token![pub]>()?;
        true
    } else {
        false
    };

    let kind = if input.peek(kw::tell) {
        input.parse::<kw::tell>()?;
        ItemKind::Tell
    } else if input.peek(kw::ask) {
        input.parse::<kw::ask>()?;
        let name: Ident = input.parse()?;
        let fields = parse_fields(input)?;
        input.parse::<Token![->]>()?;
        let response: Type = input.parse()?;
        input.parse::<Token![;]>()?;
        return Ok(Item {
            attrs,
            name,
            fields,
            expose_on_mailbox,
            kind: ItemKind::Ask {
                response: Box::new(response),
            },
        });
    } else {
        return Err(input.error("expected `tell` or `ask` item"));
    };

    let name: Ident = input.parse()?;
    let fields = parse_fields(input)?;
    input.parse::<Token![;]>()?;

    Ok(Item {
        attrs,
        name,
        fields,
        expose_on_mailbox,
        kind,
    })
}

impl Parse for IngressInput {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mailbox_kind = if input.peek(kw::unbounded) {
            input.parse::<kw::unbounded>()?;
            MailboxKind::Unbounded
        } else {
            MailboxKind::Bounded
        };

        let has_header = !(input.peek(kw::tell) || input.peek(kw::ask) || input.peek(Token![pub]));
        let (mailbox, generics) = if has_header {
            let mailbox: Ident = input.parse()?;
            let generics = if input.peek(Token![<]) {
                input.parse()?
            } else {
                Generics::default()
            };
            input.parse::<Token![,]>()?;
            (mailbox, generics)
        } else {
            (
                Ident::new("Mailbox", Span::call_site()),
                Generics::default(),
            )
        };

        let mut items = Vec::new();
        while !input.is_empty() {
            items.push(parse_item(input)?);
        }

        if items.is_empty() {
            return Err(syn::Error::new(
                mailbox.span(),
                "ingress! requires at least one `tell` or `ask` item",
            ));
        }

        Ok(Self {
            mailbox_kind,
            mailbox,
            generics,
            items,
        })
    }
}
