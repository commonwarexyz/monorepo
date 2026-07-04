use super::{
    generics::{
        collect_read_write_ingress_usage, collect_readonly_ingress_usage, filter_generics,
        validate_generics, GenericSet,
    },
    input::{self, Input, ItemKind, SpanRecord},
};
use heck::ToSnakeCase as _;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::format_ident;
use syn::{Attribute, Generics, Ident, LitStr, Result, Type};

#[derive(Clone)]
pub(crate) struct Ingress {
    pub(crate) actor: TokenStream2,
    pub(crate) names: GeneratedNames,
    pub(crate) generics: Generics,
    pub(crate) read_only: Branch,
    pub(crate) read_write: Branch,
    pub(crate) methods: Vec<Method>,
    pub(crate) policy: Policy,
    pub(crate) mailbox_kind: MailboxKind,
}

impl Ingress {
    pub(crate) fn lower(input: Input, actor: TokenStream2) -> Result<Self> {
        let Input {
            unreliable,
            custom_policy,
            mailbox,
            generics,
            items,
        } = input;

        let names = GeneratedNames::new(mailbox);
        let declared = GenericSet::from_generics(&generics);
        let read_only_usage = collect_readonly_ingress_usage(&items, &declared);
        let read_write_usage = collect_read_write_ingress_usage(&items, &declared);
        validate_generics(&generics, &declared, &read_only_usage, &read_write_usage)?;

        let mut read_only_messages = Vec::new();
        let mut read_write_messages = Vec::new();
        let mut methods = Vec::with_capacity(items.len());

        for item in &items {
            let fields = lower_fields(&item.fields);
            methods.push(Method::lower(item, &fields, &actor, &names, unreliable));

            match &item.kind {
                ItemKind::Tell => {
                    read_write_messages.push(Message::tell(item, fields));
                }
                ItemKind::Request {
                    response,
                    read_write,
                    ..
                } => {
                    let message = Message::request(item, fields, response.as_ref().clone());
                    if *read_write {
                        read_write_messages.push(message);
                    } else {
                        read_only_messages.push(message);
                    }
                }
            }
        }

        let read_only = Branch {
            actor: actor.clone(),
            name: names.read_only_ingress.clone(),
            generics: filter_generics(&generics, &read_only_usage),
            messages: read_only_messages,
        };
        let read_write = Branch {
            actor: actor.clone(),
            name: names.read_write_ingress.clone(),
            generics: filter_generics(&generics, &read_write_usage),
            messages: read_write_messages,
        };

        let mailbox_kind = if unreliable {
            MailboxKind::Unreliable
        } else {
            MailboxKind::Reliable
        };
        let policy = Policy {
            mode: match (custom_policy, mailbox_kind) {
                (true, _) => PolicyMode::Custom,
                (false, MailboxKind::Reliable) => PolicyMode::Reliable,
                (false, MailboxKind::Unreliable) => PolicyMode::Unreliable,
            },
            actor: actor.clone(),
            names: names.clone(),
            generics: generics.clone(),
        };

        Ok(Self {
            actor,
            names,
            generics,
            read_only,
            read_write,
            methods,
            policy,
            mailbox_kind,
        })
    }
}

#[derive(Clone)]
pub(crate) struct GeneratedNames {
    pub(crate) mailbox: Ident,
    pub(crate) ingress: Ident,
    pub(crate) read_only_ingress: Ident,
    pub(crate) read_write_ingress: Ident,
    pub(crate) overflow: Ident,
}

impl GeneratedNames {
    fn new(mailbox: Ident) -> Self {
        Self {
            ingress: format_ident!("{}Message", mailbox),
            read_only_ingress: format_ident!("{}ReadOnlyMessage", mailbox),
            read_write_ingress: format_ident!("{}ReadWriteMessage", mailbox),
            overflow: format_ident!("{}Overflow", mailbox),
            mailbox,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MailboxKind {
    Reliable,
    Unreliable,
}

#[derive(Clone)]
pub(crate) struct Branch {
    pub(crate) actor: TokenStream2,
    pub(crate) name: Ident,
    pub(crate) generics: Generics,
    pub(crate) messages: Vec<Message>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BranchKind {
    ReadOnly,
    ReadWrite,
}

impl BranchKind {
    fn route_ident(self) -> Ident {
        match self {
            Self::ReadOnly => Ident::new("ReadOnly", Span::call_site()),
            Self::ReadWrite => Ident::new("ReadWrite", Span::call_site()),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Message {
    pub(crate) attrs: Vec<Attribute>,
    pub(crate) name: Ident,
    pub(crate) fields: Vec<Field>,
    pub(crate) response: Option<Type>,
}

impl Message {
    fn tell(item: &input::Item, fields: Vec<Field>) -> Self {
        Self {
            attrs: item.attrs.clone(),
            name: item.name.clone(),
            fields,
            response: None,
        }
    }

    fn request(item: &input::Item, fields: Vec<Field>, response: Type) -> Self {
        Self {
            attrs: item.attrs.clone(),
            name: item.name.clone(),
            fields,
            response: Some(response),
        }
    }

    pub(crate) const fn is_unit(&self) -> bool {
        self.fields.is_empty()
    }
}

#[derive(Clone)]
pub(crate) struct Field {
    pub(crate) attrs: Vec<Attribute>,
    pub(crate) name: Ident,
    pub(crate) ty: Type,
    pub(crate) span_record: Option<SpanRecord>,
}

impl From<&input::Field> for Field {
    fn from(field: &input::Field) -> Self {
        Self {
            attrs: field.attrs.clone(),
            name: field.name.clone(),
            ty: field.ty.clone(),
            span_record: field.span_record,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SpanField {
    pub(crate) name: Ident,
    pub(crate) record: SpanRecord,
}

#[derive(Clone)]
pub(crate) struct Method {
    pub(crate) actor: TokenStream2,
    pub(crate) ingress: Ident,
    pub(crate) attrs: Vec<Attribute>,
    pub(crate) public: bool,
    pub(crate) name: Ident,
    pub(crate) variant: Ident,
    pub(crate) fields: Vec<Field>,
    pub(crate) span_name: LitStr,
    pub(crate) span_fields: Vec<SpanField>,
    pub(crate) kind: MethodKind,
}

impl Method {
    fn lower(
        item: &input::Item,
        fields: &[Field],
        actor: &TokenStream2,
        names: &GeneratedNames,
        unreliable: bool,
    ) -> Self {
        Self {
            actor: actor.clone(),
            ingress: names.ingress.clone(),
            attrs: item.attrs.clone(),
            public: item.public_method,
            name: format_ident!("{}", item.name.to_string().to_snake_case()),
            variant: item.name.clone(),
            fields: fields.to_vec(),
            span_name: span_name(&names.mailbox, &item.name),
            span_fields: lower_span_fields(fields),
            kind: MethodKind::lower(item, names, unreliable),
        }
    }
}

#[derive(Clone)]
pub(crate) enum MethodKind {
    Tell {
        feedback: Feedback,
        message: Ident,
    },
    Request {
        feedback: Feedback,
        route: Ident,
        message: Ident,
        response: Box<Type>,
        await_response: bool,
    },
}

impl MethodKind {
    fn lower(item: &input::Item, names: &GeneratedNames, unreliable: bool) -> Self {
        match &item.kind {
            ItemKind::Tell => Self::Tell {
                feedback: if unreliable {
                    Feedback::Unreliable
                } else {
                    Feedback::Reliable
                },
                message: names.read_write_ingress.clone(),
            },
            ItemKind::Request {
                response,
                read_write,
                await_response,
            } => {
                let branch = if *read_write {
                    BranchKind::ReadWrite
                } else {
                    BranchKind::ReadOnly
                };
                let message = if *read_write {
                    names.read_write_ingress.clone()
                } else {
                    names.read_only_ingress.clone()
                };

                Self::Request {
                    feedback: if unreliable {
                        Feedback::Unreliable
                    } else {
                        Feedback::Reliable
                    },
                    route: branch.route_ident(),
                    message,
                    response: response.clone(),
                    await_response: *await_response,
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Feedback {
    Reliable,
    Unreliable,
}

#[derive(Clone)]
pub(crate) struct Policy {
    pub(crate) mode: PolicyMode,
    pub(crate) actor: TokenStream2,
    pub(crate) names: GeneratedNames,
    pub(crate) generics: Generics,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyMode {
    Custom,
    Reliable,
    Unreliable,
}

fn lower_fields(fields: &[input::Field]) -> Vec<Field> {
    fields.iter().map(Field::from).collect()
}

fn lower_span_fields(fields: &[Field]) -> Vec<SpanField> {
    fields
        .iter()
        .filter_map(|field| {
            field.span_record.map(|record| SpanField {
                name: field.name.clone(),
                record,
            })
        })
        .collect()
}

/// The compile-time span name for a generated mailbox method:
/// `actor.<mailbox_snake>.<method_snake>`.
fn span_name(mailbox: &Ident, item: &Ident) -> LitStr {
    let mailbox = mailbox.to_string().to_snake_case();
    let item = item.to_string().to_snake_case();
    LitStr::new(&format!("actor.{mailbox}.{item}"), Span::call_site())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;
    use syn::GenericParam;

    fn lower_str(source: &str) -> Result<Ingress> {
        let input = syn::parse_str::<Input>(source)?;
        Ingress::lower(input, quote!(::commonware_actor))
    }

    /// All error messages joined, so substring assertions do not depend on the
    /// order in which errors were combined.
    fn lower_errors(source: &str) -> String {
        match lower_str(source) {
            Ok(_) => panic!("expected lowering to fail"),
            Err(error) => error
                .into_iter()
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }

    fn generic_names(generics: &Generics) -> Vec<String> {
        generics
            .params
            .iter()
            .map(|param| match param {
                GenericParam::Type(param) => param.ident.to_string(),
                GenericParam::Lifetime(param) => format!("'{}", param.lifetime.ident),
                GenericParam::Const(param) => param.ident.to_string(),
            })
            .collect()
    }

    #[test]
    fn log_shape_lowers_to_bare_readonly_and_generic_readwrite() {
        let ingress = lower_str(
            "Mailbox<D: Digest>, \
             subscribe read_write Propose -> D; \
             subscribe Verify -> bool;",
        )
        .expect("lowering should succeed");

        assert_eq!(ingress.read_only.messages.len(), 1);
        assert_eq!(ingress.read_only.messages[0].name, "Verify");
        assert!(ingress.read_only.generics.params.is_empty());

        assert_eq!(ingress.read_write.messages.len(), 1);
        assert_eq!(ingress.read_write.messages[0].name, "Propose");
        assert_eq!(generic_names(&ingress.read_write.generics), vec!["D"]);
    }

    #[test]
    fn split_generic_input_assigns_one_generic_per_branch() {
        let ingress = lower_str(
            "Mailbox<A: Send + 'static, B: Send + 'static>, \
             tell Left { value: A }; \
             ask Right -> B;",
        )
        .expect("lowering should succeed");

        assert_eq!(generic_names(&ingress.read_write.generics), vec!["A"]);
        assert_eq!(generic_names(&ingress.read_only.generics), vec!["B"]);
    }

    #[test]
    fn all_tell_generic_input_has_uninhabited_generic_free_readonly() {
        let ingress = lower_str(
            "Mailbox<T>, \
             tell Store { value: T };",
        )
        .expect("lowering should succeed");

        assert!(ingress.read_only.generics.params.is_empty());
        assert!(ingress.read_only.messages.is_empty());
        assert_eq!(generic_names(&ingress.read_write.generics), vec!["T"]);
    }

    #[test]
    fn rejects_generic_defaults_during_lowering() {
        let errors = lower_errors("Mailbox<D: Digest = Foo>, tell Ping { value: D };");
        assert!(
            errors.contains("defaults are not supported on ingress! generics"),
            "{errors}"
        );

        let errors = lower_errors("Mailbox<const N: usize = 4>, tell Ping { value: [u8; N] };");
        assert!(
            errors.contains("defaults are not supported on ingress! generics"),
            "{errors}"
        );
    }

    #[test]
    fn rejects_unused_generics_during_lowering() {
        let errors = lower_errors("Mailbox<T: Send + 'static>, tell Ping;");
        assert!(
            errors.contains("`T` is not used by any ingress item"),
            "{errors}"
        );
    }

    #[test]
    fn rejects_bound_dependency_on_dropped_generic_during_lowering() {
        let errors = lower_errors(
            "Mailbox<A: Send + 'static, B: AsRef<A> + Send + 'static>, \
             tell Push { value: A }; \
             ask Get { key: B } -> u64;",
        );
        assert!(errors.contains("read-only items use `B`"), "{errors}");
        assert!(errors.contains("bounds reference `A`"), "{errors}");
    }
}
