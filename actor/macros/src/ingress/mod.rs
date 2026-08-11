use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{ToTokens, quote};
use syn::{Ident, Result, parse_macro_input};

mod emit;
mod generics;
mod input;
mod model;

use input::Input;
use model::Ingress;

fn dependency_ident(name: &str) -> Result<Ident> {
    let name = name.replace('-', "_");
    let mut ident = syn::parse_str::<Ident>(&name)
        .or_else(|_| syn::parse_str::<Ident>(&format!("r#{name}")))
        .map_err(|_| {
            syn::Error::new(
                Span::call_site(),
                format!("dependency alias `{name}` cannot be used as a Rust crate path"),
            )
        })?;
    ident.set_span(Span::call_site());
    Ok(ident)
}

fn actor_path() -> Result<TokenStream2> {
    match crate_name("commonware-actor") {
        Ok(FoundCrate::Itself) => Ok(quote!(crate)),
        Ok(FoundCrate::Name(name)) => {
            let ident = dependency_ident(&name)?;
            Ok(quote!(::#ident))
        }
        Err(err) => Err(syn::Error::new(
            Span::call_site(),
            format!("unable to locate commonware-actor crate: {err}"),
        )),
    }
}

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as Input);
    actor_path()
        .and_then(|actor| lower_and_emit(input, actor))
        .unwrap_or_else(|error| error.to_compile_error())
        .into()
}

fn lower_and_emit(input: Input, actor: TokenStream2) -> Result<TokenStream2> {
    Ok(Ingress::lower(input, actor)?.into_token_stream())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand_str(source: &str) -> Result<TokenStream2> {
        let input = syn::parse_str::<Input>(source)?;
        lower_and_emit(input, quote!(::commonware_actor))
    }

    /// All error messages joined, so substring assertions do not depend on the
    /// order in which errors were combined.
    fn expand_errors(source: &str) -> String {
        expand_str(source)
            .expect_err("expected expansion to fail")
            .into_iter()
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn find_enum<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemEnum {
        file.items
            .iter()
            .find_map(|item| match item {
                syn::Item::Enum(item) if item.ident == name => Some(item),
                _ => None,
            })
            .unwrap_or_else(|| panic!("generated enum `{name}` not found"))
    }

    fn inherent_method_names(file: &syn::File, name: &str) -> Vec<String> {
        let mut methods = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Impl(item) if item.trait_.is_none() => Some(item),
                _ => None,
            })
            .filter(|item| match item.self_ty.as_ref() {
                syn::Type::Path(path) => path
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == name),
                _ => false,
            })
            .flat_map(|item| &item.items)
            .filter_map(|item| match item {
                syn::ImplItem::Fn(item) => Some(item.sig.ident.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();
        methods.sort();
        methods
    }

    fn doc_values(attrs: &[syn::Attribute]) -> Vec<String> {
        attrs
            .iter()
            .filter_map(|attr| {
                if !attr.path().is_ident("doc") {
                    return None;
                }
                match &attr.meta {
                    syn::Meta::NameValue(meta) => match &meta.value {
                        syn::Expr::Lit(expr) => match &expr.lit {
                            syn::Lit::Str(value) => Some(value.value()),
                            _ => None,
                        },
                        _ => None,
                    },
                    _ => None,
                }
            })
            .collect()
    }

    #[test]
    fn rejects_fully_unused_generic() {
        let errors = expand_errors("Mailbox<T: Send + 'static>, tell Ping;");
        assert!(
            errors.contains("`T` is not used by any ingress item"),
            "{errors}"
        );
    }

    #[test]
    fn rejects_unused_generic_among_used() {
        let errors = expand_errors(
            "Mailbox<A: Send + 'static, B: Send + 'static>, \
             tell Push { value: A }; \
             ask Get -> u64;",
        );
        assert!(
            errors.contains("`B` is not used by any ingress item"),
            "{errors}"
        );
        assert!(!errors.contains("`A` is not used"), "{errors}");
    }

    #[test]
    fn rejects_bound_dependency_on_dropped_generic() {
        let errors = expand_errors(
            "Mailbox<A: Send + 'static, B: AsRef<A> + Send + 'static>, \
             tell Push { value: A }; \
             ask Get { key: B } -> u64;",
        );
        assert!(errors.contains("read-only items use `B`"), "{errors}");
        assert!(errors.contains("bounds reference `A`"), "{errors}");
    }

    #[test]
    fn rejects_type_param_default() {
        let errors = expand_errors("Mailbox<D: Digest = Foo>, tell Ping { value: D };");
        assert!(
            errors.contains("defaults are not supported on ingress! generics"),
            "{errors}"
        );
    }

    #[test]
    fn emits_documented_mailbox_method_names() {
        let tokens = expand_str(
            "Mailbox, \
             pub tell Ping; \
             pub ask GetValue -> u64; \
             pub subscribe Watch -> u64;",
        )
        .expect("expansion should succeed");
        let file: syn::File = syn::parse2(tokens).expect("output should parse");

        assert_eq!(
            inherent_method_names(&file, "Mailbox"),
            [
                "enqueue_get_value",
                "enqueue_watch",
                "get_value",
                "ping",
                "watch",
            ]
        );
    }

    #[test]
    fn rejects_prefixed_method_name_collision() {
        let errors = expand_errors(
            "Mailbox, \
             pub tell EnqueueFoo; \
             pub ask Foo -> ();",
        );

        assert!(errors.contains("enqueue_foo"), "{errors}");
        assert!(errors.contains("conflicts"), "{errors}");
    }

    #[test]
    fn rejects_normalized_method_name_collision() {
        let errors = expand_errors(
            "Mailbox, \
             pub tell XMLHttpRequest; \
             pub tell XmlHttpRequest;",
        );

        assert!(errors.contains("xml_http_request"), "{errors}");
        assert!(errors.contains("conflicts"), "{errors}");
    }

    #[test]
    fn rejects_fixed_wrapper_method_collision() {
        for item in ["Clone", "From"] {
            let errors = expand_errors(&format!("Mailbox, pub tell {item};"));

            assert!(errors.contains("conflicts"), "{errors}");
        }
    }

    #[test]
    fn rejects_generated_type_name_generic_collision() {
        let errors = expand_errors(
            "CapturedMailbox<CapturedMailboxMessage: Send + 'static>, \
             pub tell Store { value: CapturedMailboxMessage };",
        );

        assert!(errors.contains("CapturedMailboxMessage"), "{errors}");
        assert!(errors.contains("generated type"), "{errors}");
    }

    #[test]
    fn emits_raw_identifier_for_keyword_method() {
        let tokens = expand_str("Mailbox, pub tell Type;").expect("expansion should succeed");
        let file: syn::File = syn::parse2(tokens).expect("output should parse");

        assert_eq!(inherent_method_names(&file, "Mailbox"), ["r#type"]);
    }

    #[test]
    fn normalizes_raw_item_identifier() {
        let tokens = expand_str("Mailbox, pub tell r#Ping;").expect("expansion should succeed");
        let file: syn::File = syn::parse2(tokens).expect("output should parse");

        assert_eq!(inherent_method_names(&file, "Mailbox"), ["ping"]);
    }

    #[test]
    fn rejects_unrawable_keyword_method() {
        let errors = expand_errors("Mailbox, pub tell Crate;");

        assert!(errors.contains("crate"), "{errors}");
        assert!(errors.contains("method name"), "{errors}");
    }

    #[test]
    fn generated_support_paths_are_absolute() {
        let rendered = expand_str("Mailbox, pub tell Ping; pub ask Get -> u64;")
            .expect("expansion should succeed")
            .to_string();

        for path in [
            ":: core :: clone :: Clone",
            ":: core :: ops :: FnMut",
            ":: core :: option :: Option",
            ":: core :: result :: Result",
        ] {
            assert!(rendered.contains(path), "missing `{path}` in {rendered}");
        }
    }

    #[test]
    fn generated_policy_generic_does_not_shadow_mailbox_generic() {
        let rendered = expand_str(
            "Mailbox<__Push: Send + 'static>, \
             pub tell Store { value: __Push };",
        )
        .expect("expansion should succeed")
        .to_string();

        assert!(!rendered.contains("fn drain < __Push >"), "{rendered}");
    }

    #[test]
    fn generated_policy_generic_does_not_shadow_raw_mailbox_generic() {
        let rendered = expand_str(
            "Mailbox<r#__Push: Send + 'static>, \
             pub tell Store { value: r#__Push };",
        )
        .expect("expansion should succeed")
        .to_string();

        assert!(!rendered.contains("fn drain < __Push >"), "{rendered}");
    }

    #[test]
    fn raw_generic_spelling_matches_ordinary_uses() {
        expand_str(
            "Mailbox<r#Payload: Send + 'static>, \
             pub tell Store { value: Payload };",
        )
        .expect("raw and ordinary spellings name the same generic parameter");
    }

    #[test]
    fn log_shape_expansion_drops_unused_generic_without_phantom() {
        let tokens = expand_str(
            "Mailbox<D: Digest>, \
             subscribe read_write Propose -> D; \
             subscribe Verify -> bool;",
        )
        .expect("expansion should succeed");
        let rendered = tokens.to_string();
        assert!(!rendered.contains("_Phantom"), "{rendered}");
        assert!(!rendered.contains("PhantomData"), "{rendered}");

        let file: syn::File = syn::parse2(tokens).expect("output should parse");
        assert!(
            find_enum(&file, "MailboxReadOnlyMessage")
                .generics
                .params
                .is_empty(),
            "read-only enum should carry no generics"
        );
        assert_eq!(
            find_enum(&file, "MailboxReadWriteMessage")
                .generics
                .params
                .len(),
            1,
            "read-write enum should carry only `D`"
        );
    }

    #[test]
    fn split_generics_are_filtered_per_branch() {
        let tokens = expand_str(
            "Mailbox<A: Send + 'static, B: Send + 'static>, \
             tell Left { value: A }; \
             ask Right -> B;",
        )
        .expect("expansion should succeed");

        let file: syn::File = syn::parse2(tokens).expect("output should parse");
        let read_only = find_enum(&file, "MailboxReadOnlyMessage");
        assert_eq!(read_only.generics.params.len(), 1);
        let read_write = find_enum(&file, "MailboxReadWriteMessage");
        assert_eq!(read_write.generics.params.len(), 1);
    }

    #[test]
    fn const_generic_used_in_retained_bound_is_retained() {
        let tokens = expand_str(
            "Mailbox<const N: usize, T: Bound<N>>, \
             ask Get -> T;",
        )
        .expect("expansion should succeed");

        let file: syn::File = syn::parse2(tokens).expect("output should parse");
        let read_only = find_enum(&file, "MailboxReadOnlyMessage");
        assert_eq!(read_only.generics.params.len(), 2);
    }

    #[test]
    fn type_macro_retains_referenced_branch_generics() {
        let tokens = expand_str(
            "Mailbox<T: Send + 'static>, \
             tell Store { value: identity_ty!(T) };",
        )
        .expect("type macro should retain referenced `T`");
        let file: syn::File = syn::parse2(tokens).expect("output should parse");

        assert_eq!(
            find_enum(&file, "MailboxReadWriteMessage")
                .generics
                .params
                .len(),
            1
        );
    }

    #[test]
    fn type_macro_ignores_qualified_matching_identifiers() {
        let tokens = expand_str(
            "Mailbox<T: Send + 'static>, \
             tell Store { value: T }; \
             ask Fetch -> identity_ty!(types::T);",
        )
        .expect("qualified type should not retain generic `T`");
        let file: syn::File = syn::parse2(tokens).expect("output should parse");

        assert!(
            find_enum(&file, "MailboxReadOnlyMessage")
                .generics
                .params
                .is_empty()
        );
    }

    #[test]
    fn dependency_keyword_needs_raw_identifier() {
        let ident = dependency_ident("type").expect("keyword should be raw escaped");

        assert!(syn::parse2::<syn::Path>(quote!(::#ident)).is_ok());
    }

    #[test]
    fn field_docs_are_emitted_on_message_fields() {
        let tokens = expand_str(
            r#"
            Mailbox,
            tell Store {
                /// Value retained by the actor.
                value: u64
            };
            "#,
        )
        .expect("expansion should succeed");

        let file: syn::File = syn::parse2(tokens).expect("output should parse");
        let read_write = find_enum(&file, "MailboxReadWriteMessage");
        let variant = read_write
            .variants
            .iter()
            .find(|variant| variant.ident == "Store")
            .expect("Store variant should exist");
        let syn::Fields::Named(fields) = &variant.fields else {
            panic!("Store should have named fields");
        };
        let field = fields
            .named
            .iter()
            .find(|field| field.ident.as_ref().is_some_and(|ident| ident == "value"))
            .expect("value field should exist");

        assert_eq!(
            doc_values(&field.attrs),
            vec![" Value retained by the actor."]
        );
    }
}
