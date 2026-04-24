//! Augment the development of [`commonware-runtime`](https://docs.rs/commonware-runtime) with procedural macros.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use proc_macro::TokenStream;
use proc_macro2::Span;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::quote;
use syn::{parse_quote, DeriveInput, Ident};

fn found_crate_path(found: FoundCrate) -> proc_macro2::TokenStream {
    match found {
        FoundCrate::Itself => quote!(crate),
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            quote!(::#ident)
        }
    }
}

// The upstream derive crate hardcodes `::prometheus_client::encoding` in the
// generated impls.
//
// Source: https://github.com/prometheus/client_rust/blob/7844d8617926a6f29b772d195860cf118051d019/derive-encode/src/lib.rs#L14-L133
//
// Commonware resolves through `commonware-runtime::telemetry::metrics::encoding`
// first so downstream crates can derive metric labels without a direct
// `prometheus-client` dependency.
fn metrics_encoding_path() -> proc_macro2::TokenStream {
    if let Ok(found) = crate_name("commonware-runtime") {
        let runtime = found_crate_path(found);
        return quote!(#runtime::telemetry::metrics::encoding);
    }
    if let Ok(found) = crate_name("prometheus-client") {
        let prometheus = found_crate_path(found);
        return quote!(#prometheus::encoding);
    }
    quote!(::prometheus_client::encoding)
}

// Adapted from client_rust's `EncodeLabelSet` derive and extended to support
// Commonware's `EncodeStruct` variant.
//
// Source: https://github.com/prometheus/client_rust/blob/7844d8617926a6f29b772d195860cf118051d019/derive-encode/src/lib.rs#L14-L87
#[proc_macro_derive(EncodeLabelSet, attributes(prometheus))]
pub fn derive_encode_label_set(input: TokenStream) -> TokenStream {
    derive_label_set_impl(input, false)
}

#[proc_macro_derive(EncodeStruct)]
pub fn derive_encode_struct(input: TokenStream) -> TokenStream {
    derive_label_set_impl(input, true)
}

fn derive_label_set_impl(input: TokenStream, display: bool) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();
    let name = &ast.ident;
    let encoding = metrics_encoding_path();

    let fields = match ast.clone().data {
        syn::Data::Struct(s) => match s.fields {
            syn::Fields::Named(syn::FieldsNamed { named, .. }) => named,
            syn::Fields::Unnamed(_) => {
                panic!("Can not derive Encode for struct with unnamed fields.")
            }
            syn::Fields::Unit => panic!("Can not derive Encode for struct with unit field."),
        },
        syn::Data::Enum(syn::DataEnum { .. }) => panic!("Can not derive Encode for enum."),
        syn::Data::Union(_) => panic!("Can not derive Encode for union."),
    };

    let fields_vec: Vec<_> = fields.into_iter().collect();
    let body: proc_macro2::TokenStream = fields_vec
        .iter()
        .cloned()
        .map(|f| {
            let attribute = f
                .attrs
                .iter()
                .find(|a| a.path().is_ident("prometheus"))
                .map(|a| a.parse_args::<Ident>().unwrap().to_string());
            let flatten = match attribute.as_deref() {
                Some("flatten") => true,
                Some(other) => {
                    panic!("Provided field attribute '{other}', but only 'flatten' is supported")
                }
                None => false,
            };
            let ident = f.ident.unwrap();
            if flatten {
                quote! {
                    #encoding::EncodeLabelSet::encode(&self.#ident, encoder)?;
                }
            } else {
                let ident_string = KEYWORD_IDENTIFIERS
                    .iter()
                    .find(|pair| ident == pair.1)
                    .map(|pair| pair.0.to_string())
                    .unwrap_or_else(|| ident.to_string());

                let encode_value = if display {
                    quote! {
                        ::core::write!(&mut label_value_encoder, "{}", self.#ident)?;
                    }
                } else {
                    quote! {
                        EncodeLabelValue::encode(&self.#ident, &mut label_value_encoder)?;
                    }
                };

                quote! {
                    let mut label_encoder = encoder.encode_label();
                    let mut label_key_encoder = label_encoder.encode_label_key()?;
                    EncodeLabelKey::encode(&#ident_string, &mut label_key_encoder)?;

                    let mut label_value_encoder = label_key_encoder.encode_label_value()?;
                    #encode_value

                    label_value_encoder.finish()?;
                }
            }
        })
        .collect();

    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

    let single_field_impls = if display && fields_vec.len() == 1 {
        let field = &fields_vec[0];
        let field_ident = field.ident.as_ref().unwrap();
        let field_ty = &field.ty;
        // Preserve the wrapper's own predicates and add `Clone` on the field type,
        // so wrappers that write their bounds in a `where` clause (not inline)
        // still get a well-formed `From<&T>` impl.
        let mut from_generics = ast.generics.clone();
        from_generics
            .make_where_clause()
            .predicates
            .push(parse_quote!(#field_ty: ::core::clone::Clone));
        let (from_impl_generics, from_ty_generics, from_where_clause) =
            from_generics.split_for_impl();
        quote! {
            impl #impl_generics ::core::borrow::Borrow<#field_ty> for #name #ty_generics #where_clause {
                fn borrow(&self) -> &#field_ty {
                    &self.#field_ident
                }
            }

            impl #from_impl_generics ::core::convert::From<&#field_ty> for #name #from_ty_generics #from_where_clause {
                fn from(value: &#field_ty) -> Self {
                    Self { #field_ident: value.clone() }
                }
            }
        }
    } else {
        quote!()
    };

    quote! {
        impl #impl_generics #encoding::EncodeLabelSet for #name #ty_generics #where_clause {
            fn encode(&self, encoder: &mut #encoding::LabelSetEncoder) -> ::core::result::Result<(), ::core::fmt::Error> {
                use #encoding::EncodeLabel;
                use #encoding::EncodeLabelKey;
                use #encoding::EncodeLabelValue;
                use ::core::fmt::Write as _;

                #body

                ::core::result::Result::Ok(())
            }
        }

        #single_field_impls
    }
    .into()
}

// Adapted from client_rust's `EncodeLabelValue` derive so the generated impls
// resolve through `metrics_encoding_path()` instead of a hardcoded crate path.
//
// Source: https://github.com/prometheus/client_rust/blob/7844d8617926a6f29b772d195860cf118051d019/derive-encode/src/lib.rs#L90-L133
#[proc_macro_derive(EncodeLabelValue)]
pub fn derive_encode_label_value(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();
    let name = &ast.ident;
    let encoding = metrics_encoding_path();

    let body = match ast.clone().data {
        syn::Data::Struct(_) => panic!("Can not derive EncodeLabel for struct."),
        syn::Data::Enum(syn::DataEnum { variants, .. }) => {
            let match_arms: proc_macro2::TokenStream = variants
                .into_iter()
                .map(|v| {
                    let ident = v.ident;
                    quote! {
                        #name::#ident => encoder.write_str(stringify!(#ident))?,
                    }
                })
                .collect();

            quote! {
                match self {
                    #match_arms
                }
            }
        }
        syn::Data::Union(_) => panic!("Can not derive Encode for union."),
    };

    quote! {
        impl #encoding::EncodeLabelValue for #name {
            fn encode(&self, encoder: &mut #encoding::LabelValueEncoder) -> ::core::result::Result<(), ::core::fmt::Error> {
                use ::core::fmt::Write;

                #body

                ::core::result::Result::Ok(())
            }
        }
    }
    .into()
}

// Copied from client_rust's keyword table, which in turn cites Askama.
//
// Source: https://github.com/prometheus/client_rust/blob/7844d8617926a6f29b772d195860cf118051d019/derive-encode/src/lib.rs#L135-L184
static KEYWORD_IDENTIFIERS: [(&str, &str); 49] = [
    ("as", "r#as"),
    ("break", "r#break"),
    ("const", "r#const"),
    ("continue", "r#continue"),
    ("crate", "r#crate"),
    ("else", "r#else"),
    ("enum", "r#enum"),
    ("extern", "r#extern"),
    ("false", "r#false"),
    ("fn", "r#fn"),
    ("for", "r#for"),
    ("if", "r#if"),
    ("impl", "r#impl"),
    ("in", "r#in"),
    ("let", "r#let"),
    ("loop", "r#loop"),
    ("match", "r#match"),
    ("mod", "r#mod"),
    ("move", "r#move"),
    ("mut", "r#mut"),
    ("pub", "r#pub"),
    ("ref", "r#ref"),
    ("return", "r#return"),
    ("self", "r#self"),
    ("Self", "r#Self"),
    ("static", "r#static"),
    ("struct", "r#struct"),
    ("super", "r#super"),
    ("trait", "r#trait"),
    ("true", "r#true"),
    ("type", "r#type"),
    ("unsafe", "r#unsafe"),
    ("use", "r#use"),
    ("where", "r#where"),
    ("while", "r#while"),
    ("async", "r#async"),
    ("await", "r#await"),
    ("dyn", "r#dyn"),
    ("abstract", "r#abstract"),
    ("become", "r#become"),
    ("box", "r#box"),
    ("do", "r#do"),
    ("final", "r#final"),
    ("macro", "r#macro"),
    ("override", "r#override"),
    ("priv", "r#priv"),
    ("typeof", "r#typeof"),
    ("unsized", "r#unsized"),
    ("virtual", "r#virtual"),
];
