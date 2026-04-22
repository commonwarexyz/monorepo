#![deny(dead_code)]
#![deny(missing_docs)]
#![deny(unused)]
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! Derive crate for `prometheus_client`.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro_crate::{crate_name, FoundCrate};
use quote::quote;
use syn::DeriveInput;

fn encoding_path() -> TokenStream2 {
    if let Ok(found) = crate_name("commonware-runtime") {
        let metrics_crate = found_crate_path(found);
        return quote!(#metrics_crate::metrics);
    }
    if let Ok(found) = crate_name("prometheus-client") {
        let metrics_crate = found_crate_path(found);
        return quote!(#metrics_crate::encoding);
    }
    quote!(::prometheus_client::encoding)
}

fn found_crate_path(found: FoundCrate) -> TokenStream2 {
    match found {
        FoundCrate::Itself => quote!(crate),
        FoundCrate::Name(name) => {
            let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
            quote!(::#ident)
        }
    }
}

/// Derive `prometheus_client::encoding::EncodeLabelSet`.
#[proc_macro_derive(EncodeLabelSet, attributes(prometheus))]
pub fn derive_encode_label_set(input: TokenStream) -> TokenStream {
    derive_label_set_impl(input, false)
}

/// Derive `prometheus_client::encoding::EncodeLabelSet` for a struct whose fields
/// are encoded via their [`core::fmt::Display`] impl. Lets typed values (e.g. public
/// keys, hashes) be used directly as label values without wrapping them in `String`.
#[proc_macro_derive(EncodeStruct)]
pub fn derive_encode_struct(input: TokenStream) -> TokenStream {
    derive_label_set_impl(input, true)
}

fn derive_label_set_impl(input: TokenStream, display: bool) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();
    let name = &ast.ident;
    let encoding = encoding_path();

    let fields = match ast.clone().data {
        syn::Data::Struct(s) => match s.fields {
            syn::Fields::Named(syn::FieldsNamed { named, .. }) => named,
            syn::Fields::Unnamed(_) => {
                panic!("Can not derive Encode for struct with unnamed fields.")
            }
            syn::Fields::Unit => panic!("Can not derive Encode for struct with unit field."),
        },
        syn::Data::Enum(syn::DataEnum { .. }) => {
            panic!("Can not derive Encode for enum.")
        }
        syn::Data::Union(_) => panic!("Can not derive Encode for union."),
    };

    let fields_vec: Vec<_> = fields.into_iter().collect();
    let body: TokenStream2 = fields_vec
        .iter()
        .cloned()
        .map(|f| {
            let attribute = f
                .attrs
                .iter()
                .find(|a| a.path().is_ident("prometheus"))
                .map(|a| a.parse_args::<syn::Ident>().unwrap().to_string());
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

    // Emit `Borrow<F>` and `From<&F>` only for single-field `EncodeStruct` cases so
    // `Family::get_or_create_by(&f)` works without wrapping/cloning on the hit path.
    let single_field_impls = if display && fields_vec.len() == 1 {
        let f = &fields_vec[0];
        let field_ident = f.ident.as_ref().unwrap();
        let field_ty = &f.ty;
        quote! {
            impl #impl_generics ::core::borrow::Borrow<#field_ty> for #name #ty_generics #where_clause {
                fn borrow(&self) -> &#field_ty {
                    &self.#field_ident
                }
            }

            impl #impl_generics ::core::convert::From<&#field_ty> for #name #ty_generics
            where
                #field_ty: ::core::clone::Clone,
            {
                fn from(value: &#field_ty) -> Self {
                    Self { #field_ident: value.clone() }
                }
            }
        }
    } else {
        quote!()
    };

    let gen = quote! {
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
    };

    gen.into()
}

/// Derive `prometheus_client::encoding::EncodeLabelValue`.
#[proc_macro_derive(EncodeLabelValue)]
pub fn derive_encode_label_value(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();
    let name = &ast.ident;
    let encoding = encoding_path();

    let body = match ast.clone().data {
        syn::Data::Struct(_) => {
            panic!("Can not derive EncodeLabel for struct.")
        }
        syn::Data::Enum(syn::DataEnum { variants, .. }) => {
            let match_arms: TokenStream2 = variants
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

    let gen = quote! {
        impl #encoding::EncodeLabelValue for #name {
            fn encode(&self, encoder: &mut #encoding::LabelValueEncoder) -> ::core::result::Result<(), ::core::fmt::Error> {
                use ::core::fmt::Write;

                #body

                ::core::result::Result::Ok(())
            }
        }
    };

    gen.into()
}

// Copied from https://github.com/djc/askama (MIT and APACHE licensed) and
// modified.
static KEYWORD_IDENTIFIERS: [(&str, &str); 48] = [
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
    ("static", "r#static"),
    ("struct", "r#struct"),
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
    ("yield", "r#yield"),
    ("try", "r#try"),
];
