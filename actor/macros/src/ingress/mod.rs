use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{format_ident, quote};
use std::collections::BTreeSet;
use syn::{parse_macro_input, visit::Visit, GenericParam, Generics, Ident, Result, Type};

mod parsing;
use parsing::{Field, IngressInput, Item, ItemKind, MailboxKind};

#[derive(Default)]
struct GenericUsage {
    type_params: BTreeSet<String>,
    lifetime_params: BTreeSet<String>,
    const_params: BTreeSet<String>,
}

impl GenericUsage {
    fn merge(&mut self, other: Self) {
        self.type_params.extend(other.type_params);
        self.lifetime_params.extend(other.lifetime_params);
        self.const_params.extend(other.const_params);
    }
}

struct GenericParamNames {
    type_params: BTreeSet<String>,
    lifetime_params: BTreeSet<String>,
    const_params: BTreeSet<String>,
}

impl GenericParamNames {
    fn from_generics(generics: &Generics) -> Self {
        let mut type_params = BTreeSet::new();
        let mut lifetime_params = BTreeSet::new();
        let mut const_params = BTreeSet::new();

        for param in &generics.params {
            match param {
                GenericParam::Type(param) => {
                    type_params.insert(param.ident.to_string());
                }
                GenericParam::Lifetime(param) => {
                    lifetime_params.insert(param.lifetime.ident.to_string());
                }
                GenericParam::Const(param) => {
                    const_params.insert(param.ident.to_string());
                }
            }
        }

        Self {
            type_params,
            lifetime_params,
            const_params,
        }
    }
}

struct TypeGenericUseCollector<'a> {
    names: &'a GenericParamNames,
    usage: GenericUsage,
}

impl<'a> TypeGenericUseCollector<'a> {
    fn new(names: &'a GenericParamNames) -> Self {
        Self {
            names,
            usage: GenericUsage::default(),
        }
    }
}

impl Visit<'_> for TypeGenericUseCollector<'_> {
    fn visit_type_path(&mut self, node: &syn::TypePath) {
        if node.qself.is_none() && !node.path.segments.is_empty() {
            let ident = node.path.segments[0].ident.to_string();
            if self.names.type_params.contains(&ident) {
                self.usage.type_params.insert(ident);
            }
        }

        syn::visit::visit_type_path(self, node);
    }

    fn visit_lifetime(&mut self, node: &syn::Lifetime) {
        let ident = node.ident.to_string();
        if self.names.lifetime_params.contains(&ident) {
            self.usage.lifetime_params.insert(ident);
        }

        syn::visit::visit_lifetime(self, node);
    }

    fn visit_expr_path(&mut self, node: &syn::ExprPath) {
        if node.qself.is_none() && node.path.segments.len() == 1 {
            let ident = node.path.segments[0].ident.to_string();
            if self.names.const_params.contains(&ident) {
                self.usage.const_params.insert(ident);
            }
        }

        syn::visit::visit_expr_path(self, node);
    }
}

fn actor_path() -> Result<TokenStream2> {
    match crate_name("commonware-actor") {
        Ok(FoundCrate::Itself) => Ok(quote!(::commonware_actor)),
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name.replace('-', "_"), Span::call_site());
            Ok(quote!(::#ident))
        }
        Err(err) => Err(syn::Error::new(
            Span::call_site(),
            format!("unable to locate commonware-actor crate: {err}"),
        )),
    }
}

fn collect_usage_from_type(ty: &Type, names: &GenericParamNames) -> GenericUsage {
    let mut visitor = TypeGenericUseCollector::new(names);
    visitor.visit_type(ty);
    visitor.usage
}

fn collect_usage_from_fields(fields: &[Field], names: &GenericParamNames) -> GenericUsage {
    let mut usage = GenericUsage::default();
    for field in fields {
        usage.merge(collect_usage_from_type(&field.ty, names));
    }
    usage
}

fn collect_usage_for_items(items: &[Item], names: &GenericParamNames) -> GenericUsage {
    let mut usage = GenericUsage::default();
    for item in items {
        usage.merge(collect_usage_from_fields(&item.fields, names));
        if let Some(response) = item.kind.response() {
            usage.merge(collect_usage_from_type(response, names));
        }
    }
    usage
}

fn ensure_mailbox_generics_are_used(
    generics: &Generics,
    usage: &GenericUsage,
    mailbox: &Ident,
) -> Result<()> {
    let mut error: Option<syn::Error> = None;

    for param in &generics.params {
        let (used, span, render) = match param {
            GenericParam::Type(param) => (
                usage.type_params.contains(&param.ident.to_string()),
                param.ident.span(),
                param.ident.to_string(),
            ),
            GenericParam::Lifetime(param) => (
                usage
                    .lifetime_params
                    .contains(&param.lifetime.ident.to_string()),
                param.lifetime.span(),
                format!("'{}", param.lifetime.ident),
            ),
            GenericParam::Const(param) => (
                usage.const_params.contains(&param.ident.to_string()),
                param.ident.span(),
                param.ident.to_string(),
            ),
        };

        if !used {
            let next = syn::Error::new(
                span,
                format!(
                    "mailbox generic `{render}` is unused by ingress fields/responses in `{mailbox}`"
                ),
            );
            match &mut error {
                Some(err) => err.combine(next),
                None => error = Some(next),
            }
        }
    }

    if let Some(err) = error {
        return Err(err);
    }

    Ok(())
}

fn wrapper_generics_tokens(
    generics: &Generics,
    usage: &GenericUsage,
) -> (TokenStream2, TokenStream2) {
    let mut decl_params = Vec::new();
    let mut arg_params = Vec::new();

    for param in &generics.params {
        match param {
            GenericParam::Type(param) if usage.type_params.contains(&param.ident.to_string()) => {
                let ident = &param.ident;
                let bounds = &param.bounds;
                if bounds.is_empty() {
                    decl_params.push(quote!(#ident));
                } else {
                    decl_params.push(quote!(#ident: #bounds));
                }
                arg_params.push(quote!(#ident));
            }
            GenericParam::Lifetime(param)
                if usage
                    .lifetime_params
                    .contains(&param.lifetime.ident.to_string()) =>
            {
                let lifetime = &param.lifetime;
                decl_params.push(quote!(#lifetime));
                arg_params.push(quote!(#lifetime));
            }
            GenericParam::Const(param) if usage.const_params.contains(&param.ident.to_string()) => {
                let ident = &param.ident;
                let ty = &param.ty;
                decl_params.push(quote!(const #ident: #ty));
                arg_params.push(quote!(#ident));
            }
            _ => {}
        }
    }

    if decl_params.is_empty() {
        (quote!(), quote!())
    } else {
        (quote!(<#(#decl_params),*>), quote!(<#(#arg_params),*>))
    }
}

fn to_snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    let chars: Vec<char> = name.chars().collect();

    for i in 0..chars.len() {
        let c = chars[i];
        if c.is_uppercase() {
            let prev = i > 0 && (chars[i - 1].is_lowercase() || chars[i - 1].is_ascii_digit());
            let next = i + 1 < chars.len() && chars[i + 1].is_lowercase();
            let prev_underscore = i > 0 && chars[i - 1] == '_';
            if i > 0 && !prev_underscore && (prev || next) {
                out.push('_');
            }
            for lower in c.to_lowercase() {
                out.push(lower);
            }
        } else {
            out.push(c);
        }
    }

    out
}

fn variant_fields(fields: &[Field]) -> Vec<TokenStream2> {
    fields
        .iter()
        .map(|field| {
            let attrs = &field.attrs;
            let name = &field.name;
            let ty = &field.ty;
            quote! {
                #(#attrs)*
                #name: #ty,
            }
        })
        .collect()
}

fn wrapper_fields(fields: &[Field]) -> Vec<TokenStream2> {
    fields
        .iter()
        .map(|field| {
            let attrs = &field.attrs;
            let name = &field.name;
            let ty = &field.ty;
            quote! {
                #(#attrs)*
                pub #name: #ty,
            }
        })
        .collect()
}

fn field_assignments(fields: &[Field]) -> Vec<TokenStream2> {
    fields
        .iter()
        .map(|field| {
            let name = &field.name;
            quote!(#name: self.#name,)
        })
        .collect()
}

fn method_args(fields: &[Field]) -> Vec<TokenStream2> {
    fields
        .iter()
        .map(|field| {
            let name = &field.name;
            let ty = &field.ty;
            quote!(#name: #ty)
        })
        .collect()
}

fn method_values(fields: &[Field]) -> Vec<TokenStream2> {
    fields
        .iter()
        .map(|field| {
            let name = &field.name;
            quote!(#name)
        })
        .collect()
}

/// Emit a single ingress enum variant.
///
/// Tell items become either unit or struct variants.
/// Ask items always add an implicit `response` field.
fn emit_variant(item: &Item, actor: &TokenStream2) -> TokenStream2 {
    let attrs = &item.attrs;
    let name = &item.name;
    let entries = variant_fields(&item.fields);

    match item.kind.response() {
        None if item.is_unit() => quote! {
            #(#attrs)*
            #name,
        },
        None => quote! {
            #(#attrs)*
            #name { #(#entries)* },
        },
        Some(response) => quote! {
            #(#attrs)*
            #name {
                #(#entries)*
                response: #actor::oneshot::Sender<#response>,
            },
        },
    }
}

struct WrapperEmitCtx<'a> {
    actor: &'a TokenStream2,
    ingress: &'a Ident,
    impl_generics: TokenStream2,
    ty_generics: TokenStream2,
    where_clause: Option<&'a syn::WhereClause>,
    generics: &'a Generics,
    names: &'a GenericParamNames,
}

/// Emit one wrapper type and its `Tell`/`Ask` implementation.
///
/// Wrapper generics are reduced to only those actually referenced by wrapper fields.
///
/// Subscribe items include the `response` sender as a regular struct field and
/// implement `Tell` rather than `Ask`.
fn emit_wrapper(item: &Item, ctx: &WrapperEmitCtx<'_>) -> TokenStream2 {
    let actor = ctx.actor;
    let ingress = ctx.ingress;
    let impl_generics = &ctx.impl_generics;
    let ty_generics = &ctx.ty_generics;
    let where_clause = ctx.where_clause;

    let attrs = &item.attrs;
    let name = &item.name;

    match &item.kind {
        ItemKind::Tell => {
            let usage = collect_usage_from_fields(&item.fields, ctx.names);
            let (wrapper_generics_decl, wrapper_generics_args) =
                wrapper_generics_tokens(ctx.generics, &usage);

            if item.is_unit() {
                quote! {
                    #(#attrs)*
                    pub(crate) struct #name;

                    impl #impl_generics #actor::Tell<#ingress #ty_generics> for #name #where_clause {
                        fn into_ingress(self) -> #ingress #ty_generics {
                            #ingress::#name
                        }
                    }
                }
            } else {
                let struct_fields = wrapper_fields(&item.fields);
                let assign_fields = field_assignments(&item.fields);
                quote! {
                    #(#attrs)*
                    pub(crate) struct #name #wrapper_generics_decl #where_clause {
                        #(#struct_fields)*
                    }

                    impl #impl_generics #actor::Tell<#ingress #ty_generics> for #name #wrapper_generics_args #where_clause {
                        fn into_ingress(self) -> #ingress #ty_generics {
                            #ingress::#name { #(#assign_fields)* }
                        }
                    }
                }
            }
        }
        ItemKind::Ask { response } => {
            let usage = collect_usage_from_fields(&item.fields, ctx.names);
            let (wrapper_generics_decl, wrapper_generics_args) =
                wrapper_generics_tokens(ctx.generics, &usage);

            if item.is_unit() {
                quote! {
                    #(#attrs)*
                    pub(crate) struct #name;

                    impl #impl_generics #actor::Ask<#ingress #ty_generics> for #name #where_clause {
                        type Response = #response;

                        fn into_ingress(
                            self,
                            response: #actor::oneshot::Sender<Self::Response>,
                        ) -> #ingress #ty_generics {
                            #ingress::#name { response }
                        }
                    }
                }
            } else {
                let struct_fields = wrapper_fields(&item.fields);
                let assign_fields = field_assignments(&item.fields);
                quote! {
                    #(#attrs)*
                    pub(crate) struct #name #wrapper_generics_decl #where_clause {
                        #(#struct_fields)*
                    }

                    impl #impl_generics #actor::Ask<#ingress #ty_generics> for #name #wrapper_generics_args #where_clause {
                        type Response = #response;

                        fn into_ingress(
                            self,
                            response: #actor::oneshot::Sender<Self::Response>,
                        ) -> #ingress #ty_generics {
                            #ingress::#name {
                                #(#assign_fields)*
                                response,
                            }
                        }
                    }
                }
            }
        }
        ItemKind::Subscribe { response } => {
            // Subscribe wrappers include the response sender as a struct field
            // and implement Tell (not Ask). The generated mailbox method creates
            // the oneshot and passes the sender through.
            let mut usage = collect_usage_from_fields(&item.fields, ctx.names);
            usage.merge(collect_usage_from_type(response, ctx.names));
            let (wrapper_generics_decl, wrapper_generics_args) =
                wrapper_generics_tokens(ctx.generics, &usage);

            let struct_fields = wrapper_fields(&item.fields);
            let assign_fields = field_assignments(&item.fields);
            quote! {
                #(#attrs)*
                pub(crate) struct #name #wrapper_generics_decl #where_clause {
                    #(#struct_fields)*
                    pub response: #actor::oneshot::Sender<#response>,
                }

                impl #impl_generics #actor::Tell<#ingress #ty_generics> for #name #wrapper_generics_args #where_clause {
                    fn into_ingress(self) -> #ingress #ty_generics {
                        #ingress::#name {
                            #(#assign_fields)*
                            response: self.response,
                        }
                    }
                }
            }
        }
    }
}

/// Emit one generated mailbox convenience method set.
///
/// - `pub tell` produces `method`, `method_lossy`, and `try_method` (bounded only)
/// - `pub ask` produces `method` and `method_timeout`
/// - `pub subscribe` produces `method` returning `oneshot::Receiver<Response>`
/// - `unbounded` tell methods are synchronous
fn emit_mailbox_method(
    item: &Item,
    actor: &TokenStream2,
    mailbox_kind: MailboxKind,
    has_wrapper_generics: bool,
) -> TokenStream2 {
    let attrs = &item.attrs;
    let variant = &item.name;
    let method = format_ident!("{}", to_snake_case(&variant.to_string()));
    let lossy_method = format_ident!("{}_lossy", method);
    let try_method = format_ident!("try_{}", method);
    let timeout_method = format_ident!("{}_timeout", method);
    let args = method_args(&item.fields);
    let values = method_values(&item.fields);

    // Unit wrappers that carry PhantomData need braced construction.
    let unit_constructor = if item.is_unit() && has_wrapper_generics {
        quote!(#variant { _phantom: ::core::marker::PhantomData })
    } else if item.is_unit() {
        quote!(#variant)
    } else {
        // Not used for non-unit items.
        quote!()
    };

    match (&item.kind, mailbox_kind, item.is_unit()) {
        (ItemKind::Tell, MailboxKind::Unbounded, true) => quote! {
            #(#attrs)*
            pub fn #method(&mut self) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.tell(#unit_constructor)
            }

            #(#attrs)*
            pub fn #lossy_method(&mut self) -> bool {
                self.0.tell_lossy(#unit_constructor)
            }
        },
        (ItemKind::Tell, MailboxKind::Unbounded, false) => quote! {
            #(#attrs)*
            pub fn #method(&mut self, #(#args),*) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.tell(#variant { #(#values),* })
            }

            #(#attrs)*
            pub fn #lossy_method(&mut self, #(#args),*) -> bool {
                self.0.tell_lossy(#variant { #(#values),* })
            }
        },
        (ItemKind::Tell, MailboxKind::Bounded, true) => quote! {
            #(#attrs)*
            pub async fn #method(&mut self) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.tell(#unit_constructor).await
            }

            #(#attrs)*
            pub async fn #lossy_method(&mut self) -> bool {
                self.0.tell_lossy(#unit_constructor).await
            }

            #(#attrs)*
            pub fn #try_method(&self) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.try_tell(#unit_constructor)
            }
        },
        (ItemKind::Tell, MailboxKind::Bounded, false) => quote! {
            #(#attrs)*
            pub async fn #method(&mut self, #(#args),*) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.tell(#variant { #(#values),* }).await
            }

            #(#attrs)*
            pub async fn #lossy_method(&mut self, #(#args),*) -> bool {
                self.0.tell_lossy(#variant { #(#values),* }).await
            }

            #(#attrs)*
            pub fn #try_method(&self, #(#args),*) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.try_tell(#variant { #(#values),* })
            }
        },
        (ItemKind::Ask { response }, _, true) => quote! {
            #(#attrs)*
            pub async fn #method(&mut self) -> Result<#response, #actor::mailbox::MailboxError> {
                self.0.ask(#unit_constructor).await
            }

            /// Like [`Self::#method`] but races the response against `timeout`.
            pub async fn #timeout_method<__Timeout>(
                &mut self,
                timeout: __Timeout,
            ) -> Result<#response, #actor::mailbox::MailboxError>
            where
                __Timeout: ::core::future::Future<Output = ()> + Send,
            {
                self.0.ask_timeout(#unit_constructor, timeout).await
            }
        },
        (ItemKind::Ask { response }, _, false) => quote! {
            #(#attrs)*
            pub async fn #method(&mut self, #(#args),*) -> Result<#response, #actor::mailbox::MailboxError> {
                self.0.ask(#variant { #(#values),* }).await
            }

            /// Like [`Self::#method`] but races the response against `timeout`.
            pub async fn #timeout_method<__Timeout>(
                &mut self,
                #(#args,)*
                timeout: __Timeout,
            ) -> Result<#response, #actor::mailbox::MailboxError>
            where
                __Timeout: ::core::future::Future<Output = ()> + Send,
            {
                self.0.ask_timeout(#variant { #(#values),* }, timeout).await
            }
        },
        (ItemKind::Subscribe { response }, MailboxKind::Bounded, true) => quote! {
            #(#attrs)*
            pub async fn #method(&mut self) -> #actor::oneshot::Receiver<#response> {
                let (tx, rx) = #actor::oneshot::channel();
                self.0.tell_lossy(#variant { response: tx }).await;
                rx
            }
        },
        (ItemKind::Subscribe { response }, MailboxKind::Bounded, false) => quote! {
            #(#attrs)*
            pub async fn #method(&mut self, #(#args),*) -> #actor::oneshot::Receiver<#response> {
                let (tx, rx) = #actor::oneshot::channel();
                self.0.tell_lossy(#variant { #(#values,)* response: tx }).await;
                rx
            }
        },
        (ItemKind::Subscribe { response }, MailboxKind::Unbounded, true) => quote! {
            #(#attrs)*
            pub fn #method(&mut self) -> #actor::oneshot::Receiver<#response> {
                let (tx, rx) = #actor::oneshot::channel();
                self.0.tell_lossy(#variant { response: tx });
                rx
            }
        },
        (ItemKind::Subscribe { response }, MailboxKind::Unbounded, false) => quote! {
            #(#attrs)*
            pub fn #method(&mut self, #(#args),*) -> #actor::oneshot::Receiver<#response> {
                let (tx, rx) = #actor::oneshot::channel();
                self.0.tell_lossy(#variant { #(#values,)* response: tx });
                rx
            }
        },
    }
}

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as IngressInput);
    let actor = match actor_path() {
        Ok(path) => path,
        Err(err) => return err.to_compile_error().into(),
    };

    let IngressInput {
        mailbox_kind,
        mailbox,
        generics,
        items,
    } = input;

    let ingress = format_ident!("{}Message", mailbox);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let names = GenericParamNames::from_generics(&generics);
    let global_usage = collect_usage_for_items(&items, &names);
    if let Err(err) = ensure_mailbox_generics_are_used(&generics, &global_usage, &mailbox) {
        return err.to_compile_error().into();
    }

    let variants = items.iter().map(|item| emit_variant(item, &actor));
    let wrappers = items.iter().map(|item| {
        let ctx = WrapperEmitCtx {
            actor: &actor,
            ingress: &ingress,
            impl_generics: quote!(#impl_generics),
            ty_generics: quote!(#ty_generics),
            where_clause,
            generics: &generics,
            names: &names,
        };
        emit_wrapper(item, &ctx)
    });
    let methods = items
        .iter()
        .filter(|item| item.expose_on_mailbox)
        .map(|item| emit_mailbox_method(item, &actor, mailbox_kind, false));

    let mailbox_inner_ty = match mailbox_kind {
        MailboxKind::Bounded => quote!(#actor::mailbox::Mailbox<#ingress #ty_generics>),
        MailboxKind::Unbounded => quote!(#actor::mailbox::UnboundedMailbox<#ingress #ty_generics>),
    };

    quote! {
        pub enum #ingress #generics #where_clause {
            #(#variants)*
        }

        pub struct #mailbox #generics #where_clause (#mailbox_inner_ty);

        impl #impl_generics Clone for #mailbox #ty_generics #where_clause {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl #impl_generics ::core::fmt::Debug for #mailbox #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(stringify!(#mailbox))
            }
        }

        impl #impl_generics ::core::convert::From<#mailbox_inner_ty> for #mailbox #ty_generics #where_clause {
            fn from(inner: #mailbox_inner_ty) -> Self {
                Self(inner)
            }
        }

        impl #impl_generics #mailbox #ty_generics #where_clause {
            #(#methods)*
        }

        #(#wrappers)*
    }
    .into()
}
