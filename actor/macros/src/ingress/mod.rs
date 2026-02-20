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

fn collect_readonly_ingress_usage(items: &[Item], names: &GenericParamNames) -> GenericUsage {
    let mut usage = GenericUsage::default();
    for item in items {
        if let ItemKind::Ask {
            response,
            read_write: false,
        } = &item.kind
        {
            usage.merge(collect_usage_from_fields(&item.fields, names));
            usage.merge(collect_usage_from_type(response, names));
        }
    }
    usage
}

fn collect_read_write_ingress_usage(items: &[Item], names: &GenericParamNames) -> GenericUsage {
    let mut usage = GenericUsage::default();
    for item in items {
        match &item.kind {
            ItemKind::Tell => {
                usage.merge(collect_usage_from_fields(&item.fields, names));
            }
            ItemKind::Ask {
                response,
                read_write: true,
            }
            | ItemKind::Subscribe { response } => {
                usage.merge(collect_usage_from_fields(&item.fields, names));
                usage.merge(collect_usage_from_type(response, names));
            }
            ItemKind::Ask {
                read_write: false, ..
            } => {}
        }
    }
    usage
}

fn has_unused_generics(generics: &Generics, usage: &GenericUsage) -> bool {
    generics.params.iter().any(|param| match param {
        GenericParam::Type(param) => !usage.type_params.contains(&param.ident.to_string()),
        GenericParam::Lifetime(param) => !usage
            .lifetime_params
            .contains(&param.lifetime.ident.to_string()),
        GenericParam::Const(param) => !usage.const_params.contains(&param.ident.to_string()),
    })
}

fn phantom_variant_for_unused_generics(generics: &Generics, usage: &GenericUsage) -> TokenStream2 {
    if generics.params.is_empty() || !has_unused_generics(generics, usage) {
        return quote!();
    }

    let phantom_args: Vec<_> = generics
        .params
        .iter()
        .map(|p| match p {
            GenericParam::Type(tp) => {
                let ident = &tp.ident;
                quote!(#ident)
            }
            GenericParam::Lifetime(lp) => {
                let lt = &lp.lifetime;
                quote!(&#lt ())
            }
            GenericParam::Const(param) => {
                let ident = &param.ident;
                quote!([(); #ident])
            }
        })
        .collect();
    quote! {
        #[doc(hidden)]
        _Phantom(::core::marker::PhantomData<(#(#phantom_args),*)>),
    }
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

fn emit_readonly_variant(item: &Item, actor: &TokenStream2) -> Option<TokenStream2> {
    let ItemKind::Ask {
        response,
        read_write: false,
    } = &item.kind
    else {
        return None;
    };

    let attrs = &item.attrs;
    let name = &item.name;
    let entries = variant_fields(&item.fields);

    Some(quote! {
        #(#attrs)*
        #name {
            #(#entries)*
            response: #actor::oneshot::Sender<#response>,
        },
    })
}

fn emit_read_write_variant(item: &Item, actor: &TokenStream2) -> Option<TokenStream2> {
    let attrs = &item.attrs;
    let name = &item.name;
    let entries = variant_fields(&item.fields);

    Some(match &item.kind {
        ItemKind::Tell if item.is_unit() => quote! {
            #(#attrs)*
            #name,
        },
        ItemKind::Tell => quote! {
            #(#attrs)*
            #name { #(#entries)* },
        },
        ItemKind::Ask {
            response,
            read_write: true,
        }
        | ItemKind::Subscribe { response } => quote! {
            #(#attrs)*
            #name {
                #(#entries)*
                response: #actor::oneshot::Sender<#response>,
            },
        },
        ItemKind::Ask {
            read_write: false, ..
        } => return None,
    })
}

struct WrapperEmitCtx<'a> {
    actor: &'a TokenStream2,
    ingress: &'a Ident,
    readonly_ingress: &'a Ident,
    read_write_ingress: &'a Ident,
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
    let readonly_ingress = ctx.readonly_ingress;
    let read_write_ingress = ctx.read_write_ingress;
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
                            #ingress::ReadWrite(#read_write_ingress::#name)
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
                            #ingress::ReadWrite(#read_write_ingress::#name { #(#assign_fields)* })
                        }
                    }
                }
            }
        }
        ItemKind::Ask {
            response,
            read_write,
        } => {
            let usage = collect_usage_from_fields(&item.fields, ctx.names);
            let (wrapper_generics_decl, wrapper_generics_args) =
                wrapper_generics_tokens(ctx.generics, &usage);

            if item.is_unit() {
                let constructor = if *read_write {
                    quote!(#ingress::ReadWrite(#read_write_ingress::#name { response }))
                } else {
                    quote!(#ingress::ReadOnly(#readonly_ingress::#name { response }))
                };
                quote! {
                    #(#attrs)*
                    pub(crate) struct #name;

                    impl #impl_generics #actor::Ask<#ingress #ty_generics> for #name #where_clause {
                        type Response = #response;

                        fn into_ingress(
                            self,
                            response: #actor::oneshot::Sender<Self::Response>,
                        ) -> #ingress #ty_generics {
                            #constructor
                        }
                    }
                }
            } else {
                let struct_fields = wrapper_fields(&item.fields);
                let assign_fields = field_assignments(&item.fields);
                let constructor = if *read_write {
                    quote!(#ingress::ReadWrite(#read_write_ingress::#name {
                        #(#assign_fields)*
                        response,
                    }))
                } else {
                    quote!(#ingress::ReadOnly(#readonly_ingress::#name {
                        #(#assign_fields)*
                        response,
                    }))
                };
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
                            #constructor
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
                        #ingress::ReadWrite(#read_write_ingress::#name {
                            #(#assign_fields)*
                            response: self.response,
                        })
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
/// - `pub subscribe` produces:
///   - `method` (lossy enqueue, returns `oneshot::Receiver<Response>`)
///   - `try_method` (delivery-checked, returns `Result<oneshot::Receiver<Response>, MailboxError>`)
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
            pub fn #method(&self) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.tell(#unit_constructor)
            }

            #(#attrs)*
            pub fn #lossy_method(&self) -> bool {
                self.0.tell_lossy(#unit_constructor)
            }
        },
        (ItemKind::Tell, MailboxKind::Unbounded, false) => quote! {
            #(#attrs)*
            pub fn #method(&self, #(#args),*) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.tell(#variant { #(#values),* })
            }

            #(#attrs)*
            pub fn #lossy_method(&self, #(#args),*) -> bool {
                self.0.tell_lossy(#variant { #(#values),* })
            }
        },
        (ItemKind::Tell, MailboxKind::Bounded, true) => quote! {
            #(#attrs)*
            pub async fn #method(&self) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.tell(#unit_constructor).await
            }

            #(#attrs)*
            pub fn #lossy_method(&self) -> bool {
                self.0.tell_lossy(#unit_constructor)
            }

            #(#attrs)*
            pub fn #try_method(&self) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.try_tell(#unit_constructor)
            }
        },
        (ItemKind::Tell, MailboxKind::Bounded, false) => quote! {
            #(#attrs)*
            pub async fn #method(&self, #(#args),*) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.tell(#variant { #(#values),* }).await
            }

            #(#attrs)*
            pub fn #lossy_method(&self, #(#args),*) -> bool {
                self.0.tell_lossy(#variant { #(#values),* })
            }

            #(#attrs)*
            pub fn #try_method(&self, #(#args),*) -> Result<(), #actor::mailbox::MailboxError> {
                self.0.try_tell(#variant { #(#values),* })
            }
        },
        (ItemKind::Ask { response, .. }, _, true) => quote! {
            #(#attrs)*
            pub async fn #method(&self) -> Result<#response, #actor::mailbox::MailboxError> {
                self.0.ask(#unit_constructor).await
            }

            /// Like [`Self::#method`] but races the response against `timeout`.
            pub async fn #timeout_method<__Timeout>(
                &self,
                timeout: __Timeout,
            ) -> Result<#response, #actor::mailbox::MailboxError>
            where
                __Timeout: ::core::future::Future<Output = ()>,
            {
                self.0.ask_timeout(#unit_constructor, timeout).await
            }
        },
        (ItemKind::Ask { response, .. }, _, false) => quote! {
            #(#attrs)*
            pub async fn #method(&self, #(#args),*) -> Result<#response, #actor::mailbox::MailboxError> {
                self.0.ask(#variant { #(#values),* }).await
            }

            /// Like [`Self::#method`] but races the response against `timeout`.
            pub async fn #timeout_method<__Timeout>(
                &self,
                #(#args,)*
                timeout: __Timeout,
            ) -> Result<#response, #actor::mailbox::MailboxError>
            where
                __Timeout: ::core::future::Future<Output = ()>,
            {
                self.0.ask_timeout(#variant { #(#values),* }, timeout).await
            }
        },
        (ItemKind::Subscribe { response }, MailboxKind::Bounded, true) => quote! {
            #(#attrs)*
            pub fn #method(&self) -> #actor::oneshot::Receiver<#response> {
                let (tx, rx) = #actor::oneshot::channel();
                let _ = self.0.try_tell(#variant { response: tx });
                rx
            }

            #(#attrs)*
            pub fn #try_method(&self) -> Result<#actor::oneshot::Receiver<#response>, #actor::mailbox::MailboxError> {
                let (tx, rx) = #actor::oneshot::channel();
                self.0.try_tell(#variant { response: tx })?;
                Ok(rx)
            }
        },
        (ItemKind::Subscribe { response }, MailboxKind::Bounded, false) => quote! {
            #(#attrs)*
            pub fn #method(&self, #(#args),*) -> #actor::oneshot::Receiver<#response> {
                let (tx, rx) = #actor::oneshot::channel();
                let _ = self.0.try_tell(#variant { #(#values,)* response: tx });
                rx
            }

            #(#attrs)*
            pub fn #try_method(&self, #(#args),*) -> Result<#actor::oneshot::Receiver<#response>, #actor::mailbox::MailboxError> {
                let (tx, rx) = #actor::oneshot::channel();
                self.0.try_tell(#variant { #(#values,)* response: tx })?;
                Ok(rx)
            }
        },
        (ItemKind::Subscribe { response }, MailboxKind::Unbounded, true) => quote! {
            #(#attrs)*
            pub fn #method(&self) -> #actor::oneshot::Receiver<#response> {
                let (tx, rx) = #actor::oneshot::channel();
                self.0.tell_lossy(#variant { response: tx });
                rx
            }

            #(#attrs)*
            pub fn #try_method(&self) -> Result<#actor::oneshot::Receiver<#response>, #actor::mailbox::MailboxError> {
                let (tx, rx) = #actor::oneshot::channel();
                self.0.tell(#variant { response: tx })?;
                Ok(rx)
            }
        },
        (ItemKind::Subscribe { response }, MailboxKind::Unbounded, false) => quote! {
            #(#attrs)*
            pub fn #method(&self, #(#args),*) -> #actor::oneshot::Receiver<#response> {
                let (tx, rx) = #actor::oneshot::channel();
                self.0.tell_lossy(#variant { #(#values,)* response: tx });
                rx
            }

            #(#attrs)*
            pub fn #try_method(&self, #(#args),*) -> Result<#actor::oneshot::Receiver<#response>, #actor::mailbox::MailboxError> {
                let (tx, rx) = #actor::oneshot::channel();
                self.0.tell(#variant { #(#values,)* response: tx })?;
                Ok(rx)
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
    let readonly_ingress = format_ident!("{}ReadOnlyMessage", mailbox);
    let read_write_ingress = format_ident!("{}ReadWriteMessage", mailbox);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let names = GenericParamNames::from_generics(&generics);

    let readonly_variants: Vec<_> = items
        .iter()
        .filter_map(|item| emit_readonly_variant(item, &actor))
        .collect();
    let read_write_variants: Vec<_> = items
        .iter()
        .filter_map(|item| emit_read_write_variant(item, &actor))
        .collect();
    let wrappers = items.iter().map(|item| {
        let ctx = WrapperEmitCtx {
            actor: &actor,
            ingress: &ingress,
            readonly_ingress: &readonly_ingress,
            read_write_ingress: &read_write_ingress,
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

    let readonly_usage = collect_readonly_ingress_usage(&items, &names);
    let read_write_usage = collect_read_write_ingress_usage(&items, &names);
    let readonly_phantom = phantom_variant_for_unused_generics(&generics, &readonly_usage);
    let read_write_phantom = phantom_variant_for_unused_generics(&generics, &read_write_usage);

    quote! {
        pub enum #readonly_ingress #generics #where_clause {
            #(#readonly_variants)*
            #readonly_phantom
        }

        pub enum #read_write_ingress #generics #where_clause {
            #(#read_write_variants)*
            #read_write_phantom
        }

        pub enum #ingress #generics #where_clause {
            ReadOnly(#readonly_ingress #ty_generics),
            ReadWrite(#read_write_ingress #ty_generics),
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

        impl #impl_generics #actor::IntoIngressEnvelope for #ingress #ty_generics #where_clause {
            type ReadOnlyIngress = #readonly_ingress #ty_generics;
            type ReadWriteIngress = #read_write_ingress #ty_generics;

            fn into_ingress_envelope(self) -> #actor::IngressEnvelope<Self::ReadOnlyIngress, Self::ReadWriteIngress> {
                match self {
                    Self::ReadOnly(message) => #actor::IngressEnvelope::ReadOnly(message),
                    Self::ReadWrite(message) => #actor::IngressEnvelope::ReadWrite(message),
                }
            }
        }

        #(#wrappers)*
    }
    .into()
}
