use super::{
    input::SpanRecord,
    model::{
        Branch, Feedback, Field, Ingress, MailboxKind, Message, Method, MethodKind, Policy,
        PolicyMode, SpanField,
    },
};
use proc_macro2::TokenStream as TokenStream2;
use quote::{quote, ToTokens};

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

fn method_args(fields: &[Field]) -> Vec<TokenStream2> {
    fields
        .iter()
        .map(|field| {
            let attrs = &field.attrs;
            let name = &field.name;
            let ty = &field.ty;
            quote! {
                #(#attrs)*
                #name: #ty
            }
        })
        .collect()
}

fn method_values(fields: &[Field]) -> Vec<TokenStream2> {
    fields
        .iter()
        .map(|field| {
            let attrs = &field.attrs;
            let name = &field.name;
            quote! {
                #(#attrs)*
                #name,
            }
        })
        .collect()
}

fn method_call_values(fields: &[Field]) -> Vec<TokenStream2> {
    fields
        .iter()
        .map(|field| {
            let name = &field.name;
            quote!(#name,)
        })
        .collect()
}

/// Span field recordings for fields annotated with `#[span]`, referencing
/// the generated method arguments by name.
fn span_field_tokens(fields: &[SpanField]) -> Vec<TokenStream2> {
    fields
        .iter()
        .map(|field| {
            let name = &field.name;
            match field.record {
                SpanRecord::Display => quote!(#name = %#name,),
                SpanRecord::Debug => quote!(#name = ?#name,),
            }
        })
        .collect()
}

fn message_variant(message: &Message, actor: &TokenStream2) -> TokenStream2 {
    let attrs = &message.attrs;
    let name = &message.name;
    let fields = variant_fields(&message.fields);

    match &message.response {
        Some(response) => quote! {
            #(#attrs)*
            #name {
                #(#fields)*
                response: #actor::oneshot::Sender<#response>,
            },
        },
        None if message.is_unit() => quote! {
            #(#attrs)*
            #name,
        },
        None => quote! {
            #(#attrs)*
            #name { #(#fields)* },
        },
    }
}

fn response_closed_arm(message: &Message) -> TokenStream2 {
    let name = &message.name;
    match &message.response {
        Some(_) => quote!(Self::#name { response, .. } => response.is_closed(),),
        None if message.is_unit() => quote!(Self::#name => false,),
        None => quote!(Self::#name { .. } => false,),
    }
}

impl ToTokens for Branch {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        let ingress = &self.name;
        let generics = &self.generics;
        let variants: Vec<_> = self
            .messages
            .iter()
            .map(|message| message_variant(message, &self.actor))
            .collect();
        let closed_arms: Vec<_> = self.messages.iter().map(response_closed_arm).collect();
        let (impl_generics, ty_generics, _) = generics.split_for_impl();

        // Matching a reference to an uninhabited enum still requires an arm, so
        // an empty enum matches on the dereferenced (uninhabited) place instead.
        let closed_body = if variants.is_empty() {
            quote!(match *self {})
        } else {
            quote! {
                match self {
                    #(#closed_arms)*
                }
            }
        };

        tokens.extend(quote! {
            pub enum #ingress #generics {
                #(#variants)*
            }

            impl #impl_generics #ingress #ty_generics {
                #[doc(hidden)]
                pub fn response_closed(&self) -> bool {
                    #closed_body
                }
            }
        });
    }
}

impl ToTokens for Method {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        let actor = &self.actor;
        let ingress = &self.ingress;
        let attrs = &self.attrs;
        let variant = &self.variant;
        let method = &self.name;
        let method_internal = quote::format_ident!("{}_internal", method);
        let visibility = if self.public { quote!(pub) } else { quote!() };
        let dead_code = if self.public {
            quote!()
        } else {
            quote!(#[allow(dead_code)])
        };
        let args = method_args(&self.fields);

        match &self.kind {
            MethodKind::Tell { feedback, message } => {
                let span_name = &self.span_name;
                let span_fields = span_field_tokens(&self.span_fields);
                let values = method_values(&self.fields);
                let message = if self.fields.is_empty() {
                    quote!(#message::#variant)
                } else {
                    quote!(#message::#variant { #(#values)* })
                };
                let feedback = match feedback {
                    Feedback::Reliable => quote!(#actor::Feedback),
                    Feedback::Unreliable => quote!(#actor::Unreliable<#actor::Feedback>),
                };

                tokens.extend(quote! {
                    #(#attrs)*
                    #dead_code
                    #[must_use = "caller must handle enqueue feedback"]
                    #visibility fn #method_internal(&self #(, #args)*) -> #feedback {
                        let __commonware_actor_current = #actor::tracing::Span::current();
                        let __commonware_actor_span = #actor::tracing::debug_span!(
                            parent: None::<#actor::tracing::span::Id>,
                            #span_name,
                            #(#span_fields)*
                        );
                        __commonware_actor_span.follows_from(__commonware_actor_current.id());
                        self.0.enqueue(#ingress::ReadWrite {
                            span: __commonware_actor_span,
                            message: #message,
                        })
                    }
                });
            }
            MethodKind::Request {
                feedback,
                route,
                message,
                response,
                await_response,
            } => {
                let span_name = &self.span_name;
                let span_fields = span_field_tokens(&self.span_fields);
                let values = method_values(&self.fields);
                let call_values = method_call_values(&self.fields);
                let enqueue_method = quote::format_ident!("enqueue_{}_internal", method);
                let feedback = match feedback {
                    Feedback::Reliable => quote!(#actor::Feedback),
                    Feedback::Unreliable => quote!(#actor::Unreliable<#actor::Feedback>),
                };
                let enqueue = quote! {
                    let __commonware_actor_span = #actor::tracing::debug_span!(#span_name, #(#span_fields)*);
                    let (__commonware_actor_response, __commonware_actor_receiver) =
                        #actor::oneshot::channel::<#response>();
                    let __commonware_actor_feedback = self.0.enqueue(#ingress::#route {
                        span: __commonware_actor_span,
                        message: #message::#variant {
                            #(#values)*
                            response: __commonware_actor_response,
                        },
                    });
                    (__commonware_actor_feedback, __commonware_actor_receiver)
                };

                tokens.extend(quote! {
                    #(#attrs)*
                    #dead_code
                    #[must_use = "caller must handle enqueue feedback and response receiver"]
                    #visibility fn #enqueue_method(&self #(, #args)*) -> (#feedback, #actor::oneshot::Receiver<#response>) {
                        #enqueue
                    }
                });

                if *await_response {
                    tokens.extend(quote! {
                        #(#attrs)*
                        #dead_code
                        #visibility async fn #method_internal(&self #(, #args)*) -> Result<#response, #actor::ingress::Cancelled> {
                            let (_, __commonware_actor_receiver) = self.#enqueue_method(#(#call_values)*);
                            __commonware_actor_receiver
                                .await
                                .map_err(|_| #actor::ingress::Cancelled)
                        }
                    });
                } else {
                    tokens.extend(quote! {
                        #(#attrs)*
                        #dead_code
                        #visibility fn #method_internal(&self #(, #args)*) -> #actor::oneshot::Receiver<#response> {
                            let (_, __commonware_actor_receiver) = self.#enqueue_method(#(#call_values)*);
                            __commonware_actor_receiver
                        }
                    });
                }
            }
        }
    }
}

impl ToTokens for Policy {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        let actor = &self.actor;
        let ingress = &self.names.ingress;
        let overflow = &self.names.overflow;
        let generics = &self.generics;
        let (impl_generics, ty_generics, _) = generics.split_for_impl();

        match self.mode {
            PolicyMode::Custom => {}
            PolicyMode::Reliable => {
                tokens.extend(quote! {
                    #[doc(hidden)]
                    pub struct #overflow #generics (
                        ::std::collections::VecDeque<#ingress #ty_generics>
                    );

                    impl #impl_generics ::core::default::Default for #overflow #ty_generics {
                        fn default() -> Self {
                            Self(::std::collections::VecDeque::new())
                        }
                    }

                    impl #impl_generics #actor::mailbox::Overflow<#ingress #ty_generics>
                        for #overflow #ty_generics
                    {
                        fn is_empty(&self) -> bool {
                            self.0.is_empty()
                        }

                        fn drain<__Push>(&mut self, mut push: __Push)
                        where
                            __Push: FnMut(#ingress #ty_generics) -> Option<#ingress #ty_generics>,
                        {
                            while let Some(message) = self.0.pop_front() {
                                if message.response_closed() {
                                    continue;
                                }
                                if let Some(message) = push(message) {
                                    self.0.push_front(message);
                                    break;
                                }
                            }
                        }
                    }

                    impl #impl_generics #actor::mailbox::Policy for #ingress #ty_generics {
                        type Overflow = #overflow #ty_generics;

                        fn handle(overflow: &mut Self::Overflow, message: Self) {
                            if !message.response_closed() {
                                overflow.0.push_back(message);
                            }
                        }
                    }
                });
            }
            PolicyMode::Unreliable => {
                tokens.extend(quote! {
                    #[doc(hidden)]
                    #[derive(Default)]
                    pub struct #overflow;

                    impl #impl_generics #actor::mailbox::Overflow<#ingress #ty_generics> for #overflow {
                        fn is_empty(&self) -> bool {
                            true
                        }

                        fn drain<__Push>(&mut self, _push: __Push)
                        where
                            __Push: FnMut(#ingress #ty_generics) -> Option<#ingress #ty_generics>,
                        {
                        }
                    }

                    impl #impl_generics #actor::mailbox::UnreliablePolicy for #ingress #ty_generics {
                        type Overflow = #overflow;

                        fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
                            false
                        }
                    }
                });
            }
        }
    }
}

impl ToTokens for Ingress {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        let actor = &self.actor;
        let names = &self.names;
        let mailbox = &names.mailbox;
        let ingress = &names.ingress;
        let read_only_ingress = &names.read_only_ingress;
        let read_write_ingress = &names.read_write_ingress;
        let generics = &self.generics;
        let read_only = &self.read_only;
        let read_write = &self.read_write;
        let methods = &self.methods;
        let policy = &self.policy;

        let (impl_generics, ty_generics, _) = generics.split_for_impl();
        let (_, ro_ty, _) = read_only.generics.split_for_impl();
        let (_, rw_ty, _) = read_write.generics.split_for_impl();

        let mailbox_inner_ty = match self.mailbox_kind {
            MailboxKind::Reliable => {
                quote!(#actor::ingress::Mailbox<#ingress #ty_generics>)
            }
            MailboxKind::Unreliable => {
                quote!(#actor::ingress::UnreliableMailbox<#ingress #ty_generics>)
            }
        };

        tokens.extend(quote! {
            #read_only

            #read_write

            pub enum #ingress #generics {
                ReadOnly {
                    span: #actor::tracing::Span,
                    message: #read_only_ingress #ro_ty,
                },
                ReadWrite {
                    span: #actor::tracing::Span,
                    message: #read_write_ingress #rw_ty,
                },
            }

            impl #impl_generics #ingress #ty_generics {
                #[doc(hidden)]
                pub fn response_closed(&self) -> bool {
                    match self {
                        Self::ReadOnly { message, .. } => message.response_closed(),
                        Self::ReadWrite { message, .. } => message.response_closed(),
                    }
                }
            }

            #policy

            pub struct #mailbox #generics (#mailbox_inner_ty);

            impl #impl_generics Clone for #mailbox #ty_generics {
                fn clone(&self) -> Self {
                    Self(self.0.clone())
                }
            }

            impl #impl_generics ::core::fmt::Debug for #mailbox #ty_generics {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    f.write_str(stringify!(#mailbox))
                }
            }

            impl #impl_generics ::core::convert::From<#mailbox_inner_ty> for #mailbox #ty_generics {
                fn from(inner: #mailbox_inner_ty) -> Self {
                    Self(inner)
                }
            }

            impl #impl_generics #mailbox #ty_generics {
                #(#methods)*
            }

            impl #impl_generics #actor::ingress::IntoEnvelope for #ingress #ty_generics {
                type ReadOnlyMessage = #read_only_ingress #ro_ty;
                type ReadWriteMessage = #read_write_ingress #rw_ty;

                fn into_envelope(
                    self,
                ) -> (
                    #actor::tracing::Span,
                    #actor::ingress::Envelope<Self::ReadOnlyMessage, Self::ReadWriteMessage>,
                ) {
                    match self {
                        Self::ReadOnly { span, message } => {
                            (span, #actor::ingress::Envelope::ReadOnly(message))
                        }
                        Self::ReadWrite { span, message } => {
                            (span, #actor::ingress::Envelope::ReadWrite(message))
                        }
                    }
                }
            }
        });
    }
}
