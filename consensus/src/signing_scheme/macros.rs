/// Macro to generate the `Scheme` trait implementation for a raw signing scheme wrapper.
///
/// This macro generates all the boilerplate for implementing the `Scheme` trait by
/// dispatching to a raw scheme implementation. Each concrete scheme must manually define:
/// - Its struct and fields
/// - Constructors (`new`, `verifier`)
/// - `SeededScheme` implementation
///
/// The macro takes care of:
/// - Implementing all `Scheme` trait methods
/// - Extracting namespace/message from Context
/// - Dispatching to the raw scheme methods
///
/// # Parameters
/// - `$ty`: The wrapper type (e.g., `Scheme` or `Scheme<P, V>`)
/// - `$context`: Context type expression (e.g., `VoteContext<'a, D>` or `&'a Item<D>`)
/// - `$pk`: PublicKey associated type
/// - `$sig`: Signature associated type
/// - `$cert`: Certificate associated type
/// - `$raw`: Field name to access the raw scheme (e.g., `raw`)
/// - `$participants`: Field path to get participants (e.g., `raw.participants` or `participants`)
/// - `is_attributable`: Optional override for is_attributable (defaults to true)
/// - `codec_config`: Optional override for certificate_codec_config
#[macro_export]
macro_rules! impl_scheme_trait {
    (
        impl$([$($generics:tt)*])? Scheme for $ty:ty
        $(where [ $($bounds:tt)+ ])?
        {
            Context<'a, D> = [ $($context:tt)+ ],
            PublicKey = $pk:ty,
            Signature = $sig:ty,
            Certificate = $cert:ty,
            raw = $raw:ident,
            participants = $($participants:tt).+,
            $(is_attributable = $is_attributable:expr,)?
            $(codec_config = $codec_config:expr,)?
            $(codec_config_unbounded = $codec_config_unbounded:expr,)?
        }
    ) => {
        impl$(<$($generics)*>)? $crate::signing_scheme::Scheme for $ty
        $(where
            $($bounds)+)?
        {
            type Context<'a, D: commonware_cryptography::Digest> = $($context)+;
            type PublicKey = $pk;
            type Signature = $sig;
            type Certificate = $cert;

            fn me(&self) -> Option<u32> {
                self.$raw.me()
            }

            fn participants(&self) -> &commonware_utils::set::Ordered<Self::PublicKey> {
                &self.$($participants).+
            }

            fn sign_vote<D: commonware_cryptography::Digest>(
                &self,
                namespace: &[u8],
                context: Self::Context<'_, D>,
            ) -> Option<$crate::signing_scheme::Vote<Self>> {
                use $crate::signing_scheme::Context as _;
                let (namespace, message) = context.namespace_and_message(namespace);
                let (signer, signature) = self.$raw.sign_vote(namespace.as_ref(), message.as_ref())?;
                Some($crate::signing_scheme::Vote { signer, signature })
            }

            fn verify_vote<D: commonware_cryptography::Digest>(
                &self,
                namespace: &[u8],
                context: Self::Context<'_, D>,
                vote: &$crate::signing_scheme::Vote<Self>,
            ) -> bool {
                use $crate::signing_scheme::Context as _;
                let (namespace, message) = context.namespace_and_message(namespace);
                self.$raw.verify_vote(namespace.as_ref(), message.as_ref(), vote.signer, &vote.signature)
            }

            fn verify_votes<R, D, I>(
                &self,
                rng: &mut R,
                namespace: &[u8],
                context: Self::Context<'_, D>,
                votes: I,
            ) -> $crate::signing_scheme::VoteVerification<Self>
            where
                R: rand::Rng + rand::CryptoRng,
                D: commonware_cryptography::Digest,
                I: IntoIterator<Item = $crate::signing_scheme::Vote<Self>>,
            {
                use $crate::signing_scheme::Context as _;
                let (namespace, message) = context.namespace_and_message(namespace);

                let votes_raw = votes
                    .into_iter()
                    .map(|vote| (vote.signer, vote.signature))
                    .collect::<Vec<_>>();

                let (verified_raw, invalid) = self.$raw.verify_votes(
                    rng,
                    namespace.as_ref(),
                    message.as_ref(),
                    votes_raw,
                );

                let verified = verified_raw
                    .into_iter()
                    .map(|(signer, signature)| $crate::signing_scheme::Vote { signer, signature })
                    .collect();

                $crate::signing_scheme::VoteVerification::new(verified, invalid)
            }

            fn assemble_certificate<I>(&self, votes: I) -> Option<Self::Certificate>
            where
                I: IntoIterator<Item = $crate::signing_scheme::Vote<Self>>,
            {
                let votes_raw = votes
                    .into_iter()
                    .map(|vote| (vote.signer, vote.signature));
                self.$raw.assemble_certificate(votes_raw)
            }

            fn verify_certificate<R: rand::Rng + rand::CryptoRng, D: commonware_cryptography::Digest>(
                &self,
                rng: &mut R,
                namespace: &[u8],
                context: Self::Context<'_, D>,
                certificate: &Self::Certificate,
            ) -> bool {
                use $crate::signing_scheme::Context as _;
                let (namespace, message) = context.namespace_and_message(namespace);
                self.$raw.verify_certificate(
                    rng,
                    namespace.as_ref(),
                    message.as_ref(),
                    certificate,
                )
            }

            fn verify_certificates<'a, R, D, I>(
                &self,
                rng: &mut R,
                namespace: &[u8],
                certificates: I,
            ) -> bool
            where
                R: rand::Rng + rand::CryptoRng,
                D: commonware_cryptography::Digest,
                I: Iterator<Item = (Self::Context<'a, D>, &'a Self::Certificate)>,
            {
                use $crate::signing_scheme::Context as _;
                let certificates_raw = certificates.map(|(context, cert)| {
                    let (ns, msg) = context.namespace_and_message(namespace);
                    (ns, msg, cert)
                });

                let certificates_collected: Vec<_> = certificates_raw
                    .map(|(ns, msg, cert)| (ns, msg, cert))
                    .collect();

                self.$raw.verify_certificates(
                    rng,
                    certificates_collected
                        .iter()
                        .map(|(ns, msg, cert)| (ns.as_ref(), msg.as_ref(), *cert)),
                )
            }

            fn is_attributable(&self) -> bool {
                $crate::impl_scheme_trait!(@is_attributable $($is_attributable)?)
            }

            fn certificate_codec_config(&self) -> <Self::Certificate as commonware_codec::Read>::Cfg {
                $crate::impl_scheme_trait!(@codec_config self, $($codec_config)?)
            }

            fn certificate_codec_config_unbounded() -> <Self::Certificate as commonware_codec::Read>::Cfg {
                $crate::impl_scheme_trait!(@codec_config_unbounded $($codec_config_unbounded)?)
            }
        }
    };

    // Helper rules for defaults
    (@is_attributable) => { true };
    (@is_attributable $val:expr) => { $val };

    (@codec_config $self:ident,) => { $self.participants().len() };
    (@codec_config $self:ident, $val:expr) => { $val };

    (@codec_config_unbounded) => { u32::MAX as usize };
    (@codec_config_unbounded $val:expr) => { $val };
}
