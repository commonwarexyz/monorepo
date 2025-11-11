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
/// - `$context`: Context type (e.g., `VoteContext`)
/// - `$pk`: PublicKey associated type
/// - `$sig`: Signature associated type
/// - `$cert`: Certificate associated type
/// - `$raw`: Field name to access the raw scheme (e.g., `raw`)
/// - `$participants`: Field path to get participants (e.g., `raw.participants` or `participants`)
#[macro_export]
macro_rules! impl_scheme_trait {
    (
        impl$([$($generics:tt)*])? Scheme for $ty:ty
        $(where [ $($bounds:tt)+ ])?
        {
            Context = $context:ident,
            PublicKey = $pk:ty,
            Signature = $sig:ty,
            Certificate = $cert:ty,
            raw = $raw:ident,
            participants = $($participants:tt).+,
        }
    ) => {
        impl$(<$($generics)*>)? $crate::signing_scheme::Scheme for $ty
        $(where
            $($bounds)+)?
        {
            type Context<'a, D: Digest> = $context<'a, D>;
            type PublicKey = $pk;
            type Signature = $sig;
            type Certificate = $cert;

            fn me(&self) -> Option<u32> {
                self.$raw.me()
            }

            fn participants(&self) -> &Ordered<Self::PublicKey> {
                &self.$($participants).+
            }

            fn sign_vote<D: Digest>(
                &self,
                namespace: &[u8],
                context: Self::Context<'_, D>,
            ) -> Option<Vote<Self>> {
                let (namespace, message) = context.namespace_and_message(namespace);
                let (signer, signature) = self.$raw.sign_vote(namespace.as_ref(), message.as_ref())?;
                Some(Vote { signer, signature })
            }

            fn verify_vote<D: Digest>(
                &self,
                namespace: &[u8],
                context: Self::Context<'_, D>,
                vote: &Vote<Self>,
            ) -> bool {
                let (namespace, message) = context.namespace_and_message(namespace);
                self.$raw.verify_vote(namespace.as_ref(), message.as_ref(), vote.signer, &vote.signature)
            }

            fn verify_votes<R, D, I>(
                &self,
                rng: &mut R,
                namespace: &[u8],
                context: Self::Context<'_, D>,
                votes: I,
            ) -> VoteVerification<Self>
            where
                R: Rng + CryptoRng,
                D: Digest,
                I: IntoIterator<Item = Vote<Self>>,
            {
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
                    .map(|(signer, signature)| Vote { signer, signature })
                    .collect();

                VoteVerification::new(verified, invalid)
            }

            fn assemble_certificate<I>(&self, votes: I) -> Option<Self::Certificate>
            where
                I: IntoIterator<Item = Vote<Self>>,
            {
                let votes_raw = votes
                    .into_iter()
                    .map(|vote| (vote.signer, vote.signature));
                self.$raw.assemble_certificate(votes_raw)
            }

            fn verify_certificate<R: Rng + CryptoRng, D: Digest>(
                &self,
                rng: &mut R,
                namespace: &[u8],
                context: Self::Context<'_, D>,
                certificate: &Self::Certificate,
            ) -> bool {
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
                R: Rng + CryptoRng,
                D: Digest,
                I: Iterator<Item = (Self::Context<'a, D>, &'a Self::Certificate)>,
            {
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
                true
            }

            fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {
                self.participants().len()
            }

            fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {
                u32::MAX as usize
            }
        }
    };
}
