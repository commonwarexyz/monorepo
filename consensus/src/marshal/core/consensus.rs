//! Consensus abstractions and adapters for marshal.

use crate::{simplex, Roundable};
use commonware_codec::{Codec, Read};
use commonware_cryptography::{certificate::Scheme, Committable, Digest};
use commonware_parallel::Strategy;
use commonware_utils::N3f1;
use rand_core::CryptoRngCore;
use std::marker::PhantomData;

/// A certificate extracted from consensus activity.
pub enum ConsensusCertificate<N, F> {
    /// A notarization certificate.
    Notarization(N),
    /// A finalization certificate.
    Finalization(F),
}

/// Consensus operations required by marshal.
pub trait ConsensusEngine: Clone + Send + Sync + 'static {
    /// Signing scheme used by this consensus engine.
    type Scheme: Scheme;

    /// Commitment type carried in proposals and certificates.
    type Commitment: Digest;

    /// Notarization certificate type.
    type Notarization: Clone
        + Roundable
        + Committable<Commitment = Self::Commitment>
        + Codec<Cfg = <<Self::Scheme as Scheme>::Certificate as Read>::Cfg>
        + Send
        + Sync
        + 'static;

    /// Finalization certificate type.
    type Finalization: Clone
        + Roundable
        + Committable<Commitment = Self::Commitment>
        + Codec<Cfg = <<Self::Scheme as Scheme>::Certificate as Read>::Cfg>
        + Send
        + Sync
        + 'static;

    /// Activity stream type emitted by the consensus engine.
    type Activity: Clone + Send + 'static;

    /// Extract a marshaling-relevant certificate from consensus activity.
    fn into_certificate(
        activity: Self::Activity,
    ) -> Option<ConsensusCertificate<Self::Notarization, Self::Finalization>>;

    /// Batch-verifies notarization certificates, returning a per-item result.
    ///
    /// Uses bisection to efficiently identify invalid certificates when batch
    /// verification fails. Falls back to individual verification for non-batchable schemes.
    fn verify_notarizations<'a, R: CryptoRngCore>(
        rng: &mut R,
        scheme: &Self::Scheme,
        notarizations: impl IntoIterator<Item = &'a Self::Notarization>,
        strategy: &impl Strategy,
    ) -> Vec<bool>;

    /// Batch-verifies finalization certificates, returning a per-item result.
    ///
    /// Uses bisection to efficiently identify invalid certificates when batch
    /// verification fails. Falls back to individual verification for non-batchable schemes.
    fn verify_finalizations<'a, R: CryptoRngCore>(
        rng: &mut R,
        scheme: &Self::Scheme,
        finalizations: impl IntoIterator<Item = &'a Self::Finalization>,
        strategy: &impl Strategy,
    ) -> Vec<bool>;
}

/// Simplex consensus adapter for marshal.
#[derive(Default, Clone, Copy)]
pub struct SimplexConsensus<S, D>(PhantomData<(S, D)>);

impl<S, D> ConsensusEngine for SimplexConsensus<S, D>
where
    S: Scheme + simplex::scheme::Scheme<D>,
    D: Digest,
{
    type Scheme = S;
    type Commitment = D;
    type Notarization = simplex::types::Notarization<S, D>;
    type Finalization = simplex::types::Finalization<S, D>;
    type Activity = simplex::types::Activity<S, D>;

    fn into_certificate(
        activity: Self::Activity,
    ) -> Option<ConsensusCertificate<Self::Notarization, Self::Finalization>> {
        match activity {
            simplex::types::Activity::Notarization(notarization) => {
                Some(ConsensusCertificate::Notarization(notarization))
            }
            simplex::types::Activity::Finalization(finalization) => {
                Some(ConsensusCertificate::Finalization(finalization))
            }
            _ => None,
        }
    }

    fn verify_notarizations<'a, R: CryptoRngCore>(
        rng: &mut R,
        scheme: &Self::Scheme,
        notarizations: impl IntoIterator<Item = &'a Self::Notarization>,
        strategy: &impl Strategy,
    ) -> Vec<bool> {
        let certs: Vec<_> = notarizations
            .into_iter()
            .map(|n| {
                (
                    simplex::types::Subject::Notarize {
                        proposal: &n.proposal,
                    },
                    &n.certificate,
                )
            })
            .collect();
        scheme.verify_certificates_bisect::<_, D, N3f1>(rng, &certs, strategy)
    }

    fn verify_finalizations<'a, R: CryptoRngCore>(
        rng: &mut R,
        scheme: &Self::Scheme,
        finalizations: impl IntoIterator<Item = &'a Self::Finalization>,
        strategy: &impl Strategy,
    ) -> Vec<bool> {
        let certs: Vec<_> = finalizations
            .into_iter()
            .map(|f| {
                (
                    simplex::types::Subject::Finalize {
                        proposal: &f.proposal,
                    },
                    &f.certificate,
                )
            })
            .collect();
        scheme.verify_certificates_bisect::<_, D, N3f1>(rng, &certs, strategy)
    }
}

commonware_macros::stability_scope!(ALPHA {
    use crate::minimmit;
    use commonware_utils::{M5f1, N5f1};

    /// Minimmit consensus adapter for marshal.
    #[derive(Default, Clone, Copy)]
    pub struct MinimmitConsensus<S, D>(PhantomData<(S, D)>);

    impl<S, D> ConsensusEngine for MinimmitConsensus<S, D>
    where
        S: Scheme + minimmit::scheme::Scheme<D>,
        D: Digest,
    {
        type Scheme = S;
        type Commitment = D;
        type Notarization = minimmit::types::MNotarization<S, D>;
        type Finalization = minimmit::types::Finalization<S, D>;
        type Activity = minimmit::types::Activity<S, D>;

        fn into_certificate(
            activity: Self::Activity,
        ) -> Option<ConsensusCertificate<Self::Notarization, Self::Finalization>> {
            match activity {
                minimmit::types::Activity::MNotarization(notarization) => {
                    Some(ConsensusCertificate::Notarization(notarization))
                }
                minimmit::types::Activity::Finalization(finalization) => {
                    Some(ConsensusCertificate::Finalization(finalization))
                }
                _ => None,
            }
        }

        fn verify_notarizations<'a, R: CryptoRngCore>(
            rng: &mut R,
            scheme: &Self::Scheme,
            notarizations: impl IntoIterator<Item = &'a Self::Notarization>,
            strategy: &impl Strategy,
        ) -> Vec<bool> {
            let certs: Vec<_> = notarizations
                .into_iter()
                .map(|n| {
                    (
                        minimmit::types::Subject::Notarize {
                            proposal: &n.proposal,
                        },
                        &n.certificate,
                    )
                })
                .collect();
            scheme.verify_certificates_bisect::<_, D, M5f1>(rng, &certs, strategy)
        }

        fn verify_finalizations<'a, R: CryptoRngCore>(
            rng: &mut R,
            scheme: &Self::Scheme,
            finalizations: impl IntoIterator<Item = &'a Self::Finalization>,
            strategy: &impl Strategy,
        ) -> Vec<bool> {
            let certs: Vec<_> = finalizations
                .into_iter()
                .map(|f| {
                    (
                        minimmit::types::Subject::Notarize {
                            proposal: &f.proposal,
                        },
                        &f.certificate,
                    )
                })
                .collect();
            scheme.verify_certificates_bisect::<_, D, N5f1>(rng, &certs, strategy)
        }
    }
});
