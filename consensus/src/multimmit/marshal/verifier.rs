//! An [`LqcVerifier`] backed by the epoch's committee [`Scheme`].

use super::types::LqcVerifier;
use crate::multimmit::{
    scheme::{Generic, Scheme},
    types::Lqc,
};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Supervisor;
use rand_core::CryptoRng;
use std::{future::Future, sync::Arc};

/// The committee rejected an L-QC.
#[derive(Debug, thiserror::Error)]
#[error("committee rejected the L-QC")]
pub struct InvalidLqc;

/// Verifies each L-QC against a committee [`Scheme`] through `strategy`.
///
/// Each call submits the check to `strategy` as one spawned job before the returned future is
/// polled. The strategy runs it inline in the call or hands it to a worker while the marshal actor
/// awaits it, whichever it measures cheaper; a sequential strategy always runs it inline.
/// `context` seeds each verification's batch randomness.
pub struct SchemeVerifier<E, S: Scheme, T> {
    context: E,
    scheme: Arc<Generic<S>>,
    strategy: T,
}

impl<E, S: Scheme, T> SchemeVerifier<E, S, T> {
    /// Creates a verifier for `scheme`'s committee.
    pub fn new(context: E, scheme: Generic<S>, strategy: T) -> Self {
        Self {
            context,
            scheme: Arc::new(scheme),
            strategy,
        }
    }
}

impl<E, S, T> Clone for SchemeVerifier<E, S, T>
where
    E: Supervisor,
    S: Scheme,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            context: self.context.child("lqc_verifier"),
            scheme: Arc::clone(&self.scheme),
            strategy: self.strategy.clone(),
        }
    }
}

impl<E, H, S, T> LqcVerifier<H, S> for SchemeVerifier<E, S, T>
where
    E: CryptoRng + Supervisor,
    H: Hasher,
    S: Scheme,
    T: Strategy,
{
    type Error = InvalidLqc;

    fn verify(
        &mut self,
        proof: &Lqc<S, H::Digest>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let scheme = Arc::clone(&self.scheme);
        let strategy = self.strategy.clone();
        let mut rng = self.context.child("verify");
        let proof = proof.clone();
        let verified = self.strategy.spawn(1, move |_| {
            scheme
                .verify_lqc::<_, H, _>(&mut rng, &proof, &strategy)
                .is_some()
        });
        async move { verified.await.then_some(()).ok_or(InvalidLqc) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::mocks::{Bls, Committee},
        types::View,
    };
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn scheme_verifier_accepts_committee_lqcs_and_rejects_others() {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<Bls<MinPk>>::builder(91, 6).build();
            let other = Committee::<Bls<MinPk>>::builder(92, 6).build();
            let mut verifier = SchemeVerifier::new(
                context.child("verifier"),
                committee.verifier.clone(),
                Sequential,
            );

            assert!(
                LqcVerifier::<Sha256, Bls<MinPk>>::verify(
                    &mut verifier,
                    &committee.lqc(View::new(3))
                )
                .await
                .is_ok()
            );
            let mut clone = verifier.clone();
            assert!(matches!(
                LqcVerifier::<Sha256, Bls<MinPk>>::verify(&mut clone, &other.lqc(View::new(3)))
                    .await,
                Err(InvalidLqc)
            ));
        });
    }
}
