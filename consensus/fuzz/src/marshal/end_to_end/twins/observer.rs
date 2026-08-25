//! Passive observation of Marshal automaton verdicts.

use crate::{
    marshal::end_to_end::{
        app::FaultyConfig,
        invariants::{
            CertificationAgreementInvariant, ConsensusParentDigest, HeaderMismatchInvariant,
        },
    },
    simplex::Simplex,
};
use commonware_consensus::{
    Automaton, CertifiableAutomaton, simplex::types::Context as SimplexContext, types::Round,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_macros::select;
use commonware_runtime::{Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    sync::Mutex,
};
use std::sync::Arc;

type Ctx<P, D> = SimplexContext<
    D,
    <<P as Simplex>::Scheme as commonware_cryptography::certificate::Verifier>::PublicKey,
>;

/// Passively observes the real marshal automaton calls made by Simplex.
///
/// Completed certification verdicts are compared with other correct replicas
/// and checked against any verification context that differs from the block's
/// embedded context.
pub(crate) struct ObservedMarshal<P: Simplex, M, D: ConsensusParentDigest = Sha256Digest> {
    pub(crate) validator: usize,
    pub(crate) probe_input: Arc<str>,
    pub(crate) context: Arc<Mutex<deterministic::Context>>,
    pub(crate) inner: M,
    pub(crate) certification_agreement: CertificationAgreementInvariant<D>,
    pub(crate) header_mismatch: HeaderMismatchInvariant<P, FaultyConfig, D>,
}

impl<P: Simplex, M: Clone, D: ConsensusParentDigest> Clone for ObservedMarshal<P, M, D> {
    fn clone(&self) -> Self {
        Self {
            validator: self.validator,
            probe_input: self.probe_input.clone(),
            context: self.context.clone(),
            inner: self.inner.clone(),
            certification_agreement: self.certification_agreement.clone(),
            header_mismatch: self.header_mismatch.clone(),
        }
    }
}

impl<P, M, D> Automaton for ObservedMarshal<P, M, D>
where
    P: Simplex,
    D: ConsensusParentDigest,
    M: CertifiableAutomaton<Context = Ctx<P, D>, Digest = D>,
{
    type Context = Ctx<P, D>;
    type Digest = D;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let round = context.round;
        let mut result = self.inner.propose(context).await;
        let (mut tx, rx) = oneshot::channel();
        let certification_agreement = self.certification_agreement.clone();
        let runtime = self.context.lock().child("propose");
        let validator = self.validator;
        runtime.spawn(move |_| async move {
            let digest = select! {
                result = &mut result => result.ok(),
                _ = tx.closed() => result.try_recv().ok(),
            };
            let Some(digest) = digest else {
                return;
            };
            // FaultyConfig is shared and view-indexed across honest nodes. If it
            // becomes per-node, this self-proposal clause must be scoped with it.
            certification_agreement.record_proposal(validator, round, digest);
            tx.send_lossy(digest);
        });
        rx
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        digest: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        self.header_mismatch.record_verify(context.clone(), digest);
        let mut inner_rx = self.inner.verify(context.clone(), digest).await;
        let (mut tx, rx) = oneshot::channel();
        let header_mismatch = self.header_mismatch.clone();
        let probe_context = self.context.lock().child("verify_probe");
        let validator = self.validator;
        let probe_input = self.probe_input.clone();
        probe_context.spawn(move |_| async move {
            let value = select! {
                result = &mut inner_rx => result.ok(),
                _ = tx.closed() => inner_rx.try_recv().ok(),
            };
            let Some(value) = value else {
                return;
            };
            tx.send_lossy(value);
            if let Some(block_context) = header_mismatch.block_context(&digest) {
                let mismatched =
                    header_mismatch.verification_mismatch(&context, &block_context, digest);
                assert!(
                    !mismatched || !value,
                    "marshal verified a payload under a header that is not the block's embedded \
                     header: validator={validator} digest={digest} context={context:?} \
                     embedded_context={block_context:?} marshal={} stack={} input={}",
                    header_mismatch.marshal(),
                    header_mismatch.stack(),
                    probe_input,
                );
            }
        });
        rx
    }
}

impl<P, M, D> CertifiableAutomaton for ObservedMarshal<P, M, D>
where
    P: Simplex,
    D: ConsensusParentDigest,
    M: CertifiableAutomaton<Context = Ctx<P, D>, Digest = D>,
{
    async fn certify(&mut self, round: Round, digest: Self::Digest) -> oneshot::Receiver<bool> {
        let mut result = self.inner.certify(round, digest).await;
        let (mut tx, rx) = oneshot::channel();
        let header_mismatch = self.header_mismatch.clone();
        let certification_agreement = self.certification_agreement.clone();
        let context = self.context.lock().child("certify");
        let validator = self.validator;
        context.spawn(move |_| async move {
            let value = select! {
                result = &mut result => result.ok(),
                _ = tx.closed() => result.try_recv().ok(),
            };
            let Some(value) = value else {
                return;
            };
            certification_agreement.check_certify_agreement(validator, round, digest, value);
            header_mismatch.check_certification(round, digest, value);
            tx.send_lossy(value);
        });
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::end_to_end::{
            app::{ApplicationChoice, BlockContextRegistry},
            twins::stack::MarshalChoice,
        },
        simplex::SimplexCertificateMock,
        simplex_certificate_mock,
    };
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        ed25519::PublicKey as Ed25519PublicKey, sha256::Digest as Sha256Digest,
    };
    use commonware_utils::test_rng;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest([byte; 32])
    }

    fn leader() -> Ed25519PublicKey {
        simplex_certificate_mock::fixture_with::<false, true, true, _>(
            &mut test_rng(),
            b"marshal-twins-observer",
            1,
        )
        .participants
        .remove(0)
    }

    fn context(view: u64, parent: Sha256Digest) -> Ctx<SimplexCertificateMock, Sha256Digest> {
        Context {
            round: Round::new(Epoch::zero(), View::new(view)),
            leader: leader(),
            parent: (View::new(view.saturating_sub(1)), parent),
        }
    }

    #[test]
    fn parent_digest_reproposal_is_not_a_header_mismatch() {
        let parent = digest(0xA);
        let requested = context(2, parent);
        let embedded = context(1, digest(0xB));
        let invariant = HeaderMismatchInvariant::<SimplexCertificateMock, (), Sha256Digest>::new(
            ApplicationChoice::AlwaysAccept,
            (),
            |_, _, _| false,
            BlockContextRegistry::default(),
            MarshalChoice::Deferred,
            "test".into(),
        );

        assert!(!invariant.verification_mismatch(&requested, &embedded, parent,));
    }
}
