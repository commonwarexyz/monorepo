//! Passive observation of Marshal automaton verdicts.

use super::{Ctx, stack::MarshalChoice};
use crate::{
    marshal::end_to_end::{
        app::FaultyConfig,
        invariants::{CertificationAgreementInvariant, HeaderMismatchInvariant},
    },
    simplex::Simplex,
};
use commonware_consensus::{Automaton, CertifiableAutomaton, types::Round};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_macros::select;
use commonware_runtime::{Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    sync::Mutex,
};
use std::sync::Arc;

fn verification_header_mismatch<P: Simplex>(
    marshal: MarshalChoice,
    context: &Ctx<P>,
    block_context: &Ctx<P>,
    digest: Sha256Digest,
) -> bool {
    if digest == context.parent.1 {
        return false;
    }
    match marshal {
        MarshalChoice::Deferred => block_context != context,
        MarshalChoice::Inline => block_context.parent.1 != context.parent.1,
    }
}

/// Passively observes the real marshal automaton calls made by Simplex.
///
/// Completed certification verdicts are compared with other correct replicas
/// and checked against any verification context that differs from the block's
/// embedded context.
pub(super) struct ObservedMarshal<P: Simplex, M> {
    pub(super) validator: usize,
    pub(super) probe_input: Arc<str>,
    pub(super) context: Arc<Mutex<deterministic::Context>>,
    pub(super) inner: M,
    pub(super) certification_agreement: CertificationAgreementInvariant,
    pub(super) header_mismatch: HeaderMismatchInvariant<P, FaultyConfig>,
}

impl<P: Simplex, M: Clone> Clone for ObservedMarshal<P, M> {
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

impl<P, M> Automaton for ObservedMarshal<P, M>
where
    P: Simplex,
    M: CertifiableAutomaton<Context = Ctx<P>, Digest = Sha256Digest>,
{
    type Context = Ctx<P>;
    type Digest = Sha256Digest;

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
                let mismatched = verification_header_mismatch::<P>(
                    header_mismatch.marshal(),
                    &context,
                    &block_context,
                    digest,
                );
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

impl<P, M> CertifiableAutomaton for ObservedMarshal<P, M>
where
    P: Simplex,
    M: CertifiableAutomaton<Context = Ctx<P>, Digest = Sha256Digest>,
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
    use crate::{id_mock, simplex::SimplexId};
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest([byte; 32])
    }

    fn context(view: u64, parent: Sha256Digest) -> Ctx<SimplexId> {
        Context {
            round: Round::new(Epoch::zero(), View::new(view)),
            leader: id_mock::PublicKey::from_index(0),
            parent: (View::new(view.saturating_sub(1)), parent),
        }
    }

    #[test]
    fn parent_digest_reproposal_is_not_a_header_mismatch() {
        let parent = digest(0xA);
        let requested = context(2, parent);
        let embedded = context(1, digest(0xB));

        assert!(!verification_header_mismatch::<SimplexId>(
            MarshalChoice::Deferred,
            &requested,
            &embedded,
            parent,
        ));
    }
}
