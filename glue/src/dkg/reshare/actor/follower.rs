use crate::dkg::{
    reshare::{metrics::Phase, store::Store, Actor, Message},
    types::Payload,
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
};
use commonware_consensus::{marshal::core::Variant as MarshalVariant, types::Epocher};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant as BlsVariant, certificate::Scheme, BatchVerifier,
    Signer,
};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Manager};
use commonware_parallel::Strategy;
use commonware_runtime::{
    telemetry::traces::TracedExt as _, BufferPooler, Clock, Metrics, Spawner, Storage,
};
use commonware_utils::{channel::fallible::OneshotExt, Acknowledgement};
use rand_core::CryptoRngCore;
use std::ops::ControlFlow;
use tracing::{debug, info_span, Instrument as _};

impl<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A>
where
    E: Spawner + CryptoRngCore + Metrics + BufferPooler + Clock + Storage,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    X: Blocker<PublicKey = C::PublicKey>,
    P: ParticipantsProvider<PublicKey = C::PublicKey>,
    SS: SecretStore,
    T: Strategy,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + 'static,
    S: Scheme,
    MV: MarshalVariant<ApplicationBlock = B>,
    R: Registrar<Variant = V, PublicKey = C::PublicKey>,
    A: Acknowledgement,
{
    /// Enter follower mode until the end of the current epoch is observed.
    ///
    /// This mode is entered when the actor is started mid-epoch, with no recoverable state.
    /// In this case, we cannot participate in the ceremony. Instead, the actor simply waits
    /// until the final block of the epoch and forwards a
    /// [`SchemeInfo::Verifier`](crate::dkg::types::SchemeInfo::Verifier) to the [`Registrar`].
    pub(super) async fn follow(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey>,
    ) -> ControlFlow<()> {
        self.metrics.set_phase(Phase::Following);

        select_loop! {
            self.context,
            on_stopped => {
                debug!("shutdown signal received");
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                return ControlFlow::Break(());
            } => match message {
                Message::NextLog { span, response, .. } => {
                    let process = info_span!(parent: &span, "dkg.reshare.actor.follower.next_log");
                    process.in_scope(|| {
                        let _ = response.send_lossy(None);
                    });
                }
                Message::EpochInfo { span, response, .. } => {
                    let process =
                        info_span!(parent: &span, "dkg.reshare.actor.follower.epoch_info");
                    process.in_scope(|| {
                        let _ = response.send_lossy(None);
                    });
                }
                Message::Finalized {
                    span,
                    block,
                    response,
                } => {
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.follower.finalized",
                        height = block.height().traced()
                    );
                    let done = async {
                        let epoch_info = self
                            .epocher
                            .containing(block.height())
                            .expect("epocher must know of epoch");
                        if block.height() == epoch_info.last() {
                            let Some(Payload::EpochInfo(info)) = block.payload() else {
                                panic!(
                                    "critical: boundary block {} does not contain EpochInfo for epoch {}",
                                    block.height(),
                                    epoch_info.epoch()
                                );
                            };

                            let rng_seed = store
                                .seed_or_random(info.epoch, self.context.as_present_mut())
                                .await;
                            store.commit_epoch(info.clone(), rng_seed, None).await;
                            self.register_epoch(&info, None).await;

                            response.acknowledge();
                            return true;
                        }

                        response.acknowledge();
                        false
                    }
                    .instrument(process)
                    .await;
                    if done {
                        return ControlFlow::Continue(());
                    }
                }
            },
        }
        ControlFlow::Break(())
    }
}
