use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    network::Manager,
    reshare::{Actor, EpochInfoResponse, Message, metrics::Phase, store::Store},
    types::Payload,
};
use commonware_consensus::{
    marshal::core::Variant as MarshalVariant, simplex::scheme::Scheme as SimplexScheme,
    types::Epocher,
};
use commonware_cryptography::{
    BatchVerifier, Signer, bls12381::primitives::variant::Variant as BlsVariant,
    certificate::Scheme,
};
use commonware_macros::select_loop;
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage, telemetry::traces::TracedExt as _,
};
use commonware_utils::{Acknowledgement, channel::fallible::OneshotExt};
use rand_core::CryptoRng;
use std::ops::ControlFlow;
use tracing::{Instrument as _, debug, info_span};

impl<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A>
where
    E: Spawner + CryptoRng + Metrics + BufferPooler + Clock + Storage,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey, Directory = B::Directory>,
    X: Blocker<PublicKey = C::PublicKey>,
    P: ParticipantsProvider<PublicKey = C::PublicKey, Directory = B::Directory>,
    SS: SecretStore,
    T: Strategy,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + 'static,
    S: Scheme + SimplexScheme<MV::Commitment, PublicKey = C::PublicKey>,
    MV: MarshalVariant<ApplicationBlock = B>,
    R: Registrar<Variant = V, PublicKey = C::PublicKey>,
    A: Acknowledgement,
{
    /// Follows the chain without participating until the next final block of an
    /// epoch is applied.
    ///
    /// Acknowledges earlier finalized blocks without effects. Dealer-log requests
    /// receive no log and final-block requests receive
    /// [`EpochInfoResponse::Following`]. Commits and registers the final block's
    /// [`EpochInfo`](crate::dkg::types::EpochInfo) before returning `Continue`.
    /// Returns `Break` on shutdown or when the mailbox closes.
    ///
    /// Panics if the final block carries no
    /// [`EpochInfo`](crate::dkg::types::EpochInfo).
    pub(super) async fn follow(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
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
                Message::ReleaseLog { .. } => {}
                Message::EpochInfo { span, response, .. } => {
                    let process =
                        info_span!(parent: &span, "dkg.reshare.actor.follower.epoch_info");
                    process.in_scope(|| {
                        let _ = response.send_lossy(EpochInfoResponse::Following);
                    });
                }
                Message::Finalized {
                    span,
                    block,
                    response,
                } => {
                    if self.covered(&block) {
                        response.acknowledge();
                        continue;
                    }
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
                        let done = block.height() == epoch_info.last();
                        if done {
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
                            let share = self.recovered_share(store, &info).await;
                            store
                                .commit_epoch(info.clone(), rng_seed, share.clone())
                                .await;
                            self.register_epoch(&info, share).await;
                        }

                        self.advance(&block);
                        response.acknowledge();
                        done
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
