use super::setup::{EpochPreparation, PreparedEpoch};
use crate::dkg::{
    reshare::{actor::Mode, metrics::Phase, store::Store, Actor, Message},
    types::Participants,
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
};
use commonware_consensus::{
    marshal::core::Variant as MarshalVariant,
    types::{Epoch, EpochPhase, Epocher, Height},
};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant as BlsVariant, certificate::Scheme, BatchVerifier,
    Signer,
};
use commonware_macros::select_loop;
use commonware_p2p::{utils::mux::MuxHandle, Blocker, Manager, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    telemetry::traces::TracedExt as _, BufferPooler, Clock, Metrics, Spawner,
    Storage as RuntimeStorage,
};
use commonware_utils::{ordered::Set, Acknowledgement};
use rand_core::CryptoRngCore;
use tracing::{debug, info_span};

impl<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A>
where
    E: Spawner + CryptoRngCore + Metrics + BufferPooler + Clock + RuntimeStorage,
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
    pub(super) async fn run_dkg<SE, RE>(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey>,
        dealing_mux: &mut MuxHandle<SE, RE>,
    ) where
        SE: Sender<PublicKey = C::PublicKey>,
        RE: Receiver<PublicKey = C::PublicKey>,
    {
        let epoch = Epoch::zero();

        // The one-shot DKG is never resumed or re-run. If this node already
        // persisted its epoch-zero threshold share, the ceremony completed in a
        // prior run and its artifacts were durably written then. Fail loudly
        // rather than re-running the ceremony (which would misreport the completed
        // DKG as a fresh failure once the chain has finalized past epoch zero).
        if store.share(epoch).await.is_some() {
            panic!(
                "epoch-zero DKG already completed: this node's threshold share is \
                 persisted, so the ceremony finished in a prior run and does not run \
                 again. If the genesis artifact was not written, recover it from a peer \
                 instead of re-running the DKG."
            );
        }

        let completion = self.dkg_completion();
        let Some(mut prepared) = self.setup_dkg(store).await else {
            self.complete_dkg(completion, store);
            self.terminal().await;
            return;
        };

        let chan = dealing_mux
            .register(epoch.get())
            .await
            .expect("failed to register DKG channel");

        if prepared.phase == EpochPhase::Early
            && self
                .dealing(
                    epoch,
                    store,
                    prepared.dealer.as_mut(),
                    prepared.player.as_mut(),
                    chan,
                )
                .await
                .is_break()
        {
            return;
        }

        if self
            .inclusion(epoch, &prepared.info, store, prepared.dealer.as_mut())
            .await
            .is_continue()
        {
            self.complete_dkg(completion, store);
            self.terminal().await;
        }
    }

    async fn setup_dkg(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey>,
    ) -> Option<PreparedEpoch<V, C>> {
        self.metrics.set_phase(Phase::Setup);

        let height = self
            .marshal
            .get_processed_height()
            .await
            .map_or_else(Height::zero, Height::next);
        let bounds = self
            .epocher
            .containing(height)
            .expect("epocher must know of block height");
        if bounds.epoch() != Epoch::zero() {
            return None;
        }

        let participants = self
            .dkg_participants()
            .expect("DKG setup requires DKG mode");
        let snapshot = Participants {
            dealers: participants.clone(),
            players: participants.clone(),
            next_players: Set::default(),
        };
        snapshot
            .validate::<V>(self.max_participants, None, 0)
            .expect("DKG participants must be valid");

        let seed = store
            .seed_or_random(Epoch::zero(), self.context.as_present_mut())
            .await;
        store.put_seed(Epoch::zero(), seed).await;

        Some(self.prepare_epoch(
            store,
            EpochPreparation {
                epoch: Epoch::zero(),
                phase: bounds.phase(),
                participants: snapshot,
                previous: None,
                share: None,
                seed,
            },
        ))
    }

    async fn terminal(&mut self) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("shutdown signal received");
                return;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                return;
            } => match message {
                Message::NextLog { span, response, .. } => {
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.dkg_terminal.next_log"
                    );
                    process.in_scope(|| {
                        let _ = response.send(None);
                    });
                }
                Message::EpochInfo { span, response, .. } => {
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.dkg_terminal.epoch_info"
                    );
                    process.in_scope(|| {
                        let _ = response.send(None);
                    });
                }
                Message::Finalized {
                    span,
                    response,
                    block,
                } => {
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.dkg_terminal.finalized",
                        height = block.height().traced()
                    );
                    process.in_scope(|| {
                        response.acknowledge();
                    });
                }
            },
        }
    }

    pub(super) fn dkg_participants(&self) -> Option<Set<C::PublicKey>> {
        match &self.mode {
            Mode::Dkg { participants, .. } => Some(participants.clone()),
            Mode::Reshare => None,
        }
    }

    fn dkg_completion(&mut self) -> Option<super::DkgCompletion<V, C::PublicKey>> {
        match &mut self.mode {
            Mode::Dkg { completion, .. } => completion.take(),
            Mode::Reshare => unreachable!("DKG completion requires DKG mode"),
        }
    }

    fn complete_dkg(
        &mut self,
        completion: Option<super::DkgCompletion<V, C::PublicKey>>,
        store: &mut Store<E, SS, V, C::PublicKey>,
    ) {
        let info = store.current().filter(|info| info.epoch == Epoch::zero());
        if let Some(completion) = completion {
            completion(info);
        }
    }
}
