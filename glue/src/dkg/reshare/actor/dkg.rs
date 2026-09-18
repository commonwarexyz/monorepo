use super::setup::{EpochPreparation, PreparedEpoch};
use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    network::Manager,
    reshare::{Actor, EpochInfoResponse, Message, actor::Mode, metrics::Phase, store::Store},
    types::Participants,
};
use commonware_consensus::{
    marshal::core::Variant as MarshalVariant,
    simplex::scheme::Scheme as SimplexScheme,
    types::{Epoch, EpochPhase, Epocher, Height},
};
use commonware_cryptography::{
    BatchVerifier, Signer, bls12381::primitives::variant::Variant as BlsVariant,
    certificate::Scheme,
};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Receiver, Sender, utils::mux::MuxHandle};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage as RuntimeStorage,
    telemetry::traces::TracedExt as _,
};
use commonware_utils::{Acknowledgement, ordered::Set};
use rand_core::CryptoRng;
use tracing::{debug, info_span, warn};

impl<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A>
where
    E: Spawner + CryptoRng + Metrics + BufferPooler + Clock + RuntimeStorage,
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
    pub(super) async fn run_dkg<SE, RE>(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
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
        let mut prepared = match self.setup_dkg(store).await {
            Ok(Some(prepared)) => prepared,
            Ok(None) => {
                self.complete_dkg(completion, store);
                self.terminal().await;
                return;
            }
            Err(error) => {
                warn!(epoch = %epoch, %error, "failed to activate DKG peer set, shutting down");
                self.complete_dkg(completion, store);
                self.terminal().await;
                return;
            }
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
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
    ) -> Result<Option<PreparedEpoch<V, C>>, M::Error> {
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
            return Ok(None);
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
        snapshot
            .validate_epoch_capacity::<V>(self.blocks_per_epoch, None)
            .expect("DKG epoch must have enough dealer-log slots");

        // Activate the complete epoch-zero snapshot with its configured
        // directory before the channel is registered or any dealings can be
        // sent.
        let directory = self.dkg_directory().expect("DKG setup requires DKG mode");
        self.manager
            .track(Epoch::zero(), snapshot.tracked_peers(), &directory)?;

        let seed = store
            .seed_or_random(Epoch::zero(), self.context.as_present_mut())
            .await;
        store.put_seed(Epoch::zero(), seed).await;

        Ok(Some(self.prepare_epoch(
            store,
            EpochPreparation {
                epoch: Epoch::zero(),
                phase: bounds.phase(),
                participants: snapshot,
                previous: None,
                share: None,
                seed,
            },
        )))
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
                Message::ReleaseLog { .. } => {}
                Message::EpochInfo { span, response, .. } => {
                    let process = info_span!(
                        parent: &span,
                        "dkg.reshare.actor.dkg_terminal.epoch_info"
                    );
                    process.in_scope(|| {
                        let _ = response.send(EpochInfoResponse::Available(None));
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

    pub(super) fn dkg_directory(&self) -> Option<B::Directory> {
        match &self.mode {
            Mode::Dkg { directory, .. } => Some(directory.clone()),
            Mode::Reshare => None,
        }
    }

    fn dkg_completion(&mut self) -> Option<super::DkgCompletion<V, C::PublicKey, B::Directory>> {
        match &mut self.mode {
            Mode::Dkg { completion, .. } => completion.take(),
            Mode::Reshare => unreachable!("DKG completion requires DKG mode"),
        }
    }

    fn complete_dkg(
        &mut self,
        completion: Option<super::DkgCompletion<V, C::PublicKey, B::Directory>>,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
    ) {
        let info = store.current().filter(|info| info.epoch == Epoch::zero());
        if let Some(completion) = completion {
            completion(info);
        }
    }
}
