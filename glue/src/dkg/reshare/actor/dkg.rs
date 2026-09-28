use super::setup::{EpochPreparation, PreparedEpoch};
use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    network::Manager,
    reshare::{Actor, EpochInfoResponse, Message, actor::Mode, metrics::Phase, store::Store},
    types::{EpochInfo, Participants, Payload},
};
use commonware_consensus::{
    marshal::{Identifier, core::Variant as MarshalVariant},
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
        let completion = self.dkg_completion();

        // Activate the epoch-zero peer set on every start, including restarts
        // after completion, so this node can fetch and serve the one-shot chain.
        let tracked = self.track_dkg();

        // A persisted share or a tip at the final height means a prior run
        // applied the final block, which marshal stores before delivering it.
        // The bootstrap chain is never pruned or floored, so the block is still
        // stored. Report its outcome instead of running the ceremony again.
        let last = self
            .epocher
            .last(epoch)
            .expect("epocher must know epoch zero");
        if self.tip.is_some_and(|tip| tip.height >= last) || store.share(epoch).await.is_some() {
            if let Err(error) = tracked {
                warn!(epoch = %epoch, %error, "failed to activate DKG peer set after completion");
            }
            let info = self.final_info(last).await;
            if let Some(completion) = completion {
                completion(info);
            }
            self.terminal().await;
            return;
        }

        let snapshot = match tracked {
            Ok(snapshot) => snapshot,
            Err(error) => {
                warn!(epoch = %epoch, %error, "failed to activate DKG peer set");
                self.complete_dkg(completion, store);
                self.terminal().await;
                return;
            }
        };
        let mut prepared = self.setup_dkg(store, snapshot).await;

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
        snapshot: Participants<C::PublicKey>,
    ) -> PreparedEpoch<V, C> {
        self.metrics.set_phase(Phase::Setup);

        let height = self.tip.map_or_else(Height::zero, |tip| tip.height.next());
        let bounds = self
            .epocher
            .containing(height)
            .expect("epocher must know of block height");
        assert_eq!(
            bounds.epoch(),
            Epoch::zero(),
            "DKG setup requires a tip before the final block"
        );

        let seed = store
            .seed_or_random(Epoch::zero(), self.context.as_present_mut())
            .await;
        store.put_seed(Epoch::zero(), seed).await;

        self.prepare_epoch(
            store,
            EpochPreparation {
                epoch: Epoch::zero(),
                phase: bounds.phase(),
                participants: snapshot,
                previous: None,
                share: None,
                seed,
            },
        )
    }

    /// Validates the configured participants and tracks them for epoch zero,
    /// returning them as both dealers and players.
    ///
    /// Returns the manager's error if tracking fails. Panics outside DKG mode
    /// or if the participants exceed `max_participants` or the epoch's
    /// dealer-log capacity.
    fn track_dkg(&mut self) -> Result<Participants<C::PublicKey>, M::Error> {
        let participants = self
            .dkg_participants()
            .expect("DKG setup requires DKG mode");
        let snapshot = Participants {
            dealers: participants.clone(),
            players: participants,
            next_players: Set::default(),
        };
        snapshot
            .validate::<V>(self.max_participants, None, 0)
            .expect("DKG participants must be valid");
        snapshot
            .validate_epoch_capacity::<V>(self.blocks_per_epoch, None)
            .expect("DKG epoch must have enough dealer-log slots");
        let directory = self.dkg_directory().expect("DKG setup requires DKG mode");
        self.manager
            .track(Epoch::zero(), snapshot.tracked_peers(), &directory)?;
        Ok(snapshot)
    }

    /// Returns the outcome carried by the stored final DKG block (`None` for a
    /// failed DKG).
    ///
    /// Panics if marshal does not store the block.
    async fn final_info(
        &mut self,
        last: Height,
    ) -> Option<EpochInfo<V, C::PublicKey, B::Directory>> {
        let block = self
            .marshal
            .get_block(Identifier::Height(last))
            .await
            .map(MV::into_shared)
            .expect(
                "epoch-zero DKG outcome was applied, but marshal does not store the final \
                 DKG block: bootstrap storage does not match the secret store",
            );

        // Final-block verification admits only the derived EpochInfo or no payload.
        match block.payload() {
            Some(Payload::EpochInfo(info)) => Some(info),
            None => None,
            Some(Payload::DealerLog(_)) => unreachable!("final DKG block carries a dealer log"),
        }
    }

    /// Serves requests and acknowledges finalized blocks once the ceremony's
    /// outcome is reported, until shutdown or the mailbox closes.
    ///
    /// A finalized block has no effects here, so it is acknowledged without
    /// checking it against the tip.
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
