use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    reshare::{
        Actor,
        actor::Mode,
        metrics::Phase,
        store::{Dealer, Player, Store},
    },
    types::{EpochInfo, EpochOutcome, Participants, Payload, SchemeInfo},
};
use commonware_consensus::{
    marshal::{Identifier, core::Variant as MarshalVariant},
    simplex::scheme::Scheme as SimplexScheme,
    types::{Epoch, EpochPhase, Epocher, FixedEpocher, Height},
};
use commonware_cryptography::{
    BatchVerifier, PublicKey, Signer,
    bls12381::{
        dkg::feldman_desmedt::{Info, Output},
        primitives::{group::Share, variant::Variant as BlsVariant},
    },
    certificate::Scheme,
    transcript::Summary,
};
use commonware_p2p::{Blocker, Manager};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage, telemetry::metrics::GaugeExt,
};
use commonware_utils::{Acknowledgement, N3f1};
use rand_core::CryptoRng;

pub(super) struct PreparedEpoch<V, C>
where
    V: BlsVariant,
    C: Signer,
{
    pub(super) epoch: Epoch,
    pub(super) phase: EpochPhase,
    pub(super) info: Info<V, C::PublicKey>,
    pub(super) dealer: Option<Dealer<V, C>>,
    pub(super) player: Option<Player<V, C>>,
}

pub(super) struct EpochPreparation<V, P>
where
    V: BlsVariant,
    P: PublicKey,
{
    pub(super) epoch: Epoch,
    pub(super) phase: EpochPhase,
    pub(super) participants: Participants<P>,
    pub(super) previous: Option<Output<V, P>>,
    pub(super) share: Option<Share>,
    pub(super) seed: Summary,
}

pub(super) enum Setup<V, C>
where
    V: BlsVariant,
    C: Signer,
{
    Follow,
    Participate(Box<PreparedEpoch<V, C>>),
}

fn startup_height(
    epocher: &FixedEpocher,
    current_epoch: Option<Epoch>,
    state_sync_epoch: Option<Epoch>,
    processed: Option<Height>,
) -> Height {
    if let Some(epoch) = state_sync_epoch {
        return processed.map_or_else(
            || {
                epocher
                    .first(epoch)
                    .expect("epocher must know synced epoch")
            },
            Height::next,
        );
    }
    if let Some(epoch) = current_epoch {
        return epocher
            .first(epoch)
            .expect("epocher must know hinted epoch");
    }
    processed.map_or_else(Height::zero, Height::next)
}

impl<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, BV, S, MV, R, A>
where
    E: Spawner + CryptoRng + Metrics + BufferPooler + Clock + Storage,
    B: ReshareBlock<Variant = V, Signer = C>,
    V: BlsVariant,
    C: Signer,
    M: Manager<PublicKey = C::PublicKey>,
    X: Blocker<PublicKey = C::PublicKey>,
    P: ParticipantsProvider<PublicKey = C::PublicKey>,
    SS: SecretStore,
    T: Strategy,
    BV: BatchVerifier<PublicKey = C::PublicKey> + Send + 'static,
    S: Scheme + SimplexScheme<MV::Commitment, PublicKey = C::PublicKey>,
    MV: MarshalVariant<ApplicationBlock = B>,
    R: Registrar<Variant = V, PublicKey = C::PublicKey>,
    A: Acknowledgement,
{
    pub(super) async fn setup(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey>,
        current_epoch: Option<Epoch>,
        state_sync_info: Option<EpochInfo<V, C::PublicKey>>,
    ) -> Option<Setup<V, C>> {
        self.metrics.set_phase(Phase::Setup);

        let state_sync_epoch = state_sync_info.as_ref().map(|info| info.epoch);
        let processed = if state_sync_epoch.is_some() || current_epoch.is_none() {
            self.marshal.get_processed_height().await
        } else {
            None
        };
        let height = startup_height(&self.epocher, current_epoch, state_sync_epoch, processed);
        let bounds = self
            .epocher
            .containing(height)
            .expect("epocher must know of block height");
        let epoch = bounds.epoch();

        let current = store.current().filter(|current| current.epoch == epoch);
        let already_committed = current.is_some();
        let info = match current.or(state_sync_info) {
            Some(info) => info,
            None => {
                let Some(info) = self.boundary_epoch_info(epoch).await else {
                    return Some(Setup::Follow);
                };
                info
            }
        };
        if info.epoch != epoch {
            panic!(
                "boundary epoch info describes epoch {}, expected {epoch}",
                info.epoch
            );
        }

        let participants = info.participants();
        let round = epoch.get();
        participants
            .validate(self.max_participants, Some(&info.output), round)
            .expect("boundary epoch participants must be valid");
        participants
            .validate_epoch_capacity(self.blocks_per_epoch, Some(&info.output))
            .expect("boundary epoch must have enough dealer-log slots");

        let share = self.recovered_share(store, &info).await;
        let seed = store
            .seed_or_random(epoch, self.context.as_present_mut())
            .await;
        if !already_committed {
            store.commit_epoch(info.clone(), seed, share.clone()).await;
            self.register_epoch(&info, share.clone()).await;
        }
        store.prune(epoch.previous().unwrap_or(epoch)).await;

        Some(Setup::Participate(Box::new(self.prepare_epoch(
            store,
            EpochPreparation {
                epoch,
                phase: bounds.phase(),
                participants,
                previous: Some(info.output.clone()),
                share,
                seed,
            },
        ))))
    }

    pub(super) async fn recovered_share(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey>,
        info: &EpochInfo<V, C::PublicKey>,
    ) -> Option<Share> {
        let share = store.share(info.epoch).await;
        if share.is_some() || info.outcome != EpochOutcome::Failure {
            return share;
        }

        info.output.players().position(&self.signer.public_key())?;

        let previous = info.epoch.previous()?;
        store.share(previous).await
    }

    async fn boundary_epoch_info(&mut self, epoch: Epoch) -> Option<EpochInfo<V, C::PublicKey>> {
        let height = epoch
            .previous()
            .and_then(|e| self.epocher.last(e))
            .unwrap_or(Height::zero());
        let block = self
            .marshal
            .get_block(Identifier::Height(height))
            .await
            .map(MV::into_inner)?;
        let Some(Payload::EpochInfo(info)) = block.payload() else {
            panic!("boundary block {height} missing epoch info");
        };
        Some(info)
    }

    pub(super) async fn register_epoch(
        &mut self,
        info: &EpochInfo<V, C::PublicKey>,
        share: Option<Share>,
    ) {
        let scheme_info = share.map_or_else(
            || SchemeInfo::Verifier {
                participants: info.output.players().clone(),
                sharing: info.output.public().clone(),
            },
            |share| SchemeInfo::Signer {
                participants: info.output.players().clone(),
                sharing: info.output.public().clone(),
                share,
            },
        );
        self.registrar.register(info.epoch, scheme_info).await;
        self.fence.mark(info.epoch);
    }

    pub(super) fn prepare_epoch(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey>,
        preparation: EpochPreparation<V, C::PublicKey>,
    ) -> PreparedEpoch<V, C> {
        let EpochPreparation {
            epoch,
            phase,
            participants,
            previous,
            share,
            seed,
        } = preparation;

        let round = epoch.get();
        if matches!(&self.mode, Mode::Dkg { .. }) {
            let _ = self
                .manager
                .track(epoch.get(), participants.tracked_peers());
        }
        let _ = self.metrics.current_epoch.try_set(epoch.get() as i64);
        let _ = self.metrics.current_round.try_set(round as i64);

        let round = Info::new::<N3f1>(
            self.namespace,
            round,
            previous.clone(),
            self.sharing_mode,
            participants.dealers.clone(),
            participants.players.clone(),
        )
        .expect("epoch participants must produce valid round info");

        let public_key = self.signer.public_key();
        let has_prior_share = previous.is_none() || share.is_some();
        let dealer = if participants.dealers.position(&public_key).is_some() && has_prior_share {
            store.create_dealer::<C, N3f1>(epoch, self.signer.clone(), round.clone(), share, seed)
        } else {
            None
        };
        let player = participants.players.position(&public_key).and_then(|_| {
            store.create_player::<C, N3f1>(epoch, self.signer.clone(), round.clone())
        });

        PreparedEpoch {
            epoch,
            phase,
            info: round,
            dealer,
            player,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::startup_height;
    use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher};
    use commonware_utils::NZU64;

    #[test]
    fn state_sync_without_processed_height_starts_in_synced_epoch() {
        let epocher = FixedEpocher::new(NZU64!(64));
        let epoch = Epoch::new(3);

        assert_eq!(
            startup_height(&epocher, Some(epoch), Some(epoch), None),
            epocher.first(epoch).expect("test epoch")
        );
    }
}
