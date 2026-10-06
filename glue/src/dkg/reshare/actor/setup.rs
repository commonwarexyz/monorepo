use super::FinalizedTip;
use crate::dkg::{
    ParticipantsProvider, Registrar, ReshareBlock, SecretStore,
    network::{Directory, Manager},
    reshare::{
        Actor,
        metrics::Phase,
        store::{Dealer, Player, Store},
    },
    types::{EpochInfo, EpochOutcome, Participants, Payload, SchemeInfo},
};
use commonware_consensus::{
    Block,
    marshal::{
        Identifier,
        core::{Processed, Variant as MarshalVariant},
    },
    simplex::scheme::Scheme as SimplexScheme,
    types::{Epoch, EpochPhase, Epocher, FixedEpocher, Height},
};
use commonware_cryptography::{
    BatchVerifier, PublicKey, Signer,
    bls12381::{
        dkg::feldman_desmedt::{Info, Output},
        primitives::{group::Share, variant::Variant as BlsVariant},
    },
    transcript::Summary,
};
use commonware_p2p::Blocker;
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

/// State-sync epoch metadata paired with the block height of its certified floor.
pub(super) struct StateSyncStart<V, P, D>
where
    V: BlsVariant,
    P: PublicKey,
    D: Directory<P>,
{
    pub(super) info: EpochInfo<V, P, D>,
    pub(super) floor: Height,
}

/// Returns whether a state-sync floor lies after its epoch's midpoint, so the
/// blocks it skipped may have carried dealer logs.
fn state_sync_skips_inclusion_prefix(
    epocher: &FixedEpocher,
    state_sync_floor: Option<Height>,
) -> bool {
    let Some(floor) = state_sync_floor else {
        return false;
    };
    epocher
        .containing(floor)
        .expect("epocher must know state sync floor")
        .phase()
        == EpochPhase::Late
}

/// Returns the later of marshal's processed position and the parent of the
/// state-sync floor (`None` when neither exists).
///
/// `processed` pairs the position with a stored block: the processed block
/// itself, or its child when the processed block is absent.
pub(super) fn startup<B: Block>(
    processed: Option<(Processed, B)>,
    floor: Option<B>,
) -> Option<FinalizedTip<B::Digest>> {
    let processed = processed.map(|(processed, block)| match processed {
        Processed::Block(height) => FinalizedTip {
            height,
            digest: block.digest(),
        },
        Processed::Absent(height) => FinalizedTip {
            height,
            digest: block.parent(),
        },
    });
    let floor = floor.and_then(|block| {
        Some(FinalizedTip {
            height: block.height().previous()?,
            digest: block.parent(),
        })
    });
    processed
        .into_iter()
        .chain(floor)
        .max_by_key(|tip| tip.height)
}

/// Retains a dealer that can still produce a selectable log.
///
/// During the early phase, missing acknowledgements can still arrive. Afterward,
/// a recovered dealer is useful only when its durable acknowledgements already
/// form a quorum.
fn dealer_for_phase<V, C>(
    phase: EpochPhase,
    players: usize,
    dealer: Option<Dealer<V, C>>,
) -> Option<Dealer<V, C>>
where
    V: BlsVariant,
    C: Signer,
{
    dealer.filter(|dealer| {
        phase == EpochPhase::Early || dealer.has_acknowledgement_quorum::<N3f1>(players)
    })
}

impl<E, B, V, C, M, X, P, SS, T, S, MV, R, A> Actor<E, B, V, C, M, X, P, SS, T, S, MV, R, A>
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
    C::PublicKey: BatchVerifier,
    S: SimplexScheme<MV::Commitment, PublicKey = C::PublicKey>,
    MV: MarshalVariant<ApplicationBlock = B>,
    R: Registrar<Variant = V, PublicKey = C::PublicKey>,
    A: Acknowledgement,
{
    pub(super) async fn setup(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        state_sync: Option<StateSyncStart<V, C::PublicKey, B::Directory>>,
    ) -> Option<Setup<V, C>> {
        self.metrics.set_phase(Phase::Setup);

        let height = self.tip.map_or_else(Height::zero, |tip| tip.height.next());
        let bounds = self
            .epocher
            .containing(height)
            .expect("epocher must know of block height");
        let epoch = bounds.epoch();

        // Prefer the epoch committed earlier in this run, then state-sync
        // material, then the finalized boundary block.
        let current = store.current().filter(|current| current.epoch == epoch);
        let already_committed = current.is_some();
        let state_sync_floor = state_sync.as_ref().map(|start| start.floor);
        let follow = state_sync_skips_inclusion_prefix(&self.epocher, state_sync_floor);
        let info = match current.or_else(|| state_sync.map(|start| start.info)) {
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

        // Each source is read from storage or produced by consensus, so check
        // participant and dealer-log limits before building protocol state.
        let participants = info.participants();
        let round = epoch.get();
        participants
            .validate(self.max_participants, Some(&info.output), round)
            .expect("boundary epoch participants must be valid");
        participants
            .validate_epoch_capacity(self.blocks_per_epoch, Some(&info.output))
            .expect("boundary epoch must have enough dealer-log slots");

        // Persist the epoch's share and seed before registering its scheme, and
        // prune only once the epoch is durable.
        let share = self.recovered_share(store, &info).await;
        let seed = store
            .seed_or_random(epoch, self.context.as_present_mut())
            .await;
        if !already_committed {
            store.commit_epoch(info.clone(), seed, share.clone()).await;
            self.register_epoch(&info, share.clone()).await;
        }
        store.prune(epoch.previous().unwrap_or(epoch)).await;

        // A floor after the midpoint skipped blocks that may carry dealer logs,
        // so follow the committed epoch instead of participating.
        if follow {
            return Some(Setup::Follow);
        }

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

    /// Returns this node's share stored for `info.epoch`.
    ///
    /// If none is stored and `info` records a failed ceremony, returns the share
    /// stored for the previous epoch when this node is a player of the
    /// carried-forward output.
    pub(super) async fn recovered_share(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        info: &EpochInfo<V, C::PublicKey, B::Directory>,
    ) -> Option<Share> {
        let share = store.share(info.epoch).await;
        if share.is_some() || info.outcome != EpochOutcome::Failure {
            return share;
        }

        info.output.players().position(&self.signer.public_key())?;

        let previous = info.epoch.previous()?;
        store.share(previous).await
    }

    /// Returns the [`EpochInfo`] carried by the finalized boundary block that
    /// introduced `epoch` (`None` if marshal does not have the block).
    ///
    /// Panics if the block carries no [`EpochInfo`].
    async fn boundary_epoch_info(
        &mut self,
        epoch: Epoch,
    ) -> Option<EpochInfo<V, C::PublicKey, B::Directory>> {
        let height = epoch
            .previous()
            .and_then(|e| self.epocher.last(e))
            .unwrap_or(Height::zero());
        let block = self
            .marshal
            .get_block(Identifier::Height(height))
            .await
            .map(MV::into_shared)?;
        let Some(Payload::EpochInfo(info)) = block.payload() else {
            panic!("boundary block {height} missing epoch info");
        };
        Some(info)
    }

    /// Registers a signer scheme for `info` if `share` is present and a verifier
    /// scheme otherwise, then marks `info.epoch` on the fence.
    pub(super) async fn register_epoch(
        &mut self,
        info: &EpochInfo<V, C::PublicKey, B::Directory>,
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
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
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
        let _ = self.metrics.current_epoch.try_set(epoch.get() as i64);
        let _ = self.metrics.current_round.try_set(round as i64);

        let round = Info::new::<N3f1>(
            self.namespace,
            round,
            previous.clone(),
            self.sharing_mode,
            self.reveal,
            participants.dealers.clone(),
            participants.players.clone(),
        )
        .expect("epoch participants must produce valid round info");

        // Reshare dealers need the prior private share, while epoch-zero DKG has
        // no prior output. Player construction depends only on membership in the
        // new player set.
        let public_key = self.signer.public_key();
        let has_prior_share = previous.is_none() || share.is_some();
        let dealer = if participants.dealers.position(&public_key).is_some() && has_prior_share {
            store.create_dealer::<C, N3f1>(epoch, self.signer.clone(), round.clone(), share, seed)
        } else {
            None
        };
        let dealer = dealer_for_phase(phase, participants.players.len(), dealer);
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
    use super::{dealer_for_phase, startup, state_sync_skips_inclusion_prefix};
    use crate::dkg::{
        reshare::store::{AckOutcome, Store},
        tests::mocks::{self, MemorySecretStore, TestBlsVariant, child, genesis_block},
    };
    use commonware_consensus::{
        marshal::core::Processed,
        types::{Epoch, EpochPhase, Epocher as _, FixedEpocher, Height},
    };
    use commonware_cryptography::{
        Digestible as _, Signer,
        bls12381::{
            dkg::feldman_desmedt::{Info, Player, Reveal, deal},
            primitives::sharing::Mode,
        },
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_utils::{N3f1, NZU64, ordered::Set, test_rng};

    const TEST_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_RESHARE_SETUP_TEST";

    /// State sync never resumes below its certified floor, and marshal's
    /// processed position takes its digest from the stored block that backs it.
    #[test]
    fn startup_tip_covers_processed_and_floor() {
        let mut blocks = vec![genesis_block(PrivateKey::from_seed(0).public_key())];
        while blocks.len() < 5 {
            blocks.push(child(blocks.last().unwrap()));
        }
        let tip = |processed: Option<Processed>, floor: Option<usize>| {
            let processed = processed.map(|processed| {
                let anchor = processed.anchor().get() as usize;
                (processed, blocks[anchor].clone())
            });
            startup(processed, floor.map(|floor| blocks[floor].clone()))
                .map(|tip| (tip.height, tip.digest))
        };
        let covered = |index: usize| Some((Height::new(index as u64), blocks[index].digest()));
        let stored = |height| Some(Processed::Block(Height::new(height)));
        let absent = |height| Some(Processed::Absent(Height::new(height)));

        // Without state sync, the actor resumes after marshal's processed position.
        assert_eq!(tip(None, None), None);
        assert_eq!(tip(stored(2), None), covered(2));
        assert_eq!(tip(absent(2), None), covered(2));

        // A floor covers every block below it until marshal passes it.
        assert_eq!(tip(None, Some(0)), None);
        assert_eq!(tip(None, Some(3)), covered(2));
        assert_eq!(tip(stored(1), Some(3)), covered(2));
        assert_eq!(tip(absent(2), Some(3)), covered(2));
        assert_eq!(tip(stored(4), Some(3)), covered(4));
    }

    #[test]
    fn late_state_sync_floor_skips_inclusion_prefix() {
        let epocher = FixedEpocher::new(NZU64!(64));
        let epoch = Epoch::new(3);
        let midpoint = epocher.midpoint(epoch).expect("test epoch");
        let late_floor = midpoint.next();
        let late_phase = epocher.containing(late_floor).expect("test floor").phase();

        assert_eq!(late_phase, EpochPhase::Late);
        assert!(state_sync_skips_inclusion_prefix(
            &epocher,
            Some(late_floor)
        ));
        assert!(!state_sync_skips_inclusion_prefix(&epocher, Some(midpoint)));
        assert!(!state_sync_skips_inclusion_prefix(&epocher, None));
    }

    #[test]
    fn recovered_dealer_after_dealing_requires_ack_quorum() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let epoch = Epoch::new(1);
            let signers = (0..4).map(PrivateKey::from_seed).collect::<Vec<_>>();
            let players = Set::from_iter_dedup(signers.iter().map(Signer::public_key));
            let (previous, shares) =
                deal::<TestBlsVariant, _, N3f1>(test_rng(), Mode::NonZeroCounter, players.clone())
                    .expect("trusted previous output");
            let signer = signers[0].clone();
            let share = shares
                .get_value(&signer.public_key())
                .expect("dealer share")
                .clone();
            let info = Info::new::<N3f1>(
                TEST_NAMESPACE,
                epoch.get(),
                Some(previous),
                Mode::NonZeroCounter,
                Reveal::V1,
                players.clone(),
                players.clone(),
            )
            .expect("valid reshare info");
            let secret_store = MemorySecretStore::default();
            let mut store: Store<_, _, TestBlsVariant, PublicKey> = mocks::store(
                context.child("store"),
                "recovered-dealer-after-dealing",
                secret_store,
            )
            .await;
            let seed = store.seed_or_random(epoch, test_rng()).await;
            let (early_dealer, incomplete_dealer, mut recovered_dealer) = {
                let new_dealer = || {
                    store
                        .create_dealer::<PrivateKey, N3f1>(
                            epoch,
                            signer.clone(),
                            info.clone(),
                            Some(share.clone()),
                            seed,
                        )
                        .expect("current dealer")
                };
                (new_dealer(), new_dealer(), new_dealer())
            };
            assert!(
                dealer_for_phase(EpochPhase::Early, players.len(), Some(early_dealer)).is_some()
            );
            assert!(
                dealer_for_phase(EpochPhase::Midpoint, players.len(), Some(incomplete_dealer))
                    .is_none()
            );

            let dealer_key = signer.public_key();
            for player_signer in &signers[1..] {
                let player_key = player_signer.public_key();
                let mut player =
                    Player::new(info.clone(), player_signer.clone()).expect("current player");
                let (_, public, private) = recovered_dealer
                    .shares_to_distribute()
                    .find(|(recipient, _, _)| recipient == &player_key)
                    .expect("player dealing");
                let ack = player
                    .dealer_message::<N3f1>(dealer_key.clone(), public, private)
                    .expect("valid dealing")
                    .expect("new dealing");
                assert!(matches!(
                    recovered_dealer
                        .handle(&mut store, epoch, player_key, ack)
                        .await,
                    Ok(AckOutcome::Recorded)
                ));
            }
            assert!(
                dealer_for_phase(EpochPhase::Midpoint, players.len(), Some(recovered_dealer))
                    .is_some()
            );
        });
    }
}
