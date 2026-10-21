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
    types::{Epoch, EpochPhase, Epocher, Height},
};
use commonware_cryptography::{
    BatchVerifier, PublicKey, Signer,
    bls12381::{
        dkg::feldman_desmedt::{Info, Output, SignedDealerLog},
        primitives::{group::Share, variant::Variant as BlsVariant},
    },
    transcript::Summary,
};
use commonware_p2p::Blocker;
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_utils::{Acknowledgement, N3f1, ordered::Quorum as _};
use rand_core::CryptoRng;
use tracing::warn;

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

pub(super) struct EpochPreparation<V, C>
where
    V: BlsVariant,
    C: Signer,
{
    pub(super) epoch: Epoch,
    pub(super) phase: EpochPhase,
    pub(super) participants: Participants<C::PublicKey>,
    pub(super) previous: Option<Output<V, C::PublicKey>>,
    pub(super) share: Option<Share>,
    pub(super) seed: Summary,
    /// Dealer logs of the finalized blocks below a state-sync floor, which
    /// marshal never delivers, in ascending height order.
    pub(super) window: Vec<SignedDealerLog<V, C>>,
}

pub(super) enum Setup<V, C>
where
    V: BlsVariant,
    C: Signer,
{
    Follow,
    Participate(Box<PreparedEpoch<V, C>>),
}

/// State-sync epoch metadata with the dealer logs of the inclusion window
/// below its certified floor.
pub(super) struct StateSyncStart<V, C, D>
where
    V: BlsVariant,
    C: Signer,
    D: Directory<C::PublicKey>,
{
    pub(super) info: EpochInfo<V, C::PublicKey, D>,
    pub(super) window: Vec<SignedDealerLog<V, C>>,
}

/// Returns `public_key`'s share of `info.output`.
///
/// A failed ceremony carries the previous output forward, so when no share is
/// stored for `info.epoch` and the node is a player of the carried output, the
/// newest share stored for an earlier epoch is returned if it is a share of
/// that output. A node that ran through every boundary stores the carried
/// share under each epoch, while a node that state synced past several failed
/// ceremonies still holds it under the last epoch it applied. The search reads
/// one stored epoch at a time down to that share, or to epoch zero when none
/// is stored.
async fn recovered_share<E, SS, V, P, D>(
    store: &mut Store<E, SS, V, P, D>,
    public_key: &P,
    info: &EpochInfo<V, P, D>,
) -> Option<Share>
where
    E: BufferPooler + Clock + Storage + Metrics,
    SS: SecretStore,
    V: BlsVariant,
    P: PublicKey,
    D: Directory<P>,
{
    let share = store.share(info.epoch).await;
    if share.is_some() || info.outcome != EpochOutcome::Failure {
        return share;
    }

    let index = info.output.players().index(public_key)?;
    let expected = info.output.public().partial_public(index).ok()?;
    let mut epoch = info.epoch;
    while let Some(previous) = epoch.previous() {
        if let Some(share) = store.share(previous).await {
            return (share.public::<V>() == expected).then_some(share);
        }
        epoch = previous;
    }
    None
}

/// Returns the later of marshal's processed position and the parent of the
/// state-sync floor (`None` when neither exists).
///
/// `processed` pairs the position with the ready processed block or its child
/// when the processed block is absent.
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
        state_sync: Option<StateSyncStart<V, C, B::Directory>>,
    ) -> Option<Setup<V, C>> {
        self.metrics.set_phase(Phase::Setup);

        let height = self.tip.map_or_else(Height::zero, |tip| tip.height.next());
        let bounds = self
            .epocher
            .containing(height)
            .expect("epocher must know of block height");
        let epoch = bounds.epoch();
        self.metrics.set_epoch(epoch.get());

        // Prefer the epoch committed earlier in this run, then state-sync
        // material, which only the first setup of a run receives, then the
        // finalized boundary block.
        let current = store.current().filter(|current| current.epoch == epoch);
        let already_committed = current.is_some();
        let (info, window) = match (current, state_sync) {
            (Some(info), _) => (info, Vec::new()),
            (None, Some(start)) => (start.info, start.window),
            (None, None) => {
                let Some(info) = self.boundary_epoch_info(epoch).await else {
                    warn!(
                        ?epoch,
                        "boundary block unavailable, following the epoch: this node cannot certify its final block"
                    );
                    return Some(Setup::Follow);
                };
                (info, Vec::new())
            }
        };
        if info.epoch != epoch {
            panic!(
                "boundary epoch info describes epoch {}, expected {epoch}",
                info.epoch
            );
        }

        // Each source is read from storage or produced by consensus, so check
        // participant limits before building protocol state.
        let participants = info.participants();
        let round = epoch.get();
        participants
            .validate(self.max_participants, Some(&info.output), round)
            .expect("boundary epoch participants must be valid");

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

        Some(Setup::Participate(Box::new(
            self.prepare_epoch(
                store,
                EpochPreparation {
                    epoch,
                    phase: bounds.phase(),
                    participants,
                    previous: Some(info.output.clone()),
                    share,
                    seed,
                    window,
                },
            )
            .await,
        )))
    }

    /// Returns this node's share of `info.output` (see [`recovered_share`]).
    pub(super) async fn recovered_share(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        info: &EpochInfo<V, C::PublicKey, B::Directory>,
    ) -> Option<Share> {
        recovered_share(store, &self.signer.public_key(), info).await
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
        let Some(Payload::EpochInfo(info)) = block.inner().payload() else {
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

    /// Builds the ceremony round and this node's dealer and player state for an
    /// epoch.
    ///
    /// Window logs are recorded first, with the checks applied to logs
    /// delivered by marshal, so the dealer and player state derives from the
    /// same journal a node that applied those blocks holds.
    pub(super) async fn prepare_epoch(
        &mut self,
        store: &mut Store<E, SS, V, C::PublicKey, B::Directory>,
        preparation: EpochPreparation<V, C>,
    ) -> PreparedEpoch<V, C> {
        let EpochPreparation {
            epoch,
            phase,
            participants,
            previous,
            share,
            seed,
            window,
        } = preparation;

        let round = Info::new::<N3f1>(
            self.namespace,
            epoch.get(),
            previous.clone(),
            self.sharing_mode,
            self.reveal,
            participants.dealers.clone(),
            participants.players.clone(),
        )
        .expect("epoch participants must produce valid round info");

        let public_key = self.signer.public_key();
        let mut applied = 0;
        for log in window {
            if Self::observe_dealer_log(&public_key, &round, store, epoch, None, log).await {
                applied += 1;
            }
        }
        self.metrics.set_window_logs(applied);

        // Reshare dealers need the prior private share, while epoch-zero DKG has
        // no prior output. Player construction depends only on membership in the
        // new player set.
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
    use super::{dealer_for_phase, recovered_share, startup};
    use crate::dkg::{
        SecretStore as _,
        reshare::store::{AckOutcome, Store},
        tests::mocks::{self, MemorySecretStore, TestBlsVariant, child, genesis_block},
        types::{EpochInfo, EpochOutcome},
    };
    use commonware_consensus::{
        marshal::core::Processed,
        types::{Epoch, EpochPhase, Height},
    };
    use commonware_cryptography::{
        Digested, Digestible as _, Signer,
        bls12381::{
            dkg::feldman_desmedt::{Info, Player, Reveal, deal},
            primitives::sharing::Mode,
        },
        ed25519::{PrivateKey, PublicKey},
    };
    use commonware_runtime::{Runner, Supervisor as _, deterministic};
    use commonware_utils::{N3f1, TestRng, ordered::Set, sequence::Unit, test_rng};

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
                (
                    processed,
                    Digested::precomputed(blocks[anchor].clone(), blocks[anchor].digest()),
                )
            });
            startup(
                processed,
                floor.map(|floor| {
                    Digested::precomputed(blocks[floor].clone(), blocks[floor].digest())
                }),
            )
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

    /// A failed ceremony carries its output forward, so a share of that output
    /// stored under any earlier epoch recovers the node's role, while a stored
    /// share of a different output does not.
    #[test]
    fn recovered_share_matches_carried_output() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let signers = (0..4).map(PrivateKey::from_seed).collect::<Vec<_>>();
            let players = Set::from_iter_dedup(signers.iter().map(Signer::public_key));
            let (carried, shares) =
                deal::<TestBlsVariant, _, N3f1>(test_rng(), Mode::NonZeroCounter, players.clone())
                    .expect("trusted carried output");
            let (other, other_shares) = deal::<TestBlsVariant, _, N3f1>(
                TestRng::new(1),
                Mode::NonZeroCounter,
                players.clone(),
            )
            .expect("trusted other output");
            let public_key = signers[0].public_key();
            let share = shares.get_value(&public_key).expect("player share").clone();
            let info = |epoch: u64, outcome: EpochOutcome| EpochInfo {
                outcome,
                epoch: Epoch::new(epoch),
                output: carried.clone(),
                players: players.clone(),
                next_players: players.clone(),
                directory: Unit,
            };
            let mut secrets = MemorySecretStore::default();
            secrets.put_share(Epoch::new(2), share.clone()).await;
            let mut store: Store<_, _, TestBlsVariant, PublicKey> =
                mocks::store(context.child("store"), "recovered-share", secrets.clone()).await;

            // Three failed ceremonies after the stored epoch still carry the
            // stored output, so the share under epoch two is this node's share.
            assert_eq!(
                recovered_share(&mut store, &public_key, &info(5, EpochOutcome::Failure)).await,
                Some(share.clone())
            );

            // A successful ceremony replaces the output, so an unstored epoch
            // has no share to recover even though older shares exist.
            assert_eq!(
                recovered_share(&mut store, &public_key, &info(5, EpochOutcome::Success)).await,
                None
            );

            // The newest stored share decides: a share of another output stored
            // under a later epoch means this node holds no share of the carried
            // output.
            let foreign = other_shares
                .get_value(&public_key)
                .expect("other share")
                .clone();
            assert_ne!(other.public(), carried.public());
            secrets.put_share(Epoch::new(3), foreign).await;
            assert_eq!(
                recovered_share(&mut store, &public_key, &info(5, EpochOutcome::Failure)).await,
                None
            );

            // A node that is not a player of the carried output recovers nothing.
            let outsider = PrivateKey::from_seed(9).public_key();
            assert_eq!(
                recovered_share(&mut store, &outsider, &info(5, EpochOutcome::Failure)).await,
                None
            );
        });
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
