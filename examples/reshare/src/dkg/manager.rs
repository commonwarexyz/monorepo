//! A manager for a DKG/reshare round.

use crate::{
    application::Block,
    dkg::{actor::RoundInfo, DealOutcome, Dkg, Payload},
};
use commonware_codec::{Decode, Encode};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{
        dkg::{
            player::Output,
            types::{Ack, Share},
            Arbiter, Dealer, Player,
        },
        primitives::{group, poly::Public, variant::Variant},
    },
    Hasher, Signer,
};
use commonware_p2p::{
    utils::mux::{MuxHandle, SubReceiver, SubSender},
    Receiver, Recipients, Sender,
};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::metadata::Metadata;
use commonware_utils::{
    max_faults,
    ordered::{Quorum, Set},
    sequence::U64,
    union,
};
use futures::FutureExt;
use governor::{
    clock::Clock as GClock, middleware::NoOpMiddleware, state::keyed::HashMapStateStore, Quota,
    RateLimiter,
};
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, ops::Deref};
use tracing::{debug, error, info, warn};

/// The signature namespace for DKG acknowledgment messages.
const ACK_NAMESPACE: &[u8] = b"_DKG_ACK";

/// The namespace used when signing [DealOutcome]s.
const OUTCOME_NAMESPACE: &[u8] = b"_DEAL_OUTCOME";

/// The concurrency level for DKG/reshare operations.
const CONCURRENCY: usize = 1;

/// A manager for a DKG/reshare round.
///
/// Exposes functionality:
/// - Distribute a [Dealer]'s shares
/// - Process incoming shares and acknowledgements from other [Dealer]s and [Player]s.
/// - Create a [DealOutcome] from the current state, for inclusion in a [Block].
/// - Process [Block]s that may contain a [DealOutcome].
/// - Finalize the DKG/reshare round, returning the resulting [Output].
pub struct DkgManager<'ctx, E, V, C, S, R>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    V: Variant,
    C: Signer,
    S: Sender<PublicKey = C::PublicKey>,
    R: Receiver<PublicKey = C::PublicKey>,
{
    /// Prefix all signed messages to prevent replay attacks.
    namespace: Vec<u8>,

    /// The local signer.
    signer: &'ctx mut C,

    /// The current epoch.
    epoch: Epoch,

    /// The previous group polynomial and (if dealing) share.
    previous: RoundResult<V>,

    /// The dealers in the round.
    dealers: Set<C::PublicKey>,

    /// The players in the round.
    players: Set<C::PublicKey>,

    /// The outbound communication channel for peers.
    sender: SubSender<S>,

    /// The inbound communication channel for peers.
    receiver: SubReceiver<R>,

    /// The rate limiter for sending messages.
    #[allow(clippy::type_complexity)]
    rate_limiter:
        RateLimiter<C::PublicKey, HashMapStateStore<C::PublicKey>, E, NoOpMiddleware<E::Instant>>,

    /// [Dealer] metadata, if this manager is also dealing.
    dealer_meta: Option<DealerMetadata<C, V>>,

    /// The local [Player] for this round, if the manager is playing.
    player: Option<(u32, Player<C::PublicKey, V>)>,

    /// The local [Arbiter] for this round.
    arbiter: Arbiter<C::PublicKey, V>,

    /// The [Metadata] store used for persisting round state.
    round_metadata: &'ctx mut Metadata<E, U64, RoundInfo<V, C>>,
}

/// Metadata associated with a [Dealer].
struct DealerMetadata<C: Signer, V: Variant> {
    /// The [Dealer] object.
    dealer: Dealer<C::PublicKey, V>,
    /// The [Dealer]'s commitment.
    commitment: Public<V>,
    /// The [Dealer]'s shares for all players.
    shares: Set<group::Share>,
    /// Signed acknowledgements from contributors.
    acks: BTreeMap<u32, Ack<C::Signature>>,
    /// The constructed dealing for inclusion in a block, if any.
    outcome: Option<DealOutcome<C, V>>,
}

/// A result of a DKG/reshare round.
pub enum RoundResult<V: Variant> {
    /// DKG failed or hasn't happened yet; No group polynomial or share available.
    None,
    /// The new group polynomial, if the manager is not a [Player].
    Polynomial(Public<V>),
    /// The new group polynomial and the local share, if the manager is a [Player].
    Output(Output<V>),
}

impl<'ctx, E, V, C, S, R> DkgManager<'ctx, E, V, C, S, R>
where
    E: Spawner + Metrics + CryptoRngCore + Clock + GClock + Storage,
    V: Variant,
    C: Signer,
    S: Sender<PublicKey = C::PublicKey>,
    R: Receiver<PublicKey = C::PublicKey>,
{
    /// Create a new DKG/reshare manager.
    ///
    /// # Panics
    ///
    /// Panics if the signer is not in the list of contributors or if the sub-channel for the current
    /// epoch could not be registered.
    #[allow(clippy::too_many_arguments)]
    pub async fn init(
        context: &mut E,
        namespace: Vec<u8>,
        epoch: Epoch,
        public: Option<Public<V>>,
        share: Option<group::Share>,
        signer: &'ctx mut C,
        dealers: Set<C::PublicKey>,
        players: Set<C::PublicKey>,
        mux: &'ctx mut MuxHandle<S, R>,
        send_rate_limit: Quota,
        store: &'ctx mut Metadata<E, U64, RoundInfo<V, C>>,
    ) -> Self {
        let mut player = players.position(&signer.public_key()).map(|signer_index| {
            let player = Player::new(
                signer.public_key(),
                public.clone(),
                dealers.clone(),
                players.clone(),
                CONCURRENCY,
            );

            (signer_index as u32, player)
        });
        let mut arbiter = Arbiter::new(
            public.clone(),
            dealers.clone(),
            players.clone(),
            CONCURRENCY,
        );

        // If the node crashed in the middle of dealing, recover the dealer state from storage.
        let dealer_meta = if let Some(meta) = store.get(&epoch.into()) {
            for outcome in &meta.outcomes {
                let ack_indices = outcome
                    .acks
                    .iter()
                    .map(|ack| ack.player)
                    .collect::<Vec<_>>();
                if let Err(e) = arbiter.commitment(
                    outcome.dealer.clone(),
                    outcome.commitment.clone(),
                    ack_indices,
                    outcome.reveals.clone(),
                ) {
                    warn!(error = ?e, "failed to track dealer outcome in arbiter");
                }
            }

            if let Some((_, ref mut player)) = player {
                for (dealer, commitment, share) in meta.received_shares.clone() {
                    player.share(dealer, commitment, share).unwrap();
                }
            }

            if let Some((commitment, shares, acks)) = meta.deal.clone() {
                let (mut dealer, _, _) = Dealer::new(context, share.clone(), players.clone());
                for ack in acks.values() {
                    dealer
                        .ack(players.get(ack.player as usize).cloned().unwrap())
                        .unwrap();
                }
                Some(DealerMetadata {
                    dealer,
                    commitment,
                    shares,
                    acks,
                    outcome: meta.local_outcome.clone(),
                })
            } else {
                None
            }
        } else {
            // Deal if the participant has a share or if this is an initial DKG (no public polynomial).
            let is_dealer = dealers.position(&signer.public_key()).is_some();
            is_dealer.then(|| {
                let (dealer, commitment, shares) =
                    Dealer::new(context, share.clone(), players.clone());
                DealerMetadata {
                    dealer,
                    commitment,
                    shares,
                    acks: BTreeMap::new(),
                    outcome: None,
                }
            })
        };

        let (s, r) = mux.register(epoch.get()).await.unwrap();

        let rate_limiter =
            RateLimiter::hashmap_with_clock(send_rate_limit, context.deref().clone());
        let previous = public
            .map(|public| {
                share.map_or(RoundResult::Polynomial(public.clone()), |share| {
                    RoundResult::Output(Output { public, share })
                })
            })
            .unwrap_or(RoundResult::None);

        Self {
            namespace,
            signer,
            epoch,
            previous,
            dealers,
            players,
            sender: s,
            receiver: r,
            rate_limiter,
            dealer_meta,
            player,
            arbiter,
            round_metadata: store,
        }
    }

    /// Distribute the [Dealer]'s shares to all contributors that have not yet acknowledged receipt of their share.
    pub async fn distribute(&mut self, round: u64) {
        // Only attempt distribution if the manager is also a dealer.
        let Some(DealerMetadata {
            dealer,
            commitment,
            shares,
            acks,
            ..
        }) = &mut self.dealer_meta
        else {
            return;
        };

        // Find all contributors that need to be sent a share by filtering out those that have
        // not yet acknowledged receipt of their share.
        let needs_broadcast = self
            .players
            .iter()
            .enumerate()
            .filter(|(i, _)| !acks.contains_key(&(*i as u32)))
            .collect::<Vec<_>>();

        for (idx, contributor) in needs_broadcast {
            if self.rate_limiter.check_key(contributor).is_err() {
                debug!(round, player = ?contributor, "rate limited; skipping share send");
                continue;
            }

            let share = shares.get(idx).cloned().unwrap();

            if let Some((signer_index, ref mut player)) = self.player {
                if idx == signer_index as usize {
                    player
                        .share(
                            self.signer.public_key(),
                            commitment.deref().clone(),
                            share.clone(),
                        )
                        .unwrap();
                    dealer.ack(self.signer.public_key()).unwrap();

                    let ack = Ack::new::<_, V>(
                        &union(&self.namespace, ACK_NAMESPACE),
                        self.signer,
                        signer_index,
                        round,
                        &self.signer.public_key(),
                        commitment,
                    );
                    acks.insert(signer_index, ack.clone());

                    // Persist the acknowledgement to storage.
                    self.round_metadata
                        .upsert_sync(self.epoch.into(), |meta| {
                            if let Some((_, _, acks)) = &mut meta.deal {
                                acks.insert(signer_index, ack);
                            } else {
                                meta.deal = Some((
                                    commitment.deref().clone(),
                                    shares.deref().clone(),
                                    BTreeMap::from([(signer_index, ack)]),
                                ));
                            }
                            meta.received_shares.push((
                                self.signer.public_key(),
                                commitment.deref().clone(),
                                share,
                            ));
                        })
                        .await
                        .expect("must persist ack");

                    continue;
                }
            }

            let payload =
                Payload::<V, C::Signature>::Share(Share::new(commitment.deref().clone(), share))
                    .into_message(round);
            let success = self
                .sender
                .send(
                    Recipients::One(contributor.clone()),
                    payload.encode().freeze(),
                    true,
                )
                .await
                .expect("must send share");

            if success.is_empty() {
                warn!(round, player = ?contributor, "failed to send share");
            } else {
                info!(round, player = ?contributor, "sent share");
            }
        }
    }

    /// Processes all available messages from the [Receiver], handling both incoming shares and
    /// acknowledgements. Once the [Receiver] needs to wait for more messages, this function
    /// yields back to the caller.
    pub async fn process_messages(&mut self, round: u64) {
        while let Some(msg) = self.receiver.recv().now_or_never() {
            let (peer, msg) = msg.expect("receiver closed");

            let Ok(msg) =
                Dkg::<V, C::Signature>::decode_cfg(&mut msg.as_ref(), &(self.players.len() as u32))
            else {
                debug!(round, "failed to decode DKG message");
                continue;
            };
            if msg.round != round {
                warn!(
                    round,
                    msg_round = msg.round,
                    "ignoring message for different round"
                );
                continue;
            }

            match msg.payload {
                Payload::Ack(ack) => {
                    let Some(DealerMetadata {
                        acks,
                        dealer,
                        commitment,
                        shares,
                        ..
                    }) = &mut self.dealer_meta
                    else {
                        warn!(round, "ignoring ack; not a dealer");
                        continue;
                    };

                    // Verify index matches
                    let Some(player) = self.players.get(ack.player as usize) else {
                        warn!(round, index = ack.player, "invalid ack index");
                        continue;
                    };

                    if player != &peer {
                        warn!(round, index = ack.player, "mismatched ack index");
                        continue;
                    }

                    // Verify signature on incoming ack
                    if !ack.verify::<V, _>(
                        &union(&self.namespace, ACK_NAMESPACE),
                        &peer,
                        round,
                        &self.signer.public_key(),
                        commitment,
                    ) {
                        warn!(round, index = ack.player, "invalid ack signature");
                        continue;
                    }

                    // Store ack
                    if let Err(e) = dealer.ack(peer) {
                        debug!(round, index = ack.player, error = ?e, "failed to store ack");
                        continue;
                    }
                    info!(round, index = ack.player, "stored ack");

                    acks.insert(ack.player, ack.clone());

                    // Persist the acknowledgement to storage.
                    self.round_metadata
                        .upsert_sync(self.epoch.into(), |meta| {
                            if let Some((_, _, acks)) = &mut meta.deal {
                                acks.insert(ack.player, ack);
                            } else {
                                meta.deal = Some((
                                    commitment.deref().clone(),
                                    shares.deref().clone(),
                                    BTreeMap::from([(ack.player, ack)]),
                                ));
                            }
                        })
                        .await
                        .expect("must persist ack");
                }
                Payload::Share(Share { commitment, share }) => {
                    let Some((signer_index, ref mut player)) = self.player else {
                        warn!(round, "ignoring share; not a player");
                        continue;
                    };

                    // Store share
                    if let Err(e) = player.share(peer.clone(), commitment.clone(), share.clone()) {
                        debug!(round, error = ?e, "failed to store share");
                        continue;
                    }

                    // Persist the share to storage.
                    self.round_metadata
                        .upsert_sync(self.epoch.into(), |meta| {
                            meta.received_shares
                                .push((peer.clone(), commitment.clone(), share));
                        })
                        .await
                        .expect("must persist share");

                    // Send ack
                    let payload = Payload::<V, C::Signature>::Ack(Ack::new::<_, V>(
                        &union(&self.namespace, ACK_NAMESPACE),
                        self.signer,
                        signer_index,
                        round,
                        &peer,
                        &commitment,
                    ))
                    .into_message(round);
                    self.sender
                        .send(
                            Recipients::One(peer.clone()),
                            payload.encode().freeze(),
                            true,
                        )
                        .await
                        .expect("must send ack");

                    info!(round, player = ?peer, "sent ack");
                }
            }
        }
    }

    /// Processes a [Block] that may contain a [DealOutcome], tracking it with the [Arbiter] if
    /// all acknowledgement signatures are valid.
    pub async fn process_block(&mut self, round: u64, block: Block<impl Hasher, C, V>) {
        let Some(outcome) = block.deal_outcome else {
            debug!(height = block.height, "saw block with no deal outcome");
            return;
        };

        // Ensure the outcome is for the current round.
        if outcome.round != round {
            warn!(
                outcome_round = outcome.round,
                round, "outcome round does not match current round"
            );
            return;
        }

        // Verify the dealer is part of this round.
        //
        // This rule does not prevent a dealer from submitting a dealing of another dealer. If this
        // is desired, it could be enforced by checking the proposer of the block matches the dealer.
        if self.dealers.index(&outcome.dealer).is_none() {
            warn!(round, dealer = ?outcome.dealer, "ignoring unregistered dealer");
            return;
        }

        // Verify the dealer's signature before considering processing the outcome.
        if !outcome.verify(&union(&self.namespace, OUTCOME_NAMESPACE)) {
            warn!(round, "invalid dealer signature; ignoring deal outcome");
            return;
        }

        // Verify all ack signatures
        if !outcome.acks.iter().all(|ack| {
            self.players
                .get(ack.player as usize)
                .map(|public_key| {
                    ack.verify::<V, _>(
                        &union(&self.namespace, ACK_NAMESPACE),
                        public_key,
                        round,
                        &outcome.dealer,
                        &outcome.commitment,
                    )
                })
                .unwrap_or(false)
        }) {
            self.arbiter
                .disqualify(outcome.dealer.clone())
                .expect("failed to disqualify dealer");
            warn!(round, dealer = ?outcome.dealer, "invalid ack signatures; disqualifying dealer");
            return;
        }

        // Check dealer commitment (both whether dealer is valid and whether commitment is valid)
        let ack_indices = outcome
            .acks
            .iter()
            .map(|ack| ack.player)
            .collect::<Vec<_>>();
        if let Err(e) = self.arbiter.commitment(
            outcome.dealer.clone(),
            outcome.commitment.clone(),
            ack_indices,
            outcome.reveals.clone(),
        ) {
            warn!(round, dealer = ?outcome.dealer, error = ?e, "failed to track dealer outcome in arbiter");
            return;
        }

        // Persist deal outcome to storage
        self.round_metadata
            .upsert_sync(self.epoch.into(), |meta| {
                if let Some(pos) = meta
                    .outcomes
                    .iter()
                    .position(|i| i.dealer == outcome.dealer)
                {
                    meta.outcomes[pos] = outcome;
                } else {
                    meta.outcomes.push(outcome);
                }
            })
            .await
            .expect("must persist deal outcome");

        info!(
            round,
            height = block.height,
            "processed deal outcome from block"
        );
    }

    /// Finalize the DKG/reshare round, returning the [Output].
    pub async fn finalize(self, round: u64) -> (Set<C::PublicKey>, RoundResult<V>, bool) {
        let (result, disqualified) = self.arbiter.finalize();
        let result = match result {
            Ok(output) => output,
            Err(e) => {
                error!(error = ?e, ?disqualified, "failed to finalize arbiter; aborting round");
                return (self.dealers, self.previous, false);
            }
        };

        match self.player {
            Some((signer_index, player)) => {
                let commitments = result.commitments.into_iter().collect::<BTreeMap<_, _>>();
                let reveals = result
                    .reveals
                    .into_iter()
                    .filter_map(|(dealer_idx, shares)| {
                        shares
                            .iter()
                            .find(|s| s.index == signer_index)
                            .cloned()
                            .map(|share| (dealer_idx, share))
                    })
                    .collect::<BTreeMap<_, _>>();

                let n_commitments = commitments.len();
                let n_reveals = reveals.len();

                let output = match player.finalize(commitments, reveals) {
                    Ok(output) => output,
                    Err(e) => {
                        error!(error = ?e, "failed to finalize player; aborting round");
                        return (self.dealers, self.previous, false);
                    }
                };

                info!(
                    round,
                    ?disqualified,
                    n_commitments,
                    n_reveals,
                    "finalized DKG/reshare round"
                );

                (self.players, RoundResult::Output(output), true)
            }
            None => (self.players, RoundResult::Polynomial(result.public), true),
        }
    }

    /// Instantiate the [DealOutcome] from the current state of the manager.
    pub async fn construct_deal_outcome(&mut self, round: u64) {
        // Only attempt to construct a deal outcome if the manager is also a dealer.
        let Some(DealerMetadata {
            commitment,
            shares,
            acks,
            outcome,
            ..
        }) = &mut self.dealer_meta
        else {
            return;
        };

        // Collect required reveals.
        let reveals = (0..self.players.len() as u32)
            .filter_map(|i| {
                (!acks.contains_key(&i))
                    .then(|| shares.get(i as usize).cloned())
                    .flatten()
            })
            .collect::<Vec<_>>();

        // If too many reveals, don't attempt to construct a deal outcome.
        if reveals.len() > max_faults(self.players.len() as u32) as usize {
            warn!(
                round,
                "too many reveals; skipping deal outcome construction"
            );
            return;
        }

        let local_outcome = Some(DealOutcome::new(
            self.signer,
            &union(&self.namespace, OUTCOME_NAMESPACE),
            round,
            commitment.deref().clone(),
            acks.values().cloned().collect(),
            reveals,
        ));

        self.round_metadata
            .upsert_sync(self.epoch.into(), |meta| {
                meta.local_outcome = local_outcome.clone();
            })
            .await
            .expect("must persist local outcome");

        *outcome = local_outcome;
    }

    /// Returns the [DealOutcome] for inclusion in a block, if one has been processed.
    pub fn take_deal_outcome(&mut self) -> Option<DealOutcome<C, V>> {
        self.dealer_meta
            .as_mut()
            .and_then(|meta| meta.outcome.take())
    }
}
